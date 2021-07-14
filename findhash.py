# -*- coding:utf-8 -*-
import codecs
import re
from collections import Counter
import ida_nalt
import idautils
import idc
import idaapi
import os
import ida_bytes
import xml.etree.ElementTree as ET
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK, get_user_idadir, idadir
import time


### MD5，SHA1，SHA224, SHA256，SHA384，SHA512


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

# 获取SO文件名和路径
def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    if fullpath:
        filepath, filename = os.path.split(fullpath)
        return filepath, filename
    else:
        return None, None

so_path, so_name = getSoPathAndName()

def getSegAddr():
    textStart=0
    textEnd=0
    end = 0
    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)).lower()=='.text' or (idc.get_segm_name(seg)).lower()=='text':
            textStart=idc.get_segm_start(seg)
            textEnd=idc.get_segm_end(seg)
        tmp = idc.get_segm_end(seg)
        if end < tmp:
            end = tmp
    return textStart,textEnd,end


# 判断是代码还是数据
# def code_or_data(ea):
#     flags = ida_bytes.get_full_flags(ea)
#
#     if ida_bytes.is_data(flags):
#         return 1
#
#     elif ida_bytes.is_code(flags):
#         return 2
#
#     else:
#         return 0

# 还原命名粉碎
def demangle_str(s):
    demangled = idc.demangle_name(s,idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else s


# 判断arm/thumb，thumb+1
def thumb_or_arm(offset):
    offset = int(offset, 16)
    arm_or_thumb = idc.get_sreg(offset, "T")
    if arm_or_thumb:
        offset += 1
    return offset


# 加载特征库
def load_signatures():
    db = idadir("plugins/findhash.xml")
    if not os.path.isfile(db):
        db = os.path.join(get_user_idadir(), "plugins/findhash.xml")
    root = ET.parse(db).getroot()

    signature = []
    for p in root:
        name, data = p.attrib['t'].split(" [")
        bits, size = data[:-1].split(".")
        bits = int(bits)

        signature.append({
            "name": name,
            "bits": bits,
            "size": int(size),
            "data": codecs.decode(p.text, ('hex')),
        })

    return signature

# 对结果做总结
def get_result(dic):
    funclist = []
    constlist = []

    for key, value in dic.items():
        if value["type"] == 2:
            if value["init"] and value["round"]:
                value["describe"] = f"函数{value['funcName']}疑似哈希函数主体，包含初始化常数以及运算部分。"
            elif value["init"]:
                value["describe"] = f"函数{value['funcName']}疑似哈希函数，包含初始化魔数的代码。"
            else:
                value["describe"] = f"函数{value['funcName']}疑似哈希函数运算部分。"

            value["hookOffset"] = hex(thumb_or_arm(key))
            funclist.append([value["funcName"], value["describe"], value["hookOffset"]])
        if value["type"] == 1:
            constlist.append([value['describe'], key])
    return funclist,constlist


# 处理结果，生成frida脚本
def generate_script(funclist,constlist):
    script_module = """
function monitor_constants(targetSo) {
    let const_array = [];
    let const_name = [];
    let const_addr = $$$const_addrs;

    for (var i = 0; i < const_addr.length; i++) {
        const_array.push({base:targetSo.add(const_addr[i][1]),size:0x1});
        const_name.push(const_addr[i][0]);
    }

    MemoryAccessMonitor.enable(const_array, {
        onAccess: function (details) {
            console.log("\\n");
            console.log("监控到疑似加密常量的内存访问\\n");
            console.log(const_name[details.rangeIndex]);
            console.log("访问来自:"+details.from.sub(targetSo)+"(可能有误差)");
    }
});
}

function hook_suspected_function(targetSo) {
    const funcs = $$$funcs;
    for (var i in funcs) {
        let relativePtr = funcs[i][2];
        let funcPtr = targetSo.add(relativePtr);
        let describe = funcs[i][1];
        let handler = (function() {
        return function(args) {
            console.log("\\n");
            console.log(describe);
            console.log(Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n"));
        };
        })();
    Interceptor.attach(funcPtr, {onEnter: handler});
}
}


function main() {
    var targetSo = Module.findBaseAddress('$$$.so');
    // 对疑似哈希算法常量的地址进行监控，使用frida MemoryAccessMonitor API，有几个缺陷，在这里比较鸡肋。
    // 1.只监控第一次访问，所以如果此区域被多次访问，后续访问无法获取。可以根据这篇文章做改良和扩展。https://bbs.pediy.com/thread-262104-1.htm
    // 2.ARM 64无法使用
    // 3.无法查看调用栈
    // 在这儿用于验证这些常量是否被访问，访问了就说明可能使用该哈希算法。
    // MemoryAccessMonitor在别处可能有较大用处，比如ollvm过的so，或者ida xref失效/过多等情况。
    // hook和monitor这两个函数，只能分别注入和测试，两个同时会出错，这可能涉及到frida inline hook的原理
    // 除非hook_suspected_function 没结果，否则不建议使用monitor_constants。
    // monitor_constants(targetSo);

    hook_suspected_function(targetSo);
}

setImmediate(main);
    """
    hookscript = script_module.replace("$$$.so", so_name).replace("$$$const_addrs",str(constlist)).replace("$$$funcs",str(funclist))

    return hookscript


class findhash(plugin_t):
    flags = PLUGIN_PROC
    comment = "findhash"
    help = ""
    wanted_name = "findhash"
    wanted_hotkey = ""

    def init(self):
        print("findHash (v0.1) plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):

        start_time = time.time()
        is_64bits = idaapi.get_inf_structure().is_64bit()
        if is_64bits:
            print("这个脚本只考虑了32位SO的反编译代码，64位未适配。")

        textStart, textEnd, end = getSegAddr()
        found = {}
        offsets = []

        # 从二进制中搜索，这部分和findcrypt/signsrch中的处理类似
        sig_list = load_signatures()
        bytes = ida_bytes.get_bytes(0, end)
        for sig in sig_list:
            oneInfo = {"describe": 0, "type": 0}
            ea = None
            idx = bytes.find(sig["data"])
            if idx != -1:
                ea = idx

            ## 同一个魔数可能在so文件中出现多次
            while ea != None:
                name = sig["name"]
                offset = hex(ea)
                oneInfo["type"] = 1
                oneInfo["describe"] = name
                found[offset] = oneInfo
                offsets.append(offset)
                idx = bytes.find(sig["data"], ea + sig["size"])
                if idx != -1:
                    ea = idx
                else:
                    ea = None

        # 正则匹配伪C中的魔数初始化，以及哈希运算部分
        for func in idautils.Functions(textStart, textEnd):
            try:
                oneInfo = {'type': 0, "describe": 0, "funcName": 0, "init": 0,
                           "round": 0, "hookOffset": 0}
                decompilerStr = str(idaapi.decompile(func))

                Suspected_magic_num = [i[1] for i in re.findall(
                    "(]|\+ \d{1,3}\)) = -?(0?x?[0-9A-FL]{8,20});",
                    decompilerStr)]
                Suspected_transform_funcs = re.findall(" ([^ (*]{2,}?)\(",
                                                       decompilerStr)[1:]
                funcs_count = list(Counter(Suspected_transform_funcs).values())
                max_func_num = max(funcs_count) if funcs_count else 0

                if len(Suspected_magic_num) >= 3:
                    if hex(func) in offsets:
                        found[hex(func)]["init"] = 1
                    else:
                        functionName = demangle_str(
                            str(idaapi.ida_funcs.get_func_name(func)))
                        oneInfo["type"] = 2
                        oneInfo["funcName"] = functionName
                        oneInfo["init"] = 1
                        found[hex(func)] = oneInfo

                if max_func_num > 60:
                    if hex(func) in offsets:
                        found[hex(func)]["round"] = 1
                    else:
                        functionName = demangle_str(
                            str(idaapi.ida_funcs.get_func_name(func)))
                        oneInfo["type"] = 2
                        oneInfo["funcName"] = functionName
                        oneInfo["round"] = 1
                        found[hex(func)] = oneInfo

            except:
                pass

        funclist, constlist = get_result(found)

        print("***************************在二进制文件中检索hash算法常量************************************")
        for i in constlist:
            print(i[1] + ":" + i[0])

        for i in funclist:
            print(i[2] + ":" + i[1])
        myscript = generate_script(funclist, constlist)

        script_name = so_name.split(".")[0] + "_findhash_" + str(int(time.time())) + ".js"
        save_path = os.path.join(so_path, script_name)
        with open(save_path, "w", encoding="utf-8")as F:
            F.write(myscript)

        # 对哈希相关的字符串和出现的路径进行搜索
        IDAStrings = idautils.Strings()
        IDAStrings = [[str(i), i.ea] for i in IDAStrings]
        hashstring = ["md", "dgst", "digest", "final", "update", "sha"]
        SOURCE_FILES_REGEXP = r"([a-z_\/\\][a-z0-9_/\\:\-\.@]+\.(c|cc|cxx|c\+\+|cpp|h|hpp|m|rs|go|ml))($|:| )"
        Suspected_string = []

        for s, ea in IDAStrings:
            s = demangle_str(s)
            if s and len(s) > 4:
                path = re.findall(SOURCE_FILES_REGEXP, s, re.IGNORECASE)
                if path:
                    Suspected_string.append([ea, path[0][0]])

            for h in hashstring:
                if (h in s) and ("__cxa_finalize" not in s):
                    Suspected_string.append([ea, s])

        print("***************************存在以下可疑的字符串************************************")
        for ea, i in Suspected_string:
            print(f"{hex(ea)}:{i}")

        print("生成对应的hook脚本如下：")
        print(f"frida -UF -l {save_path}")

        print("***********************************************************************************")
        print("花费 %s 秒，因为会对全部函数反编译，所以比较耗时间哈" % (time.time() - start_time))


    def term(self):
        pass


def PLUGIN_ENTRY():
    return findhash()
