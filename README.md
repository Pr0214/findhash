# findhash
在哈希算法上，比Findcrypt更好的检测工具，同时生成Frida hook代码。

### 使用方法
* 把findhash.xml和findhash.py扔到ida plugins目录下
* ida -edit-plugin-findhash

### 试图解决的问题
* 哈希函数的初始化魔数被修改
* 想快速验证所分析的函数中是否使用了MD5，SHA1、SHA2这些哈希算法。
* Findcrypt/Signsrch没找出来


