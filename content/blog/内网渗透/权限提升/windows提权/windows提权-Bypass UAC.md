---
title: "windows提权-Bypass UAC"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# windows提权-Bypass UAC

大多数应用程序都是以中级别完整性运行的，包括本地管理员会话，但如果选择“以管理员身份”运行，可以从中级别完整性提升到高级别，但这个过程会有UAC对话框弹出：

![image-20241231143754429](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241231143754429.png)

用户账户控制（User Accou Control），一种安全机制，开启后，每个需要使用到管理员访问令牌的应用都需要征得管理员同意

UAC限制的用户：除Administrator（RID 500）的所有用户（包括非RID 500的管理员）

非RID 500管理员用户登录后，系统会为其创建两个单独的访问令牌：

* 标准访问令牌
* 管理员访问令牌

管理员正常启动不执行管理任务的应用就是使用的标准访问令牌，当要执行高权限管理任务就需要使用管理员访问令牌，就会触发UAC弹窗

而Bypass UAC，实际上就是绕过上面所说的安全机制，使非RID 500的管理员账户可以直接调用管理员访问令牌来获取全部管理员权限，这仅仅是绕过了保护机制，不是真正意义上的提权（和linux的rbash逃逸的感觉相似）

### UAC白名单

微软在UAC中为一部分系统程序设置了白名单，白名单中的程序能够用静默的方式自动提升到管理员权限运行，比如rundll32.exe、explorer.exe

可以通过微软官方提供的工具Sigcheck和Strings来寻找白名单程序，白名单程序的Mainifest数据中autoElivate属性值为true，检测工具大多也是检测这个属性

我们可以通过对这些白名单程序进行DLL劫持、DLL注入、注册表劫持，实现Bypass UAC

### DLL劫持

和我linux提权文章中写的so共享库劫持原理相似

程序启动时DLL的加载顺序如下:

- 1.程序所在目录
- 2.程序加载目录（SetCurrentDirectory）
- 3.系统目录即 SYSTEM32 目录
- 4.16位系统目录即 SYSTEM 目录
- 5.Windows目录
- 6.PATH环境变量中列出的目录

PS：Windows操作系统通过“DLL路径搜索目录顺序”和“Know DLLs注册表项”的机制来确定应用程序所要调用的DLL的路径，之后，应用程序就将DLL载入了自己的内存空间，执行相应的函数功能

我只需要将同名恶意dll的位置放在合法dll的搜索目录之前，加载的时候就实现了劫持

### 模拟可信任目录

程序请求自动提升权限的条件：

- 文件Manitest中autoElevate属性的值为True

- 检查文件的签名

- 文件是否位于系统可信任目录中

系统在检查可信任目录时，相关函数会自动去掉可执行文件路径中的空格。如果可执行文件位于“C:\windows \system32”目录（在windows后有一个空格，下文统称“模拟可信任目录”）中，系统在检查时会自动去除路径中的空格，这样就通过了最后一个条件的检查

那么根据可信任目录来创建一个包含尾随空格的模拟可信任目录，将一个白名单程序复制到模拟可信任目录中，配合DLL劫持等技术即可成功绕过UAC

比如：

~~~cmd
md "\\?\c:\windows "
md "\\?\c:\windows \System32"
copy c:\windows\system32\winSAT.exe "\\?\c:\windows \System32\winSAT.exe"
~~~

接下来可以编写一个恶意的dll文件并将其放入该目录进行dll劫持，注意构造的dll需要与原来的dll具有相同的导出函数

### 相关工具

#### UACME

[hfiref0x/UACME: Defeating Windows User Account Control](https://github.com/hfiref0x/UACME)

集成了n种bypass UAC方法，具体使用看readme吧

#### msf

msf也集成了几个绕过模块，在bypass之后，执行getsystem可以直接提升至system权限