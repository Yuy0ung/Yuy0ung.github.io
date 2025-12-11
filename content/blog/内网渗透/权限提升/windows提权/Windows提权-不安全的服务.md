---
title: "Windows提权-不安全的服务"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# Windows提权-不安全的服务

windows服务是随着开机而启动的一些可以运行在后台、无需与用户交互、可长时间运行的可执行文件

服务默认的启动账户：

* 本地服务账户（local service）
* 本地系统账户（system）

而不安全的服务配置可能会导致权限提升

### 弱权限的服务配置

由system创建并运行的服务，若普通用户有权限修改服务配置，则可以将BINARY_PATH（可执行文件路径）改为恶意文件路径并重启服务，则可以用system权限执行恶意文件，实现权限提升

利用方法很多这里列举一下：

#### winPEAs

这里更适合CS的场景，当使用CS上线主机之后，可以进行如下操作

查看主机是否支持.NET：

~~~cmd
reg query "HKLM\Software\Microsoft\NET Framework Setup\NDP" /s /v version | findstr /i version | sort /+26 /r
~~~

![image-20240924184516198](https://img2023.cnblogs.com/blog/3450279/202409/3450279-20240924184519069-23427970.png)

这里显示服务器安装了高版本的.NET，那么可以使用从内存加载.NET版本的winpeas无文件落地的方法来查看服务信息：

~~~cmd
execute-assembly winPEASany.exe quiet notcolor servicesinfo
~~~

若不支持或版本较低，可以使用.exe或.bat文件来执行：

~~~cmd
winPEASany.exe quiet notcolor servicesinfo
~~~



#### metasploit

#### powerUp

