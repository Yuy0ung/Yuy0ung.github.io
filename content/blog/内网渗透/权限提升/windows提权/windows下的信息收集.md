---
title: "windows下的信息收集"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 权限提升-windows下的信息收集

进入内网后，可以通过信息收集扩展攻击面，找到更多可能导致权限提升的入口点

### 服务器信息枚举

##### 版本信息

查看系统版本号：

~~~cmd
ver
~~~

##### 架构信息

获取到服务器架构信息，有助于后续选择对应的漏洞利用程序或编写exp和payload

~~~cmd
wmic os get osarchitecture
~~~

或

~~~cmd
echo %PROCESSOR_ARCHITECTURE%
~~~

##### 服务信息

获取服务信息可以得知系统服务的进程ID、启动方式和状态，效果类似于运行services.msc

~~~cmd
sc query state=all
~~~

或

~~~powershell
wmic service list brief
~~~

powershell命令获取服务及服务对应的执行文件路径和参数：

~~~powershell
Get-wmiObject win32_service | select Name,PathName
~~~

##### 进程信息

获取系统进程:

~~~cmd
tasklist
~~~

获取进程信息:

~~~cmd
tasklist /svc
~~~

使用wmic命令获取系统进程信息：

~~~cmd
wmic process list brief
~~~

也可以使用powershell cmdlet命令：

~~~powershell
ps
~~~

或

~~~powershell
Get-WmiObject -Query "select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select-Object Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | Format-Table -AutoSize
~~~

##### 驱动信息

获取当前系统中安装的服务器驱动程序信息：

~~~cmd
driverquery
~~~

服务器驱动程序信息有助于我们发现可能存在漏洞的驱动，进而去搜索漏洞利用程序进行提权

##### 磁盘信息

获取计算机的全部磁盘信息：

~~~powershell
wmic logicaldisk get caption,description,providername
~~~

获取某个磁盘的文件夹树并将结果输出到文件夹中：

~~~cmd
tree D:\ >E:\Desktop\tree.txt
~~~

获取某个磁盘的文件列表并将结果输出到文本文件中：

~~~cmd
dir /s D:\ >E:\Desktop\tree.txt
~~~

##### 补丁信息

获取系统补丁情况：

~~~cmd
wmic qfe get Caption,Description,HotFixID,InstalledOn
~~~

也可以使用Powershell cmdlet命令：

~~~powershell
Get-wmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid}
~~~

或

~~~powershell
Get-Hotfix
~~~

在获取到系统补丁情况后，我们能够查询当前系统是否存在未修复的漏洞，有助于利用系统漏洞进行本地权限提升

##### 系统信息

获取系统信息：

~~~cmd
systeminfo
~~~

另外，计算机名可能与管理员的个人信息、个人习惯或内网服务器的命名规则有关，也可以直接使用cmd命令获取：

~~~cmd
hostname
~~~

##### 应用程序信息

可以使用powershell-cmdlet命令查看系统安装的应用程序信息

通过查询注册表的方式：

~~~powershell
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
~~~

通过列出程序安装文件夹的方式：

~~~powershell
Get-ChildItem 'C:\Program Files','C:\Program File (x86)' | ft Parent,Name,LastWriteTime
~~~

通过获取WMI对象的方式：

~~~powershell
Get-WmiObject -Class Win32_product
~~~

也可以执行cmd命令获取应用程序信息：

~~~cmd
wmic product get name,version
~~~

**TIPS**:在Metasploit的meterpreter命令行下，可使用模块**post/windows/gather/enum_applications**枚举系统中安装的应用程序

检索服务器上是否安装了.NET及.NET的版本信息：
~~~cmd
reg query "HKLM\Software\Microsoft\NET Framework Setup\NDP" /s /v version | findstr /i version | sort /+26 /r
~~~

判断服务器是否安装了PowerShell，查看PowerShell引擎版本信息

~~~cmd
reg query "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion
~~~

在获取到系统信息应用程序的安装情况后，我们可以查询是否存在可能有漏洞的应用程序，或获取有更多敏感系统信息的第三方应用，有助于提升权限

##### 计划任务信息

获取服务器的计划任务信息：

~~~cmd
schtasks /query /fo LIST /v		#查看全部计划任务
schtasks /query /fo LIST /v | findstr /v "\Microsoft"	#排除默认的windows任务
~~~

也可以执行powershell cmdlet命令获取计划任务信息：

~~~powershell
Get-ScheduledTask	#查看全部计划任务
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State,Author	#排除默认的windows任务
~~~

获取到服务器的计划任务情况后，我们可以检查当前用户对某些高权限用户运行的计划任务所对应的目录或文件是否具有修改权限，若有修改权限，可以将目标程序替换为后门程序，从而实现权限提升

##### 开机启动信息

获取开机启动项文件：

~~~cmd
wmic startup get caption,command,location
~~~

获取某个用户的开机启动项文件夹：

~~~cmd
dir "C:\Users\<用户名>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
~~~

列出对所有用户都有效的开机启动项文件夹：

~~~cmd
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
~~~

查看注册表中的开机启动项：

~~~cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
~~~

查询到开机启动项文件夹或注册表中的开机启动项文件之后，我们可以通过查看当前用户是否对这些文件有写入或修改等权限，来判断是否能够权限提升                                                                                                                                                                                                                                                     

##### 环境变量信息

环境变量是计算机中一个动态“对象“，包含可编辑的值，用于存储有关操作系统环境的信息（比如系统路径、应用程序设置、系统参数等），可以被系统中的一个或多个软件使用，用来帮助应用程序了解文件的安装位置、临时文件的存储位置等

通过使用环境变量，操作系统和软件可以更好的交互，从而提高整体的可读性和可维护性

获取环境变量：

~~~cmd
set
~~~

使用powershell cmdlet命令获取环境变量信息

~~~powershell
Get-ChildItem Env: | ft Key,Value
~~~

或

~~~cmd
dir env:
~~~

### 网络信息枚举

##### IP信息

使用cmd获取本机IP地址、DNS、网关等配置信息：
~~~cmd
ipconfig/all
~~~

##### 端口信息

查看计算机当前的网络状态和监听的端口以及相应的进程ID：

~~~cmd
netstat -ano
~~~

* -a 参数显示计算机所有的连接和监听端口
* -n 参数以数字形式显示地址和端口号
* -o 参数显示与每个连接相关的进程ID

##### 网络接口信息

powershell cmdlet命令获取计算机的网络适配器名称、描述、IP地址和IP段：

~~~powershell
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
~~~

##### 路由信息

路由表是一种由网络路由器使用的数据结构，用于存储网络路径的信息，包括目的地址、网关地址、接口以及路由标志等；通过查看当前系统的路由表，可以帮助我们了解系统的路由器情况

获取路由表信息：

~~~cmd
route print
~~~

也可以执行powershell cmdlet命令获取路由表信息

~~~powershell
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
~~~

##### 共享信息

显示或配置当前计算机的共享资源，包括共享文件夹，打印机等

~~~cmd
net share
~~~

或

~~~powershell
wmic share get name,path,status,caption
~~~

也可以使用metasploit的post/windows/gather/enum_shares模块获取共享信息

### 用户信息枚举

##### 当前用户信息

执行cmd命令 **“whoami /all”**，查看当前用户名、SID、所属组、权限分配信息

值得注意的是组名中的 **“Mandatory Label”**，意思是“强制性标签”；在windows系统中，这个标签表示进程运行的完整性级别，级别从低到高依次为：

* Untrust
* Low
* Medium
* High
* System

级别越低，权限越低

##### 所有用户/组信息

查看服务器上所有用户账户（不能列出用户名结尾添加了“$”符号的隐藏用户）：
~~~cmd
net user
~~~

powershell cmdlet命令获取更详细的信息，包括隐藏账户、是否启用、上次登录时间：

~~~cmd
Get-LocalUser | ft Name,Enable,LastLogon
~~~

通过注册表查看服务器中的用户账户：

~~~cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
~~~

执行上面的命令，在每行账户的末尾都存在SID，可以根据SID查看用户名：

~~~cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<用户SID>" /v ProfileImagePath
~~~

列出C:\Users\文件夹下的目录也可以查看服务器上存在的用户：

~~~cmd
Get-ChildItem C:\Users -Force | select Name
~~~

cmd命令查看服务器所有用户组：

~~~cmd
net localgroup
~~~

powershell cmdlet命令查看用户组：

~~~powershell
Get-LocalGroup
~~~

cmd命令获取某个用户信息：

~~~cmd
net user <用户名>
~~~

获取某个组里有哪些用户：

~~~cmd
net Localgroup <组名>
~~~

powershell命令获取组中的用户：
~~~powershell
Get-LocalGroupMember <组名> | ft Name, PrincipalSource
~~~

##### 在线用户信息

cmd命令获取当前在线用户、状态、空闲时间和登录时间等信息：

~~~cmd
query user
~~~

或

~~~cmd
qwinsta
~~~

获取在线用户信息，有助于渗透测测试人员掌握管理员的工作时间，以规避在管理员在线时进行提权等操作

##### 用户策略信息

cmd命令获取用户策略信息：

~~~cmd
net accounts
~~~

获取用户策略信息，包括密码锁定阈值等，有助于爆破等操作

### 防护软件枚举

##### 防火墙状态

获取系统防火墙策略及状态

~~~cmd
netsh advfirewall show allprofiles
~~~

使用powershell命令列出防火墙阻止的所有端口：

~~~powershell
$f=New-object -comObject HNetCfg.FwPolicy2;$f.rules | where {$_.action -eq "0"} | select name,applicationname,localports
~~~

##### windows defender状态

powershell cmdlet获取系统windows defender状态：

~~~powershell
Get-MpComputerStatus
~~~

常见字段含义：

* AntivirusEnabled:防病毒软件是否启用
* RealTimeProtectionEnabled：实时保护是否已开启

powershell cmdet添加检查排除项（需要管理员权限执行）：
~~~powershell
Add-MpPreference -ExclusionPath "C:\Temp"	#排除文件夹
Set-MpPreference -ExclusionProcess "beacon.exe"	#排除某进程
~~~

powershell cmdet关闭windows defender实时保护（需要管理员权限执行，且已关闭篡改防护）：

~~~powershell
Set-MpPreference -DisableRealtimeMonitoring $true
~~~

##### 常见的防护软件进程

* 360系列：360tray.exe/360safe.exe/ZhuDongFangYu.exe/360sd.exe
* QQ电脑管家：QQPCRTP.exe
* Avira（小红伞）：avcenter.exe/avguard.exe/avgnt.exe/sched.exe
* 安全狗：SafeDogGuardCenter.exe等带有safedog字符的进程
* D盾：D_Safe_Manage.exe/d_manage.exe
* 火绒：hipstray.exe/wsctrl.exe/usysdiag.exe
* 卡巴斯基：avp.exe
* Mcafee：Mcshield.exe/Tbmom.exe/Frameworkservice.exe
* ESET NOD32：egui.exe/ekrn.exe/eguiProxy.exe
* 赛门铁克：ccSetMgr.exe
* 趋势杀毒：TMBMSRV.exe
* 瑞星杀毒：RavMonD.exe

盲目地向服务器上传利用工具或代码很容易触发服务器地防护软件。所以，在获取到服务器的防火墙状态和安全软件信息后，我们要知道服务器中是否存在可能会暴露我们行踪的防护软件，根据获得的信息，进行针对性的免杀
