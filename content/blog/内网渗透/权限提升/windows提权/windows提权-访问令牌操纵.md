---
title: "windows提权-访问令牌操纵"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# windows提权-访问令牌操纵

### Windows访问令牌

令牌（Token）是系统的临时密钥，相当于账户名和密码，用来决定是否允许这次请求和判断这次请求是属于哪一个用户的，它允许你在不提供密码或其他凭证的前提下，访问网络和系统资源，这些令牌持续存在系统中，除非系统重新启动

令牌最大的特点就是随机性，不可预测，一般黑客或软件无法猜测出来，令牌有很多种：

~~~
访问令牌（Access Token）表示访问控制操作主题的系统对象
会话令牌（Session Token）：是交互会话中唯一的身份标识符，可以理解为web中的token
密保令牌（Security Token）又叫作认证令牌或者硬件令牌，是一种计算机身份效验的物理设备
~~~

Windows 的访问令牌（AccessToken） 中包含如下内容

~~~
用户账户的安全标识符(SID)
用户所属的组的SID
用于标识当前登陆会话的登陆SID
用户或用户组所拥有的权限列表
所有者SID
主要组的SID
访问控制列表
访问令牌的来源
令牌是主要令牌还是模拟令牌
限制SID的可选列表
目前的模拟等级
其他统计的数据
~~~

Windows 的访问令牌（AccessToken） 有两种类型

* Delegation Token：授权令牌，也叫主令牌，支持交互式会话登录 (例如本地用户直接登录、远程桌面登录访问)

* Impresonation Token：模拟令牌，支持非交互的会话 (例如使用 net use访问共享文件夹)。

两种 token 只在系统重启后清除，具有 Delegation token 的用户在注销后，该 Token 将变成Impersonation token（模拟令牌），依旧有效

值得一提的是，令牌窃取只能在特权用户上下文中才能完成，因为通过令牌创建进程使用的`CreateProcessWithTokenW`和`CreateProcessAsUserA`两个windows API分别要求用户必须拥有`SeImpersonatePrivilege`和`SeAssignPrimaryTokenPrivilege/SeIncreaseQuotaPrivilege`特权，而拥有这两个特权的用户一般为系统管理员账户、网络服务账户、系统服务账户（IIS、MSSQL等）

### 令牌窃取

该操作往往用来将管理员权限提升至SYSTEM、TrustedInstaller等更高权限，若本地管理员因为某些组策略设置无法获取某些特权，可以通过令牌窃取来假冒`NT AUTHORITY\SYSTEM`的令牌 

#### 利用JCTokenUtil窃取令牌

本来想使用incognito.exe的，但是发现了一款incognito.exe二开工具[JCTokenUtil](https://github.com/chroblert/JCTokenUtil/)，感觉更好用

* 首先上传工具至目标主机，执行命令获取`NT AUTHORITY\SYSTEM`账户的令牌：

  ~~~cmd
  TokenUtil_x64.exe ListTokens -u "NT AUTHORITY\SYSTEM" 
  ~~~

  ![image-20241010205643236](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241010205644421-2139962666.png)

* 再试试用获取到的`NT AUTHORITY\SYSTEM`账户令牌执行命令：

  ~~~cmd
  TokenUtil_x64.exe Execute -p 304 -e whoami -c 
  ~~~

  ![image-20241010205755170](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241010205755669-1838553159.png)

#### 利用metasploit窃取令牌

msf同样内置了incognito框架，可以直接使用

* 首先使用msf控制目标主机的管理员权限：

  ![image-20241010210909417](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241010210910924-1008461156.png)

* 加载incognito，进行令牌窃取，用法如下：

  ~~~sh
  load incognito #加载incognito
  list_tokens -u #列举token令牌
  impersonate_token "NT AUTHORITY\SYSTEM" #权限窃取
  rev2self 或 drop_token #返回之前的token
  ~~~

  ![image-20241010211514549](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241010211515673-336327924.png)

#### 通过令牌获取TrustedInstaller权限

即使获取了system权限，也无法修改windows系统文件：

而从Windows vista开始系统内置了一个TrustedInstaller安全主体，拥有系统文件修改权限，专用于对系统进行修改、更新等操作，而其以一个账户的形式出现，即`NT SERVICE\TrustedInstaller`，那么我们便可以尝试进行令牌窃取

TrustedInstaller本身也是一个服务，该服务启动时会运行`C:\Windows\servicing\TrustedInstaller.exe`程序，其拥有者为`NT SERVICE\TrustedInstaller`，可以借此进行窃取：

* 首先启动TrustedInstaller服务并记住token：

  ~~~cmd
  sc start TrustedInstaller
  ~~~

  ![image-20241010214800908](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241010214802738-613089295.png)

* 根据PID窃取token：

  ~~~sh
  sc stop TrustedInstaller
  ~~~

  ![image-20241010220632312](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241010220633133-1139526919.png)

### potato家族提权

potato家族是一种非常常用的提权技术，通过操纵访问令牌，可将已获取的服务账户权限提升至SYSTEM，总的来说可以理解为NTLM反射的应用

#### 基本原理

##### SeAssignPrimaryTokenPrivilege 权限

* System帐号（也叫LocalSystem）的交互服务与非交互服务初始特权都一样
* 非System帐号的特权数一样（与具体帐号有关），只是做为服务的程序大部分特权初始都是关闭的，需要服务自己根据需要打开（Enable）
* System帐号的特权比Administrator帐号多出几个特权：`SeAssignPrimaryTokenPrivilege`，`SeLockMemoryPrivilege`，`SeTcbPrivilege`，`SeCreatePermanentPrivilege`，`SeAuditPrivilege`；但 `Administrator` 帐号多了一个`SeRemoteShutdownPrivilege` 特权
* 除了System帐号，其他帐号是不可能运行在TCB（Trusted Computing Base）中的

##### 基本利用思路

利用Potato提权的是前提是拥有 `SeImpersonatePrivilege` 或`SeAssignPrimaryTokenPrivilege`权限，以下用户拥有`SeImpersonatePrivilege`权限：

* 本地管理员账户(不包括管理员组普通账户)和本地服务账户
* Windows服务的登陆账户
* Local System(NT AUTHORITY\SYSTEM)
* Network Service(NT AUTHORITY\Network Service)
* Local Service(NT AUTHORITY\Local Service)

所以提权方向：

`Administrator ——> SYSTEM Service ——> SYSTEM`

服务账户在 `windows` 权限模型中本身就拥有`很高的权限`，所以在实战场景中，若成功拿到了IIS等服务的 WebShell 或者通过 MSSQL 服务的xp_cmdshell 成功执行了系统命令，此时获取的服务账户拥有`SeImpersonatePrivilege` 和`SeAssignPrimaryTokenPrivilege` 特权，就可以通过 Potato 家族提升至 SYSTEM 权限

当用户具有`SeImpersonatePrivilege`特权，则可以调用`CreateProcessWithTokenW`时以某个Token的权限启动新进程
当用户具有`SeAssignPrimaryTokenPrivilege`特权，则可以调用`CreateProcessAsUserW`以`Token`权限启动新进程

#### Origin Potato_MS08-068 (土豆始祖漏洞）

SMB协议中一个公开披露的漏洞。该漏洞可能允许在受影响的系统上执行远程代码。成功利用此漏洞的攻击者可以安装程序；查看、更改或删除数据；或创建具有完全用户权限的新账户

本质上是一个类似于HTLM relay 的漏洞

#### MS16-075_HOT Potato (MS08-068的变种)

一个典型的 `NTLM_RELAY` 利用链,需要等待 `windows update`

利用环境：`DBNS`欺骗，`WPAD` 和 `Windows update` 服务,按照Relay的一般流程，我们从三方面着手，将思路串起来，达到本地提权的效果

* **怎么发起ntlm请求**
  发起ntlm请求的方式:
  配合NBNS投毒欺骗和伪造WPAD代理服务器拿到用户的 `Net-NTML hash`，所有的HTTP请求将会被重定向至 "http://localhost/GETHASHESxxxxx" ，其中的xxxxx表示的是某些唯一标识符。将会影响目标主机中所有的用户，包括管理员账户和系统账户

* **拿到ntlm 请求之后要做什么**
  MS08-068虽然限制了同台主机之间smb到smb的Relay，但是并没有限制从http到smb，我们配置配合NBNS投毒欺骗和伪造WPAD代理服务器拿到的ntlm请求说http的形式，我们可以直接relay 到本机的smb。

* **服务端是否要求签名**
  我们Relay到的服务端协议是smb，除非是域内的域控，不然在工作组环节底下，或者域内的域成员机器，都是不要求签名的。

#### ghost potato

因为ms08-068补丁存在漏洞导致，补丁后的ntlm：

当我们存在两个主机进行SMB通信时，A向B发送了type1请求，同时他将自己的pszTargetName设置为`cifs/B`, 当拿到type2的challenge时，向lsass进程中写入缓存 -> (Challenge,`cifs/B`)。 而后A向B发送type3，B收到response后，会到lsass中去寻找是否存在缓存(Challenge,`cifs/B`), 因为只有A主机写入了缓存，所以如果A和B不是同一个主机，那么肯定B主机不存在缓存，认证成功。

然而，这个缓存只有300s的时效，300s后会被清空，那么此时即便是ntlm relay到本机，补丁也不起作用

#### Rotten Potato

ms16-075的一个变种，是一个本地提权手法，不能用于域用户提权，可以将权限提升至`NT AUTHORITY \ SYSTEM`

通过 `DCOM call` 来使服务向攻击者监听的端口发起连接并进行 `NTLM` 认证,需要`SelmpersonatePrivilege`权限

此时，如果要模拟令牌，最好以具有SeImpersonate特权（或等效特权）的帐户运行。幸运的是，这包括Windows中的许多服务帐户，渗透测试人员通常最终以这些帐户运行。例如，IIS和SQL Server帐户

大致原理如下：

>（1）欺骗“NT AUTHORITY\SYSTEM”帐户通过 NTLM 对我们控制的 TCP 端点进行身份验证。
>（2）中间人此身份验证尝试（NTLM 中继）在本地协商“NT AUTHORITY\SYSTEM”帐户的安全令牌。这是通过一系列 Windows API 调用完成的。
>（3）冒充我们刚刚协商好的令牌。仅当攻击者当前帐户有权模拟安全令牌时，才能做到这一点。这通常适用于大多数服务帐户，而不适用于大多数用户级帐户。

优点：

>1. 100%可靠
>2. 全版本通杀
>3. 立即生效，不用像hot potato那样有时候需要等Windows更新才能使用。

#### Juicy Potato

ms16-075的一个变种，原理和rotten potato几乎相同，只是增加了一点扩展https://github.com/ohpe/juicy-potato

UknowSec还有一个二开版本，自行了解

利用链如下：

* 加载COM，发出请求，权限为 `System`,在指定ip和端口的位置尝试加载一个COM对象。

  `RottenPotatoNG` 使用的 COM 对象为 BITS ，CLSID为`{4991d34b-80a1-4291-83b6-3328366b9097}`
  可供选择的COM对象不唯一，`Juicy Potato` 提供了多个，详细列表可参考地址：https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

* 回应步骤1的请求，发起NTLM认证，正常情况下，由于权限不足，当前权限不是System，无法认证成功。

* 针对本地端口，同样发起NTLM认证，权限为当前用户。由于权限为当前用户，所以NTLM认证能够成功完成。`RottenPotatoNG` 使用的 `135` 端口。

`Juicy Potato` 支持指定任意本地端口，但是RPC一般默认为135端口，很少被修改。

* 分别拦截两个`NTLM`认证的数据包，替换数据，通过NTLM重放使得步骤1(权限为`System`)的NTLM认证通过，获得`System`权限的`Token`,重放时需要注意`NTLM`认证的`NTLM Server Challenge`不同，需要修正。

* 利用`System`权限的`Token`创建新进程

* 如果开启SeImpersonate权限，调用CreateProcessWithToken，传入System权限的Token，创建的进程为System权限。

* 如果开启SeAssignPrimaryToken权限，调用CreateProcessAsUser，传入System权限的Token，创建的进程为System权限

上面两个potato仅适用于win10 v1809和win server 2019之前版本的系统，在之后的版本中，微软通过检查RPC绑定字符串中指定的端口来修复了该问题，无法再使用原来的方法进行中间人攻击

#### PrintSpoofer（Pipe Potato）

通过Windows named pipe的一个API: `ImpersonateNamedPipeClient`来模拟高权限客户端的token（还有类似的`ImpersonatedLoggedOnUser`，`RpcImpersonateClient`函数），调用该函数后会更改当前线程的安全

但当传递`\\127.0.0.1/pipe/foo`时，校验路径时会认为`127.0.0.1/pipe/foo`是主机名，随后在连接`named pipe`时会对参数做标准化，将`/`转化为`\`，于是就会连接`\\127.0.0.1\pipe\foo\pipe\spoolss`，攻击者就可以注册这个`named pipe`从而窃取`client`的`token`

简单来说就是：利用了打印机组件路径检查的BUG，使`SYSTEM`权限服务能连接到攻击者创建的`named pipe`

#### Sweet Potato

`Juicy Potato` 的重写https://github.com/CCob/SweetPotato

`COM/WinRM/Spoolsv` 的集合版，也就是 `Juicy/PrintSpoofer`，可用于从Windows 7 到 windows10/windows server2019的本地服务到system特权升级
