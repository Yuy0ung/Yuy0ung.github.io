---
title: "Windows协议之NTLM"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# Windows协议之NTLM

NTLM协议（New Technology LAN Manager）协议是微软用于**Windows身份验证**的主要协议之一

早期SMB协议以明文口令的形式在网络上传递，存在安全性问题，进而出现了LM（LAN manager）协议，然而该协议因为太简单，还是容易被破解，微软进而提出了NTLM协议

NTLM协议既可用于工作组环境中的机器身份验证，又可用于域环境身份验证，还可以为 SMB、HTTP、LDAP、SMTP 等上层微软应用提供身份验证

值得一提的是：NTLM是底层的认证协议，必须嵌入上层应用协议中，消息的传输依赖于使用NTLM的上层协议，比如SMB、HTTP等

### 一、SSPI与SSP的概念

##### 1.SSPI

SSPI（Security Service Provider Interface，安全服务提供接口）是windows定义的一套接口，该接口定义了与安全有关的功能函数，包含但不限于：

* 身份验证机制
* 为其他协议提供的session security（会话安全）机制，会话安全可为通信提供数据的完整性校验以及数据的加密、解密功能

注意：SSPI只是定义了一套接口函数，并没有实现具体内容

##### 2.SSP

SSP（Security Service Provider，安全服务提供者）是SSPI的实现者，微软自己实现了很多SSP，用于提供安全功能，例如：

* NTLM SSP：Windows NT 3.51中引入（msv1_0.dll），为Windows 2000之前的客户端-服务器域和非域身份验证（SMB/CIFS）提供 NTLM 质询/响应身份验证
* Kerberos SSP：Windows 2000中引入，Windows vista中更新为支持AES（kerberos.dll），Windows 2000及更高版本中首选的客户端-服务器域相互身份验证
* Digest SSP：Windows XP中引入（wdigest.dll），在 Windows 与 kerberos 不可用的非Windows系统间提供基于 HTTP 和 SASL 身份验证的质询/响应
* Negotiate SSP:Windows 2000 中引入（secur32.dll) ，默认选择 Kerberos，如果不可用则选择 NTLM 协议。Negotiate SSP 提供单点登录能力，有时称为集成 Windows 身份验证（尤其是用于 IIS 时)。在 Windows 7 及更高版本中，NEGOExts 引入了协商使用客户端和服务器上 支持的已安装定制 SSP 进行身份验证
* Cred SSP:Windows Vista 中引入，Windows XP SP3 上也可用 （credssp.dll)，为远程桌面连接提供单点登录（SSO)和网络级身份验证
* Schannel SSP:Windows 2000 中引入（Schannel.dll)，Windows Vista 中 更新为支持更强的 AES 加密和 ECC[6] 该提供者使用 SSL/TLS 记录来加密数据有效载荷
* PKU2U SSP:Windows 7 中引入（pku2u.dll) ， 在不隶属域的系统之间提供使用数字证书的对等身份验证

因为SSPI中定义了与session security有关的API，所以上层应用利用任何SSP与远程的服务进行身份验证后，此SSP都会为本次连接生成一个随机key，这个key被称为session key。上层应用经过身份验证后，可以选择性的使用这个key对之后发往服务端或接收自身服务端的数据进行签名或加密

在系统层面，SSP就是一个dll（动态链接库），用来实现身份验证等安全功能。不同的SSP实现的身份验证机制是不一样的，比如NTLM SSP实现的是一种基于质询/响应的身份验证机制，而Kerberos SSP实现的是基于Ticket（票据）的身份验证机制，我们也可以编写自己的SSP并将其注册到操作系统中，让操作系统支持我们自定义的身份验证方法

可以用一张图表示SSPI、SSP和各种应用的关系：

![image-20240527224739470](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240616204731100-347079760.png)

### 二、LM Hash 加密算法

LM是微软推出的一个身份认证协议，使用的加密算法是LM Hash，此加密的本质是DES加密，虽然其容易被破解，但为了保证系统兼容性，windows只是将LM Hash禁用（从windows vista和windows server 2008开始默认禁用）

LM Hash明文密码被限定在14位以内，也就是说，若要停止使用LM Hash，将用户的密码设置为14位以上即可，如果攻击者抓取的LM Hash为"aad3b435b51404eeaad3b435b51404ee"，说明LM Hash为空值或被禁用了

### 三、NTLM Hash加密算法

NTLM Hash加密算法是微软为了在提高安全性的同时，保证兼容性而设计的散列加密算法，它是基于MD4加密算法进行加密的

为了解决LM Hash加密和身份验证方案中固有的安全弱点，微软于1993年在windows NT 3.1中首次引入了NTLM Hash，从windows vista和windows server 2008开始，默认禁用了LM Hash，只存储NTLM Hash，而LM Hash的位置则为空:

~~~NTLM Hash
aad3b435b51404eeaad3b435b51404ee
~~~

##### 1.NTLM Hash加密流程

NTLM Hash是由明文密码经过三步加密而成：

~~~NTLM
NTLM Hash =md4(unicode(hex(password)))
~~~

具体如下：

* 先将用户密码转换为16进制格式
* 再将16进制格式的字符串进行ASCII转Unicode编码
* 最后对Unicode编码的16进制字符串进行标准MD4单向哈希加密

##### 2.windows系统存储的NTLM Hash及NTLM本地认证

用户的密码经过NTLM Hash加密后存储在`C:\Windows\system23\config\SAM`文件中

在用户输入密码进行身份验证的过程中，所有操作都是在本地进行的。系统将用户输入的密码转换为NTLM Hash，再将其与SAM中的NTLM Hash文件进行比较，若相同则说明密码正确，反之则为错误。当用户注销、重启、锁屏后，操作系统会让winlog.exe显示登陆界面，即密码输入框，在winlog.exe程序接收到输入之后，会将密码交给lsass.exe进程，lsass.exe进程中会存储一份明文密码，并将其加密成NTLM Hash，与SAM数据库进行比较和认证

在上述过程中，有个lsass.exe进程，我们在渗透过程中使用的Mimikatz就是从该进程中抓取的明文或Hash密码

使用MSF或CS通过转储Hash抓到的密码格式如下：

~~~hash
用户名:用户SID:LM Hash:NTLM Hash:::
~~~

### 四、NTLM协议认证

NTLM协议是一种基于Challenge/Response（质询/响应）的验证机制，由三种类型消息组成：

* Type 1（协商，Negotiate）
* Type 2（质询，Challenge）
* Type 3（认证，Authentication）

##### 1.工作组环境下的NTLM认证

工作组环境下的NTLM认证如下：

* 当客户端需要访问服务器的某个服务时，就需要进行身份验证。在客户端输入服务器的用户名和密码进行验证后，就会缓存用户输入的服务器密码的NTLM Hash值，然后，客户端会向服务端发送一个请求，该请求利用NTLM SSP生成NTLMSSP_NEGOTIATE消息（被称为Type 1协商消息）

* 服务端接收到客户端发送过来的Type 1消息后，读取其中的内容，并从中选择自己所能接受的服务内容、加密等级、安全服务等，然后传入NTLM SSP得到NTLMSSP_CHALLENGE消息（被称为Type 2质询消息），并将此Type 2消息发回给客户端，消息中包含一个由服务器生成的16位随机值，被称为challenge值，服务端收到后会对其进行缓存

* 客户端收到服务端返回的Type 2消息后，读取服务端所支持的内容，并取出其中的challenge值，用缓存的NTLM Hash对其进行加密得到Response信息，最后将Response、用户名、challenge等信息组合得到Net-NTLM Hash，再将Net-NTLM Hash封装到NTLMSSP_AUTH消息中（被称为Type 3认证消息），发送给服务端

  服务端收到认证消息后，从Net-NTLM Hash中取出response，然后用自己密码的HTLM Hash对challenge值进行加密，得到自己的response，将客户端发送的response和自己的作比较判断是否相等，若相等，则证明客户端输入的密码正确，认证成功，反之则认证失败


可画一张图概括一下：

![image-20240529155528371](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240616204742391-933789950.png)

##### 2.域环境下的NTLM认证

与工作组环境不同，在域环境中，所有域用户的Hash都存储于域控的NTDS.dit中，所以服务器本身无法计算response进行验证，所以需要与域控建立安全通道，通过域控完成最终的认证流程

步骤如下：

* Type1同工作组环境
* Type2同工作组环境
* Type3同工作组环境
* 服务端收到客户端发来的Type3消息后，通过Netlogon协议与域控建立一个安全通道，将验证消息转发给域控
* 域控根据Type 3消息中的用户名，在NTDS.dit中获取用户的NTLM Hash对challenge进行加密得到response，将其与Type 3消息中的response进行对比，若一致，则密码正确，认证成功，反之则失败
* 服务端根据域控返回的结果，对客户端进行相应的回复

画一张图来描述：

![3450279-20240616204751686-1940031638](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240618181052281-566552702.png)

##### 3.NTLM v1与NTLM v2的区别

NTLM协议有NTLM v1和NTLM v2两个版本，目前使用最多的是NTLM v2，两者最显著的区别是Challenge值和加密算法不同，共同之处是都是用NTLM Hash进行加密。另外，NTLM v2存在一个扩展版本NTLM v2 Session，强化了对会话安全性的支持

* challenge值：
  * NTLM v1：8B
  * NTLM v2：16B
* Net-NTLM Hash使用的加密算法
  * NTLM v1：DES加密算法
  * NTLM v2：HMAC-MD5加密算法

Net-NTLM Hash v1和Net-NTLM Hash v2的构成格式如下：

~~~Net-NTLM Hash
# Net-NTLM Hash v1
username::hostname:LM response:NTLM response:challenge
# Net-NTLM Hash v2
username::domain:challenge:HMAC-MD5:blob
~~~

通过 Mimikatz 操作 LSASS 抓取NTLM Hash的操作受到了 Windows 10企业版和 Windows Server 2016中的凭证保护的限制，可以使用工具InternalMonologue.exe在不接触 lsass.exe进程的情况下抓取Net-NTLM Hash v1并转换为相应的NTLM Hash

##### 4.LmCompatibilityLevel

LmCompatibilityLevel值用来确定网络登录使用的质询/响应身份验证协议。该选项会影响客户端使用的身份验证协议的等级、协商的会话安全的等级以及服务器接受的身份验证的等级，其值对应含义如下表：

![屏幕截图 2024-05-30 172409](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240616204758612-1185699058.png)

LmCompatibilityLevel值的修改通常有两种方法： 

* 手动修改本地安全策略
* 命令修改注册表lmcompatibilitylevel的值

### 五、NTLM协议的安全问题

从NTLM认证的流程中可以看到，在Type 3认证消息中是使用用户密码的HTLM Hash进行response消息的计算的，因此，在没有拿到用户密码的明文而只拿到Hash的情况下，可以进行PTH（Pass The Hash，哈希传递）攻击。同样，在Type 3消息中还存在Net-NTLM Hash，当获得了Net-NTLM Hash后，可以进行中间人攻击，重放Net-NTLM Hash，即NTLM Relay（NTLM 中继）攻击。由于NTLM v1协议加密过程存在天然缺陷，因此可以对Net-NTLM v1 Hash进行破解，得到NTLM Hash之后即可横向移动

（本文只对安全问题稍作介绍，后续另写文章详细研究）

##### 1.pass the hash

哈希传递攻击是内网横向移动的一种方式，因为NTLM认证过程中是使用用户密码的NTLM Hash来对challenge进行加密从而得到response，所以当获取到用户的HTLM Hash而未解出明文密码时，可以利用该NTLM Hash进行PTH攻击，对内网其他机器进行Hash碰撞，碰撞到使用相同密码的主机即可通过135或445端口进行横向移动

##### 2.NTLM Relay

严格来看，NTLM Relay的称法并不准确，而应该叫Net-NTLM Relay。作为中间人，攻击者将来自客户端的 type 1  消息转发给服务端，将来自服务端的 type 2 消息转发给客户端，而攻击发生在NTLM认证的第三步，因为 type 3 消息中存在客户端计算好的Net-NTLM Hash，所以在获取到 type 3 消息后，中间人直接将其转发给服务端，服务端验证通过后，会授予攻击者访问的权限，而不授予客户端

可用图片概括上述过程：

![image-20240530200806710](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240616204807160-673217470.png)

##### 3.Net-NTLM v1 Hash破解

由于NTLM v1身份认证协议加密过程存在天然缺陷，只要获取到Net-NTLM v1 Hash，就能破解为NTLM Hash，这与密码强度无关。在域环境中，该缺陷更为突出，因为在域中使用Hash即可远程连接目标机器。若域控允许发送NTLM v1响应，我们就可以通过与域控机器进行NTLM认证，然后抓取域控的Net-NTLM v1 Hash，破解为NTLM Hash。使用域控的机器账户和Hash即可导出域内所有用户Hash（自从Windows Vista开始，微软就默认使用NTLM v2身份认证协议，要想降级到NTLM v1的话，需要手动进行修改，并且需要目标主机的管理员权限才能进行操作）
