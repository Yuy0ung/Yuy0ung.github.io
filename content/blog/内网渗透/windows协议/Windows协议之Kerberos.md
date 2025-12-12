---
title: "Windows协议之Kerberos"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# Windows协议之Kerberos

Kerberos协议一种网络身份验证协议，是一种在开放的非安全网络中认证并识别用户身份信息的方法，旨在使用密钥加密技术为客户端/服务端提供应用程序提供强身份验证

Kerberos本来是西方神话中守卫地狱之门的三头犬的名字，之所以使用这个名字，是因为该协议需要三方共同参与才能完成一次认证。

目前主流使用的Kerberos版本为2005年RFC4120**(https://www.rfc-editor.org/rfc/rfc4120.html)**标准定义的KerberosV5版本，**Windows、Linux和Mac OS均支持Kerberos协议**

### 一、Kerberos基础

在Kerberos协议中，主要有以下三个角色：

* 访问服务的客户端：Kerberos客户端代表需要访问资源的用户进行操作的应用程序，例如打开文件、查询数据库或打印文档。每个Kerberos客户端在访问资源之前都会请求身份验证

* 提供服务的服务端：域内提供服务的服务端，服务端都有唯一的SPN（服务主体名称）

* 提供认证服务的KDC（Key Distribution Center，密钥分发中心）：KDC是一种网络服务，它向活动目录域内的用户和计算机提供会话票据和临时会话密钥，其服务账户为krbtgt。KDC作为活动目录域服务的一部分运行在每个域控上

  这里的krbtgt账户是在创建活动目录时系统自动创建的一个账户，其作用是在KDC的服务账户，其密码是系统随机生成的，无法正常登陆主机

  而KDC包含AS（Authentication Server，认证服务器）和TGS（Ticket Granting Server，票据授权服务器）

Kerberos是一种基于票据（Ticket）的认证方式。客户端想要访问服务端的某个服务，首先需要购买服务端认可的ST（Service Ticket，服务票据）。通俗点说，就是客户端在访问服务前需要先买票，等待服务端验票之后才允许访问。而该票据不能直接购买，还需要一张TGT（Tiket Granting  Tiket，认购权证）。也就是说客户端在买票前还需要获得一张TGT。而ST和TGT均由KDC发放，因为KDC运行在域控上，所以TGT和ST也均由域控发放

Kerberos协议使用TCP/UDP 88 端口进行认证，使用TCP/UDP 464 端口进行密码重设

Kerberos协议有两个基础认证模块：AS_REQ&AS_REP 和 TGS_REQ&TGS_REP，以及微软扩展的两个认证模块S4U和PAC。S4U是微软为了实现委派而扩展的模块，分为S4u2Self和S4u2Proxy。在Kerberos最初设计的流程里只说明了如何证明客户端的真实身份，并没有说明客户端是否有权限访问该服务，因为在域中不同权限的用户能够访问的资源是不同的。微软为了解决该问题，引入了PAC（Privilige Attribute Certificate，特权属性证书）的概念

### 二、PAC

PAC包含各种授权信息、附加凭据信息、配置文件和策略信息等，例如用户所属的用户组、用户所具有的权限等。上文提到过，在最初的RFC1510规定的标准Kerberos认证过程中并没有PAC，微软在自己的产品实现的Kerberos流程中加入了PAC的概念

在一个正常的kerberos认证流程中，KDC返回的TGT的ST都带有PAC，这样的好处是在以后对资源的访问中，服务端接收到客户请求的时候不再需要借助KDC提供完整的授权信息来完成对用户权限的判断，而只需要根据请求中所包含的PAC信息直接与本地资源的ACL相比较来做出裁决

#### 1.PAC结构

PAC的顶部结构是这样的：

~~~PAC
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned long64 ULONG64;
typedef unsigned char UCHAR;

typedef struct _PACTYPE {
    ULONG cBuffers;
    ULONG Version;                         
    PAC_INFO_BUFFER Buffers[1];
} PACTYPE;
~~~

各字段含义:

* cBuffers：包含数组缓冲区中的条目数
* Version：版本
* Buffers：包含一个PAC_INFO_BUFFER结构的数组

而PAC_INFO_BUFFER结构包含关于每个部分的信息，非常重要：

~~~PAC
typedef struct _PAC_INFO_BUFFER {
	ULONG ulType;
    ULONG cbBufferSize;
    ULONG64 Offset;
} PAC_INFO_BUFFER;
~~~

各字段含义：

* ulType：包含此缓冲区中的数据的类型，可能为如下字段：
  * Logon Info (1)
  * Client Info Type (10)
  * UPN DNS Info (12)
  * Server Checksum (6)
  * Privsvr Checksum (7)
* cbBufferSize：缓冲大小
* Offset：缓冲偏移量

#### 2.PAC凭证信息

Logon Info类型的PAC_LOGON_INFO包含Kerberos票据客户端的凭据信息。数据本身包含在一个KERB_VALIDAVTION_INFO结构中，该结构是由NDR编码的。NDR编码的输出被放置Logon Info类型的PAC_INFO_BUFFER结构中。KERB_VALIDAVTION_INFO结构定义如下：

~~~PAC
typedef struct _KERB_VALIDATION_INFO {
    FILETIME Reserved0;
    FILETIME Reserved1;
    FILETIME KickOffTime;
    FILETIME Reserved2;
    FILETIME Reserved3;
    FILETIME Reserved4;
    UNICODE_STRING Reserved5;
    UNICODE_STRING Reserved6;
    UNICODE_STRING Reserved7;
    UNICODE_STRING Reserved8;
    UNICODE_STRING Reserved9;
    UNICODE_STRING Reserved10;
    USHORT Reserved11;
    USHORT Reserved12;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG GroupCount;
    [size_is(GroupCount)] PGROUP_MEMBERSHIP GroupIds;
    ULONG UserFlags;
    ULONG Reserved13[4];
    UNICODE_STRING Reserved14;
    UNICODE_STRING Reserved15;
    PSID LogonDomainId;
    ULONG Reserved16[2];
    ULONG Reserved17;
    ULONG Reserved18[7];
    ULONG SidCount;
    [size_is(SidCount)] PKERB_SID_AND_ATTRIBUTES ExtraSids;
    PSID ResourceGroupDomainSid;
    ULONG ResourceGroupCount;
    [size_is(ResourceGroupCount)] PGROUP_MEMBERSHIP ResourceGroupIds;
} KERB_VALIDATION_INFO;
~~~

字段含义如下：

* Acct Name：该字段对应的值是用户sAMAccountName属性的值
* Full Name：该字段对应的值是用户displayName属性的值
* User RID：该字段对应的值是用户的RID，也就是用户SID的最后部分
* Group RID：对于该字段，域用户的Group RID恒为513(也就是Domain Users的RID)，机器用户的Group RID恒为515(也就是Domain Computers的RID)，域控的Group RID恒为516(也就是Domain Controllers的RID)
* Num RIDS：用户所属组的个数
* GroupIDS：用户所属的所有组的RID

#### 3.PAC签名

PAC中包含两个数字签名：

* PAC_SERVER_CHECKSUM ：使用服务密钥进行签名

* PAC_PRIVSVR_CHECKSUM：使用KDC密钥进行签名

签名的原因：

* 服务密钥签名以验证此PAC已由服务签名
* KDC密钥签名以防止不受信任的服务用无效的PAC为自己伪造票据

两个签名分别以PAC_SERVER_CHECKSUM和PAC_PRIVSVR_CHECKSUM类型的PAC_INFO_BUFFER发送

在PAC数据用于访问控制前，必须检查PAC_SERVER_CHECKSUM签名，这将验证客户端是否知道服务密钥

而PAC_PRIVSVR_CHECKSUM签名的验证是可选的，默认不开启，其用于验证PAC是否由KDC签发，而不是由KDC以外的具有访问服务密钥的第三方放入票据中

签名部分结构如下：

~~~PAC
typedef struct _PAC_SIGNATURE_DATA {
    ULONG SignatureType;
    UCHAR Signature[1];     
} PAC_SIGNATURE_DATA, *PPAC_SIGNATURE_DATA;
~~~

字段含义如下：

* SignatureType：此字段包含用于创建签名的校验和的类型，校验和必须是一个键控的校验和

* Signature：此字段由一个包含校验和数据的字节数组组成，字节的长度可以由包装PAC_INFO_BUFFER结构来决定

####  4.KDC验证PAC

当服务端收到客户端发来的AP-REQ消息时，只能校验PAC_SERVER_CHECKSUM签名，并不能校验PAC_PRIVSVR_CHECKSUM签名

如果要校验PAC_PRIVSVR_CHECKSUM签名，服务端还需要将客户发来的ST中的PAC签名发给KDC进行校验，而大部分服务默认并没有KDC验证PAC这一步（需要将目标服务主机配置为验证KDC PAC签名，默认未开启），此时服务端就无需将ST中的PAC签名发给KDC校验，**这也是白银票据攻击成功的前提**

执行KDC验证PAC的话，意味着在响应时间和带宽使用方面的成本，它需要带宽使用来在应用服务器和KDC之间传输请求和响应，这可能会导致大容量应用程序服务器中出现一些性能问题。在这样的环境中，用户身份验证可能会导致额外的网络延迟和大量的流量。因此，默认情况下，KDC不验证PAC签名

如果目标服务器主机配置为需要校验PAC_PRIVSVR_CHECKSUM签名，服务端会将这个PAC的数字签名以KRB_VERIFY_PAC的消息通过RPC协议发送给KDC，KDC再将该PAC数字签名的结果以RPC返回码的形式发送给服务端，服务端就可以根据返回结果判断PAC的真实性与有效性了，如此，即使攻击者拥有服务密钥，可以制作ST，也无法伪造KDC的PAC_PRIVSVR_CHECKSUM签名，无法通过KDC签名校验

而主机开启KDC签名校验，需要有以下条件：

* **应用程序具有SeTcbPrivilege权限**，SeTcbPrivilege权限允许为用户帐户分配“作为操作系统的一部分”。本地系统、网络服务和本地服务帐户都是由windows定义的服务用户帐户。每个帐户都有一组特定的特权

* **应用程序是一个服务，验证KDC PAC签名的注册表项被设置为1，默认为0**

  修改方法如下：

  * 启动注册表编辑器regedit.exe

  * 找到以下子键：HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters

  * 添加一个ValidateKdcPacSignature的键值(DWORD类型)。该值为0时，不会进行KDC PAC校验。该值为1时，会进行KDC PAC校验。因此可以将该值设置为1启用KDC PAC校验

对于验证KDC PAC签名这个注册表键值，有以下几点注意事项：

* 如果服务端并非一个服务程序，而是一个**普通应用程序**，它将不受以上注册表的影响，而总是进行KDC PAC校验。

* 如果服务端并非一个程序，而是一个**驱动**，其认证过程在系统内核内完成，它将不受以上注册表的影响，而永不进行PAC校验。

* 使用以上注册表项，需要在Windows Server 2003 SP2或更新的操作系统。

* 在运行Windows Server 2008或更新操作系统的服务器上，该注册表项的值缺省为0(默认没有该ValidateKdcPacSignature键值)，也就是不进行KDC PAC校验。

**注：**注册在**本地系统帐户**下的服务无论如何配置，都不会触发KDC验证PAC签名。也就是说譬如SMB、CIFS、HOST等服务无论如何都不会触发KDC验证PAC签名。

#### 5.PAC在Kerberos中的优缺点

* 优点

  客户端在访问网络资源的时候服务端不再需要向KDC查询授权信息， 而是直接在本地进行PAC信息与ACL的比较，从而节约了网络资源

  可以绘图对比一下：

  * 无PAC的情况：
    ![image-20240613170909526](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240613170910666-128873941.png)

  * 有PAC的情况：

    ![image-20240613172333127](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240613172334020-1646651598.png)

* 缺点

  * PAC在用户认证阶段引入会导致认证时间过长：
    Windows Kerberos客户端会通过RPC调用KDC上的函数来验证PAC信息，这时候用户会观察到在服务器端与KDC之间的RPC包流量的增加
  * PAC是微软特有的一个特性，所以启用了PAC的域中将不便于装有其他操作系统的服务器， 制约了域配置的灵活性
  * 安全问题：2014年产生了一个域内提权漏洞（MS14-068）

### 三、Kerberos认证流程

可以绘制一张图来概括Kerberos的认证流程：

![image-20240613224049516](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240613224049995-858937545.png)

接下来分析具体流程

#### AS-REQ&AS-REP

经过此步，客户端获得了由KDC的AS发放的TGT

##### 1.AS-REQ

当域内某个用户想要访问域内某个服务时，输入用户名和密码，本机就会向KDC的AS认证服务发送一个AS-REQ认证请求。

请求包中部分字段含义如下：

* PA-DATA PA-ENC-TIMESTAMP：这个是预认证，就是用用户密钥（通常为NTLM hash或AES Key）加密时间戳，作为value发送给KDC的AS服务。然后KDC从活动目录中查询出用户的密钥对其进行解密，即可获得时间戳，如果能解密，且时间戳在一定的范围内，则证明认证通过。因为这里是使用用户密钥加密的时间戳，所以有可能造成**哈希传递攻击或密钥传递攻击**

  **注意**：在AS-REQ请求包中，只有该部分是加密的，这一部分属于预认证，被称为Authenticator，而用户密钥的类型支持多种，客户端支持的加密方式是由提供的凭据类型决定的，对应如下（左边为用户密钥类型，右边为密钥加密时间戳的方式），优先级从到下逐渐降低（在后面的认证过程中，krbtgt和服务的密钥的类型同理）：

  ![image-20240614170733030](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240614170733687-1901061622.png)

* PA-DATA PA-PAC-REQUEST：这个是启用PAC支持的扩展。字段中有一个padata-value字段，其中include-pac对应的值为True或False,KDC根据include的值来确定返回的票据中是否需要携带PAC

* kdc-options：用于与KDC协商一些选项设置

* cname：请求的用户名，用户名是否存在会影响返回包的内容，因此可以进行**域内用户名枚举**；而用户名存在时，密码的正确与否也会影响返回包，因此可以进行**密码喷洒（password spraying）**

* realm：域名

* sname：请求的服务名，包含type和value，AS-REQ中sname始终为krbtgt，即这个阶段请求的服务都是krbtgt

* etype：加密类型

* 以及一些其他信息：如版本号，消息类型，票据有效时间，协商选项等

##### 2.AS-REP

当KDC的AS认证服务接收到客户端发来的AS-REQ请求后，从活动目录数据库中取出该用户的密钥，然后用该密钥对请求包中的Authenticator预认证部分进行解密，如果解密成功，并且时间戳在有效的范围内，则证明请求者提供的用户密钥正确（验证时间戳以确保kerberos中的时钟同步）

KDC的AS认证服务在成功认证客户端的身份之后，发送AS-REP响应包给客户端。AS-REP响应包中主要包括如下信息：

* crealm：域名

* cname：请求的用户名

* ticket：认购权证票据（TGT）

  TGT认购权证中包含一些明文显示的信息，如版本号tkt-vno、域名realm、请求的服务名sname。

  TGT中最重要的还是**enc-part**字段（TGT中的加密部分），是使用krbtgt帐户密钥（一般为NTLM-hash）加密的。加密部分主要包含的内容有Logon Session Key、请求的用户名cname、域名crealm、认证时间authtime、认证到期时间endtime、authorization-data等信息，最重要的是authorization-data部分，该部分中包含PAC，客户端的身份权限等信息包含在PAC中，而PAC中最主要的还是通过User RID和Group RID来辨别用户权限的

  **KDC生成PAC的过程如下：**KDC在收到客户端发来的AS-REQ请求后，从请求中取出cname字段，然后查询活动目录数据库，找到sAMAccountName属性为cname字段的值的用户，用该用户的身份生成一个对应的PAC

  上面提到，**enc-part**字段部分是用krbtgt的密钥加密的，所以如果我们获得了krbtgt的密钥，就可以自己制作一个ticket，即可造成黄金票据传递攻击

* enc-part：这个enc-part与上面TGT中的enc-part不同，是AS-REP中最外层的使用用户密钥加密Logon Session Key后的值，其作用是用于确保客户端和KDC下阶段之间通信安全，主要包含了认证时间authtime、认证到期时间endtime、域名srealm、请求的服务名sname、协商标志flags等信息

  **注**：在TGT内部和外部的enc-part中都存在Logon Session Key

* 以及一些其他信息：如版本号，消息类型等

#### TGS-REQ&TGS-REP

客户端在收到KDC的AS-REP后，使用用户密钥解密enc_Logon Session Key（外部的enc-part），得到Logon Session Key，并且也获得了TGT。之后客户端会在本地缓存此TGT和Logon Session Key。接下来客户端要凭借该TGT向KDC购买相应的ST，ST是KDC的TGS服务发放的。该阶段中，微软引入了两个扩展自协议S4u2Self和S4u2Proxy（在后面委派部分介绍）

##### 3.TGS-REQ

客户端用上一步获得的TGT发起TGS-REQ，向KDC购买针对指定服务的ST

TGS-REQ中重要字段如下：

* padata：padata中包含ap_req,这个是TGS_REQ必须携带的部分
* ap-req：存在于padata，这部分会携带AS_REP里面获取到的TGT认购权证和使用原始的Logon Session Key加密的时间戳
* ticket：存在于ap-req中，AS-REP响应包中返回的TGT认购权证
* authenticator: 存在于ap-req中，原始Logon Session Key加密的时间戳，用于下一阶段的会话安全认证。为了确保后阶段的会话安全，TGS-REQ中ap-req中的authenticator字段的值是用上一步AS-REP中返回的Logon Session Key加密的时间戳

##### 4.TGS-REP

KDC的TGS服务在接收到TGS-REQ后会进行如下操作：

* 使用krbtgt的密钥解密TGT中的加密部分，得到Logon Session Key和PAC等信息，解密成功则说明该TGT是KDC颁发的

* 验证PAC的签名，签名正确则证明PAC未被篡改
* 使用Logon Session Key解密authenticator得到时间戳等信息，若解密成功，且票据时间在有效范围内，则证明该会话安全

经过上述步骤，KDC的TGS就完成了对客户端的认证，TGS便发送REP给客户端

**注**：发送TGS-REP前KDC并不会验证客户端是否有权限访问服务端。不管用户是否有访问服务的权限，只要TGT正确，均会返回ST

在TGS-REP中，部分字段如下：

* ticket：即ST，ST中包含明文显示的信息比如：版本号tkt-vno、域名realm、请求的服务名sname......加密部分是使用服务密钥加密的，主要包含Server Session Key、请求的用户名cname、域名crealm、认证时间authtime、认证到期时间endtime、authorization-data等信息，而authorization-data部分中包含PAC，客户端的身份权限等信息包含在PAC中

  **注**：在正常的非S4u2Self请求的TGS过程中，KDC在ST中的PAC直接复制了TGT中的PAC

* enc-part（ticket中的）：这部分是使用服务的密钥加密的

* enc-part（最外层的）：这部分是使用原始的Logon Session Key加密的。里面最重要的字段是Service Session Key（和ST中的server session key一样），包含请求的用户名sname、域名srealm、认证时间authtime、认证到期时间endtime、协商标志flags等信息，作为下一阶段的认证密钥

#### AP-REQ&AP-REP双向认证

客户端收到KDC返回的TGS-REP消息后，从中取出ST，准备开始申请访问服务

##### 5.AP-REQ

客户端在接收到KDC的TGS回复后，通过缓存的Logon Session Key解密TGS-REP的外层enc-part得到service session key，同时也获得了ST。service session key和ST会被客户端缓存。

客户端访问指定服务时，将发起AP-REQ，其中部分字段如下：

* ticket：票据（ST）
* authenticator：Service Session Key加密的时间戳

##### 6.AP-REP

服务端在收到客户端发来的AP-REQ后，通过服务密钥解密ST，得到Service Session Key和PAC等信息，再用Service Session Key解密authenticator得到时间戳，如果解密成功，且时间戳在有效范围内，则成功验证客户端身份

* **在默认不开启KDC验证PAC的情况下**，验证客户端身份后，服务端将从PAC中取出代表用户身份权限信息的数据，直接与请求的服务ACL做对比，并且校验PAC_SERVER_CHECKSUM签名，成功后生成相应的访问令牌，服务端根据访问令牌的权限决定是否开启相应的服务

* **在开启KDC验证PAC的情况下**，在原本校验基础上，客户端还会将PAC_PRIVSVR_CHECKSUM签名以KRB_VERIFY_PAC的消息通过RPC协议发送给KDC，KDC再将该PAC数字签名的结果以RPC返回码的形式发送给服务端，以此判断PAC的真实性和有效性，然后返回校验结果，服务端根据校验结果决定是否开启相应的服务

接下来，服务端根据AP-REQ中的mutual-required选项决定服务端是否返回AP-REP:

* mutual-required选项为ture时，表明客户端想要验证服务端的身份，服务端会用Service Session Key加密时间戳作为authenticator，在AP-REP中发送给客户端进行验证，客户端在验证服务端身份后决定是否访问该服务
* mutual-required选项为false时，则不返回AP-REP

#### S4u2Self&S4u2Proxy协议

为了在kerberos协议层面直接对约束性委派进行支持，微软对kerberos协议扩展了两个自协议：S4u2Self（Service for User to Self）和S4u2Proxy（Service for User to Proxy）

* S4u2Self可以代表任意用户请求针对自身的服务票据
* S4u2Proxy可以用上一步获得的ST，以用户的名义情求针对其他指定服务的ST

##### S4u2Self

和正常的TGS-REQ包相比，S4u2Self协议的TGS-REQ包中，PA-DATA部分会多一个 pA-FOR-USER字段，数据类型是S4U2Self，该字段包含的字段：

* name：要模拟的用户
* sname：请求的服务自身

##### S4u2Proxy

和正常的TGS-REQ包相比，S4u2Proxy协议的TGS-REQ包中，PA-DATA部分会多一个PA_PAC_OPTIONS，数据类型是S4U2Proxy；还会增加一个additional-tickets字段，该字段的内容就是上一步利用S4u2Self请求的ST

### 四、Kerberos协议的安全问题

Kerberos协议各阶段容易产生的安全问题，可以绘制一幅图来总结：

![image-20240621224304346](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240621224306896-1548204939-20251212105537122.png)

此处只对AS-REQ&AS-REP阶段和TGS-REP阶段的问题稍作介绍，后面会另发文章详细记录Kerberos相关安全问题

#### AS-REQ阶段的安全问题

##### 1.哈希传递攻击

上面提到，在AS-REQ阶段，使用的是用户密码的NTLM hash或AES Key来加密的时间戳，所以可以获取NTLM hash造成PTH攻击，也可能获取AES Key造成PTK攻击

##### 2.域用户名枚举

AS-REQ中的cname表示请求的用户名，用户名是否存在会影响返回包的内容，因此可以进行域内用户名枚举（当未获取到有效域用户权限时，可以使用这个方法枚举域内用户）

##### 3.密码喷洒攻击

而用户名存在时，密码的正确与否也会影响返回包，这里虽然可以进行密码爆破，但连续针对同一账户的密码猜测很有可能会导致账户被锁定，因此有了密码喷洒喷洒攻击：即在猜解密码时，使用每个密码去尝试所有用户名

#### AS-REP阶段的安全问题

##### 1.黄金票据攻击

上文提到，在AS-REP阶段，返回的TGT的加密部分是由krbtgt用户的密钥加密的，因此，如果我们获得了krbtgt的密钥，我们就可以自己制作一个TGT，该票据被称为黄金票据

##### 2.AS-REP Roasting

预身份验证是Kerberos身份验证的第一步(AS_REQ & AS_REP)，它的主要作用是防止密码脱机爆破。默认情况下，预身份验证是开启的，KDC会记录密码错误次数，防止在线爆破

上文提到，在AS-REP阶段，Logon Session Key是用用户的密钥加密的。对于域用户，如果设置了“Do not require Kerberos preauthentication”（不需要预认证）选项，攻击者可以向域控的88端口发送AS_REQ，此时域控不会做任何验证就将TGT和使用该用户密钥加密的Logon Session Key返回。如此，攻击者可以对获取到的加密的Longon Session Key进行离线破解，如果破解成功，可以获得用户的密码明文，即完成了AS-REP Roasting攻击

#### TGS-REP阶段的安全问题

##### 1.Kerberoasting攻击

上文提到，ST是用服务的密钥加密，因此，如果我们能获取到ST，就可以尝试对ST进行破解，得到服务的密钥，造成了Kerberoasting攻击

还有一个原因是当用户向KDC发起TGS-REQ时，不论用户是否有服务的访问权限，只要TGT正确，KDC都会返回ST

##### 2.白银票据攻击

同样，因为ST是用服务的密钥加密，如果我们获取到服务的密钥，就可以签发任意的ST，这个票据又称为白银票据，即完成了白银票据攻击
