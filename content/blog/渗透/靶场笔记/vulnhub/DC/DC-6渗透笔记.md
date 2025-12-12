---
title: "DC-6渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# DC-6渗透笔记

靶机给了两个提示，一个是插件，一个是暴力破解

### 信息收集

#### IP探测

![image-20240721161713732](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721161713724-1443644218.png)

IP为192.168.111.142

#### 端口探测

![image-20240721161759582](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721161759490-980666497.png)

可知开放了22端口和80端口

#### 网页信息搜集

访问网页发现无法访问

![image-20240721161852895](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721161852598-2145947093.png)

发现url被解析成wordy，和DC-2类似，在hosts文件添加解析再次访问

![image-20240721162335634](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721162336416-2066819475.png)

主要信息就是CMS为wordpress 5.1.1

先扫一下目录：

![image-20240721162725787](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721162725859-1879727514.png)

可以找到后台登陆点

### 漏洞利用

#### 暴力破解登陆后台

根据提示可以想到这里应该是要暴力破解一下后台密码

先用wpscan扫扫

~~~shell
wpscan --url http://wordy --enumerate u
~~~

![image-20240721164141907](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721164142085-134221907.png)

枚举出几个用户，先保存在文件里

我们直接用rockyou.txt爆破一下：

~~~shell
wpscan --url http://wordy -P /usr/share/wordlists/rockyou.txt -U wpname.txt
~~~

字典很大，耐心等待

最后得到mark的密码：helpdesk01

即可登录进入后台

#### 后台getshell

后台发现这个插件似乎使用命令执行，lookup抓包看看：

![image-20240721171534203](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721171534157-501957967.png)

还真是，那就直接反弹shell：

![image-20240721172316636](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721172316726-1095117511.png)

ok已经getshell，再拿个pty：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721172426430-1201678872.png" alt="image-20240721172426833" style="zoom:150%;" />

接下来就是提权了

### 权限提升

在stuff目录下找到了一个任务清单：

![image-20240721173609299](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721173609092-485318415.png)

发现了graham的密码：GSo7isUM1D4

直接登录：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721173717500-1386144627.png" alt="image-20240721173717624" style="zoom:150%;" />

看看sudo权限：

![image-20240721173904325](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721173904365-754218415.png)

发现一个免密sudo（身份为jens）的脚本，看看内容和权限：
![image-20240721174115145](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721174114881-507677389.png)

jens用户可读可写可执行，很明显的sudo脚本篡改提权，直接追加写入内容，再以jens用户执行，可以拿到jens身份的bash（这里尝试的时候，提示权限不足，应该是切换用户时的问题，于是换成使用ssh登录graham用户）：

![image-20240721180642892](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721180642686-1067631521.png)

再看看jens的sudo权限：

![image-20240721181043514](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721181043587-788312517.png)

发现nmap可以免密sudo执行，而nmap可以执行脚本文件，也可以实现权限提升：

![image-20240721181740017](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721181740155-160856389.png)

成功拿到root权限

在/root目录拿到flag：

![image-20240721182123390](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240721182123336-1994521683.png)