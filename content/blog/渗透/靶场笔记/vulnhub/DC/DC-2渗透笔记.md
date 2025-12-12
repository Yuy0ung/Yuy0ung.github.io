---
title: "DC-2渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# vulnhub-DC:2渗透笔记

### 信息搜集

#### IP探测

老规矩，先探测一下IP：

~~~shell
nmap -sP 192.168.111.0/24
~~~

![image-20240715161830565](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715161831122-910763766.png)

确定IP为192.168.111.144

#### 端口探测

看看开了哪些端口：

~~~shell
nmap -sV -p- 192.168.111.144
~~~

![image-20240715162050242](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715162050650-443741704.png)

可以看到开放了两个端口：

* 80端口，这个应该就是web服务
* 7744端口，似乎是把ssh服务默认的22改成了7744

#### 网页信息收集

浏览器访问80端口看看：

![image-20240715162402283](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715162402515-2105706616.png)

不能访问，但显示了个dc-2，这里涉及一个dns解析顺序的问题：

~~~
根据Windows系统规定，在进行DNS请求以前，Windows系统会先检查自己的Hosts文件中是否有这个地址映射关系，如果有则调用这个IP地址映射，如果没有再向已知的DNS服务器提出域名解析。 也就是说Hosts的请求级别比DNS高
~~~

所以我们修改C:/Windows/System32/drivers/etc/HOSTS文件进行host碰撞：

![image-20240715162707796](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715162708133-71093939.png)

ok现在再访问一下进入web服务：

可以访问了且发现了flag1：

~~~
你通常使用的字典可能行不通，所以也许你需要使用cewl。

更多的密码总是更好，但有时你就是无法赢得所有的。

登录为一个用户来查看下一个flag

如果找不到它，尝试以另一个身份登录
~~~

他这里应该是让我使用cewl进行密码攻击，但并不代表只有这种方法，我们接着看看

![image-20240715162827987](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715162829194-1231726177.png)

依旧是通过wappalyzer得到web服务的基本信息：

* wordpress 4.7.10
* php语言
* Apache
* debian系统
* mysql数据库

还是dirsearch扫一扫目录：

![image-20240715173517298](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715173517979-1403181923.png)

没有什么特别有用的信息

### 漏洞利用

#### wordpress（flag1、flag2）

根据提示使用kali自带的cewl生成密码字典：

~~~shell
cewl http://dc-2/ -w dict.txt			//保存在dict.txt中
~~~

这个txt作为我们后续爆破用的字典

接下来按照flag1的提示，是要进行登录，针对wordpress一般可以试试wpscan：

用wpscan枚举一下用户名

~~~shell
wpscan --url http://dc-2/ --enumerate u
~~~

![image-20240715175237833](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715175238466-791836176.png)

发现三个用户名，我们同样将他们保存至user.txt

接下来是针对用户的密码爆破，用户名和密码的字典指定为我们保存的字典：

~~~shell
wpscan --url http://dc-2/ -U user.txt -P dict.txt
~~~

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715175814875-460633213.png" alt="image-20240715175814731" style="zoom:150%;" />

可以看见，jerry和tom的密码都被爆破出来了，让我们登录试试

![image-20240715180346153](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715180346666-1951959271.png)

登录jerry的账号发现了flag2：**如果你无法利用WordPress并走捷径，还有另一种方式。希望你找到了另一个入口点。**

后台确实没有什么突破口了，而flag2提示要寻找其他利用点，首先想到的就是还未曾使用的ssh服务了

#### SSH（flag3）

我们收集到了2对账密，可以尝试一下是否能远程连接ssh：

![image-20240715181720587](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715181721120-1250192673.png)

 使用jerry的账密连接发现密码错误，而使用tom的账号连接成功，直接拿到shell

在当前目录发现flag3.txt，但无法cat：

![image-20240715182127405](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715182127664-933106760.png)

使用vi看看：

![image-20240715182015565](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715182015869-1398759624.png)

拿到flag3：**可怜的老汤姆总是追赶杰瑞。或许他应该因为所有的压力起诉杰瑞。**

### 后渗透

#### rbash逃逸（flag4）

因为当前shell是rbash，考虑进行rbash逃逸

这里首先想到的就是利用vi进行逃逸，输入末行命令：

~~~vi
:set shell=/bin/bash

shell
~~~

如此，即可成功实现绕过限制：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715203413787-1563359231.png" alt="image-20240715203413459" style="zoom:150%;" />

但是这个shell有很多命令无法执行：su、sudo、git......，我们需要将命令添加至环境变量：

~~~shell
export PATH=$PATH:/bin/
export PATH=$PATH:/usr/bin
~~~

这样就可以su命令切换到jerry用户，密码还是试试wordpress的密码：

![image-20240715211744867](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715211745112-1785991258.png)

成功切换到jerry用户，在用户的家目录发现了flag4：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715212016428-519096248.png" alt="image-20240715212016425" style="zoom:150%;" />

看看内容：

![image-20240715203535494](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715203535625-705222679.png)

品一下：**很高兴看到你走了这么远，但你还没到家。你还需要找到最后一个flag（真正重要的flag）。这里没有提示，你只能靠自己了。快走，（git）离开这里**

#### git提权（flag5）

很明显，flag4的提示就是git利用来提权了：

看看有哪些命令可以sudo执行

~~~shell
sudo -l
~~~

还真是，git能sudo执行而且不用输入密码，直接用git打sudo提权：

首先得将shell窗口变窄，让回显信息不能一页显示，再查看git帮助文档

~~~shell
sudo git -p help
~~~

此时可以输入末行命令：

~~~sh
!/bin/bash
~~~

即可获得权限为root的shell：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715214857126-192753447.png" alt="image-20240715214857100" style="zoom:150%;" />

看看/root目录：

![image-20240715214956191](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240715214956362-1824325933.png)

成功找到了最后一个flag

### 总结

渗透过程中，我们利用了如下攻击手段：

* cewl配合wpscan爆破wordpress用户账密
* 密码复用，ssh连接主机getshell
* 利用vim末行命令进行逃逸，突破rbash限制
* 密码复用切换shell账户
* 利用git帮助文档末行命令实现sodo提权
