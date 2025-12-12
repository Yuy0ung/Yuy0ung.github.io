---
title: "内网信息收集-BloodHound分析域环境"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 内网信息收集-BloodHound分析域环境

bloodhound是一款单页JavaScript Web应用程序，是一款强大的域内环境分析工具，能通过图与线的形式将域内相关用户、组、计算机、会话、ACL等对象之间的关系以可视化方式呈现，我们可以利用它来识别高度复杂的攻击路径

### bloodhound的安装

这里我在windows上进行安装

#### 安装neo4j数据库

这里我在windows上安装[Neo4j Deployment Center - Graph Database & Analytics](https://neo4j.com/deployment-center/#community)：

下载好，解压，直接执行命令启动：

~~~cmd
neo4j.bat console
~~~

只要jdk版本正确，就能够正常启动

![image-20240912194617110](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912194620799-2847468.png)

然后浏览器访问并登录：

~~~
Host : http://localhost:7474
Username : neo4j
Password : neo4j
~~~

![image-20240912194730170](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912194733441-1009721940.png)

修改默认密码：

![image-20240912194844553](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912194847851-77755018.png)

neo4j就安装完毕了

#### 运行bloodhound

下载[bloodhound](https://github.com/BloodHoundAD/BloodHound/releases/tag/v4.3.1)，解压后直接启动exe，并用noe4j的账号密码登录：

![image-20240912202647846](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912202651065-344837007.png)

进入后页面左上角有三个选项卡：

* database info（数据库信息）
* node info（节点信息）
* analysis（分析）

右上角有很多设置选项，这里不细说

## 活动目录信息收集

收集工具使用sharphound（这里用1.x的版本）

有两种收集方案：

* powershell采集脚本：SharpHound.ps1
* 可执行文件：SharpHound.exe

命令如下

~~~cmd
SharpHound.exe -c all

powershell -exec bypass -command "Import-Module ./SharpHound.ps1; Invoke-BloodHound -c all"
~~~

两种方法都需要将文件上传至目标主机，我这里使用exe进行收集：

![image-20240912202832487](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912202835827-1153010778.png)

会在当前目录生成格式为“时间戳_BloodHound.zip”的文件

#### 导入数据

直接压缩包拖动导入即可：

![image-20240912202956302](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912202959336-1395861449.png)

上传后左上角的database info处就有数据了，此时进入analysis模块，选择不同的查询条件，可以进行不同的分析查询，比如“find all domain admins”：

![image-20240912205222473](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912205223662-1374556607.png)

此时单击任意节点，左上角会进入node info并显示节点信息：

* 节点概述
* 节点属性
* 所属组
* 所拥有的权限
* ......

#### 边缘信息

边缘（Edge）是连接两个节点的连线，可以反映两个相互作用的节点之间的关系，例如这里“member of”表示域用户YUY0UNG是用户组DOMAIN ADMINS的成员：

![image-20240912210308495](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912210309488-440263711.png)

常见边缘类型如下，详见官方文档：

![image-20240912210508720](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912210510259-2018869502.png)

![image-20240912210554524](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912210555773-852318359.png)

#### 数据分析

常用的查询功能如下：

![image-20240912210957784](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912210959722-4817640.png)

![image-20240912211022559](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912211023851-1358876600.png)

这里记录比较常用的：

##### 查找所有的域管理员

单击find all domain admins，可以看见两个域管理员用户

![image-20240912211641803](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912211657039-280659881.png)

##### 识别到达域管理员的最短路径

单击find shortest paths to domain admins，识别到达域管理员的最短路径

![image-20240912211817420](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912211818558-2129563020.png)

##### 查找所有拥有DCSync权限的主体

选择模块find principals with DCSync Rights，查找所有拥有DCSync权限的主体

![image-20240912212837544](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912212839155-2115590704.png)

拥有DCSync权限的主体可以通过Directory Replication Server（DRS）服务的GetNCChanges接口向域控发起数据同步请求，并从域控请求数据。通过DCSync，我们可以导出所有域用户的NTLM Hash，实现隐蔽的权限维持

##### 映射域信任关系

选择map domain trusts，显示当前域信任关系

由于我搭建的域环境为单域，就不放图了

通过收集有关域信任关系的信息，可以为在域林环境中横向移动寻找机会

##### 到达无约束委派的最短路径

选择shortest paths to unconstrained delegation systems，识别到达无约束委派的最短路径

![image-20240912214413723](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912214414930-1285257445.png)

域委派是指将域内用户的权限委派给服务账户，使服务账户能够以该用户的身份在域内开展其他活动比如访问域内其他服务，为域内的多跳认证带来便利，但也增加了隐患，通过滥用委派，可以获取域管理员权限，接管整个域环境，也能制作后门实现隐蔽的权限维持

##### 所有kerberroastable用户

选择list all kerberoastable accounts，列出所有kerberroastable用户：

![image-20240912215900053](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912215901109-423939289.png)

kerberroastable用户可以被用来离线破解服务账户哈希值，获取AD控制权

##### 到达高价值目标的最短路径

选择shortest paths to high value targets，识别到达高价值目标的最短路径：

![image-20240912220554175](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240912220555684-859506376.png)

##### 所有非域控的域管理登录

选择find domain admin logons to non-domain contrllers，查看所有非域控的域管理登录

通过找出域管理员在所有非域控的主机的登陆痕迹，为准确获取域管理员提供了方向，例如入侵主机找到域管理员活动的进程，通过进程迁移、令牌窃取等手段，获取域管理权限
