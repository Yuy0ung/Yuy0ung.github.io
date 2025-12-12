---
title: "DC-7渗透笔记"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# DC-7渗透笔记

靶场作者说明：

![image-20240722153524012](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722153524705-550943464.png)

### 信息搜集

IP、端口、目录一条龙：

![image-20240722153329484](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722153330313-1941059765.png)

可知：

* IP为192.168.111.145
* 开放22、80端口
* 目录毛都没扫出

看看web网页：

![image-20240722152803919](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722152804604-1344200974.png)

可知cms是Drupal 8

### 漏洞利用

#### 敏感信息泄露

在靶场描述里说挑战不完全是技术性的，要跳出框框思考，说明突破口可能不是网站本身，找找看

![image-20240722153902459](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722153902603-2143634694.png)

在页脚发现一个叫@DC7USER的用户，搜搜结果发现了该用户的github

![image-20240722153954052](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722153954182-252992894.png)

看看他发的代码：

![image-20240722154037391](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722154037579-75814788.png)

在config.php里面发现了账密，试试登录drupal呢

#### 利用账密连接ssh

![image-20240722154219764](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722154220029-1754029050.png)

错了，那还有登陆的地方就是22端口的ssh服务，连接试试：

![image-20240722154353498](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722154353802-1278096501.png)

这就getshell了？

#### shell下的信息搜集

正常进行信息收集，看看suid、sudo、内核等：

![image-20240722154723089](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722154723818-2042137893.png)

确实没有什么利用点，那可能就是有什么利用文件了，找找看：

![image-20240722154945910](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722154946915-1767379922.png)

当前目录有备份文件夹，但里面是加密的gpg文件，而mbox记录了root的定时任务，路径为`/opt/scripts/backups.sh`，过去看看：

![image-20240722155603261](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722155603946-1048303683.png)

利用这个root的任务可以提权，但发现脚本只有root和www-data可写，得想办法拿到www-data身份，那就得通过web服务拿shell，那么入手点又要回到后台，先看看脚本

脚本内容：

~~~bash
#!/bin/bash  
# 删除 /home/dc7user/backups/ 目录下的所有文件  
rm /home/dc7user/backups/*  

# 切换目录到 /var/www/html/  
cd /var/www/html/  

# 使用 Drush 工具导出数据库，并将结果保存为 /home/dc7user/backups/website.sql  
drush sql-dump --result-file=/home/dc7user/backups/website.sql  

# 返回上级目录  
cd ..  

# 将 html/ 目录的内容打包成 website.tar.gz 并保存在 /home/dc7user/backups/ 目录下  
tar -czf /home/dc7user/backups/website.tar.gz html/  

# 使用 GPG 对 /home/dc7user/backups/website.sql 文件进行对称加密，并用指定的密码保护  
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.sql  

# 使用 GPG 对 /home/dc7user/backups/website.tar.gz 文件进行对称加密，并用指定的密码保护  
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.tar.gz  

# 将 /home/dc7user/backups/ 目录下所有文件的所有者改为 dc7user  
chown dc7user:dc7user /home/dc7user/backups/*  

# 删除 /home/dc7user/backups/website.sql 文件  
rm /home/dc7user/backups/website.sql  

# 删除 /home/dc7user/backups/website.tar.gz 文件  
rm /home/dc7user/backups/website.tar.gz
~~~

这里重点在于drush，是一个简化了创建和管理Drupal8网站的命令行工具，可以用来修改密码：

~~~shell
drush upwd admin --password="123456"
~~~

#### 重置密码进入后台

我们去web目录尝试修改网页的admin密码：
![image-20240722160155849](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722160156012-672320161.png)

修改后尝试登录admin：

![image-20240722160509108](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722160509127-1329267670.png)

登录成功

到后台的思路基本就是找写webshell的点了，发现在Content => Add content =>Basic page处似乎可以写：

![image-20240722161048298](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722161048540-1694046438.png)

发现Drupal 8不支持PHP代码，需要将php单独作为一个模块导入，进入Extend => Install new module，输入url：`https://ftp.drupal.org/files/projects/php-8.x-1.0.tar.gz`

然后install，安装完毕就enable激活，勾选要激活的模块：

![image-20240722161323297](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722161323333-258300211.png)

然后再install即可写php代码了:

![image-20240722161647761](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722161647768-1918289949.png)

保存后看看路径：

![image-20240722161713495](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722161713401-499946066.png)

蚁剑连接：

![image-20240722161806748](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722161806757-1042009380.png)

接下来反弹shell:
![image-20240722162024246](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722162024309-1210078131.png)

获取pty：
<img src="https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722162150752-1598023236.png" alt="image-20240722162150910" style="zoom:150%;" />

ok正式进入提权阶段

### 权限提升

修改我们先前发现的定时任务脚本，写入反弹shell代码，开启监听并等待定时任务以root身份执行：
![image-20240722165141211](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722165142258-344636705.png)

成功反弹到root的shell：

![image-20240722165232527](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722165232482-671547293.png)

然后拿flag:

![image-20240722165257709](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240722165258370-1489223825.png)

收工

### 总结

本次渗透过程的漏洞或利用：

* github源码泄露ssh账密
* 邮箱泄露定时任务脚本
* drush重置drupal的管理员密码
* 后台支持php模块导致写webshell
* 定时任务脚本可被www-data篡改
* 定时任务脚本以root运行实现提权