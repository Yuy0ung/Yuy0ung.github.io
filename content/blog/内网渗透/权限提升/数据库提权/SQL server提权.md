---
title: "SQL server提权"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# SQL server提权

SQL server，即mssql，是微软开发的一款关系型数据库系统，常出现在windows主机上，而SQL server具有一些常规的打法（主要是用于提权），这里学习并记录

### 发现SQL server

#### 本地查看

SQL server默认1433端口，所以如果在getshell后发现1433端口处于监听状态，则有可能安装了SQL server

如果端口被修改，可以通过查看进程ID来查找SQL server：

~~~cmd
tasklist /svc | findstr MSSQLSERVER

netstat -ano | findstr <进程ID>
~~~

 
