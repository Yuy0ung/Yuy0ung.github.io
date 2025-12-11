---
title: "JS逆向基础"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# JS逆向基础+有道翻译JS简单分析

由于最近工作中测试相关资产时，发现很多网站，包括小程序等的web端，传输的数据都是经过了加解密的，于是便需要我们对js中的加解密部分进行分析、调试和逆向，并编写hook代码，配合一些工具将我们测试的请求自动加密，将响应自动解密（其实和爬虫非常类似），实现对数据加解密的对抗

## 前置知识

### JS相关

你可能需要先掌握：javascript基础、闭包、面向对象、原型、原型链

对这些概念掌握且能看懂js代码即可

### 数据传输相关

加解密、编解码、消息摘要，这些其实就是应用密码学相关知识，了解原理和作用

### 基础反调试

这里说的是最简单的一类情况，常体现为禁用F12、禁用右键等，都是CTF入门接触的，直接在浏览器选项中调出开发者工具即可

由于调出开发者工具后会占据一部分屏幕导致innerWidth或innerHeight的值变小，这一属性也有可能用于反调试，解决方案就是让开发者工具以单独窗口打开而不是停靠在浏览器页面上

### 一些开发者工具的功能

很多操作在干渗透的时候都会了，就不多赘述，这里记录一点以前没用过的：

* 保留日志/持续记录（一般开启）
* 禁用缓存（一般开启）
* 内容格式化（值得注意的是搜索文件内容最好搜索格式化之前的，格式化可能会补充空格之类的导致搜索不到）
* Fetch/XHR：js代码中发送的网络请求，比如fetch/ajax
* 文档/HTML：页面加载的第一个html
* 网络：可以看到请求与响应（值得一提的是，在这里无法通过ctrl+f进行搜索请求体内容）
* 调用堆栈：调试界面的功能，当函数运行起来时，调用堆栈可以描述当前运行到的断点处的代码
* 控制台输出：分为错误、告警、信息、日志、调试等几种输出级别

## 基础步骤

这里以有道翻译的文本翻译功能为例来将基础过一遍，这里先用写爬虫一样的逻辑来走一遍，后面再写关于渗透测试环境中的简单分析

### 加密逻辑分析

首先是加密，即我们发送请求时抓包，发现包中的一些数据不是明文，或者相比提交的数据多了一些像签名之类的参数，就需要分析前端加密逻辑

#### 定位数据来源

首先需要做的事就是定位我们数据交互时加解密数据的请求包，对于学习了网安的人，相信不论是f12还是burp都是极为简单的，我们可以很轻松定位到指定文本翻译功能的包：
![image-20250516234211883](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250516234211883.png)

#### 识别加密参数

这里我们先将定位到的请求包复制为curl命令：

![image-20250517004337192](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250517004337192.png)

并转换为python request：

![image-20250517004742406](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250517004742406.png)

在这里我们可以运行脚本并获得加密后的结果：

![image-20250517004832447](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250517004832447.png)

我们分析请求参数:
~~~python
data = {
    "i": "你好",
    "from": "auto",
    "to": "",
    "useTerm": "false",
    "dictResult": "true",
    "keyid": "webfanyi",
    "sign": "68732687ef98f424db7c2c20c30ddb9d",
    "client": "fanyideskweb",
    "product": "webfanyi",
    "appVersion": "1.0.0",
    "vendor": "web",
    "pointParam": "client,mysticTime,product",
    "mysticTime": "1747409777255",
    "keyfrom": "fanyi.web",
    "mid": "1",
    "screen": "1",
    "model": "1",
    "network": "wifi",
    "abtest": "0",
    "yduuid": "abcdefg"
}
~~~

其实不难看出来一些关键信息：

* i就是我们请求的文本内容明文
* sign在这里应该是md5这种请求摘要签名，通过更改其他的参数，查看加密的响应可以知道，参数 i 没有参与摘要算法，但时间戳mysticTime参与了（签名一般都是本地js生成）

#### 定位分析加密算法

入手点肯定是sign的签名算法，通过全局搜索寻找一下（可以过滤掉无用的文件类型比如css），像下面这样搜索关键字：

* `sign`
* `sign=`（注意这里不要加等号）
* `sign:`
  * `\bsign`（需要启用正则表达式，`\b`代表匹配字符边界）

可以发现很多疑似的代码，我们可以都打上断点进行验证，比如：

![image-20250518132153323](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250518132153323.png)

打上断点在重新触发翻译功能发送请求：
![image-20250518132911071](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250518132911071.png)

发现并没有运行至断点，说明定位不对，换个搜索继续直至找到sign的位置，发现只有app.1695dab9.js中的sign两次触发断点：
![image-20250518220020610](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250518220020610.png)

可以初步判断这里就是我们目标的sign就是这里，我们可以验证一下，首先清空网络请求，再次触发翻译至断点，然后选中这个sign的内容，右键在控制台求值：
![Firefox 2025-05-18 22.08.39](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/Firefox%202025-05-18%2022.08.39.png)

可以看到求值是固定的，这里如果有经验的话可以初步判断是类似md5的算法了：
![image-20250518221627241](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250518221627241.png)

可以分析一下这里S函数的两个参数：
![image-20250518221823634](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250518221823634.png)

a很明显是一个时间戳，而e疑似是salt这种东西

我们还可以发现，每次请求，两次触发断点时的sign值都是不一样的：
![image-20250519000026137](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519000026137.png)

分析网络请求，可知第二次断点的sign值就是我们的翻译请求包的值：

* 第一次断点的请求：

  ![image-20250519000419635](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519000419635.png)

* 第二次断点的请求：
  ![image-20250519000502457](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519000502457.png)

接下来定位到S函数内部进行分析，可以从选中函数jump to definition：
![image-20250519001106483](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519001106483.png)

也可以选择从断点处步进：

![image-20250519001151991](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519001151991.png)

这样我们可以发现S函数的定义就在请求代码上面：
![image-20250519001245241](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519001245241.png)

可以看到mysticTime就是我们传入的时间戳，key就是我们传入的salt，再分析一下函数内模板字面量的其他两个值d和u：

![image-20250519001759155](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519001759155.png)

可以看到client和product的值其实是汉语拼音，验证后可以知道这两个参数是固定的

我们上面提到了S函数返回的sign格式疑似md5，于是将这里函数内的这串参数拿去试一下：

~~~
client=fanyideskweb&mysticTime=1747584582990&product=webfanyi&key=Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3
~~~

md5后：
![image-20250519002905256](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519002905256.png)

我们得到了md5字符串`f7809939d67c6626ff2c0552ec6f04d9`，这和第二次断点的sign一致：

![image-20250519003004210](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519003004210.png)

表明确实是使用标准md5无魔改，并且我们分析S函数时可以看见内部调用的是`_`函数，定位后可以确认的确是md5加密算法：
![image-20250519003308548](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519003308548.png)

这一部分加密用python实现：
~~~python
def get_sign(time,key):
    md5_obj = md5()
    md5_obj.update(f'client=fanyideskweb&mysticTime={time}&product=webfanyi&key={key}'.encode())

    sign = md5_obj.hexdigest()
    return sign
~~~

经过分析我们已经基本搞懂加密部分了，但是细心一点就会发现我们的key也就是盐值，每次请求会变，那么接下来的问题就是分析它的动态盐值逻辑了

#### 动态盐值解决

因为salt是动态的，并且需要client和server同步，所以很大可能是client向server请求的，在网络请求中搜索salt值定位一下：
![image-20250519101959566](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519101959566.png)

发现是在js中进行获取的，那么我们获取的方法很明显了，直接请求这个js然后正则匹配获取salt，和上面同样的方法，转化为python，但是请求中依然有sign：
![image-20250519110511678](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519110511678.png)

分析一下就知道这个肯定是第一次调用S函数时获取的，那么想要解决第二次的salt，就要先获取第一次的salt，调试定位一下，发现第一次的salt是在app.js中加载的：

![image-20250519110704671](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519110704671.png)

那么我们也可以请求然后正则：

~~~python
def get_salt1():
    url = "https://shared.ydstatic.com/dict/translation-website/0.6.1/js/app.1695dab9.js"
    response = requests.get(url, headers=HEADERS)
    return re.findall(pattern='="([a-zA-Z0-9]{20})"', string=response.text)[-1]

~~~

这样是可以获得第一个salt，接下来是第二个，需要时间戳➕sign：
~~~python
def get_salt2(salt1):
    t = int(round(time.time() * 1000))

    url = "https://dict.youdao.com/webtranslate/key"
    params = {
        "keyid": "webfanyi-key-getter",
        "sign": get_sign(t,salt1),
        "client": "fanyideskweb",
        "product": "webfanyi",
        "appVersion": "1.0.0",
        "vendor": "web",
        "pointParam": "client,mysticTime,product",
        "mysticTime": t,
        "keyfrom": "fanyi.web",
        "mid": "1",
        "screen": "1",
        "model": "1",
        "network": "wifi",
        "abtest": "0",
        "yduuid": "abcdefg"
    }
    response = requests.get(url, headers=HEADERS, cookies=COOKIES, params=params)

    return re.findall(pattern='"([a-zA-Z0-9]{32})"', string=response.text)[-1]
~~~

再将函数进行统一调用：
~~~python
import requests
import time
from encode import get_sign, get_salt1, get_salt2, COOKIES, HEADERS

url = "https://dict.youdao.com/webtranslate"
# 获取时间戳
t = int(round(time.time() * 1000))
key1 = get_salt1()
key2 = get_salt2(key1)
data = {
    "i": "你好",
    "from": "auto",
    "to": "",
    "useTerm": "false",
    "dictResult": "true",
    "keyid": "webfanyi",
    "sign": get_sign(t,key2),
    "client": "fanyideskweb",
    "product": "webfanyi",
    "appVersion": "1.0.0",
    "vendor": "web",
    "pointParam": "client,mysticTime,product",
    "mysticTime": t,
    "keyfrom": "fanyi.web",
    "mid": "1",
    "screen": "1",
    "model": "1",
    "network": "wifi",
    "abtest": "0",
    "yduuid": "abcdefg"
}
response = requests.post(url, headers=HEADERS, cookies=COOKIES, data=data)

print(response.text)
print(response)
~~~

这样我们便使用python实现了和有道前端一样的请求加密逻辑：
![image-20250519141420362](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519141420362.png)

至此，我们完成了加密的全过程，接下来就是响应结果的解密了

### 解密逻辑分析
