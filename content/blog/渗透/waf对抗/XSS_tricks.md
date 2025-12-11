---
title: "XSS_tricks"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# XSS_tricks

记录一些适用于bypass waf的XSS小tricks

以及一些不是很容易想到的可以测试XSS的场景

## 巧用反引号

> 该trick来自于0xsdeo师傅的Spade sec公众号

反引号可以达到一个不用括号的效果，很适合用于`()`括号被转义后的情况

比如下面几个demo：

* 控制台输出：

  ~~~html
  <script>console.log`1`;</script>
  ~~~

* 弹窗：

  ~~~html
  <script>alert`1`;</script>
  ~~~

在这里，反引号引起来的内容叫做模板字面量，又称模板字符串，在es6中一般用来字符串插值：

~~~js
let name = 'Yuy0ung';
`hello ${name}`
~~~

效果如下：

![image-20250510100006369](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250510100006369.png)

在除了这种用法外，就是我们payload的用法了，即配合默认或自定义标签函数

那么，除了弹窗和控制台输出，获取cookie就需要再构造一下了，思路和上面的字符串插值很像：

~~~js
console.log`${document.cookie}`
~~~

![image-20250510102443520](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250510102443520.png)

可以注意到这里有一个多余的数组，具体原因可以查阅es6文档，这里不做赘述

当然这个数组会导致我们使用alet弹不出cookie，所以推荐使用console.log

**总结：**上面的payload优势在于反引号、`$`、`{}`三种符号不容易被转义，巧用了模板字面量的特性

### 文件上传XSS的content-type绕过

除了常规的`text/html`的content-type，还可以有一些其他的：

* text/htm
* htm/text
* html/text

都可以试一试，主要基于后端的配置，在思考bypass的时候可以从这方面进行思考

## 可能存在XSS的非常规场景

### OCR服务处

比如有些功能点支持OCR识别发票文字内容并输出，那么我们可以在图片上P一个XSS的payload进行测试，这是一个很巧妙的思路

### hidden标签处

F12全局搜索hidden标签，可能找到一些不显示但是内容可控的标签，比如用于页面跳转功能的隐藏标签，比如下面这个demo：

![image-20250510110728205](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250510110728205.png)

name是ReturnUrl，这里尝试直接GET传参：

![image-20250510110750381](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250510110750381.png)

发现value可控，那么就可以尝试构造闭合：

![image-20250510110909523](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250510110909523.png)

可以看见成功闭合了，那么接下来就是直接打XSS：

![image-20250510111140278](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250510111140278.png)

