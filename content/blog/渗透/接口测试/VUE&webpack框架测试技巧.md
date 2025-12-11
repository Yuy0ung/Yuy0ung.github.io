---
title: "VUE&webpack框架测试技巧"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 浅谈VUE+webpack框架测试技巧

主要记录针对vue和webpack的测试技巧

## 基础知识

Vue.js 是一个渐进式 JavaScript 框架，用于构建用户界面，学过一点点前端便很好理解：

* 原生JS：要手动抓取DOM元素，用addEventListener监听点击，自己计算总价并更新页面
* Vue：你只要写好数据 cartItems 和 totalPrice，界面会自动跟着变化

而 Webpack 是一个模块打包工具，用于将项目中的各种资源（如 JavaScript 模块、CSS 样式文件、图片等）打包成浏览器可以识别的文件，同样很好理解：

假设一个大型项目，前端的文件：

- 100 份JS文件
- 50 份CSS文件
- 200 种图片字体等

正常加载的话可能需要浏览器发几百个请求，而Webpack可以很好的整合打包，一次性加载，显著降低请求的压力，比如说：

>你写了一个 .vue 文件（包含HTML/JS/CSS）
>↓
>Webpack 用 vue-loader 拆解成三部分
>↓
>JS部分交给Babel转译
>CSS部分交给PostCSS加前缀
>↓
>最后合并成 1个app.js 和 1个style.css
>↓
>浏览器只需加载2个文件就能运行整个应用

## 框架测试

接下来分析针对vue+webpack这类网站的测试技巧

### 特征识别

最简单就是看url中是否有`/#/`，如果有，很可能就是vue站点

![image-20250216012927215](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250216012927215.png)

首先就是我们常用的浏览器插件**Wappalyzer**，可以快速识别网站是否使用了webpack或vue技术：

![image-20250215182702291](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250215182702291.png)

其次学习过vue开发的就知道还有一款用于vue测试的插件**Vue.js devtools**，同样可以识别网站前端是否为vue：

* 正常情况下插件为灰色：

  ![image-20250215183018450](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250215183018450.png)

* 若网站使用了vue，插件图标则会亮起：

  ![image-20250215183109909](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250215183109909.png)

我们也可以F12查看网页加载的js文件来判断，通常是一个或少量`app.xxx.js`和一大堆`chunk-xxx.js`文件：

![image-20250215184538807](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250215184538807.png)

### API接口和路由获取

#### 常规插件

首先肯定非常方便的插件**findsomething**，能将加载出的js中的路由识别并列出：
![image-20250215185229786](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250215185229786.png)

也有类似的其他工具，比如burp的HAE、BurpJSLinkFinder等插件

#### JS文件

* 首先查看的就是app.xxx.js，通过搜索关键字（比如`path:"`）可能会找到一些路由：

  ![image-20250216182447777](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250216182447777.png)

* 上面提到了chunk结构的打包文件，在低权限状态下，有些js不会自动加载，往往这类js可能会存在大量接口和敏感信息，一般来说可以进入app.js这类文件查看所有的chunk-xxx.js：

  ![image-20250216021422486](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250216021422486.png)

* 这里我们可以写一个脚本处理这些chunk为对应url，再进行批量访问，配合burp插件等寻找隐藏接口**（比如httpx代理到burp，配合jslinkfinder和Hae进行处理）**，可以扩大攻击面：

  ![image-20250216021849481](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250216021849481.png)

* 当然，有的网站会将webpack的包给出来（也可能是webpack源码泄露，涉及source-map相关概念），那么可以尝试在其中的`/api/`、`/router/`这类目录中寻找网站路由代码：

  ![image-20250216181449762](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250216181449762.png)

#### 工具

这个时候有人问了，师傅师傅，你这些技巧还是太吃操作了，有没有更简单强势的方法推荐一下？有的兄弟，有的

懒人专属扫描工具好吧：

[GitHub - zangcc/Aakian-FaCai: 基于前端vue框架的JavaFx图形化GUI漏洞扫描工具](https://github.com/zangcc/Aakian-FaCai?tab=readme-ov-file)

当然，市面上还有很多类似工具，可以自行选择

### 接口测试

常见的就是未授权这类逻辑漏洞的测试了

比如这个某大学的案例（厚码）：

正常访问web目录是会跳转到登录页面的：

![image-20250412175228807](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250412175228807.png)

搜集分析一下路由，经典一搜一大堆：

![image-20250412175707465](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250412175707465.png)

挨着挨着尝试访问都有鉴权，直到这个/home路由：

![image-20250412175826482](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250412175826482.png)

访问发现直接进去了没有登录：

![image-20250412180008663](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250412180008663.png)

可以看见是一个大屏，泄漏了部门、金额等信息，不细说了
