---
title: "gin框架"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# gin框架

## 快速入门

初始化go mod

~~~sh
go mod init <项目名>
~~~

下载gin依赖

~~~sh
go get -u github.com/gin-gonic/gin
~~~

创建一个example.go:

~~~go
package main

import "github.com/gin-gonic/gin"

func main() {
	router := gin.Default()
	router.GET("/whoami", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello Yuy0ung",
		})
	})
	router.Run(":5003") //在5003端口监听并启动服务
}
~~~

运行：

~~~go
go run example.go
~~~

访问127.0.0.1:5003

![QQ_1757061218743](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757061218743.png)



## 包

~~~go
package main
~~~

## 导入

~~~go
import (
	"github.com/gin-gonic/gin"
	"github.com/thinkerou/favicon"
)
~~~

## 主函数

### 启动

启动到5003端口，一般在主函数最后

~~~go
r.Run(":5003")
~~~

### 基础资源

~~~~go
	r := gin.Default()
	r.Static("/static", "./static")
	r.Use(favicon.New("./static/favicon.ico"))
~~~~

### 首页

~~~go
	r.GET("/index", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "index",
		})
	})
~~~

### 404

~~~go
	r.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{
			"message": "no route",
		})
	})
~~~

### get传参

~~~go
	// get传参
	r.GET("/user", func(c *gin.Context) {
		username, ok := c.GetQuery("user")
		if !ok {
			c.JSON(200, gin.H{
				"message": "need a username",
			})
			return
		}
		password := c.DefaultQuery("pass", "123456")
		c.JSON(200, gin.H{
			"message":  "get",
			"username": username,
			"password": password,
		})
	})
~~~

### 路径传参

~~~go
	// 路径传参
	r.GET("/ctf/:name", func(c *gin.Context) {
		name := c.Param("name")
		c.JSON(200, gin.H{
			"message": "CTF就该学" + name,
		})
	})
~~~

### json传参

~~~go
	// json传参
	r.POST("/json", func(c *gin.Context) {
		var user struct {
			Name string `json:"name"`
			Pass string `json:"pass"`
		}
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(400, gin.H{
				"message": "参数错误",
			})
		}
		c.JSON(200, gin.H{
			"name": user.Name,
			"pass": user.Pass,
		})
	})
~~~

### 静态html页面

~~~go
	// 静态页面
	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{
			"title": "Gin",
		})
	})
~~~

### 重定向到外站

~~~go
	//重定向到cnblogs
	r.GET("/blog", func(c *gin.Context) {
		c.Redirect(302, "www.cnblogs.com/yuy0ung/")
	})
~~~

### 跳转到页面

~~~go
	r.POST("/tologin", func(c *gin.Context) {
		c.Request.URL.Path = "/login"
		r.HandleContext(c)
	})
~~~

### 登录

~~~go
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		// username := c.Query("username")
		// password := c.Query("password")
		if username == "admin" && password == "admin" {
			c.JSON(200, gin.H{
				"status":  "ok",
				"message": "登录成功",
			})
		} else {
			c.JSON(200, gin.H{
				"status": "error",
			})
		}
	})
~~~

### 文件上传

配合前端使用：

~~~go
	//文件上传页面
	r.GET("/upload", func(c *gin.Context) {
		c.HTML(200, "upload.html", gin.H{
			"title": "上传文件",
		})
	})
	r.POST("/upload", func(c *gin.Context) {
		//从请求中读取文件
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(500, gin.H{
				"message": "上传文件失败",
			})
			return
		}
		//保存文件至./files
		err = c.SaveUploadedFile(file, "./files/"+file.Filename)
		if err != nil {
			c.JSON(500, gin.H{
				"message": "保存文件失败",
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "上传成功",
		})
	})
~~~

### 路由组

就是平时见到的/api/v1/xxx那种,可以嵌套

~~~go
	//路由组
	v1 := r.Group("/api")
	{
		v1.GET(/whoami", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "Yuy0ung",
			})
		})
		//嵌套
		user := v1.Group("/user")
		{
			user.GET("/1", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "user1",
				})
			})
			user.GET("/2", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "user2",
				})
			})
		}
	}
~~~

### 中间件

可多层：

~~~go
// 定义中间件
func auth(c *gin.Context) {
	fmt.Println("auth in")
	c.Next()
	fmt.Println("auth out")
}
func status(c *gin.Context) {
	fmt.Println("status in")
	c.Next()
	fmt.Println("status out")
}
func main() {
	r := gin.Default()
	r.Static("/static", "./static")
	r.Use(favicon.New("./static/favicon.ico"))

	r.GET("/auth", auth, status, func(c *gin.Context) {
		fmt.Println("authpage in")
		c.JSON(200, gin.H{
			"message": "auth",
		})
	})
  //.......
}
~~~

全局注册：

![QQ_1757065653808](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757065653808.png)

路由组注册：

![QQ_1757065715015](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757065715015.png)

传递信息：

![QQ_1757065949025](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757065949025.png)

访问auth路由的输出顺序：

~~~
auth in
status in
authpage in
ok
status out
auth out
~~~

携程传参：

![QQ_1757066447279](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1757066447279.png)

这里的携程函数时异步的，不会阻塞主请求流程，执行时机由 Go runtime 调度器决定，所以通常会“延迟”，表现为最后才打印
