---
title: "GraphQL渗透测试学习"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# 浅谈GraphQL渗透测试

### 前置知识

#### GraphQL概念

GraphQL是一个用于 API的查询语言，下面我用通俗的语言来谈谈它的特点：

>简单说，**GraphQL 是一种“灵活取数据”的工具**。比如你点外卖时，可以自由组合菜品，而不用按固定套餐点。GraphQL 的作用类似：**前端可以按需“点”数据，后端精准返回**

那么这里就可以看出GraphQL与传统Rest API的区别了，我们同样以”点外卖“来描述：

* **Rest API**：固定套餐，比如

  * 套餐A：用户信息（姓名、头像）
  * 套餐B：用户的朋友列表
  * 套餐C：用户的订单记录

  那么可以看出来它的**局限**：如果你想同时要“用户姓名”和“朋友列表”，得点两次套餐（发两次请求），或者让后端临时做个新套餐（改接口）

* **GraphQL**：自助餐，想要什么直接通过接口告诉后端，比如下面这个请求：

  ~~~graphql
  query {
    user {
      name          # 只要姓名
      friends {     # 和朋友列表
        name
      }
    }
  }
  ~~~

  这个请求能够，一次精准拿到 `name` 和 `friends` 数据，不会多拿（比如不需要头像），也不会少拿

通过上面的描述，我们能够知道GraphQL API与Rest API最大的区别：GraphQL 通过将数据查询和数据修改分离开来，使得客户端能够更灵活地控制所需数据的粒度和类型，并且在多个资源之间建立关系

#### GraphQL查询方式

查询方式主要有：

- Query
- Mutation
- Subscription
- Input
- Enum
- Union
- Interface

最常见的是`Query`、`Mutation`、`Subscription`三种，这里简单举例：

##### Query（查询）

用于获取数据，只读取不修改：

~~~graphql
query 操作名称(可选参数) {
  字段名(参数) {
    子字段
  }
}
~~~

##### Mutation（变更）

用于修改数据，属于写操作，会改变服务器状态：

~~~graphql
mutation 操作名称(输入参数) {
  操作名(输入) {
    返回的字段
  }
}
~~~

##### Subscription（订阅）

实时监听数据变化（类似 WebSocket），属于长连接，服务器主动推送数据：

~~~graphql
subscription 操作名称 {
  监听的事件名 {
    返回的字段
  }
}
~~~

##### 例

简单介绍了，再举个例子，请求如下：

~~~graphql
# 查询用户信息及其文章标题
query GetUserWithPosts($userId: ID!) {
  user(id: $userId) {
    name
    email
    posts(limit: 5) {
      title
      createdAt
    }
  }
}
~~~

那么响应格式为：

~~~json
{
  "data": {
    "user": {
      "name": "小明",
      "email": "xiaoming@example.com",
      "posts": [
        { "title": "GraphQL 教程", "createdAt": "2023-01-01" }
      ]
    }
  }
}
~~~

这里基础概念就介绍这么多，更详细的介绍可以参考官网

### GraphQL渗透测试

#### API发现

##### 通过路径特征

因为GraphQL的“自助餐”特性，它的接口路径比较固定，常见的路径如下：

~~~
/graphql
/graphiql
/gql
/query
/graph
/v1/graphql
/v2/graphql
/v3/graphql
/v1/graphiql
/v2/graphiql
/v3/graphiql
/api/graphql
/api/graphiql
/graphql/api
/v1/api/graphql
/v2/api/graphql
/console
/playground
/graphql/console
/graphql-devtools
/graphql-explorer
/graphql-playground
/graphql-playground-html
/laravel-graphql-playground
/graphql.php                  # PHP 实现
/index.php?graphql            # PHP 参数化
/HyperGraphQL                 # 特定框架
/portal-graphql
/graphql/schema.json          # Schema 文件
/graphql/schema.xml
/graphql/schema.yaml
......
~~~

例如：

![image-20250202160256769](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202160256769.png)

##### 报错信息判断

一些不正确的请求（POST->GET）或者参数缺失可能导致报错，即可借此判断：

![image-20250202154852355](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202154852355.png)

##### 通过请求探测

通过一些比较通用的payload进行请求尝试，比如`query{__typename}`

这里举个例子，我们可以使用fofa随便找一个使用了GraphQL的网站，首先用fofa语法搜集graphql报错的网页：

~~~fofa
body="Must provide query string" || body="GraphQL validation failed"
~~~

查询后随便开一个网页：

![image-20250202152954939](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202152954939.png)

现在报错是因为没有提供query参数，我们使用POST方法传一个通用的payload进行请求探测（注意）`Content-Type`最好改成`application/json`：

~~~json
{"query":"query{__typename}"}
~~~

![image-20250202153230282](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202153230282.png)

可以看到响应从400变成200，查询成功，如此即可判断网站使用了graphql API，请求成功后burp会自动再请求这里新增一个GraphQL模块，可以直接在这里构造graphql请求：

![image-20250202154303680](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202154303680.png)

当然，我们可以继续使用`__schema`字段进行**内省查询**，这个字段在所有查询的根类型上都可用：

* 查询接口中的可用类型：

  ~~~graphql
  query {
    __schema {
      types {
        name
      }
    }
  }
  ~~~

  ![image-20250202154450630](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202154450630.png)

* 更详细的架构信息：

  ~~~graphql
  query {__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}
  ~~~

  ![image-20250202154545078](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202154545078.png)

#### 攻击面的展开

##### 信息泄露/越权

不当的配置可能导致网站的graphql架构以及存储的敏感数据暴露

有的API使用内省查询可以列出列出GraphQL中所有Query、Mutation、ObjectType、Field、Arguments：

~~~graphql
query IntrospectionQuery {
      __schema {
        
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      
      
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
      
      
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  
~~~

返回包返回的就是该API端点的所有信息，例如这个站：

![image-20250202205825154](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202205825154.png)

放到[GraphQL Voyager](https://graphql-kit.com/graphql-voyager/)中可以生成可视化的文档：

![image-20250202205738134](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202205738134.png)

效果：

![image-20250202205708874](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202205708874.png)

在列出的信息中，寻找敏感信息比如email、password、secretKey、token、licenseKey、session，还可以多多关注废弃的字段（deprecated fields）

那么上面的信息里可以看到很多email，我们来试着查询一下：

![image-20250202212125282](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250202212125282.png)

这里401了，可以看到正常情况下，查询是需要鉴权的，如果权限校验不当，就会造成越权或者未授权查询，下面是笔者遇到的鉴权不当导致的批量查看用户邮箱以及密码哈希：

![image-20250203173949170](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250203173949170.png)

当然除此以外还可以搜索类型中是否有edit、delete、remove、add等功能，来达到数据编辑、删除、添加的功能，这里就不再一一举例了

##### GraphQL注入

相信在介绍GraphQL的时候也能注意到，它的功能其实有点类似于SQL的增删改查，这个，而这个GraphQL注入其实也和SQL注入类似

所谓注入，无非就是构造闭合并插入其他语句执行，这个漏洞P神也在先知白帽大会分享过，一看就懂（红色部分为用户可控的注入数据）：

![image-20250204153359429](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250204153359429.png)

漏洞的出现场景大致为graphql语句不可控，但语句中的某一部分参数用户可控，网页逻辑大致为：

用户访问URL -> 前端获取参数 -> 拼接成GraphQL语句 -> 发送 -> 后端执行

在这种情况下，就可以尝试GraphQL注入改变原本的GraphQL语义进行漏洞利用

和SQL类似，防御这类漏洞使用参数化查询即可，原理如下：

* GraphQL语句中声明变量并指定类型：

  ~~~graphql
  query GetUser($id: ID!) {
    user(id: $id) {
      name
      email
    }
  }
  ~~~

* 通过独立的参数（如JSON）传入变量值，而非直接拼接字符串:

  ~~~json
  { "id": "123" }
  ~~~

* 那么这样最后的查询即使是`123") { deleteUser } # `这类可能造成注入的payload，也不会被解析为操作，在json中表现为：

  ~~~json
  { "id": "123) { deleteUser }" }
  ~~~

##### SQL注入等传统漏洞

除了GraphQL注入，SQL注入也是可能出现的

笔者还发现有的文章将GraphQL注入和SQL注入混为一谈，其实两者有很大区别

首先我们要理清GraphQL API和SQL之间在网页上可能存在的联系，如下：

~~~
客户端 → GraphQL API（参数化查询） → 服务端解析 → 数据库查询（可能含SQL拼接） → 数据库执行
~~~

那么很明显了，如果服务端在处理 GraphQL 参数时直接将用户输入拼接到 SQL 语句中，可能触发 **SQL 注入**

同理，这类传统漏洞都有可能存在比如：代码执行、命令执行、XSS、SSRF、任意文件读取等

再者，也有可能使用批量/递归/重复查询进行拒绝服务攻击利用

##### 相关工具的前端漏洞

GraphiQL（一个浏览器GraphQL客户端，纯前端应用）及使用其的Graphene-Django框架可能会产生一些前端漏洞比如CSRF、click hijacking等，可以自行了解详情

### 总结

GraphQL算是一个国内外比较常见的API了，泄漏、注入、未授权的测试都比较方便，在SRC中可以多加关注
