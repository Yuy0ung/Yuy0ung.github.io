---
title: "CodeQL基础"
date: 2025-12-11T00:00:00+08:00
draft: false
weight: 1
---

# CodeQL基础

## 配置

简单说一下环境配置

引擎地址：https://github.com/github/codeql-cli-binaries/releases，下载后配置环境变量：

![QQ_1764324742906](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1764324742906.png)

然后安装sdk：https://github.com/github/codeql，改名成ql，放在之前引擎的同目录下：

![image-20251128181257723](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251128181257723.png)

然后在vscode安装插件：

![QQ_1764324799890](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1764324799890.png)

在设置里添加一下CodeQL可执行文件的位置：

![image-20251128181342913](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251128181342913.png)

用CodeQL分析项目本质是执行查询，首先需要去待审计源代码的根目录建立分析数据库，我这里分析的一个开源的漏洞合集：https://github.com/l4yn3/micro_service_seclab/

首先要建立分析数据库：
~~~sh
codeql database create javaseclabstest --language="java" --command="mvn clean install -Dmaven.test.skip=true" --source-root=/Users/yuy0ung/Desktop/SAST/micro_service_seclab-main
~~~

![image-20251203175126741](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251203175126741.png)

执行成功你应该可以在这个目录里看到一个codeqltest目录:

![QQ_1764325090840](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1764325090840.png)

接着我们在vscode引入这个目录：

![QQ_1764502485467](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1764502485467.png)

然后我们新建一个query： `demo.ql`，内容为`select "Hello World`“，位置为`CodeQL/ql/java/ql/examples/test.ql`

接下来运行query：
![image-20251202172201418](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251202172201418.png)

可以看到结果输出了hello world，说明配置没有问题了

## CodeQL基础语法

### ql语法

说白了就是查询语法，QL查询的语法结构为：

```sql
from [datatype] var
where condition(var = something)
select var
```

比如：
~~~sql
import java

from int i
where i = 1
select i
~~~

* 第一行表示我们要引入CodeQL的类库，因为我们分析的项目是java的，所以要import java（如果QL文件在 `ql\java\ql\` 目录中时就不需要 `import java` 了，因为这是 CodeQL 标准库目录，其会自动隐式加载该目录下的依赖，但如果写在其他目录下就需要手动 `import java` ，包括其子目录）
* 第三行表示定义一个int型变量i，表示我们获取所有的int类型的数据
* 第四行为判定条件
* 第五行为输出i

也就是说在所有的整形数字i中，当i==1的时候，就输出i，按照这个逻辑，最终的输出就应该为1:
![image-20251203135714622](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251203135714622.png)

到这里我们不难看出来CodeQL规则编写思路：查询的区域->过滤规则->输出

### 类库

上面说了CodeQL引擎会将代码转换为数据库，这个数据库其实就是可识别的AST数据库

在AST里面Method代表的就是类当中的方法；比如说我们项目的所有的方法调用，MethodAccess获取的就是所有的方法调用
下面是常用的类库：

| Method       | 方法类，Method method表示获取当前项目中所有的方法            |
| ------------ | ------------------------------------------------------------ |
| MethodAccess | 方法调用类，MethodAccess call表示获取当前项目当中的所有方法调用 |
| Parameter    | 参数类，Parameter表示获取当前项目当中所有的参数              |

现在获取项目当中定义的所有方法：

~~~sql
import java

from Method i
select i
~~~

![image-20251203141635241](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251203141635241.png)

可以看到所有的方法都被查询出来了，接下来运用下面的语法：

* hashName() 判断名字是否匹配
* getName() 获取当前方法的名称
* getDeclaringType() 获取当前方法所属class的名称

可以得到这样的查询语句：

~~~sql
import java
 
from Method i
where i.hasName("delete")
select i.getName(), i.getDeclaringType()
~~~

可以查询出来所有名为delete的方法：

![image-20251203175448092](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251203175448092.png)

### 谓词

如果限制条件比较多，where 语句就会很冗长，CodeQL提供一种机制可以帮助我们把很长的查询语句封装成函数，而这个函数，就叫谓词

比如上面的demo我们可以改成这样：
~~~sql
import java

# predicate 表示当前方法没有返回值
predicate isDel(Method i) {
    i.getName()="delete"
}

from Method i
where isDel(i)
select i.getName(), i.getDeclaringType()
~~~

查询效果也是一样的：
![image-20251203175605966](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251203175605966.png)

### 设置Source与Sink

> 在代码自动化安全审计的理论当中，有一个最核心的三元组概念，就是(source，sink和sanitizer)
>
> source是指漏洞污染链条的输入点。比如获取http请求的参数部分，就是非常明显的Source
>
> sink是指漏洞污染链条的执行点，比如SQL注入漏洞，最终执行SQL语句的函数就是sink(这个函数可能叫query或者exeSql，或者其它)
>
> sanitizer又叫净化函数，是指在整个的漏洞链条当中，如果存在一个方法阻断了整个传递链，那么这个方法就叫sanitizer，也就是waf

只有当source和sink同时存在，并且从source到sink的链路是通的，才表示当前漏洞是存在的

#### Source点

在CodeQL中我们通过以下方法来设置Source：

~~~sql
override predicate isSource(DataFlow::Node src) {}
~~~

我的项目使用的是`Spring Boot`框架，那么source就是http参数入口的代码参数，比如在下面的代码中，source就是username：

~~~sql
@RequestMapping(value = "/one")
public List<Student> one(@RequestParam(value = "username") String username) {
    return indexLogic.getStudent(username);
}
~~~

这里我们设置为：

~~~sql
override predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
~~~

`RemoteFlowSource` 是 CodeQL 标准库中预定义的 **“远程数据源”** 类，比如HTTP 请求参数，用户输入以及其他外部输入等都是

这是`SDK`自带的规则，里面包含了大多常用的Source入口。我们使用的SpringBoot也包含在其中，可以直接使用。

注: instanceof 语法是CodeQL提供的语法，后面在CodeQL进阶部分会提到，这里就是检查获得的 src 是否为 RemoteFlowSource

#### Sink点

通过以下方法来设置Sink

```
override predicate isSink(DataFlow::Node sink) {}
```

在实际中，我们最后都是触发到某个恶意方法，如 getter，setter，所以 sink 应该是个方法，假设我们这里的sink 点是个数据库的`query`方法(Method)的调用(MethodAccess)，所以我们设置Sink为：

```sql
override predicate isSink(DataFlow::Node sink) {
exists(Method method, MethodAccess call |
      method.hasName("query")
      and
      call.getMethod() = method and
      sink.asExpr() = call.getArgument(0)
	  )
}
```

> 这里我们使用了exists子查询，这个是CodeQL谓词语法里非常常见的语法结构，它根据内部的子查询返回true or false，来决定筛选出哪些数据。
>
> `sink.asExpr() = call.getArgument(0)`：将 sink 节点转换为表达式，并检查它是否等于 `call` 的第一个参数
>
> 故上面sink语句的作用是查找一个query()方法的调用点，并把它的第一个参数设置为sink

当刚才设置的source变量流入这个方法时，说明注入点和触发点是通的，就能产生注入漏洞

### flow数据流

设置好Source和Sink，就相当于搞定了首尾，接下来就是疏通中间的利用链。一个受污染的变量，能够毫无阻拦的流转到危险函数，就表示存在漏洞

这个连通工作就是CodeQL引擎本身来完成的。我们通过使用`config.hasFlowPath(source, sink)`方法来判断是否连通。

比如如下代码：

```sql
from VulConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"
```

> 我们传递给`config.hasFlowPath(source, sink)`我们定义好的source和sink，系统就会自动帮我们判断是否存在漏洞了。
>
> `source.getNode()`：获取源节点的底层语法树节点（AST Node），显示漏洞源头在代码中的具体位置

## 代码分析&规则编写

接下来针对上面加载的项目数据库进行练手，当然这里的规则更多是先开枪后画靶，学习ql规则编写的思路，后续会再更新一篇偏向通用的规则编写的

### SQL

首先写个 ql 查询代码来检测 sql 注入漏洞，因为sink点是query，所以代码如下:

~~~sql
/**
 * @id java/examples/vuldemo
 * @name Sql-Injection
 * @description Sql-Injection
 * @kind path-problem
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import DataFlow::PathGraph

class VulConfig extends TaintTracking::Configuration {
     VulConfig() { this = "SqlInjectionConfig"}
    
    override predicate isSource(DataFlow::Node src) {
        src instanceof RemoteFlowSource
    }
    
    override predicate isSink(DataFlow::Node sink) {
        exists(Method method, MethodAccess call |
            method.hasName("query")
            and
            call.getMethod() = method and
            sink.asExpr() = call.getArgument(0)
        )
    }

}

from VulConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"
~~~

CodeQL 在定义类上的语法和 Java 类似，其中 extends 的父类 `TaintTracking::Configuration` 是官方提供用来做数据流分析的通用类，提供很多数据流分析相关的方法，比如isSource(定义source)，isSink(定义sink)

`src instanceof RemoteFlowSource` 表示src 必须是 RemoteFlowSource 类型。在RemoteFlowSource里，官方提供很非常全的source定义，我们本次用到的Springboot的Source就已经涵盖了。

- 注：上面的注释和其它语言是不一样的，不能够删除，它是程序的一部分，因为在我们生成测试报告的时候，上面注释当中的name，description等信息会写入到审计报告中。

这里的`isSource` 和`isSink` 根据自己需要进行重写，而判断中间是否疏通可以使用CodeQL提供的`config.hasFlowPath(source, sink)`来帮我们处理

查询后可以看到，从source点到sink点的链路直接显示出来了：

![image-20251203180745222](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251203180745222.png)

这里爆警告说是 `DataFlow::PathGraph` 在新版本中被弃用了，所以这段代码只能在低版本的规则库里跑

这里开头有 `@kind path-problem` ，说明结果至少是4列，写了这个结果就会输出完整的污点传播路径，除此之外对输出还有其他要求，比如每列要输出的类型也有要求等

跟进代码，可以直接看到sink点的代码内容：

![image-20251203181514727](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251203181514727.png)

#### 误报处理

我们分析source点，发现有一处 sql 注入，其输入的参数类型为 `List<Long>` ，即纯数字，不可能存在注入：

![image-20251204151645772](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251204151645772.png)

说明我们给的限制并未严格要求参数类型，就会导致以上的误报产生，我们可以用 isSanitizer 来避免这种情况：

isSanitizer是CodeQL的类TaintTracking::Configuration提供的净化方法，它的函数原型如下：
~~~sql
override predicate isSanitizer(DataFlow::Node node) {}
~~~

在CodeQL自带的默认规则里，对当前节点是否为基础类型做了判断:

~~~sql
override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node.getType() instanceof NumberType
}
~~~

表示如果当前节点是上面提到的基础类型，那么此污染链将被净化阻断，漏洞将不存在，可以看到这里默认规则只是一些基础类型，没有类似 `List<long>` 等的复合类型，所以我们需要将 TaintTracking::Configuration 中的 isSanitizer 重写下：

~~~sql
override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node.getType() instanceof NumberType or
    exists(ParameterizedType pt| node.getType() = pt and pt.getTypeArgument(0) instanceof NumberType ) 
    # 这里的 ParameterizedType 代表所有泛型，判断泛型当中的传参是否为 Number 型
 }
~~~

这样在检测到 `List<long>` 时就会将其净化掉，这样链子就不通了，也就不会出现误报了：

![image-20251204152404479](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251204152404479.png)

#### 关于lombok

由于java的封装特性，每一个变量都要写`setter`和`setter`很麻烦，所以就有了`lombok`，引入以来后通过`@Data`注解就可以自动实现`getter`和`setter`（不是自动补全代码的方式实现）

可以看到这里是能识别到的：
![image-20251204153247577](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251204153247577.png)

如果不能识别，可以通过如下的方法快速还原`setter`和`getter`方法，来自[github issue](https://github.com/github/codeql/issues/4984)：

~~~sh
# get a copy of lombok.jar
wget https://projectlombok.org/downloads/lombok.jar -O "lombok.jar"
# run "delombok" on the source files and write the generated files to a folder named "delombok"
java -jar "lombok.jar" delombok -n --onlyChanged . -d "delombok"
# remove "generated by" comments
find "delombok" -name '*.java' -exec sed '/Generated by delombok/d' -i '{}' ';'
# remove any left-over import statements
find "delombok" -name '*.java' -exec sed '/import lombok/d' -i '{}' ';'
# copy delombok'd files over the original ones
cp -r "delombok/." "./"
# remove the "delombok" folder
rm -rf "delombok"
~~~

#### 漏报

此时我们发现我们的ql代码根本无法查询mybatis的注入：

![image-20251204160920016](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251204160920016.png)

主要原因是我们的sink点判断使用的判断query，而mybatis的查询是在运行期把注解字符串（含 ${}）处理后交给它自己的执行器，所以还需要优化sink点判断规则，思路是定位字面含有 "${"的字面量并找到调用该 mapper 方法的调用点，所以最终的代码：

~~~sql
/**
 * @id java/examples/vuldemo
 * @name Sql-Injection
 * @description Sql-Injection
 * @kind path-problem
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import DataFlow::PathGraph

class VulConfig extends TaintTracking::Configuration {
    VulConfig() { this = "SqlInjectionConfig" }
    
    override predicate isSource(DataFlow::Node src) {
        src instanceof RemoteFlowSource
    }
    
    override predicate isSink(DataFlow::Node sink) {
        exists(Method method, MethodAccess call |
            method.hasName("query")
            and
            call.getMethod() = method
            and
            sink.asExpr() = call.getArgument(0)
        )
				//新增的mybatis场景判断
        or
        exists(Method mapperMethod, MethodAccess mapperCall, StringLiteral dollarLit, int startLineMeth, int endLineLit |
            // 找到一个字符串字面量，字面含有 "${"
            dollarLit.toString().indexOf("${") >= 0 and
            // 同一源码文件
            dollarLit.getLocation().getFile() = mapperMethod.getLocation().getFile() and
            // 获取方法起始行与字面量结束行
            startLineMeth = mapperMethod.getLocation().getStartLine() and
            endLineLit = dollarLit.getLocation().getEndLine() and
            // 字面量应出现在方法上方（或同一行）
            endLineLit <= startLineMeth and
            // 找到调用该 mapper 方法的调用点
            mapperCall.getMethod() = mapperMethod and
            // 把第一个实参视作 sink
            sink.asExpr() = mapperCall.getArgument(0)
        )
    }

    override predicate isSanitizer(DataFlow::Node node) {
        node.getType() instanceof PrimitiveType or
        node.getType() instanceof BoxedType or
        node.getType() instanceof NumberType or
        exists(ParameterizedType pt | node.getType() = pt and pt.getTypeArgument(0) instanceof NumberType )
    }
}

from VulConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "SQL injection"
~~~

此时的ql就能查询出mybatis的注入场景了：
![image-20251204162338988](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251204162338988.png)

不过这里的mybatis注入场景是将语句写在java文件的，后续还需要考虑xml形式的mybatis注入场景