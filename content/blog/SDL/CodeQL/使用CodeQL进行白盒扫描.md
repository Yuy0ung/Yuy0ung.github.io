---
title: "使用CodeQL进行白盒扫描"
date: 2025-12-17T00:00:00+08:00
draft: false
weight: 10
---

# 使用CodeQL进行白盒扫描

接下来学点不一样的，从企业安全建设角度出发，我们通常会根据codeQL提供的的CWE漏洞规则，针对代码进行扫描，我们选取以下CWE规则：

~~~
【注入类】
- SQL Injection (089)
- XSS (079)
- Command Exec (078)
- Expression / Code Injection (094)
- SSRF (918)
- XXE (611)

【资源访问类】
- Path Traversal (22)

【反序列化】
- Unsafe Deserialization (502)

【认证授权】
- Authentication Bypass (287)
- Authorization Bypass (807)

【敏感信息】
- Hardcoded Credentials (798)
~~~

接下来以https://github.com/whgojp/JavaSecLab/项目为例

## SQL注入

我们使用codeql官方的规则进行sql注入扫描（记得先构建数据库）：

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-089 \
  --format=sarif-latest \
  --output=sql.sarif
~~~

![image-20251216104533092](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216104533092.png)

可以看到扫描完成后在文件夹新增了一个sarif文件，这个就是扫描结果文件，可以在vscode下载sarif viewer插件进行解析查看：
![6f2bac46131bc294ac75406979531746](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/6f2bac46131bc294ac75406979531746.png)

同理我们可以检测其他漏洞

## XXE

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-611 \
  --format=sarif-latest \
  --output=xxe.sarif
~~~

![image-20251216110152690](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216110152690.png)

## SSRF

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-918 \
  --format=sarif-latest \
  --output=ssrf.sarif
~~~

![image-20251216110412396](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216110412396.png)

## RCE

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-078 \
  --format=sarif-latest \
  --output=rce-command.sarif
~~~

![image-20251216111645006](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216111645006.png)

## 不安全的反序列化

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-502 \
  --format=sarif-latest \
  --output=deserialize.sarif
~~~

![image-20251216112903627](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216112903627.png)

这个规则挺牛逼，各种反序列化都照顾到了

## 表达式注入

针对SPEL这类

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-094 \
  --format=sarif-latest \
  --output=spel.sarif
~~~

![image-20251216114342745](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216114342745.png)

## XSS

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-079 \
  --format=sarif-latest \
  --output=xss.sarif
~~~

![image-20251216114626355](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216114626355.png)

## 硬编码

~~~sql
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-798 \
  --format=sarif-latest \
  --output=cwe-798-hardcoded-credentials.sarif
~~~

![image-20251216182123703](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216182123703.png)

## 目录穿越/任意文件

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-022 \
  --format=sarif-latest \
  --output=cwe-022-path-traversal.sarif
~~~

![image-20251216182419768](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216182419768.png)

## 认证/授权绕过

~~~sh
codeql database analyze ~/tools/CodeQL/db/javasecpro \
  codeql/java-queries:Security/CWE/CWE-287 \
  codeql/java-queries:Security/CWE/CWE-807 \
  --format=sarif-latest \
  --output=auth-and-authorization-bypass.sarif
~~~

## 漏报处理

针对上面的扫描结果，分析了靶场源码，也在代码搭建的平台上进行了验证，发现有一定的误报，不过宁可错杀不可放过，这些甚至能够扫描出来靶场没有考虑到的一些地方的漏洞

接下来处理漏报的情况

### 反射调用触发的 RCE

RCE的情况出现了漏报，因为这里是反射调用的：
![QQ_1765874156453](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1765874156453.png)

我们只能新增一个规则针对这类情况，可以适当的宽泛一点，可以概括为**用户可控的方法参数进入了反射调用 invoke 的参数**：

~~~sql
import java

from
  MethodCall invoke,
  Parameter p
where
  // 反射执行点
  invoke.getMethod().getName() = "invoke"

  // payload 的访问表达式，出现在 invoke 某个参数的表达式子树中
  and exists(Expr arg |
    arg = invoke.getArgument(_) and
    arg.getAChildExpr*() = p.getAnAccess()
  )
select
  invoke,
  p,
  "Method parameter flows into reflective Method.invoke arguments"
~~~

这样就能覆盖我们的漏洞点：

![image-20251216174608245](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251216174608245.png)

### jdbc反序列化

反序列化的扫描结果并没有jdbc，补充一下：

~~~sql
/**
 * @name Universal Unsafe Deserialization (Official Sinks + JDBC Sources)
 * @description Detects unsafe deserialization using official sink definitions plus custom JDBC sources.
 * @kind path-problem
 * @id java/universal-unsafe-deserialization-official
 * @problem.severity error
 * @security-severity 9.8
 * @tags security
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
// 引入官方库
import semmle.code.java.security.UnsafeDeserializationQuery

module UniversalDeserializationConfig implements DataFlow::ConfigSig {

  // 1. Source
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
    or
    exists(MethodCall mc |
      mc.getMethod().getName().matches("get%") and
      (
        mc.getMethod().getDeclaringType().hasName("ResultSet") or
        mc.getMethod().getDeclaringType().(RefType).getASupertype*().hasName("ResultSet") or
        mc.getMethod().getDeclaringType().(RefType).getASupertype*().hasName("java.sql.ResultSet") or
        mc.getMethod().getDeclaringType().hasName("CallableStatement") or
        mc.getMethod().getDeclaringType().(RefType).getASupertype*().hasName("java.sql.CallableStatement")
      ) and
      src = DataFlow::exprNode(mc)
    )
  }

  // 2. Sink: 使用官方定义的 Sink 集合
  predicate isSink(DataFlow::Node sink) {
    sink instanceof UnsafeDeserializationSink
  }

  // 3. Additional Steps
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Gap 1: byte[] -> new ByteArrayInputStream(byte[])
    exists(ConstructorCall cc |
      (
        cc.getConstructedType().hasName("java.io.ByteArrayInputStream") or
        cc.getConstructedType().hasName("ByteArrayInputStream")
      ) and
      cc.getArgument(0) = pred.asExpr() and
      succ.asExpr() = cc
    )
    or
    // Gap 2: InputStream -> new ObjectInputStream(InputStream)
    exists(ConstructorCall cc |
      (
        cc.getConstructedType().hasName("java.io.ObjectInputStream") or
        cc.getConstructedType().hasName("ObjectInputStream")
      ) and
      cc.getArgument(0) = pred.asExpr() and
      succ.asExpr() = cc
    )
  }

  predicate isBarrier(DataFlow::Node node) { none() }
}

module UniversalDeserializationFlow = TaintTracking::Global<UniversalDeserializationConfig>;
import UniversalDeserializationFlow::PathGraph

from UniversalDeserializationFlow::PathNode source, UniversalDeserializationFlow::PathNode sink
where UniversalDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe deserialization detected (Official Sinks + JDBC Source)"
~~~

这样就能把jdbc反序列化扫出来：

![image-20251217114754385](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251217114754385.png)

这样就可以在原有基础上扫描出来jdbc反序列化了

### JPA、hibernate、MyBatis的SQL注入

漏掉了这仨，CodeQL 的 Java 分析非常依赖编译环境（autobuild）。如果你的项目缺少 jar 包（比如没有 hibernate-core.jar ），CodeQL 就无法解析`org.hibernate.Session`这个类型，而如果代码里面写 `sink.getType().hasQualifiedName("org.hibernate.Session")`，CodeQL 会因为类型解析失败而返回 false，导致漏报

可以重写一下isSink，在官方的基础上处理疑似JPA/Hibernate的点，这里顺便也考虑了mybatis的注解场景，然后增加一下断链修复（比如复杂的字符串拼接）：

~~~sql
/**
 * @name Universal SQL Injection (Robust Hybrid Mode)
 * @description Detects SQL injection using a hybrid approach: official sinks + fuzzy type matching.
 * @kind path-problem
 * @id java/universal-sql-injection-robust-fixed
 * @problem.severity error
 * @security-severity 9.0
 * @tags security
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
// 引入官方库以复用其精准定义
import semmle.code.java.security.SqlInjectionQuery

module RobustSqlInjectionConfig implements DataFlow::ConfigSig {

  // 1. Source: 远程输入
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
  }

  // 2. Sink: 混合策略
  predicate isSink(DataFlow::Node sink) {
    // A. 官方精准 Sink
    sink instanceof QueryInjectionSink
    or
    // B. 模糊类型 Sink (针对依赖缺失场景)
    exists(MethodCall mc |
      mc.getMethod().getName() in [
        "createQuery", "createNativeQuery", "createSQLQuery", // JPA/Hibernate
        "executeQuery", "executeUpdate", "execute"            // JDBC
      ] and
      (
        mc.getQualifier().getType().getName().matches("%Session%") or        // Hibernate Session
        mc.getQualifier().getType().getName().matches("%EntityManager%") or  // JPA EntityManager
        mc.getQualifier().getType().getName().matches("%Query%") or          // Query, TypedQuery
        mc.getQualifier().getType().getName().matches("%Statement%") or      // Statement, PreparedStatement
        mc.getQualifier().getType().getName().matches("%Template%")          // JdbcTemplate, HibernateTemplate
      ) and
      sink.asExpr() = mc.getArgument(0)
    )
    or
    // C. MyBatis 注解
    exists(Annotation ann |
      ann.getType().hasName(["Select", "Update", "Insert", "Delete"]) and
      exists(string sql, Method method, Parameter param |
        sql = ann.getValue("value").(StringLiteral).getValue() and
        method = ann.getTarget() and
        param = method.getParameter(_) and
        sql.matches("%${" + param.getName() + "}%") and
        sink.asParameter() = param
      )
    )
  }

  //断链修复
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // 字符串拼接
    exists(AddExpr add |
      add.getAnOperand() = pred.asExpr() and
      succ.asExpr() = add
    )
    or
    exists(MethodCall mc |
      mc.getMethod().getName() = "append" and
      mc.getQualifier().getType().hasName("StringBuilder") and
      (
        mc.getArgument(0) = pred.asExpr() and succ.asExpr() = mc
        or
        pred.asExpr() = mc.getQualifier() and succ.asExpr() = mc
      )
    )
  }

  predicate isBarrier(DataFlow::Node node) { 
    node.getType() instanceof PrimitiveType and 
    not node.getType().hasName("char") and
    not node.getType().hasName("byte")
  }
}

module RobustSqlFlow = TaintTracking::Global<RobustSqlInjectionConfig>;
import RobustSqlFlow::PathGraph

from RobustSqlFlow::PathNode source, RobustSqlFlow::PathNode sink
where RobustSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "SQL Injection detected (Robust Mode)"
~~~

这里还遗漏了一个场景，就是MyBatis的xml Mapper场景，CodeQL 的污点追踪（Taint Tracking）通常是在 一种语言 内部进行的（从 Java Controller 到 Java Mapper）。当数据流进入 XML 文件时，链路就断了。CodeQL 不会自动把 Java 方法调用和 XML 里的 SQL 标签关联起来

我考虑的思路是 “跨语言关联与调用点阻断”：首先利用 CodeQL 的 XML 解析能力，递归遍历 MyBatis 映射文件中的所有节点（包括 `<select>` 及其嵌套的 `<if>`、`<foreach>` 等动态标签），一旦发现 `${}` 这种不安全占位符，便提取该 SQL 片段所属的 `namespace`（类名）和 `id`（方法名），反向定位到 Java 代码中的 Mapper 接口方法；接着，鉴于 Mapper 接口通常无实体实现会导致数据流中断，策略上不再试图追踪接口内部，而是直接 “劫持”所有调用该 Mapper 方法的代码位置（MethodCall），将调用处传入的参数直接标记为 Sink，从而无视复杂的代理机制和断链，精准捕获从 Controller 流入这些危险 XML 查询的污点数据：

~~~sql
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
// 引入官方库以复用其精准定义
import semmle.code.java.security.SqlInjectionQuery
// [新增] 引入 XML 库以解析 MyBatis Mapper 文件
import semmle.code.xml.XML

module RobustSqlInjectionConfig implements DataFlow::ConfigSig {

  // 1. Source: 远程输入
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
  }

  // 2. Sink: 混合策略
  predicate isSink(DataFlow::Node sink) {
    // A. 官方Sink
    sink instanceof QueryInjectionSink
    or
    // B. 模糊类型 Sink 解决依赖缺失导致类型无法解析的问题
    exists(MethodCall mc |
      mc.getMethod().getName() in [
        "createQuery", "createNativeQuery", "createSQLQuery", // JPA/Hibernate
        "executeQuery", "executeUpdate", "execute"            // JDBC
      ] and
      (
        // 使用 matches 容忍包名解析失败
        mc.getQualifier().getType().getName().matches("%Session%") or        // Hibernate Session
        mc.getQualifier().getType().getName().matches("%EntityManager%") or  // JPA EntityManager
        mc.getQualifier().getType().getName().matches("%Query%") or          // Query, TypedQuery
        mc.getQualifier().getType().getName().matches("%Statement%") or      // Statement, PreparedStatement
        mc.getQualifier().getType().getName().matches("%Template%")          // JdbcTemplate, HibernateTemplate
      ) and
      sink.asExpr() = mc.getArgument(0)
    )
    or
    // C. MyBatis 注解 Sink (@Select("${name}") 场景)
    exists(Annotation ann |
      ann.getType().hasName(["Select", "Update", "Insert", "Delete"]) and
      exists(string sql, Method method, Parameter param |
        // 1. 获取注解里的 SQL 语句
        sql = ann.getValue("value").(StringLiteral).getValue() and
        // 2. 找到 ${} 模式
        sql.matches("%${" + param.getName() + "}%") and
        // 3. 关联回方法参数
        method = ann.getTarget() and
        param = method.getParameter(_) and
        sink.asParameter() = param
      )
    )
    or
    // D. MyBatis Mapper 调用 Sink (直接标记调用点，解决 Interface 无实现导致的数据流断链问题)
    exists(MethodCall mc, Method method, Parameter param |
      // 只要方法名一致，且声明类名包含 XML namespace 的最后一部分 (类名)
      mc.getMethod().getName() = method.getName() and
      method.getDeclaringType().getQualifiedName().matches("%" + mc.getMethod().getDeclaringType().getName()) and
      
      // 确保这个 method 确实是 XML 里那个有漏洞的方法
      isMyBatisXmlSink(method, param) and
      
      // 标记调用点的参数为 Sink
      sink.asExpr() = mc.getArgument(param.getPosition())
    )
  }

  // 3. 断链修复 (增强污点流转)
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // 字符串拼接 (+)
    exists(AddExpr add |
      add.getAnOperand() = pred.asExpr() and
      succ.asExpr() = add
    )
    or
    // StringBuilder/Buffer
    exists(MethodCall mc |
      mc.getMethod().getName() = "append" and
      mc.getQualifier().getType().getName().matches("%Builder") and // 模糊匹配 StringBuilder
      (
        mc.getArgument(0) = pred.asExpr() and succ.asExpr() = mc
        or
        pred.asExpr() = mc.getQualifier() and succ.asExpr() = mc
      )
    )
  }

  // 4. 减少误报
  predicate isBarrier(DataFlow::Node node) { 
    node.getType() instanceof PrimitiveType and 
    not node.getType().hasName("char") and
    not node.getType().hasName("byte")
  }
}

module RobustSqlFlow = TaintTracking::Global<RobustSqlInjectionConfig>;
import RobustSqlFlow::PathGraph

from RobustSqlFlow::PathNode source, RobustSqlFlow::PathNode sink
where RobustSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "SQL Injection detected (Robust Mode)"

// 辅助谓词：解析 MyBatis XML 查找注入点 (移到 Module 外部)
predicate isMyBatisXmlSink(Method method, Parameter param) {
  exists(XmlElement mapper, XmlElement sqlTag, string namespace, string id, XmlCharacters chars |
    // 1. 找到 <mapper> 标签及其 namespace
    mapper.getName() = "mapper" and
    namespace = mapper.getAttribute("namespace").getValue() and
    
    // 2. 找到 <select/insert/update/delete> 标签及其 id
    sqlTag.getParent() = mapper and
    sqlTag.getName() in ["select", "insert", "update", "delete"] and
    id = sqlTag.getAttribute("id").getValue() and
    
    // 3. 不直接取 sqlTag.getTextValue()，而是递归查找该标签下的任意子标签 (XmlElement)，包括自己，这样可以覆盖 <if>, <foreach> 等动态标签内的文本
    exists(XmlElement subTag |
        (subTag = sqlTag or subTag.getParent+() = sqlTag) and
        subTag.getTextValue().indexOf("${") >= 0 and
        
        // 4. 提取包含 ${} 的那段文本
        exists(string content | content = subTag.getTextValue() |
        
            // 5. 映射回 Java 方法 (Namespace -> Class, ID -> Method)
            method.getDeclaringType().getQualifiedName() = namespace and
            method.getName() = id and
            
            // 6. 简单的参数匹配
            param = method.getParameter(_) and
            (
              // 情况 A: 参数名精准匹配
              content.indexOf("${" + param.getName() + "}") >= 0
              or
              // 情况 B: 兜底
              content.length() > 0
            )
        )
    )
  )
}
~~~

这样就可以把代码上所有的SQL注入场景都捕获了:

![image-20251217163200661](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251217163200661.png)

## 总结

在写规则的过程中，保证漏洞匹配的情况下，会适当的放宽条件，因为漏报远比误报更严重，况且误报是可以靠LLM、人工审核进行降噪的，这样会让漏洞覆盖更完整
