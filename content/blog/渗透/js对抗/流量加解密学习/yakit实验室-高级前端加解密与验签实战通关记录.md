---
title: "yakit实验室-高级前端加解密与验签实战通关记录"
date: 2025-12-11T00:00:00+08:00
draft: false
---

# yakit靶场-高级前端加解密与验签实战

感谢kio师傅指路，发现https://vulinbox.bachang.org/#这个宝藏靶场，当然有yakit也可以在本地搭建

这里默认读者已经拥有js逆向基础，不会细讲一些知识点了，更多是过程体现，以及如何配合galaxy实现自动的加解密

galaxy的基础使用可以看我这篇文章：[网站流量加解密场景入门&Galaxy使用](https://yuy0ung.github.io/blog/%E6%B8%97%E9%80%8F/js%E5%AF%B9%E6%8A%97/%E6%B5%81%E9%87%8F%E5%8A%A0%E8%A7%A3%E5%AF%86%E5%AD%A6%E4%B9%A0/%E7%BD%91%E7%AB%99%E6%B5%81%E9%87%8F%E5%8A%A0%E8%A7%A3%E5%AF%86-galaxy%E4%BD%BF%E7%94%A8/)

文中我编写的的http hook已经打包上传至我的github：https://github.com/Yuy0ung/galaxy_HttpHook_for_yakit-vulinbox，需要可以自取

## 前端签名HMAC-SHA256

首先分析表单数据判断，前端是做了签名的：

![image-20250519142956094](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519142956094.png)

签名后的数据包：
![image-20250525160043291](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525160043291.png)

js中定位一下加解密代码块：
![image-20250519143242662](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519143242662.png)

很贴心，注释都写好了，简单分析一下

~~~js
    function outputObj(jsonData) {
        const word = `username=${jsonData.username}&password=${jsonData.password}`;;
        return {
            "signature": Encrypt(word),
            "key": key.toString(),
            username: jsonData.username, password: jsonData.password,
        }
    }
~~~

从这段代码可以分析出，签名是将我们传入的`	username=admin&password=123456`进行了hmac_sha256加密，而密钥就是将`1234123412341234`转16进制即`31323334313233343132333431323334`

>值得一提的是CryptoJS 的 key 在没有明确指定编码方式的情况下，默认的 `toString` 方法将输出十六进制 (Hex) 格式的字符串
>
>当然CryptoJS还有其他很多编码器，在进行js分析时候，需要注意编码情况，不然会浪费大量不必要的时间

我们可以自行加密验证一下：

![image-20250519144447944](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519144447944.png)

签名确实和加密后的表单一致

那么接下来写个http hook：

~~~python
import json
import hmac
import hashlib
import typing as t
from fastapi import FastAPI
from _base_classes import *

SECRET_KEY = b"1234123412341234"  # 固定HMAC key（16字节）
KEY_STR = SECRET_KEY.hex()  # 发送到服务器时作为key字段

app = FastAPI()


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp，解密，方便Burp看到明文"""
    # 获取原始数据
    content_dict = json.loads(request.content)
    # 移除签名与key
    content_dict.pop("signature", None)
    content_dict.pop("key", None)
    # 转回字节流
    request.content = json.dumps(content_dict).encode()
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server，加密，加上HMAC签名"""
    # 解析原始数据
    content_dict = json.loads(request.content)
    # 构造待签名字符串（如 username=admin&password=123456）
    sign_str = "&".join(f"{k}={v}" for k, v in content_dict.items())
    signature = hmac_sha256(sign_str.encode(), SECRET_KEY)
    # 构造新结构
    content_dict["signature"] = signature
    content_dict["key"] = KEY_STR
    request.content = json.dumps(content_dict).encode()
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    """Server -> Burp，不涉及解密，直接透传"""
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    """Burp -> Client，不涉及加密，直接透传"""
    return response


def hmac_sha256(data: bytes, key: bytes) -> str:
    mac = hmac.new(key, data, hashlib.sha256)
    return mac.hexdigest()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

运行hook：

![image-20250525154957066](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525154957066.png)

看到hook正在监听8003端口，接下来burp上配置并启动hook：

![image-20250525155134602](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525155134602.png)

开启hook后再抓包，可以看到请求中的json已经自动解密：
![image-20250519152510851](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519152510851.png)

再试试放包：

![image-20250519152706057](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519152706057.png)

签名校验成功，这代表我们的hook是没有问题的

到这里自动加解密已经成功实现了，接下来直接爆破：

![image-20250519152247196](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519152247196.png)

爆破成功，账户密码为admin/admin

## 前端签名HMAC-SHA256+RSA

依然是签名

![image-20250519153546028](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519153546028.png)

定位到加解密代码：

![image-20250519153645822](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519153645822.png)

分析一下可以知道，signature在原本hmac_sha256的基础上进行了RSA加密，并且每次都会向server的`/crypto/js/rsa/public/key`路由动态获取RSA的公钥

>值得一提的是：
>
>jsrsasign 是前端常用的 RSA 加解密的库，一般这样调用：
>
>~~~js
>KEYUTIL.getKey(publicKey).encrypt(...)
>~~~

简单更改一下hook即可:

~~~python
import json
import hmac
import hashlib
import typing as t
import requests
from fastapi import FastAPI
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from _base_classes import *

SECRET_KEY = b"1234123412341234"  
KEY_STR = SECRET_KEY.hex() 
RSA_PUBLIC_KEY_URL = "http://127.0.0.1:8787/crypto/js/rsa/public/key"

app = FastAPI()


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp，解密"""
    content_dict = json.loads(request.content)
    content_dict.pop("signature", None)
    content_dict.pop("key", None)
    request.content = json.dumps(content_dict).encode()
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server，加密签名 + RSA 公钥加密"""
    content_dict = json.loads(request.content)

    # 构造签名字符串
    sign_str = "&".join(f"{k}={v}" for k, v in content_dict.items())

    # HMAC-SHA256摘要
    hmac_signature = hmac_sha256(sign_str.encode(), SECRET_KEY)

    # 获取RSA公钥并加密签名
    rsa_pub_pem = fetch_rsa_public_key()
    encrypted_signature = rsa_encrypt(hmac_signature, rsa_pub_pem)

    # 加入加密签名与key字段
    content_dict["signature"] = encrypted_signature
    content_dict["key"] = KEY_STR
    request.content = json.dumps(content_dict).encode()
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response


# --- 加密与工具函数 ---

def hmac_sha256(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def fetch_rsa_public_key() -> str:
    """向服务端获取RSA公钥（PEM格式）"""
    try:
        res = requests.get(RSA_PUBLIC_KEY_URL, timeout=3)
        res.raise_for_status()
        return res.text
    except Exception as e:
        raise RuntimeError(f"无法获取RSA公钥: {e}")


def rsa_encrypt(data: str, pubkey_pem: str) -> str:
    """使用RSA公钥对HMAC签名加密，返回Base64字符串"""
    rsa_key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(data.encode())
    return encrypted.hex()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

依旧抓包检验：
![image-20250519155946048](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519155946048.png)

可以看到自动加解密没什么问题，接下来就是爆破：

![image-20250519161212941](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519161212941.png)

成功爆破：admin/admin

## AES-CBC前端加密

可以看到加密后已经完全看不懂了，有data、key、iv三个参数：
![image-20250519164232080](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519164232080.png)

定位到加解密代码：

![image-20250519164432235](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519164432235.png)

经分析可以得出：

* 加密为AES默认的CBC
* key的十六进制为31323334313233343132333431323334
* iv为随机生成

而加解密过程就明显了：
![image-20250519165429916](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519165429916.png)

在submiJSON中可以看到，是将原本账号密码的json经过AES-CBC处理变成data，并和key、iv组成新的json发送至server，那么写一个http hook：
~~~python
import json
import base64
import typing as t
import os
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from _base_classes import *

SECRET_KEY = b"1234123412341234"  # 16字节 key
KEY_HEX = SECRET_KEY.hex()

app = FastAPI()


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp：解密"""
    # 解析加密 JSON
    encrypted_json = json.loads(request.content)
    iv_hex = encrypted_json["iv"]
    data_b64 = encrypted_json["data"]

    # 解密内容
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(base64.b64decode(data_b64)), AES.block_size)

    request.content = decrypted
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server：加密"""
    raw_json = request.content  # 明文 JSON（字节）
    iv = os.urandom(16)

    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(raw_json, AES.block_size))

    encrypted_json = {
        "data": base64.b64encode(ciphertext).decode(),
        "key": KEY_HEX,
        "iv": iv.hex()
    }

    request.content = json.dumps(encrypted_json).encode()
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

抓包验证：
![image-20250519170753430](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519170753430.png)

自动加解密成功，开始爆破：
![image-20250519171105655](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519171105655.png)

爆破成功：admin/admin

## AES-ECB前端加密

和上面的类似，不点在于ECB模式不需要iv，这里就不分析了，http hook如下：

~~~python
import json
import base64
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from _base_classes import *

SECRET_KEY = b"1234123412341234"  # 16字节 key
KEY_HEX = SECRET_KEY.hex()

app = FastAPI()


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp：解密"""
    encrypted_json = json.loads(request.content)
    data_b64 = encrypted_json["data"]

    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(data_b64)), AES.block_size)

    request.content = decrypted
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server：加密"""
    raw_json = request.content  # 原始 JSON（字节）

    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(raw_json, AES.block_size))

    encrypted_json = {
        "data": base64.b64encode(ciphertext).decode(),
        "key": KEY_HEX
    }

    request.content = json.dumps(encrypted_json).encode()
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

自动加解密成功：

![image-20250519173044780](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519173044780.png)

爆破成功：

![image-20250519173242753](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519173242753.png)

## AES-ECB SQL注入

乍一看和上一个没区别，但是说是打SQL注入，手测一下发现username可以注入：
![image-20250519232542380](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519232542380.png)

hook不用改直接用galaxy的send decrypted request to sqlmap：

![image-20250519205809794](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250519205809794.png)

sqlmap跑一下（因为sql的代理走的burp，所以）：

（这里不知道什么原因，在本地搭建的靶场使用sqlmap的时候，发现对本地IP的http流量到不了burp，于是使用的[vulinbox在线靶场](https://vulinbox.bachang.org/#)继续实验）

![](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250523181752622.png)

确实能打，这里就不进一步注入了

## AES-ECB SQL注入+bypass认证

前端没变，只是在密码处增加了注入点，依然用前面的http hook即可：

![image-20250524161920929](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250524161920929.png)

## AES-ECB表单加密

这次的加密提交的表单：
![image-20250524162720490](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250524162720490.png)

从前端代码上看，不同点是加密后的json有了个iv，未加密的json中多了一项age：
![image-20250524165222936](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250524165222936.png)

但是从密码学角度上分析，iv在这里是没有作用的，所以我们依然可以直接用前面的http hook自动加解密：

![image-20250524203937243](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250524203937243.png)

## RSA表单加密

这一关用的是RSA加密，json中给出了data、公私钥及其base64（这几关本地靶场的前端资源加载有问题，用的在线靶场，后面发现更新一下靶场就好了）

![image-20250524205344541](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250524205344541.png)

加密后表单的json一大坨哈哈哈哈：
![image-20250525155733233](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525155733233.png)

js找到加解密代码：
![image-20250525154518566](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525154518566.png)

分析可知：

* RSA-OAEP加密
* 填充方案的哈希函数是sha256（一般默认是sha1）

根据分析的结果以及json结构编写http hook：

~~~python
import json
import base64
import typing as t
from fastapi import FastAPI
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from _base_classes import *

app = FastAPI()
JSON_KEY = "data"
app.state.pubkey = None
app.state.prikey = None

@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp：解密"""
    encrypted_json: t.Dict = json.loads(request.content)

    encrypted_data: bytes = get_data(request.content)
    prikey_b64 = encrypted_json["privateKeyBase64"]

    pubkey_b64 = encrypted_json["publicKeyBase64"]

    pubkey = base64.b64decode(pubkey_b64)
    prikey = base64.b64decode(prikey_b64)
    app.state.pubkey = pubkey
    app.state.prikey = prikey
    
    prikey = base64.b64decode(prikey_b64)  
    decrypted : bytes = decrypt(encrypted_data, prikey)
    request.content = decrypted
    return request

@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server：加密"""

    data: bytes = request.content

    public_key = app.state.pubkey
    encryptedData: bytes = encrypt(data, public_key)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    
    request.content = body
    return request

@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response

def decrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted_data = cipher.decrypt(content)
    assert isinstance(decrypted_data, bytes)
    return decrypted_data


def encrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher.encrypt(content)


def get_data(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json[JSON_KEY])

def to_data(content: bytes) -> bytes:
    pubkey = app.state.pubkey
    prikey = app.state.prikey
    pubkey_str = pubkey.decode()
    prikey_str = prikey.decode()
    pubkey_b64 = base64.b64encode(pubkey).decode()
    prikey_b64 = base64.b64encode(prikey).decode()

    body_json = {
        "data": "",
        "publicKey": "",
        "publicKeyBase64": "",
        "privateKey": "",
        "privateKeyBase64": ""
        }
    body_json[JSON_KEY] = base64.b64encode(content).decode()
    body_json["publicKey"] = pubkey_str
    body_json["publicKeyBase64"] = pubkey_b64
    body_json["privateKey"] = prikey_str
    body_json["privateKeyBase64"] = prikey_b64
    return json.dumps(body_json).encode()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

成功实现自动加解密：
![image-20250525155409385](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525155409385.png)

## RSA表单加密（远程动态获取密钥）

可以看到加密后的数据是没有密钥的：

![image-20250525163109995](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525163109995.png)

![image-20250525163206875](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525163206875.png)

分析js可知公钥是从服务端动态获取的：

![image-20250525163413781](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525163413781.png)



看一下获取时的返回：
![image-20250525163833494](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250525163833494.png)

既然这个接口公私钥都能获取，那么就在上一个hook的基础上做更改（由于在线靶场的密钥接口有点延迟，所以我把timeout调成30了，正常来说不用这么长）：
~~~python
import json
import base64
import typing as t
import requests
from fastapi import FastAPI
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from _base_classes import *

app = FastAPI()
JSON_KEY = "data"
app.state.pubkey = None
app.state.prikey = None


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp：解密"""
    fetch_rsa_keys()

    encrypted_data: bytes = get_data(request.content)
    prikey = app.state.prikey
    
    decrypted : bytes = decrypt(encrypted_data, prikey)
    request.content = decrypted
    return request

@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server：加密"""
    fetch_rsa_keys()

    data: bytes = request.content

    public_key = app.state.pubkey
    encryptedData: bytes = encrypt(data, public_key)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    
    request.content = body
    return request

@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response

def decrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted_data = cipher.decrypt(content)
    assert isinstance(decrypted_data, bytes)
    return decrypted_data


def encrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher.encrypt(content)


def get_data(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json[JSON_KEY])

def to_data(contnet: bytes) -> bytes:
    body_json = {
        "data": ""
        }
    body_json[JSON_KEY] = base64.b64encode(contnet).decode()
    return json.dumps(body_json).encode()

def fetch_rsa_keys() -> t.Tuple[bytes, bytes]:
    url = "http://127.0.0.1:8787/crypto/js/rsa/generator"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        app.state.pubkey = data["publicKey"].encode()
        app.state.prikey = data["privateKey"].encode()
    except Exception as e:
        raise RuntimeError(f"无法获取RSA密钥: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

成功自动加解密：
![image-20250526003250437](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526003250437.png)

## RSA表单加密+响应加密（远程动态获取密钥）

和上一关不同的是响应也加密了：
![image-20250526004237414](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526004237414.png)

响应（这里靶场还很贴心的给出了data解密后的origin作为参考）：
![image-20250526004422463](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526004422463.png)

解密函数：
![image-20250526004817945](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526004817945.png)

根据解密逻辑继续修改上面的hook：

~~~python
import json
import base64
import typing as t
import requests
from fastapi import FastAPI
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from _base_classes import *

app = FastAPI()
JSON_KEY = "data"
app.state.pubkey = None
app.state.prikey = None


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp：解密"""
    fetch_rsa_keys()

    encrypted_data: bytes = get_data(request.content)
    prikey = app.state.prikey
    
    decrypted : bytes = decrypt(encrypted_data, prikey)
    request.content = decrypted
    return request

@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server：加密"""
    fetch_rsa_keys()

    data: bytes = request.content

    public_key = app.state.pubkey
    encryptedData: bytes = encrypt(data, public_key)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    
    request.content = body
    return request

@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    fetch_rsa_keys()

    encrypted_data: bytes = get_data(response.content)
    prikey = app.state.prikey
    
    decrypted : bytes = decrypt(encrypted_data, prikey)
    response.content = decrypted
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response

def decrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted_data = cipher.decrypt(content)
    assert isinstance(decrypted_data, bytes)
    return decrypted_data


def encrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher.encrypt(content)


def get_data(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json[JSON_KEY])

def to_data(content: bytes) -> bytes:

    body_json = {
        "data": ""
        }
    body_json[JSON_KEY] = base64.b64encode(content).decode()
    return json.dumps(body_json).encode()

def fetch_rsa_keys() -> t.Tuple[bytes, bytes]:
    url = "http://127.0.0.1:8787/crypto/js/rsa/generator"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        app.state.pubkey = data["publicKey"].encode()
        app.state.prikey = data["privateKey"].encode()
    except Exception as e:
        raise RuntimeError(f"无法获取RSA密钥: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

成功自动加解密请求和响应：
![image-20250526005342069](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526005342069.png)

## RSA加密AES密钥，服务器传输

>由于RSA加解密有长度限制，以及解密速度等问题，所以如https等协议都是用非对称加密对称加密的密钥，然后用对称加密算法来加密数据

可以看到加密的json又不一样了：
![image-20250526170437353](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526170437353.png)

![image-20250526165824400](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526165824400.png)

分析一下js，RSA的key依旧是远程动态获取的：

![image-20250526171153292](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526171153292.png)

加解密流程：

![image-20250526172300525](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250526172300525.png)

可以判断请求内容和响应是AES-GCM加密(这里tag直接拼接在data末尾)，随机生成的key和iv又被RSA加密了，写个hook：

~~~python
import json
import base64
import typing as t
import requests
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from _base_classes import *

app = FastAPI()
JSON_KEY = "data"
app.state.pubkey = None
app.state.prikey = None
app.state.iv = None
app.state.key = None


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp：解密"""
    fetch_rsa_keys()

    encrypted_iv: bytes = get_iv(request.content)
    encrypted_key: bytes = get_key(request.content)
    encrypted_data: bytes = get_data(request.content)
    

    prikey = app.state.prikey

    iv : bytes = rsa_decrypt(encrypted_iv, prikey)
    key : bytes = rsa_decrypt(encrypted_key, prikey)
    decrypted: bytes = aes_decrypt(encrypted_data, key, iv)
    set_iv_keys(iv, key)

    request.content = decrypted
    return request

@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server：加密"""
    fetch_rsa_keys()

    data: bytes = request.content

    key = app.state.key
    iv = app.state.iv

    encryptedData: bytes = aes_encrypt(data, key, iv)

    body: bytes = to_data(encryptedData)
    # 更新body
    
    request.content = body
    return request

@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    fetch_rsa_keys()

    encrypted_iv: bytes = get_iv(response.content)
    encrypted_key: bytes = get_key(response.content)
    encrypted_data: bytes = get_data(response.content)
    set_iv_keys(encrypted_iv, encrypted_key)

    prikey = app.state.prikey

    iv : bytes = rsa_decrypt(encrypted_iv, prikey)
    key : bytes = rsa_decrypt(encrypted_key, prikey)
    decrypted: bytes = aes_decrypt(encrypted_data, key, iv)

    response.content = decrypted
    return response

@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response

def rsa_decrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted_data = cipher.decrypt(content)
    assert isinstance(decrypted_data, bytes)
    return decrypted_data

def aes_decrypt(ciphertext_with_tag: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext_with_tag[:-16], ciphertext_with_tag[-16:])
    return plaintext

def rsa_encrypt(content: bytes, public_key: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted_data = cipher.encrypt(content)
    return encrypted_data

def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag 

def get_data(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json[JSON_KEY])
def get_iv(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json["encryptedIV"])
def get_key(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json["encryptedKey"])

def to_data(content: bytes) -> bytes:
    pubkey = app.state.pubkey
    iv = app.state.iv
    key = app.state.key
    encrypt_key = rsa_encrypt(key, pubkey)
    encrypt_iv = rsa_encrypt(iv, pubkey)
    body_json = {
        "data": "",
        "iv": "",
        "encryptedIV": "",
        "encryptedKey": ""
        }
    body_json[JSON_KEY] = base64.b64encode(content).decode()
    body_json["iv"] = iv.decode()
    body_json["encryptedIV"] = base64.b64encode(encrypt_iv).decode('utf-8')
    body_json["encryptedKey"] = base64.b64encode(encrypt_key).decode('utf-8')
    return json.dumps(body_json).encode()

def fetch_rsa_keys() -> t.Tuple[bytes, bytes]:
    url = "http://127.0.0.1:8787/crypto/js/rsa/generator"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        app.state.pubkey = data["publicKey"].encode()
        app.state.prikey = data["privateKey"].encode()
    except Exception as e:
        raise RuntimeError(f"无法获取RSA密钥: {e}")
    
def set_iv_keys(iv: bytes, key: bytes) -> t.Tuple[bytes, bytes]:
    app.state.iv = iv
    app.state.key = key

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

成功自动加解密：
![image-20250527010203875](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527010203875.png)

## SQL 注入(从登陆到 Dump 数据库)

最后一关，这是一个登录场景：
![image-20250527140223797](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527140223797.png)

抓个包看看加密：
![image-20250527140326772](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527140326772.png)

目测是请求和响应都做了aes加密，分析js可知是CBC模式：

![image-20250527140554520](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527140554520.png)

那么很简单了，写个hook：

~~~python
# 第十二关
import json
import base64
import typing as t
import os
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from _base_classes import *

app = FastAPI()

app.state.key = None
app.state.key_hex = None

@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """客户端 -> Burp：解密"""
    # 解析加密 JSON
    encrypted_json = json.loads(request.content)
    key_hex = encrypted_json["key"]
    key = bytes.fromhex(key_hex)
    app.state.key = key
    app.state.key_hex = key_hex
    iv_hex = encrypted_json["iv"]
    data_b64 = encrypted_json["message"]

    # 解密内容
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(base64.b64decode(data_b64)), AES.block_size)

    request.content = decrypted
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """Burp -> Server：加密"""
    raw_json = request.content  # 明文 JSON（字节）
    iv = os.urandom(16)
    key = app.state.key
    key_hex = app.state.key_hex

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(raw_json, AES.block_size))

    encrypted_json = {
        "key": key_hex,
        "iv": iv.hex(),
        "message": base64.b64encode(ciphertext).decode(),
    }

    request.content = json.dumps(encrypted_json).encode()
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    encrypted_json = json.loads(response.content)
    key_hex = encrypted_json["key"]
    key = bytes.fromhex(key_hex)
    app.state.key = key
    app.state.key_hex = key_hex
    iv_hex = encrypted_json["iv"]
    data_b64 = encrypted_json["message"]

    # 解密内容
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(base64.b64decode(data_b64)), AES.block_size)

    response.content = decrypted
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
~~~

成功自动加解密：

![image-20250527145958913](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527145958913.png)

由于题目说是注入，所以试试万能密码：

![image-20250527150211246](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527150211246.png)

直接登录成功返回token了，进去看看：

![image-20250527150733270](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527150733270.png)

发现有一个查询功能，并且hook自动解密了一个查询的请求包：

![image-20250527150710412](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527150710412.png)

既然是查询，那么这里很容易想到能否注入，sql代理到burp一把梭（同样因为本地靶场sqlmap代理不了，跑的在线靶场😓）：

![image-20250527151859065](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527151859065.png)

发现存在SQLite注入，但是由于在线靶场比较脆弱经常502，这里就不dump数据库了😁

不过话又说回来，既然加解密都实现了，那就手注试试，这里用的是联合查询注入：

* order by发现是3列：

  ![image-20250527182705743](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527182705743.png)

* 联合查询查看回显位：

  ![image-20250527182759950](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527182759950.png)

* 读取数据库结构信息：
  ![Burp Suite Professional 2025-05-27 18.29.03](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/Burp%20Suite%20Professional%202025-05-27%2018.29.03.png)

* 读取vulin_users表：
  ![image-20250527183118023](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527183118023.png)

* 查询表中数据：
  ![image-20250527183321570](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20250527183321570.png)





至此我们通关了整个yakit的vulinbox靶场