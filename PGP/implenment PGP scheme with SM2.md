## implenment PGP scheme with SM2

PGP是混合加密系统

1.生成会话密钥，这里用SM2密钥交换协议进行实现

2.信息发送方用SM2公钥对会话密钥进行加密，并用会话密钥通过对称加密算法

对data进行加密，将会话密钥加密和data加密发送给接受方

3.接收方对会话密钥用SM2私钥解密，用会话密钥对data解密获取最终的data

![image-20220730210947314](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730210947314.png)

#### 代码实现

AES代码实现

```python
def Pad(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  

def AES_encrypt(key, text):
    aes = AES.new(Pad(key), AES.MODE_ECB)  
    encrypt_aes = aes.encrypt(Pad(text))  
    text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  
    return text

def AES_decrypt(key, text):
    aes = AES.new(Pad(key), AES.MODE_ECB)  
    base64_text = base64.decodebytes(text.encode(encoding='utf-8'))  
    text = str(aes.decrypt(base64_text), encoding='utf-8').replace('\0', '')  
    return text
```

发送方和接受方

```python
def PGP_Send(pK,data,Com_key):
    #Com_key = Get_str(20) 随机生成,或者采用密钥交换进行生成
    ciphertext =AES_encrypt(Com_key,data)
    cipherkey,length,lenx = encryption(Com_key,pK)
    print("加密完成，加密消息是:",ciphertext)
    return ciphertext,cipherkey,length,lenx


def PGP_Receive(d,ciphertext,cipherkey,length,lenx):
    temp = decryption(cipherkey,d,length,lenx)
    temp = bytes.fromhex(temp)
    Com_key = temp.decode()
    plaintext = AES_decrypt(Com_key,ciphertext)
    print("解密完成，明文是:",plaintext)
    return 
```

#### 结果验证

我们直接对代码进行执行

也可以对代码进行修改，采用随机生成K而不适用密钥交换协议实现

![image-20220730215008477](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730215008477.png)
