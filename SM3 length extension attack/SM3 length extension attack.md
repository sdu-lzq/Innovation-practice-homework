### SM3 length extension attack

这里对SM3的长度扩展攻击进行实现，这里基于MD结构的性质

- 攻击者可以控制message
- 攻击者需要知道key的长度，如不知道可以考虑暴力破解
- 攻击已经知道了包含key的一个消息的hash值
- hash算法使用了Merkle–Damgard construction进行数据的压缩（比如MD5、SHA-1等）并采取 **H**(*密钥* ∥ *消息*) 构造

攻击可以达到的效果在于，如果知道一个原消息哈希值H(key∥M1)及其(key∥M1)长度，对于任意的字符串M2，攻击者可以计算出H(pad(key∥M1) + M2)的值，而不需要知道是key及M1是多少

#### 代码实现

长度扩展攻击

1.随机生成一个消息m1，用SM3计算出Hash值（hash1）

2.生成一个附加消息m‘，首先用hash1推导出结束后Iv的值，作为初始的链接变量

3.用IV加密m’得到hash2

4.继续计算m1+padding+m'的hash值（hash3），如果攻击成功，hash2和hash3应该相等

```python
def length_extend_attack(_m,length_old):
    New_iv = []
    for i in range(8):
        New_iv.append(int(Hash1[i*8:i*8+8],16))
    #将原mssage的hash结果进行分组作为新的iv值
    length = hex((length_old+len(_m))*4)[2:]
    #计算出加上m’后的消息总长度
    length = (16-len(length))*'0' + length
    #最后填充的消息的长度
    _m = _m + '8'
    #首先在后面填充一个1
    if len(_m)%128 > 112:
        _m = _m + '0'*(128-len(_m)%128+112)+length
        # (l+1)%512>448先补余，然后再填448
    else:
        _m = _m + '0'*(112-len(_m)%128)+length
    group_m = SM3.Group(_m)
    group_number = len(group_m)
    V = [New_iv]
    #创建一个二维数组
    for i in range(group_number):
        V.append(SM3.CF(V,group_m,i))
    #逐步对分组进行迭代
    res = ''
    for va in V[group_number]:
        res += hex(va)[2:]
    return res
```

#### 验证结果

![image-20220730162458590](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730162458590.png)