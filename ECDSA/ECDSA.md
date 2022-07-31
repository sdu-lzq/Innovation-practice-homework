### ECDSA



我们这里使用Secp256k1的椭圆曲线参数

Secp256k1为基于Fp有限域上的椭圆曲线，由于其特殊构造的特殊性，其优化后的实现比其他曲线性能上可以提高30％，有明显以下两个优点：

> 1）占用很少的带宽和存储资源，密钥的长度很短。
>
> 2）让所有的用户都可以使用同样的操作完成域运算。

#### ECDSA签名和验签

```python
def Sign(msg,sK):
    #使用hash算法对交易明文进行hash
    msg = hashlib.sha256(msg.encode()).digest()
    hash = int.from_bytes(msg,'big')
    #生成一个随机数K，计算R = K*G 取R的x
    k = random.randrange(0,p)
    R = Scalar_mult(k,G)
    Rx = R[0]%n
    # print(R)
    s = (inverse_mod(k,n)*(hash+Rx*sK))%n
    return (Rx,s)




def verify(pK,msg,sign):
    msg = hashlib.sha256(msg.encode()).digest()
    hash = int.from_bytes(msg,'big')
    r,s = sign
    s1 = inverse_mod(s,n)
    # print((hash*s1)%n)
    _R = point_add(Scalar_mult(((hash*s1)%n),G),Scalar_mult(((r*s1)%n),pK))
    #这里出现了致命错误，要注意运算必须在模n下进行
    _r = _R[0]%n
    if _r == r:
        print('correct')
    else:
        print('false')
```

#### Deduce public key from Sign

- $\quad s=\left(\left(1+d_{A}\right)^{-1} \cdot\left(k-r \cdot d_{A}\right)\right) \bmod n$
- $s \cdot\left(1+d_{A}\right)=\left(k-r \cdot d_{A}\right) \bmod n$
- $(s+r) d_{A}=(k-s) \bmod n$
- $(s+r) d_{A} G=(k-s) G \bmod n$
- $\quad d_{A} \cdot G=P_{A}=(s+r)^{-1}(k G-s G)$

由签名我们可以反推出私钥的值

kG的计算我们可以由$(r-e) \pmod n$

y的计算需要利用二次剩余计算

##### 二次剩余计算

```python
def Tonelli(n, p):
    # 勒让德符号
    def legendre(a, p):
        return pow(a, (p - 1) // 2, p)

    assert legendre(n, p) == 1, "不是二次剩余"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

```

##### 公钥推断

```python
#Pk = (r+s)^(-1)(kG-sG)
def Deduce2(sign,msg):
    r,s = sign
    x = r %p
    y = (x**3)+7
    y = Tonelli(y,p)
    #由二次剩余得出y
    msg = hashlib.sha256(msg.encode()).digest()
    e = int.from_bytes(msg,'big')
    point = (x,y)
    # point2 = (x,p-y)
    kG = Scalar_mult(s%p,point)
    sG = Scalar_mult(e%p,G)
    nesG = (sG[0],p-sG[1])
    skG = point_add(kG,nesG)
    _pK = Scalar_mult(inverse_mod(r,n),skG)
    # skG = Scalar_mult(s%n,point2)
    # skGeG = point_add(skG,nesG)
    # __pK = Scalar_mult(inverse_mod(r,n),skGeG)
    return _pK

```

#### 结果验证

这里我们直接运行代码对结果进行验证，但在运行过程中我们发现会由一定概率恢复错误的密钥值

![image-20220730222530055](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730222530055.png)
