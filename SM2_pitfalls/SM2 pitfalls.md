## SM2 pitfalls

#### leaking k leads to leaking d

首先对消息进行签名

Compute$d_{A}$with $\sigma = (r,s)$and k

计算过程，直接带入公式计算

- $s=\left(\left(1+d_{A}\right)^{-1} \cdot\left(k-r \cdot d_{A}\right)\right) \bmod n$
- $s\left(1+d_{A}\right)=\left(k-r \cdot d_{A}\right) \bmod n$
- $d_{A}=(s+r)^{-1} \cdot(k-s) \bmod n$

```python
def leaking_k(r,s,k):
    da = (inverse_mod(s+r,n)*(k-s))%n
    print("利用泄露的k计算私钥:",da)
    return 
```

#### Reusing K

恢复原理如图 ，在使用相同k的情况下，我们直接使用推导公式就可以恢复出相应的私钥

![image-20220730232958638](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730232958638.png)

```python
def reuse_k(Za,da,k):
    m1 = "message1"
    m2 = "message2"
    r1,s1 = signature(m1,Za,da,k)
    r2,s2 = signature(m2,Za,da,k)
    da = ((s2-s1)%n*inverse_mod((s1-s2)%n+(r1-r2)%n,n))%n
    print("重复使用k，计算出的公钥为:",da)
    return 
```

#### reusing k by different users

不同的user使用相同的k进行签名计算，则对方就可以利用签名值对对方的私钥进行计算

![image-20220730233222450](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730233222450.png)

在对方获取到签名值的情况下，可以使用推导公式进行计算

```python
def reuse_k_users(Za,da,k):
    m1 = "message1"
    m2 = "message2"
    print("Bob和Alice使用相同k进行签名")
    r1,s1 = signature(m1,Za,da,k)
    r2,s2 = signature(m2,Za,da,k)
    print("Alice deduce Bob key:",((k-s2)*inverse_mod(s2+r2,n))%n)
    print("Alice deduce Bob key:",((k-s1)*inverse_mod(s1+r1,n))%n)
    return
```

#### same d and k with ECDSA

SM2签名算法和ECDSA签名算法如果使用相同的私钥和k，就可以通过ECDSA和SM2的签名值将私钥的值进行恢复

![image-20220730234137003](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730234137003.png)

```python
def same_d_k(Za,sK,k):
    m = "hello"
    r1,s1,e1 = ECDSA_Sign(m,sK,k)
    r2,s2 = signature(m,Za,sK,k)
    da = ((s1*s2-e1)*inverse_mod(r1-s1*s2-s1*r2,n))%n
    print("ECDSA和SM2使用相同的k和d计算da:",da)
    return
```

#### 结果验证

我们在main函数中已经对相应计算模块进行接入，可以直接进行运行

![image-20220730234415240](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730234415240.png)