# SM2 2P

#### SM2 two-party sign

两方用各自生成的公私钥进行消息交换共同签名,具体流程如图

![image-20220730224717526](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730224717526.png)

```python
def Sign(msg):
    #A
    d1,pK1 = Key_gen()
    ned1 = inverse_mod(d1,p)
    P1 = Scalar_mult(ned1,G)
    print("Alice计算d1和P1,d1:{},P1:{}".format(d1,P1))
    #B
    d2,pK2 = Key_gen()
    neG = (G[0],p-G[1])
    ned2 = inverse_mod(d2,p)
    P = point_add(Scalar_mult(ned2,P1),neG)
    print("Bob计算d2，计算Public key:",P)
    #A
    Z = 'AB'
    M = msg+Z
    e = hashlib.sha256(M.encode()).hexdigest()
    e = int(e,16)
    K1 = random.randrange(1,n)
    Q1 = Scalar_mult(K1,G)
    print("Alice计算Q1和e,Bob计算r")
    #B
    K2 = random.randrange(1,n)
    Q2 = Scalar_mult(K2,G)
    K3 = random.randrange(1,n)
    x1,y1 = point_add(Scalar_mult(K3,Q1),Q2)
    r = (x1+e)%n
    s2 = (d2*K3)%n
    s3 = (d2*(r+K2))%n
    #A
    s = ((d1*K1)*s2+d1*s3-r)%n
    return r,s
```

#### SM2 two-party decrypt

双方用共同参与形成的密钥对对消息进行加密，然后一方在不泄露自身私钥的前提下，进行消息交换，让另一方能够成功对消息进行解密，具体过程如图：

![image-20220730230106205](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730230106205.png)

```python
def P2_enc_dec(M): 
    d1 = random.randrange(1,n)
    print("1.Alice生成一个私钥d1:",d1)
    d2 = random.randrange(1,n)
    print("2.Bob生成一个私钥d2:",d2)
    msg = M.encode('utf-8')
    msg = msg.hex() 
    k = random.randrange(1,n)
    c = Scalar_mult(k,G)
    #print(len(str(c[0])))
    C1 = str(c[0])+str(c[1])
    ned = inverse_mod((d1*d2)%p,p)-1
    P = Scalar_mult(ned,G)
    x2,y2 = Scalar_mult(k,P)
    lenMsg = len(msg)
    t = SM3.KDF(str(x2)+str(y2), lenMsg / 2)
    form = '%%0%dx' % lenMsg
    C2 = form % (int(msg, 16) ^ int(t, 16))
    C3 = SM3.SM3(str(x2) + msg + str(y2))
    C = C1+C2+C3
    print("利用公私钥进行加密，得到密文：",C)
    T1 = Scalar_mult(inverse_mod(d1%p,p)%p,c)
    print("Alice得到密文，计算T1:",T1)
    T2 = Scalar_mult(inverse_mod(d2%p,p)%p,T1)
    print("Bob得到T1计算T2：",T2)

    print("Alice得到T2，计算明文M")
    _c = (c[0],p-c[1])
    _P = point_add(T2,_c)
    _x2,_y2 = _P
    _x2,_y2 = Scalar_mult(k,P)
    t = SM3.KDF(str(_x2)+str(_y2), lenMsg / 2)
    form = '%%0%dx' % lenMsg
    _M = form % (int(C2, 16) ^ int(t, 16))
    u = SM3.SM3(str(_x2) + _M +str(_y2))
    if u == C3:
        return _M
    else:
        return None

```

#### 结果验证

对2P-Sign进行执行

![image-20220730230706266](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730230706266.png)

对2P-decrypt进行执行

![image-20220730231603836](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730231603836.png)
