## SM2

[www.gmbz.org.cn/main/viewfile/20180108015515787986.html](http://www.gmbz.org.cn/main/viewfile/20180108015515787986.html)

这里对SM2算法进行应用

首先按照官方文档中定义椭圆曲线参数，然后对基本运算进行实现

![image-20220730174701260](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730174701260.png)

SM2 parameters:prime field

然后实现基本运算

1.使用扩展欧几里得算法实现模逆运算

```python
def inverse_mod(a, p):
    old_s, s = 1, 0
    old_t, t = 0, 1
    old_r, r = a, p
    if p == 0:
        return 1, 0, a
    else:
        while r != 0:
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
            old_t, t = t, old_t - q * t
    return (old_s%p+p)%p

```

2.验证是否在曲线上

```python
def On_curve(point):
    #无穷远点
    if point is None:
        return True
    else:
        x,y = point
        return (y*y-x*x*x-a*x-b)%p == 0
#将点带入椭圆曲线方程
```

3.point_add 和point_double

![image-20220730175101696](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730175101696.png)

4.Scalar multiplication

![image-20220730175156850](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730175156850.png)

#### 加解密过程实现

首先选择一个随机私钥k，然后在生成元G生成元，在循环群上生成公钥Pa = kG

![image-20220730175607773](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730175607773.png)

加密过程如图所示，这里要用到KDF操作，我们在SM3文件中预先进行了实现

KDF全称（Key derivation function） 密钥导出函数。密码学中，密钥导出函数是指使用伪随机函数从主密钥master_key中导出一个或多个密钥key。KDF可用于将密钥扩展到更长的密钥或获得所需格式的密钥。密钥加密哈希函数是用于密钥推导的伪随机函数的流行示例。

具体步骤如下

a) 初始化一个 32 比特构成的计数器 $c t=0 \times 00000001$;
b) 对 $i$ 从 1 到 $[k l e n / v]$ 执行：
b.1) 计算 $H a_{i}=H_{v}(\mathrm{Z} \| c t)$;
b. 2) $c t^{++}$;
c) 若 $k l e n / v$ 是整数, 令 $H a !\lceil\mathrm{klm} / \mathrm{v}\rceil=H a\lceil\mathrm{klm} / \mathrm{v}\rceil$,
否则令 $H a !\lceil$ klen/v $\rceil$ 为 $H a\lceil k l e n / v\rceil$ 最左边的 $(k l e n-(v \times\lfloor k l e n / v\rfloor))$ 比特；
d) 令 $K=H a_{1}\left\|H a_{2}\right\| \cdots\left\|H a\lceil\mathrm{ken} / v\rceil_{-1}\right\| H a !\lceil\mathrm{Hem} / v\rceil$ 。

```python
def KDF(z,klen):
    klen = int(klen)
    ct = 0x00000001
    cnt = math.ceil(klen/32)
    Ha = ""
    for i in range(cnt):
        msg = z+hex(ct)[2:].rjust(8,'0')
        #print(msg)
        Ha  = Ha + SM3(msg)
        #print(Ha)
        ct += 1
    return Ha[0:klen*2]

```

解密过程

![image-20220730180636913](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730180636913.png)

```python
def encryption(M, Pk): 
    msg = M.encode('utf-8')
    msg = msg.hex()  
    k,c = Key_gen()
    C1 = str(c[0])+str(c[1]) 
    print(C1)
    lenx = len(str(c[0]))
    length  = len(C1)
    if Pk == None:
        print("Infinite point!")
        exit(1)

    x2,y2  = Scalar_mult(k,Pk)

    xy = str(x2)+str(y2)
    lenMsg = len(msg)

    t = SM3.KDF(xy, lenMsg / 2)

    if int(t, 16) == 0:
        temp = encryption(M, Pk)
        return temp
    else:
        form = '%%0%dx' % lenMsg
        C2 = form % (int(msg, 16) ^ int(t, 16))
        C3 = SM3.SM3(str(x2) + msg + str(y2))


        return C1 + C3 + C2,length,lenx


def decryption(C, Sk, length,lenx): 
    length2 = length+64
    C1 = C[0:length]

    x = int(C1[:lenx], 10)
    y = int(C1[lenx:], 10)
    if pow(y, 2) % p != (pow(x, 3) + a * x + b) % p:
        print("C1不满足方程")
        exit(1)
    if C1 == None:
        print("Infinite point!")
        exit(1)
    C3 = C[length:length2]
    C2 = C[length2:]
    x2,y2 = Scalar_mult(Sk,(x,y))
    print(x2)
    xy = str(x2)+str(y2)
    cl = len(C2)

    t = SM3.KDF(xy, cl / 2)

    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % cl
        M = form % (int(C2, 16) ^ int(t, 16))

        u = SM3.SM3(str(x2) + M + str(y2))
        if u == C3:
            return M
        else:
            return None

```

#### 签名和验签

我们这里按照老师给出的签名和验签步骤进行实现

这里Za中的EATL是签名者ID的位长度，占两个字节

```python
def signature(m,Za,da):
    msg = Za+m
    e = hashlib.sha256(msg.encode()).hexdigest()
    #对消息进行hash处理
    k,point = Key_gen()
    x1 = point[0]
    r = (int(e,16)+x1)%n
    s = (inverse_mod(1+da,n)*(k-r*da))%n
    return r,s


def Verify(r,s,Za,m,Pa):
    if r not in range(1,n-1):
        return False
    if s not in range(1,n-1):
        return False
    msg = Za+m
    e = hashlib.sha256(msg.encode()).hexdigest()
    t = (r+s)%n
    if t==0:
        return False
    point1 = Scalar_mult(t,Pa)
    point2 = Scalar_mult(s,G)
    point = point_add(point1,point2)
    x1,y1 = point
    R = (int(e,16)+x1)%n
    if R == r:
        return True
    else:
        return False
```

#### 密钥交换

这里还对密钥交换协议进行了简单实现

原理如图

![image-20220730194014679](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730194014679.png)

其中A和B通过交换信息计算出相同的密钥$K_{A}$和$K_{B}$

```python
IDA = 'ida'
IDB = 'idb'
klen= 128
da,Pka = Key_gen()
db,Pkb = Key_gen()
Za = '{:04x}'.format(len(IDA)*4)+str(a)+str(b)+str(G[0])+str(G[1])+str(Pka[0])+str(Pka[1])
Zb = '{:04x}'.format(len(IDA)*4)+str(a)+str(b)+str(G[0])+str(G[1])+str(Pkb[0])+str(Pkb[1])


def Alice(Ra,Rb,ra):
    w = math.ceil(math.log2(n)/2)-1
    _x1=((1<<w)+(Ra[0]&((1<<w)-1)))%(1<<128)
    ta=(da+_x1*ra)%n
    _x2=((1<<w)+(Rb[0]&((1<<w)-1)))%(1<<128)
    X2Rb = Scalar_mult(_x2,Rb)
    temp = point_add(Pkb,X2Rb)
    U=Scalar_mult(h*ta,temp)
    Xu,Yu = U
    m=str(Xu)+str(Yu) +Za+Zb
    Ka = SM3.KDF(m,klen)
    print("Alice计算的K",Ka)
    S1msg = "0x02"+str(Yu)+hashlib.sha256((str(Xu)+Za+Zb+str(Ra)+str(Rb)).encode()).hexdigest()
    S1 = hashlib.sha256(S1msg.encode()).hexdigest()
    print("Alice计算的S1：",S1)
    Samsg = "0x03"+str(Yu)+hashlib.sha256((str(Xu)+Za+Zb+str(Ra)+str(Rb)).encode()).hexdigest()
    SA = hashlib.sha256(Samsg.encode()).hexdigest()
    print("Alice计算的SA：",SA)
    return 

def Bob(Ra,Rb,rb):
    w = math.ceil(math.log2(n)/2)-1
    x2 = Rb[0]
    _x2 = ((1<<w)+(x2&((1<<w)-1)))%(1<<128)
    tb = (db+_x2*rb)%n
    _x1 = ((1<<w)+(Ra[0]&((1<<w)-1)))%(1<<128)
    x1Ra = Scalar_mult(_x1,Ra)
    temp = point_add(x1Ra,Pka)
    V = Scalar_mult(h*tb,temp)
    Xv,Yv = V
    msg = str(Xv)+str(Yv)+Za+Zb
    Kb = SM3.KDF(msg,klen)
    print("Bob计算的K",Kb)
    Sbmsg = "0x02"+str(Yv)+hashlib.sha256((str(Xv)+Za+Zb+str(Ra)+str(Rb)).encode()).hexdigest()
    SB = hashlib.sha256(Sbmsg.encode()).hexdigest()
    print("Bob计算的SB:",SB)
    S2msg = "0x03"+str(Yv)+hashlib.sha256((str(Xv)+Za+Zb+str(Ra)+str(Rb)).encode()).hexdigest()
    S2 = hashlib.sha256(S2msg.encode()).hexdigest()
    print("Bob计算的S2:",S2)
    return 

```

#### 结果验证

加解密验证

![image-20220730203348800](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730203348800.png)

签名验签验证

![image-20220730203458679](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730203458679.png)

密钥交换验证

![image-20220730203537958](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730203537958.png)