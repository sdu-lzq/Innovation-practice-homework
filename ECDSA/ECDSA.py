from audioop import mul
from tkinter import N
import utils
import hashlib
import random



p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0
b = 7
G=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
h = 1

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

def On_curve(point):
    #无穷远点
    if point is None:
        return True
    else:
        x,y = point
        return (y*y-x*x*x-a*x-b)%p == 0


def point_add(point1,point2):
    assert On_curve(point1) and On_curve(point2)
    if point1 == None:
        return point2
    if point2  == None:
        return point1
    x1,y1 = point1
    x2,y2 = point2
    if x1 == x2 :
        if y1 !=y2:
            return None
        else:
            return double(point1)
    else:
        lamb = (y2-y1)*inverse_mod((x2-x1)%p,p)%p
        x3 = (lamb**2-x1-x2)%p
        y3 = (lamb*(x1-x3)-y1)%p
    point3 = (x3,y3)
    return point3


def double(point):
    assert On_curve(point)
    if point == None:
        return point
    x,y = point
    lamb = (3*(x**2)+a)*inverse_mod((2*y)%p,p)%p
    x3 = (lamb**2-2*x)%p
    y3 = (lamb*(x-x3)-y)%p
    point3 = (x3,y3)
    return point3


def Scalar_mult(k,point):
    assert On_curve(point)
    flag = 1<<255
    acc = None
    for i in range(255):
        if 0!=k&flag:
            acc = point_add(point,acc)
        acc = double(acc)
        flag>>=1
    if 0!=k&flag:
        acc = point_add(acc,point)
    return acc

def Key_gen():
    sK = random.randrange(1,n)
    pK = Scalar_mult(sK,G)
    return sK,pK





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

#Pk = (r+s)^(-1)(kG-sG)
def Deduce(sign,msg):
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

def Deduce2(sign,msg):
    msg = hashlib.sha256(msg.encode()).digest()
    e = int.from_bytes(msg,'big') 
    r,s = sign
    kGx = r%p
    kGy = ((kGx*kGx*kGx)+7)%p
    kG = (kGx,kGy)
    inv = inverse_mod((s+r),n)
    sG = Scalar_mult(s%p,G)
    nesG = (sG[0],p-sG[1])
    print(On_curve(kG))
    On_curve(sG)
    pK = Scalar_mult(inv,point_add(kG,nesG))
    return pK

if __name__ == '__main__':
    sK,pK = Key_gen()
    print("生成的公钥值是：",pK)
    sign =  Sign('hello',sK)
    print("对消息hello进行签名的签名值为:",sign)
    verify(pK,'hello',sign)
    print("利用签名值进行推断公钥为:",Deduce(sign,'hello'))