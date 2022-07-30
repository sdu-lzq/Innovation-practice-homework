
import random
import secrets
from stringprep import c22_specials
import hashlib
from numpy import sign
from SM2_KeyEx import IDA
import SM3

p =0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
G=(0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
    0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2)
n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
h = 1
Fp = 256

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




def signature(m,Za,da):
    msg = Za+m
    e = hashlib.sha256(msg.encode()).hexdigest()
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


if __name__ == "__main__":
    sK,pK = Key_gen()
    secret = 'hello'
    IDA = "IDA" 
    Za = '{:04x}'.format(len(IDA)*4)+str(a)+str(b)+str(G[0])+str(G[1])+str(pK[0])+str(pK[1])
    
    r,s = signature(secret,Za,sK)
    print("对消息hello进行签名,签名值为r={},s={}:".format(r,s))
    print("对签名结果进行验证为：",Verify(r,s,Za,secret,pK)) 
