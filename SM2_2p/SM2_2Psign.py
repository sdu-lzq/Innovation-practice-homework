
import random
from stringprep import c22_specials
import hashlib
import math
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



msg = 'hello'
print("最终签名r和s为:",Sign(msg))





