
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






if __name__ == "__main__":
    ra,Ra = Key_gen()
    rb,Rb = Key_gen()
    Alice(Ra,Rb,ra)
    Bob(Ra,Rb,rb)