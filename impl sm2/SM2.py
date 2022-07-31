
import random
from stringprep import c22_specials
import hashlib
from numpy import sign
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


def encryption(M, Pk): 
    msg = M.encode('utf-8')
    msg = msg.hex()  
    k,c = Key_gen()
    C1 = str(c[0])+str(c[1]) 
    #print(C1)
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
    #print(x2)
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



if __name__ == "__main__":
    len_para = int(Fp/4)
    sK,pK = Key_gen()
    print("\nPublic key is:",pK)
    print("\nSecret key is:",sK)
    secret = "hello everyone!"
    print("加密信息为：",secret)
    C,length,lenx = encryption(secret,pK)
    #print(C)
    a = decryption(C,sK,length,lenx)
    a = bytes.fromhex(a)
    print("Decryption is:",a.decode())

