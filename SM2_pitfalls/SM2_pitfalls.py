import random
import ECDSA
import hashlib



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




def signature(m,Za,da,k):
    msg = Za+m
    e = hashlib.sha256(msg.encode()).hexdigest()
    point = Scalar_mult(k,G)
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

#pitfalls
def ECDSA_Sign(msg,sK,k):
    #使用hash算法对交易明文进行hash
    msg = hashlib.sha256(msg.encode()).digest()
    hash = int.from_bytes(msg,'big')
    #生成一个随机数K，计算R = K*G 取R的x
    R = Scalar_mult(k,G)
    Rx = R[0]%n
    # print(R)
    s = (inverse_mod(k,n)*(hash+Rx*sK))%n
    return Rx,s,hash

def leaking_k(r,s,k):
    da = (inverse_mod(s+r,n)*(k-s))%n
    print("利用泄露的k计算私钥:",da)
    return 



def reuse_k(Za,da,k):
    m1 = "message1"
    m2 = "message2"
    r1,s1 = signature(m1,Za,da,k)
    r2,s2 = signature(m2,Za,da,k)
    da = ((s2-s1)%n*inverse_mod((s1-s2)%n+(r1-r2)%n,n))%n
    print("重复使用k，计算出的公钥为:",da)
    return 


def reuse_k_users(Za,da,k):
    m1 = "message1"
    m2 = "message2"
    print("Bob和Alice使用相同k进行签名")
    r1,s1 = signature(m1,Za,da,k)
    r2,s2 = signature(m2,Za,da,k)
    print("Alice deduce Bob key:",((k-s2)*inverse_mod(s2+r2,n))%n)
    print("Alice deduce Bob key:",((k-s1)*inverse_mod(s1+r1,n))%n)
    return


def same_d_k(Za,sK,k):
    m = "hello"
    r1,s1,e1 = ECDSA_Sign(m,sK,k)
    r2,s2 = signature(m,Za,sK,k)
    da = ((s1*s2-e1)*inverse_mod(r1-s1*s2-s1*r2,n))%n
    print("ECDSA和SM2使用相同的k和d计算da:",da)
    return

if __name__ == "__main__":
    sK,pK = Key_gen()
    secret = 'hello'
    IDA = 'IDa'
    ENTL = '{:04x}'.format(len(IDA)*4)
    Za = hashlib.sha256((ENTL+IDA+str(a)+str(b)+str(G)+str(pK)).encode()).hexdigest()
    k = random.randrange(1,n)
    r,s = signature(secret,Za,sK,k)
    print("对消息hello进行签名,签名值为r={},s={}:".format(r,s))
    print("对签名结果进行验证为：",Verify(r,s,Za,secret,pK)) 
    print("私钥的值为:",sK)
    leaking_k(r,s,k)
    k = random.randrange(1,n)
    reuse_k(Za,sK,k)
    reuse_k_users(Za,sK,k)
    same_d_k(Za,sK,k)
