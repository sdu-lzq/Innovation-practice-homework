import random
import SM3
import cryptography
import string
import base64
from Crypto.Cipher import AES

def Pad(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  

def AES_encrypt(key, text):
    aes = AES.new(Pad(key), AES.MODE_ECB)  
    encrypt_aes = aes.encrypt(Pad(text))  
    text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  
    return text

def AES_decrypt(key, text):
    aes = AES.new(Pad(key), AES.MODE_ECB)  
    base64_text = base64.decodebytes(text.encode(encoding='utf-8'))  
    text = str(aes.decrypt(base64_text), encoding='utf-8').replace('\0', '')  
    return text



ellipseN = int('8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7', 16) 
ellipseP = int('8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3', 16)
ellipseG = '421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2'
ellipse_a = int('787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498',16)
ellipse_b = int('63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A',16)
ellipse_a_3 = (ellipse_a + 3) % ellipseP  
Fp = 256


def Get_str(strlen):
    str = ''
    a = [random.choice(string.digits+'abcdef') for i in range(strlen)]
    str = "".join(a)
    return str


def Exgcd(a, b):
    s_, s = 1, 0
    t_, t = 0, 1
    r_, r = a, b
    if b == 0:
        return 1, 0, a
    else:
        while r != 0:
            q = r_ // r
            r_, r = r, r_ - q * r
            s_, s = s, s_ - q * s
            t_, t = t, t_ - q * t
    return s_


def Reverse(Mj, mj):
    s = Exgcd(Mj, mj)
    while s < 1:
        s += mj
    return s


#椭圆曲线运算
def Add(P, Q, length):
    Px = int(P[:length], 16)
    Py = int(P[length:], 16)
    Qx = int(Q[:length], 16)
    Qy = int(Q[length:], 16)
    #first caculate the x,y label
    lamda = (Qy - Py) * Reverse(Qx - Px, ellipseP) % ellipseP 
    _x = (pow(lamda, 2) - Px - Qx)%ellipseP
    _y = (lamda * (Px - _x) - Py)%ellipseP
    return hex(_x)[2:] + hex(_y)[2:]

def Mul(point, length):
    xPoint = int(point[:length], 16)
    yPoint = int(point[length:], 16)
    lamda = (3 * pow(xPoint, 2) + ellipse_a) * Reverse(2 * yPoint, ellipseP) % ellipseP
    xNew = (pow(lamda, 2) - 2 * xPoint)%ellipseP
    yNew = (lamda * (xPoint - xNew) - yPoint)%ellipseP
    return hex(xNew)[2:] + hex(yNew)[2:]



#生成公钥
def gen_pK(k, point, length):
    P = point
    Q = point
    bk = bin(k)
    start = str(bk).find('1')
    for i in range(len(bk), start):
        Q = Mul(Q, length)
        if bk[i] == 1:
            Q = Add(Q, P, length)
    return Q




def encryption(M, Pk, length, strHex=0): 
    msg = M.encode('utf-8')
    msg = msg.hex()  
    k = Get_str(length)
    C1 = gen_pK(int(k, 16), ellipseG, length)


    if str(Pk)[:length] == '0' and str(Pk)[length:] == '0':
        print("Infinite point!")
        exit(1)
    xy = gen_pK(int(k, 16), Pk, length)

    x2 = xy[0:length]
    y2 = xy[length:2 * length]
    lenMsg = len(msg)

    t = SM3.KDF(xy, lenMsg / 2)

    if int(t, 16) == 0:
        temp = encryption(M, Pk, length)
        return temp
    else:
        form = '%%0%dx' % lenMsg
        C2 = form % (int(msg, 16) ^ int(t, 16))

        C3 = SM3.SM3(x2 + msg + y2)

        return C1 + C3 + C2


def decryption(C, Sk, length): 
    len_2 = 2 * length
    len_3 = len_2 + 64
    C1 = C[0:len_2]

    x = int(C1[:length], 16)
    y = int(C1[length:], 16)
    if pow(y, 2) % ellipseP != (pow(x, 3) + ellipse_a * x + ellipse_b) % ellipseP:
        print("C1不满足方程")
        exit(1)
    if (C1[:length],C1[length:]) == (0,0):
        print("Infinite point!")
        exit(1)
    C3 = C[len_2:len_3]
    C2 = C[len_3:]
    xy = gen_pK(int(Sk, 16), C1, length)

    x2 = xy[0:length]
    y2 = xy[length:len_2]
    cl = len(C2)

    t = SM3.KDF(xy, cl / 2)

    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % cl
        M = form % (int(C2, 16) ^ int(t, 16))

        u = SM3.SM3(x2 + M + y2)
        if u == C3:
            return M
        else:
            return None



def PGP_Alice(pK,data,len_para):
    Com_key = Get_str(10)
    ciphertext =AES_encrypt(Com_key,data)
    cipherkey = encryption(Com_key,pK,len_para,0)
    print("加密完成，加密消息是:",ciphertext)
    return ciphertext,cipherkey


def PGP_Bob(d,ciphertext,cipherkey,len_para):
    temp = decryption(cipherkey,d,len_para)
    temp = bytes.fromhex(temp)
    Com_key = temp.decode()
    plaintext = AES_decrypt(Com_key,ciphertext)
    print("解密完成，明文是:",plaintext)
    return 


 
len_para = int(Fp/4)
d = Get_str(len_para)
Pa =  gen_pK(int(d,16),ellipseG,len_para)
print("\nPublic key is:",Pa)
print("\nSecret key is:",d)
data = "hello everyone!"
ciphertext,cipherkey = PGP_Alice(Pa,data,len_para)
PGP_Bob(d,ciphertext,cipherkey,len_para)