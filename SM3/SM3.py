# SM3
import math
from typing import ByteString


IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
T = [0x79cc4519, 0x7a879d8a]

def AsToByte(string):
    BString = ''
    for i in string:
        BString += hex(ord(i))[2:]
    return BString


def FF(X, Y, Z, j):
    if j >= 0 and j <= 15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (X & Z) | (Y & Z))


def RoundS(X, i):
    i = i % 32
    return ((X << i) & 0xFFFFFFFF) | ((X & 0xFFFFFFFF) >> (32 - i))


def GG(X, Y, Z, j):
    if j >= 0 and j <= 15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (~X & Z))


def P0(X):
    return X ^ RoundS(X, 9) ^ RoundS(X, 17)


def P1(X):
    return X ^ RoundS(X, 15) ^ RoundS(X, 23)


def T_(j):
    if j >= 0 and j <= 15:
        return T[0]
    else:
        return T[1]


def Pad(message):
    m = bin(int(message, 16))[2:]
    if len(m) != len(message) * 4:
        m = '0' * (len(message) * 4 - len(m)) + m
    l = len(m)
    Pad_len = '0' * (64 - len(bin(l)[2:])) + bin(l)[2:]
    m = m + '1'
    if len(m) % 512 > 448:
        m = m + '0' * (512 - len(m) % 512 + 448) + Pad_len
    else:
        m = m + '0' * (448 - len(m) % 512) + Pad_len
    m = hex(int(m, 2))[2:]
    return m


def Group(m):
    n = len(m) / 128
    M = []
    for i in range(int(n)):
        M.append(m[0 + 128 * i:128 + 128 * i])
    return M


def Ex_msg(M, n):
    W = []
    _W = []
    for j in range(16):
        W.append(int(M[n][0 + 8 * j:8 + 8 * j], 16))
    for j in range(16, 68):
        W.append(P1(W[j - 16] ^ W[j - 9] ^ RoundS(W[j - 3], 15)) ^ RoundS(W[j - 13], 7) ^ W[j - 6])
    for j in range(64):
        _W.append(W[j] ^ W[j + 4])
    return W, _W


def CF(V, M, i):
    A, B, C, D, E, F, G, H = V[i]
    W, _W = Ex_msg(M, i)
    for j in range(64):
        SS1 = RoundS((RoundS(A, 12) + E + RoundS(T_(j), j % 32)) % (2 ** 32), 7)
        SS2 = SS1 ^ RoundS(A, 12)
        TT1 = (FF(A, B, C, j) + D + SS2 + _W[j]) % (2 ** 32)
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) % (2 ** 32)
        D = C
        C = RoundS(B, 9)
        B = A
        A = TT1
        H = G
        G = RoundS(F, 19)
        F = E
        E = P0(TT2)
    a, b, c, d, e, f, g, h = V[i]
    V_ = [a ^ A, b ^ B, c ^ C, d ^ D, e ^ E, f ^ F, g ^ G, h ^ H]
    return V_


def Round_iter(M):
    n = len(M)
    V = []
    V.append(IV)
    for i in range(n):
        V.append(CF(V, M, i))
    return V[n]


def SM3(message):
    m = Pad(message)  
    M = Group(m)  
    Vn = Round_iter(M)  
    res = ''
    for x in Vn:
            res += hex(x)[2:]
    return res



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


if __name__ == "__main__":
    content = AsToByte('abc')
    res = SM3(content)
    print(res)