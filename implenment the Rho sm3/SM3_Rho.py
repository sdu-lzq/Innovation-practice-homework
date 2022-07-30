from tokenize import Hexnumber
import SM3
import time


def Rho(bitnumber):
    Hexnum = int(bitnumber/4)
    #这里我们对4个bit可以代表一个16进制字节的值
    m = hex(2)[2:]
    #首先随便选择一个消息进行开始
    m_1 = SM3.SM3(m)
    m_2 = SM3.SM3(m_1)
    #然后计算一步和两步，找到碰撞
    while m_1[:Hexnum] != m_2[:Hexnum]:
        m_1 = SM3.SM3(m_1)
        m_2 = SM3.SM3(SM3.SM3(m_2))
    return  m_1[:Hexnum], m_1,m_2

if __name__ == '__main__':
    bitnumber = 10
    print("对{}bit的值进行Rho碰撞攻击".format(bitnumber))
    start = time.time()
    value,m_1,m_2 = Rho(bitnumber)
    end = time.time()
    print("碰撞值为{},消息1为{},消息2为{}".format(value,m_1,m_2))
    print("caculate time is :",end-start)







