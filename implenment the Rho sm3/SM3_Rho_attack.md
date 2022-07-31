### SM3_Rho_attack

这里对应的是对SM3进行Rho攻击，Rho攻击类似于大步小步，由于Hash运算是在有限域中进行运算，最终会形成一个类似$\rho$的循环，这里我们也是对部分bit长度进行攻击。

#### 代码实现

```python
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

```



对代码直接进行运行，得到验证结果
![image-20220730165807435](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730165807435.png)
