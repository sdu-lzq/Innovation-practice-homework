from SM3 import *
import time

#这里我们找到杂凑函数的碰撞

def birthday_attack(bitnumber:int):
    #首先是搜寻空间的大小,这里number为原象空间的大小
    space = int(2**(bitnumber/2))
    #这里建立一个hash列表来存储
    Hashtable = [0]*2**bitnumber
    for i in range(space):
        res = int(SM3(str(i))[0:int(bitnumber/4)],16)
        #在space里选择元素进行加密
        if Hashtable[res] == 0:
            Hashtable[res] = i
            continue
        else:
            return True

if __name__ == '__main__':
    bitnumber = 18
    start = time.time()
    print(birthday_attack(bitnumber))
    end = time.time()
    print("\n")
    print("caculate time is",(end-start))
