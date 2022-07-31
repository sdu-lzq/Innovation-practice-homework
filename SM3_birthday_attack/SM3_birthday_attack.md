## SM3_birthday_attack

下面对SM3进行生日攻击实现

##### 首先介绍Hash碰撞

如果不同的输入得到了同一个哈希值，就发生了"哈希碰撞"（collision）。

##### 生日攻击

哈希碰撞的概率取决于两个因素（假设哈希函数是可靠的，每个值的生成概率都相同）。

> - 取值空间的大小（即哈希值的长度）
> - 整个生命周期中，哈希值的计算次数

这个问题在数学上早有原型，叫做"[生日问题](https://en.wikipedia.org/wiki/Birthday_problem)"（birthday problem）：一个班级需要有多少人，才能保证每个同学的生日都不一样？

答案很出人意料。如果至少两个同学生日相同的概率不超过5%，那么这个班只能有7个人。事实上，一个23人的班级有50%的概率，至少两个同学生日相同；50人班级有97%的概率，70人的班级则是99.9%的概率（计算方法见后文）。

这意味着，如果哈希值的取值空间是365，只要计算23个哈希值，就有50%的可能产生碰撞。也就是说，哈希碰撞的可能性，远比想象的高，这种利用哈希空间不足够大，而制造碰撞的攻击方法，就被称为生日攻击（birthday attack）。

生日攻击公式，这里省略数学推导
$$
P(n,d) \approx 1-e^{-n(n-1)/2d}
$$
这里d是取值空间，n是样本的大小

##### SM3引用

对整个SM3哈希结果进行碰撞时间复杂度较高，这里我们对部分bit进行生日碰撞攻击实现

```python
def birthday_attack(bitnumber:int):
    #首先是搜寻空间的大小,这里number为原象空间的大小
    space = int(2**(bitnumber))
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
	#将Hash结果当作索引，如果Hash表中存储原象为0，就将原象存入相应位置，如果已经存储其它原象就找到了一对碰撞
```

#### 代码验证

可以直接对攻击代码进行运行

![image-20220730154045901](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730154045901.png)
