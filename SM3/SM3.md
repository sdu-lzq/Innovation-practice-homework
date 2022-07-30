# SM3

#### 项目代码说明

[在线预览|GB/T 32905-2016 (gb688.cn)](http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=45B1A67F20F3BF339211C391E9278F5E)

[SM3密码杂凑算法的并行化优化方法与流程 (xjishu.com)](http://www.xjishu.com/zhuanli/62/201811323148.html)

这里我们放官方的国密文档

首先我们对IV和常量T进行一个初始化

然后对这里面的布尔函数以及置换函数进行实现，这里置换函数我们利用#define代替函数，#define宏在程序运行过程中，只执行逻辑部分，完成替换即可，能够提高模块执行的速度。

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730114945980.png" alt="image-20220730114945980" style="zoom:50%;" />

下面对迭代过程进行实现，首先将消息进行扩展，将消息分组按照下面的方法扩展成132个消息字，然后再逻辑压缩函数作用下进行迭代压缩，这里在迭代过程中，我尝试使用SIMD指令集进行解决，但是由于数据格式之间转化问题没有实现。

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730122739680.png" alt="image-20220730122739680" style="zoom:50%;" />

这里我们还对消息进行了填充，消息填充过程的具体细节已经在代码中给出了注释。

另外为了后面实现的方便性，还利用python对sm3进行了实现

#### 代码运行

我们可以直接对代码进行运行验证 

![image-20220730122153776](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730122153776.png)

![image-20220730122245671](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730122245671.png)

和官方文档的杂凑值相同

![image-20220730122612706](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730122612706.png)

python的运行结果

