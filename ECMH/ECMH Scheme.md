### ECMH Scheme

![img](https://img-blog.csdnimg.cn/20190207100942236.JPG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2phc29uX2N1aWppYWh1aQ==,size_16,color_FFFFFF,t_70)

这里将字符串的Hash映到椭圆曲线上，我们可以按上图的算法

对字符串序列中的值进行Hash转化成整数值，然后代入椭圆曲线上的x轴的点，然后利用二次剩余求出y的值。如果是连续的Hash字符串，则将Hash后的值进行转化椭圆曲线上的点相加。

#### 结果验证

结果验证直接对代码进行执行

这里ECMH结构决定它具有同态性和可交换性，我们进行了验证

![image-20220730205250446](https://github.com/sdu-lzq/Innovation-practice-homework/blob/main/image/image-20220730205250446.png)
