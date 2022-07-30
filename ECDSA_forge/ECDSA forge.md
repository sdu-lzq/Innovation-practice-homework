## ECDSA forge

Forge signature when the signed message is not checked

我们这里获取了一个有效的签名$\sigma$利用私钥d进行签名，然后伪造一个消息签名

![image-20220731000115394](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220731000115394.png)

```python
def Forge(pK):
    u = random.randrange(1,n)
    v = random.randrange(1,n)
    _R = point_add(Scalar_mult(u,G),Scalar_mult(v,pK))
    _r = _R[0]
    _e = (_r*u*inverse_mod(v,n))%n
    _s = (_r*inverse_mod(v,n))%n
    print("伪造的消息hash:",_e)
    return _r,_s,_e
```

按上述原理实现伪造代码

#### 结果验证

我们还要对生成的消息进行验证，并求出伪造的消息hash

直接运行代码进行验证

![image-20220731001128592](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220731001128592.png)