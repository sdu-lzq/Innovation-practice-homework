## SM4

[www.gmbz.org.cn/main/viewfile/20180108015408199368.html](http://www.gmbz.org.cn/main/viewfile/20180108015408199368.html)

加解密运算
1.首先将输入的128bit明文分成 4个32bit的数据$x_{0},x_{1},x_{2},x_{3}$,并作32轮轮变换.
2.$x_{i}$暂时不做处理，将$x_{i+1},x_{i+2},x_{i+3}$和轮密钥$rk_{i}$异或得到一个32bit都数据，作为S盒变换的输入.
3.下面进行S盒变换的过程，每个S盒的输入都是8位的一个字节，将这8位的前4位对应的16进制数作为行编号，后4位作为列编号，然后用S盒中对应位置的数进行代替.
4.然后将刚才Sbox的结果分别循环左移2，10，18，24位，得到的数与Sbox的输出进行异或然后得到$x_{i+4}$.
5.将最后输出的$x_{35},x_{34},x_{33},x_{32}$合并成一个128bit都数据，最为最后的结果进行输出.
6.解密的过程和加密的过程其实没有本质区别，由于是对称密码方案，在解密时我们只需要将32轮的轮密钥反序使用即可。

我们按照SM4实现的相关步骤首先实现了SM4的基础实现版本，下面我们对SM4进行加速优化



##### P1 查表优化

为了提升效率，我们可以将S盒和后续的循环移位运算进行合并

1.预计算，生成查找表

```c
//4个T表
static uint32_t Table0[256];
static uint32_t Table1[256];
static uint32_t Table2[256];
static uint32_t Table3[256];

uint8_t S_replace(uint8_t in) {
    uint8_t xlable = in >> 4;
    uint8_t ylable = in << 4;
    ylable = ylable >> 4;
    int index = xlable * 16 + ylable;
    return SBox[index];
}


uint32_t Cycle_shift_left(uint32_t num, int shift) {
    return (num << shift) ^ (num >> (32 - shift));
}


uint32_t L(uint32_t num) {
    return num = Cycle_shift_left(num, 2) ^ Cycle_shift_left(num, 10) ^ Cycle_shift_left(num, 18) ^ Cycle_shift_left(num, 24)^num;
}



void generate_table() {
    for (int i = 0; i < 256; i++) {
        Table0[i] = L(((uint32_t)S_replace((uint8_t)i)) <<24);
        Table1[i] = L(((uint32_t)S_replace((uint8_t)i)) << 16);
        Table2[i] = L(((uint32_t)S_replace((uint8_t)i)) << 8);
        Table3[i] = L(((uint32_t)S_replace((uint8_t)i)));
    }
}
```

将最后32bit合并成4个表进行操作，在T操作中将最后的结果进行异或合并

2.在加密过程中应用查表

##### P2 查表优化+SIMD单指令多数据优化

具体实现如下，这里我们结合了查表优化策略

1.加载8组消息至$imm_{i},is \in [0,3]$

2.通过pack进行打包，使得$X_{i}$对应第i个小分组
3.迭代32轮

4.$K_{i}$是轮密钥，$Temp \leftarrow X_{1} \oplus X_{2}\oplus X_{3}\oplus K_{i} $,$Temp \leftarrow T(Temp)\oplus X_{0}$

5.$X_{0},X_{1},X_{2},X_{3}\leftarrow X_{1},X_{2},X_{3},Temp$

6.$X_{0},X_{1},X_{2},X_{3} \leftarrow  X_{3},X_{2},X_{1},X_{0}$

7.unpack，将$X_{i}$打包回原始的状态$imm_{i}$

8.存储$imm_{i}$到对应的内存

```c
void SM4_encryption(uint8_t* ciphertext) {
    uint32_t k[36];
    k[0] = MK[0] ^ FK[0]; k[1] = MK[1] ^ FK[1]; k[2] = MK[2] ^ FK[2]; k[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++) {
        rK[i] = k[i + 4] = k[i] ^ RoundK(k[i + 3] ^ k[i + 2] ^ k[i + 1] ^ CK[i]);
    }
    
    __m256i X[4], Temp[4], Mask;
    Mask = _mm256_set1_epi32(0xFF);
    //加载数据
    Temp[0] = _mm256_loadu_si256((const __m256i*)plaintext + 0);
    Temp[1] = _mm256_loadu_si256((const __m256i*)plaintext + 1);
    Temp[2] = _mm256_loadu_si256((const __m256i*)plaintext + 2);
    Temp[3] = _mm256_loadu_si256((const __m256i*)plaintext + 3);
    //合并每组128bit数据的某32bit字
    X[0] = MM256_PACK0_EPI32(Temp[0], Temp[1], Temp[2], Temp[3]);
    X[1] = MM256_PACK1_EPI32(Temp[0], Temp[1], Temp[2], Temp[3]);
    X[2] = MM256_PACK2_EPI32(Temp[0], Temp[1], Temp[2], Temp[3]);
    X[3] = MM256_PACK3_EPI32(Temp[0], Temp[1], Temp[2], Temp[3]);

    __m256i vindex =
        _mm256_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
    X[0] = _mm256_shuffle_epi8(X[0], vindex);
    X[1] = _mm256_shuffle_epi8(X[1], vindex);
    X[2] = _mm256_shuffle_epi8(X[2], vindex);
    X[3] = _mm256_shuffle_epi8(X[3], vindex);
    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        __m256i k =
            _mm256_set1_epi32(rK[i]);
        Temp[0] = _mm256_xor_si256(_mm256_xor_si256(X[1], X[2]),
            _mm256_xor_si256(X[3], k));
        //查表
        Temp[1] = _mm256_xor_si256(
            X[0], _mm256_i32gather_epi32((const int*)Table0,
                _mm256_and_si256(Temp[0], Mask), 4));
        Temp[0] = _mm256_srli_epi32(Temp[0], 8);
        Temp[1] = _mm256_xor_si256(
            Temp[1], _mm256_i32gather_epi32(
                (const int*)Table1, _mm256_and_si256(Temp[0], Mask), 4));
        Temp[0] = _mm256_srli_epi32(Temp[0], 8);
        Temp[1] = _mm256_xor_si256(
            Temp[1], _mm256_i32gather_epi32(
                (const int*)Table2, _mm256_and_si256(Temp[0], Mask), 4));
        Temp[0] = _mm256_srli_epi32(Temp[0], 8);
        Temp[1] = _mm256_xor_si256(
            Temp[1], _mm256_i32gather_epi32(
                (const int*)Table3, _mm256_and_si256(Temp[0], Mask), 4));

        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = Temp[1];
    }
    //转化端序
    X[0] = _mm256_shuffle_epi8(X[0], vindex);
    X[1] = _mm256_shuffle_epi8(X[1], vindex);
    X[2] = _mm256_shuffle_epi8(X[2], vindex);
    X[3] = _mm256_shuffle_epi8(X[3], vindex);
    //恢复分组并装填
    _mm256_storeu_si256((__m256i*)ciphertext + 0,
        MM256_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm256_storeu_si256((__m256i*)ciphertext + 1,
        MM256_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm256_storeu_si256((__m256i*)ciphertext + 2,
        MM256_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm256_storeu_si256((__m256i*)ciphertext + 3,
        MM256_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}

```

#### 代码运行和结果验证

这里分别对相应代码进行运行即可

![image-20220730143943862](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730143943862.png)

![image-20220730145131205](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730145131205.png)

![image-20220730145117591](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730145117591.png)

最终优化结果和时间

一种python实现方案

![image-20220730145608565](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730145608565.png)