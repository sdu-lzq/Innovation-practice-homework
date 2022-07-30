# Meow Get Key

通过老师的讲解我们可以知道，由于Meow结构的可逆性，我们可以由message和Hash value推导出原有Key的值，要实现可逆，需要我们在结构上进行把握。

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220729231034484.png" alt="image-20220729231034484" style="zoom:50%;" />

Meow中的AES是单轮的AES解密操作，并且有逆列混合，逆行移位，逆S盒还有异或密钥。

这里我们可以由官方给出的指令引导手册进行查看

https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#ig_expand=262,280,267,272,262,6386,302&othertechs=AES&text=_mm_alignr_epi8&techs=SSSE3

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220729234243191.png" alt="image-20220729234243191" style="zoom:50%;" />

这里是一次AES解密操作，我们可以看到进行了逆行移位，逆字节代换，逆列混淆，最后和key进行了异或

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220729233414079.png" alt="image-20220729233414079" style="zoom:50%;" />

逆列混合操作

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220729233658127.png" alt="image-20220729233658127" style="zoom: 50%;" />



这里是对最后一轮的AES进行解密，可以看到进行了逆行移位操作，逆字节代换，然后进行了一次异或密钥。

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220729233740603.png" alt="image-20220729233740603" style="zoom:50%;" />

aes加密运算

因此我们要进行逆运算，首先要将输入值与密钥异或，这里我们密钥依然正序输入（不用aesenc），然后进行列混淆，字节代换，行移位，这里移位和字节代换操作可以进行交换

```python
#define inv_aesdec(A, B) \
pxor(A, B);              \
MixCol(A);           \
aesenc(A, xmm_setzero);  \
invMixCol(A)
//首先异或密钥，然后列混合，然后和0进行aes加密，效果没有异或密钥，这样再进行一次逆列混淆，就可以实现aesdec的逆过程
```

对Finalization的逆运算进行实现，我们首先先观察正向运算的图

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220730000226407.png" alt="image-20220730000226407" style="zoom:50%;" />

要实现逆向运算要从下向上进行

```c
#define INV_Finalization(r1, r2, r3, r5, r6, r7) \
pxor(r2, r3);         \ //r2和r3进行异或
inv_aesdec(r5, r2);   \//将r5进行逆aes运算，r2作为轮密钥
psubq(r6, r7);        \//r6,r7进行相加的逆运算
pxor(r5, r7);         \
psubq(r2, r6);        \
inv_aesdec(r1, r5);
```

在头文件中我们可以看到MEOW_MIX_REG的操作，下面我们也要将其进行逆向，这里只需要将操作进行逆使用即可

<img src="C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220731003909980.png" alt="image-20220731003909980" style="zoom:50%;" />

```c
#define MEOW_MIX_REG(r1, r2, r3, r4, r5,  i1, i2, i3, i4) \
aesdec(r1, r2);              \
INSTRUCTION_REORDER_BARRIER; \
paddq(r3, i1);               \
pxor(r2, i2);                \
aesdec(r2, r4);              \
INSTRUCTION_REORDER_BARRIER; \
paddq(r5, i3);               \
pxor(r4, i4);
```

```c
#define INV_MEOW_MIX_REG(r1, r2, r3, r4, r5,  i1, i2, i3, i4) \
pxor(r4, i4);                \
psubq(r5, i3);               \
INSTRUCTION_REORDER_BARRIER; \
inv_aesdec(r2, r4);          \
pxor(r2, i2);                \
psubq(r3, i1);               \
INSTRUCTION_REORDER_BARRIER; \
inv_aesdec(r1, r2);          \
```

然后接下来就是对函数进行逆序的实现

1.将hashmsg装入寄存器

2.逆向实现Squeeze

3.逆向实现Finalization，记录最终数据单元顺序

4.对mssage进行处理，并执行Aborsb Message的逆向过程



```python
static void INVMeowHash(meow_umm Len, void* HashMsg, void* msg, void* Key_buffer) {

	meow_u128 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;// NOTE(casey): xmm0-xmm7 are the hash accumulation lanes
	meow_u128 xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;// NOTE(casey): xmm8-xmm15 hold values to be appended (residual, length)
	//这里我们只需要使用hashmsg
	meow_u8* rcx = (meow_u8*)HashMsg;
	movdqu(xmm0, rcx + 0x00); 
	movdqu(xmm1, rcx + 0x10); 
	movdqu(xmm2, rcx + 0x20); 
	movdqu(xmm3, rcx + 0x30); 
	movdqu(xmm4, rcx + 0x40);
	movdqu(xmm5, rcx + 0x50); 
	movdqu(xmm6, rcx + 0x60); 
	movdqu(xmm7, rcx + 0x70); 
	//将hashmsg装入相应的128bit内容中，相应一个是16字节

	INV_Squeeze(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);
	//先进行Squeeze的逆操作

	//Finalization 根据结构相当每次将值左移一个，进行12轮
	MEOW_INV_SHUFFLE(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);//3,4,5,6,7,0,1,2
	MEOW_INV_SHUFFLE(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);
	MEOW_INV_SHUFFLE(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);
	MEOW_INV_SHUFFLE(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);
	MEOW_INV_SHUFFLE(xmm7, xmm0, xmm1, xmm3, xmm4, xmm5);
	MEOW_INV_SHUFFLE(xmm6, xmm7, xmm0, xmm2, xmm3, xmm4);
	MEOW_INV_SHUFFLE(xmm5, xmm6, xmm7, xmm1, xmm2, xmm3);
	MEOW_INV_SHUFFLE(xmm4, xmm5, xmm6, xmm0, xmm1, xmm2);
	MEOW_INV_SHUFFLE(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);
	MEOW_INV_SHUFFLE(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);//2
	MEOW_INV_SHUFFLE(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);//1
	MEOW_INV_SHUFFLE(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);//0,1,2,3,4,5,6,7
	
	
	//首先用0对相应内存进行初始化
	pxor_clear(xmm8, xmm8);
	pxor_clear(xmm9, xmm9);
	pxor_clear(xmm10, xmm10);
	pxor_clear(xmm11, xmm11);
	pxor_clear(xmm12, xmm12);
	pxor_clear(xmm13, xmm13);
	pxor_clear(xmm14, xmm14);
	pxor_clear(xmm15, xmm15);

	meow_u8* Last = (meow_u8*)msg + (Len & ~0xf);

	//对msg进行处理
	int unsigned Len8 = (Len & 0xf);
	if (Len8) {

		movdqu(xmm8, &MeowMaskLen[0x10 - Len8]);

		meow_u8* LastOk = (meow_u8*)((((meow_umm)(((meow_u8*)msg) + Len - 1)) | (MEOW_PAGESIZE - 1)) - 16);
		int Align = (Last > LastOk) ? ((int)(meow_umm)Last) & 0xf : 0;
		movdqu(xmm10, &MeowShiftAdjust[Align]);
		movdqu(xmm9, Last - Align);
		pshufb(xmm9, xmm10);
		pand(xmm9, xmm8);
	}
	if (Len & 0x10) {
		xmm11 = xmm9;
		movdqu(xmm9, Last - 0x10);
	}

	xmm8 = xmm9;
	xmm10 = xmm9;
	palignr(xmm8, xmm11, 15);
	palignr(xmm10, xmm11, 1);
	movq(xmm15, Len);
	palignr(xmm12, xmm15, 15);
	palignr(xmm14, xmm15, 1);

	
	//r4-1 i4-10 r5-2 i3-01 r2-4 i2-00 r3-6 i1-0f r1-0 
	//1,2,3,4,5,6,7,0按照这个顺序进行输入，寄存器最后输出的顺序
	MEOW_INV_MIX_REG(xmm1, xmm5, xmm7, xmm2, xmm3, xmm12, xmm13, xmm14, xmm15);
	MEOW_INV_MIX_REG(xmm0, xmm4, xmm6, xmm1, xmm2, xmm8, xmm9, xmm10, xmm11);
	//再进行一轮，确定剩下的密钥值,这里逆序执行
	// NOTE(casey): To maintain the mix-down pattern, we always Meow Mix the less-than-32-byte residual, even if it was empty
	 // NOTE(casey): Append the length, to avoid problems with our 32-byte padding

	/*正向进行
	*     // NOTE(casey): To maintain the mix-down pattern, we always Meow Mix the less-than-32-byte residual, even if it was empty
    MEOW_MIX_REG(xmm0, xmm4, xmm6, xmm1, xmm2, xmm8, xmm9, xmm10, xmm11);

    // NOTE(casey): Append the length, to avoid problems with our 32-byte padding
    MEOW_MIX_REG(xmm1, xmm5, xmm7, xmm2, xmm3, xmm12, xmm13, xmm14, xmm15);
	*/


	meow_u8* rax = (meow_u8*)Key_buffer;
	movdqu_mem(rax + 0x00, xmm0);
	movdqu_mem(rax + 0x10, xmm1);
	movdqu_mem(rax + 0x20, xmm2);
	movdqu_mem(rax + 0x30, xmm3);
	movdqu_mem(rax + 0x40, xmm4);
	movdqu_mem(rax + 0x50, xmm5);
	movdqu_mem(rax + 0x60, xmm6);
	movdqu_mem(rax + 0x70, xmm7);
	Key_buffer = rax;
	return;
}
```

#### 结果验证

我们利用代码获取Key，并将Key代入正向Hash验证值

![image-20220731005052206](C:\Users\lc-lzq\AppData\Roaming\Typora\typora-user-images\image-20220731005052206.png)
