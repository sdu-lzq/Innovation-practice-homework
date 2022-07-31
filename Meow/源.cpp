#include <iostream>
#include <stdio.h>
#include <memory.h>
#include "meow_hash_x64_aesni.h"

using namespace std;


#define INSTRUCTION_REORDER_BARRIER _ReadWriteBarrier()
//_m128i也就是我们将它当作一个128bit的整数进行使用
static meow_u128 xmm_setzero = _mm_setzero_si128(); //meow_u128  == _m128i  
#define prefetcht0(A)           _mm_prefetch((char *)(A), _MM_HINT_T0)
#define movdqu(A, B)	    A = _mm_loadu_si128((__m128i *)(B))
#define movdqu_mem(A, B)        _mm_storeu_si128((__m128i *)(A), B)
#define movq(A, B)          A = _mm_set_epi64x(0, B);
#define pshufb(A, B)        A = _mm_shuffle_epi8(A, B)
#define pxor(A, B)	        A = _mm_xor_si128(A, B)
#define paddq(A, B)         A = _mm_add_epi64(A, B)
#define psubq(A, B)	        A = _mm_sub_epi64(A, B)
#define aesenc(A, B)	    A = _mm_aesenc_si128(A, B)
#define pxor_clear(A, B)	A = _mm_setzero_si128(); // NOTE(casey): pxor_clear is a nonsense thing that is only here because compilers don't detect xor(a, a) is clearing a :(
#define palignr(A, B, i)    A = _mm_alignr_epi8(A, B, i)
#define pand(A, B)          A = _mm_and_si128(A, B)
#define aesdec(A, B)        A = _mm_aesdec_si128(A, B)
#define invMixCol(A)		A = _mm_aesimc_si128(A) //逆列混合
#define MixCol(A)			A = _mm_aesdeclast_si128(A, xmm_setzero); \
							A = _mm_aesenc_si128(A, xmm_setzero) 



//inSR + inSB + SR + SB +MC = MC
#define MEOW_INV_SHUFFLE(r0, r1, r2, r4, r5, r6) \
pxor(r1, r2);         \
inv_aesdec(r4, r1);   \
psubq(r5, r6);        \
pxor(r4, r6);         \
psubq(r1, r5);        \
inv_aesdec(r0, r4);
//r1和r2进行异或，将r4进行逆aes运算，r1作为轮密钥，r5,r6进行相加的逆运算


#define inv_aesdec(A, B) \
pxor(A, B);              \
MixCol(A);           \
aesenc(A, xmm_setzero);  \
invMixCol(A)
//xor+MC+SR+SB+MC+INMC = XOR+MC+SB+SR



//r4-1 i4-10 r5-2 i3-01 r2-4 i2-00 r3-6 i1-0f r1-0 
#define MEOW_INV_MIX_REG(r1, r2, r3, r4, r5,  i1, i2, i3, i4) \
pxor(r4, i4);                \
psubq(r5, i3);               \
INSTRUCTION_REORDER_BARRIER; \
inv_aesdec(r2, r4);          \
pxor(r2, i2);                \
psubq(r3, i1);               \
INSTRUCTION_REORDER_BARRIER; \
inv_aesdec(r1, r2);          \



#define INV_Squeeze(r0,r1,r2,r3,r4,r5,r6,r7)\
psubq(r0, r4);\
pxor(r0, r1);\
pxor(r4, r5);\
psubq(r0, r2);\
psubq(r1, r3);\
psubq(r4, r6);\
psubq(r5, r7);\



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


int main() {

	const char* msg = "LiZhuoqun_202000460041";
	const char* Hash_value = "sdu_cst_20220610";

	//先对消息进行处理  
	int msglen = strlen(msg); 
	char* message = new char[msglen + 1];
	memset(message, 0, msglen + 1);
	memcpy(message, msg, msglen);

	int Hash_len = strlen(Hash_value);
	char* Hashed_message = new char[Hash_len + 1];
	memset(Hashed_message, 0, Hash_len + 1);
	memcpy(Hashed_message, Hash_value, Hash_len);

	meow_u8 KeyBuffer[128];
	memset(KeyBuffer, 0, 128);
	INVMeowHash(msglen, Hashed_message, message, KeyBuffer);


	cout << "The message is:" << message<<endl;

	printf("%s\n\t", "Key: ");
	for (int i = 0; i < 128; i++) {
		printf("%02X", (int)KeyBuffer[i]);
		if (i % 16 == 15) {
			printf("\n\t");
		}
	}

	meow_u128 Hash_verify = MeowHash(KeyBuffer, msglen, message);
	unsigned char Hash_con[20];
	memset(Hash_con, 0, 20);
	movdqu_mem(Hash_con, Hash_verify);
	printf("\n\n");
	printf("将Key带入加密进行验证，得到的Hash value为：%s", Hash_con);
	return 0;
}