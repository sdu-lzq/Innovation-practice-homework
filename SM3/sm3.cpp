#include"sm3.h"
#include<Windows.h>
#include<iostream>
#include<immintrin.h>



LARGE_INTEGER nFreq;
LARGE_INTEGER nBeginTime;
LARGE_INTEGER nEndTime;
double Time = 0;

static unsigned char message_buffer[64] = { 0 };
static unsigned int iv[8] = { 0 };
static unsigned int T[64] = { 0 };

/* set the T*/
int init_T() {
	for (int i = 0; i < 16; i++)
		T[i] = 0x79cc4519;
	for (int i = 16; i < 64; i++)
		T[i] = 0x7a879d8a;
	return 1;
}


void SM3_init()
{
	init_T();
	iv[0] = 0x7380166f;
	iv[1] = 0x4914b2b9;
	iv[2] = 0x172442d7;
	iv[3] = 0xda8a0600;
	iv[4] = 0xa96f30bc;
	iv[5] = 0x163138aa;
	iv[6] = 0xe38dee4d;
	iv[7] = 0xb0fb0e4e;
}



void out_hex()
{
	unsigned int i = 0;
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", iv[i]);
	}
	printf("\n");
}

/*define the bool function*/
unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, unsigned int j) {
	unsigned int ret = 0;
	if (0 <= j && j < 16)
		ret = X ^ Y ^ Z;
	else if (16 <= j && j < 64)
		ret = (X & Y) | (X & Z) | (Y & Z);
	return ret;
}


unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z,unsigned int j) {
	unsigned int ret = 0;
	if (0 <= j && j < 16)
		ret = X ^ Y ^ Z;
	else if (16 <= j && j < 64)
		ret = (X & Y) | ((~X) & Z);
	return ret;
}

unsigned int Round_shift(unsigned int a, unsigned int k) {
	k = k % 32;
	return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));
}
/*The function is for round_shift
*k is the number of shift
* the xor is using for the extend

*/


#define P_0(X) X^(Round_shift(X,9))^(Round_shift(X,17))
#define P_1(X) X^(Round_shift(X,15))^(Round_shift(X,23))



int IC(unsigned char* arr) {
	unsigned int W[68];
	unsigned int _W[64];
	unsigned int j;
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int SS1, SS2, TT1, TT2;
	for (j = 0; j < 16; j++)
		W[j] = arr[j * 4 + 0] << 24 | arr[j * 4 + 1] << 16 | arr[j * 4 + 2] << 8 | arr[j * 4 + 3];
	for (j = 16; j < 68; j++)
		W[j] = P_1(W[j - 16] ^ W[j - 9] ^ (Round_shift(W[j - 3], 15))) ^ (Round_shift(W[j - 13], 7)) ^ W[j - 6];
	for (j = 0; j < 64; j++)
		_W[j] = W[j] ^ W[j + 4];
	A = iv[0];
	B = iv[1];
	C = iv[2];
	D = iv[3];
	E = iv[4];
	F = iv[5];
	G = iv[6];
	H = iv[7];
	for (int j = 0; j < 64; j++)
	{
		SS1 = Round_shift(((Round_shift(A, 12)) + E + (Round_shift(T[j], j))) & 0xFFFFFFFF,7);
		SS2 = SS1 ^ Round_shift(A, 12);
		TT1 = (FF(A, B, C, j) + D + SS2 + _W[j])&0xFFFFFFFF;
		TT2 = (GG(E, F, G, j) + H + SS1 + W[j])&0xFFFFFFFF;
		D = C;
		C = Round_shift(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = Round_shift(F, 19);
		F = E;
		E = P_0(TT2);

	}
	iv[0] = (A ^ iv[0]);
	iv[1] = (B ^ iv[1]);
	iv[2] = (C ^ iv[2]);
	iv[3] = (D ^ iv[3]);
	iv[4] = (E ^ iv[4]);
	iv[5] = (F ^ iv[5]);
	iv[6] = (G ^ iv[6]);
	iv[7] = (H ^ iv[7]);
	return 1;
}

/*Group the messages and iteratively compress the filled chunks*/
void Block(unsigned char* msg, unsigned int msglen) {
	int i;
	int left = 0;
	unsigned long long total = 0;

	for (i = 0; i < msglen / 64; i++) {
		memcpy(message_buffer, msg + i * 64, 64);
		IC(message_buffer);
	}
	/*First fill the each block*/
	total = msglen * 8;
	/*every char has 8 bit*/
	left = msglen % 64;
	memset(&message_buffer[left], 0, 64 - left);
	/*memset(address,value,sizeof(the lenth of address))
	 The memset function is an initialization function that initializes a contiguous piece of memory to a value.

	 It is initialized in bytes.
	*/
	memcpy(message_buffer, msg + i * 64, left);
	/*now the value of i is the last chunk*/
	message_buffer[left] = 0x80;
	if (left <= 55) {
		for (i = 0; i < 8; i++)
			message_buffer[56 + i] = (total >> ((8 - 1 - i) * 8)) & 0xFF;
      		IC(message_buffer);
	}
	else {
		IC(message_buffer);
		memset(message_buffer, 0, 64);
		for (i = 0; i < 8; i++)
		{
			message_buffer[56 + i] = (total >> (8 - 1 - i) * 8) & 0xFF;

		}
		IC(message_buffer);
	}
}


int SM3(unsigned char* text, int len, unsigned char* iv) {
	SM3_init();
	Block(text, len);
	return 1;
}


int main(int argc, int* argv[]) {
	unsigned char iv[32] = { 0 };
	const char* text = "abc";
	int len;
	len = strlen(text);
	QueryPerformanceFrequency(&nFreq);
	QueryPerformanceCounter(&nBeginTime);
	SM3((unsigned char*)text, len, iv);
	QueryPerformanceCounter(&nEndTime);
	Time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
	std::cout << "Total time is  " << Time << std::endl;
	out_hex();
	return 0;
}