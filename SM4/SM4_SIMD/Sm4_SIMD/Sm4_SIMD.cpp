//------------------sm4.c---------------------
#include "Sm4_SIMD.h"

static uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
static uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
    0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
    0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
    0x484f565d, 0x646b7279 };
//S��

uint8_t plaintext[16 * 8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

uint32_t rK[32];

//������Կ
uint32_t MK[] = { 0x01234567,0x89abcdef,0xfedcba98,0x76543210 };



static uint8_t SBox[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48 };



//4��T��
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
    return num = Cycle_shift_left(num, 2) ^ Cycle_shift_left(num, 10) ^ Cycle_shift_left(num, 18) ^ Cycle_shift_left(num, 24) ^ num;
}



void generate_table()  {
    for (int i = 0; i < 256; i++) {
        Table3[i] = L(((uint32_t)S_replace((uint8_t)i)) <<24);
        Table2[i] = L(((uint32_t)S_replace((uint8_t)i)) << 16);
        Table1[i] = L(((uint32_t)S_replace((uint8_t)i)) << 8);
        Table0[i] = L(((uint32_t)S_replace((uint8_t)i)));
    }
}

int RoundK(uint32_t _K) {
    uint8_t* KK = (uint8_t*)&_K;
    uint8_t B_8[4];
    B_8[0] = S_replace(KK[0]);
    B_8[1] = S_replace(KK[1]);
    B_8[2] = S_replace(KK[2]);
    B_8[3] = S_replace(KK[3]);
    uint32_t* B_32 = (uint32_t*)B_8;
    uint32_t B13 = Cycle_shift_left(*B_32, 13);
    uint32_t B23 = Cycle_shift_left(*B_32, 23);
    return *B_32 ^ B13 ^ B23;
}


void Inv_dump_buf(uint8_t* buf, uint32_t len)
{
    int i;
    for (i = 0; i< len; i++) {
        printf("%02X%", buf[i]);
        printf(" ");
    }
}


void dump_buf(uint8_t* buf, uint32_t len) {
    int i;
    for (i = len - 1; i >= 0; i--) {
        printf("%02X%",buf[i]);
        printf(" ");
    }
}

#define MM256_PACK0_EPI32(a, b, c, d)                  \
    _mm256_unpacklo_epi64(_mm256_unpacklo_epi32(a, b), \
                          _mm256_unpacklo_epi32(c, d))
#define MM256_PACK1_EPI32(a, b, c, d)                  \
    _mm256_unpackhi_epi64(_mm256_unpacklo_epi32(a, b), \
                          _mm256_unpacklo_epi32(c, d))
#define MM256_PACK2_EPI32(a, b, c, d)                  \
    _mm256_unpacklo_epi64(_mm256_unpackhi_epi32(a, b), \
                          _mm256_unpackhi_epi32(c, d))
#define MM256_PACK3_EPI32(a, b, c, d)                  \
    _mm256_unpackhi_epi64(_mm256_unpackhi_epi32(a, b), \
                          _mm256_unpackhi_epi32(c, d))

void SM4_encryption(uint8_t* ciphertext) {
    uint32_t k[36];
    k[0] = MK[0] ^ FK[0]; k[1] = MK[1] ^ FK[1]; k[2] = MK[2] ^ FK[2]; k[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++) {
        rK[i] = k[i + 4] = k[i] ^ RoundK(k[i + 3] ^ k[i + 2] ^ k[i + 1] ^ CK[i]);
    }
    
    __m256i X[4], Temp[4], Mask;
    Mask = _mm256_set1_epi32(0xFF);
    //��������
    Temp[0] = _mm256_loadu_si256((const __m256i*)plaintext + 0);
    Temp[1] = _mm256_loadu_si256((const __m256i*)plaintext + 1);
    Temp[2] = _mm256_loadu_si256((const __m256i*)plaintext + 2);
    Temp[3] = _mm256_loadu_si256((const __m256i*)plaintext + 3);
    //�ϲ�ÿ��128bit���ݵ�ĳ32bit��
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
    // 32�ֵ���
    for (int i = 0; i < 32; i++) {
        __m256i k =
            _mm256_set1_epi32(rK[i]);
        Temp[0] = _mm256_xor_si256(_mm256_xor_si256(X[1], X[2]),
            _mm256_xor_si256(X[3], k));
        //���
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
    //ת������
    X[0] = _mm256_shuffle_epi8(X[0], vindex);
    X[1] = _mm256_shuffle_epi8(X[1], vindex);
    X[2] = _mm256_shuffle_epi8(X[2], vindex);
    X[3] = _mm256_shuffle_epi8(X[3], vindex);
    //�ָ����鲢װ��
    _mm256_storeu_si256((__m256i*)ciphertext + 0,
        MM256_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm256_storeu_si256((__m256i*)ciphertext + 1,
        MM256_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm256_storeu_si256((__m256i*)ciphertext + 2,
        MM256_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm256_storeu_si256((__m256i*)ciphertext + 3,
        MM256_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}

int main() {
    generate_table();
    double run_time;
    _LARGE_INTEGER time_start;	
    _LARGE_INTEGER time_over;	
    double dqFreq;		
    LARGE_INTEGER f;	
    QueryPerformanceFrequency(&f);
    dqFreq = (double)f.QuadPart;
    QueryPerformanceCounter(&time_start);
    uint8_t ciphertext[16];
    SM4_encryption(ciphertext);
    QueryPerformanceCounter(&time_over);	
    run_time = 1000000 * (double)(time_over.QuadPart - time_start.QuadPart) / dqFreq;
    printf("\nrun_time��%fus\n", run_time);
    printf("\n\n");
    printf("SIMD�ۺ��Ż�:\n");
    dump_buf((uint8_t*)ciphertext, 16);

}