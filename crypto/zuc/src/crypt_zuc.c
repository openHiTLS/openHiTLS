/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ZUC

#include "crypt_zuc_local.h"
#include <stdio.h>

#define MAKEU32(a, b, c ,d) (\
((uint32_t)(a) << 24)        \
| ((uint32_t)(b) << 16)      \
| ((uint32_t)(c) << 8)       \
| ((uint32_t)(d)))

// ZUC128 LFSR Init
#define MAKEU31(a, b, c) (\
((uint32_t)(a) << 23)     \
| ((uint32_t)(b) << 8)    \
| ((uint32_t)(c)))

// ZUC256 LFSR Init
#define M2U31(a, b, c, d) (\
((uint32_t)(a) << 23)      \
| ((uint32_t)(b) << 16)    \
| ((uint32_t)(c) << 8)     \
| ((uint32_t)(d)))

#define MulByPow2(x, k) ((((x) << (k)) | ((x) >> (31 - (k)))) & 0x7FFFFFFF)

/* linear transformation L1 */
#define L1(X) 		    \
	((X)            ^	\
	ROTL32((X),  2) ^	\
	ROTL32((X), 10) ^	\
	ROTL32((X), 18) ^	\
	ROTL32((X), 24))

/* linear transformation L2 */
#define L2(X) 			\
	((X)            ^   \
	ROTL32((X),  8) ^	\
	ROTL32((X), 14) ^	\
	ROTL32((X), 22) ^	\
	ROTL32((X), 30))

// GB/T 33133.1 ——2016
static const uint8_t S0[256] = {
	0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,
	0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,
	0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,
	0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,
	0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,
	0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,
	0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,
	0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,
	0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,
	0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,
	0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,
	0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,
	0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,
	0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,
	0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,
	0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60,
};

// GB/T 33133.1 ——2016
static const uint8_t S1[256] = {
	0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,
	0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,
	0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,
	0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,
	0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,
	0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,
	0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,
	0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,
	0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,
	0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,
	0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,
	0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,
	0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,
	0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,
	0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,
	0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2,
};

static const uint32_t EK_d[3][16] = {
    {   // GB/T 33133.1 ——2016
        0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
        0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
    },
    {   // ZUC256 Stream Cipher
        0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30
    },
    {   // An Addendum to the ZUC-256 Stream Cipher
        0x64, 0x43, 0x7B, 0x2A, 0x11, 0x05, 0x51, 0x42,
        0x1A, 0x31, 0x18, 0x66, 0x14, 0x2E, 0x01, 0x5C
    }
};

/* c = a + b mod (2^31 – 1) */
static inline uint32_t AddM(uint32_t a, uint32_t b) {
    uint32_t c = a + b;
    return (c & 0x7FFFFFFF) + (c >> 31);
}

/* Bit Reorganization Procedure */
static inline void BitReorganization(CRYPT_ZUC_Ctx *ctx) {
    ctx->X[0] = (((ctx->S[15] & 0x7fff8000) << 1) | (ctx->S[14] & 0xffff));
    ctx->X[1] = (((ctx->S[11] & 0xffff) << 16) | (ctx->S[9] >> 15)); 
    ctx->X[2] = (((ctx->S[7] & 0xffff) << 16) | (ctx->S[5] >> 15));
    ctx->X[3] = (((ctx->S[2] & 0xffff) << 16) | (ctx->S[0] >> 15));
}

/** 
 * GB/T 33133.1 ——2016
 * F function
*/ 
static inline uint32_t F(CRYPT_ZUC_Ctx *ctx)
{
    uint32_t W, W1, W2, u, v;
    W = (ctx->X[0] ^ ctx->R[0]) + ctx->R[1];
    W1 = ctx->R[0] + ctx->X[1];
    W2 = ctx->R[1] ^ ctx->X[2];
    u = L1((W1 << 16) | (W2 >> 16));
    v = L2((W2 << 16) | (W1 >> 16));
    ctx->R[0] = MAKEU32(S0[u >> 24], S1[(u >> 16) & 0xFF], S0[(u >> 8) & 0xFF], S1[u & 0xFF]);
    ctx->R[1] = MAKEU32(S0[v >> 24], S1[(v >> 16) & 0xFF], S0[(v >> 8) & 0xFF], S1[v & 0xFF]);
    return W;
}

// LFSR With Initialization Mode
static void ZUC_LFSR_IMode(CRYPT_ZUC_Ctx *ctx, uint32_t u) {
    uint32_t f, v;

    f = ctx->S[0];
    v = MulByPow2(ctx->S[0], 8);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[4], 20);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[10], 21);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[13], 17);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[15], 15);
    f = AddM(f, v);

    f = AddM(f, u);

    /* update the state */
    for(int i = 0; i < 15; ++i) 
        ctx->S[i] = ctx->S[i + 1];
    
    ctx->S[15] = f;
}

/* LFSR With Work Mode */
static void ZUC_LFSR_WMode(CRYPT_ZUC_Ctx *ctx) {
    uint32_t f, v;

    f = ctx->S[0];
    v = MulByPow2(ctx->S[0], 8);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[4], 20);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[10], 21);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[13], 17);
    f = AddM(f, v);

    v = MulByPow2(ctx->S[15], 15);
    f = AddM(f, v);

    /* update state */
    for(int i = 0; i < 15; ++i) 
        ctx->S[i] = ctx->S[i + 1];
    
    ctx->S[15] = f;
}

void ZUC_Init(CRYPT_ZUC_Ctx *ctx){

    // LFSR init
    if(ctx->type & CRYPT_ZUC128){
        // GB/T 33133.1 ——2016
        ctx->S[0]  = MAKEU31(ctx->key[0],  EK_d[0][0],  ctx->iv[0]);
        ctx->S[1]  = MAKEU31(ctx->key[1],  EK_d[0][1],  ctx->iv[1]);
        ctx->S[2]  = MAKEU31(ctx->key[2],  EK_d[0][2],  ctx->iv[2]);
        ctx->S[3]  = MAKEU31(ctx->key[3],  EK_d[0][3],  ctx->iv[3]);
        ctx->S[4]  = MAKEU31(ctx->key[4],  EK_d[0][4],  ctx->iv[4]);
        ctx->S[5]  = MAKEU31(ctx->key[5],  EK_d[0][5],  ctx->iv[5]);
        ctx->S[6]  = MAKEU31(ctx->key[6],  EK_d[0][6],  ctx->iv[6]);
        ctx->S[7]  = MAKEU31(ctx->key[7],  EK_d[0][7],  ctx->iv[7]);
        ctx->S[8]  = MAKEU31(ctx->key[8],  EK_d[0][8],  ctx->iv[8]);
        ctx->S[9]  = MAKEU31(ctx->key[9],  EK_d[0][9],  ctx->iv[9]);
        ctx->S[10] = MAKEU31(ctx->key[10], EK_d[0][10], ctx->iv[10]);
        ctx->S[11] = MAKEU31(ctx->key[11], EK_d[0][11], ctx->iv[11]);
        ctx->S[12] = MAKEU31(ctx->key[12], EK_d[0][12], ctx->iv[12]);
        ctx->S[13] = MAKEU31(ctx->key[13], EK_d[0][13], ctx->iv[13]);
        ctx->S[14] = MAKEU31(ctx->key[14], EK_d[0][14], ctx->iv[14]);
        ctx->S[15] = MAKEU31(ctx->key[15], EK_d[0][15], ctx->iv[15]);

    } else if(ctx->type & CRYPT_ZUC256 && ctx->ivlen == CRYPT_ZUC_IVLEN23B){
        // ZUC256 Stream Cipher, DOI: 10.13868/j.cnki.jcr.000228
        ctx->S[0]  = M2U31(ctx->key[0],  EK_d[1][0],  ctx->key[21], ctx->key[16]);
        ctx->S[1]  = M2U31(ctx->key[1],  EK_d[1][1],  ctx->key[22], ctx->key[17]);
        ctx->S[2]  = M2U31(ctx->key[2],  EK_d[1][2],  ctx->key[23], ctx->key[18]);
        ctx->S[3]  = M2U31(ctx->key[3],  EK_d[1][3],  ctx->key[24], ctx->key[19]);
        ctx->S[4]  = M2U31(ctx->key[4],  EK_d[1][4],  ctx->key[25], ctx->key[20]);
        ctx->S[5]  = M2U31(ctx->iv[0],   (EK_d[1][5]|ctx->iv[17]),  ctx->key[5], ctx->key[26]);
        ctx->S[6]  = M2U31(ctx->iv[1],   (EK_d[1][6]|ctx->iv[18]),  ctx->key[6], ctx->key[27]);
        ctx->S[7]  = M2U31(ctx->iv[10],  (EK_d[1][7]|ctx->iv[19]),  ctx->key[7], ctx->iv[2]);
        ctx->S[8]  = M2U31(ctx->key[8],  (EK_d[1][8]|ctx->iv[20]),  ctx->iv[3], ctx->iv[11]);
        ctx->S[9]  = M2U31(ctx->key[9],  (EK_d[1][9]|ctx->iv[21]),  ctx->iv[12],   ctx->iv[4]);
        ctx->S[10] = M2U31(ctx->iv[5],   (EK_d[1][10]|ctx->iv[22]), ctx->key[10],   ctx->key[28]);
        ctx->S[11] = M2U31(ctx->key[11], (EK_d[1][11]|ctx->iv[23]), ctx->iv[6],   ctx->iv[13]);
        ctx->S[12] = M2U31(ctx->key[12], (EK_d[1][12]|ctx->iv[24]), ctx->iv[7],   ctx->iv[14]);
        ctx->S[13] = M2U31(ctx->key[13], EK_d[1][13], ctx->iv[15],   ctx->iv[8]);
        ctx->S[14] = M2U31(ctx->key[14], (EK_d[1][14]|(ctx->key[31]>>4)), ctx->iv[16],  ctx->iv[9]);
        ctx->S[15] = M2U31(ctx->key[14], (EK_d[1][15]|(ctx->key[31]&0x0f)), ctx->key[30], ctx->key[29]);
        
    } else{
        // An Addendum to the ZUC-256 Stream Cipher, https://ia.cr/2021/1439
        ctx->S[0]  = M2U31(ctx->key[0],  EK_d[2][0],  ctx->key[16], ctx->key[24]);
        ctx->S[1]  = M2U31(ctx->key[1],  EK_d[2][1],  ctx->key[17], ctx->key[25]);
        ctx->S[2]  = M2U31(ctx->key[2],  EK_d[2][2],  ctx->key[18], ctx->key[26]);
        ctx->S[3]  = M2U31(ctx->key[3],  EK_d[2][3],  ctx->key[19], ctx->key[27]);
        ctx->S[4]  = M2U31(ctx->key[4],  EK_d[2][4],  ctx->key[20], ctx->key[28]);
        ctx->S[5]  = M2U31(ctx->key[5],  EK_d[2][5],  ctx->key[21], ctx->key[29]);
        ctx->S[6]  = M2U31(ctx->key[6],  EK_d[2][6],  ctx->key[22], ctx->key[30]);
        ctx->S[7]  = M2U31(ctx->key[7],  EK_d[2][7],  ctx->iv[0],   ctx->iv[8]);
        ctx->S[8]  = M2U31(ctx->key[8],  EK_d[2][8],  ctx->iv[1],   ctx->iv[9]);
        ctx->S[9]  = M2U31(ctx->key[9],  EK_d[2][9],  ctx->iv[2],   ctx->iv[10]);
        ctx->S[10] = M2U31(ctx->key[10], EK_d[2][10], ctx->iv[3],   ctx->iv[11]);
        ctx->S[11] = M2U31(ctx->key[11], EK_d[2][11], ctx->iv[4],   ctx->iv[12]);
        ctx->S[12] = M2U31(ctx->key[12], EK_d[2][12], ctx->iv[5],   ctx->iv[13]);
        ctx->S[13] = M2U31(ctx->key[13], EK_d[2][13], ctx->iv[6],   ctx->iv[14]);
        ctx->S[14] = M2U31(ctx->key[14], EK_d[2][14], ctx->iv[7],   ctx->iv[15]);
        ctx->S[15] = M2U31(ctx->key[15], EK_d[2][15], ctx->key[23], ctx->key[31]);
    }

    // Set Register R1 & R2 to 0
    ctx->R[0] = 0;
    ctx->R[1] = 0;

    // 32 rounds of {reorganize; F; Initialize Mode;}
    for(uint32_t nCnt = 32, w; nCnt; --nCnt){
        BitReorganization(ctx);
        w = F(ctx);
        ZUC_LFSR_IMode(ctx, w>>1);
    }
    /**
     * According to GB/T 33133.1 ——2016, this is the first step of work procedure,
     * but in many use cases multiple calls are made to GenKeyStream(), 
     * put it here so we won't have to run this everytime we call GenKeyStream().
    */ 
    BitReorganization(ctx);
    F(ctx);
    ZUC_LFSR_WMode(ctx);
}

// ZUC Generate key stream , KeyStreamLen mod 4 == 0
void ZUC_GenKeyStream(CRYPT_ZUC_Ctx *ctx, uint8_t* out, int KeyStreamLen){
    // GB/T 33133.1 ——2016, discard the first output

    printf("raw KeyStream: ");
    for(uint16_t i = 0; i < KeyStreamLen; i += 4){
        BitReorganization(ctx);
        uint32_t v = F(ctx) ^ ctx->X[3];
        printf("0x%08x ", v);
        PUT_UINT32_BE(v, out, i);
        ZUC_LFSR_WMode(ctx);
    }
    printf("\n");
}

#endif // HITLS_CRYPTO_ZUC
