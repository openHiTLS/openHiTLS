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

#ifndef CRYPT_ML_KEM_LOCAL_H
#define CRYPT_ML_KEM_LOCAL_H
#include "crypt_mlkem.h"
#include "sal_atomic.h"
#include "crypt_local_types.h"

#define MLKEM_N        256
#define MLKEM_N_HALF   128
#define MLKEM_CIPHER_LEN   384

#define MLKEM_SEED_LEN 32
#define MLKEM_SHARED_KEY_LEN 32
#define MLKEM_PRF_BLOCKSIZE 64
#define MLKEM_ENCODE_BLOCKSIZE 32

#define MLKEM_Q    3329
#define MLKEM_Q_INV_BETA (-3327)  //(-MLKEM_Q) ^{-1} mod BETA, BETA = 2^{16}
#define MLKEM_Q_HALF ((MLKEM_Q + 1) / 2)
#define MLKEM_BITS_OF_Q 12
#define MLKEM_INVN 3303  // MLKEM_N_HALF * MLKEM_INVN = 1 mod MLKEM_Q
#define MLKEM_K_MAX    4

// Reference: https://eprint.iacr.org/2022/956.pdf
// Section 4.1. Efficient Plantard Arithmetic for 16-bit Modulus
#define MLKEM_PLANTARD_L 16
#define MLKEM_PLANTARD_ALPHA 3

// 1729 * 128^{-1} mod 3329 converted to Plantard domin
// 1729 is the last round ztea
#define MLKEM_LAST_ROUND_ZETA 2131356556
#define MLKEM_HALF_DEGREE_INVERSE_MOD_Q (-33544352) // 128^{-1} mod 3329 = 3303 converted to Plantard domin

typedef int32_t (*MlKemHashFunc)(uint32_t id, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);


static inline int16_t BarrettReduction(int32_t a)
{
    const int32_t v = ((1 << 27) + MLKEM_Q / 2) / MLKEM_Q;
    int32_t t = ((int64_t)v * a + (1 << 26)) >> 27;
    t *= MLKEM_Q;
    return (int16_t)(a - t);
}

static inline int16_t PlantardReduction(int32_t a)
{
    a >>= MLKEM_PLANTARD_L;
    a = (a + (1 << MLKEM_PLANTARD_ALPHA)) * MLKEM_Q;
    a >>= MLKEM_PLANTARD_L;
    return a;
}

typedef struct {
    int16_t *bufAddr;
    int16_t *matrix[MLKEM_K_MAX][MLKEM_K_MAX];
    int16_t *vectorS[MLKEM_K_MAX];
    int16_t *vectorE[MLKEM_K_MAX];
    int16_t *vectorT[MLKEM_K_MAX];
} MLKEM_MatrixSt;

typedef struct {
    int32_t paramId;        // Algorithm parameter ID (CRYPT_KEM_TYPE_MLKEM_512/768/1024)
    uint8_t k;
    uint8_t eta1;
    uint8_t eta2;
    uint8_t du;
    uint8_t dv;
    uint32_t secBits;
    uint32_t encapsKeyLen;
    uint32_t decapsKeyLen;
    uint32_t cipherLen;
    uint32_t sharedLen;
    uint32_t bits;
} CRYPT_MlKemInfo;

struct CryptMlKemCtx {
    int32_t algId;
    const CRYPT_MlKemInfo *info;
    uint8_t *ek;
    uint32_t ekLen;
    uint8_t *dk;
    uint32_t dkLen;
    BSL_SAL_RefCount references;
    void *libCtx;
    MLKEM_MatrixSt keyData;
    CRYPT_ALGO_MLKEM_DK_FORMAT_TYPE dkFormat;
    bool hasSeed;                      // Flag indicating if seed is stored
    uint8_t seed[MLKEM_SEED_LEN * 2]; // Store 64-byte seed (d || z)
};
int32_t MLKEM_DecodeDk(CRYPT_ML_KEM_Ctx *ctx, const uint8_t *dk, uint32_t dkLen);
int32_t MLKEM_DecodeEk(CRYPT_ML_KEM_Ctx *ctx, const uint8_t *ek, uint32_t ekLen);
void MLKEM_ComputNTT(int16_t *a, const int32_t *psi);
void MLKEM_ComputINTT(int16_t *a, const int32_t *psi);
void MLKEM_SamplePolyCBD(int16_t *polyF, uint8_t *buf, uint8_t eta);
void MLKEM_TransposeMatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec, int16_t **polyVecOut,
                                 const int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF]);
void MLKEM_MatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec, int16_t **polyVecOut,
                        const int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF]);
void MLKEM_VectorInnerProductAdd(uint8_t k, int16_t **polyVec1, int16_t **polyVec2, int16_t *polyOut,
                                 const int32_t *factor);
void MLKEM_VectorInnerProductAddUseCache(uint8_t k, int16_t **polyVec1, int16_t **polyVec2, int16_t *polyOut,
                                 const int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF]);

void MLKEM_ComputeMulCache(uint8_t k, int16_t **input, int16_t output[MLKEM_K_MAX][MLKEM_N_HALF], const int32_t *factor);

int32_t MLKEM_KeyGenInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *d, uint8_t *z);

int32_t MLKEM_EncapsInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *sk, uint32_t *skLen,
    uint8_t *m);

int32_t MLKEM_DecapsInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t ctLen, uint8_t *sk, uint32_t *skLen);

int32_t MLKEM_CreateMatrixBuf(uint8_t k, MLKEM_MatrixSt *st);

#endif    // ML_KEM_LOCAL_H
