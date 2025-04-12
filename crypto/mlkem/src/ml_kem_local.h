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

// 9 = 8.38 = (((MLKEM_BITS_OF_Q * (MLKEM_N/8) * 2^MLKEM_BITS_OF_Q) / MLKEM_Q) + 64) / 64;
// array_B_arbitrary_length = 9 * 64 + 2 = 578
#define MLKEM_XOF_OUTPUT_LENGTH 578

#define MLKEM_Q    3329
#define MLKEM_BITS_OF_Q 12
#define MLKEM_INVN 3303  // MLKEM_N_HALF * MLKEM_INVN = 1 mod MLKEM_Q

typedef int32_t (*MlKemHashFunc)(uint32_t id, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

static inline void MlKemAddModQ(int16_t *val)
{
    while (*val < 0) {
        *val += MLKEM_Q;
    }
}

typedef struct {
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
};

void MLKEM_ComputNTT(int16_t *a, const int16_t *psi, uint32_t pruLength);
void MLKEM_ComputINTT(int16_t *a, const int16_t *psiInv, uint32_t pruLength);
void MLKEM_SamplePolyCBD(int16_t *polyF, uint8_t *buf, uint8_t eta);
void MLKEM_MatrixMulAdd(uint8_t k, int16_t *matrix[], int16_t *vectorS[], int16_t *vectorE,
    int16_t *vectorT, const int16_t *factor);

int32_t MLKEM_KeyGenInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *d, uint8_t *z);

int32_t MLKEM_EncapsInternal(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *sk, uint32_t *skLen,
    uint8_t *m);

int32_t MLKEM_DecapsInternal(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t ctLen, uint8_t *sk, uint32_t *skLen);

#endif    // ML_KEM_LOCAL_H
