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

#ifndef FRODO_LOCAL_H
#define FRODO_LOCAL_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { FRODO_PRG_AES, FRODO_PRG_SHAKE } FrodoKemPrgType;

#define FRODO_PARA_640_N 640
#define FRODO_M_SALT_LEN 96
typedef struct FrodoKemParams FrodoKemParams;

typedef struct FrodoKemParams {
    int32_t algId;
    uint16_t n;
    uint16_t nBar;
    uint8_t logq;
    uint8_t extractedBits;
    uint8_t d;

    uint16_t pkSize;
    uint16_t kemSkSize;
    uint16_t ctxSize;
    uint16_t ss;
    uint8_t lenSeedA;
    uint8_t lenSeedSE;
    uint8_t lenMu;
    uint8_t lenPkHash;
    uint8_t lenSalt;

    const uint16_t *cdfTable;
    uint8_t cdfLen;

    FrodoKemPrgType prg;
} FrodoKemParams;

typedef struct Frodokem_Ctx {
    FrodoKemParams *para;
    uint8_t *publicKey;
    uint8_t *privateKey;
    void *libCtx;
} CRYPT_FRODOKEM_Ctx;

FrodoKemParams *FrodoGetParamsById(int32_t algId);

int32_t FrodoKemShake128(uint8_t *output, uint32_t outlen, const uint8_t *input, uint32_t inlen);
int32_t FrodoKemShake256(uint8_t *output, uint32_t outlen, const uint8_t *input, uint32_t inlen);

int32_t FrodoExpandShakeDs(uint8_t *out, uint32_t outlen, uint8_t ds, const uint8_t *seed, uint32_t seedlen,
                           const FrodoKemParams *params);

int32_t FrodoPkeKeygenSeeded(const FrodoKemParams *params, uint8_t *pk, uint16_t *matrixSTranspose,
                             const uint8_t *seedA, const uint8_t *seedSE);

// =================================================================================
// Function Prototypes from util.c
// =================================================================================

void FrodoCommonPack(uint8_t *out, const size_t outLen, const uint16_t *in, const size_t inLen, const uint8_t lsb);

void FrodoCommonUnpack(uint16_t *out, const size_t outLen, const uint8_t *in, const size_t inLen, const uint8_t lsb);

int8_t FrodoCommonCtVerify(const uint16_t *a, const uint16_t *b, size_t len);

void FrodoCommonCtSelect(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len, int8_t selector);

// =================================================================================
// Function Prototypes from core_*.c (Matrix Arithmetic)
// =================================================================================

int32_t FrodoCommonMulAddAsPlusEPortable(uint16_t *out, const uint16_t *s, const uint8_t *seedA,
                                         const FrodoKemParams *params);

int32_t FrodoCommonMulAddSaPlusEPortable(uint16_t *b, const uint16_t *s, const uint16_t *e, const uint8_t *seedA,
                                         const FrodoKemParams *params);

void FrodoCommonMulAddSbPlusEPortable(uint16_t *V0, const uint16_t *STp, const uint16_t *B, const uint16_t *Epp,
                                      const FrodoKemParams *params);

void FrodoCommonMulBs(uint16_t *out, const uint16_t *b, const uint16_t *s, const FrodoKemParams *params);
void FrodoCommonMulBsUsingSt(uint16_t *out, const uint16_t *b, const uint16_t *s, const FrodoKemParams *params);

// =================================================================================
// Function Prototypes from core_*.c (Small Matrix and Key Arithmetic)
// =================================================================================

void FrodoCommonAdd(uint16_t *out, const uint16_t *a, const uint16_t *b, const FrodoKemParams *params);
void FrodoCommonSub(uint16_t *out, const uint16_t *a, const uint16_t *b, const FrodoKemParams *params);
void FrodoCommonKeyEncode(uint16_t *out, const uint16_t *in, const FrodoKemParams *params);
void FrodoCommonKeyDecode(uint16_t *out, const uint16_t *in, const FrodoKemParams *params);

// =================================================================================
// Function Prototypes from frodokem_pke.c
// =================================================================================

int32_t FrodoPkeKeygen(const FrodoKemParams *params, uint8_t *pk, uint8_t *pke_sk);
int32_t FrodoPkeEncrypt(const FrodoKemParams *params, const uint8_t *pk, const uint8_t *mu, const uint8_t *seedSE,
                        uint8_t *ct);
int32_t FrodoPkeDecrypt(const FrodoKemParams *params, const uint8_t *pke_sk, const uint8_t *ct, uint8_t *mu);

#ifdef __cplusplus
}
#endif

#endif
