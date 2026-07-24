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
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { FRODO_PRG_AES, FRODO_PRG_SHAKE } FrodoKemPrgType;

#define FRODO_M_SALT_LEN 96
typedef struct FrodoKemParams FrodoKemParams;

typedef struct FrodoKemParams {
    int32_t algId;
    CRYPT_MD_AlgId hashId;
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

int32_t FrodoExpandShakeDs(uint8_t *out, uint32_t outlen, uint8_t ds, const uint8_t *seed, uint32_t seedlen,
                           const FrodoKemParams *params, void *libCtx);

int32_t FrodoPkeKeygenSeeded(const FrodoKemParams *params, uint8_t *pk, uint16_t *matrixSTranspose,
                             const uint8_t *seedA, const uint8_t *seedSE, void *libCtx);

void FrodoCommonSampleNFromR(uint16_t *samples, const uint32_t n, const uint16_t *cdfTable, const uint32_t cdfLen,
                             const uint8_t *rBytes);

void FrodoMulAddAsPlusE(uint16_t *out, const uint16_t *matrixS, int32_t n, int32_t nBar, uint16_t *rows,
                        int32_t rowNumber);
void FrodoMulAddSaPlusE(uint16_t *out, const uint16_t *matrixS, int32_t n, int32_t nBar, uint16_t *rows,
                        int32_t rowNumber);

// =================================================================================
// Function Prototypes from util.c
// =================================================================================

void FrodoCommonPack(uint8_t *out, const uint32_t outLen, const uint16_t *in, const uint32_t inLen,
                     const uint8_t lsb);

void FrodoCommonUnpack(uint16_t *out, const uint32_t outLen, const uint8_t *in, const uint32_t inLen,
                       const uint8_t lsb);

void FrodoCommonEncodeLe16(uint8_t *out, const uint16_t *in, uint32_t len);

void FrodoCommonDecodeLe16(uint16_t *out, const uint8_t *in, uint32_t len);

// =================================================================================
// Function Prototypes from core_*.c (Matrix Arithmetic)
// =================================================================================

int32_t FrodoCommonMulAddAsPlusEPortable(uint16_t *out, const uint16_t *matrixST, const uint8_t *seedA,
                                         const FrodoKemParams *params, void *libCtx);

int32_t FrodoCommonMulAddSaPlusEPortable(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seedA,
                                         const FrodoKemParams *params, void *libCtx);

void FrodoCommonMulAddSbPlusEPortable(uint16_t *V0, const uint16_t *STp, const uint16_t *B, const uint16_t *Epp,
                                      const FrodoKemParams *params);

void FrodoCommonMulBs(uint16_t *out, const uint16_t *b, const uint16_t *s, const FrodoKemParams *params);
void FrodoCommonMulBsUsingSt(uint16_t *out, const uint16_t *b, const uint16_t *sT, const FrodoKemParams *params);

// =================================================================================
// Function Prototypes from core_*.c (Small Matrix and Key Arithmetic)
// =================================================================================

void FrodoCommonAdd(uint16_t *out, const uint16_t *a, const uint16_t *b, const FrodoKemParams *params);
void FrodoCommonSub(uint16_t *out, const uint16_t *a, const uint16_t *b, const FrodoKemParams *params);
void FrodoCommonKeyEncode(uint16_t *out, const uint8_t *mu, const FrodoKemParams *params);
void FrodoCommonKeyDecode(uint8_t *mu, const uint16_t *in, const FrodoKemParams *params);

// =================================================================================
// Function Prototypes from frodokem_pke.c
// =================================================================================

int32_t FrodoPkeKeygen(const FrodoKemParams *params, uint8_t *pk, uint8_t *pke_sk);
int32_t FrodoPkeEncrypt(const FrodoKemParams *params, const uint8_t *pk, const uint8_t *mu, const uint8_t *seedSEp,
                        uint8_t *ct, void *libCtx);
int32_t FrodoPkeDecrypt(const FrodoKemParams *params, const uint8_t *pkeSk, const uint8_t *ct, uint8_t *mu);

#ifdef __cplusplus
}
#endif

#endif
