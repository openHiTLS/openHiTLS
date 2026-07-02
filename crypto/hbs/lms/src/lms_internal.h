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

#ifndef LMS_INTERNAL_H
#define LMS_INTERNAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_HSS_LMS)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "lms_params.h"
#include "bsl_bytes.h"
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* LMS type identifiers */
#define LMS_SHA256_M32_H5  0x00000005
#define LMS_SHA256_M32_H10 0x00000006
#define LMS_SHA256_M32_H15 0x00000007
#define LMS_SHA256_M32_H20 0x00000008
#define LMS_SHA256_M32_H25 0x00000009

#define LMOTS_SHA256_N32_W1 0x00000001
#define LMOTS_SHA256_N32_W2 0x00000002
#define LMOTS_SHA256_N32_W4 0x00000003
#define LMOTS_SHA256_N32_W8 0x00000004

#define LMS_TYPE_LEN                   4
#define LMS_Q_LEN                      4
#define LMS_MAX_SAFE_HEIGHT_FOR_UINT64 60

#define LMS_ROOT_NODE_INDEX       1
#define LMS_LEFT_CHILD_MULTIPLIER 2

/* Public key field offsets */
#define LMS_PUBKEY_LMS_TYPE_OFFSET 0
#define LMS_PUBKEY_OTS_TYPE_OFFSET 4
#define LMS_PUBKEY_I_OFFSET        8
#define LMS_PUBKEY_ROOT_OFFSET     24
#define LMS_PUBKEY_MAX_LEN         (24 + LMS_SHA256_N)

/* Full struct definitions */
struct LmsOtsCtx {
    const uint8_t *I;
    uint32_t q;
    uint32_t n;
    uint32_t w;
    uint32_t p;
    uint32_t ls;
    const LmsFamilyHashFuncs *hashFuncs;
};

struct LmsTreeCtx {
    const LMS_Para *para;
    const uint8_t *I;
    const uint8_t *seed;
    uint32_t height;
    uint32_t n;
    const LmsFamilyHashFuncs *hashFuncs;
    uint8_t **cachedTree;
    uint32_t *cachedTreeSize;
    bool *treeCacheValid;
};

/* OTS types */
typedef struct {
    const uint8_t *I;
    uint32_t q;
    uint32_t expectedOtsType;
} LMS_OtsValidateCtx;

/* LMS verification */
int32_t LmsValidateSignature(const uint8_t *publicKey, const uint8_t *message, uint32_t messageLen,
    const uint8_t *signature, uint32_t signatureLen);

/* OTS shared helpers */
uint32_t LmOtsGetSigLen(uint32_t otsType);
int32_t LmOtsChain(uint8_t *buffer, uint32_t start, uint32_t steps, const LmsOtsCtx *ctx, uint32_t k);
uint32_t LmOtsCoef(const uint8_t *Q, uint32_t i, uint32_t w);
int32_t LmOtsComputeQ(uint8_t *Q, const LmsOtsCtx *ctx, const uint8_t *C, const uint8_t *message,
    uint32_t messageLen);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* LMS_INTERNAL_H */
