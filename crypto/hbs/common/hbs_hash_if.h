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

#ifndef HBS_HASH_IF_H
#define HBS_HASH_IF_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hbs
 * @brief Hash function interface shared by XMSS, XMSSMT and SLH-DSA.
 */
typedef struct HbsHashFuncs {
    int32_t (*skDerive)(const void *ctx, const void *adrs, uint8_t *out);
    int32_t (*chainHash)(const void *ctx, const void *adrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out);
    int32_t (*nodeHash)(const void *ctx, const void *adrs, const uint8_t *in, uint32_t inLen, uint8_t *out);
    int32_t (*msgHash)(const void *ctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen, const uint8_t *idx,
        uint8_t *out);
    int32_t (*pkCompress)(const void *ctx, const void *adrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out);
    int32_t (*sigRandGen)(const void *ctx, const uint8_t *key, const uint8_t *msg, uint32_t msgLen, uint8_t *out);
    int32_t (*chain)(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t steps, const uint8_t *pubSeed,
        void *adrs, const void *ctx, uint8_t *output);
} HbsHashFuncs;

/**
 * @ingroup hbs
 * @brief Address operation interface shared by XMSS, XMSSMT and SLH-DSA.
 */
typedef struct HbsAdrsOps {
    void (*setLayerAddr)(void *adrs, uint32_t layer);
    void (*setTreeAddr)(void *adrs, uint64_t tree);
    void (*setType)(void *adrs, uint32_t type);
    void (*setKeyPairAddr)(void *adrs, uint32_t keyPair);
    void (*setChainAddr)(void *adrs, uint32_t chain);
    void (*setTreeHeight)(void *adrs, uint32_t height);
    void (*setHashAddr)(void *adrs, uint32_t hash);
    void (*setTreeIndex)(void *adrs, uint32_t index);
    uint32_t (*getTreeIndex)(const void *adrs);
    void (*copyKeyPairAddr)(void *dest, const void *src);
    uint32_t (*getAdrsLen)(void);
} HbsAdrsOps;

/**
 * @ingroup hbs
 * @brief Calculate a digest over multiple non-contiguous buffers.
 */
int32_t CalcMultiMsgHash(CRYPT_MD_AlgId mdId, const CRYPT_ConstData *hashData, uint32_t hashDataLen, uint8_t *out,
    uint32_t outLen);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_XMSSMT || HITLS_CRYPTO_SLH_DSA */
#endif /* HBS_HASH_IF_H */
