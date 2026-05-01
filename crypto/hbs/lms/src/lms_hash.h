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

#ifndef LMS_HASH_H
#define LMS_HASH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS

#include <stdint.h>
#include <stddef.h>
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct LmsPara LMS_Para;
typedef struct LmsOtsCtx LmsOtsCtx;
typedef struct LmsTreeCtx LmsTreeCtx;

/**
 * @ingroup lms
 * @brief LMS Hash Function Table (aligned with XMSS/SLH-DSA design)
 *
 * This design follows the XMSS/SLH-DSA pattern where hash functions receive
 * context parameters, allowing domain separation logic to be encapsulated
 * within the hash functions rather than requiring callers to manually
 * construct input buffers.
 *
 * Benefits of this approach:
 * - Reduces boilerplate code at call sites
 * - Encapsulates domain separation logic
 * - Improves type safety
 * - Easier to extend with new hash algorithms
 */
typedef struct LmsFamilyHashFuncs {
    int32_t (*skDerive)(const LmsOtsCtx *ctx, uint8_t *out);
    int32_t (*chainHash)(const LmsOtsCtx *ctx, uint32_t k, uint32_t j, const uint8_t *prev, uint8_t *out);
    int32_t (*leafHash)(const LmsTreeCtx *ctx, uint32_t r, const uint8_t *otsPubKey, uint8_t *out);
    int32_t (*nodeHash)(const LmsTreeCtx *ctx, uint32_t r, const uint8_t *left, const uint8_t *right, uint8_t *out);
    int32_t (*msgHash)(const LmsTreeCtx *ctx, uint32_t q, const uint8_t *C, const uint8_t *msg, uint32_t msgLen,
                       uint8_t *out);
    int32_t (*pkCompress)(const LmsOtsCtx *ctx, const uint8_t *chains, uint8_t *out);
} LmsFamilyHashFuncs;

/* NOTE: LmsHashFuncs alias removed. Use LmsFamilyHashFuncs directly. */

/**
 * @ingroup lms
 * @brief Get hash functions for a given LMS algorithm type.
 *
 * @param lmsType [IN] LMS algorithm type
 * @return Pointer to hash function table
 */
const LmsFamilyHashFuncs *LmsGetHashFuncs(uint32_t lmsType);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_LMS */
#endif /* LMS_HASH_H */
