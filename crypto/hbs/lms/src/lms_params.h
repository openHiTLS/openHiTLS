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

#ifndef LMS_PARAMS_H
#define LMS_PARAMS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HSS_LMS

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lms_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* LMS Constants and Definitions */

#define LMS_SHA256_N         32 // SHA-256 hash output length in bytes
#define LMS_I_LEN            16 // Merkle tree identifier length
#define LMS_SEED_LEN         32 // Seed length
#define LMS_MAX_HASH         32 // Maximum hash length supported
#define LMS_MIN_HEIGHT       5 // Minimum Merkle tree height
#define LMS_MAX_HEIGHT       25 // Maximum Merkle tree height
#define LMS_MAX_MESSAGE_SIZE (16 * 1024 * 1024) // Maximum message size (16MB) to prevent DoS

/* Hash domain separation constants (RFC 8554) */
#define LMS_D_PBLC 0x8080 // OTS public key hash
#define LMS_D_MESG 0x8181 // Message hash
#define LMS_D_LEAF 0x8282 // Leaf node hash
#define LMS_D_INTR 0x8383 // Internal node hash

/**
 * @ingroup lms
 * @brief Hash type identifier used in the LMS_Para.h field and LmOtsParams.
 *
 * A new hash algorithm first appears as a new LMS or OTS type code;
 * the lmsType value alone is sufficient to dispatch to the correct
 * LmsFamilyHashFuncs table (see LmsGetHashFuncs).
 */
#define LMS_HASH_SHA256 1 /**< SHA-256 (RFC 8554 original parameter sets) */

/**
 * @ingroup lms
 * @brief LMS parameter structure
 *
 * Populated by LmsParaInit, which reads n / height / w / p / ls from
 * the LMS and OTS type-code lookups and copies the correct
 * LmsFamilyHashFuncs table corresponding to the lmsType.
 */
typedef struct LmsPara {
    uint32_t lmsType; /**< LMS parameter set identifier */
    uint32_t otsType; /**< LM-OTS parameter set identifier */
    uint32_t h; /**< Hash type (LMS_HASH_SHA256, …) */
    uint32_t n; /**< Hash output length in bytes (e.g. 32 for SHA-256) */
    uint32_t height; /**< Merkle tree height */
    uint32_t w; /**< Winternitz parameter */
    uint32_t p; /**< Number of n-byte string elements in OTS signature */
    uint32_t ls; /**< Checksum left shift */
    uint32_t pubKeyLen; /**< Public key length (24 + n bytes) */
    uint32_t prvKeyLen; /**< Private key length (32 + LMS_SEED_LEN) */
    uint32_t sigLen; /**< Signature length */
    LmsFamilyHashFuncs hashFuncs; /**< Hash function pointers for this lmsType */
} LMS_Para;

/**
 * @ingroup lms
 * @brief Look up LMS parameter set.
 *
 * @param paramSet [IN]  Parameter set identifier
 * @param h        [OUT] Hash type
 * @param n        [OUT] Hash output length
 * @param height   [OUT] Tree height
 * @return CRYPT_SUCCESS if parameter set is valid, error code otherwise
 */
int32_t LmsLookupParamSet(uint32_t paramSet, uint32_t *h, uint32_t *n, uint32_t *height);

/**
 * @ingroup lms
 * @brief LM-OTS parameter output structure
 */
typedef struct {
    uint32_t h; /**< Hash type */
    uint32_t n; /**< Hash output length */
    uint32_t w; /**< Winternitz parameter */
    uint32_t p; /**< Number of n-byte strings */
    uint32_t ls; /**< Checksum left shift */
} LmOtsParams;

/**
 * @ingroup lms
 * @brief Look up LM-OTS parameter set.
 *
 * @param paramSet [IN]  Parameter set identifier
 * @param params   [OUT] Output parameters structure
 * @return CRYPT_SUCCESS if parameter set is valid, error code otherwise
 */
int32_t LmOtsLookupParamSet(uint32_t paramSet, LmOtsParams *params);

/**
 * @ingroup lms
 * @brief Initialize LMS parameters structure.
 *
 * @param para    [OUT] Parameter structure to initialize
 * @param lmsType [IN]  LMS parameter set
 * @param otsType [IN]  LM-OTS parameter set
 * @return 0 on success, error code on failure
 */
int32_t LmsParaInit(LMS_Para *para, uint32_t lmsType, uint32_t otsType);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* LMS_PARAMS_H */
