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

#ifndef HSS_PARAMS_H
#define HSS_PARAMS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HSS

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lms_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HSS Constants and Definitions */

/* HSS hierarchy constraints */
/* HSS_MAX_LEVELS is the maximum number of levels that the serialized private-key
 * format (and all public API entry points) actually support.  It matches the
 * compressed-parameter encoding limit so that callers never encounter a value
 * that is accepted by the parameter-setting interface but rejected later.
 *
 * HSS_LEVELS_ARRAY_SIZE is used exclusively for compile-time array sizing.
 * It is kept at 8 (the RFC 8554 theoretical maximum) so that internal buffers
 * are large enough if the limit is ever raised without requiring a struct-layout
 * change.  It must NOT be used as a runtime upper-bound in API validation.
 */
#define HSS_LEVELS_ARRAY_SIZE 8 /* Internal array dimension — do NOT use for API validation */
#define HSS_MAX_LEVELS        3 /* Maximum externally-supported levels (serialization limit) */
#define HSS_MIN_LEVELS        1 /* Minimum hierarchy levels (1 = equivalent to LMS) */

/* HSS key lengths (fixed) */
#define HSS_PRVKEY_LEN 48 // Private key: counter(8) + params(8) + seed(32)
#define HSS_PUBKEY_LEN 60 // Public key: levels(4) + lms_type(4) + ots_type(4) + I(16) + root(32)

/* HSS private key offsets */
#define HSS_PRVKEY_COUNTER_OFFSET 0 // Signature counter (8 bytes, big-endian)
#define HSS_PRVKEY_COUNTER_LEN    8
#define HSS_PRVKEY_PARAMS_OFFSET  8 // Compressed parameter set (8 bytes)
#define HSS_PRVKEY_PARAMS_LEN     8
#define HSS_PRVKEY_SEED_OFFSET    16 // Master seed (32 bytes)
#define HSS_PRVKEY_SEED_LEN       32

/* HSS public key offsets */
#define HSS_PUBKEY_LEVELS_OFFSET   0 // Number of levels (4 bytes, big-endian)
#define HSS_PUBKEY_LMS_TYPE_OFFSET 4 // Top-level LMS type (4 bytes, big-endian)
#define HSS_PUBKEY_OTS_TYPE_OFFSET 8 // Top-level OTS type (4 bytes, big-endian)
#define HSS_PUBKEY_I_OFFSET        12 // Top-level I value (16 bytes)
#define HSS_PUBKEY_ROOT_OFFSET     28 // Top-level root hash (32 bytes)

/* HSS signature offsets */
#define HSS_SIG_NSPK_OFFSET 0 // Number of signed public keys (4 bytes)
#define HSS_SIG_NSPK_LEN    4
#define HSS_SIG_DATA_OFFSET 4 // Start of signature data

/* Seed derivation domain separators */
#define HSS_SEED_ROOT_I       0x00 // Root tree I derivation
#define HSS_SEED_ROOT_SEED    0x01 // Root tree seed derivation
#define HSS_SEED_CHILD_SUFFIX 0x01 // Child seed derivation suffix

/* Compressed parameter set size */
#define HSS_COMPRESSED_PARAMS_LEN 8 // Compressed parameter set length (8 bytes)
#define HSS_MAX_COMPRESSED_LEVELS 3 // Maximum levels that fit in compressed format

/* Seed derivation buffer sizes (RFC 8554) */
#define HSS_ROOT_SEED_DERIVE_BUF_LEN  34 // masterSeed(32) + domain(1) + padding(1)
#define HSS_CHILD_SEED_DERIVE_BUF_LEN 60 // parentSeed(32) + parentI(16) + treeIndex(8) + level(4)
#define HSS_CHILD_SEED_SUFFIX_BUF_LEN 61 // CHILD_SEED_DERIVE_BUF_LEN + suffix(1)

/* Parameter compression field sizes */
#define HSS_COMPRESSED_LEVEL_FIELD_SIZE 1 // Levels field size in compressed format
#define HSS_COMPRESSED_PARAM_PAIR_SIZE  2 // Size of (lms_type, ots_type) pair in compressed format

/**
 * @ingroup hss
 * @brief HSS parameter structure
 */
typedef struct HssPara {
    uint32_t levels; /**< Number of HSS levels (1-3) */
    uint32_t lmsType[HSS_LEVELS_ARRAY_SIZE]; /**< LMS type for each level */
    uint32_t otsType[HSS_LEVELS_ARRAY_SIZE]; /**< OTS type for each level */

    /* Computed parameters */
    size_t pubKeyLen; /**< Public key length (always 60) */
    size_t prvKeyLen; /**< Private key length (always 48) */
    size_t sigLen; /**< Maximum signature length */
    uint64_t maxSignatures; /**< Total signature capacity */

    /* Per-level LMS parameters (populated from LMS parameter lookup) */
    LMS_Para levelPara[HSS_LEVELS_ARRAY_SIZE]; /**< LMS parameters for each level */
} HSS_Para;

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS */
#endif /* HSS_PARAMS_H */
