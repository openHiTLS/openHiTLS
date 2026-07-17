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
#ifdef HITLS_CRYPTO_HSS_LMS

#include <stdint.h>
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

/* HSS private key length (fixed, independent of hash output size):
 *   counter(8) + compressed_params(8) + seed(32) = 48 */
#define HSS_PRVKEY_LEN 48

/* HSS public key offsets */
#define HSS_PUBKEY_LEVELS_OFFSET   0 // Number of levels (4 bytes, big-endian)
#define HSS_PUBKEY_LMS_TYPE_OFFSET 4 // Top-level LMS type (4 bytes, big-endian)
#define HSS_PUBKEY_OTS_TYPE_OFFSET 8 // Top-level OTS type (4 bytes, big-endian)
#define HSS_PUBKEY_ROOT_OFFSET     28 // Top-level root hash (32 bytes)

/* HSS signature offsets */
#define HSS_SIG_NSPK_LEN    4

/**
 * @ingroup hss
 * @brief HSS parameter structure
 */
typedef struct HssPara {
    uint32_t levels; /**< Number of HSS levels (1-3) */
    uint32_t lmsType[HSS_LEVELS_ARRAY_SIZE]; /**< LMS type for each level */
    uint32_t otsType[HSS_LEVELS_ARRAY_SIZE]; /**< OTS type for each level */

    /* Computed parameters */
    uint32_t pubKeyLen; /**< Public key length (always 60) */
    uint32_t prvKeyLen; /**< Private key length (always 48) */
    uint32_t sigLen; /**< Maximum signature length */
    uint64_t maxSignatures; /**< Total signature capacity */

    /* Per-level LMS parameters (populated from LMS parameter lookup) */
    LMS_Para levelPara[HSS_LEVELS_ARRAY_SIZE]; /**< LMS parameters for each level */
} HSS_Para;

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* HSS_PARAMS_H */
