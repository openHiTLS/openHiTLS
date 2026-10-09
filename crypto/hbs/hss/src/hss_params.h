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

/* HSS hierarchy constraints: private keys support 3 levels; verification supports 8. */
#define HSS_LEVELS_ARRAY_SIZE 8 /* Internal array dimension */
#define HSS_MAX_LEVELS        3 /* Private-key serialization limit */
#define HSS_MAX_VERIFY_LEVELS HSS_LEVELS_ARRAY_SIZE /* RFC 8554 verification limit */
#define HSS_MIN_LEVELS        1 /* Minimum hierarchy levels (1 = equivalent to LMS) */

/* HSS private key length (fixed, independent of hash output size):
 *   counter(8) + compressed_params(8) + seed(32) = 48 */
#define HSS_PRVKEY_LEN 48

/* HSS signature offsets */
#define HSS_SIG_NSPK_LEN    4

/**
 * @ingroup hss
 * @brief HSS parameter structure
 */
typedef struct HssPara {
    uint32_t levels; /**< Number of HSS levels */
    uint32_t lmsType[HSS_LEVELS_ARRAY_SIZE]; /**< LMS type for each level */
    uint32_t otsType[HSS_LEVELS_ARRAY_SIZE]; /**< OTS type for each level */

    /* Computed parameters */
    uint32_t pubKeyLen; /**< Top-level LMS public key length */
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
