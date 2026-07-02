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

#ifndef HSS_LOCAL_H
#define HSS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HSS_LMS

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "crypt_hss.h"
#include "lms_internal.h"
#include "hss_params.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HSS_PRVKEY_LEN is defined in hss_params.h, included above. */

/**
 * @ingroup hss
 * @brief HSS context structure
 */
struct HssCtx {
    HSS_Para para; /**< HSS parameters (embedded, not heap-allocated) */
    uint8_t *publicKey; /**< HSS public key buffer */
    uint8_t *privateKey; /**< HSS private key buffer */
    uint32_t publicLen; /**< Actual allocated length of publicKey buffer */
    uint64_t signatureIndex; /**< Current signature index (cached from private key) */
    void *libCtx; /**< Library context */
    uint8_t *cachedTrees[HSS_LEVELS_ARRAY_SIZE]; /**< Cached Merkle trees for each level */
    uint32_t cachedTreeSizes[HSS_LEVELS_ARRAY_SIZE]; /**< Sizes of cached trees */
    bool treeCacheValid[HSS_LEVELS_ARRAY_SIZE]; /**< Cache validity flags for each level */
    uint64_t cachedTreeIndex[HSS_LEVELS_ARRAY_SIZE]; /**< Tree index each cache was built for */
};

/**
 * @ingroup hss
 * @brief Initialize HSS parameter structure
 * @param para     [OUT] Parameter structure to initialize
 * @param levels   [IN]  Number of hierarchy levels (1-8)
 * @param lmsTypes [IN]  Array of LMS types for each level
 * @param otsTypes [IN]  Array of OTS types for each level
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssParaInit(HSS_Para *para, uint32_t levels, const uint32_t *lmsTypes, const uint32_t *otsTypes);

/**
 * @ingroup hss
 * @brief Get HSS signature length
 * @param para [IN] HSS parameters
 * @return Signature length in bytes
 */
uint32_t HssGetSignatureLen(const HSS_Para *para);

/**
 * @ingroup hss
 * @brief Get maximum signature capacity
 * @param para [IN] HSS parameters
 * @return Maximum number of signatures
 */
uint64_t HssGetMaxSignatures(const HSS_Para *para);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */

#endif /* HSS_LOCAL_H */
