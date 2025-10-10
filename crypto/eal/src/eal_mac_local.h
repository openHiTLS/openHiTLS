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

#ifndef EAL_MAC_LOCAL_H
#define EAL_MAC_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MAC)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CRYPT_MAC_STATE_NEW = 0,
    CRYPT_MAC_STATE_INIT,
    CRYPT_MAC_STATE_UPDATE,
    CRYPT_MAC_STATE_FINAL
} CRYPT_MAC_WORKSTATE;

struct EAL_MacCtx {
    EAL_MacMethod macMeth;
    void *ctx;  // MAC context
    CRYPT_MAC_AlgId id;
    CRYPT_MAC_WORKSTATE state;
};

/**
 * @ingroup eal
 * @brief Find the default MAC method by the algorithm ID.
 *
 * @param id The algorithm ID.
 *
 * @return The MAC method.
 */
const EAL_MacMethod *EAL_MacFindDefaultMethod(CRYPT_MAC_AlgId id);

/**
 * @ingroup eal
 * @brief Find MAC algorithm implementation method by algorithm ID
 *
 * This function retrieves the default implementation method for specified MAC algorithm ID.
 * If the input method pointer is NULL, will allocate new memory for method structure. Otherwise,
 * will initialize the provided method structure.
 *
 * @param id        [IN] MAC algorithm identifier (e.g. CRYPT_MAC_HMAC, CRYPT_MAC_CMAC)
 * @param method    [IN/OUT] Pointer to method structure.
 *                  If NULL, function will allocate new memory. Caller must free returned pointer when no longer needed.
 *                  If not NULL, the method should be cleared before calling this function.
 *
 * @return Pointer to MAC method structure on success. NULL on failure (invalid ID or allocate fail).
 *         Note: When input method is NULL, returned pointer MUST be freed by caller.
 *               When input method is not NULL, returns the same pointer with initialized contents.
 */
EAL_MacMethod *EAL_MacFindMethod(CRYPT_MAC_AlgId id, EAL_MacMethod *method);

/**
 * @ingroup eal
 * @brief Find MAC algorithm implementation method by algorithm ID with provider context
 *
 * This function retrieves the default implementation method for specified MAC algorithm ID.
 * If the input method pointer is NULL, will allocate new memory for method structure. Otherwise,
 * will initialize the provided method structure.
 *
 * @param id        [IN] MAC algorithm identifier (e.g. CRYPT_MAC_HMAC, CRYPT_MAC_CMAC)
 * @param libCtx    [IN] The library context.
 * @param attrName  [IN] The attribute name.
 * @param method    [IN/OUT] Pointer to method structure.
 *                  If NULL, function will allocate new memory. Caller must free returned pointer when no longer needed.
 *                  If not NULL, the method should be cleared before calling this function.
 * @param provCtx   [OUT] The provider context.
 *
 * @return Pointer to MAC method structure on success. NULL on failure (invalid ID or alloc fail).
 *         Note: When input method is NULL, returned pointer MUST be freed by caller.
 *               When input method is not NULL, returns the same pointer with initialized contents.
 */
EAL_MacMethod *EAL_MacFindMethodEx(CRYPT_MAC_AlgId id, void *libCtx, const char *attrName, EAL_MacMethod *method,
    void **provCtx);

/**
 * @ingroup eal
 * @brief Find dependent algorithm methods for MAC calculation
 *
 * @param macId     [IN]  MAC algorithm identifier
 * @param libCtx    [IN]  Library context (for provider operations)
 * @param attrName  [IN]  Attribute name for provider selection
 * @param depMeth   [OUT] Structure containing dependent methods and algorithm IDs
 * @param provCtx   [OUT] The provider context.
 * @param isProvider [IN] Whether to use the provider method.
 *
 * @return CRYPT_SUCCESS on success, error code on failure
 *
 * @note When macId is HMAC:
 *       - depMeth->method.md is NULL:
 *         - Function will allocate new EAL_MdMethod structure internally
 *         - Caller MUST free allocated method
 *       - depMeth->method.md is non-NULL:
 *         - Function will reuse existing method structure
 *         - Original contents will be overwritten
 */
int32_t EAL_MacFindDepMethod(CRYPT_MAC_AlgId macId, void *libCtx, const char *attrName, EAL_MacDepMethod *depMeth,
    void **provCtx, bool isProvider);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_MAC

#endif // EAL_MAC_LOCAL_H
