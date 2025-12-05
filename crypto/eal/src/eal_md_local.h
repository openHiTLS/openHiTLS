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

#ifndef EAL_MD_LOCAL_H
#define EAL_MD_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MD)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CRYPT_MD_STATE_NEW = 0,
    CRYPT_MD_STATE_INIT,
    CRYPT_MD_STATE_UPDATE,
    CRYPT_MD_STATE_FINAL,
    CRYPT_MD_STATE_SQUEEZE
} CRYPT_MD_WORKSTATE;

struct EAL_MdCtx {
    EAL_MdMethod method;  /* algorithm operation entity */
    void *data;        /* Algorithm ctx, mainly context */
    uint32_t state;
    CRYPT_MD_AlgId id;
};

/**
 * @ingroup eal
 * @brief Find the default MD method by the algorithm ID.
 *
 * @param id The algorithm ID.
 *
 * @return The MD method.
 */
const EAL_MdMethod *EAL_MdFindDefaultMethod(CRYPT_MD_AlgId id);

/**
 * @ingroup eal
 * @brief Find Md algorithm implementation method by algorithm ID
 *
 * This function retrieves the default implementation method for specified MD algorithm ID.
 * If the input method pointer is NULL, will allocate new memory for method structure. Otherwise,
 * will initialize the provided method structure.
 *
 * @param id        [IN] MD algorithm identifier (e.g. CRYPT_MD_SHA256, CRYPT_MD_SHA384)
 * @param method    [IN/OUT] Pointer to method structure. 
 *                  If NULL, function will allocate new memory. Caller must free returned pointer when no longer needed.
 *                  If not NULL, the method should be cleared before calling this function.
 *
 * @return Pointer to MD method structure on success. NULL on failure (invalid ID or alloc fail).
 *         Note: When input method is NULL, returned pointer MUST be freed by caller.
 *               When input method is valid, returns the same pointer with initialized contents.
 */
EAL_MdMethod *EAL_MdFindMethod(CRYPT_MD_AlgId id, EAL_MdMethod *method);

/**
 * @ingroup eal
 * @brief Find Md algorithm implementation method by algorithm ID with provider context
 *
 * This function retrieves the default implementation method for specified MD algorithm ID.
 * If the input method pointer is NULL, will allocate new memory for method structure. Otherwise,
 * will initialize the provided method structure.
 *
 * @param id        [IN] MD algorithm identifier (e.g. CRYPT_MD_SHA256, CRYPT_MD_SHA384)
 * @param libCtx    [IN] The library context.
 * @param attrName  [IN] The attribute name.
 * @param method    [IN/OUT] Pointer to method structure.
 *                  If NULL, function will allocate new memory. Caller must free returned pointer when no longer needed.
 *                  If not NULL, the method should be cleared before calling this function.
 * @param provCtx   [OUT] The provider context.
 * @param isProvider [IN] Whether to find method from provider
 *
 * @return Pointer to MD method structure on success. NULL on failure (invalid ID or alloc fail).
 *         Note: When input method is NULL, returned pointer MUST be freed by caller.
 *               When input method is valid, returns the same pointer with initialized contents.
 */
EAL_MdMethod *EAL_MdFindMethodEx(CRYPT_MD_AlgId id, void *libCtx, const char *attrName, EAL_MdMethod *method,
    void **provCtx, bool isProvider);

/**
 * @ingroup eal
 * @brief Calculate the hash value
 *
 * @param id [IN] Algorithm ID
 * @param libCtx [IN] Library context
 * @param attr [IN] Attribute
 * @param in [IN] Input data
 * @param inLen [IN] Input data length
 * @param out [OUT] Output data
 * @param outLen [OUT] Output data length
 * @param isProvider [IN] Whether to find method from provider
 *
 * @return #CRYPT_SUCCESS Success.
 * @return #CRYPT_EAL_ERR_ALGID Algorithm ID is invalid.
 */
int32_t EAL_Md(CRYPT_MD_AlgId id, void *libCtx, const char *attr, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen, bool checkSignId, bool isProvider);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_MD

#endif // EAL_MD_LOCAL_H
