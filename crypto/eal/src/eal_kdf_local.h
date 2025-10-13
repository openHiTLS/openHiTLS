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

#ifndef EAL_KDF_LOCAL_H
#define EAL_KDF_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_KDF)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct EalKdfCtx {
    EAL_KdfMethod method;  /* algorithm operation entity */
    void *data;
    CRYPT_KDF_AlgId id;
};

/**
 * @brief Find the method by the id
 *
 * @param id [IN] The algorithm id
 * @param method [OUT] The method pointer
 *
 * @return CRYPT_SUCCESS The method is found
 * @return CRYPT_NULL_INPUT The method pointer is NULL
 * @return CRYPT_EAL_ERR_ALGID The algorithm id is not found
 */
int32_t EAL_KdfFindMethod(CRYPT_KDF_AlgId id, EAL_KdfMethod *method);

/**
 * @brief Find the method by the id
 *
 * @param id [IN] The algorithm id
 * @param libCtx [IN] The library context
 * @param attrName [IN] The attribute name
 * @param method [OUT] The method pointer
 * @param provCtx [OUT] The provider context
 *
 * @return CRYPT_SUCCESS The method is found
 * @return CRYPT_NULL_INPUT The method pointer is NULL
 * @return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL The unexpected implementation is found
 */
int32_t EAL_ProviderKdfFindMethod(CRYPT_KDF_AlgId id, void *libCtx, const char *attrName, EAL_KdfMethod *method,
    void **provCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_KDF

#endif // EAL_KDF_LOCAL_H
