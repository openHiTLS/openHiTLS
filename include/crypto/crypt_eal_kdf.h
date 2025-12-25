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

/**
 * @defgroup crypt_eal_kdf
 * @ingroup crypt
 * @brief kdf of crypto module
 */

#ifndef CRYPT_EAL_KDF_H
#define CRYPT_EAL_KDF_H

#include <stdbool.h>
#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct EalKdfCtx CRYPT_EAL_KdfCTX;

/**
 * @ingroup crypt_eal_kdf, Not supported in provider
 * @brief   Check whether the given kdf algorithm ID is valid.
 *
 * @param   id [IN] kdf algorithm ID.
 * @retval Valid, true is returned.
 *         Invalid, false is returned.
 */
bool CRYPT_EAL_KdfIsValidAlgId(CRYPT_KDF_AlgId id);

/**
 * @ingroup crypt_eal_kdf
 * @brief Generate kdf handles in the providers
 *
 * @param libCtx [IN] Library context
 * @param attrName [IN] Specify expected attribute values
 * @param algId [IN] kdf algorithm ID.
 * @retval Success: kdf ctx.
 *         Fails: NULL.
 */
CRYPT_EAL_KdfCTX *CRYPT_EAL_ProviderKdfNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName);

/**
 * @ingroup crypt_eal_kdf
 * @brief Generate kdf handles
 * @param algId [IN] kdf algorithm ID.
 * @retval Success: kdf ctx.
 *         Fails: NULL.
 */
CRYPT_EAL_KdfCTX *CRYPT_EAL_KdfNewCtx(CRYPT_KDF_AlgId algId);

/**
 * @ingroup crypt_eal_kdf
 * @brief Set the parameters of Algorithm kdf
 *
 * @param ctx [IN] kdf context
 * @param param [IN] parameters
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_KdfSetParam(CRYPT_EAL_KdfCTX *ctx, const BSL_Param *param);

 /**
 * @ingroup crypt_eal_kdf
 * @brief Derived key
 *
 * @param ctx [IN] kdf context
 * @param key [OUT] Derived key
 * @param keyLen [IN] Specify the key derivation length
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_KdfDerive(CRYPT_EAL_KdfCTX *ctx, uint8_t *key, uint32_t keyLen);

/**
 * @ingroup crypt_eal_kdf
 * @brief Deinitialize the context of kdf
 *
 * @param ctx [IN] kdf context
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_KdfDeInitCtx(CRYPT_EAL_KdfCTX *ctx);

 /**
 * @ingroup crypt_eal_kdf
 * @brief Free the context of kdf
 *
 * @param ctx [IN] kdf context
 *
 */
void CRYPT_EAL_KdfFreeCtx(CRYPT_EAL_KdfCTX *ctx);

 /**
 * @ingroup crypt_eal_kdf
 * @brief Copy the context of kdf
 * Note: When using HKDF for key derivation in CRYPT_KDF_HKDF_MODE_EXTRACT mode,
 * need set the new context's extended length use CRYPT_PARAM_KDF_EXLEN.
 * @param from [IN] kdf context
 * @param to [OUT] kdf context
 *
 */
int32_t CRYPT_EAL_KdfCopyCtx(CRYPT_EAL_KdfCTX *to, const CRYPT_EAL_KdfCTX *from);

/**
 * @ingroup crypt_eal_kdf
 * @brief   Dup the kdf context.
 *
 * @param   from [IN] original kdf context.
 * @retval  CRYPT_EAL_KdfCTX, kdf context pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_KdfCTX *CRYPT_EAL_KdfDupCtx(const CRYPT_EAL_KdfCTX *from);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_KDF_H