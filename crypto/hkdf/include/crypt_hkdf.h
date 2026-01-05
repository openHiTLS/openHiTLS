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

#ifndef CRYPT_HKDF_H
#define CRYPT_HKDF_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HKDF

#include <stdint.h>
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct CryptHkdfCtx CRYPT_HKDF_Ctx;

/**
 * @ingroup HKDF
 * @brief Generate HKDF context.
 *
 * @retval Success: cipher ctx.
 *         Fails: NULL.
 */
CRYPT_HKDF_Ctx* CRYPT_HKDF_NewCtx(void);

/**
 * @ingroup HKDF
 * @brief Set parameters for the HKDF context.
 *
 * @param ctx   [in, out] Pointer to the HKDF context.
 * @param param [in] Either a MAC algorithm ID, a salt, a password, or an iteration count.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_HKDF_SetParam(CRYPT_HKDF_Ctx *ctx, const BSL_Param *param);

/**
 * @ingroup HKDF
 * @brief Obtain the derived key based on the passed HKDF context..
 *
 * @param ctx   [in, out] Pointer to the HKDF context.
 * @param out   [out] Derived key buffer.
 * @param out   [out] Derived key buffer size.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_HKDF_Derive(CRYPT_HKDF_Ctx *ctx, uint8_t *out, uint32_t len);

/**
 * @ingroup HKDF
 * @brief HKDF deinitialization API
 *
 * @param ctx [in, out]   Pointer to the HKDF context.
 *
 * @retval #CRYPT_SUCCESS       Deinitialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_HKDF_Deinit(CRYPT_HKDF_Ctx *ctx);

/**
 * @ingroup HKDF
 * @brief free HKDF context.
 *
 * @param ctx [IN] HKDF handle
 */
void CRYPT_HKDF_FreeCtx(CRYPT_HKDF_Ctx *ctx);

/**
 * @ingroup HKDF
 * @brief Copy HKDF context.
 *
 * @param ctx [IN] HKDF handle.
 * @retval New HKDF handle.
 */
CRYPT_HKDF_Ctx *CRYPT_HKDF_DupCtx(const CRYPT_HKDF_Ctx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_HKDF

#endif // CRYPT_HKDF_H
