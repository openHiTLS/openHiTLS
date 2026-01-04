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

#ifndef CRYPT_PBKDF2_H
#define CRYPT_PBKDF2_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PBKDF2

#include <stdint.h>
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct CryptPbkdf2Ctx CRYPT_PBKDF2_Ctx;

/**
 * @ingroup PBKDF2
 * @brief Generate PBKDF2 context.
 *
 * @retval Success: PBKDF2 ctx.
 *         Fails: NULL.
 */
CRYPT_PBKDF2_Ctx* CRYPT_PBKDF2_NewCtx(void);

/**
 * @ingroup PBKDF2
 * @brief Generate PBKDF2 context.
 *
 * @param libCtx [in] Library context.
 * @param algId [in] algorithm id
 *
 * @retval Success: PBKDF2 ctx.
 *         Fails: NULL.
 */
CRYPT_PBKDF2_Ctx *CRYPT_PBKDF2_NewCtxEx(void *libCtx, int32_t algId);

/**
 * @ingroup PBKDF2
 * @brief Set parameters for the PBKDF2 context.
 *
 * @param ctx   [in, out] Pointer to the PBKDF2 context.
 * @param param [in] Either a MAC algorithm ID, a salt, a password, or an iteration count.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_PBKDF2_SetParam(CRYPT_PBKDF2_Ctx *ctx, const BSL_Param *param);

/**
 * @ingroup PBKDF2
 * @brief Obtain the derived key based on the passed PBKDF2 context..
 *
 * @param ctx   [in, out] Pointer to the PBKDF2 context.
 * @param out   [out] Derived key buffer.
 * @param out   [out] Derived key buffer size.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_PBKDF2_Derive(CRYPT_PBKDF2_Ctx *ctx, uint8_t *out, uint32_t len);

/**
 * @ingroup PBKDF2
 * @brief PBKDF2 deinitialization API
 *
 * @param ctx [in, out]   Pointer to the PBKDF2 context.
 *
 * @retval #CRYPT_SUCCESS       Deinitialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_PBKDF2_Deinit(CRYPT_PBKDF2_Ctx *ctx);

/**
 * @ingroup PBKDF2
 * @brief free PBKDF2 context.
 *
 * @param ctx [IN] PBKDF2 handle
 */
void CRYPT_PBKDF2_FreeCtx(CRYPT_PBKDF2_Ctx *ctx);

/**
 * @ingroup PBKDF2
 * @brief Copy PBKDF2 context.
 *
 * @param ctx [IN] PBKDF2 handle.
 * @retval New PBKDF2 handle.
 */
CRYPT_PBKDF2_Ctx *CRYPT_PBKDF2_DupCtx(const CRYPT_PBKDF2_Ctx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_PBKDF2

#endif // CRYPT_PBKDF2_H
