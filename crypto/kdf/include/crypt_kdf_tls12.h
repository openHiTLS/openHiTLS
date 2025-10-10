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

#ifndef CRYPT_KDF_TLS12_H
#define CRYPT_KDF_TLS12_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_KDFTLS12

#include <stdint.h>
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct CryptKdfTls12Ctx CRYPT_KDFTLS12_Ctx;

/**
 * @ingroup  KDFTLS12
 * @brief Generate KDFTLS12 context.
 *
 * @retval Success: KDFTLS12 ctx.
 *         Fails: NULL.
 */
CRYPT_KDFTLS12_Ctx* CRYPT_KDFTLS12_NewCtx(void);

/**
 * @ingroup KDFTLS12
 * @brief Generate KDFTLS12 context.
 *
 * @param libCtx [in] Library context.
 * @param algId [in] algorithm id
 *
 * @retval Success: KDFTLS12 ctx.
 *         Fails: NULL.
 */
CRYPT_KDFTLS12_Ctx *CRYPT_KDFTLS12_NewCtxEx(void *libCtx, int32_t algId);

/**
 * @ingroup KDFTLS12
 * @brief Set parameters for the KDFTLS12 context.
 *
 * @param ctx   [in, out] Pointer to the KDFTLS12 context.
 * @param param [in] Either a MAC algorithm ID, a seed, a password, or a label.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_KDFTLS12_SetParam(CRYPT_KDFTLS12_Ctx *ctx, const BSL_Param *param);

/**
 * @ingroup KDFTLS12
 * @brief Obtain the derived key based on the passed KDFTLS12 context..
 *
 * @param ctx   [in, out] Pointer to the KDFTLS12 context.
 * @param out   [out] Derived key buffer.
 * @param len   [out] Derived key buffer size.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_KDFTLS12_Derive(CRYPT_KDFTLS12_Ctx *ctx, uint8_t *out, uint32_t len);

/**
 * @ingroup KDFTLS12
 * @brief KDFTLS12 deinitialization API
 *
 * @param ctx [in, out]   Pointer to the KDFTLS12 context.
 *
 * @retval #CRYPT_SUCCESS       Deinitialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_KDFTLS12_Deinit(CRYPT_KDFTLS12_Ctx *ctx);

/**
 * @ingroup KDFTLS12
 * @brief free KDFTLS12 context.
 *
 * @param ctx [IN] KDFTLS12 handle
 */
void CRYPT_KDFTLS12_FreeCtx(CRYPT_KDFTLS12_Ctx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_KDFTLS12

#endif // CRYPT_KDF_TLS12_H
