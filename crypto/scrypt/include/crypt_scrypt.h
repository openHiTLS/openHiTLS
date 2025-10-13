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

#ifndef CRYPT_SCRYPT_H
#define CRYPT_SCRYPT_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SCRYPT

#include <stdint.h>
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct CryptScryptCtx CRYPT_SCRYPT_Ctx;

typedef int32_t (*PBKDF2_PRF)(void *libCtx, const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId,
    const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen,
    uint32_t iterCnt, uint8_t *out, uint32_t len);

#define CRYPT_SCRYPT_Ctrl NULL

/**
 * @ingroup  SCRYPT
 * @brief Generate SCRYPT context.
 *
 * @retval Success: SCRYPT ctx.
 *         Fails: NULL.
 */
CRYPT_SCRYPT_Ctx *CRYPT_SCRYPT_NewCtx(void);

/**
 * @ingroup  SCRYPT
 * @brief Generate SCRYPT context.
 *
 * @param libCtx [in] Library context.
 * @param algId [in] algorithm id
 *
 * @retval Success: SCRYPT ctx.
 *         Fails: NULL.
 */
CRYPT_SCRYPT_Ctx *CRYPT_SCRYPT_NewCtxEx(void *libCtx, int32_t algId);

/**
 * @ingroup SCRYPT
 * @brief Set parameters for the SCRYPT context.
 *
 * @param ctx   [in, out] Pointer to the SCRYPT context.
 * @param param [in] Either a MAC algorithm ID, a seed, a password, or a label.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SCRYPT_SetParam(CRYPT_SCRYPT_Ctx *ctx, const BSL_Param *param);

/**
 * @ingroup SCRYPT
 * @brief Obtain the derived key based on the passed SCRYPT context..
 *
 * @param ctx   [in, out] Pointer to the SCRYPT context.
 * @param out   [out] Derived key buffer.
 * @param len   [in] Derived key buffer size.
 *
 * @retval Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SCRYPT_Derive(CRYPT_SCRYPT_Ctx *ctx, uint8_t *out, uint32_t len);

/**
 * @ingroup SCRYPT
 * @brief SCRYPT deinitialization API
 *
 * @param ctx [in, out]   Pointer to the SCRYPT context.
 *
 * @retval #CRYPT_SUCCESS       Deinitialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SCRYPT_Deinit(CRYPT_SCRYPT_Ctx *ctx);

/**
 * @ingroup SCRYPT
 * @brief free SCRYPT context.
 *
 * @param ctx [IN] SCRYPT handle
 */
void CRYPT_SCRYPT_FreeCtx(CRYPT_SCRYPT_Ctx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_SCRYPT

#endif // CRYPT_SCRYPT_H
