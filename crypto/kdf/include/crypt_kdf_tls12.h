/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_KDF_TLS12_H
#define CRYPT_KDF_TLS12_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_KDFTLS12

#include <stdint.h>
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct CryptKdfTls12Ctx CRYPT_KDFTLS12_Ctx;

/**
 * @brief   KDF-TLS1.2
 *
 * @param macMeth [IN] Pointer to the HMAC algorithm method
 * @param mdMeth [IN] Pointer to the MD algorithm method
 * @param key [IN] Key, byte array entered by the user.
 * @param keyLen [IN] Key length, any length
 * @param label [IN] Label, byte array entered by the user. Combined with the seed as the PRF input data.
 * @param labelLen [IN] Label length, any length
 * @param seed [IN] Seed, byte array entered by a user, used as the PRF input data.
 * @param seedLen [IN] Seed length, any length
 * @param out [OUT] Derive key.
 * @param outLen [IN] Length of the derived key. The value range is [1, 0xFFFFFFFF].
 *
 * @return If the operation is successful, the CRYPT_SUCCESS is returned.
 * For other error codes, see the crypt_errno.h.
 */
int32_t CRYPT_KDF_TLS12(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *label, uint32_t labelLen, const uint8_t *seed, uint32_t seedLen, uint8_t *out, uint32_t len);

/**
 * @ingroup  KDFTLS12
 * @brief Generate KDFTLS12 context.
 *
 * @retval Success: cipher ctx.
 *         Fails: NULL.
 */
CRYPT_KDFTLS12_Ctx* CRYPT_KDFTLS12_NewCtx(void);

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
int32_t CRYPT_KDFTLS12_SetParam(CRYPT_KDFTLS12_Ctx *ctx, const CRYPT_Param *param);

/**
 * @ingroup KDFTLS12
 * @brief Obtain the derived key based on the passed KDFTLS12 context..
 *
 * @param ctx   [in, out] Pointer to the KDFTLS12 context.
 * @param out   [out] Derived key buffer.
 * @param out   [out] Derived key buffer size.
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
