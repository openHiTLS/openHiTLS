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

#ifndef CRYPT_MODES_OFB_H
#define CRYPT_MODES_OFB_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_OFB

#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief OFB mode encryption/decryption. Any byte length can be encrypted/decrypted.
 *
 * @param [IN] ctx  Context of ofb mode encryption
 * @param [IN] in   Data to be encrypted/decrypted
 * @param [OUT] out Encrypted/decrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_OFB_Crypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief SM4-OFB mode encryption
 *
 * @param [IN] ctx  Context of ofb mode encryption
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_OFB_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4-OFB mode decryption
 *
 * @param ctx [IN]  Context of ofb mode encryption
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_OFB_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_OFB

#endif // CRYPT_MODES_OFB_H
