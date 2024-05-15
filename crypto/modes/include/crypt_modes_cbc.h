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

#ifndef CRYPT_MODES_CBC_H
#define CRYPT_MODES_CBC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CBC

#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief CBC mode encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_CBC_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief CBC mode decryption
 *
 * @param ctx [IN]  mode handle
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_CBC_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_AES
/**
 * @brief AES CBC mode encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t AES_CBC_EncryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief AES CBC mode decryption
 *
 * @param ctx [IN]  mode handle
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t AES_CBC_DecryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

/**
 * @brief Clear the content in CBC mode, delete sensitive data. Preserve the memory and methods of algorithm modules
 *
 * @param ctx [IN] mode handle
 * @return none
 */
void MODE_CBC_Clean(MODE_CipherCtx *ctx);

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief SM4-CBC mode encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_CBC_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4-CBC mode decryption
 *
 * @param ctx [IN]  mode handle
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_CBC_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CBC

#endif // CRYPT_MODES_CBC_H
