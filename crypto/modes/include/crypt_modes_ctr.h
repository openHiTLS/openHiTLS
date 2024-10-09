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

#ifndef CRYPT_MODES_CTR_H
#define CRYPT_MODES_CTR_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CTR

#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief CTR mode encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 * Other error codes are returned if the operation fails.
 */
int32_t MODE_CTR_Crypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_AES
/**
 * @brief CTR mode encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 * Other error codes are returned if the operation fails.
 */
int32_t AES_CTR_EncryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief CTR mode decryption
 *
 * @param ctx [IN] mode handle
 * @param in [IN]  Data to be decrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 * Other error codes are returned if the operation fails.
 */
int32_t AES_CTR_DecryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

/**
 * @brief Clear the content in CTR mode, delete sensitive data. Preserve the memory and methods of algorithm modules
 *
 * @param ctx [IN] mode handle
 * @return none
 */
void MODE_CTR_Clean(MODE_CipherCtx *ctx);

/**
 * @brief Process the case that the number of bytes is less than 16 in CTR mode.
 *
 */
uint32_t MODE_CTR_LastHandle(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief Process the CTR mode tail.
 *
 */
void MODE_CTR_RemHandle(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief SM4-CTR mode encryption
 *
 * @param [IN] ctx mode handle
 * @param [IN] in  Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_CTR_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4-CTR mode decryption
 *
 * @param ctx [IN] mode handle
 * @param in [IN]  Data to be decrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_CTR_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CTR

#endif // CRYPT_MODES_CTR_H
