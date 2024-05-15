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

#ifndef CRYPT_MODES_ECB_H
#define CRYPT_MODES_ECB_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECB

#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief ECB mode encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_ECB_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief ECB mode decryption
 *
 * @param ctx [IN]  mode handle
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_ECB_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_AES
/**
 * @brief ECB mode assembly encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t AES_ECB_EncryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief ECB mode assembly decryption
 *
 * @param ctx [IN]  mode handle
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t AES_ECB_DecryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

/**
 * @brief Clear the ECB mode context, delete sensitive data. Preserve the memory and methods of algorithm modules
 *
 * @param ctx [IN]  mode handle
 * @return none
 */
void MODE_ECB_Clean(MODE_CipherCtx *ctx);

/**
 * @brief In ECB mode, perform parameter operations on mode.
 *
 * @param ctx [IN]  mode handle
 * @param opt [IN]  Operation
 * @param val [IN/OUT] Parameter, which can be an input parameter or an output parameter.
 * @param len [IN]  Parameter length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_ECB_Ctrl(MODE_CipherCtx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief SM4-ECB mode encryption. When the value of len is not an integer multiple of 16,
 *        MODE_SM4_ECB_Encrypt cannot be invoked to encrypt new data.
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_ECB_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4-ECB mode decryption. If the value of len is not an integer multiple of 16,
 *        this round of decryption is complete.
 *
 * @param ctx [IN]  mode handle
 * @param in [IN]   Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_ECB_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif