/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_MODES_CFB_H
#define CRYPT_MODES_CFB_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CFB

#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    MODE_CipherCtx *modeCtx;    /* Stores the pointer to MODE_CipherCtx */
    uint8_t feedbackBits;  /* Save the FeedBack length. */
} MODE_CFB_Ctx;

/**
 * @brief Set the encryption key in CFB mode.
 *
 * @param ctx [IN/OUT] mode handle
 * @param key [IN] Encryption key
 * @param len [IN] Encryption key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_CFB_SetEncryptKey(MODE_CFB_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief Initialize the module, register the method of the encryption and decryption algorithm in the module,
 *        and create the algorithm context.
 *
 * @param ctx [IN] mode handle
 * @param method [IN] Symmetric encryption and decryption methods
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_CFB_InitCtx(MODE_CFB_Ctx *ctx, const EAL_CipherMethod *method);

/**
 * @brief CFB mode encryption. Any byte can be encrypted, including 1-bit/8-bit/64-bit/128-bit CFB
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_CFB_Encrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief CFB mode decryption. Any byte can be decrypted, including 1-bit/8-bit/64-bit/128-bit CFB
 *
 * @param ctx [IN]  mode handle
 * @param in [IN]   Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_CFB_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief Perform parameter operation on mode.
 *
 * @param ctx [IN] mode handle
 * @param opt [IN] operation (Set/Get IV; Set/Get FeedbackSize)
 * @param val [IN/OUT] Parameter, which can be an input parameter or an output parameter.
 * @param len [IN] Parameter length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_CFB_Ctrl(MODE_CFB_Ctx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);

/**
 * @brief Clear the content in CFB mode, delete sensitive data. Preserve the memory and methods of algorithm modules
 *
 * @param ctx [IN] mode handle
 * @return none
 */
void MODE_CFB_Clean(MODE_CFB_Ctx *ctx);

/**
 * @brief Deinitialize the module, remove the relationship between the module and the algorithm,
 *        and release the algorithm context.
 *
 * @param ctx [IN] mode handle
 * @param method [IN] Symmetric encryption and decryption methods
 */
void MODE_CFB_DeInitCtx(MODE_CFB_Ctx *ctx);

/**
 * @brief For encrypting and decrypting bits in CFB mode (internal function, only for test)
 */
int32_t MODE_CFB_BitCrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc);

#ifdef HITLS_CRYPTO_AES
/**
 * @brief AES-CFB mode decryption
 *
 * @param ctx [IN]  mode handle
 * @param in  [IN]  Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN]  Data length
 * @param iv  [IN]  iv
 * @return Remaining unprocessed length
 */
int32_t MODE_AES_CFB_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif // HITLS_CRYPTO_AES

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief Set the encryption key in SM4-CFB mode.
 *
 * @param ctx [IN] mode handle
 * @param key [IN] Encryption key
 * @param len [IN] Encryption key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_CFB_SetEncryptKey(MODE_CFB_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4-CFB mode encryption
 *
 * @param [IN] ctx  mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_CFB_Encrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4-CFB mode decryption
 *
 * @param ctx [IN]  mode handle
 * @param in  [IN]  Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_SM4_CFB_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif // HITLS_CRYPTO_SM4

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CFB

#endif // CRYPT_MODES_CFB_H
