/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_MODES_XTS_H
#define CRYPT_MODES_XTS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XTS

#include "crypt_local_types.h"
#include "crypt_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    void *ciphCtx;                    /* Key defined by each algorithm  */
    const EAL_CipherMethod *ciphMeth; /* corresponding to the encrypt and decrypt in the bottom layer, operate keyctx */
    uint8_t iv[MODES_MAX_IV_LENGTH];  /* The length is blocksize */
    uint8_t tweak[MODES_MAX_IV_LENGTH]; /* The length is blocksize */
    uint8_t blockSize;                  /* Save the block size. */
    CRYPT_SYM_AlgId algId;              /* symmetric algorithm ID */
} MODE_XTS_Ctx;

/**
 * @brief  Initialize the module, register the method of the encryption and decryption algorithm in the module,
 *         and create the algorithm context.
 *
 * @param ctx [IN] Context of xts mode encryption
 * @param method [IN] Symmetric encryption and decryption methods
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_XTS_InitCtx(MODE_XTS_Ctx *ctx, EAL_CipherMethod *method);
/**
 * @brief Set the encryption key in XTS mode.
 *
 * @param ctx [IN] Context of xts mode encryption
 * @param key [IN] Encryption key
 * @param len [IN] Encryption key length. Only 32 (256 bits) and 64 (512 bits) are supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_XTS_SetEncryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief Set the decryption key in XTS mode.
 *
 * @param ctx [IN] Context of xts mode encryption
 * @param key [IN] Decryption key
 * @param len [IN] Decryption key length. Only 32 (256 bits) and 64 (512 bits) are supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_XTS_SetDecryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief XTS mode encryption. If the value of len is not an integer multiple of 16,
 *        MODE_XTS_Encrypt cannot be invoked to encrypt new data.
 *
 * @param [IN] ctx  Context of xts mode encryption
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_XTS_Encrypt(MODE_XTS_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief XTS mode decryption. If the value of len is not an integer multiple of 16,
 *        this round of the decryption is complete.
 *
 * @param ctx [IN]  Context of xts mode encryption
 * @param in [IN]   Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_XTS_Decrypt(MODE_XTS_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
/**
 * @brief Clear the XTS mode context, delete sensitive data. Preserve the memory and methods of algorithm modules
 *
 * @param ctx [IN] Context of xts mode encryption
 * @return none
 */
void MODE_XTS_Clean(MODE_XTS_Ctx *ctx);
/**
 * @brief Operate parameters for the XTS mode.
 *
 * @param ctx [IN] Context of xts mode encryption
 * @param opt [IN] Operation
 * @param val [IN/OUT] Parameter, which can be an input parameter or an output parameter.
 * @param len [IN] Parameter length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODE_XTS_Ctrl(MODE_XTS_Ctx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief SM4-XTS mode setting encryption key
 *
 * @param ctx [IN] Context of xts mode encryption
 * @param key [IN] Encryption key
 * @param len [IN] Encryption key length. Only 32 bytes (256bits) is supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_XTS_SetEncryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4-XTS mode setting decryption key
 *
 * @param ctx [IN] Context of xts mode encryption
 * @param key [IN] Decryption key
 * @param len [IN] Decryption key length. Only 32 bytes (256bits) is supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_XTS_SetDecryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4-XTS mode encryption. When the value of len is not an integer multiple of 16,
 *        MODE_SM4_XTS_Encrypt cannot be invoked to encrypt new data.
 *
 * @param [IN] ctx Mode handle
 * @param [IN] in   Data to be encrypted
 * @param [OUT] out Encrypted data
 * @param [IN] len  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_XTS_Encrypt(MODE_XTS_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4-XTS mode decryption. If the value of len is not an integer multiple of 16,
 *        this round of the decryption is complete.
 *
 * @param ctx [IN] Context of xts mode encryption
 * @param in [IN]   Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN]  Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_XTS_Decrypt(MODE_XTS_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief Clear the SM4-XTS mode context, delete sensitive data. Preserve the memory and methods of algorithm modules
 *
 * @param ctx [IN] Context of xts mode encryption
 * @return none
 */
void MODES_SM4_XTS_Clean(MODE_XTS_Ctx *ctx);
#endif // HITLS_CRYPTO_SM4

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_XTS

#endif // CRYPT_MODES_XTS_H
