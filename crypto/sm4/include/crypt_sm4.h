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

#ifndef CRYPT_SM4_H
#define CRYPT_SM4_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CRYPT_SM4_BLOCKSIZE     16
#define CRYPT_SM4_BLOCKSIZE_16  256
#define CRYPT_SM4_ROUNDS 32

typedef struct {
    uint8_t iv[CRYPT_SM4_BLOCKSIZE];
    uint32_t rk[CRYPT_SM4_ROUNDS];
} CRYPT_SM4_Ctx;

/**
 * @brief SM4 Set the encryption and decryption key.
 *
 * @param [IN] ctx       SM4 context
 * @param [IN] key       Key
 * @param [IN] keyLen    Key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_SetKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t keyLen);

/**
 * @brief SM4 encryption. The data length must be an integer multiple of 16.
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] in       Data to be encrypted
 * @param [OUT] out     Encrypted data
 * @param [IN] length   Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);

/**
 * @brief SM4 decryption. The data length must be an integer multiple of 16.
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] in       Data to be decrypted
 * @param [OUT] out     Decrypted Data
 * @param [IN] length   Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);

/**
 * @brief Clear the SM4 context
 *
 * @param [IN] ctx sm4 context
 */
void CRYPT_SM4_Clean(CRYPT_SM4_Ctx *ctx);

#ifdef HITLS_CRYPTO_XTS
/**
 * @brief SM4 Set the encryption key.
 *
 * @param ctx [IN] sm4 Context
 * @param key [IN] Key. The first 16 bytes are data_key, and the last 16 bytes are tweak_key.
 * @param keyLen [IN] Key length
 *
 * @retval #CRYPT_SUCCESS           succeeded.
 * @retval #CRYPT_NULL_INPUT        ctx or key is NULL.
 * @retval #CRYPT_SM4_ERR_KEY_LEN  The key length is not equal to 32.
 */
int32_t CRYPT_SM4_XTS_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4 Set the decryption key.
 *
 * @param ctx [IN] sm4 Context
 * @param key [IN] Key
 * @param keyLen [IN] Key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_XTS_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len);
 
/**
 * @brief Clear SM4_xts context
 *
 * @param [IN] ctx sm4 context
 */
void CRYPT_SM4_XTS_Clean(CRYPT_SM4_Ctx *ctx);

/**
 * @brief SM4 XTS mode encryption
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN] Length of the decrypted data
 * @param iv [IN] Set IV
 *
 * @retval #CRYPT_SUCCESS           succeeded.
 * @retval #CRYPT_NULL_INPUT        ctx,in,out is NULL
 * @retval #CRYPT_SM4_DATALEN_ERROR The length of the decrypted data is less than 16 bytes.
 */
int32_t CRYPT_SM4_XTS_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

/**
 * @brief SM4 XTS mode encryption
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 * @param iv [IN] Set IV
 *
 * @retval #CRYPT_SUCCESS           succeeded.
 * @retval #CRYPT_NULL_INPUT        ctx/in/out is NULL
 * @retval #CRYPT_SM4_DATALEN_ERROR The length of the encrypted data is less than 16.
 */
int32_t CRYPT_SM4_XTS_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);
#endif

/**
 * @brief SM4 Set the encryption key (optimized).
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] key      Key
 * @param [IN] len      Key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4 Set the decryption key (optimized).
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] key      Key
 * @param [IN] len      Key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len);

#ifdef HITLS_CRYPTO_ECB
/**
 * @brief SM4 ECB mode encryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_ECB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief SM4 ECB mode decryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] Decrypted data
 * @param len [IN] Length of the decrypted data
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_ECB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

#ifdef HITLS_CRYPTO_CBC
/**
 * @brief SM4 CBC mode encryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CBC_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

/**
 * @brief SM4 CBC mode decryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] decrypted data
 * @param len [IN] Length of the decrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CBC_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);
#endif

#if defined(HITLS_CRYPTO_CTR) || defined(HITLS_CRYPTO_GCM)
/**
 * @brief SM4 CTR mode encryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CTR_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

/**
 * @brief SM4 CTR mode decryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] decrypted data
 * @param len [IN] Length of the decrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CTR_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);
#endif

#ifdef HITLS_CRYPTO_OFB
/**
 * @brief SM4 OFB mode encryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 * @param iv [IN] Set IV
 * @param offset [OUT] Length of less than one block
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_OFB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv, uint8_t *offset);

/**
 * @brief SM4 OFB mode decryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] decrypted data
 * @param len [IN] Length of the decrypted data
 * @param iv [IN] Set IV
 * @param offset [OUT] Length of less than one block
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_OFB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv, uint8_t *offset);
#endif

#ifdef HITLS_CRYPTO_CFB
/**
 * @brief SM4 CFB mode encryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 * @param iv [IN] Set IV
 * @param offset [OUT] Length of less than one block.
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CFB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv, uint8_t *offset);

/**
 * @brief SM4 CFB mode decryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] decrypted data
 * @param len [IN] Length of the decrypted data
 * @param iv [IN] Set IV
 * @param offset [OUT] Length of less than one block.
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CFB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv, uint8_t *offset);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HITLS_CRYPTO_SM4

#endif // CRYPT_SM4_H