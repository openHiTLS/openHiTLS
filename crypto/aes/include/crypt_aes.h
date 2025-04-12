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

#ifndef CRYPT_AES_H
#define CRYPT_AES_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_AES

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_AES_128 128
#define CRYPT_AES_192 192
#define CRYPT_AES_256 256

#define CRYPT_AES_MAX_ROUNDS  14
#define CRYPT_AES_MAX_KEYLEN  (4 * (CRYPT_AES_MAX_ROUNDS + 1))

/**
 * @ingroup CRYPT_AES_Key
 *
 * aes key structure
 */
typedef struct {
    uint32_t key[CRYPT_AES_MAX_KEYLEN];
    uint32_t rounds;
} CRYPT_AES_Key;

/**
 * @ingroup aes
 * @brief Set the AES encryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 16 bytes.
*/
int32_t CRYPT_AES_SetEncryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES encryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 24 bytes.
*/
int32_t CRYPT_AES_SetEncryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES encryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN]  Encryption key
 * @param len [IN]  Key length. The value must be 32 bytes.
*/
int32_t CRYPT_AES_SetEncryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES decryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN] Decryption key
 * @param len [IN]  Key length. The value must be 16 bytes.
*/
int32_t CRYPT_AES_SetDecryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES decryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN] Decryption key
 * @param len [IN]  Key length. The value must be 24 bytes.
*/
int32_t CRYPT_AES_SetDecryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief Set the AES decryption key.
 *
 * @param ctx [IN]  AES handle
 * @param key [IN] Decryption key
 * @param len [IN]  Key length. The value must be 32 bytes.
*/
int32_t CRYPT_AES_SetDecryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup aes
 * @brief AES encryption
 *
 * @param ctx [IN] AES handle, storing keys
 * @param in  [IN] Input plaintext data. The value must be 16 bytes.
 * @param out [OUT] Output ciphertext data. The length is 16 bytes.
 * @param len [IN] Block length.
*/
int32_t CRYPT_AES_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup aes
 * @brief AES decryption
 *
 * @param ctx [IN] AES handle, storing keys
 * @param in  [IN] Input ciphertext data. The value must be 16 bytes.
 * @param out [OUT] Output plaintext data. The length is 16 bytes.
 * @param len [IN] Block length. The length is 16.
*/
int32_t CRYPT_AES_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_CBC
/**
 * @ingroup aes
 * @brief AES cbc encryption
 *
 * @param ctx [IN]  AES handle, storing keys
 * @param in  [IN]  Input plaintext data, 16 bytes.
 * @param out [OUT] Output ciphertext data. The length is 16 bytes.
 * @param len [IN]  Block length.
 * @param iv  [IN]  Initialization vector.
*/
int32_t CRYPT_AES_CBC_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

/**
 * @ingroup aes
 * @brief AES cbc decryption
 *
 * @param ctx [IN]  AES handle, storing keys
 * @param in  [IN]  Input ciphertext data. The value is 16 bytes.
 * @param out [OUT] Output plaintext data. The length is 16 bytes.
 * @param len [IN]  Block length.
 * @param iv  [IN]  Initialization vector.
*/
int32_t CRYPT_AES_CBC_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);
#endif /* HITLS_CRYPTO_CBC */

#if defined(HITLS_CRYPTO_CTR) || defined(HITLS_CRYPTO_GCM)
/**
 * @ingroup aes
 * @brief AES ctr encryption
 *
 * @param ctx [IN]  AES handle, storing keys
 * @param in  [IN]  Input plaintext data, 16 bytes.
 * @param out [OUT] Output ciphertext data. The length is 16 bytes.
 * @param len [IN]  Block length.
 * @param iv  [IN]  Initialization vector.
*/
int32_t CRYPT_AES_CTR_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);
#endif

#ifdef HITLS_CRYPTO_ECB
/**
 * @ingroup aes
 * @brief AES ecb encryption
 *
 * @param ctx [IN]  AES handle, storing keys
 * @param in  [IN]  Input plaintext data. The length is a multiple of 16 bytes.
 * @param out [OUT] Output ciphertext data. The length is a multiple of 16 bytes.
 * @param len [IN]  Block length.
*/
int32_t CRYPT_AES_ECB_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup aes
 * @brief AES ecb decryption
 *
 * @param ctx [IN]  AES handle, storing keys
 * @param in  [IN]  Input ciphertext data. The value is 16 bytes.
 * @param out [OUT] Output plaintext data. The length is 16 bytes.
 * @param len [IN]  Block length.
*/
int32_t CRYPT_AES_ECB_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

#ifdef HITLS_CRYPTO_CFB
/**
 * @brief Decryption in CFB mode
 *
 * @param ctx [IN] Mode handle
 * @param in  [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Data length
 * @param iv  [IN] Initial vector
 * @return Success response: CRYPT_SUCCESS
 * Returned upon failure: Other error codes.
 */
int32_t CRYPT_AES_CFB_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);
#endif

#ifdef HITLS_CRYPTO_XTS
/**
 * @ingroup aes
 * @brief AES xts encryption
 *
 * @param ctx [IN]  AES key
 * @param in  [IN]  Input plaintext.
 * @param out [OUT] Output ciphertext.
 * @param len [IN]  Input length. The length is guaraenteed to be greater than block-size.
 * @param tweak [IN/OUT]  XTS tweak.
*/
int32_t CRYPT_AES_XTS_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in,
    uint8_t *out, uint32_t len, const uint8_t *tweak);

/**
 * @ingroup aes
 * @brief AES xts decryption
 *
 * @param ctx [IN]  AES handle, storing keys
 * @param in  [IN]  Input ciphertext data. The value is 16 bytes.
 * @param out [OUT] Output plaintext data. The length is 16 bytes.
 * @param len [IN]  Block length.
 * @param t [IN/OUT]  XTS tweak.
*/
int32_t CRYPT_AES_XTS_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in,
    uint8_t *out, uint32_t len, const uint8_t *t);
#endif

/**
 * @ingroup aes
 * @brief Delete the AES key information.
 *
 * @param ctx [IN]  AES handle, storing keys
 * @return void
*/
void CRYPT_AES_Clean(CRYPT_AES_Key *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_AES

#endif // CRYPT_AES_H
