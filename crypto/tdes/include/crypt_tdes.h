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

#ifndef CRYPT_TDES_H
#define CRYPT_TDES_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_TDES) || defined(HITLS_CRYPTO_DES)

#include <stdint.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define DES_BLOCK_BYTE_NUM 8
#define TDES_KEY_LEN 24
#define DES_KEY_LEN 8

/**
 * @ingroup CRYPT_DES_Key
 *
 * DES Key Structure
 */
typedef struct {
    uint32_t ks[32]; // It has 16 rounds of des encryption, each round contains 2 32-bit keys, needs 32*32bits in total.
    uint32_t keyNeedCheck;
} CRYPT_DES_Key;

/**
 * @ingroup CRYPT_TDES_Key
 *
 * TDES Key Structure
 */
typedef struct {
    CRYPT_DES_Key key1;
    CRYPT_DES_Key key2;
    CRYPT_DES_Key key3;
} CRYPT_TDES_Key;

/* DES */

/**
 * @ingroup des
 * @brief Set the DES key.
 *
 * @param ctx [OUT] DES handle
 * @param key [IN] Encryption/Decryption key
 * @param len [IN] Key length. The value is 8.
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_DES_SetCryptKey(CRYPT_DES_Key *ctx, const uint8_t *key, uint32_t len);

#ifdef HITLS_CRYPTO_DES
/**
 * @ingroup des
 * @brief DES encryption.
 *
 * @param ctx [IN] DES handle, storing keys
 * @param in  [IN] The input plaintext data, which must be 8 bytes.
 * @param out [OUT] The output ciphertext data. The length is 8 bytes.
 * @param len [IN] Block length. The value must be 8.
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_DES_Encrypt(const CRYPT_DES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup des
 * @brief DES decryption.
 *
 * @param ctx [IN] DES handle, storing keys
 * @param in  [IN] The input ciphertext data, which must be 8 bytes.
 * @param out [OUT] Output plaintext data, with a length of 8 bytes.
 * @param len [IN] Block length.
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_DES_Decrypt(const CRYPT_DES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup des
 * @brief Clear the DES key information.
 *
 * @param ctx [IN]  DES handle, storing keys
 * @return void
 */
void CRYPT_DES_Clean(CRYPT_DES_Key *ctx);

/**
 * @ingroup des
 * @brief Set des-ctx to perform parameter operations.
 *
 * @param ctx [IN] Mode handle
 * @param opt [IN] Operation
 * @param val [IN/OUT] Parameter, which can be an input parameter or an output parameter.
 * @param len [IN] Parameter length
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_DES_Ctrl(CRYPT_DES_Key *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);
#endif

#ifdef HITLS_CRYPTO_TDES
/**
 * @ingroup tdes
 * @brief Set the TDES key.
 *
 * @param ctx [OUT] TDES handle
 * @param key [IN] Encryption/Decryption key
 * @param len [IN] Key length. The value is 24.
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_TDES_SetCryptKey(CRYPT_TDES_Key *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup tdes
 * @brief TDES encryption.
 *
 * @param ctx [IN] TDES handle, storing keys
 * @param in  [IN] The input plaintext data, which must be 8 bytes.
 * @param out [OUT] The output ciphertext data. The length is 8 bytes.
 * @param len [IN] Block length, which must be 8.
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_TDES_Encrypt(const CRYPT_TDES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup tdes
 * @brief TDES decryption.
 *
 * @param ctx [IN] TDES handle, storing keys
 * @param in  [IN] The input ciphertext data, which must be 8 bytes.
 * @param out [OUT] Output plaintext data, with a length of 8 bytes.
 * @param len [IN] Block length.
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_TDES_Decrypt(const CRYPT_TDES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @ingroup tdes
 * @brief Clear the TDES key information.
 *
 * @param ctx [IN]  TDES handle, storing keys
 * @return void
*/
void CRYPT_TDES_Clean(CRYPT_TDES_Key *ctx);

/**
 * @ingroup tdes
 * @brief Set the TDES-ctx to perform parameter operations.
 *
 * @param ctx [IN] Mode handle
 * @param opt [IN] Operation
 * @param val [IN/OUT] Parameter, which can be an input parameter or an output parameter.
 * @param len [IN] Parameter length
 * @return CRYPT_SUCCESS            succeeded
 * @return Other error codes        failed
 */
int32_t CRYPT_TDES_Ctrl(CRYPT_TDES_Key *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);
#endif

/**
 * @ingroup des
 * @brief Check the DES key.
 *
 * @param key [IN] DSA key
 * @param len [IN] Key length. The value is 8.
 * @return CRYPT_SUCCESS         Not a weak key.
 * @return CRYPT_DES_ERR_KEY     Is a weak key.
 * @return CRYPT_DES_ERR_LEN     The key is NULL or length is not equal to 8.
 */
int32_t CRYPT_DES_CheckWeakKey(const uint8_t *key, uint32_t len);

/**
 * @ingroup des
 * @brief Check whether the key is a DES weak key or fails the DES parity check.
 *
 * @param key [IN] DSA key
 * @param len [IN] Key length. The value is 8.
 * @return CRYPT_SUCCESS         Check pass.
 * @return CRYPT_DES_ERR_KEY     Check fail.
 * @return CRYPT_DES_ERR_LEN     The key is NULL or length is not equal to 8.
 */
int32_t CRYPT_DES_KeyValidityCheck(const uint8_t *key, uint32_t len);

/**
 * @ingroup des
 * @brief Set key odd parity.
 *
 * @param key [IN] DSA key
 * @param len [IN] Key length. The value is 8.
 * @return CRYPT_SUCCESS         Succeeded
 * @return CRYPT_DES_ERR_LEN     The key is NULL or length is not equal to 8.
 */
int32_t CRYPT_DES_SetKeyOddParity(uint8_t *key, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* #if defined(HITLS_CRYPTO_TDES) || defined(HITLS_CRYPTO_DES) */

#endif
