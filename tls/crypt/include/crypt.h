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

#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>
#include "hitls_crypt_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The maximum length of the RSA signature is 512. The maximum length of the ECC signature does not reach 1024. */
#define MAX_SIGN_SIZE 1024

/* Used to transfer key derivation parameters. */
typedef struct {
    HITLS_HashAlgo hashAlgo;    /* Hash algorithm */
    const uint8_t *secret;      /* Initialization key */
    uint32_t secretLen;         /* Key length */
    const uint8_t *label;       /* Label */
    uint32_t labelLen;          /* Label length */
    const uint8_t *seed;        /* Seed */
    uint32_t seedLen;           /* Seed length */
} CRYPT_KeyDeriveParameters;

/**
 * @brief Generate a random number.
 *
 * @param buf [OUT] Random number
 * @param len [IN] Random number length
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      Unregistered callback
 * @retval HITLS_CRYPT_ERR_GENRATE_RANDOM   Failed to generate a random number.
 */
int32_t SAL_CRYPT_Rand(uint8_t *buf, uint32_t len);

/**
 * @brief Obtain the HMAC length.
 *
 * @param hashAlgo [IN] hash algorithm
 *
 * @return HMAC length
 */
uint32_t SAL_CRYPT_HmacSize(HITLS_HashAlgo hashAlgo);

/**
 * @brief Initialize the HMAC context.
 *
 * @param hashAlgo   [IN] hash algorithm
 * @param key        [IN] Key
 * @param len        [IN] Key length
 *
 * @return HMAC context
 */
HITLS_HMAC_Ctx *SAL_CRYPT_HmacInit(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len);

/**
 * @brief   Release the HMAC context.
 *
 * @param   hmac [IN] HMAC context
 */
void SAL_CRYPT_HmacFree(HITLS_HMAC_Ctx *hmac);

/**
 * @brief Add the HMAC input data.
 *
 * @param hmac [IN] HMAC context
 * @param data [IN] Input data
 * @param len  [IN] Input data length
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      Unregistered callback
 * @retval HITLS_CRYPT_ERR_HMAC             The HMAC operation fails.
 */
int32_t SAL_CRYPT_HmacUpdate(HITLS_HMAC_Ctx *hmac, const uint8_t *data, uint32_t len);

/**
 * @brief Calculate the HMAC result.
 *
 * @param hmac [IN] HMAC context
 * @param out  [OUT] Output data
 * @param len  [IN/OUT] IN: Maximum length of data padding OUT: Output data length
 *
 * @retval HITLS_SUCCESS                 succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK   Unregistered callback
 * @retval HITLS_CRYPT_ERR_HMAC          The HMAC operation fails.
 */
int32_t SAL_CRYPT_HmacFinal(HITLS_HMAC_Ctx *hmac, uint8_t *out, uint32_t *len);

/**
 * @brief HMAC function
 *
 * @param hashAlgo  [IN] hash algorithm
 * @param key       [IN] Key
 * @param keyLen    [IN] Key length
 * @param in        [IN] Input data
 * @param inLen     [IN] Input data length
 * @param out       [OUT] Output data
 * @param outLen    [IN/OUT] IN: Maximum length of data padding OUT: Output data length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HMAC         The HMAC operation fails.
 */
int32_t SAL_CRYPT_Hmac(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @brief PRF function
 *
 * @param input  [IN] Key derivation parameter
 * @param md     [OUT] Output key
 * @param outLen [OUT] Output key length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HMAC         The HMAC operation fails.
 * @retval HITLS_MEMALLOC_FAIL          Memory application failed.
 */
int32_t SAL_CRYPT_PRF(CRYPT_KeyDeriveParameters *input, uint8_t *out, uint32_t outLen);

/**
 * @brief Obtain the hash length.
 *
 * @param hashAlgo [IN] Hash algorithm
 *
 * @return Hash length
 */
uint32_t SAL_CRYPT_DigestSize(HITLS_HashAlgo hashAlgo);

/**
 * @brief Initialize the hash context.
 *
 * @param hashAlgo [IN] hash algorithm
 *
 * @return hash context
 */
HITLS_HASH_Ctx *SAL_CRYPT_DigestInit(HITLS_HashAlgo hashAlgo);

/**
 * @brief Copy the hash context.
 *
 * @param ctx [IN] hash Context
 *
 * @return hash context
 */
HITLS_HASH_Ctx *SAL_CRYPT_DigestCopy(HITLS_HASH_Ctx *ctx);

/**
 * @brief Release the hash context.
 *
 * @param ctx [IN] hash Context
 */
void SAL_CRYPT_DigestFree(HITLS_HASH_Ctx *ctx);

/**
 * @brief Add the hash input data.
 *
 * @param ctx  [IN] hash Context
 * @param data [IN] Input data
 * @param len  [IN] Length of the input data
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST       hash operation failed.
 */
int32_t SAL_CRYPT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len);

/**
 * @brief Calculate the hash result.
 *
 * @param ctx [IN] hash context
 * @param out [OUT] Output data
 * @param len [IN/OUT] IN: Maximum length of data padding OUT: Length of output data
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST       hash operation failed.
 */
int32_t SAL_CRYPT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len);

/**
 * @brief Calculate the hash.
 *
 * @param hashAlgo  [IN] hash algorithm
 * @param in        [IN] Input data
 * @param inLen     [IN] Length of the input data
 * @param out       [OUT] Output data
 * @param outLen    [IN/OUT] IN: Maximum length of data padding OUT: Length of output data
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST       hash operation failed.
 */
int32_t SAL_CRYPT_Digest(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @brief Encryption
 *
 * @param cipher [IN] Key parameters
 * @param in     [IN] Plaintext data
 * @param inLen  [IN] Length of the plaintext data
 * @param out    [OUT] Ciphertext data
 * @param outLen [IN/OUT] IN: Maximum length of data padding OUT: Length of ciphertext data
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_ENCRYPT      Encryption failed.
 */
int32_t SAL_CRYPT_Encrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Decrypt
 *
 * @param cipher [IN] Key parameters
 * @param in     [IN] Ciphertext data
 * @param inLen  [IN] Length of the ciphertext data
 * @param out    [OUT] Plaintext data
 * @param outLen [IN/OUT] IN: Maximum length of data padding OUT: Length of plaintext data
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_DECRYPT      decryption failure
 */
int32_t SAL_CRYPT_Decrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Generate the ECDH key pair.
 *
 * @param curveParams [IN] Elliptic curve parameter
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_GenEcdhKeyPair(const HITLS_ECParameters *curveParams);

/**
 * @brief Deep Copy ECDH Key Pair
 *
 * @param key [IN] Key handle
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_DupEcdhKey(HITLS_CRYPT_Key *key);

/**
 * @brief Release the ECDH key.
 *
 * @param key [IN] Key handle
 */
void SAL_CRYPT_FreeEcdhKey(HITLS_CRYPT_Key *key);

/**
 * @brief Obtain the ECDH public key data.
 *
 * @param key       [IN] Key handle
 * @param pubKeyBuf [OUT] Public key data
 * @param bufLen    [IN] Maximum length of data padding.
 * @param usedLen   [OUT] Public key data length
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      Unregistered callback
 * @retval HITLS_CRYPT_ERR_ENCODE_ECDH_KEY  Failed to obtain the public key data.
 */
int32_t SAL_CRYPT_EncodeEcdhPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief Calculate the ECDH shared key.
 *
 * @param key               [IN] Local key handle
 * @param peerPubkey        [IN] Peer public key data
 * @param pubKeyLen         [IN] Public key data length
 * @param sharedSecret      [OUT] Shared key
 * @param sharedSecretLen   [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      Unregistered callback
 * @retval HITLS_CRYPT_ERR_CALC_SHARED_KEY  Failed to calculate the shared key.
 */
int32_t SAL_CRYPT_CalcEcdhSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief SM2 calculates the ECDH shared key.
 *
 * @param sm2ShareKeyParam  [IN] Parameters required for calculating the shared key
 * @param sharedSecret      [OUT] Shared key
 * @param sharedSecretLen   [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      Unregistered callback
 * @retval HITLS_CRYPT_ERR_CALC_SHARED_KEY  Failed to calculate the shared key.
 */
int32_t SAL_CRYPT_CalcSm2dhSharedSecret(HITLS_Sm2GenShareKeyParameters *sm2ShareKeyParam, uint8_t *sharedSecret,
                                        uint32_t *sharedSecretLen);

/**
 * @brief Generate a DH key pair.
 *
 * @param secbits [IN] Key security level
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyBySecbits(int32_t secbits);

/**
 * @brief Generate a DH key pair.
 *
 * @param p     [IN] p Parameter
 * @param plen  [IN] p Parameter length
 * @param g     [IN] g Parameter
 * @param glen  [IN] g Parameter length
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyByParams(uint8_t *p, uint16_t plen, uint8_t *g, uint16_t glen);

/**
 * @brief Deep Copy DH Key Pair
 *
 * @param key [IN] Key handle
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_DupDhKey(HITLS_CRYPT_Key *key);

/**
 * @brief Release the DH key.
 *
 * @param key [IN] Key handle
 */
void SAL_CRYPT_FreeDhKey(HITLS_CRYPT_Key *key);

/**
 * @brief Obtain the DH parameter.
 *
 * @param key   [IN] Key handle
 * @param p     [OUT] p Parameter
 * @param plen  [IN/OUT] IN: Maximum length of data padding OUT: p Parameter length
 * @param g     [OUT] g Parameter
 * @param glen  [IN/OUT] IN: Maximum length of data padding OUT: g Parameter length
 *
 * @return HITLS_SUCCESS succeeded.
 */
int32_t SAL_CRYPT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *plen,
    uint8_t *g, uint16_t *glen);

/**
* @brief Obtain the DH public key data.
*
* @param key        [IN] Key handle
* @param pubKeyBuf  [OUT] Public key data
* @param bufLen     [IN] Maximum length of data padding.
* @param usedLen    [OUT] Public key data length
*
* @retval HITLS_SUCCESS                 succeeded.
* @retval HITLS_UNREGISTERED_CALLBACK   Unregistered callback
* @retval HITLS_CRYPT_ERR_ENCODE_DH_KEY Failed to obtain the public key data.
 */
int32_t SAL_CRYPT_EncodeDhPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief Calculate the DH shared key.
 *
 * @param key                [IN] Local key handle
 * @param peerPubkey         [IN] Peer public key data
 * @param pubKeyLen          [IN] Public key data length
 * @param sharedSecret       [OUT] Shared key
 * @param sharedSecretLen    [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS                     succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK       Unregistered callback
 * @retval HITLS_CRYPT_ERR_CALC_SHARED_KEY   Failed to calculate the shared key.
 */
int32_t SAL_CRYPT_CalcDhSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief HKDF-Extract
 *
 * @param input  [IN] Input key material
 * @param prk    [OUT] Output key
 * @param prkLen [IN/OUT] IN: Maximum buffer length OUT: Output key length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT calculation fails.
 */
int32_t SAL_CRYPT_HkdfExtract(HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen);

/**
 * @brief   HKDF-Expand
 *
 * @param input  [IN] Input key material
 * @param okm    [OUT] Output key
 * @param okmLen [IN] Output key length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND  calculation fails.
 */
int32_t SAL_CRYPT_HkdfExpand(HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen);

/**
 * @brief   HKDF-ExpandLabel
 *
 * @param input  [IN] Input key material.
 * @param prk    [OUT] Output key
 * @param prkLen [IN/OUT] IN: Maximum buffer length OUT: Output key length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT calculation fails.
 * @retval HITLS_MEMCPY_FAIL            Memory Copy Failure
 */
int32_t SAL_CRYPT_HkdfExpandLabel(CRYPT_KeyDeriveParameters *deriveInfo,
    uint8_t *outSecret, uint32_t outLen);

#ifdef __cplusplus
}
#endif
#endif
