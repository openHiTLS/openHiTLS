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

#ifndef CRYPT_DEFAULT_H
#define CRYPT_DEFAULT_H
#include <stdint.h>
#include "hitls_crypt_type.h"
#include "hitls_crypt_reg.h"
#include "hitls_crypt.h"
#include "crypt_eal_rand.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a random number.
 *
 * @param buf [OUT] Random number
 * @param len [IN] Random number length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#ifdef HITLS_CRYPTO_DRBG
#define CRYPT_DEFAULT_RandomBytes CRYPT_EAL_Randbytes
#else
#define CRYPT_DEFAULT_RandomBytes NULL
#endif

/**
 * @brief Obtain the HMAC length.
 *
 * @param hashAlgo [IN] hash algorithm
 *
 * @return HMAC length
 */
#define CRYPT_DEFAULT_HMAC_Size CRYPT_DEFAULT_DigestSize

/**
 * @brief Initialize the HMAC context.
 *
 * @param hashAlgo [IN] Hash algorithm
 * @param key [IN] Key
 * @param len [IN] Key length
 *
 * @return HMAC context
 */
HITLS_HMAC_Ctx *CRYPT_DEFAULT_HMAC_Init(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len);

/**
 * @brief ReInitialize the HMAC context.
 *
 * @param ctx [IN] HMAC context.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#define CRYPT_DEFAULT_HMAC_ReInit HITLS_CRYPT_HMAC_ReInit

/**
 * @brief Release the HMAC context.
 *
 * @param hmac [IN] HMAC context. The CTX is set NULL by the invoker.
 */
#define CRYPT_DEFAULT_HMAC_Free HITLS_CRYPT_HMAC_Free

/**
 * @brief Add the HMAC input data.
 *
 * @param hmac [IN] HMAC context
 * @param data [IN] Input data
 * @param len [IN] Input data length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#define CRYPT_DEFAULT_HMAC_Update HITLS_CRYPT_HMAC_Update

/**
 * @brief HMAC calculation result
 *
 * @param hmac [IN] HMAC context
 * @param out [OUT] Output data
 * @param len [IN/OUT] IN: Maximum length of data padding OUT: Output data length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#define CRYPT_DEFAULT_HMAC_Final HITLS_CRYPT_HMAC_Final

/**
 * @brief HMAC function
 *
 * @param hashAlgo [IN] Hash algorithm
 * @param key [IN] Key
 * @param keyLen [IN] Key length
 * @param in [IN] Input data
 * @param inLen [IN] Input data length
 * @param out [OUT] Output data
 * @param outLen [IN/OUT] IN: Maximum length of data padding OUT: Output data length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_HMAC(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @brief Obtain the hash length.
 *
 * @param hashAlgo [IN] hash algorithm
 *
 * @return Hash length
 */
#define CRYPT_DEFAULT_DigestSize HITLS_CRYPT_DigestSize

/**
 * @brief Initialize the hash context.
 *
 * @param hashAlgo [IN] Hash algorithm
 *
 * @return hash context
 */
HITLS_HASH_Ctx *CRYPT_DEFAULT_DigestInit(HITLS_HashAlgo hashAlgo);

/**
 * @brief Copy the hash context.
 *
 * @param ctx [IN] hash context
 *
 * @return hash context
 */
#define CRYPT_DEFAULT_DigestCopy HITLS_CRYPT_DigestCopy

/**
 * @brief Release the hash context.
 *
 * @param ctx [IN] Hash context. The CTX is set NULL by the invoker.
 */
#define CRYPT_DEFAULT_DigestFree HITLS_CRYPT_DigestFree

/**
 * @brief Add the hash input data.
 *
 * @param ctx [IN] hash Context
 * @param data [IN] Input data
 * @param len [IN] Length of the input data
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#define CRYPT_DEFAULT_DigestUpdate HITLS_CRYPT_DigestUpdate

/**
 * @brief Calculate the hash result.
 *
 * @param ctx [IN] hash context
 * @param out [OUT] Output data
 * @param len [IN/OUT] IN: Maximum length of data padding OUT: Length of output data
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#define CRYPT_DEFAULT_DigestFinal HITLS_CRYPT_DigestFinal

/**
 * @brief hash function
 *
 * @param hashAlgo [IN] hash algorithm
 * @param in [IN] Input data
 * @param inLen [IN] Input data length
 * @param out [OUT] Output data
 * @param outLen [IN/OUT] IN: Maximum length of data padding OUT: Output data length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_Digest(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Encryption
 *
 * @param cipher [IN] Key parameters
 * @param in [IN] Plaintext data
 * @param inLen [IN] Length of the plaintext data
 * @param out [OUT] Ciphertext data
 * @param outLen [IN/OUT] IN: Maximum length of data padding OUT: Length of ciphertext data
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_Encrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Decrypt
 *
 * @param cipher [IN] Key parameters
 * @param in [IN] Ciphertext data
 * @param inLen [IN] Length of the ciphertext data
 * @param out [OUT] Plaintext data
 * @param outLen [IN/OUT] IN: Maximum length of data padding OUT: Length of plaintext data
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_Decrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Release the cipher ctx.
 *
 * @param ctx [IN] cipher ctx handle. The handle is set NULL by the invoker.
 */
#define CRYPT_DEFAULT_CipherFree HITLS_CRYPT_CipherFree

/**
 * @brief Generate the ECDH key pair.
 * 
 * @param ctx [IN] ssl ctx handle.
 * @param curveParams [IN] ECDH parameter
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateEcdhKey(HITLS_Ctx *ctx, const HITLS_ECParameters *curveParams);

/**
 * @brief Generate a DH key pair.
 *
 * @param secbits [IN] Key security level
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateDhKeyBySecbits(int32_t secbits);

/**
 * @brief Generate a DH key pair.
 *
 * @param p [IN] p Parameter
 * @param plen [IN] p Parameter length
 * @param g [IN] g Parameter
 * @param glen [IN] g Parameter length
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateDhKeyByParameters(uint8_t *p, uint16_t pLen, uint8_t *g, uint16_t gLen);

/**
 * @brief Obtain the DH parameter.
 *
 * @param key [IN] Key handle
 * @param p [OUT] p Parameter
 * @param plen [IN/OUT] IN: Maximum length of data padding OUT: p Parameter length
 * @param g [OUT] g Parameter
 * @param glen [IN/OUT] IN: Maximum length of data padding OUT: g Parameter length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#ifdef HITLS_TLS_SUITE_KX_DHE
#define CRYPT_DEFAULT_GetDhParameters HITLS_CRYPT_GetDhParameters
#else
#define CRYPT_DEFAULT_GetDhParameters NULL
#endif /* HITLS_TLS_SUITE_KX_DHE */

/**
 * @brief Deep copy key
 *
 * @param key [IN] Key handle
 */
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
#define CRYPT_DEFAULT_DupKey HITLS_CRYPT_DupKey
#endif

/**
 * @brief Release the key.
 *
 * @param key [IN] Key handle. The key is set NULL by the invoker.
 */
#define CRYPT_DEFAULT_FreeKey HITLS_CRYPT_FreeKey

/**
 * @brief Obtain the public key data.
 *
 * @param key [IN] Key handle
 * @param pubKeyBuf [OUT] Public key data
 * @param bufLen [IN] Maximum length of data padding.
 * @param usedLen [OUT] Public key data length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#define CRYPT_DEFAULT_GetPubKey HITLS_CRYPT_GetPubKey

/**
 * @brief Calculate the shared key. Ref RFC 5246 section 8.1.2, this interface will remove the pre-zeros.
 *
 * @param key [IN] Local key handle
 * @param peerPubkey [IN] Peer public key data
 * @param pubKeyLen [IN] Public key data length
 * @param sharedSecret [OUT] Shared key
 * @param sharedSecretLen [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_DhCalcSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief Calculate the shared key. Ref RFC 8446 section 7.4.1, this interface will retain the leading zeros.
 * after calculation.
 *
 * @param key [IN] Local key handle
 * @param peerPubkey [IN] Peer public key data
 * @param pubKeyLen [IN] Public key data length
 * @param sharedSecret [OUT] Shared key
 * @param sharedSecretLen [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_EcdhCalcSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief Calculate the SM2 shared key.
 *
 * @param sm2Params [IN] SM2 parameters
 * @param sharedSecret [OUT] Shared key
 * @param sharedSecretLen [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_CalcSM2SharedSecret(HITLS_Sm2GenShareKeyParameters *sm2Params,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief HKDF-Extract
 *
 * @param input [IN] Input key material.
 * @param prk [OUT] Output key
 * @param prkLen [IN/OUT] IN: Maximum buffer length OUT: Output key length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_HkdfExtract(const HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen);

/**
 * @brief HKDF-Expand
 *
 * @param input [IN] Input key material.
 * @param okm [OUT] Output key
 * @param okmLen [IN] Output key length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
int32_t CRYPT_DEFAULT_HkdfExpand(const HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen);

/**
 * @brief KEM-Encapsulate
 *
 * @param params [IN] KEM encapsulation parameters
 *
 * @retval HITLS_SUCCESS succeeded.
 */
int32_t CRYPT_DEFAULT_KemEncapsulate(HITLS_KemEncapsulateParams *params);

/**
 * @brief KEM-Decapsulate
 *
 * @param key [IN] Key handle
 * @param ciphertext [IN] Ciphertext data
 * @param ciphertextLen [IN] Ciphertext data length
 * @param sharedSecret [OUT] Shared key
 * @param sharedSecretLen [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval Other         failure
 */
#ifdef HITLS_TLS_FEATURE_KEM
#define CRYPT_DEFAULT_KemDecapsulate HITLS_CRYPT_KemDecapsulate
#endif /* HITLS_TLS_FEATURE_KEM */

#ifdef __cplusplus
}
#endif
#endif