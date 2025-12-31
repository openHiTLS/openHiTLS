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
#include "tls.h"
#include "hitls_crypt_reg.h"

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
    HITLS_Lib_Ctx *libCtx;
    const char *attrName;
} CRYPT_KeyDeriveParameters;

enum HITLS_CryptoCallBack {
    HITLS_CRYPT_CALLBACK_RAND_BYTES = 0,
    HITLS_CRYPT_CALLBACK_HMAC_SIZE,
    HITLS_CRYPT_CALLBACK_HMAC_INIT,
    HITLS_CRYPT_CALLBACK_HMAC_FREE,
    HITLS_CRYPT_CALLBACK_HMAC_UPDATE,
    HITLS_CRYPT_CALLBACK_HMAC_FINAL,
    HITLS_CRYPT_CALLBACK_HMAC,
    HITLS_CRYPT_CALLBACK_DIGEST_SIZE,
    HITLS_CRYPT_CALLBACK_DIGEST_INIT,
    HITLS_CRYPT_CALLBACK_DIGEST_COPY,
    HITLS_CRYPT_CALLBACK_DIGEST_FREE,
    HITLS_CRYPT_CALLBACK_DIGEST_UPDATE,
    HITLS_CRYPT_CALLBACK_DIGEST_FINAL,
    HITLS_CRYPT_CALLBACK_DIGEST,
    HITLS_CRYPT_CALLBACK_ENCRYPT,
    HITLS_CRYPT_CALLBACK_DECRYPT,

    HITLS_CRYPT_CALLBACK_GENERATE_ECDH_KEY_PAIR,
    HITLS_CRYPT_CALLBACK_FREE_ECDH_KEY,
    HITLS_CRYPT_CALLBACK_GET_ECDH_ENCODED_PUBKEY,
    HITLS_CRYPT_CALLBACK_CALC_ECDH_SHARED_SECRET,
    HITLS_CRYPT_CALLBACK_SM2_CALC_ECDH_SHARED_SECRET,

    HITLS_CRYPT_CALLBACK_GENERATE_DH_KEY_BY_SECBITS,
    HITLS_CRYPT_CALLBACK_GENERATE_DH_KEY_BY_PARAMS,
    HITLS_CRYPT_CALLBACK_DUP_DH_KEY,
    HITLS_CRYPT_CALLBACK_FREE_DH_KEY,
    HITLS_CRYPT_CALLBACK_DH_GET_PARAMETERS,
    HITLS_CRYPT_CALLBACK_GET_DH_ENCODED_PUBKEY,
    HITLS_CRYPT_CALLBACK_CALC_DH_SHARED_SECRET,

    HITLS_CRYPT_CALLBACK_HKDF_EXTRACT,
    HITLS_CRYPT_CALLBACK_HKDF_EXPAND,
    HITLS_CRYPT_CALLBACK_KEM_ENCAPSULATE,
    HITLS_CRYPT_CALLBACK_KEM_DECAPSULATE,
};

/**
 * @brief Generate a random number.
 *
 * @param libCtx [IN] Library context, used to manage cryptographic operations.
 * @param buf [OUT] Random number
 * @param len [IN] Random number length
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      Unregistered callback
 * @retval HITLS_CRYPT_ERR_GENRATE_RANDOM   Failed to generate a random number.
 */
int32_t SAL_CRYPT_Rand(HITLS_Lib_Ctx *libCtx, uint8_t *buf, uint32_t len);

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
 * This function initializes the HMAC (Hash-based Message Authentication Code) context
 * using the specified hash algorithm and key. It prepares the necessary state for
 * subsequent HMAC operations.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
 * @param hashAlgo   [IN] Hash algorithm to be used in the HMAC operation, e.g., HITLS_SHA256.
 * @param key        [IN] Secret key used for HMAC calculation.
 * @param len        [IN] Length of the secret key in bytes.
 *
 * @return HMAC context
 *         Returns a pointer to the initialized HMAC context.
 *         Returns NULL if the initialization fails.
 */
HITLS_HMAC_Ctx *SAL_CRYPT_HmacInit(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len);

/**
 * @brief ReInitialize the HMAC context.
 *
 * @param ctx [IN] HMAC context
 *
 * @retval HITLS_SUCCESS       succeeded.
 */
int32_t SAL_CRYPT_HmacReInit(HITLS_HMAC_Ctx *ctx);

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
 * This function calculates the HMAC (Hash-based Message Authentication Code) using the specified hash algorithm and
 * key. It takes input data and produces an output HMAC value.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
 * @param hashAlgo   [IN] Hash algorithm to be used in the HMAC operation, e.g., HITLS_SHA256.
 * @param key        [IN] Secret key used for HMAC calculation.
 * @param keyLen     [IN] Length of the secret key in bytes.
 * @param in         [IN] Input data to be processed for HMAC calculation.
 * @param inLen      [IN] Length of the input data in bytes.
 * @param out        [OUT] Buffer to store the calculated HMAC output.
 * @param outLen     [IN/OUT] IN: Maximum length of the output buffer. OUT: Actual length of the calculated HMAC output.
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HMAC         The HMAC operation fails.
 */
int32_t SAL_CRYPT_Hmac(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
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
 * This function initializes a new hash context using the specified hash algorithm.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                        algorithm provided by the algorithm provider
 * @param hashAlgo   [IN] hash algorithm
 *                   The hash algorithm to be used for the calculation. This can be
 *                   one of the predefined hash algorithms, such as HITLS_SHA256.
 *
 * @return hash context
 *         Returns a pointer to the initialized hash context.
 *         Returns NULL if the initialization fails, for example, if there is not
 *         enough memory available or if the specified hash algorithm is not supported.
 */
HITLS_HASH_Ctx *SAL_CRYPT_DigestInit(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_HashAlgo hashAlgo);

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
 * This function calculates the hash of the input data using the specified hash algorithm.
 * It takes input data and produces an output hash value.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                    algorithm provided by the algorithm provider
 * @param hashAlgo   [IN] hash algorithm
 *                   The hash algorithm to be used for the calculation. This can be
 *                   one of the predefined hash algorithms, such as HITLS_SHA256.
 * @param in         [IN] Input data
 *                   The data to be hashed. This can be any sequence of bytes.
 * @param inLen      [IN] Length of the input data
 *                   The length of the input data in bytes.
 * @param out        [OUT] Output data
 *                   The buffer where the calculated hash value will be stored.
 *                   The buffer must be large enough to hold the entire hash value.
 * @param outLen     [IN/OUT] IN: Maximum length of data padding OUT: Length of output data
 *                   On input, this parameter specifies the maximum length of the output buffer.
 *                   On output, it contains the actual length of the calculated hash value.
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST       hash operation failed.
 */
int32_t SAL_CRYPT_Digest(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @brief Encryption
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
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
int32_t SAL_CRYPT_Encrypt(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Decrypt
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
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
int32_t SAL_CRYPT_Decrypt(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Release the cipher ctx.
 *
 * @param ctx [IN] cipher ctx handle
 */
void SAL_CRYPT_CipherFree(HITLS_Cipher_Ctx *ctx);

/**
 * @brief Generate the ECDH key pair.
 *
 * @param curveParams [IN] Elliptic curve parameter
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_GenEcdhKeyPair(TLS_Ctx *ctx, const HITLS_ECParameters *curveParams);

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
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
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
int32_t SAL_CRYPT_CalcEcdhSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief SM2 calculates the ECDH shared key.
 *
 * @param libCtx            [IN] Library context, used to manage cryptographic operations.
 * @param attrName          [IN] Attribute name, used to configure the cryptographic
 *                              algorithm provided by the algorithm provider
 * @param sm2ShareKeyParam  [IN] Parameters required for calculating the shared key
 * @param sharedSecret      [OUT] Shared key
 * @param sharedSecretLen   [IN/OUT] IN: Maximum length of data padding OUT: length of the shared key
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      Unregistered callback
 * @retval HITLS_CRYPT_ERR_CALC_SHARED_KEY  Failed to calculate the shared key.
 */
int32_t SAL_CRYPT_CalcSm2dhSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_Sm2GenShareKeyParameters *sm2ShareKeyParam, uint8_t *sharedSecret,
    uint32_t *sharedSecretLen);

/**
 * @brief Generate a DH key pair.
 *
 * @param ctx      [IN] TLS context
 * @param secbits  [IN] Key security level
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyBySecbits(TLS_Ctx *ctx,
    int32_t secBits);

/**
 * @brief Generate a DH key pair.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
 * @param p          [IN] p Parameter
 * @param plen       [IN] p Parameter length
 * @param g          [IN] g Parameter
 * @param glen       [IN] g Parameter length
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *SAL_CRYPT_GenerateDhKeyByParams(HITLS_Lib_Ctx *libCtx,
    const char *attrName, uint8_t *p, uint16_t plen, uint8_t *g, uint16_t glen);

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
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
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
int32_t SAL_CRYPT_CalcDhSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief HKDF-Extract
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
 * @param input      [IN] Input key material
 * @param prk        [OUT] Output key
 * @param prkLen     [IN/OUT] IN: Maximum buffer length OUT: Output key length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT calculation fails.
 */
int32_t SAL_CRYPT_HkdfExtract(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen);

/**
 * @brief   HKDF-Expand
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, used to configure the cryptographic
 *                      algorithm provided by the algorithm provider
 * @param input      [IN] Input key material
 * @param okm        [OUT] Output key
 * @param okmLen     [IN] Output key length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND  calculation fails.
 */
int32_t SAL_CRYPT_HkdfExpand(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen);

/**
 * @brief   HKDF-ExpandLabel
 *
 * @param deriveInfo [IN] Key derivation parameters, including hash algorithm, secret, label, seed, etc.
 * @param outSecret  [OUT] Output key buffer
 * @param outLen     [IN]  Output key length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT calculation fails.
 * @retval HITLS_MEMCPY_FAIL            Memory Copy Failure
 */
int32_t SAL_CRYPT_HkdfExpandLabel(CRYPT_KeyDeriveParameters *deriveInfo,
    uint8_t *outSecret, uint32_t outLen);

/**
 * @brief Encapsulate a shared secret using KEM
 *
 * @param ctx [IN] TLS context
 * @param params [IN/OUT] KEM encapsulation parameters
 *
 * @retval HITLS_SUCCESS succeeded.
 */
int32_t SAL_CRYPT_KemEncapsulate(TLS_Ctx *ctx, HITLS_KemEncapsulateParams *params);

/**
 * @brief   KEM: Decapsulate the ciphertext to recover shared secret
 *
 * @param   key [IN] Key handle
 * @param   ciphertext [IN] Ciphertext buffer
 * @param   ciphertextLen [IN] Ciphertext length
 * @param   sharedSecret [OUT] Shared secret buffer
 * @param   sharedSecretLen [IN/OUT] IN: Maximum shared secret buffer length OUT: Actual shared secret length
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK  Unregistered callback
 * @retval HITLS_CRYPT_ERR_KEM_DECAP    Failed to decapsulate ciphertext
 */
int32_t SAL_CRYPT_KemDecapsulate(HITLS_CRYPT_Key *key, const uint8_t *ciphertext, uint32_t ciphertextLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);


#ifdef __cplusplus
}
#endif
#endif
