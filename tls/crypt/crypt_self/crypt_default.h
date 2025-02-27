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
int32_t CRYPT_DEFAULT_RandomBytes(uint8_t *buf, uint32_t len);

/**
 * @brief Obtain the HMAC length.
 *
 * @param hashAlgo [IN] hash algorithm
 *
 * @return HMAC length
 */
uint32_t CRYPT_DEFAULT_HMAC_Size(HITLS_HashAlgo hashAlgo);

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
int32_t CRYPT_DEFAULT_HMAC_ReInit(HITLS_HMAC_Ctx *ctx);

/**
 * @brief Release the HMAC context.
 *
 * @param hmac [IN] HMAC context. The CTX is set NULL by the invoker.
 */
void CRYPT_DEFAULT_HMAC_Free(HITLS_HMAC_Ctx *ctx);

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
int32_t CRYPT_DEFAULT_HMAC_Update(HITLS_HMAC_Ctx *ctx, const uint8_t *data, uint32_t len);

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
int32_t CRYPT_DEFAULT_HMAC_Final(HITLS_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len);

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
uint32_t CRYPT_DEFAULT_DigestSize(HITLS_HashAlgo hashAlgo);

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
HITLS_HASH_Ctx *CRYPT_DEFAULT_DigestCopy(HITLS_HASH_Ctx *ctx);

/**
 * @brief Release the hash context.
 *
 * @param ctx [IN] Hash context. The CTX is set NULL by the invoker.
 */
void CRYPT_DEFAULT_DigestFree(HITLS_HASH_Ctx *ctx);

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
int32_t CRYPT_DEFAULT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len);

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
int32_t CRYPT_DEFAULT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len);

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
void CRYPT_DEFAULT_CipherFree(HITLS_Cipher_Ctx *ctx);
/**
 * @brief Generate the ECDH key pair.
 *
 * @param curveParams [IN] ECDH parameter
 *
 * @return Key handle
 */
HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateEcdhKey(const HITLS_ECParameters *curveParams);

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
int32_t CRYPT_DEFAULT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *pLen, uint8_t *g, uint16_t *gLen);

/**
 * @brief Deep copy key
 *
 * @param key [IN] Key handle
 * @retval Key handle
 */
HITLS_CRYPT_Key *CRYPT_DEFAULT_DupKey(HITLS_CRYPT_Key *key);

/**
 * @brief Release the key.
 *
 * @param key [IN] Key handle. The key is set NULL by the invoker.
 */
void CRYPT_DEFAULT_FreeKey(HITLS_CRYPT_Key *key);

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
int32_t CRYPT_DEFAULT_GetPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen);

/**
 * @brief Calculate the shared key.
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
int32_t CRYPT_DEFAULT_CalcSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
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
 * @brief Initialize the HMAC context.
 *
 * This function initializes the HMAC (Hash-based Message Authentication Code) context
 * with the given library context, attribute name, hash algorithm, key, and key length.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param hashAlgo   [IN] Hash algorithm to be used in the HMAC operation, e.g., HITLS_SHA256.
 * @param key        [IN] Secret key used for HMAC calculation.
 * @param len        [IN] Length of the secret key in bytes.
 *
 * @return HMAC context
 *         Returns a pointer to the initialized HMAC context.
 *         Returns NULL if the initialization fails.
 */
HITLS_HMAC_Ctx *HITLS_CRYPT_HMAC_Init(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len);

/**
 * @brief Perform HMAC calculation.
 *
 * This function calculates the HMAC (Hash-based Message Authentication Code)
 * using the given library context, attribute name, hash algorithm, key, input data,
 * and stores the result in the output buffer.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param hashAlgo   [IN] Hash algorithm to be used in the HMAC operation, e.g., HITLS_SHA256.
 * @param key        [IN] Secret key used for HMAC calculation.
 * @param keyLen     [IN] Length of the secret key in bytes.
 * @param in         [IN] Input data to be processed for HMAC calculation.
 * @param inLen      [IN] Length of the input data in bytes.
 * @param out        [OUT] Buffer to store the calculated HMAC output.
 * @param outLen     [IN/OUT] IN: Maximum length of the output buffer. OUT: Actual length of the calculated HMAC output.
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval Other                        failure
 */
int32_t HITLS_CRYPT_HMAC(HITLS_Lib_Ctx *libCtx, const char *attrName,
        HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
        const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @brief Initialize the hash context.
 *
 * This function initializes the hash context with the given hash algorithm.
 *
 * @param hashAlgo   [IN] Hash algorithm to be used in the hash operation, e.g., HITLS_SHA256.
 *
 * @return hash context
 *         Returns a pointer to the initialized hash context.
 *         Returns NULL if the initialization fails.
 */
HITLS_HASH_Ctx *CRYPT_DEFAULT_DigestInit(HITLS_HashAlgo hashAlgo);

/**
 * @brief Perform hash calculation.
 *
 * This function calculates the hash of the input data using the given library context,
 * attribute name, hash algorithm, and stores the result in the output buffer.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param hashAlgo   [IN] Hash algorithm to be used in the hash operation, e.g., HITLS_SHA256.
 * @param in         [IN] Input data to be processed for hash calculation.
 * @param inLen      [IN] Length of the input data in bytes.
 * @param out        [OUT] Buffer to store the calculated hash output.
 * @param outLen     [IN/OUT] IN: Maximum length of the output buffer. OUT: Actual length of the calculated hash output.
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval Other                        failure
 */
int32_t HITLS_CRYPT_Digest(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Perform encryption operation.
 *
 * This function encrypts the input data using the given library context, attribute name,
 * cipher parameters, and stores the encrypted data in the output buffer.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param cipher     [IN] Key parameters for the encryption operation.
 * @param in         [IN] Plaintext data to be encrypted.
 * @param inLen      [IN] Length of the plaintext data in bytes.
 * @param out        [OUT] Buffer to store the encrypted data (ciphertext).
 * @param outLen     [IN/OUT] IN: Maximum length of the output buffer. OUT: Actual length of the encrypted data.
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval Other                        failure
 */
int32_t HITLS_CRYPT_Encrypt(HITLS_Lib_Ctx *libCtx, const char *attrName, const HITLS_CipherParameters *cipher,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @brief Perform decryption operation.
 *
 * This function decrypts the input ciphertext using the given library context, attribute name,
 * cipher parameters, and stores the decrypted data in the output buffer.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param cipher     [IN] Key parameters for the decryption operation.
 * @param in         [IN] Ciphertext data to be decrypted.
 * @param inLen      [IN] Length of the ciphertext data in bytes.
 * @param out        [OUT] Buffer to store the decrypted data (plaintext).
 * @param outLen     [IN/OUT] IN: Maximum length of the output buffer. OUT: Actual length of the decrypted data.
 *
 * @retval HITLS_SUCCESS                succeeded.
 * @retval Other                        failure
 */
int32_t HITLS_CRYPT_Decrypt(HITLS_Lib_Ctx *libCtx, const char *attrName, const HITLS_CipherParameters *cipher,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @brief Generate an ECDH key pair.
 *
 * This function generates an ECDH (Elliptic Curve Diffie-Hellman) key pair
 * using the given library context, attribute name, configuration, and curve parameters.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param config     [IN] Configuration for the ECDH key generation.
 * @param curveParams [IN] ECDH parameter specifying the elliptic curve.
 *
 * @return Key handle
 *         Returns a pointer to the generated ECDH key handle.
 *         Returns NULL if the key generation fails.
 */
HITLS_CRYPT_Key *HITLS_CRYPT_GenerateEcdhKey(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_Config *config, const HITLS_ECParameters *curveParams);


/**
 * @brief Calculate the shared secret.
 *
 * This function calculates the shared secret using the given library context, attribute name, local key handle, peer public key data, and its length.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param key        [IN] Local key handle.
 * @param peerPubkey [IN] Peer public key data.
 * @param pubKeyLen  [IN] Length of the peer public key data.
 * @param sharedSecret [OUT] Buffer to store the shared secret.
 * @param sharedSecretLen [IN/OUT] IN: Maximum length of the buffer. OUT: Actual length of the shared secret.
 *
 * @retval HITLS_SUCCESS  Succeeded.
 * @retval Other          Failed.
 */
int32_t HITLS_CRYPT_CalcSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief Calculate the SM2 shared secret.
 *
 * This function calculates the SM2 shared secret using the given library context, attribute name, and SM2 parameters.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param sm2Params  [IN] Parameters for SM2 shared key generation.
 * @param sharedSecret [OUT] Buffer to store the shared secret.
 * @param sharedSecretLen [IN/OUT] IN: Maximum length of the buffer. OUT: Actual length of the shared secret.
 *
 * @retval HITLS_SUCCESS  Succeeded.
 * @retval Other          Failed.
 */
int32_t HITLS_CRYPT_CalcSM2SharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_Sm2GenShareKeyParameters *sm2Params, uint8_t *sharedSecret,
    uint32_t *sharedSecretLen);

/**
 * @brief Generate a DH key pair based on the security level.
 *
 * This function generates a DH key pair using the given library context, attribute name, configuration, and named group ID.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param paraId    [IN] param ID.
 *
 * @return Key handle
 *         Returns a pointer to the generated DH key pair handle.
 *         Returns NULL if the key generation fails.
 */
HITLS_CRYPT_Key *HITLS_CRYPT_GenerateDhKeyBySecbits(HITLS_Lib_Ctx *libCtx,
    const char *attrName, int32_t paraId);

/**
 * @brief Generate a DH key pair based on parameters.
 *
 * This function generates a DH key pair using the given library context, attribute name, p parameter, and g parameter.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param p          [IN] p parameter.
 * @param pLen       [IN] Length of the p parameter.
 * @param g          [IN] g parameter.
 * @param gLen       [IN] Length of the g parameter.
 *
 * @return Key handle
 *         Returns a pointer to the generated DH key pair handle.
 *         Returns NULL if the key generation fails.
 */
HITLS_CRYPT_Key *HITLS_CRYPT_GenerateDhKeyByParameters(HITLS_Lib_Ctx *libCtx,
    const char *attrName, uint8_t *p, uint16_t pLen, uint8_t *g, uint16_t gLen);

/**
 * @brief HKDF expand function.
 *
 * This function performs the HKDF expand operation using the given library context, attribute name, and HKDF expand input.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param input      [IN] HKDF expand input.
 * @param okm        [OUT] Buffer to store the output key.
 * @param okmLen     [IN] Length of the output key.
 *
 * @retval HITLS_SUCCESS  Succeeded.
 * @retval Other          Failed.
 */
int32_t HITLS_CRYPT_HkdfExpand(HITLS_Lib_Ctx *libCtx,
    const char *attrName, const HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen);

/**
 * @brief HKDF extract function.
 *
 * This function performs the HKDF extract operation using the given library context, attribute name, and HKDF extract input.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param input      [IN] HKDF extract input.
 * @param prk        [OUT] Buffer to store the output key.
 * @param prkLen     [IN/OUT] IN: Maximum length of the buffer. OUT: Actual length of the output key.
 *
 * @retval HITLS_SUCCESS  Succeeded.
 * @retval Other          Failed.
 */
int32_t HITLS_CRYPT_HkdfExtract(HITLS_Lib_Ctx *libCtx,
        const char *attrName, const HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen);


#ifdef __cplusplus
}
#endif
#endif