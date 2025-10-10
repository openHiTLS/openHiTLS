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

#ifndef HITLS_CRYPT_H
#define HITLS_CRYPT_H
#include <stdint.h>
#include "hitls_crypt_type.h"
#include "hitls_crypt_reg.h"
#include "crypt.h"
#ifdef __cplusplus
extern "C" {
#endif

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
int32_t HITLS_CRYPT_HMAC(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_HashAlgo hashAlgo, const uint8_t *key,
    uint32_t keyLen, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

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
int32_t HITLS_CRYPT_Digest(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_HashAlgo hashAlgo, const uint8_t *in,
    uint32_t inLen, uint8_t *out, uint32_t *outLen);

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
 * This function calculates the shared secret using the given library context, attribute name, local key handle,
 * peer public key data, and its length. Ref RFC 5246 section 8.1.2, this interface will remove the pre-zeros.
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
int32_t HITLS_CRYPT_DhCalcSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_CRYPT_Key *key,
    uint8_t *peerPubkey, uint32_t pubKeyLen, uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief Calculate the shared secret.
 *
 * This function calculates the shared secret using the given library context, attribute name, local key handle,
 * peer public key data, and its length. Ref RFC 8446 section 7.4.1, this interface will retain the leading zeros.
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
int32_t HITLS_CRYPT_EcdhCalcSharedSecret(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_CRYPT_Key *key,
    uint8_t *peerPubkey, uint32_t pubKeyLen, uint8_t *sharedSecret, uint32_t *sharedSecretLen);

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
    HITLS_Sm2GenShareKeyParameters *sm2Params, uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief Generate a DH key pair based on the security level.
 *
 * This function generates a DH key pair using the given library context, attribute name, configuration, and named group
 * ID.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param tlsConfig  [IN] TLS configuration.
 * @param secBits    [IN] Security level.
 *
 * @return Key handle
 *         Returns a pointer to the generated DH key pair handle.
 *         Returns NULL if the key generation fails.
 */
HITLS_CRYPT_Key *HITLS_CRYPT_GenerateDhKeyBySecbits(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_Config *tlsConfig, int32_t secBits);

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
 * This function performs the HKDF expand operation using the given library context, attribute name, and HKDF expand
 * input.
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
int32_t HITLS_CRYPT_HkdfExpand(HITLS_Lib_Ctx *libCtx, const char *attrName, const HITLS_CRYPT_HkdfExpandInput *input,
    uint8_t *okm, uint32_t okmLen);

/**
 * @brief HKDF extract function.
 *
 * This function performs the HKDF extract operation using the given library context, attribute name, and HKDF extract
 * input.
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
int32_t HITLS_CRYPT_HkdfExtract(HITLS_Lib_Ctx *libCtx, const char *attrName, const HITLS_CRYPT_HkdfExtractInput *input,
    uint8_t *prk, uint32_t *prkLen);

/**
 * @brief Generate a sequence of random bytes of the specified length.
 *
 * This function is used to generate a sequence of random bytes of the specified length
 * and store it in the provided buffer. It uses the passed library context for random number generation.
 *
 * @param libCtx [IN] Library context, used to manage cryptographic operations.
 * @param bytes [OUT] Buffer used to store the generated random byte sequence.
 * @param bytesLen [IN] Length (in bytes) of the random byte sequence to be generated.
 *
 * @retval Returns HITLS_SUCCESS on success, and other error codes on failure.
 */
int32_t HITLS_CRYPT_RandbytesEx(HITLS_Lib_Ctx *libCtx, uint8_t *bytes, uint32_t bytesLen);

/**
 * @brief Initialize the hash context.
 *
 * This function initializes the hash context with the given library context, attribute name, and hash algorithm.
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations.
 * @param attrName   [IN] Attribute name, which may be used for specific configuration.
 * @param hashAlgo   [IN] Hash algorithm to be used in the hash operation, e.g., HITLS_SHA256.
 */
HITLS_HASH_Ctx *HITLS_CRYPT_DigestInit(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_HashAlgo hashAlgo);

/**
 * @brief Free DH key structure.
 *
 * @param key [IN] Pointer to DH key structure to be freed.
 */
void HITLS_CRYPT_FreeKey(HITLS_CRYPT_Key *key);

/**
 * @brief Get DH parameters from key.
 *
 * @param key  [IN] DH key structure.
 * @param p    [OUT] Prime modulus parameter.
 * @param pLen [IN/OUT] IN: Buffer length, OUT: Actual length of prime modulus.
 * @param g    [OUT] Generator parameter.
 * @param gLen [IN/OUT] IN: Buffer length, OUT: Actual length of generator.
 *
 * @retval HITLS_SUCCESS  Succeeded.
 * @retval Other          Failed.
 */
int32_t HITLS_CRYPT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *pLen, uint8_t *g, uint16_t *gLen);


/**
 * @brief Reinitialize an HMAC context for reuse.
 * 
 * @param ctx [IN] HMAC context to reinitialize.
 * @retval HITLS_SUCCESS  Reinitialization succeeded.
 * @retval Other          Failed to reinitialize context.
 */
int32_t HITLS_CRYPT_HMAC_ReInit(HITLS_HMAC_Ctx *ctx);

/**
 * @brief Free an HMAC context.
 * 
 * @param ctx [IN] HMAC context to free.
 */
void HITLS_CRYPT_HMAC_Free(HITLS_HMAC_Ctx *ctx);

/**
 * @brief Update HMAC computation with input data.
 * 
 * @param ctx  [IN] HMAC context.
 * @param data [IN] Input data to process.
 * @param len  [IN] Length of input data in bytes.
 * @retval HITLS_SUCCESS  Update succeeded.
 * @retval Other          Failed to update HMAC.
 */
int32_t HITLS_CRYPT_HMAC_Update(HITLS_HMAC_Ctx *ctx, const uint8_t *data, uint32_t len);

/**
 * @brief Finalize HMAC computation and get the MAC value.
 * 
 * @param ctx [IN] HMAC context.
 * @param out [OUT] Buffer to store the MAC value.
 * @param len [IN/OUT] IN: Buffer size, OUT: Actual MAC length.
 * @retval HITLS_SUCCESS  Finalization succeeded.
 * @retval Other          Failed to finalize HMAC.
 */
int32_t HITLS_CRYPT_HMAC_Final(HITLS_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len);

/**
 * @brief Get the output size of a hash algorithm.
 * 
 * @param hashAlgo [IN] Hash algorithm identifier.
 * @return Digest size in bytes. Returns 0 for unsupported algorithms.
 */
uint32_t HITLS_CRYPT_DigestSize(HITLS_HashAlgo hashAlgo);

/**
 * @brief Create a copy of a hash context.
 * 
 * @param ctx [IN] Original hash context to copy.
 * @return New hash context copy. Returns NULL on failure.
 */
HITLS_HASH_Ctx *HITLS_CRYPT_DigestCopy(HITLS_HASH_Ctx *ctx);

/**
 * @brief Free a hash context.
 * 
 * @param ctx [IN] Hash context to free.
 */
void HITLS_CRYPT_DigestFree(HITLS_HASH_Ctx *ctx);

/**
 * @brief Update hash computation with input data.
 * 
 * @param ctx  [IN] Hash context.
 * @param data [IN] Input data to process.
 * @param len  [IN] Length of input data in bytes.
 * @retval HITLS_SUCCESS  Update succeeded.
 * @retval Other          Failed to update hash.
 */
int32_t HITLS_CRYPT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len);

/**
 * @brief Finalize hash computation and get the digest.
 * 
 * @param ctx [IN] Hash context.
 * @param out [OUT] Buffer to store the digest.
 * @param len [IN/OUT] IN: Buffer size, OUT: Actual digest length.
 * @retval HITLS_SUCCESS  Finalization succeeded.
 * @retval Other          Failed to finalize hash.
 */
int32_t HITLS_CRYPT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len);

/**
 * @brief Free a cipher context.
 * 
 * @param ctx [IN] Cipher context to free.
 */
void HITLS_CRYPT_CipherFree(HITLS_Cipher_Ctx *ctx);

/**
 * @brief Create a copy of a cryptographic key.
 * 
 * @param key [IN] Original key to duplicate.
 * @return New key handle copy. Returns NULL on failure.
 */
HITLS_CRYPT_Key *HITLS_CRYPT_DupKey(HITLS_CRYPT_Key *key);

/**
 * @brief Get the public key of a cryptographic key.
 * 
 * @param key [IN] Key to get public key from.
 * @param pubKeyBuf [OUT] Buffer to store the public key.
 * @param bufLen [IN] Buffer length.
 * @param pubKeyLen [IN/OUT] IN: Buffer length, OUT: Actual public key length.
 * @retval HITLS_SUCCESS  Succeeded.
 * @retval Other          Failed.
 */
int32_t HITLS_CRYPT_GetPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen);

/**
 * @brief KEM-Encapsulate
 *
 * @param libCtx     [IN] Library context, used to manage cryptographic operations
 * @param attrName   [IN] Attribute name, used to configure the cryptographic algorithm
 * @param config     [IN] TLS configuration
 * @param params     [IN] KEM encapsulation parameters
 *
 * @retval HITLS_SUCCESS succeeded.
 */
int32_t HITLS_CRYPT_KemEncapsulate(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_Config *config, HITLS_KemEncapsulateParams *params);

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
int32_t HITLS_CRYPT_KemDecapsulate(HITLS_CRYPT_Key *key, const uint8_t *ciphertext, uint32_t ciphertextLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @brief PRF function
 *
 * @param input [IN] Key derivation parameter
 * @param out [OUT] Output key
 * @param outLen [IN] Output key length
 *
 * @retval HITLS_SUCCESS succeeded.
 */
int32_t HITLS_CRYPT_PRF(CRYPT_KeyDeriveParameters *input, uint8_t *out, uint32_t outLen);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPT_H */
