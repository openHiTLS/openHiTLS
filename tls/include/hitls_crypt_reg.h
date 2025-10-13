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

/**
 * @defgroup hitls_crypt_reg
 * @ingroup hitls
 * @brief  Algorithm related interfaces to be registered
 */

#ifndef HITLS_CRYPT_REG_H
#define HITLS_CRYPT_REG_H

#include <stdint.h>
#include "hitls_type.h"
#include "hitls_crypt_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Input parameters for KEM encapsulation
 */
typedef struct {
    HITLS_NamedGroup groupId;      /**< Named group ID */
    uint8_t *peerPubkey;           /**< Peer's public key */
    uint32_t pubKeyLen;            /**< Length of peer's public key */
    uint8_t *ciphertext;           /**< [OUT] Encapsulated ciphertext */
    uint32_t *ciphertextLen;       /**< [IN/OUT] IN: Maximum ciphertext buffer length OUT: Actual ciphertext length */
    uint8_t *sharedSecret;         /**< [OUT] Generated shared secret */
    uint32_t *sharedSecretLen;     /**< [IN/OUT] IN: Maximum shared secret buffer length OUT: Actual shared secret length */
} HITLS_KemEncapsulateParams;

/**
 * @ingroup hitls_crypt_reg
 * @brief   Obtain the random number.
 *
 * @param   buf [OUT] Random number
 * @param   len [IN] Random number length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_RandBytesCallback)(uint8_t *buf, uint32_t len);

/**
 * @ingroup hitls_crypt_reg
 * @brief   ECDH: Generate a key pair based on elliptic curve parameters.
 *
 * @param   ctx [IN] TLS object
 * @param   curveParams [IN] Elliptic curve parameter
 *
 * @retval  Key handle
 */
typedef HITLS_CRYPT_Key *(*CRYPT_GenerateEcdhKeyPairCallback)(HITLS_Ctx *ctx, const HITLS_ECParameters *curveParams);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the key.
 *
 * @param   key [IN] Key handle
 */
typedef void (*CRYPT_FreeEcdhKeyCallback)(HITLS_CRYPT_Key *key);

/**
 * @ingroup hitls_crypt_reg
 * @brief   ECDH: Extract the public key data.
 *
 * @param   key [IN] Key handle
 * @param   pubKeyBuf [OUT] Public key data
 * @param   bufLen [IN] Buffer length
 * @param   pubKeyLen [OUT] Public key data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_GetEcdhEncodedPubKeyCallback)(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen,
    uint32_t *pubKeyLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   ECDH: Calculate the shared key based on the local key and peer public key. Ref RFC 8446 section 7.4.1,
 * this callback should strip the leading zeros.
 *
 * @param   key [IN] Key handle
 * @param   peerPubkey [IN] Public key data
 * @param   pubKeyLen [IN] Public key data length
 * @param   sharedSecret [OUT] Shared key
 * @param   sharedSecretLen [IN/OUT] IN: Maximum length of the key padding OUT: Key length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_CalcEcdhSharedSecretCallback)(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   KEM: Encapsulate a shared secret using peer's public key.
 *
 * @param   params [IN/OUT] Parameters for KEM encapsulation
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_KemEncapsulateCallback)(HITLS_KemEncapsulateParams *params);
/**
 * @ingroup hitls_crypt_reg
 * @brief   KEM: Decapsulate the ciphertext to recover shared secret.
 *
 * @param   key [IN] Key handle
 * @param   ciphertext [IN] Ciphertext buffer
 * @param   ciphertextLen [IN] Ciphertext length
 * @param   sharedSecret [OUT] Shared secret buffer
 * @param   sharedSecretLen [IN/OUT] IN: Maximum length of the shared secret buffer OUT: Actual shared secret length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_KemDecapsulateCallback)(HITLS_CRYPT_Key *key, const uint8_t *ciphertext, uint32_t ciphertextLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   SM2 calculates the shared key based on the local key and peer public key.
 *
 * @param   sm2Params [IN] Shared key calculation parameters
 * @param   sharedSecret [OUT] Shared key
 * @param   sharedSecretLen [IN/OUT] IN: Maximum length of the key padding OUT: Key length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_Sm2CalcEcdhSharedSecretCallback)(HITLS_Sm2GenShareKeyParameters *sm2Params,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Generate a key pair based on secbits.
 *
 * @param   secbits [IN] Key security level
 *
 * @retval  Key handle
 */
typedef HITLS_CRYPT_Key *(*CRYPT_GenerateDhKeyBySecbitsCallback)(int32_t secbits);

/**
 * @ingroup hitls_crypt_reg
 * @brief   DH: Generate a key pair based on the dh parameter.
 *
 * @param   p [IN] p Parameter
 * @param   plen [IN] p Parameter length
 * @param   g [IN] g Parameter
 * @param   glen [IN] g Parameter length
 *
 * @retval  Key handle
 */
typedef HITLS_CRYPT_Key *(*CRYPT_GenerateDhKeyByParamsCallback)(uint8_t *p, uint16_t plen, uint8_t *g, uint16_t glen);

/**
 * @ingroup hitls_crypt_reg
 * @brief  Deep copy key
 *
 * @param   key [IN] Key handle
 * @retval  Key handle
 */
typedef HITLS_CRYPT_Key *(*CRYPT_DupDhKeyCallback)(HITLS_CRYPT_Key *key);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the key.
 *
 * @param   key [IN] Key handle
 */
typedef void (*CRYPT_FreeDhKeyCallback)(HITLS_CRYPT_Key *key);

/**
 * @ingroup hitls_crypt_reg
 * @brief   DH: Obtain p g plen glen by using the key handle.
 *
 * @attention If the p and g parameters are null pointers, only the lengths of p and g are obtained.
 *
 * @param   key [IN] Key handle
 * @param   p [OUT] p Parameter
 * @param   plen [IN/OUT] IN: Maximum length of data padding OUT: p Parameter length
 * @param   g [OUT] g Parameter
 * @param   glen [IN/OUT] IN: Maximum length of data padding OUT: g Parameter length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_DHGetParametersCallback)(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *plen,
    uint8_t *g, uint16_t *glen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   DH: Extract the Dh public key data.
 *
 * @param   key [IN] Key handle
 * @param   pubKeyBuf [OUT] Public key data
 * @param   bufLen [IN] Buffer length
 * @param   pubKeyLen [OUT] Public key data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_GetDhEncodedPubKeyCallback)(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen,
    uint32_t *pubKeyLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   DH: Calculate the shared key based on the local key and peer public key. Ref RFC 5246 section 8.1.2,
 * this callback should retain the leading zeros.
 *
 * @param   key [IN] Key handle
 * @param   peerPubkey [IN] Public key data
 * @param   pubKeyLen [IN] Public key data length
 * @param   sharedSecret [OUT] Shared key
 * @param   sharedSecretLen [IN/OUT] IN: Maximum length of the key padding OUT: Key length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_CalcDhSharedSecretCallback)(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Obtain the HMAC length based on the hash algorithm.
 *
 * @param   hashAlgo [IN] Hash algorithm
 *
 * @retval  HMAC length
 */
typedef uint32_t (*CRYPT_HmacSizeCallback)(HITLS_HashAlgo hashAlgo);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Initialize the HMAC context.
 *
 * @param   hashAlgo [IN] Hash algorithm
 * @param   key [IN] Key
 * @param   len [IN] Key length
 *
 * @retval  HMAC context
 */
typedef HITLS_HMAC_Ctx *(*CRYPT_HmacInitCallback)(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len);

/**
 * @ingroup hitls_crypt_reg
 * @brief   reinit the HMAC context.
 *
 * @param   ctx [IN] HMAC context
 *
 * @retval  HMAC context
 */
typedef int32_t (*CRYPT_HmacReInitCallback)(HITLS_HMAC_Ctx *ctx);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the HMAC context.
 *
 * @param   ctx [IN] HMAC context
 */
typedef void (*CRYPT_HmacFreeCallback)(HITLS_HMAC_Ctx *ctx);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Add the HMAC input data.
 *
 * @param   ctx [IN] HMAC context
 * @param   data [IN] Input data
 * @param   len [IN] Data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_HmacUpdateCallback)(HITLS_HMAC_Ctx *ctx, const uint8_t *data, uint32_t len);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Output the HMAC result.
 *
 * @param   ctx [IN] HMAC context
 * @param   out [OUT] Output data
 * @param   len [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_HmacFinalCallback)(HITLS_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len);

/**
 * @ingroup hitls_crypt_reg
 * @brief Function for calculating the HMAC for a single time
 *
 * @param   hashAlgo [IN] Hash algorithm
 * @param   key [IN] Key
 * @param   keyLen [IN] Key length
 * @param   in [IN] Input data.
 * @param   inLen [IN] Input data length
 * @param   out [OUT] Output the HMAC data result.
 * @param   outLen [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_HmacCallback)(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Obtain the hash length.
 *
 * @param   hashAlgo [IN] Hash algorithm.
 *
 * @retval  Hash length
 */
typedef uint32_t (*CRYPT_DigestSizeCallback)(HITLS_HashAlgo hashAlgo);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Initialize the hash context.
 *
 * @param   hashAlgo [IN] Hash algorithm
 *
 * @retval  Hash context
 */
typedef HITLS_HASH_Ctx *(*CRYPT_DigestInitCallback)(HITLS_HashAlgo hashAlgo);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Copy the hash context.
 *
 * @param   ctx [IN] Hash Context
 *
 * @retval  Hash context
 */
typedef HITLS_HASH_Ctx *(*CRYPT_DigestCopyCallback)(HITLS_HASH_Ctx *ctx);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the hash context.
 *
 * @param   ctx [IN] Hash Context
 */
typedef void (*CRYPT_DigestFreeCallback)(HITLS_HASH_Ctx *ctx);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Hash Add input data.
 *
 * @param   ctx [IN] Hash context
 * @param   data [IN] Input data
 * @param   len [IN] Input data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_DigestUpdateCallback)(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Output the hash result.
 *
 * @param   ctx [IN] Hash context
 * @param   out [IN] Output data.
 * @param   len [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_DigestFinalCallback)(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Hash function
 *
 * @param   hashAlgo [IN] Hash algorithm
 * @param   in [IN] Input data
 * @param   inLen [IN] Input data length
 * @param   out [OUT] Output data
 * @param   outLen [IN/OUT] IN: Maximum buffer length OUT: Output data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_DigestCallback)(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   TLS encryption
 *
 * Provides the encryption capability for records, including the AEAD and CBC algorithms.
 * Encrypts the input factor (key parameter) and plaintext based on the record protocol
 * to obtain the ciphertext.
 *
 * @attention: The protocol allows the sending of app packets with payload length 0.
 *             Therefore, the length of the plaintext input may be 0. Therefore,
 *             the plaintext with the length of 0 must be encrypted.
 * @param   cipher [IN] Key parameters
 * @param   in [IN] Plaintext data
 * @param   inLen [IN] Plaintext data length
 * @param   out [OUT] Ciphertext data
 * @param   outLen [IN/OUT] IN: maximum buffer length OUT: ciphertext data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_EncryptCallback)(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   TLS decryption
 *
 * Provides decryption capabilities for records, including the AEAD and CBC algorithms.
 * Decrypt the input factor (key parameter) and ciphertext according to the record protocol to obtain the plaintext.
 *
 * @param   cipher [IN] Key parameters
 * @param   in [IN] Ciphertext data
 * @param   inLen [IN] Ciphertext data length
 * @param   out [OUT] Plaintext data
 * @param   outLen [IN/OUT] IN: maximum buffer length OUT: plaintext data length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_DecryptCallback)(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   Release the cipher ctx.
 *
 * @param   ctx [IN] cipher ctx handle
 */
typedef void (*CRYPT_CipherFreeCallback)(HITLS_Cipher_Ctx *ctx);
/**
 * @ingroup hitls_crypt_reg
 * @brief   HKDF-Extract
 *
 * @param   input [IN] Enter the key material.
 * @param   prk [OUT] Output key
 * @param   prkLen [IN/OUT] IN: Maximum buffer length OUT: Output key length
 *
 * @retval 0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_HkdfExtractCallback)(const HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen);

/**
 * @ingroup hitls_crypt_reg
 * @brief   HKDF-Expand
 *
 * @param   input [IN] Enter the key material.
 * @param   outputKeyMaterial [OUT] Output key
 * @param   outputKeyMaterialLen [IN] Output key length
 *
 * @retval  0 indicates success. Other values indicate failure.
 */
typedef int32_t (*CRYPT_HkdfExpandCallback)(
    const HITLS_CRYPT_HkdfExpandInput *input, uint8_t *outputKeyMaterial, uint32_t outputKeyMaterialLen);

/**
 * @ingroup hitls_cert_reg
 * @brief   Callback function that must be registered
 */
typedef struct {
    CRYPT_RandBytesCallback randBytes;                  /**< Obtain the random number. */
    CRYPT_HmacSizeCallback hmacSize;                    /**< HMAC: obtain the HMAC length based
                                                             on the hash algorithm. */
    CRYPT_HmacInitCallback hmacInit;                    /**< HMAC: initialize the context. */
    CRYPT_HmacReInitCallback hmacReinit;                /**< HMAC: reinitialize the context. */
    CRYPT_HmacFreeCallback hmacFree;                    /**< HMAC: release the context. */
    CRYPT_HmacUpdateCallback hmacUpdate;                /**< HMAC: add input data. */
    CRYPT_HmacFinalCallback hmacFinal;                  /**< HMAC: output result. */
    CRYPT_HmacCallback hmac;                            /**< HMAC: single HMAC function. */
    CRYPT_DigestSizeCallback digestSize;                /**< HASH: obtains the hash length. */
    CRYPT_DigestInitCallback digestInit;                /**< HASH: initialize the context. */
    CRYPT_DigestCopyCallback digestCopy;                /**< HASH: copy the hash context. */
    CRYPT_DigestFreeCallback digestFree;                /**< HASH: release the context. */
    CRYPT_DigestUpdateCallback digestUpdate;            /**< HASH: add input data. */
    CRYPT_DigestFinalCallback digestFinal;              /**< HASH: output the hash result. */
    CRYPT_DigestCallback digest;                        /**< HASH: single hash function. */
    CRYPT_EncryptCallback encrypt;                      /**< TLS encryption: provides the encryption
                                                            capability for records. */
    CRYPT_DecryptCallback decrypt;                      /**< TLS decryption: provides the decryption
                                                             capability for records. */
    CRYPT_CipherFreeCallback cipherFree;                /**< CIPHER: release the context. */
} HITLS_CRYPT_BaseMethod;

/**
 * @ingroup hitls_cert_reg
 * @brief   ECDH Callback function to be registered
 */
typedef struct {
    CRYPT_GenerateEcdhKeyPairCallback generateEcdhKeyPair;      /**< ECDH: generate a key pair based
                                                                           on the elliptic curve parameters. */
    CRYPT_FreeEcdhKeyCallback freeEcdhKey;                      /**< ECDH: release the elliptic curve key. */
    CRYPT_GetEcdhEncodedPubKeyCallback getEcdhPubKey;           /**< ECDH: extract public key data. */
    CRYPT_CalcEcdhSharedSecretCallback calcEcdhSharedSecret;    /**< ECDH: calculate the shared key based on
                                                                           the local key and peer public key. */
    CRYPT_Sm2CalcEcdhSharedSecretCallback sm2CalEcdhSharedSecret;
    CRYPT_KemEncapsulateCallback kemEncapsulate;                 /**< KEM: encapsulate a shared secret */
    CRYPT_KemDecapsulateCallback kemDecapsulate;                 /**< KEM: decapsulate the ciphertext */
} HITLS_CRYPT_EcdhMethod;

/**
 * @ingroup hitls_cert_reg
 * @brief   DH Callback function to be registered
 */
typedef struct {
    CRYPT_GenerateDhKeyBySecbitsCallback generateDhKeyBySecbits;    /**< DH: Generate a key pair based on secbits */
    CRYPT_GenerateDhKeyByParamsCallback generateDhKeyByParams;      /**< DH: Generate a key pair
                                                                             based on the dh parameter */
    CRYPT_DupDhKeyCallback dupDhKey;                                /**< DH: deep copy key*/
    CRYPT_FreeDhKeyCallback freeDhKey;                              /**< DH: release the key */
    CRYPT_DHGetParametersCallback getDhParameters;                  /**< DH: obtain the p g plen glen
                                                                             by using the key handle */
    CRYPT_GetDhEncodedPubKeyCallback getDhPubKey;                   /**< DH: extract the Dh public key data */
    CRYPT_CalcDhSharedSecretCallback calcDhSharedSecret;            /**< DH: calculate the shared key based on
                                                                             the local key and peer public key */
} HITLS_CRYPT_DhMethod;

/**
 * @ingroup hitls_cert_reg
 * @brief   KDF function
 */
typedef struct {
    CRYPT_HkdfExtractCallback hkdfExtract;
    CRYPT_HkdfExpandCallback hkdfExpand;
} HITLS_CRYPT_KdfMethod;

/**
 * @ingroup hitls_cert_reg
 * @brief   Register the basic callback function.
 *
 * @param   userCryptCallBack [IN] Callback function to be registered
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter is NULL..
 */
int32_t HITLS_CRYPT_RegisterBaseMethod(HITLS_CRYPT_BaseMethod *userCryptCallBack);

/**
 * @ingroup hitls_cert_reg
 * @brief   Register the ECDH callback function.
 *
 * @param   userCryptCallBack [IN] Callback function to be registered
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter is NULL..
 */
int32_t HITLS_CRYPT_RegisterEcdhMethod(HITLS_CRYPT_EcdhMethod *userCryptCallBack);

/**
 * @ingroup hitls_cert_reg
 * @brief   Register the callback function of the DH.
 *
 * @param   userCryptCallBack [IN] Callback function to be registered
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter is NULL..
 */
int32_t HITLS_CRYPT_RegisterDhMethod(const HITLS_CRYPT_DhMethod *userCryptCallBack);

/**
 * @brief   Register the callback function of the HKDF.
 *
 * @param   userCryptCallBack [IN] Callback function to be registered
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter is NULL..
 */
int32_t HITLS_CRYPT_RegisterHkdfMethod(HITLS_CRYPT_KdfMethod *userCryptCallBack);

#ifdef __cplusplus
}
#endif
#endif