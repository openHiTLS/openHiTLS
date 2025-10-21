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
 * @defgroup crypt_eal_hpke
 * @ingroup crypt
 * @brief hpke of crypto module
 */

#ifndef CRYPT_EAL_HPKE_H
#define CRYPT_EAL_HPKE_H

#include <stdint.h>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CRYPT_HPKE_MODE_BASE = 0x00,
    CRYPT_HPKE_MODE_PSK = 0x01,
    CRYPT_HPKE_MODE_AUTH = 0x02,
    CRYPT_HPKE_MODE_AUTH_PSK = 0x03
} CRYPT_HPKE_Mode;

typedef enum {
    CRYPT_KEM_DHKEM_P256_HKDF_SHA256 = 0x0010,
    CRYPT_KEM_DHKEM_P384_HKDF_SHA384 = 0x0011,
    CRYPT_KEM_DHKEM_P521_HKDF_SHA512 = 0x0012,
    CRYPT_KEM_DHKEM_X25519_HKDF_SHA256 = 0x0020,
} CRYPT_HPKE_KEM_AlgId;

typedef enum {
    CRYPT_KDF_HKDF_SHA256 = 0x0001,
    CRYPT_KDF_HKDF_SHA384 = 0x0002,
    CRYPT_KDF_HKDF_SHA512 = 0x0003
} CRYPT_HPKE_KDF_AlgId;

typedef enum {
    CRYPT_AEAD_AES_128_GCM = 0x0001,
    CRYPT_AEAD_AES_256_GCM = 0x0002,
    CRYPT_AEAD_CHACHA20_POLY1305 = 0x0003,
    CRYPT_AEAD_EXPORT_ONLY = 0xffff
} CRYPT_HPKE_AEAD_AlgId;

typedef struct {
    CRYPT_HPKE_KEM_AlgId kemId;
    CRYPT_HPKE_KDF_AlgId kdfId;
    CRYPT_HPKE_AEAD_AlgId aeadId;
} CRYPT_HPKE_CipherSuite;

typedef enum {
    CRYPT_HPKE_SENDER = 0,
    CRYPT_HPKE_RECIPIENT = 1,
} CRYPT_HPKE_Role;

typedef struct CRYPT_EAL_HpkeCtx CRYPT_EAL_HpkeCtx;

/**
 * @ingroup crypt_eal_hpke
 * @brief Generate a key pair for HPKE using the specified cipher suite and input key material
 *
 * This function generates a key pair for HPKE using the provided cipher suite and input key material.
 * The generated key pair is returned in a CRYPT_EAL_PkeyCtx structure.
 *
 * @param libCtx [IN] The library context
 * @param attrName [IN] Specify expected attribute values
 * @param cipherSuite [IN] The HPKE cipher suite to be used for key generation
 * @param ikm [IN] The input key material for key generation
 * @param ikmLen [IN] The length of the input key material
 * @param pkey [OUT] A pointer to a pointer to the generated CRYPT_EAL_PkeyCtx structure
 *
 * @retval #CRYPT_SUCCESS if the key pair is generated successfully
 *         Other error codes defined in crypt_errno.h if an error occurs
 */
int32_t CRYPT_EAL_HpkeGenerateKeyPair(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    CRYPT_HPKE_CipherSuite cipherSuite, uint8_t *ikm, uint32_t ikmLen, CRYPT_EAL_PkeyCtx **pkey);

/**
 * @ingroup crypt_eal_hpke
 * @brief Create a new HPKE context
 *
 * @param libCtx [IN] Library context
 * @param attrName [IN] Specify expected attribute values
 * @param role [IN] HPKE role (sender or recipient)
 * @param mode [IN] HPKE mode
 * @param cipherSuite [IN] HPKE cipher suite containing KEM, KDF and AEAD algorithms
 *
 * @retval CRYPT_EAL_HpkeCtx pointer if successful, NULL if failed
 */
CRYPT_EAL_HpkeCtx *CRYPT_EAL_HpkeNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_HPKE_Role role,
    CRYPT_HPKE_Mode mode, CRYPT_HPKE_CipherSuite cipherSuite);

/**
 * @ingroup crypt_eal_hpke
 * @brief Get the length of the encapsulated key for the specified cipher suite
 *
 * @param cipherSuite [IN] HPKE cipher suite
 * @param encapKeyLen [OUT] Length of the encapsulated key
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes defined in crypt_errno.h if an error occurs
 */
int32_t CRYPT_EAL_HpkeGetEncapKeyLen(CRYPT_HPKE_CipherSuite cipherSuite, uint32_t *encapKeyLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Setup HPKE base mode for sender
 *
 * This function only sets up the HPKE context for the sender in the base mode and psk mode.
 * It takes the sender's private key, the recipient's public key, and additional
 * information to generate an encapsulated key.
 *
 * @param ctx [IN] HPKE context for the sender
 * @param pkey [IN] Private key context for the sender, if set to NULL, will generate a keypair randomly
 * @param info [IN] Additional information for the key setup
 * @param infoLen [IN] Length of the additional information
 * @param pkR [IN] Recipient's public key. For ec key, the format is 04 || X || Y, for X25519 key, the format is X.
 * @param pkRLen [IN] Length of the recipient's public key
 * @param encapKey [OUT] Buffer to store the encapsulated key
 * @param encapKeyLen [IN/OUT] On input, the length of the buffer; on output, the length of the encapsulated key
 *
 * @retval #CRYPT_SUCCESS if the setup is successful
 *         Other error codes defined in crypt_errno.h if an error occurs
 */
int32_t CRYPT_EAL_HpkeSetupSender(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *info, uint32_t infoLen,
    uint8_t *pkR, uint32_t pkRLen, uint8_t *encapKey, uint32_t *encapKeyLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Seal (encrypt) data using HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param aad [IN] Additional authenticated data
 * @param aadLen [IN] Length of additional authenticated data
 * @param plainText [IN] Plaintext to encrypt
 * @param plainTextLen [IN] Length of plaintext
 * @param cipherText [OUT] Ciphertext output buffer, if set to NULL, only return the ciphertext length
 * @param cipherTextLen [IN/OUT] On input, the length of the buffer; on output, the length of the ciphertext
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeSeal(CRYPT_EAL_HpkeCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *plainText,
    uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Setup HPKE for the recipient
 *
 * This function sets up the HPKE context for the recipient only in the base mode and psk mode.
 * It takes the recipient's private key, additional information, and the encapsulated key to generate the shared secret.
 *
 * @param ctx [IN] HPKE context for the recipient
 * @param pkey [IN] Private key context for the recipient
 * @param info [IN] Additional information for the key setup
 * @param infoLen [IN] Length of the additional information
 * @param encapKey [IN] Encapsulated key input buffer
 * @param encapKeyLen [IN] Length of the encapsulated key
 *
 * @retval #CRYPT_SUCCESS if the setup is successful
 *         Other error codes defined in crypt_errno.h if an error occurs
 */
int32_t CRYPT_EAL_HpkeSetupRecipient(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *info, uint32_t infoLen,
    uint8_t *encapKey, uint32_t encapKeyLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Open an HPKE-encrypted message
 *
 * @param ctx [IN] HPKE context for decryption
 * @param aad [IN] Additional authenticated data
 * @param aadLen [IN] Length of the additional authenticated data
 * @param cipherText [IN] The encrypted message to be decrypted
 * @param cipherTextLen [IN] Length of the encrypted message
 * @param plainText [OUT] Buffer to store the decrypted message
 * @param plainTextLen [IN/OUT] On input, the length of the buffer; on output, the length of the decrypted message
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeOpen(CRYPT_EAL_HpkeCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *cipherText,
    uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Export a secret from the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param info [IN] Additional information for the export
 * @param infoLen [IN] Length of the additional information
 * @param key [OUT] Buffer to store the exported secret
 * @param keyLen [IN] Length of the buffer for the exported secret
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeExportSecret(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen, uint8_t *key,
    uint32_t keyLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Set the sequence number for the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param seq [IN] Sequence number to be set
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeSetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t seq);

/**
 * @ingroup crypt_eal_hpke
 * @brief Retrieve the sequence number from the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param seq [OUT] Buffer to store the retrieved sequence number
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeGetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t *seq);

/**
 * @ingroup crypt_eal_hpke
 * @brief Retrieve the shared secret from the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param buff [OUT] Buffer to store the shared secret
 * @param buffLen [IN/OUT] On input, the length of the buffer; on output, the length of the shared secret
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeGetSharedSecret(CRYPT_EAL_HpkeCtx *ctx, uint8_t *buff, uint32_t *buffLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Set the shared secret in the HPKE context
 *
 * This function set the shared secret and generate the hpke key info.
 *
 * @param ctx [IN] HPKE context
 * @param info [IN] Additional information for the shared secret
 * @param infoLen [IN] Length of the additional information
 * @param buff [IN] Buffer containing the shared secret
 * @param buffLen [IN] Length of the shared secret
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeSetSharedSecret(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen, uint8_t *buff,
    uint32_t buffLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Free HPKE context and associated resources
 *
 * @param ctx [IN] HPKE context to free
 */
void CRYPT_EAL_HpkeFreeCtx(CRYPT_EAL_HpkeCtx *ctx);

/**
 * @ingroup crypt_eal_hpke
 * @brief Setup psk and pskId for mode_psk and mode_auth_psk
 *
 * @param ctx [IN] HPKE context 
 * @param psk [IN] Pre-shared key (PSK) used for the key exchange
 * @param pskLen [IN] Length of the pre-shared key (PSK) in bytes
 * @param pskId [IN] Identifier for the pre-shared key (PSK)
 * @param pskIdLen [IN] Length of the PSK identifier in bytes
 *
 * @retval #CRYPT_SUCCESS if the setup is successful
 *         Other error codes defined in crypt_errno.h if an error occurs
 */
int32_t CRYPT_EAL_HpkeSetPsk(CRYPT_EAL_HpkeCtx *ctx,uint8_t* psk,uint32_t pskLen,uint8_t* pskId,uint32_t pskIdLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Set the authentication private key in the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param pkey [IN] Private key context for authentication
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeSetAuthPriKey(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_hpke
 * @brief Set the authentication public key in the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param pub [IN] Public key buffer
 * @param pubLen [IN] Length of the public key buffer
 *
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeSetAuthPubKey(CRYPT_EAL_HpkeCtx *ctx, uint8_t *pub, uint32_t pubLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_HPKE_H
