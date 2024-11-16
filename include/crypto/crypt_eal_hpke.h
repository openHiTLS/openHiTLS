
#ifndef CRYPT_EAL_HPKE_H
#define CRYPT_EAL_HPKE_H

#include <stdint.h>
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"

typedef enum {
    CRYPT_HPKE_MODE_BASE = 0x00,
} CRYPT_HPKE_mode;

typedef enum {
    CRYPT_KEM_DHKEM_P256_HKDF_SHA256 = 0x0010,    /* DHKEM(P-256, HKDF-SHA256) */
    CRYPT_KEM_DHKEM_P384_HKDF_SHA384 = 0x0011,    /* DHKEM(P-384, HKDF-SHA384) */
    CRYPT_KEM_DHKEM_P521_HKDF_SHA512 = 0x0012,    /* DHKEM(P-521, HKDF-SHA512) */
    CRYPT_KEM_DHKEM_X25519_HKDF_SHA256 = 0x0020,  /* DHKEM(X25519, HKDF-SHA256) */
    CRYPT_KEM_DHKEM_X448_HKDF_SHA512 = 0x0021     /* DHKEM(X448, HKDF-SHA512) */
} CRYPT_HPKE_KEM_AlgId;

typedef enum {
    CRYPT_KDF_HKDF_SHA256 = 0x0001,    /* HKDF-SHA256 */
    CRYPT_KDF_HKDF_SHA384 = 0x0002,    /* HKDF-SHA384 */
    CRYPT_KDF_HKDF_SHA512 = 0x0003     /* HKDF-SHA512 */
} CRYPT_HPKE_KDF_AlgId;

typedef enum {
    CRYPT_AEAD_AES_128_GCM = 0x0001,        /* AES-128-GCM */
    CRYPT_AEAD_AES_256_GCM = 0x0002,        /* AES-256-GCM */
    CRYPT_AEAD_CHACHA20_POLY1305 = 0x0003,  /* ChaCha20-Poly1305 */
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

typedef struct EAL_HpkeCtx CRYPT_EAL_HpkeCtx;

typedef enum {
    CRYPT_HPKE_PARAM_SYM_KEY = 0,          /* Symmetric key */
    CRYPT_HPKE_PARAM_BASE_NONCE = 1,       /* Base nonce */
    CRYPT_HPKE_PARAM_EXPORTER_SECRET = 2,  /* Exporter secret */
} CRYPT_HPKE_PARAM_TYPE;

/**
 * @ingroup crypt_eal_hpke
 * @brief Generate a key pair for HPKE using the specified cipher suite and input key material.
 *
 * This function generates a key pair for HPKE using the provided cipher suite and input key material.
 * The generated key pair is returned in a CRYPT_EAL_PkeyCtx structure.
 *
 * @param cipher [IN] The HPKE cipher suite to be used for key generation.
 * @param ikm [IN] The input key material for key generation.
 * @param ikmLen [IN] The length of the input key material.
 * @param pctx [OUT] A pointer to a pointer to the generated CRYPT_EAL_PkeyCtx structure.
 *
 * @retval #CRYPT_SUCCESS if the key pair is generated successfully.
 * @retval Other error codes defined in crypt_errno.h if an error occurs.
 */
int32_t CRYPT_EAL_HpkeGenerateKeyPair(CRYPT_HPKE_CipherSuite cipher, const uint8_t *ikm, uint32_t ikmLen,
    CRYPT_EAL_PkeyCtx **pctx);

/**
 * @ingroup crypt_eal_hpke
 * @brief Create a new HPKE context
 *
 * @param mode [IN] HPKE mode (base, PSK, auth, or auth-PSK)
 * @param cipher [IN] HPKE cipher suite containing KEM, KDF and AEAD algorithms
 * @retval CRYPT_EAL_HpkeCtx* HPKE context pointer if successful, NULL if failed
 */
CRYPT_EAL_HpkeCtx *CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_Role role, CRYPT_HPKE_mode mode, CRYPT_HPKE_CipherSuite cipher);

/**
 * @ingroup crypt_eal_hpke
 * @brief Setup HPKE base mode for sender
 *
 * This function sets up the HPKE context for the sender in the base mode.
 * It takes the sender's private key, the recipient's public key, and additional
 * information to generate an encapsulated key.
 *
 * @param ctx [IN/OUT] HPKE context for the sender
 * @param pkey [IN] Private key context for the sender
 * @param info [IN] Additional information for the key setup
 * @param infoLen [IN] Length of the additional information
 * @param pkR [IN] Recipient's public key
 * @param pkRLen [IN] Length of the recipient's public key
 * @param enc [OUT] Buffer to store the encapsulated key
 * @param encLen [OUT] Length of the encapsulated key
 *
 * @retval #CRYPT_SUCCESS if the setup is successful
 * @retval Other error codes defined in crypt_errno.h if an error occurs
 */
int32_t CRYPT_EAL_HpkeSetupSender(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *info,
    uint32_t infoLen, const uint8_t *pkR, uint32_t pkRLen, uint8_t *enc, uint32_t *encLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Seal (encrypt) data using HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param aad [IN] Additional authenticated data
 * @param aadLen [IN] Length of additional authenticated data
 * @param plainText [IN] Plaintext to encrypt
 * @param plainTextLen [IN] Length of plaintext
 * @param cipherText [OUT] Ciphertext output buffer
 * @param cipherTextLen [OUT] Length of ciphertext
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeSeal(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *aad, uint32_t aadLen,
    const uint8_t *plain, uint32_t plainLen, uint8_t *cipherText, uint32_t *cipherTextLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Setup HPKE for the recipient
 *
 * This function sets up the HPKE context for the recipient.
 * It takes the recipient's private key, additional information,
 * and the encapsulated key to generate the shared secret.
 *
 * @param ctx [IN/OUT] HPKE context for the recipient
 * @param pkey [IN] Private key context for the recipient
 * @param info [IN] Additional information for the key setup
 * @param infoLen [IN] Length of the additional information
 * @param encapsulatedKey [IN] Encapsulated key input buffer
 * @param encapsulatedKeyLen [IN] Length of the encapsulated key
 *
 * @retval #CRYPT_SUCCESS if the setup is successful
 * @retval Other error codes defined in crypt_errno.h if an error occurs
 */
int32_t CRYPT_EAL_HpkeSetupRecipient(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *info,
    uint32_t infoLen, const uint8_t *encapsulatedKey, uint32_t encapsulatedKeyLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Open an HPKE-encrypted message
 *
 * @param ctx [IN/OUT] HPKE context for decryption
 * @param cipherText [IN] The encrypted message to be decrypted
 * @param cipherTextLen [IN] Length of the encrypted message
 * @param aad [IN] Additional authenticated data
 * @param aadLen [IN] Length of the additional authenticated data
 * @param plainText [OUT] Buffer to store the decrypted message
 * @param plainTextLen [IN/OUT] On input, the length of the buffer; on output, the length of the decrypted message
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeOpen(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *cipherText, uint32_t cipherTextLen,
    const uint8_t *aad, uint32_t aadLen, unsigned char *plainText, uint32_t *plainTextLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Export a secret from the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param info [IN] Additional information for the export
 * @param infoLen [IN] Length of the additional information
 * @param key [OUT] Buffer to store the exported secret
 * @param keyLen [IN] Length of the buffer for the exported secret
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeExportSecret(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *info, uint32_t infoLen, uint8_t *key,
    uint32_t keyLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Set the sequence number for the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param seq [IN] Sequence number to be set
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
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeGetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t *seq);

/**
 * @ingroup crypt_eal_hpke
 * @brief Retrieve a parameter from the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param type [IN] Type of parameter to retrieve
 * @param buff [OUT] Buffer to store the retrieved parameter
 * @param buffLen [IN/OUT] On input, the length of the buffer; on output, the length of the retrieved parameter
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeGetParam(CRYPT_EAL_HpkeCtx *ctx, CRYPT_HPKE_PARAM_TYPE type, uint8_t *buff, uint32_t *buffLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Set a parameter in the HPKE context
 *
 * @param ctx [IN] HPKE context
 * @param type [IN] Type of parameter to set
 * @param buff [IN] Buffer containing the parameter value
 * @param buffLen [IN] Length of the parameter value
 * @retval #CRYPT_SUCCESS if successful
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_HpkeSetParam(CRYPT_EAL_HpkeCtx *ctx, CRYPT_HPKE_PARAM_TYPE type, const uint8_t *buff,
    uint32_t buffLen);

/**
 * @ingroup crypt_eal_hpke
 * @brief Free HPKE context and associated resources
 *
 * @param ctx [IN] HPKE context to free
 */
void CRYPT_EAL_HpkeFreeCtx(CRYPT_EAL_HpkeCtx *ctx);
#endif