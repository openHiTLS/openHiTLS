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

#ifndef HITLS_CRYPT_TYPE_H
#define HITLS_CRYPT_TYPE_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_obj.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void HITLS_Lib_Ctx;

/**
 * @ingroup hitls_crypt_type
 * @brief   Key handle, which is converted into the corresponding structure based on the algorithm library
 * used by the user.
 */
typedef void HITLS_CRYPT_Key;

/**
 * @ingroup hitls_crypt_type
 * @brief   Hash context. The user converts the structure based on the algorithm library.
 */
typedef void HITLS_HASH_Ctx;

/**
 * @ingroup hitls_crypt_type
 * @brief   HMAC context. The user converts the HMAC context into the corresponding structure
 * based on the algorithm library.
 */
typedef void HITLS_HMAC_Ctx;

/**
 * @ingroup hitls_crypt_type
 * @brief   cipher context. The user converts the cipher context into the corresponding structure
 * based on the algorithm library.
 */
typedef void HITLS_Cipher_Ctx;

typedef struct BslList HITLS_CIPHER_List;

/**
 * @ingroup hitls_crypt_type
 * @brief   Enumerated value of the symmetric encryption algorithm type.
 */
typedef enum {
    HITLS_AEAD_CIPHER,
    HITLS_CBC_CIPHER,
    HITLS_CIPHER_TYPE_BUTT = 255
} HITLS_CipherType;

/**
 * @ingroup hitls_crypt_type
 * @brief   Enumerated value of the symmetric encryption algorithm.
 */
typedef enum {
    HITLS_CIPHER_NULL = BSL_CID_UNKNOWN,
    HITLS_CIPHER_AES_128_CBC = BSL_CID_AES128_CBC,
    HITLS_CIPHER_AES_256_CBC = BSL_CID_AES256_CBC,
    HITLS_CIPHER_AES_128_GCM = BSL_CID_AES128_GCM,
    HITLS_CIPHER_AES_256_GCM = BSL_CID_AES256_GCM,
    HITLS_CIPHER_AES_128_CCM = BSL_CID_AES128_CCM,
    HITLS_CIPHER_AES_256_CCM = BSL_CID_AES256_CCM,
    HITLS_CIPHER_AES_128_CCM8 = BSL_CID_AES128_CCM8,
    HITLS_CIPHER_AES_256_CCM8 = BSL_CID_AES256_CCM8,
    HITLS_CIPHER_CHACHA20_POLY1305 = BSL_CID_CHACHA20_POLY1305,
    HITLS_CIPHER_SM4_CBC = BSL_CID_SM4_CBC,
    HITLS_CIPHER_SM4_GCM = BSL_CID_SM4_GCM,
} HITLS_CipherAlgo;

/**
 * @ingroup hitls_crypt_type
 * @brief   Hash algorithm enumeration
 */
typedef enum {
    HITLS_HASH_NULL = BSL_CID_UNKNOWN,
    HITLS_HASH_MD5 = BSL_CID_MD5,
    HITLS_HASH_SHA1 = BSL_CID_SHA1,
    HITLS_HASH_SHA_224 = BSL_CID_SHA224,
    HITLS_HASH_SHA_256 = BSL_CID_SHA256,
    HITLS_HASH_SHA_384 = BSL_CID_SHA384,
    HITLS_HASH_SHA_512 = BSL_CID_SHA512,
    HITLS_HASH_SM3 = BSL_CID_SM3,
} HITLS_HashAlgo; // CRYPT_MD_AlgId

/**
 * @ingroup hitls_crypt_type
 * @brief   MAC algorithm enumerated value
 */
typedef enum {
    HITLS_MAC_NULL = BSL_CID_UNKNOWN,
    HITLS_MAC_MD5 = BSL_CID_HMAC_MD5,
    HITLS_MAC_1 = BSL_CID_HMAC_SHA1,
    HITLS_MAC_224 = BSL_CID_HMAC_SHA224,
    HITLS_MAC_256 = BSL_CID_HMAC_SHA256,
    HITLS_MAC_384 = BSL_CID_HMAC_SHA384,
    HITLS_MAC_512 = BSL_CID_HMAC_SHA512,
    HITLS_MAC_SM3 = BSL_CID_HMAC_SM3,
    HITLS_MAC_AEAD = BSL_CID_MAC_AEAD,
} HITLS_MacAlgo;

/**
 * @ingroup hitls_crypt_type
 * @brief   Enumerated value of the authentication algorithm
 */
typedef enum {
    HITLS_AUTH_NULL,
    HITLS_AUTH_RSA,
    HITLS_AUTH_ECDSA,
    HITLS_AUTH_DSS,
    HITLS_AUTH_PSK,
    HITLS_AUTH_SM2,
    HITLS_AUTH_ANY,
    HITLS_AUTH_SPAKE2P, /* For SPAKE2+ PAKE authentication */
    HITLS_AUTH_BUTT = 255
} HITLS_AuthAlgo;

/**
 * @ingroup hitls_crypt_type
 * @brief   Key exchange algorithm enumerated value
 */
typedef enum {
    HITLS_KEY_EXCH_NULL,
    HITLS_KEY_EXCH_ECDHE,
    HITLS_KEY_EXCH_DHE,
    HITLS_KEY_EXCH_ECDH,
    HITLS_KEY_EXCH_DH,
    HITLS_KEY_EXCH_RSA,
    HITLS_KEY_EXCH_PSK,
    HITLS_KEY_EXCH_DHE_PSK,
    HITLS_KEY_EXCH_ECDHE_PSK,
    HITLS_KEY_EXCH_RSA_PSK,
    HITLS_KEY_EXCH_ECC, /* sm2 encrypt */
    HITLS_KEY_EXCH_SPAKE2P, /* SPAKE2+ PAKE */
    HITLS_KEY_EXCH_BUTT = 255
} HITLS_KeyExchAlgo;

/**
 * @ingroup hitls_crypt_type
 * @brief   Signature algorithm enumeration
 */
typedef enum {
    HITLS_SIGN_RSA_PKCS1_V15 = BSL_CID_RSA,
    HITLS_SIGN_DSA = BSL_CID_DSA,
    HITLS_SIGN_ECDSA = BSL_CID_ECDSA,
    HITLS_SIGN_RSA_PSS = BSL_CID_RSASSAPSS,
    HITLS_SIGN_ED25519 = BSL_CID_ED25519,
    HITLS_SIGN_SM2 = BSL_CID_SM2DSA,
    HITLS_SIGN_BUTT = 255
} HITLS_SignAlgo;

/**
 * @ingroup hitls_crypt_type
 * @brief   Elliptic curve type enumerated value
 */
typedef enum {
    HITLS_EC_CURVE_TYPE_NAMED_CURVE = 3,
    HITLS_EC_CURVE_TYPE_BUTT = 255
} HITLS_ECCurveType;

/**
 * @ingroup hitls_crypt_type
 * @brief   Named Group enumerated value
 */
typedef enum {
    HITLS_EC_GROUP_SECP256R1 = 23,
    HITLS_EC_GROUP_SECP384R1 = 24,
    HITLS_EC_GROUP_SECP521R1 = 25,
    HITLS_EC_GROUP_BRAINPOOLP256R1 = 26,
    HITLS_EC_GROUP_BRAINPOOLP384R1 = 27,
    HITLS_EC_GROUP_BRAINPOOLP512R1 = 28,
    HITLS_EC_GROUP_CURVE25519 = 29,
    HITLS_EC_GROUP_SM2 = 41,
    HITLS_FF_DHE_2048 = 256,
    HITLS_FF_DHE_3072 = 257,
    HITLS_FF_DHE_4096 = 258,
    HITLS_FF_DHE_6144 = 259,
    HITLS_FF_DHE_8192 = 260,
    HITLS_HYBRID_X25519_MLKEM768 = 4588,
    HITLS_HYBRID_ECDH_NISTP256_MLKEM768 = 4587,
    HITLS_HYBRID_ECDH_NISTP384_MLKEM1024 = 4589,
    HITLS_NAMED_GROUP_BUTT = 0xFFFFu
} HITLS_NamedGroup;

/**
 * @ingroup hitls_crypt_type
 * @brief   Elliptic curve point format enumerated value
 */
typedef enum {
    HITLS_POINT_FORMAT_UNCOMPRESSED = 0,
    HITLS_POINT_FORMAT_BUTT = 255
} HITLS_ECPointFormat;

/**
 * @ingroup hitls_crypt_type
 * @brief   Elliptic curve parameter
 */
typedef struct {
    HITLS_ECCurveType type;                 /**< Elliptic curve type. */
    union {
        void *prime;                        /**< Display prime number: corresponding to the protocol explicit_prime. */
        void *char2;                        /**< Display char2: corresponding to the protocol explicit_char2. */
        HITLS_NamedGroup namedcurve;        /**< Elliptic curve ID. */
    } param;
} HITLS_ECParameters;

/**
 * @ingroup hitls_crypt_type
 * @brief Key parameters
 */
typedef struct {
    HITLS_CipherType type;              /**< Encryption algorithm type. Currently, only aead is supported. */
    HITLS_CipherAlgo algo;              /**< Symmetric encryption algorithm. */
    const uint8_t *key;                 /**< Symmetry key. */
    uint32_t keyLen;                    /**< Symmetry key length. */
    const uint8_t *iv;                  /**< IV. */
    uint32_t ivLen;                     /**< IV length. */
    uint8_t *aad;                       /**< Aad: AEAD: one of the input parameters for encryption and decryption.
                                             additional data. */
    uint32_t aadLen;                    /**< Aad length. */
    const uint8_t *hmacKey;             /**< Hmac key. */
    uint32_t hmacKeyLen;                /**< Hmac key length. */
    HITLS_Cipher_Ctx **ctx;             /**< HITLS_Cipher_Ctx handle */
} HITLS_CipherParameters;

/**
 * @ingroup hitls_crypt_type
 * @brief   sm2  ecdhe negotiation key parameters
 */
typedef struct {
    HITLS_CRYPT_Key *tmpPriKey;        /* Local temporary private key. */
    uint8_t *tmpPeerPubkey;            /* Peer temporary public key. */
    uint32_t tmpPeerPubKeyLen;         /* Length of the peer temporary public key. */
    HITLS_CRYPT_Key *priKey;           /* Local private key, which is used for SM2 algorithm negotiation.
                                          It is the private key of the encryption certificate. */
    HITLS_CRYPT_Key *peerPubKey;       /* Peer public key, which is used for SM2 algorithm negotiation.
                                          It is the public key in the encryption certificate. */
    bool isClient;                     /* Client ID, which is used by the SM2 algorithm negotiation key. */
} HITLS_Sm2GenShareKeyParameters;

/**
 * @ingroup hitls_crypt_type
 * @brief   HKDF-Extract Input
 */
typedef struct {
    HITLS_HashAlgo hashAlgo;    /* Hash algorithm. */
    const uint8_t *salt;        /* Salt value. */
    uint32_t saltLen;           /* Salt value length. */
    const uint8_t *inputKeyMaterial;         /* Input Keying Material. */
    uint32_t inputKeyMaterialLen;            /* Ikm length. */
} HITLS_CRYPT_HkdfExtractInput;

/**
 * @ingroup hitls_crypt_type
 * @brief   HKDF-Expand Input
 */
typedef struct {
    HITLS_HashAlgo hashAlgo;    /* Hash algorithm. */
    const uint8_t *prk;         /* A pseudorandom key of at least HashLen octets. */
    uint32_t prkLen;            /* Prk length. */
    const uint8_t *info;        /* Extended data. */
    uint32_t infoLen;           /* Extend the data length. */
} HITLS_CRYPT_HkdfExpandInput;

#ifdef __cplusplus
}
#endif

/* Placeholder IANA values for new PAKE Cipher Suites */
/* These values are used in the CipherSuiteInfo definitions in tls/config/src/cipher_suite.c */
#ifdef HITLS_CRYPTO_SPAKE2P /* Guard for PAKE feature */
#define HITLS_TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256 (0xFEA0U)
#define HITLS_TLS_SPAKE2P_ED25519_WITH_AES_256_GCM_SHA384 (0xFEA1U)
#endif /* HITLS_CRYPTO_SPAKE2P */

#endif
