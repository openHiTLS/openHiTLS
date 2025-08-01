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
 * @defgroup crypt
 * @brief crypto module
 */

/**
 * @defgroup crypt_algid
 * @ingroup crypt
 * @brief id of algorithms
 */

#ifndef CRYPT_ALGID_H
#define CRYPT_ALGID_H

#include "bsl_obj.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @ingroup  crypt_algid
 *
 * RAND algorithm ID
 */
typedef enum {
    CRYPT_RAND_SHA1 = BSL_CID_RAND_SHA1,
    CRYPT_RAND_SHA224 = BSL_CID_RAND_SHA224,
    CRYPT_RAND_SHA256 = BSL_CID_RAND_SHA256,
    CRYPT_RAND_SHA384 = BSL_CID_RAND_SHA384,
    CRYPT_RAND_SHA512 = BSL_CID_RAND_SHA512,
    CRYPT_RAND_HMAC_SHA1 = BSL_CID_RAND_HMAC_SHA1,
    CRYPT_RAND_HMAC_SHA224 = BSL_CID_RAND_HMAC_SHA224,
    CRYPT_RAND_HMAC_SHA256 = BSL_CID_RAND_HMAC_SHA256,
    CRYPT_RAND_HMAC_SHA384 = BSL_CID_RAND_HMAC_SHA384,
    CRYPT_RAND_HMAC_SHA512 = BSL_CID_RAND_HMAC_SHA512,
    CRYPT_RAND_AES128_CTR = BSL_CID_RAND_AES128_CTR,
    CRYPT_RAND_AES192_CTR = BSL_CID_RAND_AES192_CTR,
    CRYPT_RAND_AES256_CTR = BSL_CID_RAND_AES256_CTR,
    CRYPT_RAND_AES128_CTR_DF = BSL_CID_RAND_AES128_CTR_DF,
    CRYPT_RAND_AES192_CTR_DF = BSL_CID_RAND_AES192_CTR_DF,
    CRYPT_RAND_AES256_CTR_DF = BSL_CID_RAND_AES256_CTR_DF,
    CRYPT_RAND_SM3 = BSL_CID_RAND_SM3,
    CRYPT_RAND_SM4_CTR_DF = BSL_CID_RAND_SM4_CTR_DF,
    CRYPT_RAND_ALGID_MAX = BSL_CID_UNKNOWN
} CRYPT_RAND_AlgId;

/**
 * @ingroup  crypt_algid
 *
 * Hash algorithm ID
 */
typedef enum {
    CRYPT_MD_MD5 = BSL_CID_MD5,
    CRYPT_MD_SHA1 = BSL_CID_SHA1,
    CRYPT_MD_SHA224 = BSL_CID_SHA224,
    CRYPT_MD_SHA256 = BSL_CID_SHA256,
    CRYPT_MD_SHA384 = BSL_CID_SHA384,
    CRYPT_MD_SHA512 = BSL_CID_SHA512,
    CRYPT_MD_SHA3_224 = BSL_CID_SHA3_224,
    CRYPT_MD_SHA3_256 = BSL_CID_SHA3_256,
    CRYPT_MD_SHA3_384 = BSL_CID_SHA3_384,
    CRYPT_MD_SHA3_512 = BSL_CID_SHA3_512,
    CRYPT_MD_SHAKE128 = BSL_CID_SHAKE128,
    CRYPT_MD_SHAKE256 = BSL_CID_SHAKE256,
    CRYPT_MD_SM3 = BSL_CID_SM3,
    CRYPT_MD_MAX = BSL_CID_UNKNOWN
} CRYPT_MD_AlgId;

/**
 * @ingroup  crypt_algid
 *
 * MAC algorithm ID
 */
typedef enum {
    CRYPT_MAC_HMAC_MD5 = BSL_CID_HMAC_MD5,
    CRYPT_MAC_HMAC_SHA1 = BSL_CID_HMAC_SHA1,
    CRYPT_MAC_HMAC_SHA224 = BSL_CID_HMAC_SHA224,
    CRYPT_MAC_HMAC_SHA256 = BSL_CID_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384 = BSL_CID_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512 = BSL_CID_HMAC_SHA512,
    CRYPT_MAC_HMAC_SHA3_224 = BSL_CID_HMAC_SHA3_224,
    CRYPT_MAC_HMAC_SHA3_256 = BSL_CID_HMAC_SHA3_256,
    CRYPT_MAC_HMAC_SHA3_384 = BSL_CID_HMAC_SHA3_384,
    CRYPT_MAC_HMAC_SHA3_512 = BSL_CID_HMAC_SHA3_512,
    CRYPT_MAC_HMAC_SM3 = BSL_CID_HMAC_SM3,
    CRYPT_MAC_CMAC_AES128 = BSL_CID_CMAC_AES128,
    CRYPT_MAC_CMAC_AES192 = BSL_CID_CMAC_AES192,
    CRYPT_MAC_CMAC_AES256 = BSL_CID_CMAC_AES256,
    CRYPT_MAC_CMAC_SM4 = BSL_CID_CMAC_SM4,
    CRYPT_MAC_CBC_MAC_SM4 = BSL_CID_CBC_MAC_SM4,
    CRYPT_MAC_GMAC_AES128 = BSL_CID_GMAC_AES128,
    CRYPT_MAC_GMAC_AES192 = BSL_CID_GMAC_AES192,
    CRYPT_MAC_GMAC_AES256 = BSL_CID_GMAC_AES256,
    CRYPT_MAC_SIPHASH64 = BSL_CID_SIPHASH64,
    CRYPT_MAC_SIPHASH128 = BSL_CID_SIPHASH128,
    CRYPT_MAC_MAX = BSL_CID_UNKNOWN
} CRYPT_MAC_AlgId;

/**
 * @ingroup  crypt_algid
 *
 * Asymmetric algorithm ID
 */
typedef enum {
    CRYPT_PKEY_DSA = BSL_CID_DSA,
    CRYPT_PKEY_ED25519 = BSL_CID_ED25519,
    CRYPT_PKEY_X25519 = BSL_CID_X25519,
    CRYPT_PKEY_RSA = BSL_CID_RSA,
    CRYPT_PKEY_DH = BSL_CID_DH,
    CRYPT_PKEY_ECDSA = BSL_CID_ECDSA,
    CRYPT_PKEY_ECDH = BSL_CID_ECDH,
    CRYPT_PKEY_SM2 = BSL_CID_SM2DSA,
    CRYPT_PKEY_PAILLIER = BSL_CID_PAILLIER,
    CRYPT_PKEY_ELGAMAL = BSL_CID_ELGAMAL,
    CRYPT_PKEY_SLH_DSA = BSL_CID_SLH_DSA,
	CRYPT_PKEY_ML_KEM = BSL_CID_ML_KEM,
    CRYPT_PKEY_ML_DSA = BSL_CID_ML_DSA,
    CRYPT_PKEY_HYBRID_KEM = BSL_CID_HYBRID_KEM,
    CRYPT_PKEY_XMSS = BSL_CID_XMSS,
    CRYPT_PKEY_MAX = BSL_CID_UNKNOWN
} CRYPT_PKEY_AlgId;

/**
 * @ingroup  cipher_algid
 * @brief Symmetric algorithm mode ID
 *
 * There is a mapping relationship with the g_ealCipherMethod list. Attention any modification must be synchronized.
 */
typedef enum {
    CRYPT_CIPHER_AES128_CBC = BSL_CID_AES128_CBC,
    CRYPT_CIPHER_AES192_CBC = BSL_CID_AES192_CBC,
    CRYPT_CIPHER_AES256_CBC = BSL_CID_AES256_CBC,

    CRYPT_CIPHER_AES128_CTR = BSL_CID_AES128_CTR,
    CRYPT_CIPHER_AES192_CTR = BSL_CID_AES192_CTR,
    CRYPT_CIPHER_AES256_CTR = BSL_CID_AES256_CTR,

    CRYPT_CIPHER_AES128_ECB = BSL_CID_AES128_ECB,
    CRYPT_CIPHER_AES192_ECB = BSL_CID_AES192_ECB,
    CRYPT_CIPHER_AES256_ECB = BSL_CID_AES256_ECB,

    CRYPT_CIPHER_AES128_XTS = BSL_CID_AES128_XTS,
    CRYPT_CIPHER_AES256_XTS = BSL_CID_AES256_XTS,

    CRYPT_CIPHER_AES128_CCM = BSL_CID_AES128_CCM,
    CRYPT_CIPHER_AES192_CCM = BSL_CID_AES192_CCM,
    CRYPT_CIPHER_AES256_CCM = BSL_CID_AES256_CCM,

    CRYPT_CIPHER_AES128_GCM = BSL_CID_AES128_GCM,
    CRYPT_CIPHER_AES192_GCM = BSL_CID_AES192_GCM,
    CRYPT_CIPHER_AES256_GCM = BSL_CID_AES256_GCM,

    CRYPT_CIPHER_CHACHA20_POLY1305 = BSL_CID_CHACHA20_POLY1305,

    CRYPT_CIPHER_SM4_XTS = BSL_CID_SM4_XTS,
    CRYPT_CIPHER_SM4_CBC = BSL_CID_SM4_CBC,
    CRYPT_CIPHER_SM4_ECB = BSL_CID_SM4_ECB,
    CRYPT_CIPHER_SM4_CTR = BSL_CID_SM4_CTR,
    CRYPT_CIPHER_SM4_GCM = BSL_CID_SM4_GCM,
    CRYPT_CIPHER_SM4_CFB = BSL_CID_SM4_CFB,
    CRYPT_CIPHER_SM4_OFB = BSL_CID_SM4_OFB,

    CRYPT_CIPHER_AES128_CFB = BSL_CID_AES128_CFB,
    CRYPT_CIPHER_AES192_CFB = BSL_CID_AES192_CFB,
    CRYPT_CIPHER_AES256_CFB = BSL_CID_AES256_CFB,
    CRYPT_CIPHER_AES128_OFB = BSL_CID_AES128_OFB,
    CRYPT_CIPHER_AES192_OFB = BSL_CID_AES192_OFB,
    CRYPT_CIPHER_AES256_OFB = BSL_CID_AES256_OFB,

    CRYPT_CIPHER_MAX = BSL_CID_UNKNOWN,
} CRYPT_CIPHER_AlgId;

/**
 * @ingroup  crypt_algid
 *
 * Parameter ID of an asymmetric algorithm. The most significant 16 bits indicate the algorithm ID,
 * and the least significant 16 bits map the ID definition of the algorithm LowLevel.
 */
typedef enum {
    CRYPT_DH_RFC2409_768 = BSL_CID_DH_RFC2409_768,
    CRYPT_DH_RFC2409_1024 = BSL_CID_DH_RFC2409_1024,
    CRYPT_DH_RFC3526_1536 = BSL_CID_DH_RFC3526_1536,
    CRYPT_DH_RFC3526_2048 = BSL_CID_DH_RFC3526_2048,
    CRYPT_DH_RFC3526_3072 = BSL_CID_DH_RFC3526_3072,
    CRYPT_DH_RFC3526_4096 = BSL_CID_DH_RFC3526_4096,
    CRYPT_DH_RFC3526_6144 = BSL_CID_DH_RFC3526_6144,
    CRYPT_DH_RFC3526_8192 = BSL_CID_DH_RFC3526_8192,
    CRYPT_DH_RFC7919_2048 = BSL_CID_DH_RFC7919_2048,
    CRYPT_DH_RFC7919_3072 = BSL_CID_DH_RFC7919_3072,
    CRYPT_DH_RFC7919_4096 = BSL_CID_DH_RFC7919_4096,
    CRYPT_DH_RFC7919_6144 = BSL_CID_DH_RFC7919_6144,
    CRYPT_DH_RFC7919_8192 = BSL_CID_DH_RFC7919_8192,
    CRYPT_ECC_NISTP224 = BSL_CID_NIST_PRIME224,
    CRYPT_ECC_NISTP256 = BSL_CID_PRIME256V1,
    CRYPT_ECC_NISTP384 = BSL_CID_SECP384R1,
    CRYPT_ECC_NISTP521 = BSL_CID_SECP521R1,
    CRYPT_ECC_BRAINPOOLP256R1 = BSL_CID_ECC_BRAINPOOLP256R1,
    CRYPT_ECC_BRAINPOOLP384R1 = BSL_CID_ECC_BRAINPOOLP384R1,
    CRYPT_ECC_BRAINPOOLP512R1 = BSL_CID_ECC_BRAINPOOLP512R1,
    CRYPT_ECC_SM2 = BSL_CID_SM2PRIME256,
    CRYPT_HYBRID_X25519_MLKEM512 = BSL_CID_X25519_MLKEM512,
    CRYPT_HYBRID_X25519_MLKEM768 = BSL_CID_X25519_MLKEM768,
    CRYPT_HYBRID_X25519_MLKEM1024 = BSL_CID_X25519_MLKEM1024,
    CRYPT_HYBRID_ECDH_NISTP256_MLKEM512 = BSL_CID_ECDH_NISTP256_MLKEM512,
    CRYPT_HYBRID_ECDH_NISTP256_MLKEM768 = BSL_CID_ECDH_NISTP256_MLKEM768,
    CRYPT_HYBRID_ECDH_NISTP256_MLKEM1024 = BSL_CID_ECDH_NISTP256_MLKEM1024,
    CRYPT_HYBRID_ECDH_NISTP384_MLKEM512 = BSL_CID_ECDH_NISTP384_MLKEM512,
    CRYPT_HYBRID_ECDH_NISTP384_MLKEM768 = BSL_CID_ECDH_NISTP384_MLKEM768,
    CRYPT_HYBRID_ECDH_NISTP384_MLKEM1024 = BSL_CID_ECDH_NISTP384_MLKEM1024,
    CRYPT_HYBRID_ECDH_NISTP521_MLKEM512 = BSL_CID_ECDH_NISTP521_MLKEM512,
    CRYPT_HYBRID_ECDH_NISTP521_MLKEM768 = BSL_CID_ECDH_NISTP521_MLKEM768,
    CRYPT_HYBRID_ECDH_NISTP521_MLKEM1024 = BSL_CID_ECDH_NISTP521_MLKEM1024,
    CRYPT_PKEY_PARAID_MAX = BSL_CID_UNKNOWN
} CRYPT_PKEY_ParaId;

/**
 * @ingroup  crypt_algid
 *
 * Elliptic Curve Point Encoding Format
 */
typedef enum {
    CRYPT_POINT_COMPRESSED,
    CRYPT_POINT_UNCOMPRESSED, /**< default format. */
    CRYPT_POINT_HYBRID,
    CRYPT_POINT_MAX
} CRYPT_PKEY_PointFormat;

/**
 * @ingroup  crypt_algid
 *
 * KDF algorithm ID
 */
typedef enum {
    CRYPT_KDF_SCRYPT = BSL_CID_SCRYPT,
    CRYPT_KDF_PBKDF2 = BSL_CID_PBKDF2,
    CRYPT_KDF_KDFTLS12 = BSL_CID_KDFTLS12,
    CRYPT_KDF_HKDF = BSL_CID_HKDF,
    CRYPT_KDF_MAX = BSL_CID_UNKNOWN
} CRYPT_KDF_AlgId;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_ALGID_H
