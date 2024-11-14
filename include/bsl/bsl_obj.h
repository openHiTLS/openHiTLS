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
 * @defgroup bsl_obj
 * @ingroup bsl
 * @brief object module
 */

#ifndef BSL_OBJ_H
#define BSL_OBJ_H

#include <stdbool.h>
#include <stdint.h>
#include "bsl_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_obj
 * All algorithm ID
 */
typedef enum {
    BSL_CID_UNKNOWN = 0,       /**< Unknown alg id */

    /* Algorithm cids from symmetric algorithm */
    // chacha
    BSL_CID_CHACHA20_POLY1305 = 1,

    // aes
    BSL_CID_AES128_CBC = 16,        /**< identifies AES-128 algorithm in CBC mode */
    BSL_CID_AES128_ECB,             /**< identifies AES-128 algorithm in ECB mode */
    BSL_CID_AES128_OFB,             /**< identifies AES-128 algorithm in OFB mode */
    BSL_CID_AES128_CFB,             /**< identifies AES-128 algorithm in CFB mode */
    BSL_CID_AES192_CBC,             /**< identifies AES-192 algorithm in CBC mode */
    BSL_CID_AES192_ECB,             /**< identifies AES-192 algorithm in ECB mode */
    BSL_CID_AES192_OFB,             /**< identifies AES-192 algorithm in OFB mode */
    BSL_CID_AES192_CFB,             /**< identifies AES-192 algorithm in CFB mode */
    BSL_CID_AES256_CBC,             /**< identifies AES-256 algorithm in CBC mode */
    BSL_CID_AES256_ECB,             /**< identifies AES-256 algorithm in ECB mode */
    BSL_CID_AES256_OFB,             /**< identifies AES-256 algorithm in OFB mode */
    BSL_CID_AES256_CFB,             /**< identifies AES-256 algorithm in CFB mode */
    BSL_CID_AES128_GCM,             /**< Identifies the AES128 algorithm in GCM mode */
    BSL_CID_AES192_GCM,             /**< Identifies the AES128 algorithm in GCM mode */
    BSL_CID_AES256_GCM,             /**< Identifies the AES256 algorithm in GCM mode */
    BSL_CID_AES128_CTR,             /**< Identifies the AES128 algorithm in CTR mode */
    BSL_CID_AES192_CTR,             /**< Identifies the AES128 algorithm in CTR mode */
    BSL_CID_AES256_CTR,             /**< Identifies the AES128 algorithm in CTR mode */
    BSL_CID_AES128_CCM,
    BSL_CID_AES192_CCM,
    BSL_CID_AES256_CCM,

    // sm4
    BSL_CID_SM4_XTS = 116,
    BSL_CID_SM4_CBC,
    BSL_CID_SM4_CTR,
    BSL_CID_SM4_GCM,
    BSL_CID_SM4_CFB,
    BSL_CID_SM4_OFB,
    BSL_CID_SM4_ECB,

    /* asymmetrical algorithm */
    BSL_CID_RSA = 5001,              /**< identifies the RSA algorithm */
    BSL_CID_RSASSAPSS,
    BSL_CID_MD5WITHRSA,
    BSL_CID_SHA1WITHRSA,
    BSL_CID_SHA224WITHRSAENCRYPTION,
    BSL_CID_SHA256WITHRSAENCRYPTION,
    BSL_CID_SHA384WITHRSAENCRYPTION,
    BSL_CID_SHA512WITHRSAENCRYPTION,
    BSL_CID_SM3WITHRSAENCRYPTION,
    BSL_CID_DSA = 5051,              /**< identifies the DSA algorithm */
    BSL_CID_DSAWITHSHA1,
    BSL_CID_DSAWITHSHA224,
    BSL_CID_DSAWITHSHA256,
    BSL_CID_DSAWITHSHA384,
    BSL_CID_DSAWITHSHA512,
    BSL_CID_ECDSA = 5101,            /**< identifies the ECDSA algorithm */
    BSL_CID_ECDSAWITHSHA1,
    BSL_CID_ECDSAWITHSHA224,
    BSL_CID_ECDSAWITHSHA256,
    BSL_CID_ECDSAWITHSHA384,
    BSL_CID_ECDSAWITHSHA512,
    BSL_CID_SM2 = 5151,              /**< identifies Chinese standard of SM2 */
    BSL_CID_SM2DSAWITHSM3,
    BSL_CID_SM2DSAWITHSHA1,
    BSL_CID_SM2DSAWITHSHA256,

    BSL_CID_DH = 5201,               /**< identifies the Diffie-Hellman algorithm */
    BSL_CID_ECDH = 5216,             /**< identifies the EC Diffie-Hellman algorithm */
    BSL_CID_ED25519 = 5261,         /**< Identifies ED25519 algorithm */
    BSL_CID_X25519 = 5276,          /**< Identifies X25519 algorithm */
    BSL_CID_PAILLIER = 5291,        /**< identifies the Paillier algorithm */

    /* hash algorithm */
    BSL_CID_MD4 = 10001,            /**< identifies MD4 hash algorithm */
    BSL_CID_MD5,                    /**< identifies the MD5 hash algorithm */
    BSL_CID_SHA1,                   /**< identifies the SHA1 hash algorithm */
    BSL_CID_SHA224,                 /**< identifies the SHA224 hash algorithm */
    BSL_CID_SHA256,                 /**< identifies the SHA256 hash algorithm */
    BSL_CID_SHA384,                 /**< identifies the SHA384 hash algorithm */
    BSL_CID_SHA512,                 /**< identifies the SHA512 hash algorithm */
    BSL_CID_SHA3_224,
    BSL_CID_SHA3_256,
    BSL_CID_SHA3_384,
    BSL_CID_SHA3_512,
    BSL_CID_SHAKE128,
    BSL_CID_SHAKE256,
    BSL_CID_SM3,                    /**< identifies SM3 hash algorithm */

    /* Message authentication code algorithm */
    // hmac
    BSL_CID_HMAC_MD5 = 10501,       /**< identifies hmac with MD5 */
    BSL_CID_HMAC_SHA1,              /**< identifies hmac with SHA1 */
    BSL_CID_HMAC_SHA224,            /**< identifies hmac with SHA224 */
    BSL_CID_HMAC_SHA256,            /**< identifies hmac with SHA256 */
    BSL_CID_HMAC_SHA384,            /**< identifies hmac with SHA384 */
    BSL_CID_HMAC_SHA512,            /**< identifies hmac with SHA512 */
    BSL_CID_HMAC_SHA3_224,          /**< identifies hmac with SHA3_224 */
    BSL_CID_HMAC_SHA3_256,          /**< identifies hmac with SHA3_256 */
    BSL_CID_HMAC_SHA3_384,          /**< identifies hmac with SHA3_384 */
    BSL_CID_HMAC_SHA3_512,          /**< identifies hmac with SHA3_512 */
    BSL_CID_HMAC_SM3,               /**< identifies hmac with SM3 */

    /* Random number algorithm */
    // DRBG
    BSL_CID_RAND_SHA1 = 11001,
    BSL_CID_RAND_SHA224,
    BSL_CID_RAND_SHA256,
    BSL_CID_RAND_SHA384,
    BSL_CID_RAND_SHA512,
    BSL_CID_RAND_HMAC_SHA1,
    BSL_CID_RAND_HMAC_SHA224,
    BSL_CID_RAND_HMAC_SHA256,
    BSL_CID_RAND_HMAC_SHA384,
    BSL_CID_RAND_HMAC_SHA512,
    BSL_CID_RAND_AES128_CTR,
    BSL_CID_RAND_AES192_CTR,
    BSL_CID_RAND_AES256_CTR,
    BSL_CID_RAND_AES128_CTR_DF,
    BSL_CID_RAND_AES192_CTR_DF,
    BSL_CID_RAND_AES256_CTR_DF,

    /* Key derivation algorithm */
    BSL_CID_SCRYPT = 11501,         /**< Identifieds Scrypt KDF algorithm */
    BSL_CID_KDFTLS12,

    // hkdf
    BSL_CID_HKDF,

    /* PKCS 5 */
    BSL_CID_PBKDF2 = 12001,         /**< identifies PBKDF2 */
    BSL_CID_PBES2,

    /* standard constant international curve */
    // BRAINPOOL
    BSL_CID_ECC_BRAINPOOLP256R1 = 12501,
    BSL_CID_ECC_BRAINPOOLP384R1,
    BSL_CID_ECC_BRAINPOOLP512R1,

    // SECP
    BSL_CID_SECP384R1,               /**< identifies NIST prime curve 384 */
    BSL_CID_SECP521R1,               /**< identifies NIST prime curve 521 */

    // RFC 3279 Curve Id
    BSL_CID_PRIME256V1,              /**< identifies RFC 3279 PRIME256V1 */

    // NIST Curve
    BSL_CID_NIST_PRIME224,           /**< NIST Curve P-224 */

    // standard constant sm series curve
    BSL_CID_SM2PRIME256,             /**< identifies sm2 curve */

    /* standard constant prime */
    BSL_CID_DH_RFC2409_768 = 12651,
    BSL_CID_DH_RFC2409_1024,
    BSL_CID_DH_RFC3526_1536,
    BSL_CID_DH_RFC3526_2048,
    BSL_CID_DH_RFC3526_3072,
    BSL_CID_DH_RFC3526_4096,
    BSL_CID_DH_RFC3526_6144,
    BSL_CID_DH_RFC3526_8192,
    BSL_CID_DH_RFC7919_2048,
    BSL_CID_DH_RFC7919_3072,
    BSL_CID_DH_RFC7919_4096,
    BSL_CID_DH_RFC7919_6144,
    BSL_CID_DH_RFC7919_8192,

    /* rfc5280 */
    BSL_CID_CE = 127001,
    BSL_CID_CE_AUTHORITYKEYID,
    BSL_CID_CE_SUBJECTKEYID,
    BSL_CID_CE_KEYUSAGE,
    BSL_CID_CE_SUBJECTALTNAME,
    BSL_CID_CE_BASICCONSTRAINTS,
    BSL_CID_CE_CRLNUMBER,
    BSL_CID_CE_CRLREASON,
    BSL_CID_CE_INVALIDITYDATE,
    BSL_CID_CE_DELTACRLINDICATOR,
    BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT,
    BSL_CID_CE_CERTIFICATEISSUER,
    BSL_CID_CE_EXTENDEDKEYUSAGE,
    BSL_CID_CE_FRESHESTCRL,
    BSL_CID_CE_SERVERAUTH,
    BSL_CID_CE_CLIENTAUTH,
    BSL_CID_CE_CODESIGNING,
    BSL_CID_CE_EMAILPROTECTION,
    BSL_CID_CE_TIMESTAMPING,
    BSL_CID_CE_OSCPSIGNING,

    /* rfc4055 */
    BSL_CID_MGF1 = 127301,

    /* rfc3279 */
    BSL_CID_EC_PUBLICKEY = 130001,

    /* Attributes: rfc4519, rfc5280 */
    BSL_CID_COMMONNAME = 130301,
    BSL_CID_SURNAME,
    BSL_CID_SERIALNUMBER,
    BSL_CID_COUNTRYNAME,
    BSL_CID_LOCALITYNAME,
    BSL_CID_STATEORPROVINCENAME,
    BSL_CID_STREETADDRESS,
    BSL_CID_ORGANIZATIONNAME,
    BSL_CID_ORGANIZATIONUNITNAME,
    BSL_CID_TITLE,
    BSL_CID_GIVENNAME,
    BSL_CID_INITIALS,
    BSL_CID_GENERATIONQUALIFIER,
    BSL_CID_DNQUALIFIER,
    BSL_CID_PSEUDONYM,
    BSL_CID_DOMAINCOMPONENT,
    BSL_CID_USERID,
    BSL_CID_EMAILADDRESS,

    /* rfc 2985 attribute */
    BSL_CID_REQ_EXTENSION = 130601,

    /* rfc2315 */
    BSL_CID_CONTENTINFO = 130701,
    BSL_CID_DATA, // kind of contentInfo
    BSL_CID_SIGENEDDATA,
    BSL_CID_ENCRYPTEDDATA,
    BSL_CID_ENVELOPEDDATA,

    /* PKCS9  */
    BSL_CID_FRIENDLYNAME = 130801,
    BSL_CID_LOCALKEYID,
    BSL_CID_X509CERTIFICATE,

    /* rfc7292 */
    BSL_CID_KEYBAG = 130901, // kind of safeBag.
    BSL_CID_PKCS8SHROUDEDKEYBAG,
    BSL_CID_CERTBAG,
    BSL_CID_CRLBAG,
    BSL_CID_SECRETBAG,
    BSL_CID_SAFECONTENT,
    BSL_CID_PKCS12KDF,

    BSL_CID_MAX,
    BSL_CID_EXTEND = 0x60000000,
} BslCid;

#ifdef __cplusplus
}
#endif

#endif // BSL_OBJ_H
