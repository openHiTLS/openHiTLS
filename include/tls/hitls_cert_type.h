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
 * @defgroup hitls_cert_type
 * @ingroup  hitls
 * @brief    Structures related to a certificate
 */

#ifndef HITLS_CERT_TYPE_H
#define HITLS_CERT_TYPE_H

#include <stdint.h>
#include "bsl_obj.h"
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_cert_type
 * @brief   Describes the x509 certificate
 */
typedef void HITLS_CERT_X509;

/**
 * @ingroup hitls_cert_type
 * @brief   Describes the CRL
 */
typedef void HITLS_CERT_CRL;

/**
 * @ingroup hitls_cert_type
 * @brief   Describes the certificate key
 */
typedef void HITLS_CERT_Key;

/**
 * @ingroup hitls_cert_type
 * @brief   Describes the certificate
 */
typedef void HITLS_CERT_Store;

/**
 * @ingroup hitls_cert_type
 * @brief   Describes the certificate
 */
typedef void HITLS_CERT_StoreCtx;

/**
 * @ingroup hitls_cert_type
 * @brief    Describes the list of trusted CAs
 */
typedef struct BslList HITLS_TrustedCAList;

/**
 * @ingroup hitls_cert_type
 * @brief   Describes the certificate chain
 */
typedef struct BslList HITLS_CERT_Chain;

/**
 * @ingroup hitls_cert_type
 * @brief   Describes the CRL list
 */
typedef struct BslList HITLS_CERT_CRLList;

/**
 * @ingroup hitls_cert_type
 * @brief   ctrl option
 */
typedef enum {
    CERT_STORE_CTRL_SET_VERIFY_DEPTH = 0,   /**< Set the certificate verification depth. */
    CERT_STORE_CTRL_ADD_CERT_LIST,      /**< Add ca and chain certificate to store */
    CERT_STORE_CTRL_ADD_CRL_LIST,       /**< Add CRL list to store */
    CERT_STORE_CTRL_CLEAR_CRL_LIST,     /**< clear all CRL list */
    CERT_STORE_CTRL_SET_VERIFY_FLAGS,   /**< Set the certificate verification flags. */
    CERT_STORE_CTRL_ADD_CA_PATH,              /**< Set the CA path. */

    CERT_CTRL_GET_ENCODE_LEN = 200,           /**< Obtain the length of the certificate code. */
    CERT_CTRL_GET_PUB_KEY,              /**< Obtaining the Certificate Public Key (Release Required). */
    CERT_CTRL_GET_SIGN_ALGO,            /**< Obtain the certificate signature algorithm. */


    CERT_KEY_CTRL_GET_SIGN_LEN = 400,         /**< Obtain the signature length. */
    CERT_KEY_CTRL_GET_TYPE,             /**< Obtaining the Key Type. */
    CERT_KEY_CTRL_GET_CURVE_NAME,       /**< Obtain the elliptic curve ID. */
    CERT_KEY_CTRL_GET_POINT_FORMAT,     /**< Obtains the format of the EC point. */
    CERT_KEY_CTRL_GET_SECBITS,          /**< Obtain the security bits. */
    CERT_KEY_CTRL_IS_KEYENC_USAGE,      /**< Is the encryption certificate permission. */
    CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE,      /**< Is it digital signature permission. */
    CERT_KEY_CTRL_IS_KEY_CERT_SIGN_USAGE,     /**< Is the certificate issuing permission. */
    CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE,     /**< Is it the certificate verification permission. */
    CERT_KEY_CTRL_GET_PARAM_ID,               /**< Obtain the parameter ID. */
    CERT_KEY_CTRL_IS_DATA_ENC_USAGE,          /**< Is it the data encryption permission. */
    CERT_KEY_CTRL_IS_NON_REPUDIATION_USAGE,   /**< Is it the non-repudiation permission. */
    CERT_KEY_CTRL_GET_PSS_MD,                 /**< Obtain PSS hash */

    CERT_CTRL_BUTT,
} HITLS_CERT_CtrlCmd;

/**
 * @ingroup hitls_cert_type
 * @brief   Read data format
 */
typedef enum {
    TLS_PARSE_TYPE_FILE,   /**< Parse file */
    TLS_PARSE_TYPE_BUFF,   /**< Parse buffer */
    TLS_PARSE_TYPE_BUTT,
} HITLS_ParseType;

/**
 * @ingroup hitls_cert_type
 * @brief   Read data format
 */
typedef enum {
    TLS_PARSE_FORMAT_PEM = BSL_FORMAT_PEM,        /**< PEM format */
    TLS_PARSE_FORMAT_ASN1 = BSL_FORMAT_ASN1,       /**< ASN1 format */
    TLS_PARSE_FORMAT_PFX_COM = BSL_FORMAT_PFX_COM,    /**< PFX COM format */
    TLS_PARSE_FORMAT_PKCS12 = BSL_FORMAT_PKCS12,     /**< PKCS12 format */
    TLS_PARSE_FORMAT_BUTT = BSL_FORMAT_UNKNOWN,
} HITLS_ParseFormat;

/**
 * @ingroup hitls_cert_type
 * @brief   cert store type
 */
typedef enum {
    TLS_CERT_STORE_TYPE_DEFAULT,   /**< Default CA store */
    TLS_CERT_STORE_TYPE_VERIFY,    /**< Verifies the store, which is used to verify the certificate chain */
    TLS_CERT_STORE_TYPE_CHAIN,     /**< Certificate chain store, used to assemble the certificate chain */
    TLS_CERT_STORE_TYPE_BUTT,
} HITLS_CERT_StoreType;

/**
 * @ingroup hitls_cert_type
 * @brief   Certificate Public Key Type
 */
typedef enum {
    TLS_CERT_KEY_TYPE_UNKNOWN = BSL_CID_UNKNOWN,
    TLS_CERT_KEY_TYPE_RSA = BSL_CID_RSA,
    TLS_CERT_KEY_TYPE_RSA_PSS = BSL_CID_RSASSAPSS,
    TLS_CERT_KEY_TYPE_DSA = BSL_CID_DSA,
    TLS_CERT_KEY_TYPE_ECDSA = BSL_CID_ECDSA,
    TLS_CERT_KEY_TYPE_ED25519 = BSL_CID_ED25519,
    TLS_CERT_KEY_TYPE_SM2 = BSL_CID_SM2DSA
} HITLS_CERT_KeyType;

/**
 * @ingroup hitls_cert_type
 * @brief   Certificate Signature Algorithm Enumeration
 */
typedef enum {
    /* Reservation algorithm. */
    CERT_SIG_SCHEME_RSA_PKCS1_SHA1 = 0x0201,
    CERT_SIG_SCHEME_DSA_SHA1 = 0X0202,
    CERT_SIG_SCHEME_ECDSA_SHA1 = 0x0203,
    CERT_SIG_SCHEME_ECDSA_SHA224 = 0x0303,
    /* RSASSA-PKCS1-v1_5 algorithms */
    CERT_SIG_SCHEME_RSA_PKCS1_SHA224 = 0x0301,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA256 = 0x0401,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA384 = 0x0501,
    CERT_SIG_SCHEME_RSA_PKCS1_SHA512 = 0x0601,
    /* DSA algorithms */
    CERT_SIG_SCHEME_DSA_SHA224 = 0x0302,
    CERT_SIG_SCHEME_DSA_SHA256 = 0X0402, /**<  signature algorithm: DSA_SHA256 */
    CERT_SIG_SCHEME_DSA_SHA384 = 0X0502, /**<  signature algorithm: DSA_SHA384 */
    CERT_SIG_SCHEME_DSA_SHA512 = 0X0602, /**<  signature algorithm: DSA_SHA512 */
    /* ECDSA algorithms */
    CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256 = 0x0403,
    CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384 = 0x0503,
    CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512 = 0x0603,
    /* GM sig algorithms */
    CERT_SIG_SCHEME_SM2_SM3 = 0x0708,
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256 = 0x0804,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384 = 0x0805,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512 = 0x0806,
    /* EdDSA algorithms */
    CERT_SIG_SCHEME_ED25519 = 0x0807,
    CERT_SIG_SCHEME_ED448 = 0x0808,
    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256 = 0x0809,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384 = 0x080a,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512 = 0x080b,
    CERT_SIG_SCHEME_UNKNOWN = 0xffff
} HITLS_SignHashAlgo;

/**
 * @ingroup hitls_cert_type
 * @brief   Trusted CA ID Type
 */
typedef enum {
    HITLS_TRUSTED_CA_PRE_AGREED = 0, /**< preset CA */
    HITLS_TRUSTED_CA_KEY_SHA1 = 1,   /**< Trusted CA key Hash  */
    HITLS_TRUSTED_CA_X509_NAME = 2,  /**< Trusted CA x509 Certificate Name */
    HITLS_TRUSTED_CA_CERT_SHA1 = 3,  /**< Trusted CA Certificate Hash */
    HITLS_TRUSTED_CA_UNKNOWN = 255
} HITLS_TrustedCAType;

/**
 * @ingroup hitls_cert_type
 * @brief   Node structure used to describe the trusted CA certificate list
 */
typedef struct HitlsTrustedCANode {
    HITLS_TrustedCAType caType; /**< Trusted CA type */
    uint8_t *data;              /**< Trusted CA data */
    uint32_t dataSize;          /**< Trusted CA data length */
} HITLS_TrustedCANode;

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CERT_TYPE_H */
