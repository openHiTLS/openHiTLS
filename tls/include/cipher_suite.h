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

#ifndef CIPHER_SUITE_H
#define CIPHER_SUITE_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "hitls_config.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00ffu   /* renegotiation cipher suite */

#define TLS_FALLBACK_SCSV 0x5600u   /* downgraded protocol cipher suite */

/* cert request Type of the certificate requested */
typedef enum {
    /* rfc5246 7.4.4 */
    CERT_TYPE_RSA_SIGN = 1,
    CERT_TYPE_DSS_SIGN = 2,
    CERT_TYPE_RSA_FIXED_DH = 3,
    CERT_TYPE_DSS_FIXED_DH = 4,
    /* rfc8422 5.5 */
    CERT_TYPE_ECDSA_SIGN = 64,
    CERT_TYPE_UNKNOWN = 255
} CERT_Type;

/**
 * CipherSuiteInfo structure, used to transfer public cipher suite information.
 */
typedef struct TlsCipherSuiteInfo {
    bool enable;                        /**< Enable flag */
    const char *name;                   /**< Cipher suite name */
    const char *stdName;                /**< RFC name of the cipher suite */
    uint16_t cipherSuite;               /**< cipher suite */

    /* algorithm type */
    HITLS_CipherAlgo cipherAlg;         /**< Symmetric-key algorithm */
    HITLS_KeyExchAlgo kxAlg;            /**< key exchange algorithm */
    HITLS_AuthAlgo authAlg;             /**< server authorization algorithm */
    HITLS_MacAlgo macAlg;               /**< mac algorithm */
    HITLS_HashAlgo hashAlg;             /**< hash algorithm */

    /**
     * Signature combination, including the hash algorithm and signature algorithm:
     * TLS 1.2 negotiates the signScheme.
     */
    HITLS_SignHashAlgo signScheme;

    /* key length */
    uint8_t fixedIvLength;     /**< If the AEAD algorithm is used, the value is the implicit IV length */
    uint8_t encKeyLen;         /**< Length of the symmetric key */
    uint8_t macKeyLen;         /**<  If the AEAD algorithm is used, the MAC key length is 0 */

    /* result length */
    uint8_t blockLength;      /**< If the block length is not zero, the alignment should be handled */
    uint8_t recordIvLength;   /**< The explicit IV needs to be sent to the peer end */
    uint8_t macLen;           /**< The length of the MAC address. If the AEAD algorithm is used, this member variable
                                *  will be the length of the tag */

    uint16_t minVersion;         /**< Minimum version supported by the cipher suite */
    uint16_t maxVersion;         /**< Maximum version supported by the cipher suite */
    uint16_t minDtlsVersion;     /**< Minimum DTLS version supported by the cipher suite */
    uint16_t maxDtlsVersion;     /**< Maximum DTLS version supported by the cipher suite */
    HITLS_CipherType cipherType; /**< Encryption algorithm type */
    int32_t strengthBits;        /**< Encryption algorithm strength */
} CipherSuiteInfo;

/**
 * SignSchemeInfo structure, used to transfer the signature algorithm information.
 */
typedef struct {
    HITLS_SignHashAlgo scheme;      /**< Signature hash algorithm */
    HITLS_SignAlgo signAlg;         /**< Signature algorithm */
    HITLS_HashAlgo hashAlg;         /**< hash algorithm */
} SignSchemeInfo;

typedef struct {
    HITLS_SignHashAlgo scheme;      /**< signature algorithm */
    HITLS_NamedGroup cureName;      /**< public key curve name (ECDSA only) */
} EcdsaCurveInfo;

/**
 * Mapping between cipher suites and certificate types
 */
typedef struct {
    uint16_t cipherSuite;      /**< cipher suite */
    CERT_Type certType;        /**< Certificate type */
} CipherSuiteCertType;

/**
 * @brief   Obtain the cipher suite information.
 *
 * @param   cipherSuite [IN] Cipher suite of the information to be obtained
 * @param   cipherInfo  [OUT] Cipher suite information
 *
 * @retval  HITLS_SUCCESS obtained successfully.
 * @retval  HITLS_INTERNAL_EXCEPTION An unexpected internal error.
 * @retval  HITLS_MEMCPY_FAIL memcpy_s failed to be executed.
 * @retval  HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE No information about the cipher suite is found.
 */
int32_t CFG_GetCipherSuiteInfo(uint16_t cipherSuite, CipherSuiteInfo *cipherInfo);

/**
 * @brief   Check whether the input cipher suite is supported.
 *
 * @param   cipherSuite [IN] cipher suite to be checked
 *
 * @retval  true Supported
 * @retval  false Not supported
 */
bool CFG_CheckCipherSuiteSupported(uint16_t cipherSuite);

/**
 * @brief   Check whether the input cipher suite complies with the version.
 *
 * @param   cipherSuite [IN] cipher suite to be checked
 * @param   minVersion  [IN] Indicates the earliest version of the cipher suite.
 * @param   maxVersion  [IN] Indicates the latest version of the cipher suite.
 *
 * @retval  true Supported
 * @retval  false Not supported
 */
bool CFG_CheckCipherSuiteVersion(uint16_t cipherSuite, uint16_t minVersion, uint16_t maxVersion);

/**
 * @brief  Obtain the signature algorithm and hash algorithm by combining the parameters of
 * the signature hash algorithm.
 * @param   ctx [IN] TLS context
 * @param   scheme [IN] Signature and hash algorithm combination
 * @param   signAlg [OUT] Signature algorithm
 * @param   hashAlg [OUT] Hash algorithm
 *
 * @retval  true Obtained successfully.
 * @retval  false Obtaining failed.
 */
bool CFG_GetSignParamBySchemes(const HITLS_Ctx *ctx, HITLS_SignHashAlgo scheme, HITLS_SignAlgo *signAlg,
    HITLS_HashAlgo *hashAlg);

/**
 * @brief   Obtain the certificate type based on the cipher suite.
 *
 * @param   cipherSuite [IN] Cipher suite
 *
 * @retval  Certificate type corresponding to the cipher suite
 */
uint8_t CFG_GetCertTypeByCipherSuite(uint16_t cipherSuite);

/**
 * @brief   get the group name of the ecdsa
 *
 * @param   scheme [IN] signature algorithm
 *
 * @retval  group name
 */
HITLS_NamedGroup CFG_GetEcdsaCurveNameBySchemes(const HITLS_Ctx *ctx, HITLS_SignHashAlgo scheme);

#define IS_SM_TLS13(cipherSuite) (((cipherSuite) == HITLS_SM4_GCM_SM3) || ((cipherSuite) == HITLS_SM4_CCM_SM3))

#ifdef __cplusplus
}
#endif

#endif // CIPHER_SUITE_H
