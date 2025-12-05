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

#ifndef HITLS_PKI_CERT_H
#define HITLS_PKI_CERT_H

#include "hitls_pki_types.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_X509_Cert HITLS_X509_Cert;

/**
 * @ingroup pki
 * @brief Allocate a certificate.
 *
 * @retval HITLS_X509_Cert *
 */
HITLS_X509_Cert *HITLS_X509_CertNew(void);

/**
 * @brief Create a new X509 certificate object using the provider mechanism
 *
 * @param libCtx [IN] Library context from CRYPT_EAL_LibCtx
 * @param attrName [IN] Provider attribute name for capability matching
 *
 * @return HITLS_X509_Cert* Certificate object or NULL on failure
 */
HITLS_X509_Cert *HITLS_X509_ProviderCertNew(HITLS_PKI_LibCtx *libCtx, const char *attrName);

/**
 * @ingroup pki
 * @brief Unallocate a certificate.
 *
 * @param cert [IN] The certificate.
 */
void HITLS_X509_CertFree(HITLS_X509_Cert *cert);

/**
 * @ingroup pki
 * @brief Duplicate a certificate.
 *
 * @param src  [IN] Source certificate.
 * @retval HITLS_X509_Cert *, success.
 *         NULL, fail.
 */
HITLS_X509_Cert *HITLS_X509_CertDup(HITLS_X509_Cert *src);

/**
 * @ingroup pki
 * @brief Sign a certificate.
 *
 * @attention 1. This function can only be used when generating a new certificate.
 *            2. You need to first call interfaces HITLS_X509_CertCtrl to set cert information.
 *
 * @param mdId     [IN] The message digest algorithm ID.
 * @param prvKey   [IN] The private key context used for signing.
 * @param algParam [IN] The signature algorithm parameters.
 * @param cert     [IN] The certificate to be signed.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Cert *cert);

/**
 * @ingroup pki
 * @brief Compute the digest of the certificate.
 *
 * @attention This function must be called after generating or parsing a certificate.
 *
 * @param cert  [IN] The certificate.
 * @param mdId [IN] Digest algorithm.
 * @param data [IN/OUT] The digest result.
 * @param dataLen [IN/OUT] The length of the digest.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertDigest(HITLS_X509_Cert *cert, CRYPT_MD_AlgId mdId, uint8_t *data, uint32_t *dataLen);

/**
 * @ingroup pki
 * @brief Generic function to process certificate.
 *
 * @param cert   [IN] The certificate.
 * @param cmd    [IN] HITLS_X509_Cmd
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertCtrl(HITLS_X509_Cert *cert, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup pki
 * @brief Parse the CERT in the buffer.
 * @par Description: Parse the CERT in the buffer.
 *  If the parsing is successful, the memory for the cert is requested from within the function,
 *  and the user needs to free it after use. When the parameter is BSL_FORMAT_PEM and
 *  BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param encode [IN] CERT data.
 *        BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 *        the dataLen should exclude the end '\0'
 * @param cert   [OUT] CERT after parse.
 * @return #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Cert **cert);

/**
 * @ingroup pki
 * @brief Parse a certificate buffer using the provider mechanism
 * @par Description: Parse the certificate data using a specific provider implementation.
 *  If parsing is successful, memory for the certificate is allocated internally,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 *
 * @param libCtx [IN] Library context from CRYPT_EAL_LibCtx
 * @param attrName [IN] Provider attribute name for capability matching
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN
 * @param encode [IN] Certificate data buffer
 *        BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 *        the dataLen should exclude the end '\0'
 * @param cert [OUT] Parsed certificate object
 * @return #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_ProviderCertParseBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const BSL_Buffer *encode, HITLS_X509_Cert **cert);

/**
 * @ingroup pki
 * @brief Parse the CERT in the file.
 * @par Description: Parse the CERT in the file.
 *  If the parsing is successful, the memory for the cert is requested from within the function,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param path   [IN] CERT file path.
 * @param cert   [OUT] CERT after parse.
 * @return #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertParseFile(int32_t format, const char *path, HITLS_X509_Cert **cert);

/**
 * @ingroup pki
 * @brief Parse a certificate file using the provider mechanism
 * @par Description: Parse the certificate from a file using a specific provider implementation.
 *  If parsing is successful, memory for the certificate is allocated internally,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 *
 * @param libCtx [IN] Library context from CRYPT_EAL_LibCtx
 * @param attrName [IN] Provider attribute name for capability matching
 * @param format [IN] Encoding format: "PEM"/"ASN1"/NULL
 * @param path [IN] Certificate file path
 * @param cert [OUT] Parsed certificate object
 * @return #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_ProviderCertParseFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const char *path, HITLS_X509_Cert **cert);

/**
 * @ingroup pki
 * @brief Parse the CERTs in the file.
 * @par Description: Parse multiple CERTs in the file.
 *  If the parsing is successful, the memory for the certlist is requested from within the function,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 * @param format  [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param path    [IN] Certificate file path.
 * @param certlist [OUT] Certificate list after parse.
 * @return #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertParseBundleFile(int32_t format, const char *path, HITLS_X509_List **certlist);

/**
 * @ingroup pki
 * @brief Parse multiple certificates from a bundle file using the provider mechanism
 * @par Description: Parse multiple certificates from a file using a specific provider implementation.
 *  If parsing is successful, memory for the certificate list is allocated internally,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 *
 * @param libCtx [IN] Library context from CRYPT_EAL_LibCtx
 * @param attrName [IN] Provider attribute name for capability matching
 * @param format [IN] Encoding format: "PEM"/"ASN1"/NULL
 * @param path [IN] Certificate bundle file path
 * @param certlist [OUT] List of parsed certificate objects
 * @return #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_ProviderCertParseBundleFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const char *path, HITLS_X509_List **certlist);

/**
 * @ingroup pki
 * @brief Generates an encoded certificate.
 *
 * @attention This function is used after parsing the certificate or after signing.
 *
 * @param format [IN] Encoding format: BSL_FORMAT_ASN1 or BSL_FORMAT_PEM
 * @param cert   [IN] cert
 * @param buff   [OUT] encode result
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertGenBuff(int32_t format, HITLS_X509_Cert *cert, BSL_Buffer *buff);

/**
 * @ingroup pki
 * @brief Generate a certificate file.
 *
 * @attention This function is used after parsing the certificate or after signing.
 *
 * @param format [IN] Encoding format: BSL_FORMAT_ASN1 or BSL_FORMAT_PEM
 * @param cert   [IN] cert
 * @param path   [IN] file path
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertGenFile(int32_t format, HITLS_X509_Cert *cert, const char *path);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CERT_H
