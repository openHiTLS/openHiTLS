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

#ifndef HITLS_PKI_CSR_H
#define HITLS_PKI_CSR_H

#include "hitls_pki_types.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_X509_Csr HITLS_X509_Csr;

/**
 * @ingroup pki
 * @brief Allocate a pkcs10 csr.
 *
 * @retval HITLS_X509_Csr *
 */
HITLS_X509_Csr *HITLS_X509_CsrNew(void);

/**
 * @ingroup pki
 * @brief Create a new csr object using the provider mechanism
 *
 * @param libCtx [IN] Library context from CRYPT_EAL_LibCtx
 * @param attrName [IN] Provider attribute name for capability matching
 *
 * @return HITLS_X509_Csr* Csr object or NULL on failure
 */
HITLS_X509_Csr *HITLS_X509_ProviderCsrNew(HITLS_PKI_LibCtx *libCtx, const char *attrName);

/**
 * @ingroup pki
 * @brief Release the pkcs10 csr.
 *
 * @param csr    [IN] CSR context.
 * @retval void
 */
void HITLS_X509_CsrFree(HITLS_X509_Csr *csr);

/**
 * @ingroup pki
 * @brief Sign a CSR (Certificate Signing Request).
 *
 * @attention 1. This function can only be used when generating a new csr.
 *            2. You need to first call interfaces HITLS_X509_CsrCtrl and HITLS_X509_AttrCtrl to set csr information.
 *
 * @param mdId     [IN] The message digest algorithm ID.
 * @param prvKey   [IN] The private key context used for signing.
 * @param algParam [IN] The signature algorithm parameters.
 * @param csr      [IN] The CSR to be signed.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Csr *csr);

/**
 * @ingroup pki
 * @brief Generate csr to store in buffer
 *
 * @attention This function is used after parsing the csr or after signing.
 *
 * @param format [IN] The format of the generated csr: BSL_FORMAT_ASN1/BSL_FORMAT_PEM
 * @param csr    [IN] The csr context
 * @param buff   [OUT] The buffer of the generated csr.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrGenBuff(int32_t format, HITLS_X509_Csr *csr, BSL_Buffer *buff);

/**
 * @ingroup pki
 * @brief Generate csr to store in file
 *
 * @attention This function is used after parsing the csr or after signing.
 *
 * @param format [IN] The format of the generated csr: BSL_FORMAT_ASN1/BSL_FORMAT_PEM
 * @param csr    [IN] The csr context
 * @param path   [IN] The path of the generated csr.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrGenFile(int32_t format, HITLS_X509_Csr *csr, const char *path);

/**
 * @ingroup pki
 * @brief Generic function to process csr function
 *
 * @param csr [IN] The csr context
 * @param cmd [IN] HITLS_X509_Cmd
 * @param val [IN/OUT] input and output value.
 * @param valLen [IN] value length.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrCtrl(HITLS_X509_Csr *csr, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup pki
 * @brief Parse the csr in the buffer.When the parameter is BSL_FORMAT_PEM and
 *  BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 *
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1
 * @param encode [IN] The csr data
 * @param csr [OUT] The csr context after parsing
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Csr **csr);

/**
 * @ingroup pki
 * @brief Parse the csr in the file
 *
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1
 * @param path [IN] The csr file path
 * @param csr [OUT] The csr context after parsing
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrParseFile(int32_t format, const char *path, HITLS_X509_Csr **csr);

/**
 * @ingroup pki
 * @brief Csr verify function
 *
 * @param csr [IN] The csr context
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrVerify(HITLS_X509_Csr *csr);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CSR_H
