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

#ifndef HITLS_PKI_X509_H
#define HITLS_PKI_X509_H

#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_X509_StoreCtx HITLS_X509_StoreCtx;

/**
 * @ingroup pki
 * @brief Certificate chain build function.
 * @attention
 *
 * @param int32_t [IN] Current error code for the current error.
 * @param HITLS_X509_StoreCtx [IN] X509store handle.

 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
typedef int32_t (*X509_STORECTX_VerifyCb)(int32_t, HITLS_X509_StoreCtx *);

/**
 * @ingroup pki
 * @brief Allocate a StoreCtx.
 *
 * @retval HITLS_X509_StoreCtx *
 */
HITLS_X509_StoreCtx *HITLS_X509_StoreCtxNew(void);

/**
 * @brief Create a new X509 store object using the provider mechanism
 *
 * @param libCtx [IN] Library context from CRYPT_EAL
 * @param attrName [IN] Provider attribute name for capability matching
 *
 * @return HITLS_X509_StoreCtx* Store object or NULL on failure
 */
HITLS_X509_StoreCtx *HITLS_X509_ProviderStoreCtxNew(HITLS_PKI_LibCtx *libCtx, const char *attrName);

/**
 * @ingroup pki
 * @brief Release the StoreCtx.
 *
 * @param storeCtx    [IN] StoreCtx.
 * @retval void
 */
void HITLS_X509_StoreCtxFree(HITLS_X509_StoreCtx *storeCtx);

/**
 * @ingroup pki
 * @brief Generic function to process StoreCtx.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param cmd [IN] HITLS_X509_Cmd                       data type             data length
 *        HITLS_X509_STORECTX_SET_PARAM_DEPTH           int32_t               sizeof(int32_t)
 *        HITLS_X509_STORECTX_SET_PARAM_FLAGS           uint64_t              sizeof(uint64_t)
 *        HITLS_X509_STORECTX_SET_TIME                  int64_t               sizeof(int64_t)
 *        HITLS_X509_STORECTX_SET_SECBITS               uint32_t              sizeof(uint32_t)
 *        HITLS_X509_STORECTX_CLR_PARAM_FLAGS           uint64_t              sizeof(uint64_t)
 *        HITLS_X509_STORECTX_DEEP_COPY_SET_CA          HITLS_X509_Cert       -
 *        HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA       HITLS_X509_Cert       -
 *        HITLS_X509_STORECTX_SET_CRL                   HITLS_X509_Crl        -
 *        HITLS_X509_STORECTX_SET_VFY_SM2_USERID        buffer                > 0
 *        HITLS_X509_STORECTX_SET_VERIFY_CB             callback function     sizeof(callback function)
 *        HITLS_X509_STORECTX_SET_USR_DATA              void *                sizeof(void *)
 *        HITLS_X509_STORECTX_ADD_CA_PATH               char *                string length
 *        HITLS_X509_STORECTX_CLEAR_CRL                 NULL                  0
 *        HITLS_X509_STORECTX_REF_UP                    int                   sizeof(int)
 *        HITLS_X509_STORECTX_GET_PARAM_DEPTH           int32_t *             sizeof(int32_t)
 *        HITLS_X509_STORECTX_GET_VERIFY_CB             callback function *   sizeof(callback function)
 *        HITLS_X509_STORECTX_GET_USR_DATA              void **               sizeof(void *)
 *        HITLS_X509_STORECTX_GET_PARAM_FLAGS           uint64_t *            sizeof(uint64_t)
 *        HITLS_X509_STORECTX_SET_ERROR                 int32_t               sizeof(int32_t)
 *        HITLS_X509_STORECTX_GET_ERROR                 int32_t *             sizeof(int32_t)
 *        HITLS_X509_STORECTX_GET_CUR_CERT              HITLS_X509_Cert **    sizeof(HITLS_X509_Cert *)
 *        HITLS_X509_STORECTX_SET_CUR_DEPTH             int32_t               sizeof(int32_t)
 *        HITLS_X509_STORECTX_GET_CUR_DEPTH             int32_t *             sizeof(int32_t)
 *        HITLS_X509_STORECTX_GET_CERT_CHAIN            HITLS_X509_List **    sizeof(HITLS_X509_List *)
 * @param val [IN/OUT] input and output value.
 * @param valLen [IN] value length.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_StoreCtxCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup pki
 * @brief Certificate chain verify function.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param chain [IN] certificate chain.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertVerify(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);

/**
 * @ingroup pki
 * @brief Certificate chain build function.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param isWithRoot [IN] whether the root cert is included.
 * @param cert [IN] certificate.
 * @param chain [OUT] certificate chain.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertChainBuild(HITLS_X509_StoreCtx *storeCtx, bool isWithRoot, HITLS_X509_Cert *cert,
    HITLS_X509_List **chain);

/**
 * @ingroup pki
 * @brief Verifies a certificate's hostname according to RFC6125 and RFC9525.
 *        It first checks for a matching dNSName in the Subject Alternative Name (SAN) extension.
 *        If, and only if, no dNSName entries are present, it falls back to check the Common Name (CN).
 *          flags:
 *        - # if no flag, default mode with '*.example.com' as RFC9525, we will check CN name if SAN is not present.
 *        - # if flag contains HITLS_X509_FLAG_VFY_WITH_PARTIAL_WILDCARD:
 *               more flexible wildcard matching as RFC6125 like 'fo*.example.com' matches
 *              'foo.example.com', we also will check CN name if SAN is not present.
 *
 * @param cert [IN] The certificate to verify.
 * @param flags [IN] A flag controlling wildcard matching behavior.
 * @param hostname [IN] The hostname to match against.
 * @param hostnameLen [IN] The length of the hostname.
 * @retval #HITLS_PKI_SUCCESS if the hostname is successfully verified.
 * @retval #HITLS_X509_ERR_VFY_HOSTNAME_FAIL if the hostname does not match.
 * @retval Other error codes for parsing or parameter errors.
 */
int32_t HITLS_X509_VerifyHostname(HITLS_X509_Cert *cert, uint32_t flags, const char *hostname, uint32_t hostnameLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_X509_H
