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

#ifndef CERT_METHOD_H
#define CERT_METHOD_H

#include <stdint.h>
#include "hitls_cert_type.h"
#include "tls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a certificate store.
 *
 * @param mgrCtx [IN] Certificate management struct
 *
 * @return Certificate store
 */
HITLS_CERT_Store *SAL_CERT_StoreNew(const CERT_MgrCtx *mgrCtx);

/**
 * @brief Copy the certificate store.
 *
 * @param mgrCtx [IN] Certificate management struct
 * @param store  [IN] Certificate store
 *
 * @return Certificate store
 */
HITLS_CERT_Store *SAL_CERT_StoreDup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store);

/**
 * @brief Release the certificate store.
 *
 * @param mgrCtx [IN] Certificate management struct
 * @param store  [IN] Certificate store
 *
 * @return  void
 */
void SAL_CERT_StoreFree(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store);

/**
 * @brief Construct the certificate chain.
 *
 * @param config   [IN] TLS link configuration
 * @param store    [IN] Certificate store
 * @param cert     [IN] Device certificate
 * @param certList [OUT] Certificate chain
 * @param num      [IN/OUT] IN: length of array OUT: length of certificate chain
 *
 * @retval HITLS_SUCCESS                succeeded.
 */
int32_t SAL_CERT_BuildChain(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **certList, uint32_t *num);

/**
 * @brief Verify the certificate chain.
 *
 * @param config   [IN] TLS link configuration
 * @param store    [IN] Certificate store
 * @param certList [IN] Certificate chain
 * @param num      [IN] length of certificate chain
 *
 * @retval HITLS_SUCCESS                succeeded.
 */
int32_t SAL_CERT_VerifyChain(HITLS_Ctx *ctx, HITLS_CERT_Store *store, HITLS_CERT_X509 **certList, uint32_t num);

/**
 * @brief Encode the certificate in ASN.1 DER format.
 *
 * @param ctx     [IN] TLS link object
 * @param cert    [IN] Certificate
 * @param buf     [OUT] Certificate encoding data
 * @param len     [IN] buffer length
 * @param usedLen [OUT] Data length
 *
 * @retval HITLS_SUCCESS                succeeded.
 */
int32_t SAL_CERT_X509Encode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len, uint32_t *usedLen);

/**
 * @brief Parse the bundle certificate to list.
 *
 * @param config [IN] TLS link configuration
 * @param buf    [IN] Certificate encoding data
 * @param len    [IN] Data length
 * @param type   [IN] Data type
 * @param format [IN] Data format
 *
 * @return certificate list
 */
HITLS_CERT_Chain *SAL_CERT_X509ParseBundleFile(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);

/**
 * @brief Parse the certificate.
 *
 * @param libCtx [IN] library context for provider
 * @param attrName [IN] attribute name of the provider, maybe NULL
 * @param config [IN] TLS link configuration
 * @param buf    [IN] Certificate encoding data
 * @param len    [IN] Data length
 * @param type   [IN] Data type
 * @param format [IN] Data format
 *
 * @return Certificate
 */
HITLS_CERT_X509 *SAL_CERT_X509Parse(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);

/**
 * @brief Copy the certificate.
 *
 * @param mgrCtx [IN] Certificate management struct
 * @param cert   [IN] Certificate
 *
 * @return Certificate
 */
HITLS_CERT_X509 *SAL_CERT_X509Dup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert);

/**
 * @brief Certificate reference increments by one.
 *
 * @param mgrCtx [IN] Certificate management struct
 * @param cert   [IN] Certificate
 *
 * @return Certificate
 */
HITLS_CERT_X509 *SAL_CERT_X509Ref(const CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert);

/**
 * @brief   Release the certificate.
 *
 * @param   cert [IN] Certificate
 *
 * @return  void
 */
void SAL_CERT_X509Free(HITLS_CERT_X509 *cert);

/**
 * @brief Parse the key.
 *
 * @param config [IN] TLS link configuration
 * @param buf    [IN] Key coded data
 * @param len    [IN] Data length
 * @param type   [IN] Data type
 * @param format [IN] Data format
 * @param encodeType [IN] Data encode type
 *
 * @return Key
 */
HITLS_CERT_Key *SAL_CERT_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, const char *format, const char *encodeType);

/**
 * @brief Get the parse format string.
 *
 * @param format [IN] Data format
 *
 * @return Parse format string
 */
const char *SAL_CERT_GetParseFormatStr(HITLS_ParseFormat format);

/**
 * @brief   Copy the key.
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   key [IN] Key
 *
 * @return  Key
 */
HITLS_CERT_Key *SAL_CERT_KeyDup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Key *key);

/**
 * @brief   Release the key.
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   cert [IN] Key
 *
 * @return  void
 */
void SAL_CERT_KeyFree(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Key *key);

/**
 * @brief Certificate store operation function
 *
 * @param config [IN] TLS link configuration
 * @param store  [IN] Certificate store
 * @param cmd    [IN] Operation command
 * @param in     [IN] Input parameter
 * @param out    [OUT] Output parameter
 *
 * @retval HITLS_SUCCESS                succeeded.
 */
int32_t SAL_CERT_StoreCtrl(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd, void *in, void *out);

/**
 * @brief Certificate operation function
 *
 * @param config [IN] TLS link configuration
 * @param cert   [IN] Certificate
 * @param cmd    [IN] Operation command
 * @param in     [IN] Input parameter
 * @param out    [OUT] Output parameter
 *
 * @retval HITLS_SUCCESS                succeeded.
 */
int32_t SAL_CERT_X509Ctrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd, void *in, void *out);

/**
 * @brief Key operation function
 *
 * @param config [IN] TLS link configuration
 * @param key    [IN] Key
 * @param cmd    [IN] Operation command
 * @param in     [IN] Input parameter
 * @param out    [OUT] Output parameter
 *
 * @retval HITLS_SUCCESS                succeeded.
 */
int32_t SAL_CERT_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd, void *in, void *out);

/**
 * @brief Verify the certificate private key pair.
 *
 * @param config [IN] TLS link configuration
 * @param cert   [IN] Certificate
 * @param key    [IN] Key
 *
 * @retval HITLS_SUCCESS                succeeded.
 */
int32_t SAL_CERT_CheckPrivateKey(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key);

/**
 * @brief Parse CRL from data.
 *
 * @param config [IN] TLS link configuration
 * @param buf    [IN] CRL data buffer
 * @param len    [IN] Data length
 * @param type   [IN] Parse type (file or buffer)
 * @param format [IN] Data format
 *
 * @retval HITLS_CERT_CRLList * CRL list, NULL on failure
 */
HITLS_CERT_CRLList *SAL_CERT_CrlParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);

/**
 * @brief Free CRL list.
 *
 * @param crlList [IN] CRL list to be freed
 */
void SAL_CERT_CrlFree(HITLS_CERT_CRLList *crlList);

#ifdef __cplusplus
}
#endif
#endif