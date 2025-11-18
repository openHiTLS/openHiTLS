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

#ifndef CERT_MGR_H
#define CERT_MGR_H

#include <stdint.h>
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "hitls_cert_reg.h"
#include "hitls_cert.h"
#include "tls_config.h"
#include "bsl_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Used to transfer certificates, private keys, and certificate chains. */
typedef struct CertPairInner CERT_Pair;

/**
 * @brief   Obtain the certificate
 *
 * @param   certPair [IN] Certificate resource struct
 *
 * @return  Certificate
 */
HITLS_CERT_X509 *SAL_CERT_PairGetX509(CERT_Pair *certPair);

/**
 * @ingroup hitls_cert_reg
 * @brief   Obtain the encryption certificate
 *
 * @param   certPair [IN] Certificate resource struct
 *
 * @return  Encryption certificate
 */
HITLS_CERT_X509 *SAL_CERT_GetTlcpEncCert(CERT_Pair *certPair);

HITLS_CERT_Chain *SAL_CERT_PairGetChain(CERT_Pair *certPair);

CERT_Pair *SAL_CERT_PairDup(CERT_MgrCtx *mgrCtx, CERT_Pair *srcCertPair);

/**
 * @brief   Uninstall the certificate resource but not release the struct
 *
 * @param   mgrCtx   [IN] Certificate management struct
 * @param   certPair [IN] Certificate resource struct
 *
 * @return  void
 */
void SAL_CERT_PairClear(CERT_MgrCtx *mgrCtx, CERT_Pair *certPair);

/**
 * @brief   Release the certificate resource struct
 *
 * @param   mgrCtx   [IN] Certificate management struct
 * @param   certPair [IN] Certificate resource struct. The certPair is set NULL by the invoker.
 *
 * @return  void
 */
void SAL_CERT_PairFree(CERT_MgrCtx *mgrCtx, CERT_Pair *certPair);

/**
 * @brief   Copy certificate hash table
 *
 * @param   destMgrCtx  [OUT] Certificate management struct
 * @param   srcMgrCtx   [IN] Certificate management struct
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_HashDup(CERT_MgrCtx *destMgrCtx, CERT_MgrCtx *srcMgrCtx);

/**
 * @brief   Indicates whether to enable the certificate management module.
 *
 * @param   void
 *
 * @retval  true  yes
 * @retval  false no
 */
bool SAL_CERT_MgrIsEnable(void);

/**
 * @brief   Callback for obtaining a certificate
 *
 * @param   NA
 *
 * @return  Certificate callback
 */
HITLS_CERT_MgrMethod *SAL_CERT_GetMgrMethod(void);

/**
 * @brief   Create a certificate management struct
 *
 * @param   void
 *
 * @return  Certificate management struct
 */
CERT_MgrCtx *SAL_CERT_MgrCtxNew(void);

/**
 * @brief   Create a certificate management struct with provider
 *
 * @param   libCtx     [IN] Provider library context
 * @param   attrName  [IN] Provider attrName
 *
 * @return  Certificate management struct
 */
CERT_MgrCtx *SAL_CERT_MgrCtxProviderNew(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @brief   Copy the certificate management struct
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  Certificate management struct
 */
CERT_MgrCtx *SAL_CERT_MgrCtxDup(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Release the certificate management struct
 *
 * @param   mgrCtx [IN] Certificate management struct. mgrCtx is set NULL by the invoker.
 *
 * @return  void
 */
void SAL_CERT_MgrCtxFree(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Set the cert store
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   store  [IN] cert store
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetCertStore(CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store);

/**
 * @brief   Obtain the cert store
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  cert store
 */
HITLS_CERT_Store *SAL_CERT_GetCertStore(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Set the chain store
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   store  [IN] chain store
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetChainStore(CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store);

/**
 * @brief   Obtain the chain store
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  chain store
 */
HITLS_CERT_Store *SAL_CERT_GetChainStore(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Set the verify store
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   store  [IN] verify store
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetVerifyStore(CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store);

/**
 * @brief   Obtain the verify store
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  verify store
 */
HITLS_CERT_Store *SAL_CERT_GetVerifyStore(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Add a device certificate and set it to the current. Only one certificate of each type can be added.
 *          If the certificate is added repeatedly, the certificate will be overwritten.
 *
 * @param   config      [IN] Certificate management struct
 * @param   cert        [IN] Device certificate
 * @param   isGmEncCert [IN] Indicates whether the certificate is encrypted using the TLCP.
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetCurrentCert(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isTlcpEncCert);

/**
 * @brief   Obtain the current device certificate
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  Device certificate
 */
HITLS_CERT_X509 *SAL_CERT_GetCurrentCert(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Obtain the certificate of the specified type.
 *
 * @param   mgrCtx  [IN] Certificate management struct
 * @param   keyType [IN] Certificate public key type
 *
 * @return  Device certificate
 */
HITLS_CERT_X509 *SAL_CERT_GetCert(CERT_MgrCtx *mgrCtx, HITLS_CERT_KeyType keyType);

/**
 * @brief   Add a private key and set it to the current key.
 *          Only one private key can be added for each type of certificate.
 *          If a private key is added repeatedly, it will be overwritten.
 *
 * @param   config [IN] Certificate management struct
 * @param   key    [IN] Private key
 * @param   isGmEncCertPriKey [IN] Indicates whether the private key of the certificate encrypted
 *                                 using the TLCP.
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetCurrentPrivateKey(HITLS_Config *config, HITLS_CERT_Key *key, bool isTlcpEncCertPriKey);

/**
 * @brief   Obtain the current private key
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   isGmEncCertPriKey [IN] Indicates whether the private key of the certificate encrypted
 *                                 using the TLCP.
 *
 * @return  Private key
 */
HITLS_CERT_Key *SAL_CERT_GetCurrentPrivateKey(CERT_MgrCtx *mgrCtx, bool isTlcpEncCert);

/**
 * @brief   Obtain the private key of a specified type.
 *
 * @param   mgrCtx  [IN] Certificate management struct
 * @param   keyType [IN] Private key type
 *
 * @return  Private key
 */
HITLS_CERT_Key *SAL_CERT_GetPrivateKey(CERT_MgrCtx *mgrCtx, HITLS_CERT_KeyType keyType);

int32_t SAL_CERT_AddChainCert(CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert);

HITLS_CERT_Chain *SAL_CERT_GetCurrentChainCerts(CERT_MgrCtx *mgrCtx);

void SAL_CERT_ClearCurrentChainCerts(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Delete all certificate resources, including the device certificate, private key, and certificate chain.
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  void
 */
void SAL_CERT_ClearCertAndKey(CERT_MgrCtx *mgrCtx);

int32_t SAL_CERT_AddExtraChainCert(CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert);

HITLS_CERT_Chain *SAL_CERT_GetExtraChainCerts(CERT_MgrCtx *mgrCtx);

void SAL_CERT_ClearExtraChainCerts(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Set or get certificate verification parameters.
 *
 * @param config [IN] TLS link configuration
 * @param store  [IN] Certificate store
 * @param cmd    [IN] Operation command, HITLS_CERT_CtrlCmd enum
 * @param in     [IN] Input parameter
 * @param out    [OUT] Output parameter
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_CtrlVerifyParams(HITLS_Config *config, HITLS_CERT_Store *store, uint32_t cmd, void *in, void *out);

/**
 * @brief   Set the verification depth
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   depth  [IN] Verification depth
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetVerifyDepth(CERT_MgrCtx *mgrCtx, uint32_t depth);

/**
 * @brief   Obtain the verification depth
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   depth  [IN] Verification depth
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_GetVerifyDepth(CERT_MgrCtx *mgrCtx, uint32_t *depth);

/**
 * @brief   Set the default passwd callback.
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   cb     [IN] Callback function
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetDefaultPasswordCb(CERT_MgrCtx *mgrCtx, HITLS_PasswordCb cb);

/**
 * @brief   Obtain the default passwd callback.
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  Callback function
 */
HITLS_PasswordCb SAL_CERT_GetDefaultPasswordCb(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Set the user data used in the default passwd callback.
 *
 * @param   mgrCtx   [IN] Certificate management struct
 * @param   userdata [IN] User data
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetDefaultPasswordCbUserdata(CERT_MgrCtx *mgrCtx, void *userdata);

/**
 * @brief   Obtain the user data used in the default passwd callback.
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  User data
 */
void *SAL_CERT_GetDefaultPasswordCbUserdata(CERT_MgrCtx *mgrCtx);

/**
 * @brief   Set the verify callback function, which is used during certificate verification.
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   cb     [IN] User data
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetVerifyCb(CERT_MgrCtx *mgrCtx, HITLS_VerifyCb cb);

/**
 * @brief   Obtain the verify callback function.
 *
 * @param   mgrCtx [IN] Certificate management struct
 *
 * @return  Callback function
 */
HITLS_VerifyCb SAL_CERT_GetVerifyCb(CERT_MgrCtx *mgrCtx);

#ifdef __cplusplus
}
#endif
#endif