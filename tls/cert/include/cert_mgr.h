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
#include "bsl_hash.h"
#include "tls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Used to transfer certificates, private keys, and certificate chains. */
typedef struct {
    HITLS_CERT_X509 *cert;      /* device certificate */
#ifdef HITLS_TLS_PROTO_TLCP11
    /* encrypted device cert. Currently this field is used only when the peer-end encrypted certificate is stored. */
    HITLS_CERT_X509 *encCert;
    HITLS_CERT_Key *encPrivateKey;
#endif
    HITLS_CERT_Key *privateKey; /* private key corresponding to the certificate */
    HITLS_CERT_Chain *chain;    /* certificate chain */
} CERT_Pair;

struct CertMgrCtxInner {
    uint32_t currentCertKeyType;                  /* keyType to the certificate in use. */
    /* Indicates the certificate resources on the link. Only one certificate of a type can be loaded. */
    BSL_HASH_Hash *certPairs;                     /* cert hash table. key keyType, value CERT_Pair */
    HITLS_CERT_Chain *extraChain;
    HITLS_CERT_Store *verifyStore;              /* Verifies the store, which is used to verify the certificate chain. */
    HITLS_CERT_Store *chainStore;               /* Certificate chain store, used to assemble the certificate chain */
    HITLS_CERT_Store *certStore;                /* Default CA store */
#ifndef HITLS_TLS_FEATURE_PROVIDER
    HITLS_CERT_MgrMethod method;                /* callback function */
#endif
    HITLS_PasswordCb defaultPasswdCb;           /* Default password callback, used in loading certificate. */
    void *defaultPasswdCbUserData;              /* Set the userData used by the default password callback.  */
#ifdef HITLS_TLS_CONFIG_CERT_CALLBACK
    HITLS_VerifyCb verifyCb;                    /* Certificate verification callback function */
#endif /* HITLS_TLS_CONFIG_CERT_CALLBACK */
#ifdef HITLS_TLS_FEATURE_CERT_CB
    HITLS_CertCb certCb;                      /* Certificate callback function */
    void *certCbArg;                        /* Argument for the certificate callback function */
#endif /* HITLS_TLS_FEATURE_CERT_CB */
    HITLS_Lib_Ctx *libCtx;          /* library context */
    const char *attrName;              /* attrName */
};

#define LIBCTX_FROM_CERT_MGR_CTX(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->libCtx)
#define ATTR_FROM_CERT_MGR_CTX(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->attrName)

/* Get data from CERT_MgrCtx */
#define SAL_CERT_GET_VERIFY_STORE(mgrCtx) ((mgrCtx)->verifyStore)
#define SAL_CERT_GET_VERIFY_STORE_EX(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->verifyStore)

#define SAL_CERT_GET_CHAIN_STORE(mgrCtx) ((mgrCtx)->chainStore)
#define SAL_CERT_GET_CHAIN_STORE_EX(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->chainStore)

#define SAL_CERT_GET_CERT_STORE(mgrCtx) ((mgrCtx)->certStore)
#define SAL_CERT_GET_CERT_STORE_EX(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->certStore)

#define SAL_CERT_GET_DEFAULT_PWD_CB(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->defaultPasswdCb)
#define SAL_CERT_GET_DEFAULT_PWD_CB_USRDATA(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->defaultPasswdCbUserData)

#ifdef HITLS_TLS_CONFIG_CERT_CALLBACK
#define SAL_CERT_GET_VERIIFY_CB(mgrCtx) (((mgrCtx) == NULL) ? NULL : (mgrCtx)->verifyCb)
#endif

/* Get data from CERT_Pair */
#define SAL_CERT_PAIR_GET_X509(certPair) ((certPair)->cert)
#define SAL_CERT_PAIR_GET_X509_EX(certPair) (((certPair) == NULL) ? NULL : (certPair)->cert)

#define SAL_CERT_PAIR_GET_CHAIN(certPair) ((certPair)->chain)

#ifdef HITLS_TLS_PROTO_TLCP11
#define SAL_CERT_PAIR_GET_TLCP_ENC_CERT(certPair) ((certPair)->encCert)
#define SAL_CERT_PAIR_GET_TLCP_ENC_CERT_EX(certPair) (((certPair) == NULL) ? NULL : (certPair)->encCert)
#endif

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
 * @brief   Set the chain store
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   store  [IN] chain store
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetChainStore(CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store);

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

HITLS_CERT_Chain *SAL_CERT_GetExtraChainCerts(CERT_MgrCtx *mgrCtx, bool isExtraChainCertsOnly);

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
 * @brief   Set the default passwd callback.
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   cb     [IN] Callback function
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetDefaultPasswordCb(CERT_MgrCtx *mgrCtx, HITLS_PasswordCb cb);

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
 * @brief   Set the verify callback function, which is used during certificate verification.
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   cb     [IN] User data
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetVerifyCb(CERT_MgrCtx *mgrCtx, HITLS_VerifyCb cb);

/**
 * @ingroup
 * @brief   Set the current certificate to the value based on the option parameter.
 * @param   mgrCtx [OUT] Certificate management struct
 * @param   option [IN] Setting options, including HITLS_CERT_SET_FIRST and HITLS_CERT_SET_NEXT
 * @retval  HITLS_SUCCESS           succeeded.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t SAL_CERT_SetActiveCert(CERT_MgrCtx *mgrCtx, long option);

/**
 * @brief   Set the certificate callback function.
 *
 * @param   mgrCtx [IN] Certificate management struct
 * @param   certCb [IN] Certificate callback function
 * @param   arg    [IN] Parameter for the certificate callback function
 *
 * @retval  HITLS_SUCCESS           succeeded.
 */
int32_t SAL_CERT_SetCertCb(CERT_MgrCtx *mgrCtx, HITLS_CertCb certCb, void *arg);

/**
 * @brief   Free the certificate chain.
 *
 * @param   chain [IN] Certificate chain
 */
void SAL_CERT_ChainFree(HITLS_CERT_Chain *chain);
#ifdef __cplusplus
}
#endif
#endif