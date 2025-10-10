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
#ifndef CERT_MGR_CTX_H
#define CERT_MGR_CTX_H

#include <stdint.h>
#include "hitls_crypt_type.h"
#include "hitls_cert_reg.h"
#include "cert.h"
#include "bsl_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CERT_DEFAULT_HASH_BKT_SIZE 64u

struct CertPairInner {
    HITLS_CERT_X509 *cert;      /* device certificate */
#ifdef HITLS_TLS_PROTO_TLCP11
    /* encrypted device cert. Currently this field is used only when the peer-end encrypted certificate is stored. */
    HITLS_CERT_X509 *encCert;
    HITLS_CERT_Key *encPrivateKey;
#endif
    HITLS_CERT_Key *privateKey; /* private key corresponding to the certificate */
    HITLS_CERT_Chain *chain;    /* certificate chain */
};

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

CERT_Type CertKeyType2CertType(HITLS_CERT_KeyType keyType);

int32_t CheckCurveName(HITLS_Config *config, const uint16_t *curveList, uint32_t curveNum, HITLS_CERT_Key *pubkey);

int32_t CheckPointFormat(HITLS_Config *config, const uint8_t *ecPointFormatList, uint32_t listSize,
    HITLS_CERT_Key *pubkey);

/* These functions can be stored in a separate header file. */
HITLS_CERT_Chain *SAL_CERT_ChainNew(void);
int32_t SAL_CERT_ChainAppend(HITLS_CERT_Chain *chain, HITLS_CERT_X509 *cert);
HITLS_CERT_Chain *SAL_CERT_ChainDup(CERT_MgrCtx *mgrCtx, HITLS_CERT_Chain *chain);

#define LIBCTX_FROM_CERT_MGR_CTX(mgrCtx) ((mgrCtx == NULL) ? NULL : (mgrCtx)->libCtx)
#define ATTRIBUTE_FROM_CERT_MGR_CTX(mgrCtx) ((mgrCtx == NULL) ? NULL : (mgrCtx)->attrName)

#ifdef __cplusplus
}
#endif
#endif