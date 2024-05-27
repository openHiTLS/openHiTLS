/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_X509_H
#define HITLS_X509_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_list.h"
#include "bsl_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_X509_List BslList

typedef struct _HITLS_X509_Cert HITLS_X509_Cert;

typedef struct _HITLS_X509_Crl HITLS_X509_Crl;

typedef struct _HITLS_X509_StoreCtx HITLS_X509_StoreCtx;

typedef enum {
    HITLS_X509_CERT_GET_ENCODELEN,
    HITLS_X509_CERT_ENCODE,
    HITLS_X509_CERT_GET_PUBKEY,
    HITLS_X509_CERT_GET_SIGNALG,
    HITLS_X509_CERT_REF_UP,
    HITLS_X509_CERT_EXT_KU_KEYENC,
    HITLS_X509_CERT_EXT_KU_DIGITALSIGN,
    HITLS_X509_CERT_EXT_KU_CERTSIGN,
    HITLS_X509_CERT_EXT_KU_KEYAGREEMENT
} HITLS_X509_CertCmd;

void HITLS_X509_FreeCert(HITLS_X509_Cert *cert);
int32_t HITLS_X509_ParseBuffCert(int32_t format, BSL_Buffer *encode, HITLS_X509_Cert **cert);
int32_t HITLS_X509_ParseFileCert(int32_t format, const char *path, HITLS_X509_Cert **cert);
int32_t HITLS_X509_ParseFileCertMul(int32_t format, const char *path, HITLS_X509_List **certlist);
int32_t HITLS_X509_CtrlCert(HITLS_X509_Cert *cert, int32_t cmd, void *val, int32_t valLen);
int32_t HITLS_X509_DupCert(HITLS_X509_Cert *src, HITLS_X509_Cert **dest);

typedef enum {
    HITLS_X509_CRL_REF_UP,
} HITLS_X509_CrlCmd;

void HITLS_X509_FreeCrl(HITLS_X509_Crl *crl);
int32_t HITLS_X509_CtrlCrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, int32_t valLen);
int32_t HITLS_X509_ParseBuffCrl(int32_t format, BSL_Buffer *encode, HITLS_X509_Crl **crl);
int32_t HITLS_X509_ParseFileCrl(int32_t format, const char *path, HITLS_X509_Crl **crl);
int32_t HITLS_X509_ParseFileCrlMul(int32_t format, const char *path, HITLS_X509_List **crllist);

typedef enum {
    HITLS_X509_VFY_FLAG_CRL_ALL = 1,
    HITLS_X509_VFY_FLAG_CRL_DEV = 2
} HITLS_X509_VFY_FLAGS;

typedef enum {
    HITLS_X509_STORECTX_SET_PARAM_DEPTH,
    HITLS_X509_STORECTX_SET_PARAM_FLAGS,
    HITLS_X509_STORECTX_SET_TIME,
    HITLS_X509_STORECTX_SET_SECBITS,
    /* clear flag */
    HITLS_X509_STORECTX_CLR_PARAM_FLAGS,
    HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
    HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA,
    HITLS_X509_STORECTX_SET_CRL,
    HITLS_X509_STORECTX_REF_UP,
    HITLS_X509_STORECTX_MAX
} HITLS_X509_StoreCtxCmd;

HITLS_X509_StoreCtx *HITLS_X509_NewStoreCtx(void);
void HITLS_X509_FreeStoreCtx(HITLS_X509_StoreCtx *storeCtx);
int32_t HITLS_X509_CtrlStoreCtx(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, int32_t valLen);
int32_t HITLS_X509_VerifyCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);
int32_t HITLS_X509_BuildCertChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_List **chain);

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_H
