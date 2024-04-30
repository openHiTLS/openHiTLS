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

HITLS_X509_Cert *HITLS_X509_NewCert(void);
void HITLS_X509_FreeCert(HITLS_X509_Cert *cert);
int32_t HITLS_X509_ParseBuffCert(bool isCopy, int32_t format, BSL_Buffer *encode, HITLS_X509_Cert *cert);
int32_t HITLS_X509_ParseFileCert(int32_t format, const char *path, HITLS_X509_Cert *cert);
int32_t HITLS_X509_CtrlCert(HITLS_X509_Cert *cert, int32_t cmd, void *val, int32_t *valLen);
int32_t HITLS_X509_DupCert(HITLS_X509_Cert *src, HITLS_X509_Cert **dest);

HITLS_X509_Crl *HITLS_X509_NewCrl(void);
void HITLS_X509_FreeCrl(HITLS_X509_Crl *crl);
int32_t HITLS_X509_ParseBuffCrl(bool isCopy, int32_t format, BSL_Buffer *encode, HITLS_X509_Crl *crl);
int32_t HITLS_X509_ParseFileCrl(int32_t format, const char *path, HITLS_X509_Crl *crl);


typedef enum {
    HITLS_X509_STORECTX_SET_PARAM_DEPTH,
    HITLS_X509_STORECTX_SET_PARAM_FLAGS,
    HITLS_X509_STORECTX_SET_TIME,
    HITLS_X509_STORECTX_SET_SECBITS,
    HITLS_X509_STORECTX_DEL_PARAM_FLAGS,
    HITLS_X509_STORECTX_SET_CA,
    HITLS_X509_STORECTX_SET_CRL,
    HITLS_X509_STORECTX_REF_UP
} HITLS_X509_StoreCtxCmd;

HITLS_X509_StoreCtx *HITLS_X509_NewStoreCtx(void);
void HITLS_X509_FreeStoreCtx(HITLS_X509_StoreCtx *storeCtx);
int32_t HITLS_X509_CtrlStoreCtx(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, int32_t *valLen);
int32_t HITLS_X509_VerifyCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);
int32_t HITLS_X509_BuildCertChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_List **chain);

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_H
