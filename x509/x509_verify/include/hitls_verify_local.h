/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_VERIFY_LOCAL_H
#define HITLS_VERIFY_LOCAL_H

#include <stdint.h>
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HITLS_X509_VFY_FLAG_TIME = 0x100000000,
    HITLS_X509_VFY_FLAG_SECBITS = 0x200000000
} HITLS_X509_VFY_IN_FLAGS;

typedef struct _HITLS_X509_VerifyParam {
    int32_t maxDepth;
    int64_t time;
    uint32_t securityBits;
    uint64_t flags;
} HITLS_X509_VerifyParam;

typedef struct _HITLS_X509_StoreCtx {
    HITLS_X509_List *store;
    HITLS_X509_List *crl;
    BSL_SAL_RefCount references;
    HITLS_X509_VerifyParam verifyParam;
} HITLS_X509_StoreCtx;

/*
 * Check verify param;
 * Verify whether the certificate has a critical extension that has not been parsed, and if an error is returned;
 */
int32_t HITLS_X509_VerifyParamAndExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);

/*
 * The crl is verified. By default, the certificate chain is verified.
 * You can configure not to  verify the crl or only to verify the device certificate crl
 */
int32_t HITLS_X509_VerifyCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);

#ifdef __cplusplus
}
#endif

#endif // HITLS_VERIFY_LOCAL_H