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

#ifndef HITLS_X509_VERIFY_H
#define HITLS_X509_VERIFY_H

#include "hitls_build.h"
#ifdef HITLS_PKI_X509_VFY
#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_list.h"
#include "hitls_pki_x509.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HITLS_X509_VFY_FLAG_SECBITS = 0x100000000,
    HITLS_X509_VFY_FLAG_TIME = 0x200000000,
} HITLS_X509_IN_VerifyFlag;

typedef struct _HITLS_X509_VerifyParam {
    int32_t maxDepth;
    int64_t time;
    uint32_t securityBits;
    uint64_t flags;
#ifdef HITLS_CRYPTO_SM2
    BSL_Buffer sm2UserId;
#endif
} HITLS_X509_VerifyParam;

struct _HITLS_X509_StoreCtx {
    HITLS_X509_List *store;
    HITLS_X509_List *crl;
    BSL_SAL_RefCount references;
    HITLS_X509_VerifyParam verifyParam;
    BslList *caPaths;                 // List of CA directory paths for on-demand loading (char*)
    CRYPT_EAL_LibCtx *libCtx;         // Provider context
    const char *attrName;             // Provider attribute name
};


int32_t HITLS_X509_VerifyParamAndExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);

/*
 * Verify the CRL, which is the default full certificate chain validation.
 * You can configure not to verify or only verify the terminal certificate
 */
int32_t HITLS_X509_VerifyCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_X509_VFY

#endif // HITLS_X509_VERIFY_H