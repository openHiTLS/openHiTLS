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

#ifndef HITLS_X509_STORE_LOCAL_H
#define HITLS_X509_STORE_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_X509_VFY

#include <stdbool.h>
#include <stdint.h>
#include "bsl_list.h"
#include "hitls_x509_verify.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _HITLS_X509_Store {
    HITLS_X509_List *certs;           // Shared trusted certificate store
    HITLS_X509_List *crls;            // Shared CRL store
    BSL_SAL_RefCount references;      // Refcount shared by duplicated StoreCtx instances
    BSL_SAL_ThreadLockHandle rwLock;  // Read-write lock protecting shared Store contents
#ifdef HITLS_PKI_X509_VFY_LOCATION
    BslList *caPaths;                 // Shared CA directory paths for lazy issuer loading
#endif
};

HITLS_X509_Store *HITLS_X509_StoreNew(void);
void HITLS_X509_StoreFree(HITLS_X509_Store *store);
int32_t HITLS_X509_StoreUpRef(HITLS_X509_Store *store);
int32_t HITLS_X509_StoreFindIssuerInTrust(HITLS_X509_Store *store, HITLS_X509_StoreCtx *storeCtx,
    HITLS_X509_Cert *cert, HITLS_X509_Cert **issue);
int32_t HITLS_X509_StoreGetCrlList(HITLS_X509_Store *store, HITLS_X509_List **crlList);

bool HITLS_X509_StoreHasCtrl(int32_t cmd);
int32_t HITLS_X509_StoreCtrl(HITLS_X509_Store *store, int32_t cmd, void *val, uint32_t valLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_X509_VFY
#endif // HITLS_X509_STORE_LOCAL_H
