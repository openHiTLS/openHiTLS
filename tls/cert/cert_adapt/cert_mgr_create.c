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

#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "tls_config.h"
#include "cert_method.h"
#include "cert_mgr_ctx.h"

bool SAL_CERT_MgrIsEnable(void)
{
    HITLS_CERT_MgrMethod *method = SAL_CERT_GetMgrMethod();
    return (method->certStoreNew != NULL);
}

CERT_MgrCtx *SAL_CERT_MgrCtxNew(void)
{
    HITLS_CERT_MgrMethod *method = SAL_CERT_GetMgrMethod();
    CERT_MgrCtx *newCtx = BSL_SAL_Calloc(1, sizeof(CERT_MgrCtx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15017, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "new cert manager context error: out of memory.", 0, 0, 0, 0);
        return NULL;
    }
    newCtx->currentCertIndex = TLS_CERT_KEY_TYPE_UNKNOWN;
    newCtx->verifyParam.verifyDepth = TLS_DEFAULT_VERIFY_DEPTH;
    (void)memcpy_s(&newCtx->method, sizeof(HITLS_CERT_MgrMethod), method, sizeof(HITLS_CERT_MgrMethod));

    newCtx->certStore = SAL_CERT_StoreNew(newCtx);
    if (newCtx->certStore == NULL) {
        BSL_SAL_FREE(newCtx);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15016, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "new cert manager context error: new store failed.", 0, 0, 0, 0);
        return NULL;
    }
    return newCtx;
}

static int32_t CertResourceDup(CERT_MgrCtx *destMgrCtx, CERT_MgrCtx *srcMgrCtx)
{
    CERT_Pair *destCertPair = NULL;
    CERT_Pair *srcCertPair = NULL;
    for (uint32_t i = 0; i < TLS_CERT_KEY_TYPE_NUM; i++) {
        destCertPair = &(destMgrCtx->certPair[i]);
        srcCertPair = &(srcMgrCtx->certPair[i]);
        if (srcCertPair->cert != NULL) {
            destCertPair->cert = SAL_CERT_X509Dup(srcMgrCtx, srcCertPair->cert);
            if (destCertPair->cert == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15018, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "dup cert manager context error: x509 dup error.", 0, 0, 0, 0);
                /* releasing resources at the call point */
                return HITLS_CERT_ERR_X509_DUP;
            }
        }
        if (srcCertPair->privateKey != NULL) {
            destCertPair->privateKey = SAL_CERT_KeyDup(srcMgrCtx, srcCertPair->privateKey);
            if (destCertPair->privateKey == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15020, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "dup cert manager context error: key dup error.", 0, 0, 0, 0);
                /* releasing resources at the call point */
                return HITLS_CERT_ERR_KEY_DUP;
            }
        }
        if (srcCertPair->chain != NULL) {
            destCertPair->chain = SAL_CERT_ChainDup(srcMgrCtx, srcCertPair->chain);
            if (destCertPair->chain == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_CHAIN_DUP);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15019, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "dup cert manager context error: cert chain dup error.", 0, 0, 0, 0);
                /* releasing resources at the call point */
                return HITLS_CERT_ERR_CHAIN_DUP;
            }
        }
    }
    return HITLS_SUCCESS;
}

int32_t StoreDup(CERT_MgrCtx *destMgrCtx, CERT_MgrCtx *srcMgrCtx)
{
    if (srcMgrCtx->certStore != NULL) {
        destMgrCtx->certStore = SAL_CERT_StoreDup(srcMgrCtx, srcMgrCtx->certStore);
        if (destMgrCtx->certStore == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15021, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "dup cert manager context error in copy cert store.", 0, 0, 0, 0);
            /* releasing resources at the call point */
            return HITLS_CERT_ERR_STORE_DUP;
        }
    }

    if (srcMgrCtx->chainStore != NULL) {
        destMgrCtx->chainStore = SAL_CERT_StoreDup(srcMgrCtx, srcMgrCtx->chainStore);
        if (destMgrCtx->chainStore == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15022, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "dup cert manager context error in copy chain store.", 0, 0, 0, 0);
            /* releasing resources at the call point */
            return HITLS_CERT_ERR_STORE_DUP;
        }
    }

    if (srcMgrCtx->verifyStore != NULL) {
        destMgrCtx->verifyStore = SAL_CERT_StoreDup(srcMgrCtx, srcMgrCtx->verifyStore);
        if (destMgrCtx->verifyStore == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15023, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "dup cert manager context error in copy verify store.", 0, 0, 0, 0);
            /* releasing resources at the call point */
            return HITLS_CERT_ERR_STORE_DUP;
        }
    }

    return HITLS_SUCCESS;
}

CERT_MgrCtx *SAL_CERT_MgrCtxDup(CERT_MgrCtx *mgrCtx)
{
    int32_t ret;
    if (mgrCtx == NULL) {
        return NULL;
    }

    CERT_MgrCtx *newCtx = BSL_SAL_Calloc(1, sizeof(CERT_MgrCtx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15024, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup cert manager context error: out of memory.", 0, 0, 0, 0);
        return NULL;
    }

    (void)memcpy_s(&newCtx->method, sizeof(HITLS_CERT_MgrMethod), &mgrCtx->method, sizeof(HITLS_CERT_MgrMethod));

    ret = CertResourceDup(newCtx, mgrCtx);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_MgrCtxFree(newCtx);
        return NULL;
    }

    if (mgrCtx->extraChain != NULL) {
        newCtx->extraChain = SAL_CERT_ChainDup(mgrCtx, mgrCtx->extraChain);
        if (newCtx->extraChain == NULL) {
            SAL_CERT_MgrCtxFree(newCtx);
            return NULL;
        }
    }

    ret = StoreDup(newCtx, mgrCtx);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_MgrCtxFree(newCtx);
        return NULL;
    }

    newCtx->currentCertIndex = mgrCtx->currentCertIndex;
    (void)memcpy_s(&newCtx->verifyParam, sizeof(HITLS_CertVerifyParam),
        &mgrCtx->verifyParam, sizeof(HITLS_CertVerifyParam));
    newCtx->defaultPasswdCb = mgrCtx->defaultPasswdCb;
    newCtx->defaultPasswdCbUserData = mgrCtx->defaultPasswdCbUserData;
    newCtx->verifyCb = mgrCtx->verifyCb;

    return newCtx;
}

void SAL_CERT_MgrCtxFree(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return;
    }
    SAL_CERT_ClearCertAndKey(mgrCtx);
    SAL_CERT_ChainFree(mgrCtx->extraChain);
    mgrCtx->extraChain = NULL;
    SAL_CERT_StoreFree(mgrCtx, mgrCtx->verifyStore);
    mgrCtx->verifyStore = NULL;
    SAL_CERT_StoreFree(mgrCtx, mgrCtx->chainStore);
    mgrCtx->chainStore = NULL;
    SAL_CERT_StoreFree(mgrCtx, mgrCtx->certStore);
    mgrCtx->certStore = NULL;
    BSL_SAL_FREE(mgrCtx);
    return;
}