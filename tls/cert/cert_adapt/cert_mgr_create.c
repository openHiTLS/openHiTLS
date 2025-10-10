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
#ifdef HITLS_TLS_FEATURE_PROVIDER
    return true;
#else
    HITLS_CERT_MgrMethod *method = SAL_CERT_GetMgrMethod();
    return (method->certStoreNew != NULL);
#endif
}

CERT_MgrCtx *SAL_CERT_MgrCtxNew(void)
{
    return SAL_CERT_MgrCtxProviderNew(NULL, NULL);
}

CERT_MgrCtx *SAL_CERT_MgrCtxProviderNew(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    CERT_MgrCtx *newCtx = BSL_SAL_Calloc(1, sizeof(CERT_MgrCtx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16085, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "new cert manager context error: out of memory.", 0, 0, 0, 0);
        return NULL;
    }
    newCtx->currentCertKeyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    newCtx->certPairs = BSL_HASH_Create(CERT_DEFAULT_HASH_BKT_SIZE, NULL, NULL, NULL, NULL);
    if (newCtx->certPairs == NULL) {
        BSL_SAL_FREE(newCtx);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17338, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "new cert manager context error: new certPairs failed.", 0, 0, 0, 0);
        return NULL;
    }

#ifndef HITLS_TLS_FEATURE_PROVIDER
    HITLS_CERT_MgrMethod *method = SAL_CERT_GetMgrMethod();
    (void)memcpy_s(&newCtx->method, sizeof(HITLS_CERT_MgrMethod), method, sizeof(HITLS_CERT_MgrMethod));
#endif
    newCtx->certStore = SAL_CERT_StoreNew(newCtx);
    if (newCtx->certStore == NULL) {
        BSL_HASH_Destory(newCtx->certPairs);
        BSL_SAL_FREE(newCtx);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15016, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "new cert manager context error: new store failed.", 0, 0, 0, 0);
        return NULL;
    }
    newCtx->libCtx = libCtx;
    newCtx->attrName = attrName;
    return newCtx;
}

int32_t StoreDup(CERT_MgrCtx *destMgrCtx, CERT_MgrCtx *srcMgrCtx)
{
    if (srcMgrCtx->certStore != NULL) {
        destMgrCtx->certStore = SAL_CERT_StoreDup(srcMgrCtx, srcMgrCtx->certStore);
        if (destMgrCtx->certStore == NULL) {
            /* releasing resources at the call point */
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_STORE_DUP, BINLOG_ID16092, "StoreDup fail");
        }
    }

    if (srcMgrCtx->chainStore != NULL) {
        destMgrCtx->chainStore = SAL_CERT_StoreDup(srcMgrCtx, srcMgrCtx->chainStore);
        if (destMgrCtx->chainStore == NULL) {
            /* releasing resources at the call point */
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_STORE_DUP, BINLOG_ID16093, "StoreDup fail");
        }
    }

    if (srcMgrCtx->verifyStore != NULL) {
        destMgrCtx->verifyStore = SAL_CERT_StoreDup(srcMgrCtx, srcMgrCtx->verifyStore);
        if (destMgrCtx->verifyStore == NULL) {
            /* releasing resources at the call point */
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_STORE_DUP, BINLOG_ID16095, "StoreDup fail");
        }
    }

    return HITLS_SUCCESS;
}

CERT_MgrCtx *SAL_CERT_MgrCtxDup(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16282, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "mgrCtx null", 0, 0, 0, 0);
        return NULL;
    }

    CERT_MgrCtx *newCtx = BSL_SAL_Calloc(1, sizeof(CERT_MgrCtx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16097, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup cert manager context error: out of memory.", 0, 0, 0, 0);
        return NULL;
    }
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)memcpy_s(&newCtx->method, sizeof(HITLS_CERT_MgrMethod), &mgrCtx->method, sizeof(HITLS_CERT_MgrMethod));
#endif
    int32_t ret = SAL_CERT_HashDup(newCtx, mgrCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16283, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CERT_HashDup fail, ret %d", ret, 0, 0, 0);
        SAL_CERT_MgrCtxFree(newCtx);
        return NULL;
    }

    if (mgrCtx->extraChain != NULL && (newCtx->extraChain = SAL_CERT_ChainDup(mgrCtx, mgrCtx->extraChain)) == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16284, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "ChainDup fail", 0, 0, 0, 0);
        SAL_CERT_MgrCtxFree(newCtx);
        return NULL;
    }

    if ((ret = StoreDup(newCtx, mgrCtx)) != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16285, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "StoreDup fail, ret %d", ret, 0, 0, 0);
        SAL_CERT_MgrCtxFree(newCtx);
        return NULL;
    }

    newCtx->currentCertKeyType = mgrCtx->currentCertKeyType;
    newCtx->defaultPasswdCb = mgrCtx->defaultPasswdCb;
    newCtx->defaultPasswdCbUserData = mgrCtx->defaultPasswdCbUserData;
#ifdef HITLS_TLS_CONFIG_CERT_CALLBACK
    newCtx->verifyCb = mgrCtx->verifyCb;
#endif

    newCtx->libCtx = LIBCTX_FROM_CERT_MGR_CTX(mgrCtx);
    newCtx->attrName = ATTRIBUTE_FROM_CERT_MGR_CTX(mgrCtx);
#ifdef HITLS_TLS_FEATURE_CERT_CB
    newCtx->certCb = mgrCtx->certCb;
    newCtx->certCbArg = mgrCtx->certCbArg;
#endif /* HITLS_TLS_FEATURE_CERT_CB */
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
    BSL_HASH_Destory(mgrCtx->certPairs);
    mgrCtx->certPairs = NULL;
    BSL_SAL_FREE(mgrCtx);
    return;
}