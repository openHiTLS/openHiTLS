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
#include "hitls_build.h"
#if defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER)
#include <stdint.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_pki_x509.h"
#include "bsl_list.h"
#include "hitls_cert.h"
#include "hitls_error.h"

static int32_t BuildArrayFromList(HITLS_X509_List *list, HITLS_CERT_X509 **listArray, uint32_t *num)
{
    HITLS_X509_Cert *elemt = NULL;
    uint32_t i = 0;
    int32_t ret;

    for (elemt = BSL_LIST_GET_FIRST(list); elemt != NULL; elemt = BSL_LIST_GET_NEXT(list), i++) {
        int ref = 0;
        if (i >= *num) {
            break;
        }
        ret = HITLS_X509_CertCtrl(elemt, HITLS_X509_REF_UP, (void *)&ref, (int32_t)sizeof(int));
        if (ret != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        listArray[i] = elemt;
    }

    *num = i;
    return HITLS_SUCCESS;
}

static int32_t BuildCertListFromCertArray(HITLS_CERT_X509 **listCert, uint32_t num, HITLS_X509_List **list)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_X509_Cert **listArray = (HITLS_X509_Cert **)listCert;
    *list = BSL_LIST_New(num);
    if (*list == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    for (uint32_t i = 0; i < num; i++) {
        int ref = 0;
        ret = HITLS_X509_CertCtrl(listArray[i], HITLS_X509_REF_UP, (void *)&ref, (int32_t)sizeof(int));
        if (ret != HITLS_SUCCESS) {
            BSL_LIST_FREE(*list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
            return ret;
        }
        ret = BSL_LIST_AddElement(*list, listArray[i], BSL_LIST_POS_END);
        if (ret != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_LIST_FREE(*list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
            return ret;
        }
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_X509_Adapt_BuildCertChain(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **list, uint32_t *num)
{
    (void)config;
    HITLS_X509_List *certChain = NULL;
    int32_t ret = HITLS_X509_CertChainBuild((HITLS_X509_StoreCtx *)store, false, cert, &certChain);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = BuildArrayFromList(certChain, list, num);
    BSL_LIST_FREE(certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

int32_t HITLS_X509_Adapt_VerifyCertChain(HITLS_Ctx *ctx, HITLS_CERT_Store *store, HITLS_CERT_X509 **list, uint32_t num)
{
    HITLS_X509_StoreCtx *storeCtx = (HITLS_X509_StoreCtx *)store;
    int64_t sysTime = BSL_SAL_CurrentSysTimeGet();
    if (sysTime == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_INVALID_TIME);
        return HITLS_CERT_SELF_ADAPT_INVALID_TIME;
    }
    int32_t ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_TIME, &sysTime,
        sizeof(sysTime));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
#ifdef HITLS_CRYPTO_SM2
    /* The default user id as specified in GM/T 0009-2012 */
    char sm2UserId[] = "1234567812345678";
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_VFY_SM2_USERID, sm2UserId, strlen(sm2UserId));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
#endif
#ifdef HITLS_TLS_CONFIG_CERT_CALLBACK
    HITLS_VerifyCb verCb = NULL;
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_USR_DATA, ctx, sizeof(void *));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((verCb = HITLS_GetVerifyCb(ctx)) != NULL) {
        ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_VERIFY_CB, verCb,
            sizeof(X509_STORECTX_VerifyCb));
        if (ret != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif /* HITLS_TLS_CONFIG_CERT_CALLBACK */
    HITLS_X509_List *certList = NULL;
    if ((ret = BuildCertListFromCertArray(list, num, &certList)) != HITLS_SUCCESS) {
        return ret;
    }
    HITLS_SetVerifyResult(ctx, HITLS_X509_V_OK);
    ret = HITLS_X509_CertVerify(storeCtx, certList);
    BSL_LIST_FREE(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    if (ret != HITLS_SUCCESS) {
        int32_t x509Err = HITLS_SUCCESS;
        (void)HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_GET_ERROR, &x509Err, sizeof(x509Err));
        HITLS_SetVerifyResult(ctx, x509Err != HITLS_SUCCESS ? x509Err : ret);
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif /* defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER) */
