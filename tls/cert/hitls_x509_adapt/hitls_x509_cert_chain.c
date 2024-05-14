/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "bsl_err_internal.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_x509.h"
#include "bsl_list.h"
#include "hitls_error.h"

static int32_t BuildArrayFromList(HITLS_X509_List *list, HITLS_CERT_X509 **listArray, uint32_t *num)
{
    HITLS_X509_Cert *elemt = NULL;
    int32_t i = 0;
    int32_t ret;
    for (list->curr = list->first; list->curr != NULL; list->curr = list->curr->next, i++) {
        elemt = (HITLS_X509_Cert *)list->curr->data;
        if (elemt == NULL || i >= list->count) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ADAPT_BUILD_CERT_CHAIN_ERR);
            return HITLS_X509_ADAPT_BUILD_CERT_CHAIN_ERR;
        }

        int ref = 0;
        ret = HITLS_X509_CtrlCert(elemt, HITLS_X509_CERT_REF_UP, (void *)&ref, (int32_t)sizeof(int));
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
        ret = HITLS_X509_CtrlCert(listArray[i], HITLS_X509_CERT_REF_UP, (void *)&ref, (int32_t)sizeof(int));
        if (ret != HITLS_SUCCESS) {
            BSL_LIST_FREE(*list, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
            return ret;
        }
        ret = BSL_LIST_AddElement(*list, listArray[i], BSL_LIST_POS_END);
        if (ret != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_LIST_FREE(*list, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
            return ret;
        }
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_X509_Adapt_BuildCertChain(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **list, uint32_t *num)
{
    (void)config;
    *num = 0;
    HITLS_X509_List *certChain = NULL;
    int32_t ret = HITLS_X509_BuildCertChain((HITLS_X509_StoreCtx *)store, cert, &certChain);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = BuildArrayFromList(certChain, list, num);
    BSL_LIST_FREE(certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
    return ret;
}

int32_t HITLS_X509_Adapt_VerifyCertChain(HITLS_Ctx *ctx, HITLS_CERT_Store *store, HITLS_CERT_X509 **list, uint32_t num)
{
    (void)ctx;
    HITLS_X509_List *certList = NULL;
    int32_t ret = BuildCertListFromCertArray(list, num, &certList);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_VerifyCert((HITLS_X509_StoreCtx *)store, certList);
    if (ret != HITLS_SUCCESS) {
        BSL_LIST_FREE(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
        return ret;
    }

    BSL_LIST_FREE(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
    return HITLS_SUCCESS;
}
