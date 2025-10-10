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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "hitls_error.h"
#include "cert_method.h"
#include "cert_mgr_ctx.h"


HITLS_CERT_Chain *SAL_CERT_ChainNew(void)
{
    BslList *newChain = BSL_LIST_New(sizeof(HITLS_CERT_X509 *));
    if (newChain == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15010, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "new cert chain error: out of memory.", 0, 0, 0, 0);
    }
    return newChain;
}

int32_t SAL_CERT_ChainAppend(HITLS_CERT_Chain *chain, HITLS_CERT_X509 *cert)
{
    /* add the tail to the end of the certificate chain, corresponding to the top of the stack */
    int32_t ret = BSL_LIST_AddElement(chain, cert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15011, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "append cert to chain error: out of memory.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}

static void CertChainInnerDestroyCb(void *cert)
{
    SAL_CERT_X509Free((HITLS_CERT_X509 *)cert);
}

/* release the linked list without retaining the head node */
void SAL_CERT_ChainFree(HITLS_CERT_Chain *chain)
{
    /* only certificates on the chain are destroyed, chain itself will be not destroyed */
    BSL_LIST_DeleteAll(chain, CertChainInnerDestroyCb);
    BSL_SAL_FREE(chain);
    return;
}

/* copy the certificate chain */
HITLS_CERT_Chain *SAL_CERT_ChainDup(CERT_MgrCtx *mgrCtx, HITLS_CERT_Chain *chain)
{
    int32_t ret;
    HITLS_CERT_X509 *dupCert = NULL;
    HITLS_CERT_X509 *currCert = NULL;

    if (BSL_LIST_COUNT(chain) < 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16070, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup cert chain error: list size tainted.", 0, 0, 0, 0);
        return NULL;
    }

    BslList *newChain = SAL_CERT_ChainNew();
    if (newChain == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15012, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup cert chain error: out of memory.", 0, 0, 0, 0);
        return NULL;
    }

    for (currCert = BSL_LIST_GET_FIRST(chain); currCert != NULL; currCert = BSL_LIST_GET_NEXT(chain)) {
        dupCert = SAL_CERT_X509Dup(mgrCtx, currCert);
        if (dupCert == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15013, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "dup cert chain error: x509 dup error.", 0, 0, 0, 0);
            goto EXIT;
        }
        ret = SAL_CERT_ChainAppend(newChain, dupCert);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15014, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "dup cert chain error: append new cert node error.", 0, 0, 0, 0);
            SAL_CERT_X509Free(dupCert);
            goto EXIT;
        }
    }

    return newChain;
EXIT:
    /* free the certificate chain */
    SAL_CERT_ChainFree(newChain);
    return NULL;
}