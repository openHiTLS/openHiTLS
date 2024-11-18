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
#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "cert_mgr_ctx.h"

HITLS_CERT_X509 *SAL_CERT_PairGetX509(CERT_Pair *certPair)
{
    if (certPair == NULL) {
        return NULL;
    }
    return certPair->cert;
}

#ifdef HITLS_TLS_PROTO_TLCP11
HITLS_CERT_X509 *SAL_CERT_GetTlcpEncCert(CERT_Pair *certPair)
{
    if (certPair == NULL) {
        return NULL;
    }
    return certPair->encCert;
}
#endif
#if defined(HITLS_TLS_CONNECTION_INFO_NEGOTIATION)
HITLS_CERT_Chain *SAL_CERT_PairGetChain(CERT_Pair *certPair)
{
    if (certPair == NULL) {
        return NULL;
    }
    return certPair->chain;
}
#endif /* HITLS_TLS_CONNECTION_INFO_NEGOTIATION */
CERT_Pair *SAL_CERT_PairDup(CERT_MgrCtx *mgrCtx, CERT_Pair *srcCertPair)
{
    CERT_Pair *destCertPair = BSL_SAL_Calloc(1, sizeof(CERT_MgrCtx));
    if (destCertPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16299, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }

    if (srcCertPair->cert != NULL) {
        destCertPair->cert = SAL_CERT_X509Dup(mgrCtx, srcCertPair->cert);
        if (destCertPair->cert == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16300, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "X509Dup fail", 0, 0, 0, 0);
            BSL_SAL_FREE(destCertPair);
            return NULL;
        }
    }

    if (srcCertPair->privateKey != NULL) {
        destCertPair->privateKey = SAL_CERT_KeyDup(mgrCtx, srcCertPair->privateKey);
        if (destCertPair->privateKey == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16301, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "KeyDup fail", 0, 0, 0, 0);
            SAL_CERT_X509Free(destCertPair->cert);
            BSL_SAL_FREE(destCertPair);
            return NULL;
        }
    }

    if (srcCertPair->chain != NULL) {
        destCertPair->chain = SAL_CERT_ChainDup(mgrCtx, srcCertPair->chain);
        if (destCertPair->chain == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16302, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ChainDup fail", 0, 0, 0, 0);
            SAL_CERT_X509Free(destCertPair->cert);
            SAL_CERT_KeyFree(mgrCtx, destCertPair->privateKey);
            BSL_SAL_FREE(destCertPair);
            return NULL;
        }
    }

    return destCertPair;
}

void SAL_CERT_PairClear(CERT_MgrCtx *mgrCtx, CERT_Pair *certPair)
{
    if (mgrCtx == NULL || certPair == NULL) {
        return;
    }

    if (certPair->cert != NULL) {
        SAL_CERT_X509Free(certPair->cert);
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    if (certPair->encCert != NULL) {
        SAL_CERT_X509Free(certPair->encCert);
    }
#endif
    if (certPair->privateKey != NULL) {
        SAL_CERT_KeyFree(mgrCtx, certPair->privateKey);
    }

    if (certPair->chain != NULL) {
        SAL_CERT_ChainFree(certPair->chain);
    }

    (void)memset_s(certPair, sizeof(CERT_Pair), 0, sizeof(CERT_Pair));
    return;
}

void SAL_CERT_PairFree(CERT_MgrCtx *mgrCtx, CERT_Pair *certPair)
{
    SAL_CERT_PairClear(mgrCtx, certPair);
    BSL_SAL_FREE(certPair);
    return;
}