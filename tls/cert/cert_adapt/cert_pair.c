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
#include "hitls_cert_type.h"
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

#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t TlcpCertPairDup(CERT_MgrCtx *mgrCtx, CERT_Pair *srcCertPair, CERT_Pair *destCertPair)
{
    if (srcCertPair->encCert != NULL) {
        destCertPair->encCert = SAL_CERT_X509Dup(mgrCtx, srcCertPair->encCert);
        if (destCertPair->encCert == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17341, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "enc X509Dup fail", 0, 0, 0, 0);
            return HITLS_CERT_ERR_X509_DUP;
        }
    }

    if (srcCertPair->encPrivateKey != NULL) {
        destCertPair->encPrivateKey = SAL_CERT_KeyDup(mgrCtx, srcCertPair->encPrivateKey);
        if (destCertPair->encPrivateKey == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17342, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "enc KeyDup fail", 0, 0, 0, 0);
            return HITLS_CERT_ERR_X509_DUP;
        }
    }
    return  HITLS_SUCCESS;
}
#endif

CERT_Pair *SAL_CERT_PairDup(CERT_MgrCtx *mgrCtx, CERT_Pair *srcCertPair)
{
    CERT_Pair *destCertPair = BSL_SAL_Calloc(1, sizeof(CERT_Pair));
    if (destCertPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16299, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }

    do {
#ifdef HITLS_TLS_PROTO_TLCP11
        if (TlcpCertPairDup(mgrCtx, srcCertPair, destCertPair) != HITLS_SUCCESS) {
            break;
        }
#endif

        if (srcCertPair->cert != NULL) {
            destCertPair->cert = SAL_CERT_X509Dup(mgrCtx, srcCertPair->cert);
            if (destCertPair->cert == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16300, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "X509Dup fail", 0, 0, 0, 0);
                break;
            }
        }

        if (srcCertPair->privateKey != NULL) {
            destCertPair->privateKey = SAL_CERT_KeyDup(mgrCtx, srcCertPair->privateKey);
            if (destCertPair->privateKey == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16301, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "KeyDup fail", 0, 0, 0, 0);
                break;
            }
        }

        if (srcCertPair->chain != NULL) {
            destCertPair->chain = SAL_CERT_ChainDup(mgrCtx, srcCertPair->chain);
            if (destCertPair->chain == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16302, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "ChainDup fail", 0, 0, 0, 0);
                break;
            }
        }
        return destCertPair;
    } while (false);
    SAL_CERT_PairFree(mgrCtx, destCertPair);
    return NULL;
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
    if (certPair->encPrivateKey != NULL) {
        SAL_CERT_KeyFree(mgrCtx, certPair->encPrivateKey);
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

int32_t SAL_CERT_HashDup(CERT_MgrCtx *destMgrCtx, CERT_MgrCtx *srcMgrCtx)
{
    destMgrCtx->certPairs = BSL_HASH_Create(CERT_DEFAULT_HASH_BKT_SIZE, NULL, NULL, NULL, NULL);
    if (destMgrCtx->certPairs == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17347, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "BSL_HASH_Create fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_HASH_Hash *certPairs = srcMgrCtx->certPairs;
    BSL_HASH_Iterator iter = BSL_HASH_IterBegin(certPairs);
    while (iter != BSL_HASH_IterEnd(certPairs)) {
        uint32_t keyType = (uint32_t)BSL_HASH_HashIterKey(certPairs, iter);
        CERT_Pair *certPair = (CERT_Pair *)BSL_HASH_IterValue(certPairs, iter);
        if (certPair != NULL) {
            CERT_Pair *newCertPair = SAL_CERT_PairDup(srcMgrCtx, certPair);
            if (newCertPair == NULL) {
                return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_X509_DUP, BINLOG_ID17348, "x509dup fail");
            }
            int32_t ret = BSL_HASH_Insert(destMgrCtx->certPairs, keyType, 0, (uintptr_t)newCertPair, sizeof(CERT_Pair));
            if (ret != HITLS_SUCCESS) {
                SAL_CERT_PairFree(destMgrCtx, newCertPair);
                return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17349, "insert fail");
            }
        }
        iter = BSL_HASH_IterNext(certPairs, iter);
    }
    return HITLS_SUCCESS;
}