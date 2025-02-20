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
#include "cert_method.h"
#include "cert.h"
#include "cert_mgr_ctx.h"

int32_t SAL_CERT_SetCertStore(CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store)
{
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    SAL_CERT_StoreFree(mgrCtx, mgrCtx->certStore);
    mgrCtx->certStore = store;
    return HITLS_SUCCESS;
}

HITLS_CERT_Store *SAL_CERT_GetCertStore(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return NULL;
    }

    return mgrCtx->certStore;
}

int32_t SAL_CERT_SetChainStore(CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store)
{
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    SAL_CERT_StoreFree(mgrCtx, mgrCtx->chainStore);
    mgrCtx->chainStore = store;
    return HITLS_SUCCESS;
}

HITLS_CERT_Store *SAL_CERT_GetChainStore(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return NULL;
    }

    return mgrCtx->chainStore;
}

int32_t SAL_CERT_SetVerifyStore(CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store)
{
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    SAL_CERT_StoreFree(mgrCtx, mgrCtx->verifyStore);
    mgrCtx->verifyStore = store;
    return HITLS_SUCCESS;
}

HITLS_CERT_Store *SAL_CERT_GetVerifyStore(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return NULL;
    }

    return mgrCtx->verifyStore;
}

int32_t SAL_CERT_SetCurrentCert(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isTlcpEncCert)
{
    (void)isTlcpEncCert;
    if (cert == NULL || config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16286, "unregistered callback");
    }

    int32_t ret;
    HITLS_CERT_Key *pubkey = NULL;
    ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16099, "GET PUB KEY fail");
    }

    uint32_t keyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_TYPE, NULL, (void *)&keyType);
    SAL_CERT_KeyFree(mgrCtx, pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16100, "GET KEY TYPE fail");
    }

    bool isCalloc = false;
    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, keyType);
    if (certPair == NULL) {
        certPair = BSL_SAL_Calloc(1u, sizeof(CERT_Pair));
        if (certPair == NULL) {
            return HITLS_MEMALLOC_FAIL;   // TODO 日志
        }
        isCalloc = true;
    }

    HITLS_CERT_Key **privateKey = NULL;
    HITLS_CERT_X509 **certPairCert = NULL;
    if (isTlcpEncCert) {
#ifdef HITLS_TLS_PROTO_TLCP11
        privateKey = &certPair->encPrivateKey;
        certPairCert = &certPair->encCert;
#endif
    } else {
        privateKey = &certPair->privateKey;
        certPairCert = &certPair->cert;
    }
    if (*privateKey != NULL) {
        ret = SAL_CERT_CheckPrivateKey(config, cert, *privateKey);
        if (ret != HITLS_SUCCESS) {
            /* If the certificate does not match the private key, release the private key. */
            SAL_CERT_KeyFree(mgrCtx, *privateKey);   // TODO 日志
            *privateKey = NULL;
        }
    }

    SAL_CERT_X509Free(*certPairCert);
    *certPairCert = cert;
    if (isCalloc) {
        SAL_CERT_HashInsert(mgrCtx, keyType, certPair);     // TODO 日志
    }
    mgrCtx->currentCertIndex = keyType;
    return HITLS_SUCCESS;
}

HITLS_CERT_X509 *SAL_CERT_GetCurrentCert(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16287, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "mgrCtx null", 0, 0, 0, 0);
        return NULL;
    }
    uint32_t keyType = mgrCtx->currentCertIndex;
    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, keyType);
    if (certPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16288, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "idx err", 0, 0, 0, 0);
        return NULL;
    }
    return certPair->cert;
}

HITLS_CERT_X509 *SAL_CERT_GetCert(CERT_MgrCtx *mgrCtx, HITLS_CERT_KeyType keyType)
{
    if (mgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16289, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "mgrCtx null", 0, 0, 0, 0);
        return NULL;
    }

    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, keyType);
    if (certPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16290, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "idx err", 0, 0, 0, 0);
        return NULL;
    }
    return certPair->cert;
}

int32_t SAL_CERT_SetCurrentPrivateKey(HITLS_Config *config, HITLS_CERT_Key *key, bool isTlcpEncCertPriKey)
{
    (void)isTlcpEncCertPriKey;
    if (key == NULL || config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    uint32_t keyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    int32_t ret = SAL_CERT_KeyCtrl(config, key, CERT_KEY_CTRL_GET_TYPE, NULL, (void *)&keyType);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16104, "get key type fail");
    }

    bool isCalloc = false;
    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx,keyType);
    if (certPair == NULL) {
        certPair = BSL_SAL_Calloc(1u, sizeof(CERT_Pair));
        if (certPair == NULL) {
            return HITLS_MEMALLOC_FAIL;   // TODO 日志
        }
        isCalloc = true;
    }

    HITLS_CERT_Key **certPairPrivateKey = NULL;
    HITLS_CERT_X509 **cert = NULL;
    if (isTlcpEncCertPriKey) {
#ifdef HITLS_TLS_PROTO_TLCP11
        certPairPrivateKey = &certPair->encPrivateKey;
        cert = &certPair->encCert;
#endif
    } else {
        certPairPrivateKey = &certPair->privateKey;
        cert = &certPair->cert;
    }
    if (*cert != NULL) {
        ret = SAL_CERT_CheckPrivateKey(config, *cert, key);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16107, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "set private key error: cert and key mismatch, key type = %u.", keyType, 0, 0, 0);
            /* If the certificate does not match the private key, release the certificate. */
            SAL_CERT_X509Free(*cert);
            *cert = NULL;
            return ret;     // TODO 日志
        }
    }

    SAL_CERT_KeyFree(mgrCtx, *certPairPrivateKey);
    *certPairPrivateKey = key;
    if (isCalloc) {
        SAL_CERT_HashInsert(mgrCtx, keyType, certPair);     // TODO 日志
    }
    mgrCtx->currentCertIndex = keyType;
    return HITLS_SUCCESS;
}

HITLS_CERT_Key *SAL_CERT_GetCurrentPrivateKey(CERT_MgrCtx *mgrCtx, bool isTlcpEncCert)
{
    (void)isTlcpEncCert;
    if (mgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16291, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "mgrCtx null", 0, 0, 0, 0);
        return NULL;
    }

    uint32_t keyType = mgrCtx->currentCertIndex;
    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, keyType);
    if (certPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16288, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "idx err", 0, 0, 0, 0);
        return NULL;     // TODO 日志
    }
    if (isTlcpEncCert) {
#ifdef HITLS_TLS_PROTO_TLCP11
        return certPair->encPrivateKey;
#endif
    }
    return certPair->privateKey;
}

HITLS_CERT_Key *SAL_CERT_GetPrivateKey(CERT_MgrCtx *mgrCtx, HITLS_CERT_KeyType keyType)
{
    if (mgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16293, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "mgrCtx null", 0, 0, 0, 0);
        return NULL;
    }
    // 这里有问题，如果想要国米的加密证书对应的私钥呢
    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, keyType);
    if (certPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16288, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "idx err", 0, 0, 0, 0);
        return NULL;     // TODO 日志
    }
    return certPair->privateKey;
}

int32_t SAL_CERT_AddChainCert(CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert)
{
    if (mgrCtx == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    uint32_t keyType = mgrCtx->currentCertIndex;
    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, keyType);
    if (certPair == NULL) {
        /* the certificate has not been loaded yet */
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_ADD_CHAIN_CERT);
        return HITLS_CERT_ERR_ADD_CHAIN_CERT;
    }

    HITLS_CERT_Chain *chain = certPair->chain;
    HITLS_CERT_Chain *newChain = NULL;
    if (chain == NULL) {
        newChain = SAL_CERT_ChainNew();
        if (newChain == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16295, "ChainNew fail");
        }
        chain = newChain;
    }

    int32_t ret = SAL_CERT_ChainAppend(chain, cert);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(newChain);
        return ret;
    }
    certPair->chain = chain;
    return HITLS_SUCCESS;
}

HITLS_CERT_Chain *SAL_CERT_GetCurrentChainCerts(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16296, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "mgrCtx null", 0, 0, 0, 0);
        return NULL;
    }

    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, mgrCtx->currentCertIndex);
    if (certPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16288, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "idx err", 0, 0, 0, 0);
        return NULL;     // TODO 日志
    }
    return certPair->chain;
}

void SAL_CERT_ClearCurrentChainCerts(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return;
    }

    CERT_Pair *certPair = SAL_CERT_HashFind(mgrCtx, mgrCtx->currentCertIndex);
    if (certPair == NULL || certPair->chain == NULL) {
        return;
    }
    SAL_CERT_ChainFree(certPair->chain);
    certPair->chain = NULL;
    return;
}

void SAL_CERT_ClearCertAndKey(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return;
    }

    BSL_HASH_Hash *certHash = mgrCtx->certHash;
    for (BSL_HASH_Iterator it = BSL_HASH_IterBegin(certHash); it != BSL_HASH_IterEnd(certHash);) {
        uint32_t keyType = (uint32_t)BSL_HASH_HashIterKey(certHash, it);
        CERT_Pair *certPair = (CERT_Pair *)BSL_HASH_IterValue(certHash, it);
        SAL_CERT_PairClear(mgrCtx, certPair);
        BSL_SAL_FREE(certPair);
        it = BSL_HASH_Erase(certHash, keyType);
    }
    mgrCtx->currentCertIndex = TLS_CERT_KEY_TYPE_UNKNOWN;    // TODO 决定用什么值
    return;
}

int32_t SAL_CERT_AddExtraChainCert(CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert)
{
    if (mgrCtx == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Chain *newChain = NULL;
    HITLS_CERT_Chain *chain = mgrCtx->extraChain;
    if (chain == NULL) {
        newChain = SAL_CERT_ChainNew();
        if (newChain == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16298, "ChainNew fail");
        }
        chain = newChain;
    }

    int32_t ret = SAL_CERT_ChainAppend(chain, cert);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(newChain);
        return ret;
    }
    mgrCtx->extraChain = chain;
    return HITLS_SUCCESS;
}

HITLS_CERT_Chain *SAL_CERT_GetExtraChainCerts(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return NULL;
    }

    return mgrCtx->extraChain;
}

void SAL_CERT_ClearExtraChainCerts(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return;
    }

    HITLS_CERT_Chain *chain = mgrCtx->extraChain;
    if (chain == NULL) {
        return;
    }
    SAL_CERT_ChainFree(chain);
    mgrCtx->extraChain = NULL;
    return;
}

int32_t SAL_CERT_SetVerifyDepth(CERT_MgrCtx *mgrCtx, uint32_t depth)
{
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    mgrCtx->verifyParam.verifyDepth = depth;
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_GetVerifyDepth(CERT_MgrCtx *mgrCtx, uint32_t *depth)
{
    if (mgrCtx == NULL || depth == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *depth = mgrCtx->verifyParam.verifyDepth;
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_SetDefaultPasswordCb(CERT_MgrCtx *mgrCtx, HITLS_PasswordCb cb)
{
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    mgrCtx->defaultPasswdCb = cb;
    return HITLS_SUCCESS;
}

HITLS_PasswordCb SAL_CERT_GetDefaultPasswordCb(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return NULL;
    }
    return mgrCtx->defaultPasswdCb;
}

int32_t SAL_CERT_SetDefaultPasswordCbUserdata(CERT_MgrCtx *mgrCtx, void *userdata)
{
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    mgrCtx->defaultPasswdCbUserData = userdata;
    return HITLS_SUCCESS;
}

void *SAL_CERT_GetDefaultPasswordCbUserdata(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return NULL;
    }
    return mgrCtx->defaultPasswdCbUserData;
}

int32_t SAL_CERT_SetVerifyCb(CERT_MgrCtx *mgrCtx, HITLS_VerifyCb cb)
{
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    mgrCtx->verifyCb = cb;
    return HITLS_SUCCESS;
}

HITLS_VerifyCb SAL_CERT_GetVerifyCb(CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL) {
        return NULL;
    }
    return mgrCtx->verifyCb;
}