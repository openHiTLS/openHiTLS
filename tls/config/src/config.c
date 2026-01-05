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
#include <stdbool.h>
#include "hitls_build.h"
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "hitls_type.h"
#include "hitls_error.h"
#ifdef HITLS_TLS_FEATURE_PSK
#include "hitls_psk.h"
#endif
#ifdef HITLS_TLS_PROTO_DTLS12
#include "hitls_cookie.h"
#endif
#ifdef HITLS_TLS_FEATURE_ALPN
#include "hitls_alpn.h"
#endif
#include "hitls_cert_type.h"
#ifdef HITLS_TLS_FEATURE_SNI
#include "hitls_sni.h"
#endif
#include "tls.h"
#include "tls_binlog_id.h"
#include "cert.h"
#include "crypt.h"
#ifdef HITLS_TLS_FEATURE_SESSION
#include "session_mgr.h"
#endif
#include "config_check.h"
#include "config_default.h"
#include "bsl_list.h"
#include "rec.h"
#include "cert_method.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
#include "custom_extensions.h"
#endif

#ifdef HITLS_TLS_CONFIG_CIPHER_SUITE
/* Define the upper limit of the group type */
#define MAX_GROUP_TYPE_NUM 128u
#endif

void CFG_CleanConfig(HITLS_Config *config)
{
    BSL_SAL_FREE(config->cipherSuites);
#ifdef HITLS_TLS_PROTO_TLS13
    BSL_SAL_FREE(config->tls13CipherSuites);
#endif
    BSL_SAL_FREE(config->pointFormats);
    BSL_SAL_FREE(config->groups);
    BSL_SAL_FREE(config->signAlgorithms);
#ifdef HITLS_TLS_FEATURE_PROVIDER
#ifndef HITLS_TLS_CAP_NO_STR
    for (uint32_t i = 0; i < config->groupInfolen; i++) {
        BSL_SAL_FREE(config->groupInfo[i].name);
    }
#endif
    BSL_SAL_FREE(config->groupInfo);
    config->groupInfoSize = 0;
    config->groupInfolen = 0;
#ifndef HITLS_TLS_CAP_NO_STR
    for (uint32_t i = 0; i < config->sigSchemeInfolen; i++) {
        BSL_SAL_FREE(config->sigSchemeInfo[i].name);
    }
#endif
    BSL_SAL_FREE(config->sigSchemeInfo);
    config->sigSchemeInfoSize = 0;
    config->sigSchemeInfolen = 0;
#endif

#if defined(HITLS_TLS_PROTO_TLS12) && defined(HITLS_TLS_FEATURE_PSK)
    BSL_SAL_FREE(config->pskIdentityHint);
#endif
#ifdef HITLS_TLS_FEATURE_ALPN
    BSL_SAL_FREE(config->alpnList);
#endif
#ifdef HITLS_TLS_FEATURE_SNI
    BSL_SAL_FREE(config->serverName);
#endif
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
    HITLS_CFG_ClearCAList(config);
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
    SAL_CRYPT_FreeDhKey(config->dhTmp);
    config->dhTmp = NULL;
#endif
#ifdef HITLS_TLS_FEATURE_SESSION
    SESSMGR_Free(config->sessMgr);
    config->sessMgr = NULL;
#endif
    SAL_CERT_MgrCtxFree(config->certMgrCtx);
    config->certMgrCtx = NULL;
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    FreeCustomExtensions(config->customExts);
    config->customExts = NULL;
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
    BSL_SAL_ReferencesFree(&(config->references));
#ifdef HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET
    BSL_SAL_FREE(config->sessionTicketExt);
    config->sessionTicketExtSize = 0;
#endif
}


static void ShallowCopy(HITLS_Ctx *ctx, const HITLS_Config *srcConfig)
{
    HITLS_Config *destConfig = &ctx->config.tlsConfig;

    /*
     * Other parameters except CipherSuite, PointFormats, Group, SignAlgorithms, Psk, SessionId, CertMgr, and SessMgr
     * are shallowly copied, and some of them reference globalConfig.
     */
    destConfig->libCtx = LIBCTX_FROM_CONFIG(srcConfig);
    destConfig->attrName = ATTRIBUTE_FROM_CONFIG(srcConfig);
    destConfig->minVersion = srcConfig->minVersion;
    destConfig->maxVersion = srcConfig->maxVersion;
    destConfig->isQuietShutdown = srcConfig->isQuietShutdown;
    destConfig->isSupportServerPreference = srcConfig->isSupportServerPreference;
    destConfig->maxCertList = srcConfig->maxCertList;
    destConfig->isSupportExtendMasterSecret = srcConfig->isSupportExtendMasterSecret;
    destConfig->emptyRecordsNum = srcConfig->emptyRecordsNum;
    destConfig->isKeepPeerCert = srcConfig->isKeepPeerCert;
    destConfig->version = srcConfig->version;
    destConfig->originVersionMask = srcConfig->originVersionMask;
    destConfig->endpoint = srcConfig->endpoint;
#ifdef HITLS_TLS_PROTO_TLS13
    destConfig->isMiddleBoxCompat = srcConfig->isMiddleBoxCompat;
#endif
#ifdef HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT
    destConfig->maxSendFragment = srcConfig->maxSendFragment;
#endif
#ifdef HITLS_TLS_FEATURE_REC_INBUFFER_SIZE
    destConfig->recInbufferSize = srcConfig->recInbufferSize;
#endif
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    destConfig->isSupportRenegotiation = srcConfig->isSupportRenegotiation;
    destConfig->allowClientRenegotiate = srcConfig->allowClientRenegotiate;
#endif
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
    destConfig->allowLegacyRenegotiate = srcConfig->allowLegacyRenegotiate;
#endif
#ifdef HITLS_TLS_SUITE_KX_RSA
    destConfig->needCheckPmsVersion = srcConfig->needCheckPmsVersion;
#endif
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    destConfig->needCheckKeyUsage = srcConfig->needCheckKeyUsage;
#endif
    destConfig->userData = srcConfig->userData;
    destConfig->userDataFreeCb = srcConfig->userDataFreeCb;
#ifdef HITLS_TLS_FEATURE_MODE
    destConfig->modeSupport = srcConfig->modeSupport;
#endif
    destConfig->readAhead = srcConfig->readAhead;
    destConfig->recordPaddingCb = srcConfig->recordPaddingCb;
    destConfig->recordPaddingArg = srcConfig->recordPaddingArg;
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
    destConfig->isSupportDhAuto = srcConfig->isSupportDhAuto;
    destConfig->dhTmpCb = srcConfig->dhTmpCb;
#endif

#if defined(HITLS_TLS_FEATURE_RENEGOTIATION) && defined(HITLS_TLS_FEATURE_SESSION)
    destConfig->isResumptionOnRenego = srcConfig->isResumptionOnRenego;
#endif
#ifdef HITLS_TLS_FEATURE_CERT_MODE
    destConfig->isSupportClientVerify = srcConfig->isSupportClientVerify;
    destConfig->isSupportNoClientCert = srcConfig->isSupportNoClientCert;
    destConfig->isSupportVerifyNone = srcConfig->isSupportVerifyNone;
#endif
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    destConfig->isSupportSessionTicket = srcConfig->isSupportSessionTicket;
#endif
#if defined(HITLS_TLS_FEATURE_RENEGOTIATION) && defined(HITLS_TLS_FEATURE_CERT_MODE)
    destConfig->isSupportClientOnceVerify = srcConfig->isSupportClientOnceVerify;
#endif
#ifdef HITLS_TLS_FEATURE_PHA
    destConfig->isSupportPostHandshakeAuth = srcConfig->isSupportPostHandshakeAuth;
#endif
#ifdef HITLS_TLS_FEATURE_PSK
    destConfig->pskClientCb = srcConfig->pskClientCb;
    destConfig->pskServerCb = srcConfig->pskServerCb;
#endif
#ifdef HITLS_TLS_PROTO_TLS13
    destConfig->keyExchMode = srcConfig->keyExchMode;
#endif
#ifdef HITLS_TLS_FEATURE_INDICATOR
    destConfig->infoCb = srcConfig->infoCb;
    destConfig->msgCb = srcConfig->msgCb;
    destConfig->msgArg = srcConfig->msgArg;
#endif
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    destConfig->dtlsTimerCb = srcConfig->dtlsTimerCb;
    destConfig->dtlsPostHsTimeoutVal = srcConfig->dtlsPostHsTimeoutVal;
    destConfig->isSupportDtlsCookieExchange = srcConfig->isSupportDtlsCookieExchange;
#endif
#ifdef HITLS_TLS_FEATURE_SECURITY
    destConfig->securityCb = srcConfig->securityCb;
    destConfig->securityExData = srcConfig->securityExData;
    destConfig->securityLevel = srcConfig->securityLevel;
#endif
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    destConfig->isEncryptThenMac = srcConfig->isEncryptThenMac;
#endif
#if defined(HITLS_TLS_PROTO_TLS13) && defined(HITLS_TLS_FEATURE_PSK)
    destConfig->pskFindSessionCb = srcConfig->pskFindSessionCb;
    destConfig->pskUseSessionCb = srcConfig->pskUseSessionCb;
#endif
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    destConfig->ticketNums = srcConfig->ticketNums;
#endif
#ifdef HITLS_TLS_FEATURE_FLIGHT
    destConfig->isFlightTransmitEnable = srcConfig->isFlightTransmitEnable;
#endif
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
    destConfig->recordSizeLimit = srcConfig->recordSizeLimit;
#endif
}

static int32_t DeepCopy(void** destConfig, const void* srcConfig, uint32_t logId, uint32_t len)
{
#ifndef HITLS_BSL_LOG
    (void)logId;
#endif
    BSL_SAL_FREE(*destConfig);
    *destConfig = BSL_SAL_Dump(srcConfig, len);
    if (*destConfig == NULL) {
        BSL_LOG_BINLOG_FIXLEN(logId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    return HITLS_SUCCESS;
}

static int32_t PointFormatsCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->pointFormats != NULL) {
        int32_t ret = DeepCopy((void **)&destConfig->pointFormats, srcConfig->pointFormats, BINLOG_ID16584,
            srcConfig->pointFormatsSize * sizeof(uint8_t));
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        destConfig->pointFormatsSize = srcConfig->pointFormatsSize;
    }
    return HITLS_SUCCESS;
}

static int32_t GroupCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->groups != NULL) {
        int32_t ret = DeepCopy((void **)&destConfig->groups, srcConfig->groups, BINLOG_ID16585,
            srcConfig->groupsSize * sizeof(uint16_t));
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        destConfig->groupsSize = srcConfig->groupsSize;
    }
#ifdef HITLS_TLS_FEATURE_PROVIDER
    if (srcConfig->groupInfo != NULL) {
#ifndef HITLS_TLS_CAP_NO_STR
        for (uint32_t i = 0; i < destConfig->groupInfolen; i++) {
            BSL_SAL_FREE(destConfig->groupInfo[i].name);
        }
#endif
        BSL_SAL_FREE(destConfig->groupInfo);
        destConfig->groupInfoSize = 0;
        destConfig->groupInfolen = 0;
        destConfig->groupInfo= BSL_SAL_Calloc(srcConfig->groupInfolen, sizeof(TLS_GroupInfo));
        if (destConfig->groupInfo == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->groupInfoSize = srcConfig->groupInfolen;
        for (uint32_t i = 0; i < srcConfig->groupInfolen; i++) {
            destConfig->groupInfo[i] = srcConfig->groupInfo[i];
#ifndef HITLS_TLS_CAP_NO_STR
            destConfig->groupInfo[i].name =
                BSL_SAL_Dump(srcConfig->groupInfo[i].name, strlen(srcConfig->groupInfo[i].name) + 1);
            if (destConfig->groupInfo[i].name == NULL) {
                return HITLS_MEMALLOC_FAIL;
            }
            destConfig->groupInfolen++;
#endif
        }
    }
#endif
    return HITLS_SUCCESS;
}

#if defined(HITLS_TLS_PROTO_TLS12) && defined(HITLS_TLS_FEATURE_PSK)
static int32_t PskCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->pskIdentityHint != NULL) {
        BSL_SAL_FREE(destConfig->pskIdentityHint);
        destConfig->pskIdentityHint = BSL_SAL_Dump(srcConfig->pskIdentityHint, srcConfig->hintSize * sizeof(uint8_t));
        if (destConfig->pskIdentityHint == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16586, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->hintSize = srcConfig->hintSize;
    }
    return HITLS_SUCCESS;
}
#endif
static int32_t SignAlgorithmsCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->signAlgorithms != NULL) {
        int32_t ret = DeepCopy((void **)&destConfig->signAlgorithms, srcConfig->signAlgorithms, BINLOG_ID16587,
            srcConfig->signAlgorithmsSize * sizeof(uint16_t));
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        destConfig->signAlgorithmsSize = srcConfig->signAlgorithmsSize;
    }
#ifdef HITLS_TLS_FEATURE_PROVIDER
    if (srcConfig->sigSchemeInfo != NULL) {
        for (uint32_t i = 0; i < destConfig->sigSchemeInfolen; i++) {
            BSL_SAL_FREE(destConfig->sigSchemeInfo[i].name);
        }
        BSL_SAL_FREE(destConfig->sigSchemeInfo);
        destConfig->sigSchemeInfoSize = 0;
        destConfig->sigSchemeInfolen = 0;
        destConfig->sigSchemeInfo = BSL_SAL_Calloc(srcConfig->sigSchemeInfolen, sizeof(TLS_SigSchemeInfo));
        if (destConfig->sigSchemeInfo == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->sigSchemeInfoSize = srcConfig->sigSchemeInfolen;
        for (uint32_t i = 0; i < srcConfig->sigSchemeInfolen; i++) {
            destConfig->sigSchemeInfo[i] = srcConfig->sigSchemeInfo[i];
            destConfig->sigSchemeInfo[i].name =
                BSL_SAL_Dump(srcConfig->sigSchemeInfo[i].name, strlen(srcConfig->sigSchemeInfo[i].name) + 1);
            if (destConfig->sigSchemeInfo[i].name == NULL) {
                return HITLS_MEMALLOC_FAIL;
            }
            destConfig->sigSchemeInfolen++;
        }
    }
#endif
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_ALPN
static int32_t AlpnListDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->alpnListSize == 0 || srcConfig->alpnList == NULL) {
        return HITLS_SUCCESS;
    }
    BSL_SAL_FREE(destConfig->alpnList);
    destConfig->alpnList = BSL_SAL_Dump(srcConfig->alpnList, (srcConfig->alpnListSize + 1) * sizeof(uint8_t));
    if (destConfig->alpnList == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16588, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    destConfig->alpnListSize = srcConfig->alpnListSize;
    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_FEATURE_SNI
static int32_t ServerNameDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->serverNameSize != 0 && srcConfig->serverName != NULL) {
        int32_t ret = DeepCopy((void **)&destConfig->serverName, srcConfig->serverName, BINLOG_ID16589,
            srcConfig->serverNameSize * sizeof(uint8_t));
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        destConfig->serverNameSize = srcConfig->serverNameSize;
    }
    return HITLS_SUCCESS;
}
#endif
static int32_t CipherSuiteDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->cipherSuites != NULL) {
        int32_t ret = DeepCopy((void **)&destConfig->cipherSuites, srcConfig->cipherSuites, BINLOG_ID16590,
            srcConfig->cipherSuitesSize * sizeof(uint16_t));
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        destConfig->cipherSuitesSize = srcConfig->cipherSuitesSize;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    if (srcConfig->tls13CipherSuites != NULL) {
        int32_t ret = DeepCopy((void **)&destConfig->tls13CipherSuites, srcConfig->tls13CipherSuites, BINLOG_ID16591,
            srcConfig->tls13cipherSuitesSize * sizeof(uint16_t));
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_FREE(destConfig->cipherSuites);
            return ret;
        }
        destConfig->tls13cipherSuitesSize = srcConfig->tls13cipherSuitesSize;
    }
#endif
    return HITLS_SUCCESS;
}

static int32_t CertMgrDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (!SAL_CERT_MgrIsEnable()) {
        return HITLS_SUCCESS;
    }
    destConfig->certMgrCtx = SAL_CERT_MgrCtxDup(srcConfig->certMgrCtx);
    if (destConfig->certMgrCtx == NULL) {
        return HITLS_CERT_ERR_MGR_DUP;
    }
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_FEATURE_SESSION_ID
static int32_t SessionIdCtxCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->sessionIdCtxSize != 0 &&
        memcpy_s(destConfig->sessionIdCtx, sizeof(destConfig->sessionIdCtx),
        srcConfig->sessionIdCtx, srcConfig->sessionIdCtxSize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16592, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }

    destConfig->sessionIdCtxSize = srcConfig->sessionIdCtxSize;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_ID */

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
static int32_t CryptKeyDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->dhTmp != NULL) {
        destConfig->dhTmp = SAL_CRYPT_DupDhKey(srcConfig->dhTmp);
        if (destConfig->dhTmp == NULL) {
            return HITLS_CONFIG_DUP_DH_KEY_FAIL;
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
void FreeNode(HITLS_TrustedCANode *node)
{
    BSL_SAL_FREE(node->data);
    BSL_SAL_FREE(node);
}

static HITLS_TrustedCANode *DupNameNode(const HITLS_TrustedCANode *src)
{
    /* Src is not null. */
    HITLS_TrustedCANode *dest = BSL_SAL_Malloc(sizeof(HITLS_TrustedCANode));
    if (dest == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    dest->caType = src->caType;
    // nameValue
    dest->dataSize = src->dataSize;
    if (dest->dataSize != 0) {
        dest->data = BSL_SAL_Dump(src->data, src->dataSize);
        if (dest->data == NULL) {
            BSL_SAL_Free(dest);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return NULL;
        }
    }
    return dest;
}

static int32_t CaListDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->caList != NULL) {
        destConfig->caList =
            BSL_LIST_Copy(srcConfig->caList, (BSL_LIST_PFUNC_DUP)DupNameNode, (BSL_LIST_PFUNC_FREE)FreeNode);
        if (destConfig->caList == NULL) {
            return HITLS_MEMCPY_FAIL;
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */

#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
static int32_t CustomExtsDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    destConfig->customExts = DupCustomExtensions(srcConfig->customExts);
    if (srcConfig->customExts != NULL && destConfig->customExts == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */

static int32_t BasicConfigDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    int32_t ret = HITLS_SUCCESS;
    const struct {
        int32_t (*copyFunc)(HITLS_Config *destConfig, const HITLS_Config *srcConfig);
    } copyFeatures[] = {
#ifdef HITLS_TLS_FEATURE_SESSION_ID
        {SessionIdCtxCopy},
#endif
        {CertMgrDeepCopy},
#ifdef HITLS_TLS_FEATURE_ALPN
        {AlpnListDeepCopy},
#endif
#ifdef HITLS_TLS_FEATURE_SNI
        {ServerNameDeepCopy},
#endif
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
        {CryptKeyDeepCopy},
#endif
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
        {CaListDeepCopy},
#endif
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
        {CustomExtsDeepCopy},
#endif
    };

    for (size_t i = 0; i < sizeof(copyFeatures) / sizeof(copyFeatures[0]); i++) {
        if (copyFeatures[i].copyFunc != NULL) {
            ret = copyFeatures[i].copyFunc(destConfig, srcConfig);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
    }

    return HITLS_SUCCESS;
}

int32_t DumpConfig(HITLS_Ctx *ctx, const HITLS_Config *srcConfig)
{
    int32_t ret;
    HITLS_Config *destConfig = &ctx->config.tlsConfig;

    // shallow copy
    ShallowCopy(ctx, srcConfig);

    ret = CipherSuiteDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = PointFormatsCfgDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = GroupCfgDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = SignAlgorithmsCfgDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
#if defined(HITLS_TLS_PROTO_TLS12) && defined(HITLS_TLS_FEATURE_PSK)
    ret = PskCfgDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
#endif
    ret = BasicConfigDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    return HITLS_SUCCESS;
EXIT:
    CFG_CleanConfig(destConfig);
    return ret;
}

HITLS_Config *CreateConfig(void)
{
    HITLS_Config *newConfig = BSL_SAL_Calloc(1u, sizeof(HITLS_Config));
    if (newConfig == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16594, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }
    if (BSL_SAL_ReferencesInit(&(newConfig->references)) != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16595, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ReferencesInit fail", 0, 0, 0, 0);
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    return newConfig;
}

void HITLS_CFG_FreeConfig(HITLS_Config *config)
{
    if (config == NULL) {
        return;
    }
    int ret = 0;
    (void)BSL_SAL_AtomicDownReferences(&(config->references), &ret);
    if (ret > 0) {
        return;
    }
    CFG_CleanConfig(config);
#ifdef HITLS_TLS_CONFIG_USER_DATA
    if (config->userData != NULL && config->userDataFreeCb != NULL) {
        (void)config->userDataFreeCb(config->userData);
        config->userData = NULL;
    }
#endif
    BSL_SAL_FREE(config);
}

int32_t HITLS_CFG_UpRef(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    int ret = 0;
    (void)BSL_SAL_AtomicUpReferences(&(config->references), &ret);
    (void)ret;

    return HITLS_SUCCESS;
}

uint32_t MapVersion2VersionBit(bool isDatagram, uint16_t version)
{
    (void)isDatagram;
    uint32_t ret = 0;
    switch (version) {
        case HITLS_VERSION_TLS12:
            ret = TLS12_VERSION_BIT;
            break;
        case HITLS_VERSION_TLS13:
            ret = TLS13_VERSION_BIT;
            break;
        case HITLS_VERSION_TLCP_DTLCP11:
            if (isDatagram) {
                ret = DTLCP11_VERSION_BIT;
            } else {
                ret = TLCP11_VERSION_BIT;
            }
            break;
        case HITLS_VERSION_DTLS12:
            ret = DTLS12_VERSION_BIT;
            break;
        default:
            break;
    }
    return ret;
}


#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t CheckRenegotiatedVersion(TLS_Ctx *ctx)
{
    if (ctx->negotiatedInfo.isRenegotiation) {
        uint16_t oldNegotiationVersion = ctx->negotiatedInfo.version;
        uint32_t versionBit =
            MapVersion2VersionBit(IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask), oldNegotiationVersion);
        if ((versionBit & ctx->config.tlsConfig.version) == 0) {
            return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
        }
        ctx->config.tlsConfig.version = versionBit;
        ctx->config.tlsConfig.minVersion = ctx->negotiatedInfo.version;
        ctx->config.tlsConfig.maxVersion = ctx->negotiatedInfo.version;
    }
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONFIG_VERSION
void ChangeMinMaxVersion(uint32_t versionMask, uint32_t originVersionMask, uint16_t *minVersion, uint16_t *maxVersion)
{
    uint32_t versionMaskBit = versionMask;
    if (IS_SUPPORT_TLS(versionMaskBit) && IS_SUPPORT_TLCP(versionMaskBit)) {
        versionMaskBit &= ~TLCP_VERSION_BITS;
    }
    uint32_t versionBits[] = {TLS12_VERSION_BIT, TLS13_VERSION_BIT, DTLS12_VERSION_BIT, TLCP11_VERSION_BIT,
                              DTLCP11_VERSION_BIT};
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_TLS13, HITLS_VERSION_DTLS12, HITLS_VERSION_TLCP_DTLCP11,
                           HITLS_VERSION_TLCP_DTLCP11};
    uint32_t versionBitsSize = sizeof(versionBits) / sizeof(uint32_t);
    uint32_t minIdx = 0;
    uint32_t maxIdx = 0;
    bool found = false;
    uint32_t intersection = versionMaskBit & originVersionMask;
    for (uint32_t i = 0; i < versionBitsSize; i++) {
        if ((intersection & versionBits[i]) == versionBits[i]) {
            if (!found) {
                minIdx = i;
                found = true;
            }
            maxIdx = i;
        } else if (found) {
            break;
        }
    }
    if (!found) {
        // No version is supported
        *minVersion = 0;
        *maxVersion = 0;
        return;
    }
    *minVersion = versions[minIdx];
    *maxVersion = versions[maxIdx];
}

static int ChangeVersionMask(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    uint32_t originVersionMask = config->originVersionMask;
    uint32_t versionMask = 0;
    uint32_t versionBit = 0;
    uint16_t begin = IS_DTLS_VERSION(maxVersion) ? maxVersion : minVersion;
    uint16_t end = IS_DTLS_VERSION(maxVersion) ? minVersion : maxVersion;

    for (uint16_t version = begin; version <= end; version++) {
        versionBit = MapVersion2VersionBit(IS_SUPPORT_DATAGRAM(originVersionMask), version);
        versionMask |= versionBit;
    }

    if ((versionMask & originVersionMask) == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16598, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Config version err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
        return HITLS_CONFIG_INVALID_VERSION;
    }

    config->version = (versionMask & originVersionMask);
    return HITLS_SUCCESS;
}

static int32_t CheckVersionValid(const HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    if ((minVersion < HITLS_VERSION_SSL30 && minVersion != 0) ||
        (minVersion == HITLS_VERSION_SSL30 && config->minVersion != HITLS_VERSION_SSL30) ||
        (maxVersion <= HITLS_VERSION_SSL30 && maxVersion != 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16599, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Config version err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
        return HITLS_CONFIG_INVALID_VERSION;
    }
    return HITLS_SUCCESS;
}

static void ChangeTmpVersion(HITLS_Config *config, uint16_t *tmpMinVersion, uint16_t *tmpMaxVersion)
{
    uint16_t minVersion = 0;
    uint16_t maxVersion = 0;
    ChangeMinMaxVersion(config->originVersionMask, config->originVersionMask, &minVersion, &maxVersion);
    if (*tmpMinVersion == 0) {
        if (config->originVersionMask == DTLS_VERSION_MASK) {
            *tmpMinVersion = HITLS_VERSION_DTLS12;
        } else {
            *tmpMinVersion = minVersion;
        }
    }
    if (*tmpMaxVersion == 0) {
        if (config->originVersionMask == DTLS_VERSION_MASK) {
            *tmpMaxVersion = HITLS_VERSION_DTLS12;
        } else {
            *tmpMaxVersion = maxVersion;
        }
    }
}

int32_t HITLS_CFG_SetVersion(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret = 0;
    if (config->minVersion == minVersion && config->maxVersion == maxVersion && minVersion != 0 && maxVersion != 0) {
        return HITLS_SUCCESS;
    }

    /* TLCP cannot be supported by setting the version number. They can be
     * initialized only by using the corresponding configuration initialization interface.
     */
    ret = CheckVersionValid(config, minVersion, maxVersion);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint16_t tmpMinVersion = minVersion;
    uint16_t tmpMaxVersion = maxVersion;

    ChangeTmpVersion(config, &tmpMinVersion, &tmpMaxVersion);

    ret = CheckVersion(tmpMinVersion, tmpMaxVersion);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* In invalid cases, both maxVersion and minVersion are 0 */
    ret = ChangeVersionMask(config, tmpMinVersion, tmpMaxVersion);
    if (ret == HITLS_SUCCESS) {
        ChangeMinMaxVersion(config->version, config->originVersionMask, &config->minVersion, &config->maxVersion);
    }
    return ret;
}
#endif /* HITLS_TLS_CONFIG_VERSION */

#ifdef HITLS_TLS_CONFIG_VERSION
int32_t HITLS_CFG_SetVersionForbid(HITLS_Config *config, uint32_t noVersion)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    // Now only DTLS1.2 is supported, so single version is not supported (disable to version 0)
    config->version &= ~noVersion;
    ChangeMinMaxVersion(config->version, config->originVersionMask, &config->minVersion, &config->maxVersion);
    return HITLS_SUCCESS;
}
#endif

static void GetCipherSuitesCnt(const uint16_t *cipherSuites, uint32_t cipherSuitesSize,
    uint32_t *tls13CipherSize, uint32_t *tlsCipherSize)
{
    (void)cipherSuites;
    uint32_t tmpCipherSize = *tlsCipherSize;
    uint32_t tmpTls13CipherSize = *tls13CipherSize;
    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
#ifdef HITLS_TLS_PROTO_TLS13
        if ((cipherSuites[i] >= HITLS_AES_128_GCM_SHA256 && cipherSuites[i] <= HITLS_AES_128_CCM_8_SHA256) ||
            (cipherSuites[i] == HITLS_SM4_GCM_SM3 || cipherSuites[i] == HITLS_SM4_CCM_SM3)) {
            tmpTls13CipherSize++;
            continue;
        }
#endif
        tmpCipherSize++;
    }
    *tls13CipherSize = tmpTls13CipherSize;
    *tlsCipherSize = tmpCipherSize;
}

int32_t HITLS_CFG_SetCipherSuites(HITLS_Config *config, const uint16_t *cipherSuites, uint32_t cipherSuitesSize)
{
    if (config == NULL || cipherSuites == NULL || cipherSuitesSize == 0) {
        return HITLS_NULL_INPUT;
    }

    if (cipherSuitesSize > HITLS_CFG_MAX_SIZE) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint32_t tlsCipherSize = 0;
    uint32_t validTlsCipher = 0;
    uint32_t tls13CipherSize = 0;
#ifdef HITLS_TLS_PROTO_TLS13
    uint32_t validTls13Cipher = 0;
#endif
    GetCipherSuitesCnt(cipherSuites, cipherSuitesSize, &tls13CipherSize, &tlsCipherSize);

    uint16_t *cipherSuite = BSL_SAL_Calloc(1u, (tlsCipherSize + 1) * sizeof(uint16_t));
    if (cipherSuite == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16600, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    uint16_t *tls13CipherSuite = BSL_SAL_Calloc(1u, (tls13CipherSize + 1) * sizeof(uint16_t));

    if (tls13CipherSuite == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16601, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        BSL_SAL_FREE(cipherSuite);
        return HITLS_MEMALLOC_FAIL;
    }
#endif
    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        if (CFG_CheckCipherSuiteSupported(cipherSuites[i]) != true) {
            continue;
        }
        if ((cipherSuites[i] >= HITLS_AES_128_GCM_SHA256 && cipherSuites[i] <= HITLS_AES_128_CCM_8_SHA256) ||
            (cipherSuites[i] == HITLS_SM4_GCM_SM3 || cipherSuites[i] == HITLS_SM4_CCM_SM3)) {
#ifdef HITLS_TLS_PROTO_TLS13
            tls13CipherSuite[validTls13Cipher] = cipherSuites[i];
            validTls13Cipher++;
#endif
            continue;
        }
        cipherSuite[validTlsCipher] = cipherSuites[i];
        validTlsCipher++;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    if (validTls13Cipher == 0) {
        BSL_SAL_FREE(tls13CipherSuite);
    } else {
        BSL_SAL_FREE(config->tls13CipherSuites);
        config->tls13CipherSuites = tls13CipherSuite;
        config->tls13cipherSuitesSize = validTls13Cipher;
    }
#endif
    if (validTlsCipher == 0) {
        BSL_SAL_FREE(cipherSuite);
    } else {
        BSL_SAL_FREE(config->cipherSuites);
        config->cipherSuites = cipherSuite;
        config->cipherSuitesSize = validTlsCipher;
    }

    if (validTlsCipher == 0
#ifdef HITLS_TLS_PROTO_TLS13
        && validTls13Cipher == 0
#endif
    ) {
        return HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE;
    }

    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_CFG_GetCipherSuites(HITLS_Config *config, uint16_t *data, uint32_t dataLen, uint32_t *cipherSuitesSize)
{
    if (config == NULL || data == NULL || cipherSuitesSize == NULL) {
        return HITLS_NULL_INPUT;
    }

    uint32_t num = 0;
    if (dataLen < config->cipherSuitesSize + config->tls13cipherSuitesSize) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    if (config->maxVersion == HITLS_VERSION_TLS13) {
        for (uint32_t i = 0; i < config->tls13cipherSuitesSize; i++) {
            data[num] = config->tls13CipherSuites[i];
            num += 1;
        }
    }

    for (uint32_t i = 0; i < config->cipherSuitesSize; i++) {
        data[num] = config->cipherSuites[i];
        num += 1;
    }
    *cipherSuitesSize = num;
    return HITLS_SUCCESS;
}
#endif
int32_t HITLS_CFG_SetEcPointFormats(HITLS_Config *config, const uint8_t *pointFormats, uint32_t pointFormatsSize)
{
    if ((config == NULL) || (pointFormats == NULL) || (pointFormatsSize == 0)) {
        return HITLS_NULL_INPUT;
    }

    if (pointFormatsSize > HITLS_CFG_MAX_SIZE) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *newData = BSL_SAL_Dump(pointFormats, pointFormatsSize * sizeof(uint8_t));
    if (newData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16602, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_SAL_FREE(config->pointFormats);
    config->pointFormats = newData;
    config->pointFormatsSize = pointFormatsSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetGroups(HITLS_Config *config, const uint16_t *groups, uint32_t groupsSize)
{
    if ((config == NULL) || (groups == NULL) || (groupsSize == 0u)) {
        return HITLS_NULL_INPUT;
    }

    if (groupsSize > HITLS_CFG_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint16_t *newData = BSL_SAL_Dump(groups, groupsSize * sizeof(uint16_t));
    if (newData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16603, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_SAL_FREE(config->groups);
    config->groups = newData;
    config->groupsSize = groupsSize;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_CONFIG_CIPHER_SUITE
static uint16_t GroupToId(const char *name)
{
    if (strcmp(name, "HITLS_EC_GROUP_SECP256R1") == 0) {
        return HITLS_EC_GROUP_SECP256R1;
    }
    if (strcmp(name, "HITLS_EC_GROUP_SECP384R1") == 0) {
        return HITLS_EC_GROUP_SECP384R1;
    }
    if (strcmp(name, "HITLS_EC_GROUP_SECP521R1") == 0) {
        return HITLS_EC_GROUP_SECP521R1;
    }
    if (strcmp(name, "HITLS_EC_GROUP_BRAINPOOLP256R1") == 0) {
        return HITLS_EC_GROUP_BRAINPOOLP256R1;
    }
    if (strcmp(name, "HITLS_EC_GROUP_BRAINPOOLP384R1") == 0) {
        return HITLS_EC_GROUP_BRAINPOOLP384R1;
    }
    if (strcmp(name, "HITLS_EC_GROUP_BRAINPOOLP512R1") == 0) {
        return HITLS_EC_GROUP_BRAINPOOLP512R1;
    }
    if (strcmp(name, "HITLS_EC_GROUP_CURVE25519") == 0) {
        return HITLS_EC_GROUP_CURVE25519;
    }
    if (strcmp(name, "HITLS_EC_GROUP_SM2") == 0) {
        return HITLS_EC_GROUP_SM2;
    }
    if (strcmp(name, "HITLS_FF_DHE_2048") == 0) {
        return HITLS_FF_DHE_2048;
    }
    if (strcmp(name, "HITLS_FF_DHE_3072") == 0) {
        return HITLS_FF_DHE_3072;
    }
    if (strcmp(name, "HITLS_FF_DHE_4096") == 0) {
        return HITLS_FF_DHE_4096;
    }
    if (strcmp(name, "HITLS_FF_DHE_6144") == 0) {
        return HITLS_FF_DHE_6144;
    }
    if (strcmp(name, "HITLS_FF_DHE_8192") == 0) {
        return HITLS_FF_DHE_8192;
    }
    return HITLS_NAMED_GROUP_BUTT;
}


int32_t HITLS_CFG_SetGroupList(HITLS_Config *config, const char *groupNames, uint32_t groupNamesLen)
{
    if (config == NULL || groupNames == NULL) {
        return HITLS_NULL_INPUT;
    }

    uint16_t groupIds[MAX_GROUP_TYPE_NUM] = {0};
    uint32_t cnt = 0;
    uint16_t tmpGroupId = 0;
    char *context = NULL;
    char *groupNamesTmp = (char *)BSL_SAL_Calloc(sizeof(char), groupNamesLen + 1);
    if (groupNamesTmp == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16604, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(groupNamesTmp, groupNamesLen + 1, groupNames, groupNamesLen);
    char *groupName = strtok_s((char *)groupNamesTmp, ":", &context);

    while (groupName != NULL) {
        tmpGroupId = GroupToId(groupName);
        if (tmpGroupId == HITLS_NAMED_GROUP_BUTT) {
            BSL_SAL_FREE(groupNamesTmp);
            return HITLS_CONFIG_UNSUPPORT_GROUP;
        }
        if (cnt >= MAX_GROUP_TYPE_NUM) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16168, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "the group number to be set exceeds max group number.", 0, 0, 0, 0);
            BSL_SAL_FREE(groupNamesTmp);
            return HITLS_INVALID_INPUT;
        }
        groupIds[cnt++] = tmpGroupId;
        groupName = strtok_s(NULL, ":", &context);
    }
    BSL_SAL_FREE(groupNamesTmp);
    return HITLS_CFG_SetGroups(config, groupIds, cnt);
}
#endif /* HITLS_TLS_CONFIG_CIPHER_SUITE */

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
int32_t HITLS_CFG_SetDhAutoSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isSupportDhAuto = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetTmpDh(HITLS_Config *config, HITLS_CRYPT_Key *dhPkey)
{
    if ((config == NULL) || (dhPkey == NULL)) {
        return HITLS_NULL_INPUT;
    }
#ifdef HITLS_TLS_FEATURE_SECURITY
    int32_t secBits = 0;
    /* Temporary DH security check */
    int32_t ret = SAL_CERT_KeyCtrl(config, dhPkey, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
    if (ret != HITLS_SUCCESS) {
        return HITLS_CERT_KEY_CTRL_ERR_GET_SECBITS;
    }
    ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_TMP_DH, secBits, 0, dhPkey);
    if (ret != SECURITY_SUCCESS) {
        return HITLS_CRYPT_ERR_DH;
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */
    SAL_CRYPT_FreeDhKey(config->dhTmp);
    config->dhTmp = dhPkey;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetDhAutoSupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportDhAuto;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

#ifdef HITLS_TLS_SUITE_KX_RSA
int32_t HITLS_CFG_SetNeedCheckPmsVersion(HITLS_Config *config, bool needCheck)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->needCheckPmsVersion = needCheck;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONFIG_USER_DATA
void *HITLS_CFG_GetConfigUserData(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return config->userData;
}

int32_t HITLS_CFG_SetConfigUserData(HITLS_Config *config, void *userData)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->userData = userData;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetConfigUserDataFreeCb(HITLS_Config *config, HITLS_ConfigUserDataFreeCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->userDataFreeCb = callback;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
int32_t HITLS_CFG_SetTmpDhCb(HITLS_Config *config, HITLS_DhTmpCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->dhTmpCb = callback;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

#ifdef HITLS_TLS_CONFIG_RECORD_PADDING
int32_t HITLS_CFG_SetRecordPaddingCb(HITLS_Config *config, HITLS_RecordPaddingCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->recordPaddingCb = callback;

    return HITLS_SUCCESS;
}

HITLS_RecordPaddingCb HITLS_CFG_GetRecordPaddingCb(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return config->recordPaddingCb;
}

int32_t HITLS_CFG_SetRecordPaddingCbArg(HITLS_Config *config, void *arg)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->recordPaddingArg = arg;

    return HITLS_SUCCESS;
}

void *HITLS_CFG_GetRecordPaddingCbArg(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }
    return config->recordPaddingArg;
}
#endif

#ifdef HITLS_TLS_CONFIG_KEY_USAGE
int32_t HITLS_CFG_SetCheckKeyUsage(HITLS_Config *config, bool isCheck)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->needCheckKeyUsage = isCheck;

    return HITLS_SUCCESS;
}
#endif

int32_t HITLS_CFG_SetReadAhead(HITLS_Config *config, int32_t onOff)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->readAhead = onOff;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetReadAhead(HITLS_Config *config, int32_t *onOff)
{
    if (config == NULL || onOff == NULL) {
        return HITLS_NULL_INPUT;
    }

    *onOff = config->readAhead;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSignature(HITLS_Config *config, const uint16_t *signAlgs, uint16_t signAlgsSize)
{
    if ((config == NULL) || (signAlgs == NULL) || (signAlgsSize == 0)) {
        return HITLS_NULL_INPUT;
    }

    if (signAlgsSize > HITLS_CFG_MAX_SIZE) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint16_t *newData = BSL_SAL_Dump(signAlgs, signAlgsSize * sizeof(uint16_t));
    if (newData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16605, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_SAL_FREE(config->signAlgorithms);
    config->signAlgorithms = newData;
    config->signAlgorithmsSize = signAlgsSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetRenegotiationSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportRenegotiation = support;
    return HITLS_SUCCESS;
}

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t HITLS_CFG_SetLegacyRenegotiateSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->allowLegacyRenegotiate = support;
    return HITLS_SUCCESS;
}
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */

int32_t HITLS_CFG_SetExtendedMasterSecretSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportExtendMasterSecret = support;
    return HITLS_SUCCESS;
}

#if defined(HITLS_TLS_FEATURE_PSK) && (defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12))
int32_t HITLS_CFG_SetPskIdentityHint(HITLS_Config *config, const uint8_t *hint, uint32_t hintSize)
{
    if ((config == NULL) || (hint == NULL) || (hintSize == 0)) {
        return HITLS_NULL_INPUT;
    }

    if (hintSize > HS_PSK_IDENTITY_MAX_LEN) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *newData = BSL_SAL_Dump(hint, hintSize * sizeof(uint8_t));
    if (newData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16607, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_SAL_FREE(config->pskIdentityHint);
    config->pskIdentityHint = newData;
    config->hintSize = hintSize;

    return HITLS_SUCCESS;
}
#endif

int32_t HITLS_CFG_GetExtendedMasterSecretSupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportExtendMasterSecret;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_CONFIG_VERSION
int32_t HITLS_CFG_GetMaxVersion(const HITLS_Config *config, uint16_t *maxVersion)
{
    if (config == NULL || maxVersion == NULL) {
        return HITLS_NULL_INPUT;
    }

    *maxVersion = config->maxVersion;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetMinVersion(const HITLS_Config *config, uint16_t *minVersion)
{
    if (config == NULL || minVersion == NULL) {
        return HITLS_NULL_INPUT;
    }
    *minVersion = config->minVersion;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONFIG_VERSION
int32_t HITLS_CFG_GetVersionSupport(const HITLS_Config *config, uint32_t *version)
{
    if ((config == NULL) || (version == NULL)) {
        return HITLS_NULL_INPUT;
    }

    *version = config->version;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetVersionSupport(HITLS_Config *config, uint32_t version)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    if ((version & SSLV3_VERSION_BIT) == SSLV3_VERSION_BIT) {
        return HITLS_CONFIG_INVALID_VERSION;
    }
    uint32_t tmp = version & config->originVersionMask;
    config->version |= tmp;
    /* Update the maximum supported version */
    ChangeMinMaxVersion(config->version, config->originVersionMask, &config->minVersion, &config->maxVersion);
    return HITLS_SUCCESS;
}

int32_t HITLS_SetVersion(HITLS_Ctx *ctx, uint32_t minVersion, uint32_t maxVersion)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetVersion(&(ctx->config.tlsConfig), (uint16_t)minVersion, (uint16_t)maxVersion);
}

int32_t HITLS_SetVersionForbid(HITLS_Ctx *ctx, uint32_t noVersion)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetVersionForbid(&(ctx->config.tlsConfig), noVersion);
}
#endif

int32_t HITLS_CFG_SetQuietShutdown(HITLS_Config *config, int32_t mode)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    /* The value 0 indicates that the quiet disconnection mode is disabled. The value 1 indicates that the quiet
     * disconnection mode is enabled.
     */
    if (mode != 0 && mode != 1) {
        return HITLS_CONFIG_INVALID_SET;
    }

    if (mode == 0) {
        config->isQuietShutdown = false;
    } else {
        config->isQuietShutdown = true;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetQuietShutdown(const HITLS_Config *config, int32_t *mode)
{
    if (config == NULL || mode == NULL) {
        return HITLS_NULL_INPUT;
    }

    *mode = (int32_t)config->isQuietShutdown;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetEncryptThenMac(HITLS_Config *config, bool encryptThenMacType)
{
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isEncryptThenMac = encryptThenMacType;
    return HITLS_SUCCESS;
#else
    (void)config;
    (void)encryptThenMacType;
    return HITLS_CONFIG_UNSUPPORT;
#endif
}

int32_t HITLS_CFG_GetEncryptThenMac(const HITLS_Config *config, bool *encryptThenMacType)
{
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    if (config == NULL || encryptThenMacType == NULL) {
        return HITLS_NULL_INPUT;
    }

    *encryptThenMacType = config->isEncryptThenMac;
    return HITLS_SUCCESS;
#else
    (void)config;
    (void)encryptThenMacType;
    return HITLS_CONFIG_UNSUPPORT;
#endif
}

int32_t HITLS_CFG_SetCipherServerPreference(HITLS_Config *config, bool isSupport)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isSupportServerPreference = isSupport;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetCipherServerPreference(const HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportServerPreference;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_MAINTAIN_KEYLOG
int32_t HITLS_CFG_SetKeyLogCb(HITLS_Config *config, HITLS_KeyLogCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->keyLogCb = callback;
    return HITLS_SUCCESS;
}

HITLS_KeyLogCb HITLS_CFG_GetKeyLogCb(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return config->keyLogCb;
}
#endif

int32_t HITLS_CFG_SetEmptyRecordsNum(HITLS_Config *config, uint32_t emptyNum)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->emptyRecordsNum = emptyNum;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetEmptyRecordsNum(const HITLS_Config *config, uint32_t *emptyNum)
{
    if (config == NULL || emptyNum == NULL) {
        return HITLS_NULL_INPUT;
    }
    *emptyNum = config->emptyRecordsNum;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetEndPoint(HITLS_Config *config, bool isClient)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->endpoint = isClient ? HITLS_ENDPOINT_CLIENT : HITLS_ENDPOINT_SERVER;
    return HITLS_SUCCESS;
}