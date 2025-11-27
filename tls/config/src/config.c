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
#include "hitls_cookie.h"

#ifdef HITLS_TLS_CONFIG_CIPHER_SUITE
/* Define the upper limit of the group type */
#define MAX_GROUP_TYPE_NUM 128u
#endif
#ifdef HITLS_TLS_EXTENSION_CERT_AUTH
static void HitlsTrustedCANodeFree(void *caNode)
{
    if (caNode == NULL) {
        return;
    }
    HITLS_TrustedCANode *newCaNode = (HITLS_TrustedCANode *)caNode;
    BSL_SAL_FREE(newCaNode->data);
    newCaNode->data = NULL;
    BSL_SAL_FREE(newCaNode);
}

void HITLS_CFG_ClearCAList(HITLS_Config *config)
{
    if (config == NULL) {
        return;
    }
    BSL_LIST_FREE(config->caList, HitlsTrustedCANodeFree);
    config->caList = NULL;
    return;
}
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
    for (uint32_t i = 0; i < config->groupInfolen; i++) {
        BSL_SAL_FREE(config->groupInfo[i].name);
    }
    BSL_SAL_FREE(config->groupInfo);
    config->groupInfoSize = 0;
    config->groupInfolen = 0;
    for (uint32_t i = 0; i < config->sigSchemeInfolen; i++) {
        BSL_SAL_FREE(config->sigSchemeInfo[i].name);
    }
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
#ifdef HITLS_TLS_EXTENSION_CERT_AUTH
    BSL_LIST_FREE(config->caList, HitlsTrustedCANodeFree);
#endif
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
    return;
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
}

static int32_t DeepCopy(void** destConfig, const void* srcConfig, uint32_t logId, uint32_t len)
{
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
        if (destConfig->groupInfo != NULL) {
            BSL_SAL_FREE(destConfig->groupInfo->name);
            BSL_SAL_FREE(destConfig->groupInfo);
        }
        destConfig->groupInfo= BSL_SAL_Calloc(srcConfig->groupInfolen, sizeof(TLS_GroupInfo));
        if (destConfig->groupInfo == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->groupInfoSize = srcConfig->groupInfolen;
        for (uint32_t i = 0; i < srcConfig->groupInfolen; i++) {
            destConfig->groupInfo[i] = srcConfig->groupInfo[i];
            destConfig->groupInfo[i].name =
                BSL_SAL_Dump(srcConfig->groupInfo[i].name, strlen(srcConfig->groupInfo[i].name) + 1);
            if (destConfig->groupInfo[i].name == NULL) {
                return HITLS_MEMALLOC_FAIL;
            }
            destConfig->groupInfolen++;
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
        BSL_SAL_FREE(destConfig->sigSchemeInfo);
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
#ifdef HITLS_TLS_FEATURE_SESSION
static int32_t SessMgrDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    destConfig->sessMgr = SESSMGR_Dup(srcConfig->sessMgr);
    if (destConfig->sessMgr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16593, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "MGR_Dup fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionTimeout(HITLS_Config *config, uint64_t timeout)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetTimeout(config->sessMgr, timeout);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTimeout(const HITLS_Config *config, uint64_t *timeout)
{
    if (config == NULL || config->sessMgr == NULL || timeout == NULL) {
        return HITLS_NULL_INPUT;
    }

    *timeout = SESSMGR_GetTimeout(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetNewSessionCb(HITLS_Config *config, const HITLS_NewSessionCb newSessionCb)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->newSessionCb = newSessionCb;
    return HITLS_SUCCESS;
}
#endif

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

static int32_t BasicConfigDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    int32_t ret = HITLS_SUCCESS;
    (void)destConfig;
    (void)srcConfig;
#ifdef HITLS_TLS_FEATURE_SESSION_ID
    ret = SessionIdCtxCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
    ret = CertMgrDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    ret = SessMgrDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_TLS_FEATURE_ALPN
    ret = AlpnListDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_TLS_FEATURE_SNI
    ret = ServerNameDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
    ret = CryptKeyDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    destConfig->customExts = DupCustomExtensions(srcConfig->customExts);
    if (srcConfig->customExts != NULL && destConfig->customExts == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
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

#ifdef HITLS_TLS_PROTO_DTLS12
HITLS_Config *HITLS_CFG_NewDTLS12Config(void)
{
    return HITLS_CFG_ProviderNewDTLS12Config(NULL, NULL);
}

HITLS_Config *HITLS_CFG_ProviderNewDTLS12Config(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    HITLS_Config *newConfig = CreateConfig();
    if (newConfig == NULL) {
        return NULL;
    }
    newConfig->version |= DTLS12_VERSION_BIT;   // Enable DTLS 1.2
    if (DefaultConfig(libCtx, attrName, HITLS_VERSION_DTLS12, newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

#endif

#ifdef HITLS_TLS_PROTO_DTLCP11
HITLS_Config *HITLS_CFG_NewDTLCPConfig(void)
{
    return HITLS_CFG_ProviderNewDTLCPConfig(NULL, NULL);
}

HITLS_Config *HITLS_CFG_ProviderNewDTLCPConfig(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    HITLS_Config *newConfig = CreateConfig();
    if (newConfig == NULL) {
        return NULL;
    }

    newConfig->version |= DTLCP11_VERSION_BIT;   // Enable DTLCP 1.1
    if (DefaultConfig(libCtx, attrName, HITLS_VERSION_TLCP_DTLCP11, newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

#endif

#ifdef HITLS_TLS_PROTO_TLCP11
HITLS_Config *HITLS_CFG_NewTLCPConfig(void)
{
    return HITLS_CFG_ProviderNewTLCPConfig(NULL, NULL);
}

HITLS_Config *HITLS_CFG_ProviderNewTLCPConfig(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    HITLS_Config *newConfig = CreateConfig();
    if (newConfig == NULL) {
        return NULL;
    }
    newConfig->version |= TLCP11_VERSION_BIT;   // Enable TLCP 1.1
    if (DefaultConfig(libCtx, attrName, HITLS_VERSION_TLCP_DTLCP11, newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}
#endif

#ifdef HITLS_TLS_PROTO_TLS12
HITLS_Config *HITLS_CFG_NewTLS12Config(void)
{
    return HITLS_CFG_ProviderNewTLS12Config(NULL, NULL);
}

HITLS_Config *HITLS_CFG_ProviderNewTLS12Config(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    HITLS_Config *newConfig = CreateConfig();
    if (newConfig == NULL) {
        return NULL;
    }
    /* Initialize the version */
    newConfig->version |= TLS12_VERSION_BIT;   // Enable TLS 1.2
    if (DefaultConfig(libCtx, attrName, HITLS_VERSION_TLS12, newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}
#endif

#ifdef HITLS_TLS_PROTO_ALL
HITLS_Config *HITLS_CFG_NewTLSConfig(void)
{
    return HITLS_CFG_ProviderNewTLSConfig(NULL, NULL);
}

HITLS_Config *HITLS_CFG_ProviderNewTLSConfig(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    HITLS_Config *newConfig = CreateConfig();
    if (newConfig == NULL) {
        return NULL;
    }
    newConfig->version |= TLS_VERSION_MASK;

    newConfig->libCtx = libCtx;
    newConfig->attrName = attrName;

    if (DefaultTlsAllConfig(newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}
#endif
#ifdef HITLS_TLS_PROTO_DTLS
HITLS_Config *HITLS_CFG_NewDTLSConfig(void)
{
    return HITLS_CFG_ProviderNewDTLSConfig(NULL, NULL);
}

HITLS_Config *HITLS_CFG_ProviderNewDTLSConfig(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    HITLS_Config *newConfig = CreateConfig();
    if (newConfig == NULL) {
        return NULL;
    }
    newConfig->version |= DTLS_VERSION_MASK;      // Enable All Versions

    newConfig->libCtx = libCtx;
    newConfig->attrName = attrName;

    if (DefaultDtlsAllConfig(newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

#endif

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

    return;
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

#ifdef HITLS_TLS_PROTO_ALL
static int ChangeVersionMask(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    uint32_t originVersionMask = config->originVersionMask;
    uint32_t versionMask = 0;
    uint32_t versionBit = 0;

    /* Creating a DTLS version but setting a TLS version is invalid. */
    if (originVersionMask == DTLS_VERSION_MASK) {
        if (IS_DTLS_VERSION(minVersion) == 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16596, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Config min version [0x%x] err.", minVersion, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
            return HITLS_CONFIG_INVALID_VERSION;
        }
    }

    if (originVersionMask == TLS_VERSION_MASK) {
        /* Creating a TLS version but setting a DTLS version is invalid. */
        if (IS_DTLS_VERSION(minVersion)) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16597, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "minVersion err", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
            return HITLS_CONFIG_INVALID_VERSION;
        }

        for (uint16_t version = minVersion; version <= maxVersion; version++) {
            versionBit = MapVersion2VersionBit(IS_SUPPORT_DATAGRAM(originVersionMask), version);
            versionMask |= versionBit;
        }

        if ((versionMask & originVersionMask) == 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16598, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Config version err", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
            return HITLS_CONFIG_INVALID_VERSION;
        }

        config->version = versionMask;
        return HITLS_SUCCESS;
    }

    return HITLS_SUCCESS;
}

static int32_t CheckVersionValid(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
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
    if (*tmpMinVersion == 0) {
        if (config->originVersionMask == DTLS_VERSION_MASK) {
            *tmpMinVersion = HITLS_VERSION_DTLS12;
        } else {
            *tmpMinVersion = HITLS_VERSION_TLS12;
        }
    } else if (*tmpMaxVersion == 0) {
        if (config->originVersionMask == DTLS_VERSION_MASK) {
            *tmpMaxVersion = HITLS_VERSION_DTLS12;
        } else {
            *tmpMaxVersion = HITLS_VERSION_TLS13;
        }
    }
    return;
}
#endif

int32_t HITLS_CFG_SetVersion(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret = 0;
#ifdef HITLS_TLS_PROTO_ALL
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

    config->minVersion = 0;
    config->maxVersion = 0;

    /* If both the latest version and the earliest version supported are 0, clear the versionMask. */
    if (minVersion == maxVersion && minVersion == 0) {
        config->version = 0;
        return HITLS_SUCCESS;
    }
#endif
    uint16_t tmpMinVersion = minVersion;
    uint16_t tmpMaxVersion = maxVersion;
#ifdef HITLS_TLS_PROTO_ALL
    ChangeTmpVersion(config, &tmpMinVersion, &tmpMaxVersion);
#endif
    ret = CheckVersion(tmpMinVersion, tmpMaxVersion);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_PROTO_ALL
    /* In invalid cases, both maxVersion and minVersion are 0 */
    if (ChangeVersionMask(config, tmpMinVersion, tmpMaxVersion) == HITLS_SUCCESS) {
#endif
        config->minVersion = tmpMinVersion;
        config->maxVersion = tmpMaxVersion;
#ifdef HITLS_TLS_PROTO_ALL
    }
#endif
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_ALL
int32_t HITLS_CFG_SetVersionForbid(HITLS_Config *config, uint32_t noVersion)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    // Now only DTLS1.2 is supported, so single version is not supported (disable to version 0)
    if ((config->originVersionMask & TLS_VERSION_MASK) == TLS_VERSION_MASK) {
        uint32_t noVersionBit = MapVersion2VersionBit(IS_SUPPORT_DATAGRAM(config->originVersionMask), noVersion);
        if ((config->version & (~noVersionBit)) == 0) {
            return HITLS_SUCCESS; // Not all is disabled but the return value is SUCCESS
        }
        config->version &= ~noVersionBit;
        uint32_t versionBits[] = {
            TLS12_VERSION_BIT, TLS13_VERSION_BIT};
        uint16_t versions[] = {
            HITLS_VERSION_TLS12, HITLS_VERSION_TLS13};
        uint32_t versionBitsSize = sizeof(versionBits) / sizeof(uint32_t);
        for (uint32_t i = 0; i < versionBitsSize; i++) {
            if ((config->version & versionBits[i]) == versionBits[i]) {
                config->minVersion = versions[i];
                break;
            }
        }
        for (int i = (int)versionBitsSize - 1; i >= 0; i--) {
            if ((config->version & versionBits[i]) == versionBits[i]) {
                config->maxVersion = versions[i];
                break;
            }
        }
    }
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
        if (cipherSuites[i] >= HITLS_AES_128_GCM_SHA256 && cipherSuites[i] <= HITLS_AES_128_CCM_8_SHA256) {
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
        if (cipherSuites[i] >= HITLS_AES_128_GCM_SHA256 && cipherSuites[i] <= HITLS_AES_128_CCM_8_SHA256) {
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

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t HITLS_CFG_SetCookieGenCb(HITLS_Config *config, HITLS_AppGenCookieCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->appGenCookieCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetCookieVerifyCb(HITLS_Config *config, HITLS_AppVerifyCookieCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->appVerifyCookieCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetDtlsTimerCb(HITLS_Config *config, HITLS_DtlsTimerCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->dtlsTimerCb = callback;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_FEATURE_SNI
int32_t HITLS_CFG_SetClientHelloCb(HITLS_Config *config, HITLS_ClientHelloCb callback, void *arg)
{
    if (config == NULL || callback == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->clientHelloCb = callback;
    config->clientHelloCbArg = arg;
    return HITLS_SUCCESS;
}
#endif

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

#ifdef HITLS_TLS_FEATURE_MODE
int32_t HITLS_CFG_SetModeSupport(HITLS_Config *config, uint32_t mode)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->modeSupport |= mode;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_ClearModeSupport(HITLS_Config *config, uint32_t mode)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->modeSupport &= (~mode);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetModeSupport(const HITLS_Config *config, uint32_t *mode)
{
    if (config == NULL || mode == NULL) {
        return HITLS_NULL_INPUT;
    }

    *mode = config->modeSupport;
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

#ifdef HITLS_TLS_CONFIG_CERT
int32_t HITLS_CFG_SetMaxCertList(HITLS_Config *config, uint32_t maxSize)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->maxCertList = maxSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetMaxCertList(const HITLS_Config *config, uint32_t *maxSize)
{
    if (config == NULL || maxSize == NULL) {
        return HITLS_NULL_INPUT;
    }

    *maxSize = config->maxCertList;
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
#ifdef HITLS_TLS_FEATURE_SNI
int32_t HITLS_CFG_SetServerName(HITLS_Config *config, uint8_t *serverName, uint32_t serverNameStrlen)
{
    if ((config == NULL) || (serverName == NULL) || (serverNameStrlen == 0)) {
        return HITLS_NULL_INPUT;
    }

    if (serverNameStrlen > HITLS_CFG_MAX_SIZE) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }
    uint32_t serverNameSize = serverNameStrlen;
    if (serverName[serverNameStrlen - 1] != '\0') {
        serverNameSize += 1;
    }
    uint8_t *newData = (uint8_t *) BSL_SAL_Malloc(serverNameSize * sizeof(uint8_t));
    if (newData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16606, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(newData, serverNameSize, serverName, serverNameStrlen);
    newData[serverNameSize - 1] = '\0';

    BSL_SAL_FREE(config->serverName);
    config->serverName = newData;
    config->serverNameSize = serverNameSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerName(HITLS_Config *config, uint8_t **serverName, uint32_t *serverNameStrlen)
{
    if (config == NULL || serverName == NULL || serverNameStrlen == NULL) {
        return HITLS_NULL_INPUT;
    }

    *serverName = config->serverName;
    *serverNameStrlen =  config->serverNameSize;

    return HITLS_SUCCESS;
}
int32_t HITLS_CFG_SetServerNameCb(HITLS_Config *config, HITLS_SniDealCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->sniDealCb = callback;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetServerNameArg(HITLS_Config *config, void *arg)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->sniArg = arg;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerNameCb(HITLS_Config *config, HITLS_SniDealCb *callback)
{
    if (config == NULL || callback == NULL) {
        return HITLS_NULL_INPUT;
    }

    *callback = config->sniDealCb;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerNameArg(HITLS_Config *config, void **arg)
{
    if (config == NULL || arg == NULL) {
        return HITLS_NULL_INPUT;
    }

    *arg = config->sniArg;

    return HITLS_SUCCESS;
}
#endif

int32_t HITLS_CFG_SetRenegotiationSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportRenegotiation = support;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_CFG_SetClientRenegotiateSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->allowClientRenegotiate = support;
    return HITLS_SUCCESS;
}
#endif
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
#if defined(HITLS_TLS_FEATURE_RENEGOTIATION) && defined(HITLS_TLS_FEATURE_SESSION)
int32_t HITLS_CFG_SetResumptionOnRenegoSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isResumptionOnRenego = support;
    return HITLS_SUCCESS;
}
#endif

int32_t HITLS_CFG_SetExtenedMasterSecretSupport(HITLS_Config *config, bool support)
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

    if (hintSize > HITLS_IDENTITY_HINT_MAX_SIZE) {
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
#ifdef HITLS_TLS_FEATURE_PSK
// Configure clientCb, which is used to obtain the PSK through identity hints
int32_t HITLS_CFG_SetPskClientCallback(HITLS_Config *config, HITLS_PskClientCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->pskClientCb = callback;
    return HITLS_SUCCESS;
}

// Set serverCb to obtain the PSK through identity.
int32_t HITLS_CFG_SetPskServerCallback(HITLS_Config *config, HITLS_PskServerCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->pskServerCb = callback;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
int32_t HITLS_CFG_SetSessionTicketSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isSupportSessionTicket = support;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_CFG_GetRenegotiationSupport(const HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportRenegotiation;
    return HITLS_SUCCESS;
}
#endif

int32_t HITLS_CFG_GetExtenedMasterSecretSupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportExtendMasterSecret;
    return HITLS_SUCCESS;
}

#if defined(HITLS_TLS_FEATURE_SESSION_TICKET)
int32_t HITLS_CFG_GetSessionTicketSupport(const HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportSessionTicket;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetTicketKeyCallback(HITLS_Config *config, HITLS_TicketKeyCb callback)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetTicketKeyCb(config->sessMgr, callback);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTicketKey(const HITLS_Config *config, uint8_t *key, uint32_t keySize, uint32_t *outSize)
{
    if (config == NULL || config->sessMgr == NULL || key == NULL || outSize == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SESSMGR_GetTicketKey(config->sessMgr, key, keySize, outSize);
}

int32_t HITLS_CFG_SetSessionTicketKey(HITLS_Config *config, const uint8_t *key, uint32_t keySize)
{
    if (config == NULL || config->sessMgr == NULL || key == NULL ||
        (keySize != HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_KEY_SIZE + HITLS_TICKET_KEY_SIZE)) {
        return HITLS_NULL_INPUT;
    }

    return SESSMGR_SetTicketKey(config->sessMgr, key, keySize);
}
#endif

#if defined(HITLS_TLS_FEATURE_CERT_MODE) && defined(HITLS_TLS_FEATURE_RENEGOTIATION)
int32_t HITLS_CFG_SetClientOnceVerifySupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportClientOnceVerify = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetClientOnceVerifySupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportClientOnceVerify;
    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_PROTO_ALL
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

#ifdef HITLS_TLS_FEATURE_ALPN
static int32_t AlpnListValidationCheck(const uint8_t *alpnList, uint32_t alpnProtosLen)
{
    uint32_t index = 0u;

    while (index < alpnProtosLen) {
        if (alpnList[index] == 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16608, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "alpnList null", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
            return HITLS_CONFIG_INVALID_LENGTH;
        }
        index += (alpnList[index] + 1);
    }

    if (index != alpnProtosLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16609, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "alpnProtosLen err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetAlpnProtos(HITLS_Config *config, const uint8_t *alpnProtos, uint32_t alpnProtosLen)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    /* If the input parameter is empty or the length is 0, clear the original alpn list */
    if (alpnProtosLen == 0 || alpnProtos == NULL) {
        BSL_SAL_FREE(config->alpnList);
        config->alpnListSize = 0;
        return HITLS_SUCCESS;
    }

    /* Add the check on alpnList. The expected format is |protoLen1|proto1|protoLen2|proto2|...| */
    if (AlpnListValidationCheck(alpnProtos, alpnProtosLen) != HITLS_SUCCESS) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *alpnListTmp = (uint8_t *)BSL_SAL_Calloc(alpnProtosLen + 1, sizeof(uint8_t));
    if (alpnListTmp == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16610, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    (void)memcpy_s(alpnListTmp, alpnProtosLen + 1, alpnProtos, alpnProtosLen);

    BSL_SAL_FREE(config->alpnList);
    config->alpnList = alpnListTmp;
    /* Ignore ending 0s */
    config->alpnListSize = alpnProtosLen;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetAlpnProtosSelectCb(HITLS_Config *config, HITLS_AlpnSelectCb callback, void *userData)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->alpnSelectCb = callback;
    config->alpnUserData = userData;

    return HITLS_SUCCESS;
}

int32_t HITLS_SelectAlpnProtocol(uint8_t **out, uint8_t *outLen, const uint8_t *servAlpnList, uint32_t servAlpnListLen,
    const uint8_t *clientAlpnList, uint32_t clientAlpnListLen)
{
     bool nullInput = out == NULL || outLen == NULL || clientAlpnList == NULL || servAlpnList == NULL ||
        servAlpnListLen == 0 || clientAlpnListLen == 0;
    if (nullInput == true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16690, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "intput null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    /* Add the check on alpnList. The expected format is |protoLen1|proto1|protoLen2|proto2|...| */
    if (AlpnListValidationCheck(servAlpnList, servAlpnListLen) != HITLS_SUCCESS ||
        AlpnListValidationCheck(clientAlpnList, clientAlpnListLen) != HITLS_SUCCESS) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    for (uint32_t i = 0; i < servAlpnListLen;) {
        for (uint32_t j = 0; j < clientAlpnListLen;) {
            if (servAlpnList[i] == clientAlpnList[j] &&
                (memcmp(&servAlpnList[i + 1], &clientAlpnList[j + 1], servAlpnList[i]) == 0)) {
                *out = (uint8_t *)(uintptr_t)&servAlpnList[i + 1];
                *outLen = servAlpnList[i];
                return HITLS_SUCCESS;
            }
            j = j + clientAlpnList[j];
            ++j;
        }
        i = i + servAlpnList[i];
        ++i;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ALPN */
#if defined(HITLS_TLS_FEATURE_SESSION_ID)
int32_t HITLS_CFG_SetSessionIdCtx(HITLS_Config *config, const uint8_t *sessionIdCtx, uint32_t len)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (len != 0 && memcpy_s(config->sessionIdCtx, sizeof(config->sessionIdCtx), sessionIdCtx, len) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    /* The allowed value is 0 */
    config->sessionIdCtxSize = len;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_FEATURE_SESSION
int32_t HITLS_CFG_SetSessionCacheMode(HITLS_Config *config, HITLS_SESS_CACHE_MODE mode)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetCacheMode(config->sessMgr, mode);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionCacheMode(HITLS_Config *config, HITLS_SESS_CACHE_MODE *mode)
{
    if (config == NULL || config->sessMgr == NULL || mode == NULL) {
        return HITLS_NULL_INPUT;
    }

    *mode = SESSMGR_GetCacheMode(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionCacheSize(HITLS_Config *config, uint32_t size)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetCacheSize(config->sessMgr, size);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionCacheSize(HITLS_Config *config, uint32_t *size)
{
    if (config == NULL || config->sessMgr == NULL || size == NULL) {
        return HITLS_NULL_INPUT;
    }

    *size = SESSMGR_GetCacheSize(config->sessMgr);
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_PROTO_ALL
int32_t HITLS_CFG_GetVersionSupport(const HITLS_Config *config, uint32_t *version)
{
    if ((config == NULL) || (version == NULL)) {
        return HITLS_NULL_INPUT;
    }

    *version = config->version;
    return HITLS_SUCCESS;
}

static void ChangeSupportVersion(HITLS_Config *config)
{
    uint32_t versionMask = config->version;
    uint32_t originVersionMask = config->originVersionMask;

    config->maxVersion = 0;
    config->minVersion = 0;
    /* The original supported version is disabled. This is abnormal and packets cannot be sent */
    if ((versionMask & originVersionMask) == 0) {
        return;
    }

    /* Currently, only DTLS1.2 is supported. DTLS1.0 is not supported */
    if ((versionMask & DTLS12_VERSION_BIT) == DTLS12_VERSION_BIT) {
        config->maxVersion = HITLS_VERSION_DTLS12;
        config->minVersion = HITLS_VERSION_DTLS12;
        return;
    }

    /* Description TLS_ANY_VERSION */
    uint32_t versionBits[] = {TLS12_VERSION_BIT, TLS13_VERSION_BIT};
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_TLS13};

    uint32_t versionBitsSize = sizeof(versionBits) / sizeof(uint32_t);
    for (uint32_t i = 0; i < versionBitsSize; i++) {
        if ((versionMask & versionBits[i]) == versionBits[i]) {
            config->maxVersion = versions[i];
            if (config->minVersion == 0) {
                config->minVersion = versions[i];
            }
        }
    }
}

int32_t HITLS_CFG_SetVersionSupport(HITLS_Config *config, uint32_t version)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    if ((version & SSLV3_VERSION_BIT) == SSLV3_VERSION_BIT) {
        return HITLS_CONFIG_INVALID_VERSION;
    }

    config->version = version;
    /* Update the maximum supported version */
    ChangeSupportVersion(config);
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

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t HITLS_CFG_SetDtlsPostHsTimeoutVal(HITLS_Config *config, uint32_t timeoutVal)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->dtlsPostHsTimeoutVal = timeoutVal;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
int32_t HITLS_CFG_SetEncryptThenMac(HITLS_Config *config, bool encryptThenMacType)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isEncryptThenMac = encryptThenMacType;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetEncryptThenMac(const HITLS_Config *config, bool *encryptThenMacType)
{
    if (config == NULL || encryptThenMacType == NULL) {
        return HITLS_NULL_INPUT;
    }

    *encryptThenMacType = config->isEncryptThenMac;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_PROTO_DTLS
int32_t HITLS_CFG_IsDtls(const HITLS_Config *config, bool *isDtls)
{
    if (config == NULL || isDtls == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isDtls = ((config->originVersionMask & DTLS12_VERSION_BIT) != 0);
    return HITLS_SUCCESS;
}
#endif
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
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
int32_t HITLS_CFG_SetTicketNums(HITLS_Config *config, uint32_t ticketNums)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->ticketNums = ticketNums;
    return HITLS_SUCCESS;
}

uint32_t HITLS_CFG_GetTicketNums(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return config->ticketNums;
}
#endif
#ifdef HITLS_TLS_FEATURE_FLIGHT
int32_t HITLS_CFG_SetFlightTransmitSwitch(HITLS_Config *config, bool isEnable)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isFlightTransmitEnable = isEnable;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetFlightTransmitSwitch(const HITLS_Config *config, bool *isEnable)
{
    if (config == NULL || isEnable == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isEnable = config->isFlightTransmitEnable;
    return HITLS_SUCCESS;
}
#endif

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t HITLS_CFG_SetDtlsCookieExchangeSupport(HITLS_Config *config, bool isSupport)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isSupportDtlsCookieExchange = isSupport;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetDtlsCookieExchangeSupport(const HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportDtlsCookieExchange;
    return HITLS_SUCCESS;
}
#endif
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
