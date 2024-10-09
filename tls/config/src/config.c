/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "hitls_type.h"
#include "hitls_error.h"
#include "hitls_psk.h"
#include "hitls_alpn.h"
#include "hitls_cert_type.h"
#include "hitls_sni.h"
#include "tls.h"
#include "cert.h"
#include "crypt.h"
#include "session_mgr.h"
#include "config_check.h"
#include "config_default.h"
#include "bsl_list.h"

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

void CFG_CleanConfig(HITLS_Config *config)
{
    BSL_SAL_FREE(config->cipherSuites);
    BSL_SAL_FREE(config->tls13CipherSuites);
    BSL_SAL_FREE(config->pointFormats);
    BSL_SAL_FREE(config->groups);
    BSL_SAL_FREE(config->signAlgorithms);
    BSL_SAL_FREE(config->pskIdentityHint);
    BSL_SAL_FREE(config->alpnList);
    BSL_SAL_FREE(config->serverName);
    BSL_LIST_FREE(config->caList, HitlsTrustedCANodeFree);
    SAL_CRYPT_FreeDhKey(config->dhTmp);
    SAL_CRYPT_FreeEcdhKey(config->ecdhTmp);
    SESSMGR_Free(config->sessMgr);
    config->sessMgr = NULL;
    SAL_CERT_MgrCtxFree(config->certMgrCtx);
    config->certMgrCtx = NULL;
    BSL_SAL_ReferencesFree(&(config->references));
    return;
}


static void ShallowCopy(HITLS_Ctx *ctx, const HITLS_Config *srcConfig)
{
    HITLS_Config *destConfig = &ctx->config.tlsConfig;

    /**
     * Other parameters except CipherSuite, PointFormats, Group, SignAlgorithms, Psk, SessionId, CertMgr, and SessMgr
     * are shallowly copied, and some of them reference globalConfig.
     */
    destConfig->minVersion = srcConfig->minVersion;
    destConfig->maxVersion = srcConfig->maxVersion;
    destConfig->version = srcConfig->version;
    destConfig->originVersionMask = srcConfig->originVersionMask;
    destConfig->isSupportRenegotiation = srcConfig->isSupportRenegotiation;
    destConfig->needCheckPmsVersion = srcConfig->needCheckPmsVersion;
    destConfig->needCheckKeyUsage = srcConfig->needCheckKeyUsage;
    destConfig->isResumptionOnRenego = srcConfig->isResumptionOnRenego;
    destConfig->isSupportClientVerify = srcConfig->isSupportClientVerify;
    destConfig->isSupportExtendMasterSecret = srcConfig->isSupportExtendMasterSecret;
    destConfig->isSupportDhAuto = srcConfig->isSupportDhAuto;
    destConfig->isSupportSessionTicket = srcConfig->isSupportSessionTicket;
    destConfig->isSupportNoClientCert = srcConfig->isSupportNoClientCert;
    destConfig->isSupportVerifyNone = srcConfig->isSupportVerifyNone;
    destConfig->isSupportClientOnceVerify = srcConfig->isSupportClientOnceVerify;
    destConfig->isSupportPostHandshakeAuth = srcConfig->isSupportPostHandshakeAuth;
    destConfig->pskClientCb = srcConfig->pskClientCb;
    destConfig->pskServerCb = srcConfig->pskServerCb;
    destConfig->userData = srcConfig->userData;
    destConfig->userDataFreeCb = srcConfig->userDataFreeCb;
    destConfig->keyExchMode = srcConfig->keyExchMode;
    destConfig->infoCb = srcConfig->infoCb;
    destConfig->msgCb = srcConfig->msgCb;
    destConfig->msgArg = srcConfig->msgArg;
    destConfig->noSecRenegotiationCb = srcConfig->noSecRenegotiationCb;
    destConfig->isQuietShutdown = srcConfig->isQuietShutdown;
    destConfig->securityCb = srcConfig->securityCb;
    destConfig->securityExData = srcConfig->securityExData;
    destConfig->securityLevel = srcConfig->securityLevel;
    destConfig->isEncryptThenMac = srcConfig->isEncryptThenMac;
    destConfig->pskFindSessionCb = srcConfig->pskFindSessionCb;
    destConfig->pskUseSessionCb = srcConfig->pskUseSessionCb;
    destConfig->isSupportServerPreference = srcConfig->isSupportServerPreference;
    destConfig->ticketNums = srcConfig->ticketNums;
    destConfig->isFlightTransmitEnable = srcConfig->isFlightTransmitEnable;
    destConfig->maxCertList = srcConfig->maxCertList;
    destConfig->recordPaddingCb = srcConfig->recordPaddingCb;
}

static int32_t PointFormatsCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->pointFormats != NULL) {
        destConfig->pointFormats = BSL_SAL_Dump(srcConfig->pointFormats, srcConfig->pointFormatsSize * sizeof(uint8_t));
        if (destConfig->pointFormats == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->pointFormatsSize = srcConfig->pointFormatsSize;
    }
    return HITLS_SUCCESS;
}

static int32_t GroupCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->groups != NULL) {
        destConfig->groups = BSL_SAL_Dump(srcConfig->groups, srcConfig->groupsSize * sizeof(uint16_t));
        if (destConfig->groups == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->groupsSize = srcConfig->groupsSize;
    }
    return HITLS_SUCCESS;
}

static int32_t PskCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->pskIdentityHint != NULL) {
        destConfig->pskIdentityHint = BSL_SAL_Dump(srcConfig->pskIdentityHint, srcConfig->hintSize * sizeof(uint8_t));
        if (destConfig->pskIdentityHint == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->hintSize = srcConfig->hintSize;
    }
    return HITLS_SUCCESS;
}

static int32_t SignAlgorithmsCfgDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->signAlgorithms != NULL) {
        destConfig->signAlgorithms = BSL_SAL_Dump(srcConfig->signAlgorithms,
            srcConfig->signAlgorithmsSize * sizeof(uint16_t));
        if (destConfig->signAlgorithms == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->signAlgorithmsSize = srcConfig->signAlgorithmsSize;
    }
    return HITLS_SUCCESS;
}

static int32_t AlpnListDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->alpnListSize == 0 || srcConfig->alpnList == NULL) {
        return HITLS_SUCCESS;
    }
    destConfig->alpnList = BSL_SAL_Dump(srcConfig->alpnList, (srcConfig->alpnListSize + 1) * sizeof(uint8_t));
    if (destConfig->alpnList == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    destConfig->alpnListSize = srcConfig->alpnListSize;
    return HITLS_SUCCESS;
}

static int32_t ServerNameDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->serverNameSize == 0 || srcConfig->serverName == NULL) {
        return HITLS_SUCCESS;
    }

    destConfig->serverName = BSL_SAL_Dump(srcConfig->serverName, srcConfig->serverNameSize * sizeof(uint8_t));
    if (destConfig->serverName == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    destConfig->serverNameSize = srcConfig->serverNameSize;

    return HITLS_SUCCESS;
}

static int32_t CipherSuiteDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->cipherSuites != NULL) {
        destConfig->cipherSuites = BSL_SAL_Dump(srcConfig->cipherSuites, srcConfig->cipherSuitesSize *
            sizeof(uint16_t));
        if (destConfig->cipherSuites == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->cipherSuitesSize = srcConfig->cipherSuitesSize;
    }

    if (srcConfig->tls13CipherSuites != NULL) {
        destConfig->tls13CipherSuites = BSL_SAL_Dump(srcConfig->tls13CipherSuites,
            srcConfig->tls13cipherSuitesSize * sizeof(uint16_t));
        if (destConfig->tls13CipherSuites == NULL) {
            BSL_SAL_FREE(destConfig->cipherSuites);
            return HITLS_MEMALLOC_FAIL;
        }
        destConfig->tls13cipherSuitesSize = srcConfig->tls13cipherSuitesSize;
    }
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

static int32_t SessionIdCtxCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->sessionIdCtxSize != 0 &&
        memcpy_s(destConfig->sessionIdCtx, sizeof(destConfig->sessionIdCtx),
        srcConfig->sessionIdCtx, srcConfig->sessionIdCtxSize) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    destConfig->sessionIdCtxSize = srcConfig->sessionIdCtxSize;
    return HITLS_SUCCESS;
}

static int32_t SessMgrDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    destConfig->sessMgr = SESSMGR_Dup(srcConfig->sessMgr);
    if (destConfig->sessMgr == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t CryptKeyDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    if (srcConfig->dhTmp != NULL) {
        destConfig->dhTmp = SAL_CRYPT_DupDhKey(srcConfig->dhTmp);
        if (destConfig->dhTmp == NULL) {
            return HITLS_CONFIG_DUP_DH_KEY_FAIL;
        }
    }

    if (srcConfig->ecdhTmp != NULL) {
        destConfig->ecdhTmp = SAL_CRYPT_DupEcdhKey(srcConfig->ecdhTmp);
        if (destConfig->ecdhTmp == NULL) {
            return HITLS_CONFIG_DUP_ECDH_KEY_FAIL;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t BasicConfigDeepCopy(HITLS_Config *destConfig, const HITLS_Config *srcConfig)
{
    int32_t ret = AlpnListDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ServerNameDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = CryptKeyDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t CFG_DumpConfig(HITLS_Ctx *ctx, const HITLS_Config *srcConfig)
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

    ret = PskCfgDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = SessionIdCtxCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = CertMgrDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = SessMgrDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = BasicConfigDeepCopy(destConfig, srcConfig);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    return HITLS_SUCCESS;
EXIT:
    CFG_CleanConfig(destConfig);
    return ret;
}

HITLS_Config *HITLS_CFG_NewDTLS12Config(void)
{
    HITLS_Config *newConfig = BSL_SAL_Calloc(1u, sizeof(HITLS_Config));
    if (newConfig == NULL) {
        return NULL;
    }

    if (BSL_SAL_ReferencesInit(&(newConfig->references)) != BSL_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    /* Initialize the version */
    newConfig->version |= DTLS12_VERSION_BIT;   // Enable DTLS 1.2
    if (DefaultConfig(HITLS_VERSION_DTLS12, newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

#ifndef HITLS_NO_TLCP11
HITLS_Config *HITLS_CFG_NewTLCPConfig(void)
{
    HITLS_Config *newConfig = BSL_SAL_Calloc(1u, sizeof(HITLS_Config));
    if (newConfig == NULL) {
        return NULL;
    }

    if (BSL_SAL_ReferencesInit(&(newConfig->references)) != BSL_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    if (DefaultConfig(HITLS_VERSION_TLCP11, newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    return newConfig;
}
#endif

HITLS_Config *HITLS_CFG_NewTLS12Config(void)
{
    HITLS_Config *newConfig = BSL_SAL_Calloc(1u, sizeof(HITLS_Config));
    if (newConfig == NULL) {
        return NULL;
    }

    if (BSL_SAL_ReferencesInit(&(newConfig->references)) != BSL_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    /* Initialize the version */
    newConfig->version |= TLS12_VERSION_BIT;   // Enable TLS 1.2
    if (DefaultConfig(HITLS_VERSION_TLS12, newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

HITLS_Config *HITLS_CFG_NewTLS13Config(void)
{
    HITLS_Config *newConfig = BSL_SAL_Calloc(1u, sizeof(HITLS_Config));
    if (newConfig == NULL) {
        return NULL;
    }

    if (BSL_SAL_ReferencesInit(&(newConfig->references)) != BSL_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    /* Initialize the version */
    newConfig->version |= TLS13_VERSION_BIT;  // Enable TLS1.3
    if (DefaultTLS13Config(newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

HITLS_Config *HITLS_CFG_NewTLSConfig(void)
{
    HITLS_Config *newConfig = BSL_SAL_Calloc(1u, sizeof(HITLS_Config));
    if (newConfig == NULL) {
        return NULL;
    }

    if (BSL_SAL_ReferencesInit(&(newConfig->references)) != BSL_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    /* Initialize the version */
    newConfig->version |= TLS_VERSION_MASK;       // Enable All Versions
    if (DefaultTlsAllConfig(newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

HITLS_Config *HITLS_CFG_NewDTLSConfig(void)
{
    HITLS_Config *newConfig = BSL_SAL_Calloc(1u, sizeof(HITLS_Config));
    if (newConfig == NULL) {
        return NULL;
    }

    if (BSL_SAL_ReferencesInit(&(newConfig->references)) != BSL_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }

    /* Initialize the version */
    newConfig->version |= DTLS_VERSION_MASK;      // Enable All Versions
    if (DefaultDtlsAllConfig(newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

void HITLS_CFG_FreeConfig(HITLS_Config *config)
{
    if (config == NULL) {
        return;
    }
    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(config->references), &ret);
    if (ret > 0) {
        return;
    }

    CFG_CleanConfig(config);
    if (config->userData != NULL && config->userDataFreeCb != NULL) {
        (void)config->userDataFreeCb(config->userData);
        config->userData = NULL;
    }
    BSL_SAL_FREE(config);

    return;
}

int32_t HITLS_CFG_UpRef(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    int ret = 0;
    BSL_SAL_AtomicUpReferences(&(config->references), &ret);
    (void)ret;

    return HITLS_SUCCESS;
}

static uint32_t MapVersion2VersionBit(uint32_t version)
{
    uint32_t ret = 0;
    switch (version) {
        case HITLS_VERSION_TLS12:
            ret = TLS12_VERSION_BIT;
            break;
        case HITLS_VERSION_TLS13:
            ret = TLS13_VERSION_BIT;
            break;
        default:
            break;
    }
    return ret;
}

static int ChangeVersionMask(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    uint32_t originVersionMask = config->originVersionMask;
    uint32_t versionMask = 0;
    uint32_t versionBit = 0;

    /* Creating a DTLS version but setting a TLS version is invalid. */
    if (originVersionMask == DTLS_VERSION_MASK) {
        if (IS_DTLS_VERSION(minVersion) == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
            return HITLS_CONFIG_INVALID_VERSION;
        }
    }

    if (originVersionMask == TLS_VERSION_MASK) {
        /* Creating a TLS version but setting a DTLS version is invalid. */
        if (IS_DTLS_VERSION(minVersion)) {
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
            return HITLS_CONFIG_INVALID_VERSION;
        }

        for (uint16_t version = minVersion; version <= maxVersion; version++) {
            versionBit = MapVersion2VersionBit(version);
            versionMask |= versionBit;
        }

        if ((versionMask & originVersionMask) == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
            return HITLS_CONFIG_INVALID_VERSION;
        }

        config->version = versionMask;
        return HITLS_SUCCESS;
    }

    return HITLS_SUCCESS;
}

static int32_t CheckVersionValid(const HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    if ((minVersion < HITLS_VERSION_SSL30 && minVersion != 0) ||
        (minVersion == HITLS_VERSION_SSL30 && config->minVersion != HITLS_VERSION_SSL30) ||
        (maxVersion <= HITLS_VERSION_SSL30 && maxVersion != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
        return HITLS_CONFIG_INVALID_VERSION;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetVersion(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (config->minVersion == minVersion && config->maxVersion == maxVersion && minVersion != 0 && maxVersion != 0) {
        return HITLS_SUCCESS;
    }

    /* TLCP cannot be supported by setting the version number. They can be
     * initialized only by using the corresponding configuration initialization interface.
     */
    int32_t ret = CheckVersionValid(config, minVersion, maxVersion);
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

    uint16_t tmpMinVersion = minVersion;
    uint16_t tmpMaxVersion = maxVersion;

    if (tmpMinVersion == 0) {
        if (config->originVersionMask == DTLS_VERSION_MASK) {
            tmpMinVersion = HITLS_VERSION_DTLS12;
        } else {
            tmpMinVersion = HITLS_VERSION_TLS12;
        }
    } else if (tmpMaxVersion == 0) {
        if (config->originVersionMask == DTLS_VERSION_MASK) {
            tmpMaxVersion = HITLS_VERSION_DTLS12;
        } else {
            tmpMaxVersion = HITLS_VERSION_TLS13;
        }
    }

    ret = CFG_CheckVersion(tmpMinVersion, tmpMaxVersion);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* In invalid cases, both maxVersion and minVersion are 0 */
    if (ChangeVersionMask(config, tmpMinVersion, tmpMaxVersion) == HITLS_SUCCESS) {
        config->minVersion = tmpMinVersion;
        config->maxVersion = tmpMaxVersion;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetVersionForbid(HITLS_Config *config, uint32_t noVersion)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    // Now only DTLS1.2 is supported, so single version is not supported (disable to version 0)
    if ((config->originVersionMask & TLS_VERSION_MASK) == TLS_VERSION_MASK) {
        uint32_t noVersionBit = MapVersion2VersionBit(noVersion);
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

int32_t HITLS_CFG_ClearTLS13CipherSuites(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_FREE(config->tls13CipherSuites);
    config->tls13cipherSuitesSize = 0;
    return HITLS_SUCCESS;
}

static void GetCipherSuitesCnt(const uint16_t *cipherSuites, uint32_t cipherSuitesSize,
    uint32_t *tls13CipherSize, uint32_t *tlsCipherSize)
{
    uint32_t tmpCipherSize = *tlsCipherSize;
    uint32_t tmpTls13CipherSize = *tls13CipherSize;
    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        if (cipherSuites[i] >= HITLS_AES_128_GCM_SHA256 && cipherSuites[i] <= HITLS_AES_128_CCM_8_SHA256) {
            tmpTls13CipherSize++;
            continue;
        }
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

    uint32_t tlsCipherSize = 0, tls13CipherSize = 0;
    uint32_t validTls13Cipher = 0, validTlsCipher = 0;

    GetCipherSuitesCnt(cipherSuites, cipherSuitesSize, &tls13CipherSize, &tlsCipherSize);

    uint16_t *cipherSuite = BSL_SAL_Calloc(1u, (tlsCipherSize + 1) * sizeof(uint16_t));
    if (cipherSuite == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    uint16_t *tls13CipherSuite = BSL_SAL_Calloc(1u, (tls13CipherSize + 1) * sizeof(uint16_t));
    if (tls13CipherSuite == NULL) {
        BSL_SAL_FREE(cipherSuite);
        return HITLS_MEMALLOC_FAIL;
    }

    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        if (CFG_CheckCipherSuiteSupported(cipherSuites[i]) != true) {
            continue;
        }
        if (cipherSuites[i] >= HITLS_AES_128_GCM_SHA256 && cipherSuites[i] <= HITLS_AES_128_CCM_8_SHA256) {
            tls13CipherSuite[validTls13Cipher] = cipherSuites[i];
            validTls13Cipher++;
            continue;
        }
        cipherSuite[validTlsCipher] = cipherSuites[i];
        validTlsCipher++;
    }

    if (validTls13Cipher == 0) {
        BSL_SAL_FREE(tls13CipherSuite);
    } else {
        BSL_SAL_FREE(config->tls13CipherSuites);
        config->tls13CipherSuites = tls13CipherSuite;
        config->tls13cipherSuitesSize = validTls13Cipher;
    }

    if (validTlsCipher == 0) {
        BSL_SAL_FREE(cipherSuite);
    } else {
        BSL_SAL_FREE(config->cipherSuites);
        config->cipherSuites = cipherSuite;
        config->cipherSuitesSize = validTlsCipher;
    }

    if (validTlsCipher == 0 && validTls13Cipher == 0) {
        return HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetEcPointFormats(HITLS_Config *config, const uint8_t *pointFormats, uint32_t pointFormatsSize)
{
    if ((config == NULL) || (pointFormats == NULL) || (pointFormatsSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (pointFormatsSize > HITLS_CFG_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *newData = BSL_SAL_Dump(pointFormats, pointFormatsSize * sizeof(uint8_t));
    /* If the allocation fails, return an error code */
    if (newData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    /* Reallocate the memory of pointFormats and update the length of pointFormats */
    BSL_SAL_FREE(config->pointFormats);
    config->pointFormats = newData;
    config->pointFormatsSize = pointFormatsSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetGroups(HITLS_Config *config, const uint16_t *groups, uint32_t groupsSize)
{
    if ((config == NULL) || (groups == NULL) || (groupsSize == 0u)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (groupsSize > HITLS_CFG_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint16_t *newData = BSL_SAL_Dump(groups, groupsSize * sizeof(uint16_t));
    /* If the allocation fails, return an error code */
    if (newData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* Reallocate the memory of groups and update the length of groups */
    BSL_SAL_FREE(config->groups);
    config->groups = newData;
    config->groupsSize = groupsSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSignature(HITLS_Config *config, const uint16_t *signAlgs, uint16_t signAlgsSize)
{
    if ((config == NULL) || (signAlgs == NULL) || (signAlgsSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (signAlgsSize > HITLS_CFG_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint16_t *newData = BSL_SAL_Dump(signAlgs, signAlgsSize * sizeof(uint16_t));
    /* If the allocation fails, return an error code */
    if (newData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* Reallocate the signAlgs memory and update the signAlgs length */
    BSL_SAL_FREE(config->signAlgorithms);
    config->signAlgorithms = newData;
    config->signAlgorithmsSize = signAlgsSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetServerName(HITLS_Config *config, uint8_t *serverName, uint32_t serverNameStrlen)
{
    uint32_t serverNameSize = 0u;
    if ((config == NULL) || (serverName == NULL) || (serverNameStrlen == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (serverNameStrlen > HITLS_CFG_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }
    serverNameSize = serverNameStrlen;
    if (serverName[serverNameStrlen - 1] != '\0') {
        serverNameSize += 1;
    }
    uint8_t *newData = (uint8_t *) BSL_SAL_Malloc(serverNameSize * sizeof(uint8_t));
    if (newData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    if (memcpy_s(newData, serverNameSize, serverName, serverNameStrlen) != EOK) {
        BSL_SAL_FREE(newData);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    newData[serverNameSize - 1] = '\0';
    /* Reallocate the serverName memory and update the serverName length */
    BSL_SAL_FREE(config->serverName);
    config->serverName = newData;
    config->serverNameSize = serverNameSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerName(HITLS_Config *config, uint8_t **serverName, uint32_t *serverNameStrlen)
{
    if (config == NULL || serverName == NULL || serverNameStrlen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *serverName = config->serverName;
    *serverNameStrlen =  config->serverNameSize;

    return HITLS_SUCCESS;
}
int32_t HITLS_CFG_SetServerNameCb(HITLS_Config *config, HITLS_SniDealCb callback)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->sniDealCb = callback;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetServerNameArg(HITLS_Config *config, void *arg)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->sniArg = arg;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerNameCb(HITLS_Config *config, HITLS_SniDealCb *callback)
{
    if (config == NULL || callback == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *callback = config->sniDealCb;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerNameArg(HITLS_Config *config, void **arg)
{
    if (config == NULL || arg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *arg = config->sniArg;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetRenegotiationSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    config->isSupportRenegotiation = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetResumptionOnRenegoSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    config->isResumptionOnRenego = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetClientVerifySupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    config->isSupportClientVerify = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetNoClientCertSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->isSupportNoClientCert = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetExtenedMasterSecretSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    /** et the extended master key flag */
    config->isSupportExtendMasterSecret = support;
    return HITLS_SUCCESS;
}

// Set the identity hint interface
int32_t HITLS_CFG_SetPskIdentityHint(HITLS_Config *config, const uint8_t *hint, uint32_t hintSize)
{
    if ((config == NULL) || (hint == NULL) || (hintSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (hintSize > HITLS_IDENTITY_HINT_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *newData = BSL_SAL_Dump(hint, hintSize * sizeof(uint8_t));
    if (newData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* Repeated settings are supported */
    BSL_SAL_FREE(config->pskIdentityHint);
    config->pskIdentityHint = newData;
    config->hintSize = hintSize;

    return HITLS_SUCCESS;
}

// Configure clientCb, which is used to obtain the PSK through identity hints
int32_t HITLS_CFG_SetPskClientCallback(HITLS_Config *config, HITLS_PskClientCb callback)
{
    if (config == NULL || callback == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->pskClientCb = callback;
    return HITLS_SUCCESS;
}

// Set serverCb to obtain the PSK through identity.
int32_t HITLS_CFG_SetPskServerCallback(HITLS_Config *config, HITLS_PskServerCb callback)
{
    if (config == NULL || callback == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->pskServerCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetClientHelloCb(HITLS_Config *config, HITLS_ClientHelloCb callback, void *arg)
{
    if (config == NULL || callback == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->clientHelloCb = callback;
    config->clientHelloCbArg = arg;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetNoSecRenegotiationCb(HITLS_Config *config, HITLS_NoSecRenegotiationCb callback)
{
    if (config == NULL || callback == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->noSecRenegotiationCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetDhAutoSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->isSupportDhAuto = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionTicketSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->isSupportSessionTicket = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetTmpDh(HITLS_Config *config, HITLS_CRYPT_Key *dhPkey)
{
    if ((config == NULL) || (dhPkey == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    SAL_CRYPT_FreeDhKey(config->dhTmp);
    config->dhTmp = dhPkey;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetRenegotiationSupport(const HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportRenegotiation;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetClientVerifySupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportClientVerify;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetNoClientCertSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportNoClientCert;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetExtenedMasterSecretSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportExtendMasterSecret;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetDhAutoSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportDhAuto;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTicketSupport(const HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportSessionTicket;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetTicketKeyCallback(HITLS_Config *config, HITLS_TicketKeyCb callback)
{
    if (config == NULL || config->sessMgr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetTicketKeyCb(config->sessMgr, callback);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTicketKey(const HITLS_Config *config, uint8_t *key, uint32_t keySize, uint32_t *outSize)
{
    if (config == NULL || config->sessMgr == NULL || key == NULL || outSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SESSMGR_GetTicketKey(config->sessMgr, key, keySize, outSize);
}

int32_t HITLS_CFG_SetSessionTicketKey(HITLS_Config *config, const uint8_t *key, uint32_t keySize)
{
    if (config == NULL || config->sessMgr == NULL || key == NULL ||
        (keySize != HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_KEY_SIZE + HITLS_TICKET_KEY_SIZE)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SESSMGR_SetTicketKey(config->sessMgr, key, keySize);
}

int32_t HITLS_CFG_SetPostHandshakeAuthSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    config->isSupportPostHandshakeAuth = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetPostHandshakeAuthSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportPostHandshakeAuth;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetVerifyNoneSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    config->isSupportVerifyNone = support;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetVerifyNoneSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportVerifyNone;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetClientOnceVerifySupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    config->isSupportClientOnceVerify = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetClientOnceVerifySupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportClientOnceVerify;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_AddCAIndication(HITLS_Config *config, HITLS_TrustedCAType caType, const uint8_t *data, uint32_t len)
{
    if ((config == NULL) || (data == NULL) || (len == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_TrustedCANode *newCaNode = BSL_SAL_Calloc(1u, sizeof(HITLS_TrustedCANode));
    if (newCaNode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    newCaNode->caType = caType;
    newCaNode->data = BSL_SAL_Dump(data, len);
    if (newCaNode->data == NULL) {
        BSL_SAL_FREE(newCaNode);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    newCaNode->dataSize = len;

    if (config->caList == NULL) {
        config->caList = BSL_LIST_New(sizeof(HITLS_TrustedCANode *));
        if (config->caList == NULL) {
            BSL_SAL_FREE(newCaNode->data);
            BSL_SAL_FREE(newCaNode);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    /* tail insertion */
    int32_t ret = (int32_t)BSL_LIST_AddElement((BslList *)config->caList, newCaNode, BSL_LIST_POS_END);
    if (ret != 0) {
        BSL_SAL_FREE(newCaNode->data);
        BSL_SAL_FREE(newCaNode);
        return ret;
    }

    return HITLS_SUCCESS;
}

HITLS_TrustedCAList *HITLS_CFG_GetCAList(const HITLS_Config *config)
{
    return config->caList;
}

int32_t HITLS_CFG_SetKeyExchMode(HITLS_Config *config, uint32_t mode)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    if (((mode & TLS13_KE_MODE_PSK_ONLY) == TLS13_KE_MODE_PSK_ONLY) ||
        ((mode & TLS13_KE_MODE_PSK_WITH_DHE) == TLS13_KE_MODE_PSK_WITH_DHE)) {
        config->keyExchMode = (mode & (TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE));
        return HITLS_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_SET);
    return HITLS_CONFIG_INVALID_SET;
}

uint32_t HITLS_CFG_GetKeyExchMode(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return config->keyExchMode;
}

int32_t HITLS_CFG_GetMaxVersion(const HITLS_Config *config, uint16_t *maxVersion)
{
    if (config == NULL || maxVersion == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *maxVersion = config->maxVersion;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetMinVersion(const HITLS_Config *config, uint16_t *minVersion)
{
    if (config == NULL || minVersion == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *minVersion = config->minVersion;
    return HITLS_SUCCESS;
}

static int32_t AlpnListValidationCheck(const uint8_t *alpnList, uint32_t alpnProtosLen)
{
    uint32_t index = 0u;

    while (index < alpnProtosLen) {
        if (alpnList[index] == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
            return HITLS_CONFIG_INVALID_LENGTH;
        }
        index += (alpnList[index] + 1);
    }

    if (index != alpnProtosLen) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetAlpnProtos(HITLS_Config *config, const uint8_t *alpnProtos, uint32_t alpnProtosLen)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
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
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *alpnListTmp = (uint8_t *)BSL_SAL_Calloc(alpnProtosLen + 1, sizeof(uint8_t));
    if (alpnListTmp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    if (memcpy_s(alpnListTmp, alpnProtosLen + 1, alpnProtos, alpnProtosLen) != EOK) {
        BSL_SAL_FREE(alpnListTmp);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    BSL_SAL_FREE(config->alpnList);
    config->alpnList = alpnListTmp;
    /* Ignore ending 0s */
    config->alpnListSize = alpnProtosLen;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetAlpnProtosSelectCb(HITLS_Config *config, HITLS_AlpnSelectCb callback, void *userData)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->alpnSelectCb = callback;
    config->alpnUserData = userData;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionIdCtx(HITLS_Config *config, const uint8_t *sessionIdCtx, uint32_t len)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (len != 0 && memcpy_s(config->sessionIdCtx, sizeof(config->sessionIdCtx), sessionIdCtx, len) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    /* The allowed value is 0 */
    config->sessionIdCtxSize = len;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionCacheMode(HITLS_Config *config, HITLS_SESS_CACHE_MODE mode)
{
    if (config == NULL || config->sessMgr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetCacheMode(config->sessMgr, mode);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionCacheMode(HITLS_Config *config, HITLS_SESS_CACHE_MODE *mode)
{
    if (config == NULL || config->sessMgr == NULL || mode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *mode = SESSMGR_GetCacheMode(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionCacheSize(HITLS_Config *config, uint32_t size)
{
    if (config == NULL || config->sessMgr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetCacheSize(config->sessMgr, size);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionCacheSize(HITLS_Config *config, uint32_t *size)
{
    if (config == NULL || config->sessMgr == NULL || size == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *size = SESSMGR_GetCacheSize(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionTimeout(HITLS_Config *config, uint64_t timeout)
{
    if (config == NULL || config->sessMgr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetTimeout(config->sessMgr, timeout);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTimeout(const HITLS_Config *config, uint64_t *timeout)
{
    if (config == NULL || config->sessMgr == NULL || timeout == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *timeout = SESSMGR_GetTimeout(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetVersionSupport(const HITLS_Config *config, uint32_t *version)
{
    if ((config == NULL) || (version == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if ((version & SSLV3_VERSION_BIT) == SSLV3_VERSION_BIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetVersion(&(ctx->config.tlsConfig), (uint16_t)minVersion, (uint16_t)maxVersion);
}

int32_t HITLS_SetVersionForbid(HITLS_Ctx *ctx, uint32_t noVersion)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetVersionForbid(&(ctx->config.tlsConfig), noVersion);
}

int32_t HITLS_CFG_SetNeedCheckPmsVersion(HITLS_Config *config, bool needCheck)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->needCheckPmsVersion = needCheck;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetQuietShutdown(HITLS_Config *config, int32_t mode)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    /* The value 0 indicates that the quiet disconnection mode is disabled. The value 1 indicates that the quiet
     * disconnection mode is enabled.
     */
    if (mode != 0 && mode != 1) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_SET);
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *mode = (int32_t)config->isQuietShutdown;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetEncryptThenMac(HITLS_Config *config, uint32_t encryptThenMacType)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (encryptThenMacType == 0) {
        config->isEncryptThenMac = false;
    } else {
        config->isEncryptThenMac = true;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetEncryptThenMac(const HITLS_Config *config, uint32_t *encryptThenMacType)
{
    if (config == NULL || encryptThenMacType == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *encryptThenMacType = (uint32_t)config->isEncryptThenMac;
    return HITLS_SUCCESS;
}

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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->userData = userData;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetConfigUserDataFreeCb(HITLS_Config *config, HITLS_ConfigUserDataFreeCb callback)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->userDataFreeCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetPskFindSessionCallback(HITLS_Config *config, HITLS_PskFindSessionCb callback)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->pskFindSessionCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetPskUseSessionCallback(HITLS_Config *config, HITLS_PskUseSessionCb callback)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->pskUseSessionCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_IsDtls(const HITLS_Config *config, uint8_t *isDtls)
{
    if (config == NULL || isDtls == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isDtls = ((config->originVersionMask & DTLS12_VERSION_BIT) != 0);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetCipherServerPreference(HITLS_Config *config, bool isSupport)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->isSupportServerPreference = isSupport;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetCipherServerPreference(const HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportServerPreference;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetTicketNums(HITLS_Config *config, uint32_t ticketNums)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->ticketNums = ticketNums;
    return HITLS_SUCCESS;
}

uint32_t HITLS_CFG_GetTicketNums(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return config->ticketNums;
}

int32_t HITLS_CFG_SetNewSessionCb(HITLS_Config *config, HITLS_NewSessionCb newSessionCb)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->newSessionCb = newSessionCb;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetFlightTransmitSwitch(HITLS_Config *config, uint8_t isEnable)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (isEnable == 0) {
        config->isFlightTransmitEnable = false;
    } else {
        config->isFlightTransmitEnable = true;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetFlightTransmitSwitch(const HITLS_Config *config, uint8_t *isEnable)
{
    if (config == NULL || isEnable == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isEnable = config->isFlightTransmitEnable;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetMaxCertList(HITLS_Config *config, uint32_t maxSize)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->maxCertList = maxSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetMaxCertList(const HITLS_Config *config, uint32_t *maxSize)
{
    if (config == NULL || maxSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *maxSize = config->maxCertList;
    return HITLS_SUCCESS;
}

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

int32_t HITLS_CFG_SetCloseCheckKeyUsage(HITLS_Config *config, bool isClose)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->needCheckKeyUsage = isClose;

    return HITLS_SUCCESS;
}