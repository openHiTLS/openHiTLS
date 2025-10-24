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
#ifdef HITLS_TLS_PROTO_TLS13
#include "securec.h"
#include "tls.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "config_default.h"
#ifdef HITLS_TLS_FEATURE_PSK
#include "hitls_psk.h"
#endif

HITLS_Config *HITLS_CFG_NewTLS13Config(void)
{
    return HITLS_CFG_ProviderNewTLS13Config(NULL, NULL);
}

HITLS_Config *HITLS_CFG_ProviderNewTLS13Config(HITLS_Lib_Ctx *libCtx, const char *attrName)
{
    HITLS_Config *newConfig = CreateConfig();
    if (newConfig == NULL) {
        return NULL;
    }
    newConfig->version |= TLS13_VERSION_BIT;  // Enable TLS1.3

    newConfig->libCtx = libCtx;
    newConfig->attrName = attrName;

    if (DefaultTLS13Config(newConfig) != HITLS_SUCCESS) {
        BSL_SAL_FREE(newConfig);
        return NULL;
    }
    newConfig->originVersionMask = newConfig->version;
    return newConfig;
}

int32_t HITLS_CFG_ClearTLS13CipherSuites(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_FREE(config->tls13CipherSuites);
    config->tls13cipherSuitesSize = 0;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetKeyExchMode(HITLS_Config *config, uint32_t mode)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (((mode & TLS13_KE_MODE_PSK_ONLY) == TLS13_KE_MODE_PSK_ONLY) ||
        ((mode & TLS13_KE_MODE_PSK_WITH_DHE) == TLS13_KE_MODE_PSK_WITH_DHE)) {
        config->keyExchMode = (mode & (TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE));
        return HITLS_SUCCESS;
    }
    return HITLS_CONFIG_INVALID_SET;
}

uint32_t HITLS_CFG_GetKeyExchMode(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    return config->keyExchMode;
}

#ifdef HITLS_TLS_FEATURE_PSK
int32_t HITLS_CFG_SetPskFindSessionCallback(HITLS_Config *config, HITLS_PskFindSessionCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->pskFindSessionCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetPskUseSessionCallback(HITLS_Config *config, HITLS_PskUseSessionCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->pskUseSessionCb = callback;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_FEATURE_PHA
int32_t HITLS_CFG_SetPostHandshakeAuthSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportPostHandshakeAuth = support;
    return HITLS_SUCCESS;
}
int32_t HITLS_CFG_GetPostHandshakeAuthSupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportPostHandshakeAuth;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PHA */

#ifdef HITLS_TLS_FEATURE_SM_TLS13
static int32_t SetTLS13SMCipherSuites(HITLS_Config *config, bool isOnlySupportSM)
{
    const uint16_t smCiphersuites13[] = {
        HITLS_SM4_GCM_SM3,
        HITLS_SM4_CCM_SM3,
    };
    size_t smCiphersuites13Size = sizeof(smCiphersuites13) / sizeof(uint16_t);
    if (isOnlySupportSM) {
        BSL_SAL_FREE(config->tls13CipherSuites);
        config->tls13CipherSuites = BSL_SAL_Dump(smCiphersuites13, sizeof(smCiphersuites13));
        if (config->tls13CipherSuites == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        config->tls13cipherSuitesSize = smCiphersuites13Size;
        BSL_SAL_FREE(config->cipherSuites);
        config->cipherSuitesSize = 0;
    } else {
        uint32_t tls13CipherSuitesSize = smCiphersuites13Size + config->tls13cipherSuitesSize;
        uint16_t *tls13CipherSuites = BSL_SAL_Calloc(tls13CipherSuitesSize, sizeof(uint16_t));
        if (tls13CipherSuites == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy_s(tls13CipherSuites, tls13CipherSuitesSize, smCiphersuites13, smCiphersuites13Size);
        uint16_t firstSmCipherSuite = 0;
        int index = 2;
        for (uint32_t i = 0; i < config->tls13cipherSuitesSize; i++) {
            if (config->tls13CipherSuites[i] != HITLS_SM4_GCM_SM3 &&
                config->tls13CipherSuites[i] != HITLS_SM4_CCM_SM3) {
                tls13CipherSuites[index++] = config->tls13CipherSuites[i];
            }
            if (firstSmCipherSuite == 0 && (config->tls13CipherSuites[i] == HITLS_SM4_GCM_SM3 ||
                                            config->tls13CipherSuites[i] == HITLS_SM4_CCM_SM3)) {
                firstSmCipherSuite = config->tls13CipherSuites[i];
            }
        }
        if (firstSmCipherSuite == 0) {
            firstSmCipherSuite = HITLS_SM4_GCM_SM3;
        }
        tls13CipherSuites[0] = firstSmCipherSuite;
        tls13CipherSuites[1] = ((firstSmCipherSuite == HITLS_SM4_GCM_SM3) ? HITLS_SM4_CCM_SM3 : HITLS_SM4_GCM_SM3);
        BSL_SAL_FREE(config->tls13CipherSuites);
        config->tls13CipherSuites = tls13CipherSuites;
        config->tls13cipherSuitesSize = index;
    }

    return HITLS_SUCCESS;
}

static int32_t SetTLS13SMSignAlgs(HITLS_Config *config, bool isOnlySupportSM)
{
    const uint16_t smSignAlg = CERT_SIG_SCHEME_SM2_SM3;
    if (isOnlySupportSM) {
        BSL_SAL_FREE(config->signAlgorithms);
        config->signAlgorithms = BSL_SAL_Dump(&smSignAlg, sizeof(smSignAlg));
        if (config->signAlgorithms == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        config->signAlgorithmsSize = 1;
    } else {
        uint32_t tls13SignAlgsSize = 1 + config->signAlgorithmsSize;
        uint16_t *tls13SignAlgs = BSL_SAL_Calloc(tls13SignAlgsSize, sizeof(uint16_t));
        if (tls13SignAlgs == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        tls13SignAlgs[0] = smSignAlg;
        int index = 1; // 第一个存放SM签名算法，1表示开始存放其他签名算法的下标
        for (uint32_t i = 0; i < config->signAlgorithmsSize; i++) {
            if (config->signAlgorithms[i] != CERT_SIG_SCHEME_SM2_SM3) {
                tls13SignAlgs[index++] = config->signAlgorithms[i];
            }
        }
        BSL_SAL_FREE(config->signAlgorithms);
        config->signAlgorithms = tls13SignAlgs;
        config->signAlgorithmsSize = index;
    }

    return HITLS_SUCCESS;
}

static int32_t SetTLS13SMGroups(HITLS_Config *config, bool isOnlySupportSM)
{
    const uint16_t smGroup = HITLS_EC_GROUP_SM2;
    if (isOnlySupportSM) {
        BSL_SAL_FREE(config->groups);
        config->groups = BSL_SAL_Dump(&smGroup, sizeof(smGroup));
        if (config->groups == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        config->groupsSize = 1;
    } else {
        uint32_t tls13GroupsSize = 1 + config->groupsSize;
        uint16_t *tls13Groups = BSL_SAL_Calloc(tls13GroupsSize, sizeof(uint16_t));
        if (tls13Groups == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        tls13Groups[0] = smGroup;
        int index = 1; // 第一个存放SM的Group值，1表示开始存放其他Group
        for (uint32_t i = 0; i < config->groupsSize; i++) {
            if (config->groups[i] != HITLS_EC_GROUP_SM2) {
                tls13Groups[index++] = config->groups[i];
            }
        }
        BSL_SAL_FREE(config->groups);
        config->groups = tls13Groups;
        config->groupsSize = index;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_EnableTls13SM(HITLS_Config *config, bool isOnlySupportSM)
{
    if (config == NULL || (config->version & TLS13_VERSION_BIT) == 0) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret = SetTLS13SMCipherSuites(config, isOnlySupportSM);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = SetTLS13SMSignAlgs(config, isOnlySupportSM);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = SetTLS13SMGroups(config, isOnlySupportSM);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SM_TLS13 */

int32_t HITLS_CFG_SetMiddleBoxCompat(HITLS_Config *config, bool isMiddleBox)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isMiddleBoxCompat = isMiddleBox;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetMiddleBoxCompat(HITLS_Config *config, bool *isMiddleBox)
{
    if (config == NULL || isMiddleBox == NULL) {
        return HITLS_NULL_INPUT;
    }
    *isMiddleBox = config->isMiddleBoxCompat;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */