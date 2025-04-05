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
int32_t HITLS_CFG_GetPostHandshakeAuthSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportPostHandshakeAuth;
    return HITLS_SUCCESS;
}
#endif
#endif /* HITLS_TLS_PROTO_TLS13 */