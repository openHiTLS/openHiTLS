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
#ifdef HITLS_TLS_PROTO_DTLS
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "hitls_type.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "tls.h"
#include "tls_binlog_id.h"
#include "cert.h"
#include "crypt.h"
#include "config_check.h"
#include "config_default.h"
#include "bsl_list.h"
#include "rec.h"
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
#include "hitls_cookie.h"
#endif
#include "cert_method.h"

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

int32_t HITLS_CFG_IsDtls(const HITLS_Config *config, bool *isDtls)
{
    if (config == NULL || isDtls == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isDtls = ((config->originVersionMask & DTLS12_VERSION_BIT) != 0);
    return HITLS_SUCCESS;
}

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

int32_t HITLS_CFG_SetDtlsPostHsTimeoutVal(HITLS_Config *config, uint32_t timeoutVal)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->dtlsPostHsTimeoutVal = timeoutVal;
    return HITLS_SUCCESS;
}

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
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
#endif /* HITLS_TLS_PROTO_DTLS */
