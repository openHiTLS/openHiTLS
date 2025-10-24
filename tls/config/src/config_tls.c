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
#include "bsl_list.h"
#include "hitls_type.h"
#include "hitls_error.h"
#include "tls.h"
#include "cert.h"
#include "crypt.h"
#include "config_check.h"
#include "config_default.h"
#include "bsl_list.h"
#include "rec.h"
#include "cert_method.h"

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

#ifdef HITLS_TLS_CONFIG_VERSION
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
#ifdef HITLS_TLS_PROTO_TLS12
    newConfig->version |= TLS12_VERSION_BIT;
#endif
#ifdef HITLS_TLS_PROTO_TLS13
    newConfig->version |= TLS13_VERSION_BIT;
#endif
#ifdef HITLS_TLS_PROTO_TLCP11
    newConfig->version |= TLCP11_VERSION_BIT;
#endif

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