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
#ifdef HITLS_TLS_FEATURE_SECURITY
#include <stdint.h>
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_security.h"
#include "tls.h"

int32_t HITLS_CFG_SetSecurityLevel(HITLS_Config *config, int32_t securityLevel)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->securityLevel = securityLevel;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSecurityLevel(const HITLS_Config *config, int32_t *securityLevel)
{
    if (config == NULL || securityLevel == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *securityLevel = config->securityLevel;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSecurityCb(HITLS_Config *config, HITLS_SecurityCb securityCb)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->securityCb = securityCb;
    return HITLS_SUCCESS;
}

HITLS_SecurityCb HITLS_CFG_GetSecurityCb(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return config->securityCb;
}

int32_t HITLS_CFG_SetSecurityExData(HITLS_Config *config, void *securityExData)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->securityExData = securityExData;
    return HITLS_SUCCESS;
}

void *HITLS_CFG_GetSecurityExData(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return config->securityExData;
}

int32_t HITLS_SetSecurityLevel(HITLS_Ctx *ctx, int32_t securityLevel)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSecurityLevel(&(ctx->config.tlsConfig), securityLevel);
}

int32_t HITLS_GetSecurityLevel(const HITLS_Ctx *ctx, int32_t *securityLevel)
{
    if (ctx == NULL || securityLevel == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetSecurityLevel(&(ctx->config.tlsConfig), securityLevel);
}

int32_t HITLS_SetSecurityCb(HITLS_Ctx *ctx, HITLS_SecurityCb securityCb)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSecurityCb(&(ctx->config.tlsConfig), securityCb);
}

HITLS_SecurityCb HITLS_GetSecurityCb(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetSecurityCb(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetSecurityExData(HITLS_Ctx *ctx, void *securityExData)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSecurityExData(&(ctx->config.tlsConfig), securityExData);
}

void *HITLS_GetSecurityExData(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetSecurityExData(&(ctx->config.tlsConfig));
}
#endif /* HITLS_TLS_FEATURE_SECURITY */