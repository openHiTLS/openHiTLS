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
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include <stddef.h>
#include "tls.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "hitls_debug.h"

int32_t HITLS_SetInfoCb(HITLS_Ctx *ctx, HITLS_InfoCb callback)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    ctx->config.tlsConfig.infoCb = callback;
    return HITLS_SUCCESS;
}

HITLS_InfoCb HITLS_GetInfoCb(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->config.tlsConfig.infoCb;
}

int32_t HITLS_CFG_SetInfoCb(HITLS_Config *config, HITLS_InfoCb callback)
{
    /* support NULL callback */
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->infoCb = callback;
    return HITLS_SUCCESS;
}

HITLS_InfoCb HITLS_CFG_GetInfoCb(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }
    return config->infoCb;
}

int32_t HITLS_SetMsgCb(HITLS_Ctx *ctx, HITLS_MsgCb callback)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetMsgCb(&(ctx->config.tlsConfig), callback);
}

int32_t HITLS_CFG_SetMsgCb(HITLS_Config *config, HITLS_MsgCb callback)
{
    /* support NULL callback */
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->msgCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetMsgCbArg(HITLS_Ctx *ctx, void *arg)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetMsgCbArg(&(ctx->config.tlsConfig), arg);
}

int32_t HITLS_CFG_SetMsgCbArg(HITLS_Config *config, void *arg)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->msgArg = arg;

    return HITLS_SUCCESS;
}
#endif