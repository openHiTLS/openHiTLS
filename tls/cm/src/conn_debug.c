/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stddef.h>
#include "tls.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "hitls_debug.h"

int32_t HITLS_SetInfoCb(HITLS_Ctx *ctx, HITLS_InfoCb callback)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetMsgCb(&(ctx->config.tlsConfig), callback);
}

int32_t HITLS_CFG_SetMsgCb(HITLS_Config *config, HITLS_MsgCb callback)
{
    /* support NULL callback */
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->msgCb = callback;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetMsgCbArg(HITLS_Config *config, void *arg)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    config->msgArg = arg;

    return HITLS_SUCCESS;
}