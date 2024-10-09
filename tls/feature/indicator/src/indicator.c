/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "tls.h"
#include "indicator.h"

void INDICATOR_StatusIndicate(const HITLS_Ctx *ctx, int32_t eventType, int32_t value)
{
    if (ctx == NULL || ctx->config.tlsConfig.infoCb == NULL) {
        return;
    }

    ctx->config.tlsConfig.infoCb(ctx, eventType, value);
}

void INDICATOR_MessageIndicate(int32_t writePoint, uint32_t tlsVersion, int32_t contentType, const void *msg,
    uint32_t msgLen, HITLS_Ctx *ctx, void *arg)
{
    if (ctx == NULL || ctx->config.tlsConfig.msgCb == NULL) {
        return;
    }

    ctx->config.tlsConfig.msgCb(writePoint, tlsVersion, contentType, msg, msgLen, ctx, arg);
}