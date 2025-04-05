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

    ctx->config.tlsConfig.msgCb(writePoint, (int32_t)tlsVersion, contentType, msg, msgLen, ctx, arg);
}
#endif /* HITLS_TLS_FEATURE_INDICATOR */