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
#ifdef HITLS_TLS_FEATURE_ALPN
#include <stdint.h>
#include "securec.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "hs_ctx.h"
#include "tls.h"
#include "alpn.h"

static int32_t SelectProtocol(TLS_Ctx *ctx, uint8_t *alpnSelected, uint16_t alpnSelectedSize)
{
    uint8_t *protoMatch = NULL;
    uint8_t protoMatchLen = 0;

    int32_t ret = HITLS_SelectAlpnProtocol(&protoMatch, &protoMatchLen, ctx->config.tlsConfig.alpnList,
        ctx->config.tlsConfig.alpnListSize, alpnSelected, alpnSelectedSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15258, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client check proposed protocol fail due to invalid params.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    } else if (protoMatch == NULL) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ALPN_PROTOCOL_NO_MATCH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15259, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server proposed protocol is not supported by client", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_ALPN_PROTOCOL_NO_MATCH;
    }
    uint32_t protoLen = protoMatchLen;

    uint8_t *alpnSelectedTmp = (uint8_t *)BSL_SAL_Calloc(1u, (protoLen + 1));
    if (alpnSelectedTmp == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15260, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client malloc selected alpn mem failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    (void)memcpy_s(alpnSelectedTmp, protoLen + 1, protoMatch, protoLen);
    BSL_SAL_FREE(ctx->negotiatedInfo.alpnSelected);
    ctx->negotiatedInfo.alpnSelected = alpnSelectedTmp;
    ctx->negotiatedInfo.alpnSelectedSize = protoLen;

    return HITLS_SUCCESS;
}

int32_t ClientCheckNegotiatedAlpn(
    TLS_Ctx *ctx, bool haveSelectedAlpn, uint8_t *alpnSelected, uint16_t alpnSelectedSize)
{
    if ((!ctx->hsCtx->extFlag.haveAlpn) && haveSelectedAlpn) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15257, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get selected alpn protocol.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    if (alpnSelectedSize == 0) {
        return HITLS_SUCCESS;
    }

    int32_t ret = SelectProtocol(ctx, alpnSelected, alpnSelectedSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15262, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "ALPN protocol: %s.", ctx->negotiatedInfo.alpnSelected, 0, 0, 0);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ALPN */