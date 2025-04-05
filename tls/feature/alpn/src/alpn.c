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

#define MAX_PROTOCOL_LEN 65536

int32_t ALPN_SelectProtocol(uint8_t **out, uint32_t *outLen, uint8_t *clientAlpnList, uint32_t clientAlpnListLen,
    uint8_t *servAlpnList, uint32_t servAlpnListLen)
{
    if (out == NULL || outLen == NULL || clientAlpnList == NULL || servAlpnList == NULL ||
        servAlpnListLen == 0 || clientAlpnListLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16690, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "intput null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    uint32_t i, j;
    for (i = 0; i < servAlpnListLen;) {
        for (j = 0; j < clientAlpnListLen;) {
            if (servAlpnList[i] == clientAlpnList[j] &&
                (memcmp(&servAlpnList[i + 1], &clientAlpnList[j + 1], servAlpnList[i]) == 0)) {
                *out = &servAlpnList[i + 1];
                *outLen = servAlpnList[i];
                return HITLS_SUCCESS;
            }
            j = j + clientAlpnList[j];
            ++j;
        }
        i = i + servAlpnList[i];
        ++i;
    }

    return HITLS_SUCCESS;
}

static int32_t SelectProtocol(TLS_Ctx *ctx, uint8_t *alpnSelected, uint16_t alpnSelectedSize)
{
    uint8_t *protoMatch = NULL;
    uint32_t protoMatchLen = 0;

    int32_t ret = ALPN_SelectProtocol(&protoMatch, &protoMatchLen, alpnSelected,
        alpnSelectedSize, ctx->config.tlsConfig.alpnList, ctx->config.tlsConfig.alpnListSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15258, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client check proposed protocol fail due to invalid params.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    } else if (protoMatch == NULL) {
        /* The RFC 7301 does not specify the behavior when the client selectedProto does not match the local
         * configuration list. */
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ALPN_PROTOCOL_NO_MATCH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15259, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server proposed protocol is not supported by client", 0, 0, 0, 0);
        return HITLS_SUCCESS;
    }

    uint8_t *alpnSelectedTmp = (uint8_t *)BSL_SAL_Calloc(1u, (protoMatchLen + 1));
    if (alpnSelectedTmp == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15260, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client malloc selected alpn mem failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    if (memcpy_s(alpnSelectedTmp, protoMatchLen + 1, protoMatch,
        protoMatchLen) != EOK) {
        BSL_SAL_FREE(alpnSelectedTmp);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15261, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client copy selected alpn failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    BSL_SAL_FREE(ctx->negotiatedInfo.alpnSelected);
    ctx->negotiatedInfo.alpnSelected = alpnSelectedTmp;
    ctx->negotiatedInfo.alpnSelectedSize = protoMatchLen;

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