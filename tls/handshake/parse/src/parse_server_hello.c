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
#ifdef HITLS_TLS_HOST_CLIENT
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "parse_common.h"
#include "parse_extensions.h"
#include "parse_msg.h"

static int32_t ParseServerHelloCipherSuite(ParsePacket *pkt, ServerHelloMsg *msg)
{
    int32_t ret = ParseBytesToUint16(pkt, &msg->cipherSuite);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15785,
            BINGLOG_STR("parse cipherSuites failed."), ALERT_DECODE_ERROR);
    }
    return HITLS_SUCCESS;
}

static int32_t ParseServerHelloCompressionMethod(ParsePacket *pkt)
{
    uint8_t comMethod = 0;
    int32_t ret = ParseBytesToUint8(pkt, &comMethod);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15786,
            BINGLOG_STR("parse compression method failed."), ALERT_DECODE_ERROR);
    }

    if (comMethod != 0u) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_COMPRESSION_METHOD_ERR, BINLOG_ID15787,
            BINGLOG_STR("client does not support compression format."), ALERT_ILLEGAL_PARAMETER);
    }

    return HITLS_SUCCESS;
}

static int32_t ParseServerHelloExtensions(ParsePacket *pkt, ServerHelloMsg *msg)
{
    uint16_t exMsgLen = 0;
    const char *logStr = BINGLOG_STR("parse extension length failed.");
    int32_t ret = ParseBytesToUint16(pkt, &exMsgLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15788,
            logStr, ALERT_DECODE_ERROR);
    }

    if (exMsgLen != (pkt->bufLen - *pkt->bufOffset)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15789,
            logStr, ALERT_DECODE_ERROR);
    }

    if (exMsgLen == 0u) {
        return HITLS_SUCCESS;
    }
    return ParseServerExtension(pkt->ctx, &pkt->buf[*pkt->bufOffset], exMsgLen, msg);
}

int32_t ParseServerHello(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    int32_t ret = HITLS_SUCCESS;
    ServerHelloMsg *msg = &hsMsg->body.serverHello;
    uint32_t bufOffset = 0;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};

    ret = ParseVersion(&pkt, &msg->version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ParseRandom(&pkt, msg->randomValue, HS_RANDOM_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ParseSessionId(&pkt, &msg->sessionIdSize, &msg->sessionId);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ParseServerHelloCipherSuite(&pkt, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ParseServerHelloCompressionMethod(&pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* If the buf length is equal to the offset length, return HITLS_SUCCESS. */
    if (bufLen == bufOffset) {
        // ServerHello is optionally followed by extension data
        return HITLS_SUCCESS;
    }

    return ParseServerHelloExtensions(&pkt, msg);
}

void CleanServerHello(ServerHelloMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->sessionId);

    CleanServerHelloExtension(msg);

    return;
}
#endif /* HITLS_TLS_HOST_CLIENT */