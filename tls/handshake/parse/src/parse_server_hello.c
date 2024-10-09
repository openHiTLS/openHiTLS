/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "parse_common.h"
#include "parse_extensions.h"
#include "parse_msg.h"

static int32_t ParseServerHelloCipherSuite(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15785, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the message length of server hello is not enough for cipher suite.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Parse the cipher suite */
    msg->cipherSuite = BSL_ByteToUint16(buf);

    return HITLS_SUCCESS;
}

static int32_t ParseServerHelloCompressionMethod(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen)
{
    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15786, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the message length of server hello is not enough for compression method.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    if (buf[0] != 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_COMPRESSION_METHOD_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15787, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the TLS client is not support compression format.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_COMPRESSION_METHOD_ERR;
    }

    return HITLS_SUCCESS;
}

static int32_t ParseServerHelloExtensions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    const uint8_t *msgBuf = buf;
    uint32_t bufOffset = 0;

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15788, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the external message length of handshake message (server hello) is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the length of the extended message */
    uint16_t exMsgLen = BSL_ByteToUint16(&msgBuf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (exMsgLen != (bufLen - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15789, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the external message length of handshake message (server hello) is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    if (exMsgLen == 0u) {
        return HITLS_SUCCESS;
    }

    return ParseServerExtension(ctx, &msgBuf[bufOffset], exMsgLen, msg);
}

int32_t ParseServerHello(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    int32_t ret = HITLS_SUCCESS;
    ServerHelloMsg *msg = &hsMsg->body.serverHello;
    const uint8_t *msgBuf = buf;
    uint32_t bufOffset = 0;
    uint32_t readLen = 0;

    ret = ParseVersion(ctx, msgBuf, bufLen, &msg->version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += sizeof(uint16_t);

    ret = ParseRandom(ctx, &msgBuf[bufOffset], bufLen - bufOffset, msg->randomValue, HS_RANDOM_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += HS_RANDOM_SIZE;

    ret = ParseSessionId(ctx, &msgBuf[bufOffset], bufLen - bufOffset, &msg->sessionId, &msg->sessionIdSize, &readLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* Update the buffer offset length */
    bufOffset += readLen;

    ret = ParseServerHelloCipherSuite(ctx, &msgBuf[bufOffset], bufLen - bufOffset, msg);
    if (ret != HITLS_SUCCESS) {
        CleanServerHello(msg);
        return ret;
    }
    /* Update the buffer offset length */
    bufOffset += sizeof(uint16_t);

    ret = ParseServerHelloCompressionMethod(ctx, &msgBuf[bufOffset], bufLen - bufOffset);
    if (ret != HITLS_SUCCESS) {
        CleanServerHello(msg);
        return ret;
    }
    /* Update the buffer offset length */
    bufOffset += sizeof(uint8_t);

    /* If the buf length is equal to the offset length, return HITLS_SUCCESS. */
    if (bufLen == bufOffset) {
        // ServerHello is optionally followed by extension data
        return HITLS_SUCCESS;
    }

    ret = ParseServerHelloExtensions(ctx, &msgBuf[bufOffset], bufLen - bufOffset, msg);
    if (ret != HITLS_SUCCESS) {
        CleanServerHello(msg);
    }

    return ret;
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
