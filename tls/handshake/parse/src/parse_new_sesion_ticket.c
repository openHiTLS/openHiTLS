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

#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_msg.h"
#include "parse_msg.h"

static int32_t ParseTicketNonce(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, NewSessionTicketMsg *msg)
{
    uint32_t ticketNonceSize;
    uint8_t *ticketNonce = NULL;
    uint32_t bufOffset = 0u;

    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    ticketNonceSize = (uint32_t)buf[bufOffset];
    bufOffset += sizeof(uint8_t);

    if (ticketNonceSize == 0 || (bufLen < (bufOffset + ticketNonceSize))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    ticketNonce = (uint8_t *)BSL_SAL_Dump(&buf[bufOffset], ticketNonceSize);
    if (ticketNonce == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
    }

    msg->ticketNonceSize = ticketNonceSize;
    msg->ticketNonce = ticketNonce;
    return HITLS_SUCCESS;
}

static int32_t ParseTicket(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, NewSessionTicketMsg *msg)
{
    uint32_t ticketSize;                    /* length of ticket */
    uint8_t *ticket = NULL;                 /* ticket */
    uint32_t bufOffset = 0u;
    bool isTls13 = (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13);

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16012, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse sesionticket message failed, bufLen %u.", bufLen, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    ticketSize = (uint32_t)BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    /* TLS1.3 does not allow the ticket length to be 0 */
    if ((isTls13 && (ticketSize == 0 || bufLen < (ticketSize + bufOffset))) ||
        (!isTls13 && (bufLen != (ticketSize + bufOffset)))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15967, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse sesionticket message failed, bufLen %u, ticket size %u.", bufLen, ticketSize, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* rfc5077 3.3
       If the server determines that it does not want to include a ticket after including the SessionTicket extension
       in the ServerHello, it sends a zero-length ticket in the NewSessionTicket handshake message */
    if (ticketSize != 0) {
        ticket = (uint8_t *)BSL_SAL_Dump(&buf[bufOffset], ticketSize);
        if (ticket == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15968, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse sesionticket message failed: malloc ticket failed.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    msg->ticketSize = ticketSize;
    msg->ticket = ticket;
    return HITLS_SUCCESS;
}

int32_t ParseNewSessionTicket(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    int32_t ret;
    uint32_t ticketLifetimeHint;            /* unit of the ticket timeout interval is second */
    NewSessionTicketMsg *msg = &hsMsg->body.newSessionTicket;

    uint32_t bufOffset = 0u;

    if (bufLen < sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15966, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse sesionticket message failed, bufLen is %u.", bufLen, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    ticketLifetimeHint = BSL_ByteToUint32(&buf[bufOffset]);
    bufOffset += sizeof(uint32_t);

    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        if (bufLen < bufOffset + sizeof(uint32_t)) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16013, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse sesionticket message failed, bufLen %u.", bufLen, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }

        msg->ticketAgeAdd = BSL_ByteToUint32(&buf[bufOffset]);
        bufOffset += sizeof(uint32_t);

        ret = ParseTicketNonce(ctx, &buf[bufOffset], bufLen - bufOffset, msg);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16014, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse sesionticket message failed: parse ticket nonce failed.", 0, 0, 0, 0);
            return ret;
        }
        bufOffset += sizeof(uint8_t) + msg->ticketNonceSize;
    }

    ret = ParseTicket(ctx, &buf[bufOffset], bufLen - bufOffset, msg);
    if (ret != HITLS_SUCCESS) {
        CleanNewSessionTicket(msg);
        return ret;
    }

    /* TLS1.3 extension is not supported */
    msg->ticketLifetimeHint = ticketLifetimeHint;
    return HITLS_SUCCESS;
}

void CleanNewSessionTicket(NewSessionTicketMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->ticketNonce);
    BSL_SAL_FREE(msg->ticket);
    msg->ticketSize = 0;
    msg->ticketNonceSize = 0;
    return;
}
