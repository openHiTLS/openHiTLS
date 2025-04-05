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
#if defined(HITLS_TLS_HOST_CLIENT) && defined(HITLS_TLS_FEATURE_SESSION_TICKET)
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
#include "parse_common.h"
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t ParseTicketNonce(ParsePacket *pkt, NewSessionTicketMsg *msg)
{
    uint8_t ticketNonceSize = 0;
    const char *logStr = BINGLOG_STR("ParseOneByteLengthField fail");
    int32_t ret = ParseOneByteLengthField(pkt, &ticketNonceSize, &msg->ticketNonce);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17010, logStr, ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID17011, logStr, ALERT_INTERNAL_ERROR);
    }

    if (ticketNonceSize == 0) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17012, logStr, ALERT_DECODE_ERROR);
    }

    msg->ticketNonceSize = (uint32_t)ticketNonceSize;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
static int32_t ParseTicket(ParsePacket *pkt, NewSessionTicketMsg *msg)
{
    bool isTls13 = (pkt->ctx->negotiatedInfo.version == HITLS_VERSION_TLS13);
    uint16_t ticketSize = 0;
    /* rfc5077 3.3
       If the server does not include a ticket after including the SessionTicket extension in the ServerHello,
       it sends a zero-length ticket in the NewSessionTicket handshake message */
    int32_t ret = ParseTwoByteLengthField(pkt, &ticketSize, &msg->ticket);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16012,
            BINGLOG_STR("parse ticketSize failed."), ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15968,
            BINGLOG_STR("malloc ticket failed."), ALERT_UNKNOWN);
    }

    /* TLS1.3 does not allow the ticket length to be 0 */
    if ((isTls13 && (ticketSize == 0)) ||
        (!isTls13 && (pkt->bufLen != *pkt->bufOffset))) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15967, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse sesionticket message failed, bufLen %u, ticket size %u.", pkt->bufLen, ticketSize, 0, 0);
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, 0, NULL, ALERT_DECODE_ERROR);
    }

    msg->ticketSize = (uint32_t)ticketSize;
    return HITLS_SUCCESS;
}

int32_t ParseNewSessionTicket(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    uint32_t bufOffset = 0u;
    NewSessionTicketMsg *msg = &hsMsg->body.newSessionTicket;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};

    const char *logStr = BINGLOG_STR("parse sesionticket len fail.");
    int32_t ret = ParseBytesToUint32(&pkt, &msg->ticketLifetimeHint);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15966, logStr, ALERT_DECODE_ERROR);
    }
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        uint32_t ticketAgeAdd = 0;
        ret = ParseBytesToUint32(&pkt, &ticketAgeAdd);
        if (ret != HITLS_SUCCESS) {
            return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16013, logStr, ALERT_DECODE_ERROR);
        }
        msg->ticketAgeAdd = ticketAgeAdd;

        ret = ParseTicketNonce(&pkt, msg);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16014, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse ticket nonce failed.", 0, 0, 0, 0);
            return ret;
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    return ParseTicket(&pkt, msg);
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
#endif /* HITLS_TLS_HOST_CLIENT || HITLS_TLS_PROTO_TLS13 */