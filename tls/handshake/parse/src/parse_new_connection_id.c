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
#ifdef HITLS_TLS_FEATURE_DTLS_CID
#include <string.h>
#include "tls.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "parse_common.h"

/*
 * RFC 9147 Section 9 NewConnectionId wire format:
 *   ConnectionId cids<0..2^16-1>;
 *   ConnectionIdUsage usage;       (1 byte)
 *
 * Each ConnectionId = opaque<0..2^8-1> = 1-byte length + CID bytes
 */
/*
 * Parse a NewConnectionId post-handshake message. The cids vector is validated
 * with a streaming walk over [len][cid] entries to reject truncated or
 * malformed payloads. No entry-count cap is enforced here because msg->cids
 * borrows the caller's wire buffer (zero allocation) and
 * DTLS_CID_ProcessPeerNewConnectionId stores only the first
 * HITLS_DTLS_CID_LIST_MAX entries, silently discarding the rest.
 */
int32_t ParseNewConnectionId(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    uint32_t bufOffset = 0u;

    /* Minimum message size: 2 bytes (cids length prefix) + 0 bytes (empty cids list) + 1 byte (usage) = 3 */
    if (bufLen < 3u) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15868,
            BINGLOG_STR("NewConnectionId msg too short"), ALERT_DECODE_ERROR);
    }

    uint16_t cidsLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += 2u;

    if (bufOffset + cidsLen + 1u != bufLen) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15868,
            BINGLOG_STR("NewConnectionId length mismatch"), ALERT_DECODE_ERROR);
    }

    /* Walk the variable-length CID vector to reject truncated [len][cid] entries. */
    uint32_t cidsParsed = 0;
    while (cidsParsed < cidsLen) {
        uint8_t cidLen = buf[bufOffset + cidsParsed];
        if (cidLen == 0) {
            return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15868,
                BINGLOG_STR("NewConnectionId zero-length CID entry"), ALERT_ILLEGAL_PARAMETER);
        }
        if (cidsParsed + 1u + cidLen > cidsLen) {
            return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15868,
                BINGLOG_STR("NewConnectionId cids field malformed"), ALERT_DECODE_ERROR);
        }
        cidsParsed += 1u + cidLen;
    }

    NewConnectionIdMsg *msg = &hsMsg->body.newConnectionId;
    /*
     * Point at the original wire bytes. The lifetime of buf spans the entire
     * HS_ProcessMsg call, which covers Dtls13RecvNewConnectionIdProcess, so the
     * pointer is valid for the consumer. parse.c clean-up therefore must not
     * BSL_SAL_FREE msg->cids any more.
     */
    msg->cids = (cidsLen > 0) ? &buf[bufOffset] : NULL;
    msg->cidsLen = cidsLen;
    bufOffset += cidsLen;

    msg->usage = buf[bufOffset];
    if (msg->usage > 1u) {
        memset(msg, 0, sizeof(*msg));
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15868,
            BINGLOG_STR("NewConnectionId invalid usage value"), ALERT_ILLEGAL_PARAMETER);
    }
    if (cidsLen == 0 && msg->usage == HITLS_DTLS_CID_IMMEDIATE) {
        memset(msg, 0, sizeof(*msg));
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15868,
            BINGLOG_STR("NewConnectionId immediate with empty CID list"), ALERT_ILLEGAL_PARAMETER);
    }

    return HITLS_SUCCESS;
}

/*
 * RFC 9147 Section 9 RequestConnectionId wire format:
 *   uint8 num_cids;
 */
/*
 * Parse a RequestConnectionId post-handshake message. The parser enforces the
 * one-byte wire shape; receive processing decides whether num_cids triggers an
 * application callback.
 */
int32_t ParseRequestConnectionId(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    if (bufLen != 1u) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15868,
            BINGLOG_STR("RequestConnectionId length is not 1"), ALERT_DECODE_ERROR);
    }

    hsMsg->body.requestConnectionId.numCids = buf[0];
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_FEATURE_DTLS_CID */
