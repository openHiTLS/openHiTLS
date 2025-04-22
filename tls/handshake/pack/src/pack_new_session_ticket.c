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
#if defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_FEATURE_SESSION_TICKET)
#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "pack_common.h"
#include "tls.h"
#include "hs_ctx.h"
#include "custom_extensions.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t PackNewSessionTicket(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;

    HS_Ctx *hsCtx = ctx->hsCtx;

    if (bufLen < (sizeof(uint32_t) + sizeof(uint16_t) + hsCtx->ticketSize)) {
        return PackBufLenError(BINLOG_ID16054, BINGLOG_STR("NewSessionTicket"));
    }

    /* hsCtx->ticket is the encrypted ticket content, which corresponds to the ticket field in the protocol */
    BSL_Uint32ToByte(hsCtx->ticketLifetimeHint, &buf[offset]);
    offset += sizeof(uint32_t);
    BSL_Uint16ToByte((uint16_t)hsCtx->ticketSize, &buf[offset]);
    offset += sizeof(uint16_t);

    /* rfc5077 3.3. NewSessionTicket Handshake Message
       If the server determines that it does not want to include a ticket after including the SessionTicket extension
       in the ServerHello, it sends a zero-length ticket in the NewSessionTicket handshake message. */
    if (hsCtx->ticketSize != 0) {
        (void)memcpy_s(&buf[offset], bufLen - offset, hsCtx->ticket, hsCtx->ticketSize);
    }

    *usedLen = offset + hsCtx->ticketSize;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13PackNewSessionTicket(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t ticketAgeAdd = 0u;
    uint32_t offset = 0u;
    uint32_t exLen = 0;
    int32_t ret = HITLS_SUCCESS;

    HS_Ctx *hsCtx = ctx->hsCtx;

    /* size of ticketLifetime + size of ticketAgeAdd + size of ticketNonce + size of nextTicketNonce + size of ticket + ticketSize */
    if (bufLen < (sizeof(uint32_t) + sizeof(uint32_t) +
        sizeof(uint8_t) + sizeof(hsCtx->nextTicketNonce) +
        sizeof(uint16_t) + hsCtx->ticketSize)) {
        return PackBufLenError(BINLOG_ID16055, BINGLOG_STR("NewSessionTicket"));
    }

    BSL_Uint32ToByte(hsCtx->ticketLifetimeHint, &buf[offset]);
    offset += sizeof(uint32_t);

    ticketAgeAdd = hsCtx->ticketAgeAdd;
    BSL_Uint32ToByte(ticketAgeAdd, &buf[offset]);
    offset += sizeof(uint32_t);

    /* The TicketNonce length field occupies one byte and the length value is 8. */
    buf[offset] = sizeof(hsCtx->nextTicketNonce);
    offset += sizeof(uint8_t);

    BSL_Uint64ToByte(hsCtx->nextTicketNonce, &buf[offset]);
    offset += sizeof(hsCtx->nextTicketNonce);

    BSL_Uint16ToByte((uint16_t)hsCtx->ticketSize, &buf[offset]);
    offset += sizeof(uint16_t);

    /* In TLS1.3, no empty new session ticket is sent
       because we ensure that hsCtx->ticketSize is not empty at the invoking point.
       Therefore, you do not need to check whether hsCtx->ticketSize is empty. */
    (void)memcpy_s(&buf[offset], bufLen - offset, hsCtx->ticket, hsCtx->ticketSize);
    offset += hsCtx->ticketSize;

    /* extension is not supported currently, set the total extension length to 0 */
    /* total extension length */
    if (bufLen < (offset + sizeof(uint16_t))) {
        return PackBufLenError(BINLOG_ID16049, BINGLOG_STR("NewSessionTicket"));
    }
    if (IsPackNeedCustomExtensions(ctx->customExts, HITLS_EX_TYPE_NEW_SESSION_TICKET)) {
        ret = PackCustomExtensions(ctx, &buf[offset + sizeof(uint16_t)], bufLen - offset - sizeof(uint16_t), &exLen,
            HITLS_EX_TYPE_NEW_SESSION_TICKET);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    if (bufLen < (offset + sizeof(uint16_t) + exLen)) {
        return PackBufLenError(BINLOG_ID16049, BINGLOG_STR("NewSessionTicket"));
    }
    BSL_Uint16ToByte(exLen, &buf[offset]);
    offset += exLen + sizeof(uint16_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER && HITLS_TLS_FEATURE_SESSION_TICKET */
