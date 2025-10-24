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
#include "hitls_error.h"
#include "pack_common.h"
#include "tls.h"
#include "hs_ctx.h"
#include "custom_extensions.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t PackNewSessionTicket(const TLS_Ctx *ctx, PackPacket *pkt)
{
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* Pack ticket lifetime hint */
    int32_t ret = PackAppendUint32ToBuf(pkt, hsCtx->ticketLifetimeHint);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack ticket length */
    ret = PackAppendUint16ToBuf(pkt, (uint16_t)hsCtx->ticketSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* rfc5077 3.3. NewSessionTicket Handshake Message
       If the server determines that it does not want to include a ticket after including the SessionTicket extension
       in the ServerHello, it sends a zero-length ticket in the NewSessionTicket handshake message. */
    if (hsCtx->ticketSize != 0) {
        ret = PackAppendDataToBuf(pkt, hsCtx->ticket, hsCtx->ticketSize);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13PackNewSessionTicket(const TLS_Ctx *ctx, PackPacket *pkt)
{
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* Pack ticket lifetime */
    int32_t ret = PackAppendUint32ToBuf(pkt, hsCtx->ticketLifetimeHint);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack ticket age add */
    ret = PackAppendUint32ToBuf(pkt, hsCtx->ticketAgeAdd);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack ticket nonce length (1 byte) */
    ret = PackAppendUint8ToBuf(pkt, sizeof(hsCtx->nextTicketNonce));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack ticket nonce (8 bytes) */
    ret = PackAppendUint64ToBuf(pkt, hsCtx->nextTicketNonce);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack ticket length */
    ret = PackAppendUint16ToBuf(pkt, (uint16_t)hsCtx->ticketSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* In TLS1.3, no empty new session ticket is sent
       because we ensure that hsCtx->ticketSize is not empty at the invoking point.
       Therefore, you do not need to check whether hsCtx->ticketSize is empty. */
    ret = PackAppendDataToBuf(pkt, hsCtx->ticket, hsCtx->ticketSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack extensions length field */
    uint32_t extensionsLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &extensionsLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsPackNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET)) {
        ret = PackCustomExtensions(ctx, pkt, HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET, NULL, 0);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */

    /* Close extensions length field */
    PackCloseUint16Field(pkt, extensionsLenPosition);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER && HITLS_TLS_FEATURE_SESSION_TICKET */
