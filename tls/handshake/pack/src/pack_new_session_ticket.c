/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>

#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"

int32_t PackNewSessionTicket(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;

    HS_Ctx *hsCtx = ctx->hsCtx;

    if (bufLen < (sizeof(uint32_t) + sizeof(uint16_t) + hsCtx->ticketSize)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16054, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of NewSessionTicket message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    /* hsCtx->ticket is the encrypted ticket content, which corresponds to the ticket field in the protocol */
    BSL_Uint32ToByte(hsCtx->ticketLifetimeHint, &buf[offset]);
    offset += sizeof(uint32_t);
    BSL_Uint16ToByte((uint16_t)hsCtx->ticketSize, &buf[offset]);
    offset += sizeof(uint16_t);

    /* rfc5077 3.3. NewSessionTicket Handshake Message
       If the server determines that it does not want to include a ticket after including the SessionTicket extension
       in the ServerHello, it sends a zero-length ticket in the NewSessionTicket handshake message. */
    if (hsCtx->ticketSize != 0 && memcpy_s(&buf[offset], bufLen - offset, hsCtx->ticket, hsCtx->ticketSize) != EOK) {
        (void)memset_s(hsCtx->ticket, hsCtx->ticketSize, 0, hsCtx->ticketSize);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15001, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "memcpy ticket fail when pack new session ticket msg.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }

    *usedLen = offset + hsCtx->ticketSize;

    return HITLS_SUCCESS;
}

int32_t Tls13PackNewSessionTicket(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t ticketAgeAdd = 0u;
    uint32_t offset = 0u;

    HS_Ctx *hsCtx = ctx->hsCtx;

    /* ticket_lifetime + ticket_age_add + ticket_nonce length part + ticket_nonce + ticket length part + ticketSize */
    if (bufLen < (sizeof(uint32_t) + sizeof(uint32_t) +
        sizeof(uint8_t) + sizeof(hsCtx->nextTicketNonce) +
        sizeof(uint16_t) + hsCtx->ticketSize)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16055, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Pack NewSessionTicket message failed: bufLen %u ticketSize %u.", bufLen, hsCtx->ticketSize, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
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
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16049, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of NewSessionTicket message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    BSL_Uint16ToByte(0, &buf[offset]);

    *usedLen = offset + sizeof(uint16_t);
    return HITLS_SUCCESS;
}
