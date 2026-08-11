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
#include "bsl_sal.h"
#include "bsl_log_internal.h"
#include "tls_binlog_id.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_dtls_cid.h"
#include "tls.h"
#include "dtls_cid.h"

/*
 * CID state is split into two tiers:
 *
 *  1. Inline single-CID state (always present in TLS_NegotiatedInfo):
 *       localCidEntry  - the single primary local recv CID advertised in the
 *                        connection_id extension and used by the record parser.
 *       peerCidEntry   - the single primary peer send CID carried on outbound
 *                        records. cidLen > 0 arms the send CID (i.e. tells the
 *                        record layer to pack it into the outbound header).
 *     These cover negotiation and the common case where CID is negotiated but
 *     never updated post-handshake.
 *
 *  2. Heap 16-slot table (cidCtx, lazily materialized):
 *       Multi-CID lists for post-handshake NewConnectionId / SwitchSendCid.
 *       Materialized on the first post-handshake CID operation, seeded from the
 *       seeded from the inline single-CID entries, and freed on ctx cleanup.
 */

bool DTLS_CID_IsEq(const uint8_t *left, uint8_t leftLen, const uint8_t *right, uint8_t rightLen)
{
    if (leftLen != rightLen) {
        return false;
    }
    return leftLen == 0 || memcmp(left, right, leftLen) == 0;
}

static uint8_t DtlsCidCountEntries(const DTLS_CidCtx *cidCtx, bool isSend)
{
    uint8_t count = 0;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (isSend) {
            if (cidCtx->sendSlots[i].state != DTLS_CID_SEND_SLOT_FREE) {
                count++;
            }
        } else if (cidCtx->recvSlots[i].state != DTLS_CID_RECV_SLOT_FREE) {
            count++;
        }
    }
    return count;
}

static uint8_t DtlsCidFillEntries(const TLS_NegotiatedInfo *ni, bool isSend, uint8_t required,
                                  HITLS_DtlsCidEntry *entries)
{
    uint8_t idx = 0;
    if (ni->cidCtx != NULL) {
        const DTLS_CidCtx *cidCtx = ni->cidCtx;
        for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
            bool isFree = isSend ? (cidCtx->sendSlots[i].state == DTLS_CID_SEND_SLOT_FREE) :
                                   (cidCtx->recvSlots[i].state == DTLS_CID_RECV_SLOT_FREE);
            if (isFree) {
                continue;
            }
            const uint8_t *cid = isSend ? cidCtx->sendSlots[i].entry.cidVal : cidCtx->recvSlots[i].entry.cidVal;
            uint8_t cidLen = isSend ? cidCtx->sendSlots[i].entry.cidLen : cidCtx->recvSlots[i].entry.cidLen;
            entries[idx].cidLen = cidLen;
            (void)memset(entries[idx].cidVal, 0, sizeof(entries[idx].cidVal));
            if (cidLen > 0) {
                (void)memcpy(entries[idx].cidVal, cid, cidLen);
            }
            idx++;
        }
    } else if (required == 1) {
        const uint8_t *cid = isSend ? ni->peerCidEntry.cidVal : ni->localCidEntry.cidVal;
        uint8_t cidLen = isSend ? ni->peerCidEntry.cidLen : ni->localCidEntry.cidLen;
        entries[idx].cidLen = cidLen;
        (void)memset(entries[idx].cidVal, 0, sizeof(entries[idx].cidVal));
        if (cidLen > 0) {
            (void)memcpy(entries[idx].cidVal, cid, cidLen);
        }
        idx++;
    }
    return idx;
}

static int32_t DtlsCidGetEntries(const TLS_Ctx *ctx, bool isSend, HITLS_DtlsCidEntry *entries, uint8_t *entryCount)
{
    if (ctx == NULL || entryCount == NULL) {
        return HITLS_NULL_INPUT;
    }
    const TLS_NegotiatedInfo *ni = &ctx->negotiatedInfo;
    uint8_t required;
    if (ni->cidCtx != NULL) {
        required = DtlsCidCountEntries(ni->cidCtx, isSend);
    } else {
        if (isSend) {
            required = (ni->peerCidEntry.cidLen > 0) ? 1 : 0;
        } else {
            required = (ni->localCidEntry.cidLen > 0) ? 1 : 0;
        }
    }

    if (entries == NULL) {
        *entryCount = required;
        return HITLS_SUCCESS;
    }
    /* Buffer too small: write the required count so the caller can retry with a larger buffer. */
    if (*entryCount < required) {
        *entryCount = required;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17407, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "GetCidEntries: caller-supplied buffer too small, need %u entries.", required, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }

    *entryCount = DtlsCidFillEntries(ni, isSend, required, entries);
    return HITLS_SUCCESS;
}

/* Configure the local receive CID that will be advertised in connection_id. */
int32_t HITLS_SetDtlsRecvCid(HITLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen)
{
    if (ctx == NULL || (cidLen > 0 && cid == NULL)) {
        return HITLS_NULL_INPUT;
    }
    if (!IS_SUPPORT_DTLS13(ctx->config.tlsConfig.originVersionMask)) {
        return HITLS_CONFIG_UNSUPPORT;
    }
    if (cidLen > HITLS_DTLS_CID_LOCAL_MAX_LEN) {
        return HITLS_INVALID_INPUT;
    }
    /* CID configuration is only mutable before handshake starts: idle state and no handshake context. */
    if (ctx->state != CM_STATE_IDLE || ctx->hsCtx != NULL) {
        return HITLS_CM_LINK_HANDSHAKING;
    }

    (void)memset(&ctx->negotiatedInfo.localCidEntry, 0, sizeof(ctx->negotiatedInfo.localCidEntry));
    ctx->negotiatedInfo.localCidEntry.cidLen = cidLen;
    if (cidLen > 0) {
        (void)memcpy(ctx->negotiatedInfo.localCidEntry.cidVal, cid, cidLen);
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_GetDtlsRecvCid(const HITLS_Ctx *ctx, HITLS_DtlsCidEntry *entries, uint8_t *entryCount)
{
    return DtlsCidGetEntries(ctx, false, entries, entryCount);
}

int32_t HITLS_GetDtlsSendCid(const HITLS_Ctx *ctx, HITLS_DtlsCidEntry *entries, uint8_t *entryCount)
{
    return DtlsCidGetEntries(ctx, true, entries, entryCount);
}

int32_t HITLS_GetDtlsIsCidNegotiated(const HITLS_Ctx *ctx, bool *isNegotiated)
{
    if (ctx == NULL || isNegotiated == NULL) {
        return HITLS_NULL_INPUT;
    }
    *isNegotiated = ctx->negotiatedInfo.isCidNegotiated;
    return HITLS_SUCCESS;
}

bool DTLS_CID_NeedCidExtForClientHello(const TLS_Ctx *ctx)
{
    /* openHiTLS does not implement CID for DTLS 1.2, so connection_id is offered only by a pure
     * DTLS 1.3 client; a client that also enables DTLS 1.2 must not offer it — the handshake could
     * downgrade to 1.2 where CID cannot be served. */
    return IS_SUPPORT_DTLS13(ctx->config.tlsConfig.version) &&
        !IS_SUPPORT_DTLS12(ctx->config.tlsConfig.version) &&
        ctx->config.tlsConfig.isSupportConnectionId;
}

/*
 * Server-side processing of ClientHello connection_id. HRR does not finalize CID
 * negotiation; the final ClientHello must be processed after HRR completes.
 *
 * Although the connection_id extension is defined for both DTLS 1.2 (RFC 9146)
 * and DTLS 1.3 (RFC 9147), this implementation only supports the DTLS 1.3
 * unified header record-layer encoding. When the negotiated version is not
 * DTLS 1.3, ignore the extension: do not enter NEGOTIATED, so the ServerHello
 * will not echo connection_id. The client then observes "no extension in
 * ServerHello" and treats CID as not negotiated.
 */
int32_t DTLS_CID_ProcessClientHello(TLS_Ctx *ctx, bool haveConnectionId, const uint8_t *connectionId,
                                    uint8_t connectionIdLen, bool isNeedSendHrr)
{
    if ((connectionIdLen > 0 && connectionId == NULL) || (connectionIdLen == 0 && connectionId != NULL)) {
        return HITLS_INVALID_INPUT;
    }
    if (isNeedSendHrr) {
        return HITLS_SUCCESS;
    }
    /* isCidNegotiated is the single source of truth for whether the server echoes
     * connection_id. It is not reset here: it defaults to false and is set true
     * only in the finalize step below, so it correctly reflects the current
     * ClientHello. (This function may be re-entered during DTLS retransmission;
     * clobbering isCidNegotiated would break the record layer mid-connection.)
     * No send-list cleanup is needed here either: cidCtx is still NULL at this
     * point (the slot table is materialized only by post-handshake CID update),
     * and peerCidEntry is re-memset in the finalize step below. */
    if (!haveConnectionId || !ctx->config.tlsConfig.isSupportConnectionId) {
        return HITLS_SUCCESS;
    }
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13) {
        /* DTLS 1.2 (RFC 9146) record-layer CID is not implemented; do not echo. */
        return HITLS_SUCCESS;
    }

    /* Finalize negotiation: fill the peer send CID from the ClientHello connection_id extension
     * and mark CID negotiated. Only the inline peerCidEntry is armed; the heap slot table stays
     * NULL until the first post-handshake CID update. */
    (void)memset(&ctx->negotiatedInfo.peerCidEntry, 0, sizeof(ctx->negotiatedInfo.peerCidEntry));
    ctx->negotiatedInfo.peerCidEntry.cidLen = connectionIdLen;
    if (connectionIdLen > 0) {
        (void)memcpy(ctx->negotiatedInfo.peerCidEntry.cidVal, connectionId, connectionIdLen);
    }
    ctx->negotiatedInfo.isCidNegotiated = true;
    return HITLS_SUCCESS;
}

/*
 * Client-side processing of ServerHello connection_id. If the server omits the
 * extension, CID is disabled for this connection even if the client offered it.
 */
int32_t DTLS_CID_ProcessServerHello(TLS_Ctx *ctx, bool haveConnectionId, const uint8_t *connectionId,
                                    uint8_t connectionIdLen)
{
    if ((connectionIdLen > 0 && connectionId == NULL) || (connectionIdLen == 0 && connectionId != NULL)) {
        return HITLS_INVALID_INPUT;
    }
    /*
     * "Client did not offer connection_id yet server echoed it" is already rejected upstream:
     * ParseServerExtension() runs GetExtensionFlagValue() on every server extension before its
     * body is parsed, and connection_id is parsed iff extFlag.haveConnectionId is true (i.e. the
     * client actually sent it). Reaching here with haveConnectionId=true therefore implies the
     * client offered CID, which (via DTLS_CID_NeedCidExtForClientHello) implies
     * config.isSupportConnectionId. An isSupportConnectionId gate here would be unreachable, so
     * it is intentionally omitted.
     */
    if (!haveConnectionId) {
        /* Server omitted connection_id: CID is not negotiated for this connection. No cleanup is
         * needed — isCidNegotiated / peerCidEntry / cidCtx are still in their zero-initialized
         * state (the ctx is memset to 0 on creation, and on the client side they are only ever
         * written by the haveConnectionId=true branch above or by post-handshake CID update,
         * neither of which has run yet). */
        return HITLS_SUCCESS;
    }
    /* Finalize negotiation: fill the peer send CID from the ServerHello connection_id extension
     * and mark CID negotiated. Only the inline peerCidEntry is armed; the heap slot table stays
     * NULL until the first post-handshake CID update. */
    (void)memset(&ctx->negotiatedInfo.peerCidEntry, 0, sizeof(ctx->negotiatedInfo.peerCidEntry));
    ctx->negotiatedInfo.peerCidEntry.cidLen = connectionIdLen;
    if (connectionIdLen > 0) {
        (void)memcpy(ctx->negotiatedInfo.peerCidEntry.cidVal, connectionId, connectionIdLen);
    }
    ctx->negotiatedInfo.isCidNegotiated = true;
    return HITLS_SUCCESS;
}

bool DTLS_CID_IsExpectedCid(const TLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen)
{
    if (ctx == NULL || (cidLen > 0 && cid == NULL)) {
        return false;
    }
    const TLS_NegotiatedInfo *ni = &ctx->negotiatedInfo;
    if (ni->cidCtx != NULL) {
        for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
            const DTLS_CidRecvSlot *slot = &ni->cidCtx->recvSlots[i];
            if ((slot->state == DTLS_CID_RECV_SLOT_ACTIVE || slot->state == DTLS_CID_RECV_SLOT_DEPRECATING) &&
                DTLS_CID_IsEq(slot->entry.cidVal, slot->entry.cidLen, cid, cidLen)) {
                return true;
            }
        }
        return false;
    }
    /* Inline fallback: match against the single primary local CID. */
    return DTLS_CID_IsEq(ni->localCidEntry.cidVal, ni->localCidEntry.cidLen, cid, cidLen);
}

#endif /* HITLS_TLS_FEATURE_DTLS_CID */
