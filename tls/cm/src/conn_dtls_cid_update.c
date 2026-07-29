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
#include "tls.h"
#include "hs.h"
#include "hs_common.h"
#include "conn_common.h"
#include "rec.h"
#include "dtls_cid.h"

static int32_t CheckCidPostHandshakeState(const HITLS_Ctx *ctx, uint8_t cidState)
{
    /* ctx is guaranteed non-NULL by the caller (HITLS_RequestConnectionId /
     * HITLS_NewConnectionId both null-check before invoking). */
    /* RequestConnectionId / NewConnectionId are DTLS 1.3-only (RFC 9147 §6). */
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17390, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "cid post-handshake rejected: not DTLS 1.3.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }
    /* Accept TRANSPORTING, or re-entry from onRecvRequestCidCb. */
    bool validState = (ctx->state == CM_STATE_TRANSPORTING) ||
                      (ctx->state == CM_STATE_HANDSHAKING && HS_GetState(ctx) == TRY_RECV_REQUEST_CONNECTION_ID);
    if (!validState) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17391, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "cid post-handshake rejected: connection not in TRANSPORTING state.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    if (!ctx->negotiatedInfo.isCidNegotiated) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17392, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "cid post-handshake rejected: connection_id not negotiated.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    if (cidState != DTLS_CID_MSG_STATE_IDLE) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17398, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "cid post-handshake rejected: another CID post-handshake is already pending.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    return HITLS_SUCCESS;
}

static int32_t CheckNewConnectionIdInput(const HITLS_Ctx *ctx, const HITLS_DtlsCidEntry *inCids, uint8_t num)
{
    uint8_t localCidLen = ctx->negotiatedInfo.localCidEntry.cidLen;
    for (uint8_t i = 0; i < num; i++) {
        if (inCids[i].cidLen != localCidLen) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17395, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
                                  "input cid length[%d] mismatch previous length [%d].", inCids[i].cidLen, localCidLen,
                                  0, 0);
            return HITLS_CONFIG_INVALID_LENGTH;
        }
        for (uint8_t j = 0; j < i; j++) {
            if (DTLS_CID_IsEq(inCids[j].cidVal, inCids[j].cidLen, inCids[i].cidVal, inCids[i].cidLen)) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17401, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
                                      "[%d]-th cid entry duplicates [%d]-th cid entry.", i, j, 0, 0);
                return HITLS_INVALID_INPUT;
            }
        }
    }
    return HITLS_SUCCESS;
}

static int32_t CheckRecvSlotDuplicate(const TLS_Ctx *ctx, const HITLS_DtlsCidEntry *inCids, uint8_t num)
{
    const DTLS_CidRecvSlot *recvList = ctx->negotiatedInfo.cidCtx->recvSlots;
    for (uint8_t i = 0; i < num; i++) {
        for (uint8_t j = 0; j < HITLS_DTLS_CID_LIST_MAX; j++) {
            if (recvList[j].state != DTLS_CID_RECV_SLOT_FREE &&
                DTLS_CID_IsEq(recvList[j].entry.cidVal, recvList[j].entry.cidLen, inCids[i].cidVal, inCids[i].cidLen)) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17400, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
                                      "[%d]-th cid entry duplicates an existing recv slot.", i, 0, 0, 0);
                return HITLS_INVALID_INPUT;
            }
        }
    }
    return HITLS_SUCCESS;
}

/*
 * Materialize the heap 16-slot table on the first post-handshake CID operation.
 * Idempotent: returns SUCCESS immediately if already present.
 */
static int32_t GetOrCreateCidCtx(TLS_Ctx *ctx)
{
    TLS_NegotiatedInfo *ni = &ctx->negotiatedInfo;
    if (ni->cidCtx != NULL) {
        return HITLS_SUCCESS;
    }

    DTLS_CidCtx *cidCtx = (DTLS_CidCtx *)BSL_SAL_Calloc(1, sizeof(DTLS_CidCtx));
    if (cidCtx == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    cidCtx->currentSendIdx = HITLS_DTLS_CID_NO_IDX;

    cidCtx->recvSlots[0].state = DTLS_CID_RECV_SLOT_ACTIVE;
    cidCtx->recvSlots[0].entry = ni->localCidEntry;

    if (ni->peerCidEntry.cidLen > 0) {
        cidCtx->sendSlots[0].state = DTLS_CID_SEND_SLOT_INUSE;
        cidCtx->sendSlots[0].entry = ni->peerCidEntry;
        cidCtx->currentSendIdx = 0;
    }

    ni->cidCtx = cidCtx;
    return HITLS_SUCCESS;
}

static void BeginImmediateRetire(TLS_Ctx *ctx)
{
    DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    if (cidCtx == NULL) {
        return;
    }
    DTLS_CidRecvSlot *recvList = cidCtx->recvSlots;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (recvList[i].state == DTLS_CID_RECV_SLOT_ACTIVE) {
            recvList[i].state = DTLS_CID_RECV_SLOT_DEPRECATING;
        }
    }
}

/* ctx is guaranteed non-NULL by the record-layer ACK callback invocation. */
int32_t DTLS_CID_OnNewConnectionIdAcked(TLS_Ctx *ctx)
{
    if (ctx->newCidState == DTLS_CID_MSG_STATE_SENT) {
        ctx->newCidState = DTLS_CID_MSG_STATE_IDLE;
    }

    DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    if (cidCtx == NULL) {
        return HITLS_SUCCESS;
    }

    DTLS_CidRecvSlot *recvList = cidCtx->recvSlots;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (recvList[i].state == DTLS_CID_RECV_SLOT_DEPRECATING) {
            (void)memset(&recvList[i], 0, sizeof(recvList[i]));
        }
    }
    return HITLS_SUCCESS;
}

/* ctx is guaranteed non-NULL by the record-layer ACK callback invocation. */
int32_t DTLS_CID_OnRequestConnectionIdAcked(TLS_Ctx *ctx)
{
    if (ctx->reqCidState == DTLS_CID_MSG_STATE_SENT) {
        ctx->reqCidState = DTLS_CID_MSG_STATE_IDLE;
    }
    return HITLS_SUCCESS;
}

/*
 * Commit a pre-validated batch of new local CIDs into the recv slot table.
 * Infallible: the caller has already verified lengths, duplicates, and that
 * at least `num` FREE slots exist. Records the written slot indices in
 * *writtenMask, which is the source of truth for the outgoing NewConnectionId
 * pack stage.
 */
static void CommitRecvCids(TLS_Ctx *ctx, const HITLS_DtlsCidEntry *inCids, uint8_t num, HITLS_DtlsCidUsage usage,
                           uint16_t *writtenMask)
{
    *writtenMask = 0;
    if (usage == HITLS_DTLS_CID_IMMEDIATE) {
        /* Keep old recv CIDs alive until the caller marks the update acknowledged. */
        BeginImmediateRetire(ctx);
    }
    DTLS_CidRecvSlot *recvList = ctx->negotiatedInfo.cidCtx->recvSlots;
    uint8_t localCidLen = ctx->negotiatedInfo.localCidEntry.cidLen;
    for (uint8_t i = 0; i < num; i++) {
        uint8_t idx = HITLS_DTLS_CID_NO_IDX;
        for (uint8_t j = 0; j < HITLS_DTLS_CID_LIST_MAX; j++) {
            if (recvList[j].state == DTLS_CID_RECV_SLOT_FREE) {
                idx = j;
                break;
            }
        }
        /* idx is guaranteed non-NO_IDX here: the caller caps num <= freeCount
         * (FREE slots counted at entry, see the accepted = min(requested, freeCount)
         * clamp), and each outer iteration consumes exactly one FREE slot. So on
         * iteration i (i <= num-1 <= freeCount-1) at least one FREE slot remains and
         * the inner loop always assigns idx before reaching here. */
        (void)memset(&recvList[idx], 0, sizeof(recvList[idx]));
        recvList[idx].state = DTLS_CID_RECV_SLOT_ACTIVE;
        /* inCids[i].cidLen is guaranteed to be equal to localCidLen by the caller's pre-validation. */
        recvList[idx].entry.cidLen = localCidLen;
        (void)memcpy(recvList[idx].entry.cidVal, inCids[i].cidVal, localCidLen);
        *writtenMask |= (uint16_t)(1u << idx);
    }
}

/*
 * Lazily dispatch a pending CID post-handshake send. Mirrors FEATURE_PHA's
 * CommonCheckPostHandshakeAuth: HITLS_NewConnectionId / HITLS_RequestConnectionId
 * only arm the CID sub-state machine (newCidState / reqCidState = PENDING) and
 * MUST NOT touch the handshake state. The actual TRY_SEND_* transition is done
 * here, on the next IO cycle, and only when the connection is quiescent
 * (TRANSPORTING). This prevents clobbering an in-flight hsCtx->state -- most
 * importantly when one of those APIs is invoked from the RequestConnectionId
 * recv callback while the recv state machine is still active.
 *
 * NewConnectionId takes precedence over RequestConnectionId when both are armed;
 * the loser is serviced on a later cycle once the connection is TRANSPORTING
 * again. CommonEventInHandshakingState frees hsCtx once a handshake completes,
 * so when the connection is quiescent hsCtx is usually NULL and HS_Init here
 * allocates a fresh one (same as FEATURE_PHA's CommonCheckPostHandshakeAuth).
 */
int32_t CommonCheckPostHandshakeCid(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    /* A handshake / post-handshake is in flight: wait. The armed flag survives
     * and is serviced once the connection returns to TRANSPORTING. */
    if (ctx->state != CM_STATE_TRANSPORTING) {
        return HITLS_SUCCESS;
    }
    if (ctx->newCidState == DTLS_CID_MSG_STATE_PENDING) {
        int32_t ret = HS_Init(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        ChangeConnState(ctx, CM_STATE_HANDSHAKING);
        return HS_ChangeState(ctx, TRY_SEND_NEW_CONNECTION_ID);
    }
    if (ctx->reqCidState == DTLS_CID_MSG_STATE_PENDING) {
        int32_t ret = HS_Init(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        ChangeConnState(ctx, CM_STATE_HANDSHAKING);
        return HS_ChangeState(ctx, TRY_SEND_REQUEST_CONNECTION_ID);
    }
    return HITLS_SUCCESS;
}

/*
 * Public API to ask the peer for fresh CIDs. Only validates state and arms
 * newCidState = PENDING; the actual TRY_SEND_REQUEST_CONNECTION_ID is dispatched
 * lazily by CommonCheckPostHandshakeCid on the next IO cycle.
 */
int32_t HITLS_RequestConnectionId(HITLS_Ctx *ctx, uint8_t numCids)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret = CheckCidPostHandshakeState(ctx, ctx->reqCidState);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (ctx->negotiatedInfo.peerCidEntry.cidLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17396, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "RequestConnectionId rejected: no peer send CID available.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }

    if (numCids == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17399, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "RequestConnectionId: no need to send record when num is zero.", 0, 0, 0, 0);
        return HITLS_SUCCESS;
    }

    ctx->reqCidNum = numCids;
    /* Only arm the CID sub-state machine; do NOT touch the handshake state.
     * The actual TRY_SEND_REQUEST_CONNECTION_ID transition is dispatched lazily
     * by CommonCheckPostHandshakeCid on the next IO cycle, mirroring FEATURE_PHA
     * (HITLS_VerifyClientPostHandshake). Calling HS_Init / HS_ChangeState here
     * would clobber an in-flight hsCtx->state, e.g. when this API is invoked
     * while another post-handshake message is being processed. */
    ctx->reqCidState = DTLS_CID_MSG_STATE_PENDING;
    return HITLS_SUCCESS;
}

/*
 * Public API to advertise new local CIDs to the peer.
 * recv-slot mutations are committed on success; the actual send is
 * deferred to the next HITLS_Write / HITLS_Connect / HITLS_Accept.
 */
int32_t HITLS_NewConnectionId(HITLS_Ctx *ctx, const HITLS_DtlsCidEntry *inCids, uint8_t *cidCount,
                              HITLS_DtlsCidUsage usage)
{
    if (ctx == NULL || cidCount == NULL) {
        return HITLS_NULL_INPUT;
    }
    uint8_t requested = *cidCount;
    if (requested > 0 && inCids == NULL) {
        return HITLS_INVALID_INPUT;
    }
    if (ctx->negotiatedInfo.localCidEntry.cidLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17394, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
                              "NewConnectionId rejected: no local recv CID configured.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    if (usage != HITLS_DTLS_CID_IMMEDIATE && usage != HITLS_DTLS_CID_SPARE) {
        return HITLS_INVALID_INPUT;
    }
    *cidCount = 0;
    int32_t ret = CheckCidPostHandshakeState(ctx, ctx->newCidState);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (requested == 0) {
        if (usage != HITLS_DTLS_CID_SPARE) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17402, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
                "NewConnectionId rejected: IMMEDIATE requires at least one CID.", 0, 0, 0, 0);
            return HITLS_INVALID_INPUT;
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17410, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "NewConnectionId: no need to send record when num is zero and usage is spare.", 0, 0, 0, 0);
        return HITLS_SUCCESS;
    }

    /* Materialize the heap slot table on the first post-handshake CID operation. */
    ret = GetOrCreateCidCtx(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    uint8_t freeCount = 0;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (cidCtx->recvSlots[i].state == DTLS_CID_RECV_SLOT_FREE) {
            freeCount++;
        }
    }
    /* SPARE can be truncated to the available slots; IMMEDIATE needs at least one slot. */
    uint8_t accepted = (requested < freeCount) ? requested : freeCount;
    if (accepted == 0) {
        if (usage == HITLS_DTLS_CID_SPARE) {
            return HITLS_SUCCESS;
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17403, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "NewConnectionId rejected: recv CID slot list is full.", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }

    ret = CheckNewConnectionIdInput(ctx, inCids, accepted);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = CheckRecvSlotDuplicate(ctx, inCids, accepted);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint16_t writtenMask = 0;
    CommitRecvCids(ctx, inCids, accepted, usage, &writtenMask);
    cidCtx->cidWrittenMask = writtenMask;
    cidCtx->cidUsage = (uint8_t)usage;
    /* Only arm the CID sub-state machine; do NOT touch the handshake state.
     * The actual TRY_SEND_NEW_CONNECTION_ID transition is dispatched lazily by
     * CommonCheckPostHandshakeCid on the next IO cycle, mirroring FEATURE_PHA
     * (HITLS_VerifyClientPostHandshake). Calling HS_Init / HS_ChangeState here
     * would clobber an in-flight hsCtx->state -- most importantly when this API
     * is invoked from the RequestConnectionId recv callback while the recv
     * state machine is still active. The recv-slot mutations above stay
     * committed; the peer learns the new CIDs only once the message is sent. */
    ctx->newCidState = DTLS_CID_MSG_STATE_PENDING;
    *cidCount = accepted;
    return HITLS_SUCCESS;
}

static int32_t DtlsCidWriteSendSlot(TLS_Ctx *ctx, uint8_t idx, const uint8_t *cid, uint8_t cidLen, uint8_t state)
{
    DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    DTLS_CidSendSlot *slot = &cidCtx->sendSlots[idx];
    (void)memset(slot, 0, sizeof(*slot));
    slot->state = state;
    slot->entry.cidLen = cidLen;
    if (cidLen > 0) {
        (void)memcpy(slot->entry.cidVal, cid, cidLen);
    }
    if (state == DTLS_CID_SEND_SLOT_INUSE) {
        cidCtx->currentSendIdx = idx;
        /* Keep peerCidEntry in sync with the INUSE send slot. */
        ctx->negotiatedInfo.peerCidEntry = slot->entry;
    }
    return HITLS_SUCCESS;
}

static bool DtlsCidIsInSendList(const TLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen)
{
    const DTLS_CidSendSlot *sendList = ctx->negotiatedInfo.cidCtx->sendSlots;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (sendList[i].state != DTLS_CID_SEND_SLOT_FREE &&
            DTLS_CID_IsEq(sendList[i].entry.cidVal, sendList[i].entry.cidLen, cid, cidLen)) {
            return true;
        }
    }
    return false;
}

/*
 * IMMEDIATE process: replace the whole send slot table. The send table is wiped
 * of any prior state (including a SwitchSendCid-selected INUSE) first, so
 * entries can be written into contiguous slots starting at 0. Slot 0 becomes
 * INUSE (the active outbound CID); the rest become UNUSED spares. Entries
 * beyond HITLS_DTLS_CID_LIST_MAX are silently dropped.
 */
static int32_t DtlsCidProcessImmediate(TLS_Ctx *ctx, const uint8_t *cids, uint32_t cidsLen)
{
    TLS_NegotiatedInfo *ni = &ctx->negotiatedInfo;
    DTLS_CidCtx *cidCtx = ni->cidCtx;
    (void)memset(&ni->peerCidEntry, 0, sizeof(ni->peerCidEntry));
    (void)memset(cidCtx->sendSlots, 0, sizeof(DTLS_CidSendSlot) * HITLS_DTLS_CID_LIST_MAX);
    cidCtx->currentSendIdx = HITLS_DTLS_CID_NO_IDX;
    uint32_t offset = 0;
    /* RFC 9147 §9: cids is a variable-length vector (opaque<0..2^16-1>), so one
     * message may carry far more entries than the local table holds. Use
     * uint32_t for processed to avoid wraparound past 255. */
    uint32_t processed = 0;
    while (offset < cidsLen) {
        uint8_t cidLen = cids[offset++];
        if (processed < HITLS_DTLS_CID_LIST_MAX) {
            uint8_t state = (processed == 0) ? DTLS_CID_SEND_SLOT_INUSE : DTLS_CID_SEND_SLOT_UNUSED;
            int32_t ret = DtlsCidWriteSendSlot(ctx, (uint8_t)processed, &cids[offset], cidLen, state);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
        processed++;
        offset += cidLen;
    }
    return HITLS_SUCCESS;
}

/*
 * SPARE process: append without clearing. A CID already present in the send
 * list is skipped (de-dup). Otherwise pick a slot in eviction order
 * FREE (preferred) > USED > UNUSED; INUSE (the active outbound CID) is never
 * evicted. A slot is selected at most once per batch, so later entries cannot
 * overwrite CIDs added earlier in the same NewConnectionId. Only the first
 * HITLS_DTLS_CID_LIST_MAX entries of the batch are considered; entries that
 * have no unselected slot available, and the rest beyond the cap, are silently
 * discarded.
 */
static int32_t DtlsCidProcessSpare(TLS_Ctx *ctx, const uint8_t *cids, uint32_t cidsLen)
{
    DTLS_CidSendSlot *sendList = ctx->negotiatedInfo.cidCtx->sendSlots;
    uint32_t offset = 0;
    uint8_t processed = 0;
    uint16_t writtenMask = 0;
    while (offset < cidsLen) {
        if (processed >= HITLS_DTLS_CID_LIST_MAX) {
            break;  /* cap: consider at most HITLS_DTLS_CID_LIST_MAX new CIDs per batch */
        }
        uint8_t cidLen = cids[offset++];
        const uint8_t *cid = &cids[offset];
        offset += cidLen;
        if (DtlsCidIsInSendList(ctx, cid, cidLen)) {
            continue;  /* de-dup: duplicates don't consume a slot nor cap budget */
        }
        processed++;
        /* Pick the best slot in a single pass. DTLS_CidSendSlotState is ordered
         * by eviction preference (smaller = better: FREE=0 < USED=1 < UNUSED=2 <
         * INUSE=3), so the smallest state is the best candidate. Strict '<' keeps
         * the first slot of the best category; INUSE is skipped explicitly (the
         * active outbound CID is never evicted). Slots already written by this
         * batch are skipped, and the scan stops early on a FREE slot. */
        uint8_t target = HITLS_DTLS_CID_NO_IDX;
        uint8_t bestPreference = UINT8_MAX;
        for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
            if ((writtenMask & (uint16_t)(1u << i)) != 0) {
                continue;
            }
            uint8_t preference = sendList[i].state;   /* read this slot's preference rank */
            if (preference == DTLS_CID_SEND_SLOT_INUSE) {
                continue;                             /* never evict the active outbound CID */
            }
            if (preference < bestPreference) {
                bestPreference = preference;          /* record the new best rank */
                target = i;
                if (preference == DTLS_CID_SEND_SLOT_FREE) {
                    break;
                }
            }
        }
        if (target == HITLS_DTLS_CID_NO_IDX) {
            continue;  /* every evictable slot was already filled by this batch */
        }
        int32_t ret = DtlsCidWriteSendSlot(ctx, target, cid, cidLen, DTLS_CID_SEND_SLOT_UNUSED);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        writtenMask |= (uint16_t)(1u << target);
    }
    return HITLS_SUCCESS;
}

int32_t DTLS_CID_ProcessPeerNewConnectionId(TLS_Ctx *ctx, const uint8_t *cids, uint32_t cidsLen, uint8_t usage)
{
    /* usage is parser-guaranteed to be IMMEDIATE or SPARE; an empty CID list can
     * only occur with SPARE (the parser rejects IMMEDIATE + empty), so just
     * return without touching the send list. */
    if (cidsLen == 0) {
        return HITLS_SUCCESS;
    }

    /* Inbound NewConnectionId mutates the send slot list; materialize it first. */
    int32_t ret = GetOrCreateCidCtx(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* The wire shape (non-truncated, self-consistent length) was already proven
     * by ParseNewConnectionId on this exact buffer, so the helpers walk it raw. */
    return (usage == HITLS_DTLS_CID_IMMEDIATE) ? DtlsCidProcessImmediate(ctx, cids, cidsLen)
                                               : DtlsCidProcessSpare(ctx, cids, cidsLen);
}

/*
 * Resolve the send slot to switch to. If cid is NULL (automatic mode) pick the
 * first UNUSED slot; otherwise match the caller-supplied CID against any
 * non-FREE slot (including USED, which the caller recycles back to INUSE). Logs
 * the reason and returns HITLS_DTLS_CID_NO_IDX if nothing matches.
 */
static uint8_t DtlsCidFindSwitchTarget(const DTLS_CidSendSlot *sendList,
                                       const uint8_t *cid, uint8_t cidLen)
{
    if (cid == NULL) {
        for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
            if (sendList[i].state == DTLS_CID_SEND_SLOT_UNUSED) {
                return i;
            }
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17405, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "SwitchSendCid rejected: no unused send CID available.", 0, 0, 0, 0);
        return HITLS_DTLS_CID_NO_IDX;
    }
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (sendList[i].state != DTLS_CID_SEND_SLOT_FREE &&
            DTLS_CID_IsEq(sendList[i].entry.cidVal, sendList[i].entry.cidLen, cid, cidLen)) {
            return i;
        }
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17406, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "SwitchSendCid rejected: specified send CID not found.", 0, 0, 0, 0);
    return HITLS_DTLS_CID_NO_IDX;
}

int32_t HITLS_SwitchSendCid(HITLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen)
{
    if (ctx == NULL || (cid != NULL && cidLen == 0) || (cid == NULL && cidLen != 0)) {
        return HITLS_NULL_INPUT;
    }
    if (!ctx->negotiatedInfo.isCidNegotiated) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17397, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "SwitchSendCid rejected: connection_id not negotiated.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    if (cidCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17404, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "SwitchSendCid rejected: no send CID available.", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }
    DTLS_CidSendSlot *sendList = cidCtx->sendSlots;
    uint8_t target = DtlsCidFindSwitchTarget(sendList, cid, cidLen);
    if (target == HITLS_DTLS_CID_NO_IDX) {
        return HITLS_INVALID_INPUT;
    }

    uint8_t oldIdx = cidCtx->currentSendIdx;
    if (oldIdx < HITLS_DTLS_CID_LIST_MAX && sendList[oldIdx].state == DTLS_CID_SEND_SLOT_INUSE) {
        sendList[oldIdx].state = DTLS_CID_SEND_SLOT_USED;
    }
    sendList[target].state = DTLS_CID_SEND_SLOT_INUSE;
    cidCtx->currentSendIdx = target;
    /* Keep peerCidEntry in sync with the INUSE send slot. */
    ctx->negotiatedInfo.peerCidEntry = sendList[target].entry;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetRecvRequestConnectionIdCb(HITLS_Ctx *ctx, HITLS_RecvRequestConnectionIdCb cb, void *userData)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    ctx->onRecvRequestCidCb = cb;
    ctx->onRecvRequestCidUserData = userData;
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_FEATURE_DTLS_CID */
