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
#include "tls.h"
#ifdef HITLS_TLS_FEATURE_DTLS_CID
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_ctx.h"
#include "pack.h"

/*
 * RFC 9147 Section 9 NewConnectionId wire format:
 *   ConnectionId cids<0..2^16-1>;   (2-byte length prefix + list of ConnectionId)
 *   ConnectionIdUsage usage;        (1 byte)
 *
 * Each ConnectionId = opaque<0..2^8-1> = 1-byte length prefix + CID bytes
 *
 * HITLS_NewConnectionId has already written the candidate CIDs into recv slots
 * and recorded them in cidWrittenMask. Packing walks the mask, computes the
 * total wire length up front, reserves the whole region in one shot, then
 * streams [cidLen][cidVal] directly out of each slot followed by the usage
 * byte. No intermediate heap buffer is involved.
 */
int32_t PackNewConnectionId(TLS_Ctx *ctx, PackPacket *pkt)
{
    /* cidCtx is materialized by HITLS_NewConnectionId before this pack runs. */
    DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    uint16_t mask = cidCtx->cidWrittenMask;

    /* Walk the mask once to compute the total ConnectionId vector body length. */
    uint32_t cidsLen = 0;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if ((mask & (uint16_t)(1u << i)) == 0) {
            continue;
        }
        const DTLS_CidRecvSlot *slot = &cidCtx->recvSlots[i];
        cidsLen += 1u + (uint32_t)slot->entry.cidLen;
    }
    if (cidsLen > UINT16_MAX) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17389, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "cidsLen = %d which exceeds 65535 bytes.", cidsLen, 0, 0, 0);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    /* Reserve the full wire footprint up front; subsequent PackAppend* calls
     * then operate inside a guaranteed-enough buffer and cannot fail. */
    uint32_t reserveLen = sizeof(uint16_t) + cidsLen + sizeof(uint8_t);
    int32_t ret = PackReserveBytes(pkt, reserveLen, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, (uint16_t)cidsLen);

    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if ((mask & (uint16_t)(1u << i)) == 0) {
            continue;
        }
        const DTLS_CidRecvSlot *slot = &cidCtx->recvSlots[i];
        (void)PackAppendUint8ToBuf(pkt, slot->entry.cidLen);
        if (slot->entry.cidLen > 0) {
            (void)PackAppendDataToBuf(pkt, slot->entry.cidVal, slot->entry.cidLen);
        }
    }

    (void)PackAppendUint8ToBuf(pkt, cidCtx->cidUsage);
    cidCtx->cidWrittenMask = 0;
    cidCtx->cidUsage = 0;
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_FEATURE_DTLS_CID */
