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

#include <stdint.h>
#include <string.h>
#include "hitls_build.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls_binlog_id.h"
#include "rec.h"
#include "record.h"

#ifdef HITLS_TLS_PROTO_DTLS13
#define DTLS13_GET_ACK_LIST(recCtx, type) \
    (((type) == REC_DTLS13_ACK_RETRANS) ? &(recCtx)->retransAckList : &(recCtx)->ackList)

static int32_t CompareRecordNumber(const RecordNumber *lhs, const RecordNumber *rhs)
{
    if (lhs->epoch != rhs->epoch) {
        return (lhs->epoch < rhs->epoch) ? -1 : 1;
    }
    if (lhs->sequenceNumber == rhs->sequenceNumber) {
        return 0;
    }
    return (lhs->sequenceNumber < rhs->sequenceNumber) ? -1 : 1;
}

static int32_t Dtls13AckListEnsureCap(Dtls13AckList *list)
{
    REC_DYN_ARRAY_GROW(list->records, list->count, list->cap, RecordNumber, REC_DTLS13_ACK_LIST_MAX_COUNT);
    return HITLS_SUCCESS;
}

static int32_t Dtls13AckListAppendInternal(Dtls13AckList *list, const RecordNumber *recordNum)
{
    uint32_t insertPos = list->count;
    for (uint32_t i = 0; i < list->count; i++) {
        int32_t cmp = CompareRecordNumber(&list->records[i], recordNum);
        if (cmp == 0) {
            return HITLS_SUCCESS;
        }
        if (cmp > 0) {
            insertPos = i;
            break;
        }
    }
    if (list->count >= REC_DTLS13_ACK_LIST_MAX_COUNT) {
        return HITLS_SUCCESS;
    }
    int32_t ret = Dtls13AckListEnsureCap(list);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    for (uint32_t i = list->count; i > insertPos; i--) {
        list->records[i] = list->records[i - 1];
    }
    list->records[insertPos] = *recordNum;
    list->count++;
    return HITLS_SUCCESS;
}

int32_t REC_Dtls13AckListAppend(TLS_Ctx *ctx, const RecordNumber *recordNum)
{
    REC_Ctx *recCtx = ctx->recCtx;
    if (recCtx == NULL || recordNum == NULL) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret = Dtls13AckListAppendInternal(&recCtx->ackList, recordNum);
    if (ret != HITLS_SUCCESS || recordNum->epoch != 2) {
        return ret;
    }
    return Dtls13AckListAppendInternal(&recCtx->retransAckList, recordNum);
}

void REC_Dtls13AckListClear(TLS_Ctx *ctx, REC_Dtls13AckListType type)
{
    REC_Ctx *recCtx = ctx->recCtx;
    if (recCtx == NULL) {
        return;
    }
    DTLS13_GET_ACK_LIST(recCtx, type)->count = 0;
}

bool REC_Dtls13AckListIsEmpty(const TLS_Ctx *ctx, REC_Dtls13AckListType type)
{
    const REC_Ctx *recCtx = ctx->recCtx;
    if (recCtx == NULL) {
        return true;
    }
    const Dtls13AckList *list = DTLS13_GET_ACK_LIST(recCtx, type);
    return list->count == 0;
}

static void Dtls13EncodeAckItems(const Dtls13AckList *list, uint8_t *buf, uint32_t baseOffset)
{
    for (uint32_t i = 0; i < list->count; i++) {
        uint32_t offset = baseOffset + i * REC_DTLS13_ACK_ITEM_LEN;
        BSL_Uint64ToByte(list->records[i].epoch, &buf[offset]);
        BSL_Uint64ToByte(list->records[i].sequenceNumber, &buf[offset + sizeof(uint64_t)]);
    }
}

static int32_t Dtls13FlushAckRecord(TLS_Ctx *ctx)
{
#ifdef HITLS_TLS_FEATURE_FLIGHT
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        return REC_FlightTransmit(ctx);
    }
#else
    (void)ctx;
#endif
    return HITLS_SUCCESS;
}

int32_t REC_Dtls13SendAck(TLS_Ctx *ctx, REC_Dtls13AckListType type)
{
    REC_Ctx *recCtx = ctx->recCtx;
    if (recCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17385, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "recCtx is null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    const Dtls13AckList *list = DTLS13_GET_ACK_LIST(recCtx, type);
    if (list->count == 0) {
        return HITLS_SUCCESS;
    }
    uint32_t ackDataLen = list->count * REC_DTLS13_ACK_ITEM_LEN;
    uint32_t dataLen = sizeof(uint16_t) + ackDataLen;
    uint8_t *buf = (uint8_t *)BSL_SAL_Calloc(1u, dataLen);
    if (buf == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    BSL_Uint16ToByte((uint16_t)ackDataLen, buf);
    Dtls13EncodeAckItems(list, buf, sizeof(uint16_t));
    int32_t ret = REC_Write(ctx, REC_TYPE_ACK, buf, dataLen);
    BSL_SAL_FREE(buf);
    if (ret == HITLS_SUCCESS) {
        ret = Dtls13FlushAckRecord(ctx);
    }
    if (ret == HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17387, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "dtls1.3 send ack success", 0, 0, 0, 0);
    }
    return ret;
}

void REC_Dtls13SetNeedSendRetransAck(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->recCtx == NULL) {
        return;
    }
    ctx->recCtx->needSendRetransAck = true;
}

int32_t REC_Dtls13FlushAck(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13) {
        return HITLS_SUCCESS;
    }
    if (ctx->recCtx == NULL) {
        return HITLS_NULL_INPUT;
    }
    REC_Ctx *recCtx = ctx->recCtx;
    if (recCtx->needSendRetransAck) {
        int32_t ret = REC_Dtls13SendAck(ctx, REC_DTLS13_ACK_RETRANS);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        recCtx->needSendRetransAck = false;
    }
    if (!REC_Dtls13AckListIsEmpty(ctx, REC_DTLS13_ACK_NORMAL)) {
        int32_t ret = REC_Dtls13SendAck(ctx, REC_DTLS13_ACK_NORMAL);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        REC_Dtls13AckListClear(ctx, REC_DTLS13_ACK_NORMAL);
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS13 */
