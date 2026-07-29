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

#include <string.h>
#include "hitls_build.h"
#include "bsl_sal.h"
#include "bsl_module_list.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "tls_binlog_id.h"
#include "hitls_error.h"
#include "rec.h"
#include "bsl_uio.h"
#include "record.h"
#include "hs.h"
#include "hs_msg.h"
#include "hs_dtls_timer.h"

#if defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP)
#ifdef HITLS_TLS_PROTO_DTLS13
static void Dtls13AckStateInitList(Dtls13AckState *state)
{
    BSL_LIST_INIT(&state->gaps);
    state->totalLen = 0;
    state->unackedBytes = 0;
    state->seqMap = NULL;
    state->seqMapSize = 0;
    state->seqMapCap = 0;
}

int32_t AckStateInit(Dtls13AckState *state, uint32_t len)
{
    if (state == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    Dtls13AckStateInitList(state);
    state->totalLen = len;
    state->unackedBytes = len;
    if (len == 0) {
        return HITLS_SUCCESS;
    }
    Dtls13GapNode *gap = (Dtls13GapNode *)BSL_SAL_Calloc(1u, sizeof(Dtls13GapNode));
    if (gap == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    BSL_LIST_INIT(&gap->head);
    gap->start = 0;
    gap->end = len;
    LIST_ADD_BEFORE(&state->gaps, &gap->head);
    return HITLS_SUCCESS;
}

void AckStateDeinit(Dtls13AckState *state)
{
    if (state == NULL) {
        return;
    }
    ListHead *head = NULL;
    ListHead *tmp = NULL;
    LIST_FOR_EACH_ITEM_SAFE(head, tmp, &state->gaps) {
        Dtls13GapNode *gap = BSL_LIST_ENTRY(head, Dtls13GapNode, head);
        BSL_LIST_REMOVE(head);
        BSL_SAL_FREE(gap);
    }
    state->totalLen = 0;
    state->unackedBytes = 0;
    BSL_SAL_FREE(state->seqMap);
    state->seqMapSize = 0;
    state->seqMapCap = 0;
}

static int32_t AckStateUpdateRange(Dtls13AckState *state, uint32_t offset, uint32_t len)
{
    if (len == 0 || offset >= state->totalLen) {
        return HITLS_SUCCESS;
    }
    uint32_t ackStart = offset;
    uint32_t ackEnd = offset + len;
    if (ackEnd > state->totalLen || ackEnd < ackStart) {
        ackEnd = state->totalLen;
    }
    ListHead *head = NULL;
    ListHead *tmp = NULL;
    LIST_FOR_EACH_ITEM_SAFE(head, tmp, &state->gaps) {
        Dtls13GapNode *gap = BSL_LIST_ENTRY(head, Dtls13GapNode, head);
        if (gap->end <= ackStart) {
            continue;
        }
        if (gap->start >= ackEnd) {
            break;
        }
        uint32_t overlapStart = gap->start > ackStart ? gap->start : ackStart;
        uint32_t overlapEnd = gap->end < ackEnd ? gap->end : ackEnd;
        if (overlapStart >= overlapEnd) {
            continue;
        }
        if (overlapStart == gap->start && overlapEnd == gap->end) {
            state->unackedBytes -= (overlapEnd - overlapStart);
            BSL_LIST_REMOVE(&gap->head);
            BSL_SAL_FREE(gap);
            continue;
        }
        if (overlapStart == gap->start) {
            state->unackedBytes -= (overlapEnd - overlapStart);
            gap->start = overlapEnd;
            continue;
        }
        if (overlapEnd == gap->end) {
            state->unackedBytes -= (overlapEnd - overlapStart);
            gap->end = overlapStart;
            continue;
        }
        Dtls13GapNode *newGap = (Dtls13GapNode *)BSL_SAL_Calloc(1u, sizeof(Dtls13GapNode));
        if (newGap == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        state->unackedBytes -= (overlapEnd - overlapStart);
        BSL_LIST_INIT(&newGap->head);
        newGap->start = overlapEnd;
        newGap->end = gap->end;
        gap->end = overlapStart;
        LIST_ADD_AFTER(&gap->head, &newGap->head);
    }
    return HITLS_SUCCESS;
}

static int32_t Dtls13FragmentListAppend(Dtls13FragmentList *list, uint32_t offset, uint32_t len)
{
    if (list->count == list->cap) {
        uint32_t newCap = (list->cap == 0) ? 4u : (list->cap * 2u);
        Dtls13FragmentRange *newFrags = (Dtls13FragmentRange *)BSL_SAL_Calloc(newCap, sizeof(Dtls13FragmentRange));
        if (newFrags == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        if (list->frags != NULL) {
            (void)memcpy(newFrags, list->frags, list->count * sizeof(Dtls13FragmentRange));
            BSL_SAL_FREE(list->frags);
        }
        list->frags = newFrags;
        list->cap = newCap;
    }
    list->frags[list->count].offset = offset;
    list->frags[list->count].len = len;
    list->count++;
    return HITLS_SUCCESS;
}

static void Dtls13FragmentListDeinit(Dtls13FragmentList *list)
{
    if (list == NULL) {
        return;
    }
    BSL_SAL_FREE(list->frags);
    list->frags = NULL;
    list->count = 0;
    list->cap = 0;
}

int32_t AckStateGetFragment(const Dtls13AckState *state, uint32_t maxFragmentLen, Dtls13FragmentList *list)
{
    if (state == NULL || list == NULL || maxFragmentLen == 0) {
        return HITLS_NULL_INPUT;
    }
    list->count = 0;
    ListHead *head = NULL;
    ListHead *tmp = NULL;
    LIST_FOR_EACH_ITEM_SAFE(head, tmp, &state->gaps) {
        Dtls13GapNode *gap = BSL_LIST_ENTRY(head, Dtls13GapNode, head);
        uint32_t cur = gap->start;
        while (cur < gap->end) {
            uint32_t fragLen = (gap->end - cur > maxFragmentLen) ? maxFragmentLen : (gap->end - cur);
            int32_t ret = Dtls13FragmentListAppend(list, cur, fragLen);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            cur += fragLen;
        }
    }
    return HITLS_SUCCESS;
}

int32_t AckStateInsertSeqMap(Dtls13AckState *state, const RecordNumber *recordNum, uint32_t offset, uint32_t len)
{
    if (state == NULL || recordNum == NULL) {
        return HITLS_NULL_INPUT;
    }
    for (uint32_t i = 0; i < state->seqMapSize; i++) {
        if (state->seqMap[i].valid && state->seqMap[i].recordNumber.epoch == recordNum->epoch &&
            state->seqMap[i].recordNumber.sequenceNumber == recordNum->sequenceNumber) {
            return HITLS_SUCCESS;
        }
    }
    if (state->seqMapSize == state->seqMapCap) {
        uint32_t newCap = (state->seqMapCap == 0) ? 4u : (state->seqMapCap * 2u);
        Dtls13SeqMapEntry *newMap = (Dtls13SeqMapEntry *)BSL_SAL_Calloc(newCap, sizeof(Dtls13SeqMapEntry));
        if (newMap == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        if (state->seqMap != NULL) {
            (void)memcpy(newMap, state->seqMap, state->seqMapSize * sizeof(Dtls13SeqMapEntry));
            BSL_SAL_FREE(state->seqMap);
        }
        state->seqMap = newMap;
        state->seqMapCap = newCap;
    }
    state->seqMap[state->seqMapSize].recordNumber = *recordNum;
    state->seqMap[state->seqMapSize].frag.offset = offset;
    state->seqMap[state->seqMapSize].frag.len = len;
    state->seqMap[state->seqMapSize].valid = true;
    state->seqMapSize++;
    return HITLS_SUCCESS;
}

int32_t AckStateProcessAck(Dtls13AckState *state, const RecordNumber *recordNum)
{
    if (state == NULL || recordNum == NULL) {
        return HITLS_NULL_INPUT;
    }
    for (uint32_t i = 0; i < state->seqMapSize; i++) {
        if (state->seqMap[i].valid && state->seqMap[i].recordNumber.epoch == recordNum->epoch &&
            state->seqMap[i].recordNumber.sequenceNumber == recordNum->sequenceNumber) {
            return AckStateUpdateRange(state, state->seqMap[i].frag.offset, state->seqMap[i].frag.len);
        }
    }
    return HITLS_SUCCESS;
}

int32_t REC_RetransmitListProcessAck(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    if (dataLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    uint32_t ackDataLen = BSL_ByteToUint16(data);
    if (dataLen != sizeof(uint16_t) + ackDataLen || (ackDataLen % REC_DTLS13_ACK_ITEM_LEN) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    RecRetransmitList *retransmitList = &ctx->recCtx->retransmitList;
    uint32_t ackCount = ackDataLen / REC_DTLS13_ACK_ITEM_LEN;
    for (uint32_t i = 0; i < ackCount; i++) {
        uint32_t ackOffset = sizeof(uint16_t) + i * REC_DTLS13_ACK_ITEM_LEN;
        RecordNumber recordNum = {0};
        recordNum.epoch = BSL_ByteToUint64(&data[ackOffset]);
        recordNum.sequenceNumber = BSL_ByteToUint64(&data[ackOffset + sizeof(uint64_t)]);
        ListHead *head = NULL;
        ListHead *tmp = NULL;
        LIST_FOR_EACH_ITEM_SAFE(head, tmp, &retransmitList->head) {
            RecRetransmitList *node = BSL_LIST_ENTRY(head, RecRetransmitList, head);
            if (node->epoch != recordNum.epoch) {
                continue;
            }
            int32_t ret = AckStateProcessAck(&node->ackState, &recordNum);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            if (node->ackState.unackedBytes == 0) {
                REC_Dtls13RetransmitAckCb ackCb = node->ackCb;
                BSL_LIST_REMOVE(&node->head);
                AckStateDeinit(&node->ackState);
                BSL_SAL_FREE(node->msg);
                BSL_SAL_FREE(node);
                if (REC_RetransmitIsEmpty(ctx->recCtx) && ctx->recCtx->readEpoch > 2) {
                    HS_StopTimer(ctx);
                }
                if (ackCb != NULL) {
                    ret = ackCb(ctx);
                    if (ret != HITLS_SUCCESS) {
                        return ret;
                    }
                }
            }
        }
    }
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_PROTO_DTLS13 */

int32_t RecRetransmitListAppendNode(RecCtx *recCtx, REC_Type type, const uint8_t *msg, uint32_t len,
    RecRetransmitList **retransmitNodePtr)
{
    RecRetransmitList *retransmitList = &recCtx->retransmitList;
    RecRetransmitList *retransmitNode = (RecRetransmitList *)BSL_SAL_Calloc(1u, sizeof(RecRetransmitList));
    if (retransmitNode == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17277, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_LIST_INIT(&(retransmitNode->head));
    retransmitNode->type = type;
    retransmitNode->msg = BSL_SAL_Dump(msg, len);
    if (retransmitNode->msg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17278, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        BSL_SAL_FREE(retransmitNode);
        return HITLS_MEMALLOC_FAIL;
    }
    retransmitNode->len = len;
#ifdef HITLS_TLS_PROTO_DTLS13
    Dtls13AckStateInitList(&retransmitNode->ackState);

    if (type == REC_TYPE_HANDSHAKE && len >= DTLS_HS_MSG_HEADER_SIZE) {
        retransmitNode->hsType = msg[0];
        retransmitNode->epoch = recCtx->writeEpoch;
        if (recCtx->writeStates.currentState != NULL) {
            retransmitNode->nextRecordSeq = RecConnGetSeqNum(recCtx->writeStates.currentState);
        }
        retransmitNode->bodyLen = BSL_ByteToUint24(&msg[DTLS_HS_MSGLEN_ADDR]);
        int32_t ret = AckStateInit(&retransmitNode->ackState, retransmitNode->bodyLen);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_FREE(retransmitNode->msg);
            BSL_SAL_FREE(retransmitNode);
            return ret;
        }
    }
#endif

#ifdef HITLS_TLS_PROTO_DTLS12
    if (type == REC_TYPE_CHANGE_CIPHER_SPEC) {
        retransmitList->isExistCcsMsg = true;
    }
#endif

    /* insert new node */
    LIST_ADD_BEFORE(&retransmitList->head, &retransmitNode->head);
    if (retransmitNodePtr != NULL) {
        *retransmitNodePtr = retransmitNode;
    }
    return HITLS_SUCCESS;
}

void REC_RetransmitListClean(REC_Ctx *recCtx)
{
    ListHead *head = NULL;
    ListHead *tmpHead = NULL;
    RecRetransmitList *retransmitList = &recCtx->retransmitList;
    RecRetransmitList *retransmitNode = NULL;

    retransmitList->isExistCcsMsg = false;
    LIST_FOR_EACH_ITEM_SAFE(head, tmpHead, &(retransmitList->head)) {
        BSL_LIST_REMOVE(head);
        retransmitNode = BSL_LIST_ENTRY(head, RecRetransmitList, head);
#ifdef HITLS_TLS_PROTO_DTLS13
        AckStateDeinit(&retransmitNode->ackState);
#endif
        BSL_SAL_FREE(retransmitNode->msg);
        BSL_SAL_FREE(retransmitNode);
    }
}

#ifdef HITLS_TLS_PROTO_DTLS13
void REC_RetransmitListRemove(REC_Ctx *recCtx, uint8_t hsType)
{
    if (recCtx == NULL) {
        return;
    }

    RecRetransmitList *retransmitList = &recCtx->retransmitList;
    ListHead *head = NULL;
    ListHead *tmpHead = NULL;
    LIST_FOR_EACH_ITEM_SAFE(head, tmpHead, &retransmitList->head) {
        RecRetransmitList *retransmitNode = BSL_LIST_ENTRY(head, RecRetransmitList, head);
        if (retransmitNode->type != REC_TYPE_HANDSHAKE || retransmitNode->hsType != hsType) {
            continue;
        }
        BSL_LIST_REMOVE(head);
        AckStateDeinit(&retransmitNode->ackState);
        BSL_SAL_FREE(retransmitNode->msg);
        BSL_SAL_FREE(retransmitNode);
    }
}

static int32_t WriteSingleDtls13RetransmitNode(TLS_Ctx *ctx, RecRetransmitList *retransmitNode)
{
    int32_t ret = REC_QueryMtu(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = REC_RecOutBufReSet(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t maxRecPayloadLen = 0;
    ret = REC_GetMaxWriteSize(ctx, &maxRecPayloadLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (maxRecPayloadLen <= DTLS_HS_MSG_HEADER_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_PMTU_TOO_SMALL);
        return HITLS_REC_PMTU_TOO_SMALL;
    }
    Dtls13FragmentList list = {0};
    ret = AckStateGetFragment(&retransmitNode->ackState, maxRecPayloadLen - DTLS_HS_MSG_HEADER_SIZE, &list);
    if (ret != HITLS_SUCCESS) {
        Dtls13FragmentListDeinit(&list);
        return ret;
    }
    uint8_t *data = (uint8_t *)BSL_SAL_Calloc(1u, maxRecPayloadLen);
    if (data == NULL) {
        Dtls13FragmentListDeinit(&list);
        return HITLS_MEMALLOC_FAIL;
    }

    RecConnStates *writeStates = &ctx->recCtx->writeStates;
    RecConnState *originCurrentState = writeStates->currentState;
    RecConnState *originOutdatedState = writeStates->outdatedState;
    RecConnState plainState = {0};
    bool restoreWriteStates = false;
    /* Epoch 0 is plaintext. After the server moves to epoch 3, only epoch 2 may remain in outdatedState,
     * so ServerHello retransmission needs a temporary plaintext state instead of an encryption state swap. */
    bool needPlainState = retransmitNode->epoch == 0 &&
        (writeStates->currentState == NULL || RecConnGetEpoch(writeStates->currentState) != 0 ||
            writeStates->currentState->suiteInfo != NULL);
    if (needPlainState) {
        RecConnSetEpoch(&plainState, 0);
        RecConnSetSeqNum(&plainState, retransmitNode->nextRecordSeq);
        writeStates->currentState = &plainState;
        restoreWriteStates = true;
    } else if (retransmitNode->epoch != ctx->recCtx->writeEpoch &&
        writeStates->outdatedState != NULL &&
        writeStates->outdatedState->epoch == retransmitNode->epoch) {
        RecConnState *tmp = writeStates->currentState;
        writeStates->currentState = writeStates->outdatedState;
        writeStates->outdatedState = tmp;
        restoreWriteStates = true;
    }

    (void)memcpy(data, retransmitNode->msg, DTLS_HS_MSG_HEADER_SIZE);
    for (uint32_t i = 0; i < list.count; i++) {
        BSL_Uint24ToByte(list.frags[i].offset, &data[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
        BSL_Uint24ToByte(list.frags[i].len, &data[DTLS_HS_FRAGMENT_LEN_ADDR]);
        (void)memcpy(&data[DTLS_HS_MSG_HEADER_SIZE],
            &retransmitNode->msg[DTLS_HS_MSG_HEADER_SIZE + list.frags[i].offset], list.frags[i].len);
        ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, data, list.frags[i].len + DTLS_HS_MSG_HEADER_SIZE);
        if (ret != HITLS_SUCCESS) {
            goto EXIT;
        }
        RecordNumber recordNum = {0};
        ret = REC_GetLastWriteRecordNum(ctx, &recordNum);
        if (ret != HITLS_SUCCESS) {
            goto EXIT;
        }
        if (recordNum.epoch == retransmitNode->epoch) {
            retransmitNode->nextRecordSeq = recordNum.sequenceNumber + 1;
        }
        ret = AckStateInsertSeqMap(&retransmitNode->ackState, &recordNum, list.frags[i].offset,
            list.frags[i].len);
        if (ret != HITLS_SUCCESS) {
            goto EXIT;
        }
    }

EXIT:
    if (restoreWriteStates) {
        writeStates->currentState = originCurrentState;
        writeStates->outdatedState = originOutdatedState;
    }
    BSL_SAL_FREE(data);
    Dtls13FragmentListDeinit(&list);
    return ret;
}
#endif /* HITLS_TLS_PROTO_DTLS13 */

bool REC_RetransmitIsEmpty(const REC_Ctx *recCtx)
{
    return (recCtx == NULL) ? true : LIST_IS_EMPTY(&recCtx->retransmitList.head);
}

#ifdef HITLS_TLS_PROTO_DTLS13
static bool Dtls13RetransmitNodeIsKeyUpdate(const RecRetransmitList *node)
{
    return node != NULL && node->type == REC_TYPE_HANDSHAKE && node->hsType == KEY_UPDATE;
}

bool REC_Dtls13RetransmitListHasKeyUpdate(const REC_Ctx *recCtx)
{
    if (recCtx == NULL) {
        return false;
    }
    const RecRetransmitList *retransmitList = &recCtx->retransmitList;
    ListHead *head = NULL;
    ListHead *tmp = NULL;
    LIST_FOR_EACH_ITEM_SAFE(head, tmp, &retransmitList->head) {
        const RecRetransmitList *node = BSL_LIST_ENTRY(head, RecRetransmitList, head);
        if (Dtls13RetransmitNodeIsKeyUpdate(node)) {
            return true;
        }
    }
    return false;
}

int32_t REC_RetransmitListPushWithAckCb(TLS_Ctx *ctx, REC_Type type, const uint8_t *msg, uint32_t len,
    REC_Dtls13RetransmitAckCb ackCb)
{
    if (ctx == NULL || ctx->recCtx == NULL || msg == NULL) {
        return HITLS_NULL_INPUT;
    }
    bool isFutureEpochNode = (HS_MsgType)msg[0] != KEY_UPDATE && REC_Dtls13RetransmitListHasKeyUpdate(ctx->recCtx);
    RecRetransmitList *retransmitNode = NULL;
    int32_t ret = RecRetransmitListAppendNode(ctx->recCtx, type, msg, len, &retransmitNode);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    retransmitNode->ackCb = ackCb;
    if (isFutureEpochNode) {
        retransmitNode->epoch = ctx->recCtx->writeEpoch + 1;
        return HITLS_SUCCESS;
    }
    ret = WriteSingleDtls13RetransmitNode(ctx, retransmitNode);
    if (ret != HITLS_SUCCESS) {
        BSL_LIST_REMOVE(&retransmitNode->head);
        AckStateDeinit(&retransmitNode->ackState);
        BSL_SAL_FREE(retransmitNode->msg);
        BSL_SAL_FREE(retransmitNode);
        return ret;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS13 */

static int32_t WriteSingleRetransmitNode(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    int32_t ret = REC_QueryMtu(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = REC_RecOutBufReSet(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t maxRecPayloadLen = 0;
    ret = REC_GetMaxWriteSize(ctx, &maxRecPayloadLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17360, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetMaxWriteSize fail", 0, 0, 0, 0);
        return ret;
    }

    if (maxRecPayloadLen >= num) {
        /* Send to the record layer */
        ret = REC_Write(ctx, recordType, data, num);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17361, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "send handshake msg to record fail.", 0, 0, 0, 0);
            return ret;
        }
    } else {
        ret = HS_DtlsSendFragmentHsMsg(ctx, maxRecPayloadLen, data);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    return HITLS_SUCCESS;
}

int32_t REC_RetransmitListFlush(TLS_Ctx *ctx)
{
    REC_Ctx *recCtx = ctx->recCtx;
    RecRetransmitList *retransmitList = &recCtx->retransmitList;
    RecRetransmitList *retransmitNode = NULL;

#ifdef HITLS_TLS_PROTO_DTLS12
    if (retransmitList->isExistCcsMsg == true) {
        REC_ActiveOutdatedWriteState(ctx);
    }
#endif

    int32_t ret = HITLS_SUCCESS;
    ListHead *head = NULL;
    ListHead *tmpHead = NULL;
#ifdef HITLS_TLS_PROTO_DTLS12
    bool isSendCcsMsg = false;
#endif
    LIST_FOR_EACH_ITEM_SAFE(head, tmpHead, &(retransmitList->head)) {
        retransmitNode = BSL_LIST_ENTRY(head, RecRetransmitList, head);
        /* UDP does not fail to send. Therefore, the sending failure case does not need to be considered. */
#ifdef HITLS_TLS_PROTO_DTLS13
        if (IS_DTLS13_CTX(ctx) && retransmitNode->type == REC_TYPE_HANDSHAKE && retransmitNode->bodyLen != 0) {
            if (retransmitNode->epoch > recCtx->writeEpoch) {
                continue;
            }
            ret = WriteSingleDtls13RetransmitNode(ctx, retransmitNode);
        } else {
#endif
            ret = WriteSingleRetransmitNode(ctx, retransmitNode->type, retransmitNode->msg, retransmitNode->len);
#ifdef HITLS_TLS_PROTO_DTLS13
        }
#endif
        if (ret != HITLS_SUCCESS) {
#ifdef HITLS_TLS_PROTO_DTLS12
            if (!isSendCcsMsg && retransmitList->isExistCcsMsg == true) {
                REC_DeActiveOutdatedWriteState(ctx);
            }
#endif

            return ret;
        }
#ifdef HITLS_TLS_PROTO_DTLS12
        if (retransmitNode->type == REC_TYPE_CHANGE_CIPHER_SPEC) {
            isSendCcsMsg = true;
            REC_DeActiveOutdatedWriteState(ctx);
        }
#endif
    }
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        (void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DATAGRAM && HITLS_BSL_UIO_UDP */
