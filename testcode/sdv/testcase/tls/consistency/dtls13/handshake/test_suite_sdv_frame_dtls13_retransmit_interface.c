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

/* BEGIN_HEADER */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <unistd.h>
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_dtls_cid.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "tls.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "simulate_io.h"
#include "stub_utils.h"
#include "record.h"
#include "rec.h"
#include "rec_header.h"
#include "hs_msg.h"
#include "dtls_cid.h"
/* END_HEADER */

int32_t AckStateInit(Dtls13AckState *state, uint32_t len);
void AckStateDeinit(Dtls13AckState *state);
int32_t AckStateInsertSeqMap(Dtls13AckState *state, const RecordNumber *recordNum, uint32_t offset, uint32_t len);
int32_t AckStateGetFragment(const Dtls13AckState *state, uint32_t maxFragmentLen, Dtls13FragmentList *list);
int32_t AckStateProcessAck(Dtls13AckState *state, const RecordNumber *recordNum);

STUB_DEFINE_RET4(int32_t, REC_Write, TLS_Ctx *, REC_Type, const uint8_t *, uint32_t);
STUB_DEFINE_RET1(int32_t, REC_RetransmitListFlush, TLS_Ctx *);
STUB_DEFINE_RET1(int32_t, REC_QueryMtu, TLS_Ctx *);
STUB_DEFINE_RET1(int32_t, REC_RecOutBufReSet, TLS_Ctx *);
STUB_DEFINE_RET2(int32_t, REC_GetMaxWriteSize, const TLS_Ctx *, uint32_t *);
STUB_DEFINE_RET2(void *, BSL_SAL_Calloc, uint32_t, uint32_t);

static REC_Type g_stubRecordType = REC_TYPE_UNKNOWN;
static uint32_t g_stubRecordLen = 0;
static uint8_t g_stubAckBuf[64] = {0};
static uint32_t g_stubWriteCnt = 0;
static uint32_t g_stubRetransmitFlushCnt = 0;
static uint32_t g_stubAckCbCnt = 0;
static uint32_t g_stubAlertCnt = 0;
static ALERT_Level g_stubAlertLevel = 0;
static ALERT_Description g_stubAlertDescription = 0;
static uint32_t g_stubMaxWriteSize = 16384;
static uint16_t g_stubWriteStateEpoch = 0;
static uint64_t g_stubWriteStateSeq = 0;
static bool g_stubWriteStateIsPlain = false;
static bool g_stubFailGapAlloc = false;
#define STUB_WRITE_TRACE_MAX 8
static uint16_t g_stubWriteStateEpochTrace[STUB_WRITE_TRACE_MAX] = {0};
static uint64_t g_stubWriteStateSeqTrace[STUB_WRITE_TRACE_MAX] = {0};

static void ResetAckStub(void)
{
    g_stubRecordType = REC_TYPE_UNKNOWN;
    g_stubRecordLen = 0;
    (void)memset(g_stubAckBuf, 0, sizeof(g_stubAckBuf));
    g_stubWriteCnt = 0;
    g_stubMaxWriteSize = 16384;
}

static RecordNumber MakeRecordNumber(uint64_t epoch, uint64_t sequenceNumber)
{
    RecordNumber recordNum = {0};
    recordNum.epoch = epoch;
    recordNum.sequenceNumber = sequenceNumber;
    return recordNum;
}

static void BuildDtls13HsMsg(uint8_t *msg, HS_MsgType msgType, uint16_t msgSeq, uint32_t bodyLen)
{
    msg[0] = (uint8_t)msgType;
    BSL_Uint24ToByte(bodyLen, &msg[DTLS_HS_MSGLEN_ADDR]);
    BSL_Uint16ToByte(msgSeq, &msg[DTLS_HS_MSGSEQ_ADDR]);
    BSL_Uint24ToByte(0, &msg[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
    BSL_Uint24ToByte(bodyLen, &msg[DTLS_HS_FRAGMENT_LEN_ADDR]);
    for (uint32_t i = 0; i < bodyLen; i++) {
        msg[DTLS_HS_MSG_HEADER_SIZE + i] = (uint8_t)(i + 1u);
    }
}

static int32_t STUB_REC_Write_Dtls13Ack(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    (void)ctx;
    g_stubRecordType = recordType;
    g_stubRecordLen = num;
    g_stubWriteCnt++;
    if (num <= sizeof(g_stubAckBuf)) {
        (void)memcpy(g_stubAckBuf, data, num);
    }
    return HITLS_SUCCESS;
}

static void ResetWriteStateStub(void)
{
    ResetAckStub();
    g_stubWriteCnt = 0;
    g_stubWriteStateEpoch = 0;
    g_stubWriteStateSeq = 0;
    g_stubWriteStateIsPlain = false;
    (void)memset(g_stubWriteStateEpochTrace, 0, sizeof(g_stubWriteStateEpochTrace));
    (void)memset(g_stubWriteStateSeqTrace, 0, sizeof(g_stubWriteStateSeqTrace));
}

static int32_t STUB_REC_Write_Dtls13State(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    RecConnState *state = ctx->recCtx->writeStates.currentState;
    uint32_t traceIndex = g_stubWriteCnt;
    g_stubWriteCnt++;
    g_stubRecordType = recordType;
    g_stubRecordLen = num;
    if (num <= sizeof(g_stubAckBuf)) {
        (void)memcpy(g_stubAckBuf, data, num);
    }
    if (state == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    g_stubWriteStateEpoch = RecConnGetEpoch(state);
    g_stubWriteStateSeq = RecConnGetSeqNum(state);
    g_stubWriteStateIsPlain = (state->suiteInfo == NULL);
    if (traceIndex < STUB_WRITE_TRACE_MAX) {
        g_stubWriteStateEpochTrace[traceIndex] = g_stubWriteStateEpoch;
        g_stubWriteStateSeqTrace[traceIndex] = g_stubWriteStateSeq;
    }
    ctx->recCtx->lastWriteEpochSeq = REC_EPOCHSEQ_CAL(g_stubWriteStateEpoch, g_stubWriteStateSeq);
    ctx->recCtx->hasLastWriteEpochSeq = true;
    RecConnSetSeqNum(state, g_stubWriteStateSeq + 1);
    return HITLS_SUCCESS;
}

static int32_t STUB_REC_RetransmitListFlush_Dtls13(TLS_Ctx *ctx)
{
    (void)ctx;
    g_stubRetransmitFlushCnt++;
    return HITLS_SUCCESS;
}

static int32_t STUB_REC_QueryMtu_Selective(TLS_Ctx *ctx)
{
    (void)ctx;
    return HITLS_SUCCESS;
}

static int32_t STUB_REC_RecOutBufReSet_Selective(TLS_Ctx *ctx)
{
    (void)ctx;
    return HITLS_SUCCESS;
}

static int32_t STUB_REC_GetMaxWriteSize_Selective(const TLS_Ctx *ctx, uint32_t *len)
{
    (void)ctx;
    *len = g_stubMaxWriteSize;
    return HITLS_SUCCESS;
}

static void *STUB_BSL_SAL_Calloc_Dtls13Gap(uint32_t num, uint32_t size)
{
    if (g_stubFailGapAlloc && num == 1u && size == sizeof(Dtls13GapNode)) {
        g_stubFailGapAlloc = false;
        return NULL;
    }
    return calloc(num, size);
}

static int32_t STUB_Dtls13RetransmitAckCb(TLS_Ctx *ctx)
{
    (void)ctx;
    g_stubAckCbCnt++;
    return HITLS_SUCCESS;
}

static int32_t STUB_Dtls13RetransmitAckCbFail(TLS_Ctx *ctx)
{
    (void)ctx;
    g_stubAckCbCnt++;
    return HITLS_INTERNAL_EXCEPTION;
}

static int32_t STUB_Dtls13KeyUpdateAckCbFlush(TLS_Ctx *ctx)
{
    g_stubAckCbCnt++;
    ctx->recCtx->writeEpoch = 4;
    ctx->recCtx->hasLastWriteEpochSeq = true;
    ctx->recCtx->lastWriteEpochSeq = REC_EPOCHSEQ_CAL(4, 2);
    return REC_RetransmitListFlush(ctx);
}

static void STUB_SendAlert(const TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    (void)ctx;
    g_stubAlertCnt++;
    g_stubAlertLevel = level;
    g_stubAlertDescription = description;
}

/**
 * @test     UT_TLS_DTLS13_ACK_STATE_FUNC_TC001
 * @title    DTLS1.3 ack state processes holes correctly.
 * @brief    Init ack state, insert record mappings, process ack, and verify hole fragments.
 * @expect   Ack state reflects holes correctly and becomes empty after full ack.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_ACK_STATE_FUNC_TC001(void)
{
    Dtls13AckState state = {0};
    Dtls13FragmentList list = {0};
    RecordNumber recordNum = {0};
    ASSERT_EQ(AckStateInit(&state, 1000), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 1);
    ASSERT_EQ(AckStateInsertSeqMap(&state, &recordNum, 200, 100), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(AckStateInsertSeqMap(&state, &recordNum, 0, 100), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 1);
    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_SUCCESS);
    ASSERT_TRUE(state.unackedBytes != 0);

    ASSERT_EQ(AckStateGetFragment(&state, 128, &list), HITLS_SUCCESS);
    ASSERT_EQ(list.count, 7);
    ASSERT_EQ(list.frags[0].offset, 100);
    ASSERT_EQ(list.frags[0].len, 100);
    ASSERT_EQ(list.frags[1].offset, 300);
    ASSERT_EQ(list.frags[1].len, 128);
    ASSERT_EQ(list.frags[2].offset, 428);
    ASSERT_EQ(list.frags[2].len, 128);
    ASSERT_EQ(list.frags[3].offset, 556);
    ASSERT_EQ(list.frags[3].len, 128);
    ASSERT_EQ(list.frags[4].offset, 684);
    ASSERT_EQ(list.frags[4].len, 128);
    ASSERT_EQ(list.frags[5].offset, 812);
    ASSERT_EQ(list.frags[5].len, 128);
    ASSERT_EQ(list.frags[6].offset, 940);
    ASSERT_EQ(list.frags[6].len, 60);

    recordNum = MakeRecordNumber(1, 3);
    ASSERT_EQ(AckStateInsertSeqMap(&state, &recordNum, 100, 100), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 4);
    ASSERT_EQ(AckStateInsertSeqMap(&state, &recordNum, 300, 700), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 3);
    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 4);
    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_SUCCESS);
    ASSERT_TRUE(state.unackedBytes == 0);
EXIT:
    BSL_SAL_FREE(list.frags);
    AckStateDeinit(&state);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_SEQMAP_FUNC_TC001
 * @title    DTLS1.3 ack state owns seq mappings.
 * @brief    Insert multiple seq mappings into ack state and process ack.
 * @expect   Mapped ack updates state and missing ack does not fail.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_SEQMAP_FUNC_TC001(void)
{
    Dtls13AckState state = {0};
    RecordNumber recordNum = {0};
    ASSERT_EQ(AckStateInit(&state, 100), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(AckStateInsertSeqMap(&state, &recordNum, 10, 20), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(2, 3);
    ASSERT_EQ(AckStateInsertSeqMap(&state, &recordNum, 40, 50), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_SUCCESS);
    ASSERT_TRUE(state.unackedBytes != 0);
    recordNum = MakeRecordNumber(3, 4);
    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_SUCCESS);
    ASSERT_TRUE(state.unackedBytes != 0);
EXIT:
    AckStateDeinit(&state);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_ACK_STATE_ALLOC_FAIL_FUNC_TC001
 * @title    DTLS1.3 ack state keeps gaps stable when split allocation fails.
 * @brief    Ack a middle range that needs a new gap and force that allocation to fail.
 * @expect   The function returns memory failure and the original unacked range remains unchanged.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_ACK_STATE_ALLOC_FAIL_FUNC_TC001(void)
{
    Dtls13AckState state = {0};
    Dtls13FragmentList list = {0};
    RecordNumber recordNum = {0};
    ASSERT_EQ(AckStateInit(&state, 100), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 1);
    ASSERT_EQ(AckStateInsertSeqMap(&state, &recordNum, 10, 10), HITLS_SUCCESS);

    STUB_REPLACE(BSL_SAL_Calloc, STUB_BSL_SAL_Calloc_Dtls13Gap);
    g_stubFailGapAlloc = true;
    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_MEMALLOC_FAIL);
    STUB_RESTORE(BSL_SAL_Calloc);
    ASSERT_EQ(state.unackedBytes, 100);
    ASSERT_EQ(AckStateGetFragment(&state, 100, &list), HITLS_SUCCESS);
    ASSERT_EQ(list.count, 1);
    ASSERT_EQ(list.frags[0].offset, 0);
    ASSERT_EQ(list.frags[0].len, 100);
    BSL_SAL_FREE(list.frags);
    list.frags = NULL;
    list.count = 0;
    list.cap = 0;

    ASSERT_EQ(AckStateProcessAck(&state, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(state.unackedBytes, 90);
    ASSERT_EQ(AckStateGetFragment(&state, 100, &list), HITLS_SUCCESS);
    ASSERT_EQ(list.count, 2);
    ASSERT_EQ(list.frags[0].offset, 0);
    ASSERT_EQ(list.frags[0].len, 10);
    ASSERT_EQ(list.frags[1].offset, 20);
    ASSERT_EQ(list.frags[1].len, 80);
EXIT:
    STUB_RESTORE(BSL_SAL_Calloc);
    BSL_SAL_FREE(list.frags);
    AckStateDeinit(&state);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_ACKLIST_FUNC_TC001
 * @title    DTLS1.3 ack list deduplicates, sorts, caps, and clears records.
 * @brief    Append duplicate, out-of-order, and overflow ack records, then clear list.
 * @expect   Ack list is ordered, capped, deduplicated, and clearable.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_ACKLIST_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    ctx.recCtx = &recCtx;
    RecordNumber recordNum = {0};
    recordNum = MakeRecordNumber(2, 5);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(2, 5);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(2, 3);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 9);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(2, 4);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(recCtx.ackList.count, 4);
    ASSERT_EQ(recCtx.ackList.records[0].epoch, 1);
    ASSERT_EQ(recCtx.ackList.records[0].sequenceNumber, 9);
    ASSERT_EQ(recCtx.ackList.records[1].epoch, 2);
    ASSERT_EQ(recCtx.ackList.records[1].sequenceNumber, 3);
    ASSERT_EQ(recCtx.ackList.records[2].epoch, 2);
    ASSERT_EQ(recCtx.ackList.records[2].sequenceNumber, 4);
    ASSERT_EQ(recCtx.ackList.records[3].epoch, 2);
    ASSERT_EQ(recCtx.ackList.records[3].sequenceNumber, 5);
    for (uint32_t i = 10; i < REC_DTLS13_ACK_LIST_MAX_COUNT + 10; i++) {
        recordNum = MakeRecordNumber(3, i);
        ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    }
    ASSERT_EQ(recCtx.ackList.count, REC_DTLS13_ACK_LIST_MAX_COUNT);
    recordNum = MakeRecordNumber(4, 1);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(recCtx.ackList.count, REC_DTLS13_ACK_LIST_MAX_COUNT);
    recordNum = MakeRecordNumber(2, 5);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(recCtx.ackList.count, REC_DTLS13_ACK_LIST_MAX_COUNT);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(&ctx, REC_DTLS13_ACK_NORMAL) == false);
    REC_Dtls13AckListClear(&ctx, REC_DTLS13_ACK_NORMAL);
    ASSERT_EQ(recCtx.ackList.count, 0);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(&ctx, REC_DTLS13_ACK_NORMAL) == true);
EXIT:
    BSL_SAL_FREE(recCtx.ackList.records);
    BSL_SAL_FREE(recCtx.retransAckList.records);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_ACKLIST_ROUTE_FUNC_TC001
 * @title    DTLS1.3 ack list also caches epoch-2 records for retrans ACK.
 * @brief    Append epoch-2 records on server/client contexts and verify target ACK lists.
 * @expect   Epoch-2 records are stored in both normal ackList and retransAckList.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_ACKLIST_ROUTE_FUNC_TC001(void)
{
    TLS_Ctx serverCtx = {0};
    TLS_Ctx clientCtx = {0};
    RecCtx serverRecCtx = {0};
    RecCtx clientRecCtx = {0};
    RecordNumber recordNum = {0};
    serverCtx.recCtx = &serverRecCtx;
    serverCtx.isClient = false;
    clientCtx.recCtx = &clientRecCtx;
    clientCtx.isClient = true;

    recordNum = MakeRecordNumber(2, 1);
    ASSERT_EQ(REC_Dtls13AckListAppend(&serverCtx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(REC_Dtls13AckListAppend(&serverCtx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(serverRecCtx.ackList.count, 1);
    ASSERT_EQ(serverRecCtx.retransAckList.count, 1);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(&serverCtx, REC_DTLS13_ACK_RETRANS) == false);

    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(REC_Dtls13AckListAppend(&serverCtx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(serverRecCtx.ackList.count, 2);
    REC_Dtls13AckListClear(&serverCtx, REC_DTLS13_ACK_NORMAL);
    ASSERT_EQ(serverRecCtx.ackList.count, 0);
    ASSERT_EQ(serverRecCtx.retransAckList.count, 1);
    REC_Dtls13AckListClear(&serverCtx, REC_DTLS13_ACK_RETRANS);
    ASSERT_EQ(serverRecCtx.retransAckList.count, 0);

    recordNum = MakeRecordNumber(2, 3);
    ASSERT_EQ(REC_Dtls13AckListAppend(&clientCtx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(clientRecCtx.ackList.count, 1);
    ASSERT_EQ(clientRecCtx.retransAckList.count, 1);
EXIT:
    BSL_SAL_FREE(serverRecCtx.ackList.records);
    BSL_SAL_FREE(serverRecCtx.retransAckList.records);
    BSL_SAL_FREE(clientRecCtx.ackList.records);
    BSL_SAL_FREE(clientRecCtx.retransAckList.records);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_SEND_ACK_FUNC_TC001
 * @title    DTLS1.3 ACK send encodes record numbers correctly.
 * @brief    Append two ACK records, stub REC_Write, and verify encoded ACK payload.
 * @expect   ACK record type, length, and encoded epoch/sequence numbers match the list.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_SEND_ACK_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    RecordNumber recordNum = {0};
    ctx.recCtx = &recCtx;
    ResetAckStub();

    ASSERT_EQ(REC_Dtls13SendAck(&ctx, REC_DTLS13_ACK_NORMAL), HITLS_SUCCESS);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_UNKNOWN);

    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 3);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);

    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13Ack);
    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    ASSERT_EQ(REC_Dtls13SendAck(&ctx, REC_DTLS13_ACK_NORMAL), HITLS_SUCCESS);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_ACK);
    ASSERT_EQ(g_stubRecordLen, sizeof(uint16_t) + 2 * REC_DTLS13_ACK_ITEM_LEN);
    ASSERT_EQ(BSL_ByteToUint16(g_stubAckBuf), (uint16_t)(2 * REC_DTLS13_ACK_ITEM_LEN));
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t)]), 1);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t) + sizeof(uint64_t)]), 2);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t) + REC_DTLS13_ACK_ITEM_LEN]), 1);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t) + REC_DTLS13_ACK_ITEM_LEN + sizeof(uint64_t)]), 3);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(&ctx, REC_DTLS13_ACK_NORMAL) == false);
EXIT:
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_QueryMtu);
    STUB_RESTORE(REC_Write);
    BSL_SAL_FREE(recCtx.ackList.records);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_SEND_ACK_FUNC_TC002
 * @title    DTLS1.3 ACK send splits large ACK lists by writable MTU.
 * @brief    Stub max writable plaintext to two ACK items and verify five items are sent in three records.
 * @expect   REC_Write is called three times and the last batch contains one ACK item.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_SEND_ACK_FUNC_TC002(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    ctx.recCtx = &recCtx;
    ResetAckStub();
    g_stubMaxWriteSize = sizeof(uint16_t) + 2 * REC_DTLS13_ACK_ITEM_LEN;

    for (uint32_t i = 0; i < 5; i++) {
        RecordNumber recordNum = MakeRecordNumber(1, i + 1);
        ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    }

    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13Ack);
    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    ASSERT_EQ(REC_Dtls13SendAck(&ctx, REC_DTLS13_ACK_NORMAL), HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, 3);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_ACK);
    ASSERT_EQ(g_stubRecordLen, sizeof(uint16_t) + REC_DTLS13_ACK_ITEM_LEN);
    ASSERT_EQ(BSL_ByteToUint16(g_stubAckBuf), (uint16_t)REC_DTLS13_ACK_ITEM_LEN);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t)]), 1);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t) + sizeof(uint64_t)]), 5);

EXIT:
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_QueryMtu);
    STUB_RESTORE(REC_Write);
    BSL_SAL_FREE(recCtx.ackList.records);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_EMPTY_FUNC_TC001
 * @title    DTLS1.3 retransmit queue empty query works.
 * @brief    Check empty queue and non-empty queue results.
 * @expect   Interface returns expected empty state.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_EMPTY_FUNC_TC001(void)
{
    RecCtx recCtx = {0};
    uint8_t msg[DTLS_HS_MSG_HEADER_SIZE + 1] = {0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xAA};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == true);
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, msg, sizeof(msg), NULL), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);
EXIT:
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_NODE_FUNC_TC001
 * @title    DTLS1.3 ack processing removes fully acked retransmit node.
 * @brief    Append one retransmit node, process ack, and verify node removal.
 * @expect   Retransmit node is removed from the shared retransmit list.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_NODE_FUNC_TC001(void)
{
    uint8_t msg[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t ackBuf[sizeof(uint16_t) + sizeof(uint64_t) * 2] = {0};
    RecordNumber recordNum = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 1;
    recCtx.readEpoch = 3;
    ctx.recCtx = &recCtx;
    ctx.timeoutValue = 1000;
    ctx.timeoutNum = 3;
    msg[0] = FINISHED;
    msg[3] = 4;
    msg[11] = 4;
    msg[12] = 1;
    msg[13] = 2;
    msg[14] = 3;
    msg[15] = 4;
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, msg, sizeof(msg), NULL), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);
    RecRetransmitList *node = BSL_LIST_ENTRY(recCtx.retransmitList.head.next, RecRetransmitList, head);
    recordNum = MakeRecordNumber(1, 10);
    ASSERT_EQ(AckStateInsertSeqMap(&node->ackState, &recordNum, 0, 4), HITLS_SUCCESS);
    BSL_Uint16ToByte((uint16_t)(sizeof(uint64_t) * 2), ackBuf);
    BSL_Uint64ToByte(1, &ackBuf[sizeof(uint16_t)]);
    BSL_Uint64ToByte(10, &ackBuf[sizeof(uint16_t) + sizeof(uint64_t)]);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, ackBuf, sizeof(ackBuf)), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == true);
    ASSERT_EQ(ctx.timeoutValue, 0);
    ASSERT_EQ(ctx.timeoutNum, 0);
EXIT:
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_ACK_TIMER_FUNC_TC001
 * @title    DTLS1.3 ACK processing does not stop the timer before read epoch advances past 2.
 * @brief    Append one retransmit node, keep readEpoch at 2, process a full ACK, and verify timer state.
 * @expect   Retransmit node is removed, but the retransmit timer is not stopped.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_ACK_TIMER_FUNC_TC001(void)
{
    uint8_t msg[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t ackBuf[sizeof(uint16_t) + REC_DTLS13_ACK_ITEM_LEN] = {0};
    RecordNumber recordNum = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 1;
    recCtx.readEpoch = 2;
    ctx.recCtx = &recCtx;
    ctx.timeoutValue = 1000;
    ctx.timeoutNum = 3;
    BuildDtls13HsMsg(msg, FINISHED, 1, 4);

    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, msg, sizeof(msg), NULL), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);
    RecRetransmitList *node = BSL_LIST_ENTRY(recCtx.retransmitList.head.next, RecRetransmitList, head);
    recordNum = MakeRecordNumber(1, 10);
    ASSERT_EQ(AckStateInsertSeqMap(&node->ackState, &recordNum, 0, 4), HITLS_SUCCESS);

    BSL_Uint16ToByte(REC_DTLS13_ACK_ITEM_LEN, ackBuf);
    BSL_Uint64ToByte(1, &ackBuf[sizeof(uint16_t)]);
    BSL_Uint64ToByte(10, &ackBuf[sizeof(uint16_t) + sizeof(uint64_t)]);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, ackBuf, sizeof(ackBuf)), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == true);
    ASSERT_EQ(ctx.timeoutValue, 1000);
    ASSERT_EQ(ctx.timeoutNum, 3);

EXIT:
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_REMOVE_FUNC_TC001
 * @title    DTLS1.3 retransmit queue can remove nodes by handshake type.
 * @brief    Append multiple retransmit nodes and remove only CertificateRequest nodes.
 * @expect   Matching handshake nodes are removed and other retransmit nodes remain.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_REMOVE_FUNC_TC001(void)
{
    RecCtx recCtx = {0};
    uint8_t certReq[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    uint8_t certReq2[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    uint8_t finished[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 2;

    certReq[0] = CERTIFICATE_REQUEST;
    BSL_Uint24ToByte(1, &certReq[DTLS_HS_MSGLEN_ADDR]);
    BSL_Uint16ToByte(1, &certReq[DTLS_HS_MSGSEQ_ADDR]);
    BSL_Uint24ToByte(1, &certReq[DTLS_HS_FRAGMENT_LEN_ADDR]);
    certReq[DTLS_HS_MSG_HEADER_SIZE] = 0xAA;

    finished[0] = FINISHED;
    BSL_Uint24ToByte(1, &finished[DTLS_HS_MSGLEN_ADDR]);
    BSL_Uint16ToByte(2, &finished[DTLS_HS_MSGSEQ_ADDR]);
    BSL_Uint24ToByte(1, &finished[DTLS_HS_FRAGMENT_LEN_ADDR]);
    finished[DTLS_HS_MSG_HEADER_SIZE] = 0xBB;

    certReq2[0] = CERTIFICATE_REQUEST;
    BSL_Uint24ToByte(1, &certReq2[DTLS_HS_MSGLEN_ADDR]);
    BSL_Uint16ToByte(3, &certReq2[DTLS_HS_MSGSEQ_ADDR]);
    BSL_Uint24ToByte(1, &certReq2[DTLS_HS_FRAGMENT_LEN_ADDR]);
    certReq2[DTLS_HS_MSG_HEADER_SIZE] = 0xCC;

    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, certReq, sizeof(certReq), NULL), HITLS_SUCCESS);
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, finished, sizeof(finished), NULL), HITLS_SUCCESS);
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, certReq2, sizeof(certReq2), NULL), HITLS_SUCCESS);

    REC_RetransmitListRemove(&recCtx, CERTIFICATE_REQUEST);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);
    ASSERT_EQ(recCtx.retransmitList.head.next->next, &recCtx.retransmitList.head);
    RecRetransmitList *remaining = BSL_LIST_ENTRY(recCtx.retransmitList.head.next, RecRetransmitList, head);
    ASSERT_EQ(remaining->hsType, FINISHED);

    REC_RetransmitListRemove(&recCtx, FINISHED);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == true);
EXIT:
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_ACK_CB_FUNC_TC001
 * @title    DTLS1.3 retransmit node ACK callback is invoked after full ACK.
 * @brief    Push one retransmit node with a callback, process its ACK, and verify callback invocation.
 * @expect   Callback is called once and the fully ACKed retransmit node is removed.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_ACK_CB_FUNC_TC001(void)
{
    uint8_t msg[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t ackBuf[sizeof(uint16_t) + sizeof(uint64_t) * 2] = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 1;
    recCtx.readEpoch = 3;
    recCtx.hasLastWriteEpochSeq = true;
    recCtx.lastWriteEpochSeq = REC_EPOCHSEQ_CAL(1, 10);
    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.config.tlsConfig.originVersionMask = DTLS13_VERSION_BIT;
    ctx.timeoutValue = 1000;
    ctx.timeoutNum = 3;
    msg[0] = KEY_UPDATE;
    BSL_Uint24ToByte(4, &msg[DTLS_HS_MSGLEN_ADDR]);
    BSL_Uint16ToByte(1, &msg[DTLS_HS_MSGSEQ_ADDR]);
    BSL_Uint24ToByte(0, &msg[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
    BSL_Uint24ToByte(4, &msg[DTLS_HS_FRAGMENT_LEN_ADDR]);
    msg[DTLS_HS_MSG_HEADER_SIZE] = 1;

    ResetAckStub();
    g_stubAckCbCnt = 0;
    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecOutBufReSet_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13Ack);

    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, msg, sizeof(msg),
        STUB_Dtls13RetransmitAckCb), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);

    BSL_Uint16ToByte((uint16_t)(sizeof(uint64_t) * 2), ackBuf);
    BSL_Uint64ToByte(1, &ackBuf[sizeof(uint16_t)]);
    BSL_Uint64ToByte(10, &ackBuf[sizeof(uint16_t) + sizeof(uint64_t)]);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, ackBuf, sizeof(ackBuf)), HITLS_SUCCESS);
    ASSERT_EQ(g_stubAckCbCnt, 1);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == true);
    ASSERT_EQ(ctx.timeoutValue, 0);
    ASSERT_EQ(ctx.timeoutNum, 0);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(REC_QueryMtu);
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_ACK_CB_FUNC_TC002
 * @title    DTLS1.3 retransmit ACK cleanup happens before callback failure is returned.
 * @brief    Process a full ACK with a failing callback.
 * @expect   The retransmit node is removed and the retransmit timer is stopped before returning callback error.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_ACK_CB_FUNC_TC002(void)
{
    uint8_t msg[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t ackBuf[sizeof(uint16_t) + sizeof(uint64_t) * 2] = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 1;
    recCtx.readEpoch = 3;
    recCtx.hasLastWriteEpochSeq = true;
    recCtx.lastWriteEpochSeq = REC_EPOCHSEQ_CAL(1, 10);
    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.config.tlsConfig.originVersionMask = DTLS13_VERSION_BIT;
    ctx.timeoutValue = 1000;
    ctx.timeoutNum = 3;
    BuildDtls13HsMsg(msg, KEY_UPDATE, 1, 4);

    ResetAckStub();
    g_stubAckCbCnt = 0;
    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecOutBufReSet_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13Ack);

    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, msg, sizeof(msg),
        STUB_Dtls13RetransmitAckCbFail), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);

    BSL_Uint16ToByte((uint16_t)(sizeof(uint64_t) * 2), ackBuf);
    BSL_Uint64ToByte(1, &ackBuf[sizeof(uint16_t)]);
    BSL_Uint64ToByte(10, &ackBuf[sizeof(uint16_t) + sizeof(uint64_t)]);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, ackBuf, sizeof(ackBuf)), HITLS_INTERNAL_EXCEPTION);
    ASSERT_EQ(g_stubAckCbCnt, 1);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == true);
    ASSERT_EQ(ctx.timeoutValue, 0);
    ASSERT_EQ(ctx.timeoutNum, 0);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(REC_QueryMtu);
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_KEYUPDATE_EXCLUSIVE_FUNC_TC001
 * @title    DTLS1.3 KeyUpdate gates later handshake messages to the next epoch.
 * @brief    Push KeyUpdate, then push NewSessionTicket while KeyUpdate is still unACKed.
 * @expect   The later message is queued for the next epoch, not written until KeyUpdate ACK flushes it.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_KEYUPDATE_EXCLUSIVE_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t ackBuf[sizeof(uint16_t) + REC_DTLS13_ACK_ITEM_LEN] = {0};
    uint8_t keyUpdate[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    uint8_t newSessionTicket[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 3;
    recCtx.hasLastWriteEpochSeq = true;
    recCtx.lastWriteEpochSeq = REC_EPOCHSEQ_CAL(3, 1);
    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.config.tlsConfig.originVersionMask = DTLS13_VERSION_BIT;
    BuildDtls13HsMsg(keyUpdate, KEY_UPDATE, 1, 1);
    BuildDtls13HsMsg(newSessionTicket, NEW_SESSION_TICKET, 2, 1);

    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecOutBufReSet_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13Ack);

    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, keyUpdate, sizeof(keyUpdate), NULL),
        HITLS_SUCCESS);
    uint32_t writeCntBeforeFuture = g_stubWriteCnt;
    ASSERT_TRUE(writeCntBeforeFuture > 0);
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, newSessionTicket,
        sizeof(newSessionTicket), NULL),
        HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, writeCntBeforeFuture);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);
    ASSERT_EQ(recCtx.retransmitList.head.next->next->next, &recCtx.retransmitList.head);
    RecRetransmitList *futureNode = BSL_LIST_ENTRY(recCtx.retransmitList.head.next->next, RecRetransmitList, head);
    ASSERT_EQ(futureNode->hsType, NEW_SESSION_TICKET);
    ASSERT_EQ(futureNode->epoch, 4);
    ASSERT_EQ(futureNode->ackState.seqMapSize, 0);

    ASSERT_EQ(REC_RetransmitListFlush(&ctx), HITLS_SUCCESS);
    ASSERT_TRUE(g_stubWriteCnt > writeCntBeforeFuture);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_HANDSHAKE);
    ASSERT_EQ(BSL_ByteToUint16(&g_stubAckBuf[DTLS_HS_MSGSEQ_ADDR]), 1);
    ASSERT_EQ(futureNode->ackState.seqMapSize, 0);

    REC_RetransmitListClean(&recCtx);
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, newSessionTicket,
        sizeof(newSessionTicket), NULL),
        HITLS_SUCCESS);

    REC_RetransmitListClean(&recCtx);
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    ResetAckStub();
    g_stubAckCbCnt = 0;
    recCtx.writeEpoch = 3;
    recCtx.hasLastWriteEpochSeq = true;
    recCtx.lastWriteEpochSeq = REC_EPOCHSEQ_CAL(3, 1);
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, keyUpdate, sizeof(keyUpdate),
        STUB_Dtls13KeyUpdateAckCbFlush),
        HITLS_SUCCESS);
    writeCntBeforeFuture = g_stubWriteCnt;
    ASSERT_TRUE(writeCntBeforeFuture > 0);
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, newSessionTicket,
        sizeof(newSessionTicket), NULL),
        HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, writeCntBeforeFuture);
    BSL_Uint16ToByte(REC_DTLS13_ACK_ITEM_LEN, ackBuf);
    BSL_Uint64ToByte(3, &ackBuf[sizeof(uint16_t)]);
    BSL_Uint64ToByte(1, &ackBuf[sizeof(uint16_t) + sizeof(uint64_t)]);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, ackBuf, sizeof(ackBuf)), HITLS_SUCCESS);
    ASSERT_EQ(g_stubAckCbCnt, 1);
    ASSERT_EQ(recCtx.writeEpoch, 4);
    ASSERT_TRUE(g_stubWriteCnt > writeCntBeforeFuture);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);
    RecRetransmitList *remaining = BSL_LIST_ENTRY(recCtx.retransmitList.head.next, RecRetransmitList, head);
    ASSERT_EQ(remaining->hsType, NEW_SESSION_TICKET);
    ASSERT_EQ(remaining->epoch, 4);
    ASSERT_EQ(remaining->ackState.seqMapSize, 1);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(REC_QueryMtu);
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_KEYUPDATE_PENDING_PHA_API_FUNC_TC001
 * @title    DTLS1.3 PHA request can be armed while KeyUpdate is waiting for ACK.
 * @brief    Prepare a transporting DTLS1.3 server with a KeyUpdate retransmit node, then call PHA API.
 * @expect   PHA API succeeds and marks PHA pending; the send path later queues the message for the next epoch.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_KEYUPDATE_PENDING_PHA_API_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t keyUpdate[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 3;
    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.state = CM_STATE_TRANSPORTING;
    ctx.phaState = PHA_EXTENSION;
    ctx.isClient = false;
    BuildDtls13HsMsg(keyUpdate, KEY_UPDATE, 1, 1);

    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, keyUpdate, sizeof(keyUpdate), NULL), HITLS_SUCCESS);
    ASSERT_TRUE(REC_Dtls13RetransmitListHasKeyUpdate(&recCtx) == true);
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(ctx.phaState, PHA_PENDING);
EXIT:
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_KEYUPDATE_PENDING_CID_API_FUNC_TC001
 * @title    DTLS1.3 RequestConnectionId can be armed while KeyUpdate is waiting for ACK.
 * @brief    Prepare a transporting DTLS1.3 connection with negotiated CID and a KeyUpdate retransmit node.
 * @expect   RequestConnectionId succeeds and marks the CID request pending; the send path later queues it next epoch.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_KEYUPDATE_PENDING_CID_API_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t keyUpdate[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 3;
    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.negotiatedInfo.isCidNegotiated = true;
    ctx.negotiatedInfo.peerCidEntry.cidLen = 4;
    ctx.state = CM_STATE_TRANSPORTING;
    BuildDtls13HsMsg(keyUpdate, KEY_UPDATE, 1, 1);

    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, keyUpdate, sizeof(keyUpdate), NULL), HITLS_SUCCESS);
    ASSERT_TRUE(REC_Dtls13RetransmitListHasKeyUpdate(&recCtx) == true);
    ASSERT_EQ(HITLS_RequestConnectionId(&ctx, 2), HITLS_SUCCESS);
    ASSERT_EQ(ctx.reqCidState, DTLS_CID_MSG_STATE_PENDING);
    ASSERT_EQ(ctx.reqCidNum, 2);
EXIT:
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_LAST_WRITE_RECORDNUM_FUNC_TC001
 * @title    DTLS last write record number query returns stored record number.
 * @brief    Set stored last write record state and query the record number.
 * @expect   Queried record number matches the stored DTLS record number.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_LAST_WRITE_RECORDNUM_FUNC_TC001(void)
{
    TLS_Ctx tlsCtx = {0};
    RecCtx recCtx = {0};
    RecordNumber recordNum = {0};
    tlsCtx.recCtx = &recCtx;
    tlsCtx.config.tlsConfig.originVersionMask = DTLS13_VERSION_BIT;
    recCtx.hasLastWriteEpochSeq = true;
    recCtx.lastWriteEpochSeq = REC_EPOCHSEQ_CAL(3, 9);
    ASSERT_EQ(REC_GetLastWriteRecordNum(&tlsCtx, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(recordNum.epoch, 3);
    ASSERT_EQ(recordNum.sequenceNumber, 9);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_TIMEOUT_ACK_FUNC_TC001
 * @title    DTLS1.3 timeout sends ack list and clears pending state.
 * @brief    Prepare partial peer flight, trigger timeout, and verify ACK write.
 * @expect   ACK record is written once and ack list becomes empty.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_TIMEOUT_ACK_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    RecordNumber recordNum = {0};
    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    ResetAckStub();
    g_stubRetransmitFlushCnt = 0;
    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 3);
    ASSERT_EQ(REC_Dtls13AckListAppend(&ctx, &recordNum), HITLS_SUCCESS);
    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13Ack);
    STUB_REPLACE(REC_RetransmitListFlush, STUB_REC_RetransmitListFlush_Dtls13);
    ASSERT_EQ(REC_Dtls13FlushAck(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(REC_RetransmitListFlush(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_ACK);
    ASSERT_EQ(g_stubRecordLen, sizeof(uint16_t) + 2 * REC_DTLS13_ACK_ITEM_LEN);
    ASSERT_EQ(BSL_ByteToUint16(g_stubAckBuf), (uint16_t)(2 * REC_DTLS13_ACK_ITEM_LEN));
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t)]), 1);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t) + sizeof(uint64_t)]), 2);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t) + REC_DTLS13_ACK_ITEM_LEN]), 1);
    ASSERT_EQ(BSL_ByteToUint64(&g_stubAckBuf[sizeof(uint16_t) + REC_DTLS13_ACK_ITEM_LEN + sizeof(uint64_t)]), 3);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(&ctx, REC_DTLS13_ACK_NORMAL) == true);
    ASSERT_EQ(g_stubRetransmitFlushCnt, 1);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(REC_RetransmitListFlush);
    BSL_SAL_FREE(recCtx.ackList.records);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_TIMEOUT_RETRANS_FUNC_TC001
 * @title    DTLS1.3 timeout falls back to retransmit flush without peer partial flight.
 * @brief    Trigger timeout processing without partial peer flight.
 * @expect   Retransmit flush path is invoked exactly once.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_TIMEOUT_RETRANS_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    g_stubRetransmitFlushCnt = 0;
    STUB_REPLACE(REC_RetransmitListFlush, STUB_REC_RetransmitListFlush_Dtls13);
    ASSERT_EQ(REC_Dtls13FlushAck(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(REC_RetransmitListFlush(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(g_stubRetransmitFlushCnt, 1);
EXIT:
    STUB_RESTORE(REC_RetransmitListFlush);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_ACK_PARSE_INVALID_FUNC_TC001
 * @title    DTLS1.3 ACK parse rejects malformed lengths.
 * @brief    Feed short, mismatched, and non-item-aligned ACK buffers to ACK processing.
 * @expect   Each malformed ACK buffer is rejected with HITLS_PARSE_INVALID_MSG_LEN and sends decode_error alert.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_ACK_PARSE_INVALID_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    uint8_t shortBuf[1] = {0};
    uint8_t mismatchBuf[sizeof(uint16_t) + 1] = {0};
    uint8_t unalignedBuf[sizeof(uint16_t) + 1] = {0};
    ctx.recCtx = &recCtx;
    ctx.method.sendAlert = STUB_SendAlert;
    BSL_LIST_INIT(&recCtx.retransmitList.head);

    BSL_Uint16ToByte(2, mismatchBuf);
    BSL_Uint16ToByte(1, unalignedBuf);

    g_stubAlertCnt = 0;
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, shortBuf, sizeof(shortBuf)), HITLS_PARSE_INVALID_MSG_LEN);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, mismatchBuf, sizeof(mismatchBuf)), HITLS_PARSE_INVALID_MSG_LEN);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, unalignedBuf, sizeof(unalignedBuf)), HITLS_PARSE_INVALID_MSG_LEN);
    ASSERT_EQ(g_stubAlertCnt, 3);
    ASSERT_EQ(g_stubAlertLevel, ALERT_LEVEL_FATAL);
    ASSERT_EQ(g_stubAlertDescription, ALERT_DECODE_ERROR);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_PUSH_FUNC_TC001
 * @title    DTLS1.3 retransmit push validates null inputs.
 * @brief    Call retransmit push with null context.
 * @expect   Interface returns the corresponding error code.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_PUSH_FUNC_TC001(void)
{
    uint8_t msg[DTLS_HS_MSG_HEADER_SIZE + 1] = {0};
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(NULL, REC_TYPE_HANDSHAKE, msg, sizeof(msg), NULL), HITLS_NULL_INPUT);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_SELECTIVE_FUNC_TC001
 * @title    DTLS1.3 selective retransmit only resends unACKed Certificate after partial ACK.
 * @brief    Push 5 server flight messages, ACK 4 (ServerHello, EncryptedExtensions,
 *           CertificateVerify, Finished), verify Certificate remains, then trigger
 *           selective retransmit and verify only Certificate is resent.
 * @expect   After ACK processing, only Certificate node remains with full gaps.
 *           Selective retransmit writes only Certificate handshake data.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_SELECTIVE_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    ctx.recCtx = &recCtx;
    ctx.isClient = false;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.config.tlsConfig.originVersionMask = DTLS13_VERSION_BIT;
    BSL_LIST_INIT(&recCtx.retransmitList.head);
    recCtx.writeEpoch = 1;

    uint8_t body4[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t bodyCert[20] = {0};
    for (int i = 0; i < 20; i++) { bodyCert[i] = (uint8_t)i; }

    uint8_t serverHello[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    serverHello[0] = SERVER_HELLO;
    BSL_Uint24ToByte(4, &serverHello[1]);
    BSL_Uint16ToByte(0, &serverHello[4]);
    BSL_Uint24ToByte(0, &serverHello[6]);
    BSL_Uint24ToByte(4, &serverHello[9]);
    memcpy(&serverHello[DTLS_HS_MSG_HEADER_SIZE], body4, 4);

    uint8_t encryptedExtensions[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    encryptedExtensions[0] = ENCRYPTED_EXTENSIONS;
    BSL_Uint24ToByte(4, &encryptedExtensions[1]);
    BSL_Uint16ToByte(1, &encryptedExtensions[4]);
    BSL_Uint24ToByte(0, &encryptedExtensions[6]);
    BSL_Uint24ToByte(4, &encryptedExtensions[9]);
    memcpy(&encryptedExtensions[DTLS_HS_MSG_HEADER_SIZE], body4, 4);

    uint8_t certificate[DTLS_HS_MSG_HEADER_SIZE + 20] = {0};
    certificate[0] = CERTIFICATE;
    BSL_Uint24ToByte(20, &certificate[1]);
    BSL_Uint16ToByte(2, &certificate[4]);
    BSL_Uint24ToByte(0, &certificate[6]);
    BSL_Uint24ToByte(20, &certificate[9]);
    memcpy(&certificate[DTLS_HS_MSG_HEADER_SIZE], bodyCert, 20);

    uint8_t certificateVerify[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    certificateVerify[0] = CERTIFICATE_VERIFY;
    BSL_Uint24ToByte(4, &certificateVerify[1]);
    BSL_Uint16ToByte(3, &certificateVerify[4]);
    BSL_Uint24ToByte(0, &certificateVerify[6]);
    BSL_Uint24ToByte(4, &certificateVerify[9]);
    memcpy(&certificateVerify[DTLS_HS_MSG_HEADER_SIZE], body4, 4);

    uint8_t finished[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    finished[0] = FINISHED;
    BSL_Uint24ToByte(4, &finished[1]);
    BSL_Uint16ToByte(4, &finished[4]);
    BSL_Uint24ToByte(0, &finished[6]);
    BSL_Uint24ToByte(4, &finished[9]);
    memcpy(&finished[DTLS_HS_MSG_HEADER_SIZE], body4, 4);

    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, serverHello, sizeof(serverHello), NULL), HITLS_SUCCESS);
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, encryptedExtensions, sizeof(encryptedExtensions), NULL), HITLS_SUCCESS);
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, certificate, sizeof(certificate), NULL), HITLS_SUCCESS);
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, certificateVerify, sizeof(certificateVerify), NULL), HITLS_SUCCESS);
    ASSERT_EQ(RecRetransmitListAppendNode(&recCtx, REC_TYPE_HANDSHAKE, finished, sizeof(finished), NULL), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);

    ListHead *head = recCtx.retransmitList.head.next;
    RecRetransmitList *nodeSH = BSL_LIST_ENTRY(head, RecRetransmitList, head);
    head = head->next;
    RecRetransmitList *nodeEE = BSL_LIST_ENTRY(head, RecRetransmitList, head);
    head = head->next;
    RecRetransmitList *nodeCert = BSL_LIST_ENTRY(head, RecRetransmitList, head);
    head = head->next;
    RecRetransmitList *nodeCV = BSL_LIST_ENTRY(head, RecRetransmitList, head);
    head = head->next;
    RecRetransmitList *nodeFin = BSL_LIST_ENTRY(head, RecRetransmitList, head);

    RecordNumber recordNum = {0};
    recordNum = MakeRecordNumber(1, 0);
    ASSERT_EQ(AckStateInsertSeqMap(&nodeSH->ackState, &recordNum, 0, 4), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 1);
    ASSERT_EQ(AckStateInsertSeqMap(&nodeEE->ackState, &recordNum, 0, 4), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 2);
    ASSERT_EQ(AckStateInsertSeqMap(&nodeCert->ackState, &recordNum, 0, 20), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 3);
    ASSERT_EQ(AckStateInsertSeqMap(&nodeCV->ackState, &recordNum, 0, 4), HITLS_SUCCESS);
    recordNum = MakeRecordNumber(1, 4);
    ASSERT_EQ(AckStateInsertSeqMap(&nodeFin->ackState, &recordNum, 0, 4), HITLS_SUCCESS);

    uint8_t ackBuf[sizeof(uint16_t) + 4 * REC_DTLS13_ACK_ITEM_LEN] = {0};
    BSL_Uint16ToByte((uint16_t)(4 * REC_DTLS13_ACK_ITEM_LEN), ackBuf);
    uint32_t off = sizeof(uint16_t);
    BSL_Uint64ToByte(1, &ackBuf[off]);
    BSL_Uint64ToByte(0, &ackBuf[off + sizeof(uint64_t)]);
    off += REC_DTLS13_ACK_ITEM_LEN;
    BSL_Uint64ToByte(1, &ackBuf[off]);
    BSL_Uint64ToByte(1, &ackBuf[off + sizeof(uint64_t)]);
    off += REC_DTLS13_ACK_ITEM_LEN;
    BSL_Uint64ToByte(1, &ackBuf[off]);
    BSL_Uint64ToByte(3, &ackBuf[off + sizeof(uint64_t)]);
    off += REC_DTLS13_ACK_ITEM_LEN;
    BSL_Uint64ToByte(1, &ackBuf[off]);
    BSL_Uint64ToByte(4, &ackBuf[off + sizeof(uint64_t)]);
    ASSERT_EQ(REC_RetransmitListProcessAck(&ctx, ackBuf, sizeof(ackBuf)), HITLS_SUCCESS);

    ASSERT_TRUE(REC_RetransmitIsEmpty(&recCtx) == false);
    uint32_t nodeCount = 0;
    ListHead *pos = NULL;
    ListHead *posTmp = NULL;
    LIST_FOR_EACH_ITEM_SAFE(pos, posTmp, &recCtx.retransmitList.head) { nodeCount++; }
    ASSERT_EQ(nodeCount, 1);
    RecRetransmitList *remaining = BSL_LIST_ENTRY(recCtx.retransmitList.head.next, RecRetransmitList, head);
    ASSERT_EQ(remaining->bodyLen, 20);
    ASSERT_EQ(remaining->ackState.unackedBytes, remaining->ackState.totalLen);
    ASSERT_TRUE(remaining->ackState.unackedBytes != 0);

    ResetAckStub();
    recCtx.hasLastWriteEpochSeq = true;
    recCtx.lastWriteEpochSeq = REC_EPOCHSEQ_CAL(1, 10);

    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecOutBufReSet_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13Ack);
    ASSERT_EQ(REC_RetransmitListFlush(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_HANDSHAKE);
    ASSERT_TRUE(g_stubRecordLen > DTLS_HS_MSG_HEADER_SIZE);
    ASSERT_EQ(BSL_ByteToUint16(&g_stubAckBuf[DTLS_HS_MSGSEQ_ADDR]), 2);
    ASSERT_EQ(BSL_ByteToUint24(&g_stubAckBuf[DTLS_HS_FRAGMENT_OFFSET_ADDR]), 0);
    ASSERT_EQ(BSL_ByteToUint24(&g_stubAckBuf[DTLS_HS_FRAGMENT_LEN_ADDR]), 20);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(REC_QueryMtu);
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_EPOCH0_PLAINTEXT_FUNC_TC001
 * @title    DTLS1.3 ServerHello retransmit uses plaintext epoch-0 state after key switch.
 * @brief    Send a ServerHello retransmit node in epoch 0, then simulate the server after Finished
 *           with current epoch 3 and outdated epoch 2, and flush the retransmit list.
 * @expect   The retransmitted ServerHello is written with epoch 0 and no cipher state, while the
 *           original current/outdated write states are restored.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_EPOCH0_PLAINTEXT_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    RecConnState epoch0State = {0};
    RecConnState epoch2State = {0};
    RecConnState epoch3State = {0};
    RecConnSuitInfo epoch2Suite = {0};
    RecConnSuitInfo epoch3Suite = {0};
    uint8_t serverHello[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};

    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.config.tlsConfig.originVersionMask = DTLS13_VERSION_BIT;
    BSL_LIST_INIT(&recCtx.retransmitList.head);

    RecConnSetEpoch(&epoch0State, 0);
    RecConnSetSeqNum(&epoch0State, 6);
    recCtx.writeEpoch = 0;
    recCtx.writeStates.currentState = &epoch0State;
    BuildDtls13HsMsg(serverHello, SERVER_HELLO, 0, 4);

    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecOutBufReSet_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13State);

    ResetWriteStateStub();
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, serverHello, sizeof(serverHello), NULL),
        HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, 1);
    ASSERT_EQ(g_stubWriteStateEpoch, 0);
    ASSERT_EQ(g_stubWriteStateSeq, 6);
    ASSERT_TRUE(g_stubWriteStateIsPlain == true);
    ASSERT_EQ(RecConnGetSeqNum(&epoch0State), 7);

    RecRetransmitList *node = BSL_LIST_ENTRY(recCtx.retransmitList.head.next, RecRetransmitList, head);
    ASSERT_EQ(node->epoch, 0);
    ASSERT_EQ(node->nextRecordSeq, 7);

    RecConnSetEpoch(&epoch2State, 2);
    RecConnSetSeqNum(&epoch2State, 11);
    epoch2State.suiteInfo = &epoch2Suite;
    RecConnSetEpoch(&epoch3State, 3);
    RecConnSetSeqNum(&epoch3State, 19);
    epoch3State.suiteInfo = &epoch3Suite;
    recCtx.writeEpoch = 3;
    recCtx.writeStates.currentState = &epoch3State;
    recCtx.writeStates.outdatedState = &epoch2State;

    ResetWriteStateStub();
    ASSERT_EQ(REC_RetransmitListFlush(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, 1);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_HANDSHAKE);
    ASSERT_EQ(g_stubWriteStateEpoch, 0);
    ASSERT_EQ(g_stubWriteStateSeq, 7);
    ASSERT_TRUE(g_stubWriteStateIsPlain == true);
    ASSERT_EQ(node->nextRecordSeq, 8);
    ASSERT_TRUE(recCtx.writeStates.currentState == &epoch3State);
    ASSERT_TRUE(recCtx.writeStates.outdatedState == &epoch2State);
    ASSERT_EQ(RecConnGetSeqNum(&epoch3State), 19);
    ASSERT_EQ(RecConnGetSeqNum(&epoch2State), 11);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(REC_QueryMtu);
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */

/**
 * @test     UT_TLS_DTLS13_RETRANS_AFTER_APP_WRITE_FUNC_TC001
 * @title    DTLS1.3 client final-flight retransmit still uses epoch-2 state after app write.
 * @brief    Send a client Finished retransmit node in epoch 2, then simulate the client switching
 *           to epoch 3 and writing application data before flushing the retransmit list.
 * @expect   The retransmitted Finished is written with the epoch-2 outdated write state, while
 *           the epoch-3 application write sequence is preserved.
 */
/* BEGIN_CASE */
void UT_TLS_DTLS13_RETRANS_AFTER_APP_WRITE_FUNC_TC001(void)
{
    TLS_Ctx ctx = {0};
    RecCtx recCtx = {0};
    RecConnState epoch2State = {0};
    RecConnState epoch3State = {0};
    RecConnSuitInfo epoch2Suite = {0};
    RecConnSuitInfo epoch3Suite = {0};
    uint8_t certificate[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    uint8_t certVerify[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};
    uint8_t finished[DTLS_HS_MSG_HEADER_SIZE + 4] = {0};

    ctx.recCtx = &recCtx;
    ctx.negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx.config.tlsConfig.originVersionMask = DTLS13_VERSION_BIT;
    BSL_LIST_INIT(&recCtx.retransmitList.head);

    RecConnSetEpoch(&epoch2State, 2);
    RecConnSetSeqNum(&epoch2State, 0);
    epoch2State.suiteInfo = &epoch2Suite;
    recCtx.writeEpoch = 2;
    recCtx.writeStates.currentState = &epoch2State;
    BuildDtls13HsMsg(certificate, CERTIFICATE, 0, 4);
    BuildDtls13HsMsg(certVerify, CERTIFICATE_VERIFY, 1, 4);
    BuildDtls13HsMsg(finished, FINISHED, 2, 4);

    STUB_REPLACE(REC_QueryMtu, STUB_REC_QueryMtu_Selective);
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecOutBufReSet_Selective);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_Selective);
    STUB_REPLACE(REC_Write, STUB_REC_Write_Dtls13State);

    ResetWriteStateStub();
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, certificate, sizeof(certificate), NULL),
        HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, 1);
    ASSERT_EQ(g_stubWriteStateEpoch, 2);
    ASSERT_EQ(g_stubWriteStateSeq, 0);
    ASSERT_EQ(RecConnGetSeqNum(&epoch2State), 1);
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, certVerify, sizeof(certVerify), NULL),
        HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, 2);
    ASSERT_EQ(g_stubWriteStateEpoch, 2);
    ASSERT_EQ(g_stubWriteStateSeq, 1);
    ASSERT_EQ(RecConnGetSeqNum(&epoch2State), 2);
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(&ctx, REC_TYPE_HANDSHAKE, finished, sizeof(finished), NULL),
        HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, 3);
    ASSERT_EQ(g_stubWriteStateEpoch, 2);
    ASSERT_EQ(g_stubWriteStateSeq, 2);
    ASSERT_EQ(RecConnGetSeqNum(&epoch2State), 3);

    RecRetransmitList *node = BSL_LIST_ENTRY(recCtx.retransmitList.head.next, RecRetransmitList, head);
    ASSERT_EQ(node->epoch, 2);
    ASSERT_EQ(node->nextRecordSeq, 1);

    RecConnSetEpoch(&epoch3State, 3);
    RecConnSetSeqNum(&epoch3State, 0);
    epoch3State.suiteInfo = &epoch3Suite;
    recCtx.writeEpoch = 3;
    recCtx.writeStates.currentState = &epoch3State;
    recCtx.writeStates.outdatedState = &epoch2State;

    ResetWriteStateStub();
    ASSERT_EQ(STUB_REC_Write_Dtls13State(&ctx, REC_TYPE_APP, finished, sizeof(finished)), HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteStateEpoch, 3);
    ASSERT_EQ(g_stubWriteStateSeq, 0);
    ASSERT_EQ(RecConnGetSeqNum(&epoch3State), 1);
    ASSERT_EQ(RecConnGetSeqNum(&epoch2State), 3);

    ResetWriteStateStub();
    ASSERT_EQ(REC_RetransmitListFlush(&ctx), HITLS_SUCCESS);
    ASSERT_EQ(g_stubWriteCnt, 3);
    ASSERT_EQ(g_stubRecordType, REC_TYPE_HANDSHAKE);
    ASSERT_EQ(g_stubWriteStateEpoch, 2);
    ASSERT_EQ(g_stubWriteStateSeq, 5);
    ASSERT_EQ(g_stubWriteStateEpochTrace[0], 2);
    ASSERT_EQ(g_stubWriteStateSeqTrace[0], 3);
    ASSERT_EQ(g_stubWriteStateEpochTrace[1], 2);
    ASSERT_EQ(g_stubWriteStateSeqTrace[1], 4);
    ASSERT_EQ(g_stubWriteStateEpochTrace[2], 2);
    ASSERT_EQ(g_stubWriteStateSeqTrace[2], 5);
    ASSERT_EQ(node->nextRecordSeq, 4);
    ASSERT_TRUE(recCtx.writeStates.currentState == &epoch3State);
    ASSERT_TRUE(recCtx.writeStates.outdatedState == &epoch2State);
    ASSERT_EQ(RecConnGetSeqNum(&epoch3State), 1);
    ASSERT_EQ(RecConnGetSeqNum(&epoch2State), 6);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(REC_QueryMtu);
    REC_RetransmitListClean(&recCtx);
    return;
}
/* END_CASE */
