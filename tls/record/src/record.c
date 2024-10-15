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

#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "rec.h"
#include "bsl_uio.h"
#include "rec_write.h"
#include "rec_read.h"
#include "record.h"

static int32_t RecConnStatesInit(RecCtx *recordCtx)
{
    recordCtx->readStates.currentState = RecConnStateNew();
    if (recordCtx->readStates.currentState == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    recordCtx->writeStates.currentState = RecConnStateNew();
    if (recordCtx->writeStates.currentState == NULL) {
        RecConnStateFree(recordCtx->readStates.currentState);
        recordCtx->readStates.currentState = NULL;
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    return HITLS_SUCCESS;
}

// Release RecStatesSuite
static void RecConnStatesDeinit(RecCtx *recordCtx)
{
    RecConnStateFree(recordCtx->readStates.currentState);
    RecConnStateFree(recordCtx->writeStates.currentState);
    return;
}

// Calculate the size of the returned buffer based on the protocol type
uint32_t RecGetInitBufferSize(const TLS_Ctx *ctx)
{
    (void)ctx;
#ifndef HITLS_NO_DTLS12

    /* If the DTLS protocol is used */
    if (IS_DTLS_VERSION(ctx->config.tlsConfig.maxVersion)) {
        /* In non-small-scale scenarios and SCTP scenarios, the size of the transmit end and receive end is 18 KB */
        return (REC_MAX_CIPHER_TEXT_LEN + REC_DTLS_RECORD_HEADER_LEN);
    }

#endif

    /* If the TLS protocol is used, there is no PMTU limit */
    return (REC_MAX_CIPHER_TEXT_LEN + REC_TLS_RECORD_HEADER_LEN);
}

int32_t REC_Init(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_MEMALLOC_FAIL;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (ctx->recCtx != NULL) {
        return HITLS_SUCCESS;
    }
    /* Allocate RecCtxHandle space */
    RecCtx *newRecCtx = (RecCtx *)BSL_SAL_Calloc(1, sizeof(RecCtx));
    if (newRecCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15531, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    uint32_t bufSize = RecGetInitBufferSize(ctx);
    newRecCtx->inBuf = RecBufNew(bufSize);
    if (newRecCtx->inBuf == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15532, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: malloc fail.", 0, 0, 0, 0);
        goto ERR;
    }

    newRecCtx->outBuf = RecBufNew(bufSize);
    if (newRecCtx->outBuf == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15533, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: malloc fail.", 0, 0, 0, 0);
        goto ERR;
    }

    ret = RecConnStatesInit(newRecCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15534, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: init connect state fail.", 0, 0, 0, 0);
        goto ERR;
    }

#ifndef HITLS_NO_DTLS12
    UnprocessedAppMsgListInit(&newRecCtx->unprocessedAppMsgList);
    LIST_INIT(&newRecCtx->retransmitList.head);
#endif

    ctx->recCtx = newRecCtx;
    return HITLS_SUCCESS;

ERR:
    RecBufFree(newRecCtx->outBuf);
    RecBufFree(newRecCtx->inBuf);
    BSL_SAL_FREE(newRecCtx);
    return ret;
}

void REC_DeInit(TLS_Ctx *ctx)
{
    if (ctx != NULL && ctx->recCtx != NULL) {
        RecCtx *recordCtx = (RecCtx *)ctx->recCtx;

        RecBufFree(recordCtx->outBuf);
        RecBufFree(recordCtx->inBuf);

        RecConnStatesDeinit(recordCtx);
        RecConnStateFree(recordCtx->readStates.pendingState);
        RecConnStateFree(recordCtx->writeStates.pendingState);
        RecConnStateFree(recordCtx->readStates.outdatedState);
        RecConnStateFree(recordCtx->writeStates.outdatedState);

#ifndef HITLS_NO_DTLS12
        BSL_SAL_FREE(recordCtx->unprocessedHsMsg.recordBody);
        UnprocessedAppMsgListDeinit(&recordCtx->unprocessedAppMsgList);
#endif
        BSL_SAL_FREE(ctx->recCtx);
    }
    return;
}

bool REC_ReadHasPending(const TLS_Ctx *ctx)
{
    if ((ctx == NULL) || (ctx->recCtx == NULL)) {
        return false;
    }

    /* Obtain the record structure */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecBuf *inBuf = recordCtx->inBuf;

    if (inBuf == NULL) {
        return false;
    }

    if (inBuf->end != inBuf->start) {
        return true;
    }

    return false;
}

int32_t REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    if ((ctx == NULL) || (ctx->recCtx == NULL) || (data == NULL)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15535, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: input invalid parameter.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t minBufSize = REC_MAX_PLAIN_LENGTH;

    if (num < minBufSize) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_BUFFER_NOT_ENOUGH);
        return HITLS_REC_ERR_BUFFER_NOT_ENOUGH;
    }

    ctx->rwstate = HITLS_NOTHING;

#ifndef HITLS_NO_DTLS12
    if (IS_DTLS_VERSION(ctx->config.tlsConfig.maxVersion)) {
        return DtlsRecordRead(ctx, recordType, data, readLen, num);
    }
#endif
    return TlsRecordRead(ctx, recordType, data, readLen, num);
}

int32_t REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    if ((ctx == NULL) || (ctx->recCtx == NULL) ||
        (num != 0 && data == NULL) ||
        (num == 0 && recordType != REC_TYPE_APP)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15537, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: input null pointer.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    ctx->rwstate = HITLS_NOTHING;

    uint32_t maxWriteSize;
    (void)REC_GetMaxWriteSize(ctx, &maxWriteSize);
    if (num > maxWriteSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15539, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record wrtie: plain length is too long.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_TOO_BIG_LENGTH);
        return HITLS_REC_ERR_TOO_BIG_LENGTH;
    }

#ifndef HITLS_NO_DTLS12
    if (IS_DTLS_VERSION(ctx->config.tlsConfig.maxVersion)) {
        /* DTLS */
        return DtlsRecordWrite(ctx, recordType, data, num);
    }
#endif

    return TlsRecordWrite(ctx, recordType, data, num);
}

int32_t REC_InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param)
{
    if (ctx == NULL || ctx->recCtx == NULL || param == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15540, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: ctx is NULL", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret = HITLS_MEMALLOC_FAIL;
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnSuitInfo clientSuitInfo = {0};
    RecConnSuitInfo serverSuitInfo = {0};
    RecConnSuitInfo *out = NULL;
    RecConnSuitInfo *in = NULL;

    RecConnState *readState = RecConnStateNew();
    RecConnState *writeState = RecConnStateNew();
    if (readState == NULL || writeState == NULL) {
        goto ERR;
    }

    /* 1.Generate a secret */
    ret = RecConnKeyBlockGen(param, &clientSuitInfo, &serverSuitInfo);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    /* 2.Set the corresponding read/write pending state */
    out = (param->isClient == true) ? &clientSuitInfo : &serverSuitInfo;
    in = (param->isClient == true) ? &serverSuitInfo : &clientSuitInfo;
    ret = RecConnStateSetCipherInfo(writeState, out);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    ret = RecConnStateSetCipherInfo(readState, in);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    /* Clear sensitive information */
    BSL_SAL_CleanseData((void *)&clientSuitInfo, sizeof(RecConnSuitInfo));
    BSL_SAL_CleanseData((void *)&serverSuitInfo, sizeof(RecConnSuitInfo));
    RecConnStateFree(recordCtx->readStates.pendingState);
    RecConnStateFree(recordCtx->writeStates.pendingState);
    recordCtx->readStates.pendingState = readState;
    recordCtx->writeStates.pendingState = writeState;
    return HITLS_SUCCESS;
ERR:
    /* Clear sensitive information */
    BSL_SAL_CleanseData((void *)&clientSuitInfo, sizeof(RecConnSuitInfo));
    BSL_SAL_CleanseData((void *)&serverSuitInfo, sizeof(RecConnSuitInfo));
    RecConnStateFree(readState);
    RecConnStateFree(writeState);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15541, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Record: malloc fail.", 0, 0, 0, 0);
    return ret;
}

int32_t REC_TLS13InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param, bool isOut)
{
    if (ctx == NULL || ctx->recCtx == NULL || param == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15542, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: ctx is NULL", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnSuitInfo suitInfo = {0};
    RecConnState *state = RecConnStateNew();
    if (state == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* 1.Generate a secret */
    int32_t ret = RecTLS13ConnKeyBlockGen(param, &suitInfo);
    if (ret != HITLS_SUCCESS) {
        RecConnStateFree(state);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* 2.Set the corresponding read/write pending state */
    RecConnStates *curState = NULL;
    if (isOut) {
        curState = &(recordCtx->writeStates);
    }  else {
        curState = &(recordCtx->readStates);
    }

    ret = RecConnStateSetCipherInfo(state, &suitInfo);
    if (ret != HITLS_SUCCESS) {
        RecConnStateFree(state);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    RecConnStateFree(curState->pendingState);
    curState->pendingState = state;
    return HITLS_SUCCESS;
}

int32_t REC_ActivePendingState(TLS_Ctx *ctx, bool isOut)
{
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnStates *states = (isOut == true) ? &recordCtx->writeStates : &recordCtx->readStates;

    if (states->pendingState == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15543, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: pending state should not be null.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }
    RecConnStateFree(states->outdatedState);
    states->outdatedState = states->currentState;
    states->currentState = states->pendingState;
    states->pendingState = NULL;
    /* Set the sequence number to 0 */
    RecConnSetSeqNum(states->currentState, 0);

#ifndef HITLS_NO_DTLS12
    if (IS_DTLS_VERSION(ctx->config.tlsConfig.maxVersion)) {
        if (isOut) {
            ++recordCtx->writeEpoch;
            RecConnSetEpoch(states->currentState, recordCtx->writeEpoch);
        } else {
            ++recordCtx->readEpoch;
            RecConnSetEpoch(states->currentState, recordCtx->readEpoch);
        }
    }
#endif

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15544, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "Record: active pending state.", 0, 0, 0, 0);
    return HITLS_SUCCESS;
}

int32_t REC_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len)
{
    if (ctx == NULL || ctx->recCtx == NULL || len == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15545, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: input null pointer.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *len = REC_MAX_PLAIN_TEXT_LENGTH;
    return HITLS_SUCCESS;
}
