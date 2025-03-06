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
#include "rec_crypto.h"
#include "hs.h"
#include "alert.h"
#include "record.h"

// Release RecStatesSuite
static void RecConnStatesDeinit(RecCtx *recordCtx)
{
    RecConnStateFree(recordCtx->readStates.currentState);
    RecConnStateFree(recordCtx->writeStates.currentState);
    return;
}

static uint32_t RecGetDefaultBufferSize(bool isDtls, bool isRead)
{
(void)isDtls;
    uint32_t recHeaderLen =
#ifdef HITLS_TLS_PROTO_DTLS12
        isDtls ? REC_DTLS_RECORD_HEADER_LEN :
#endif
        REC_TLS_RECORD_HEADER_LEN;
    uint32_t overHead = REC_MAX_WRITE_ENCRYPTED_OVERHEAD;
    if (isRead) {
        overHead = REC_MAX_READ_ENCRYPTED_OVERHEAD;
    }
    return recHeaderLen + REC_MAX_PLAIN_TEXT_LENGTH + overHead;
}

static uint32_t RecGetReadBufferSize(const TLS_Ctx *ctx)
{
    uint32_t recSize = RecGetDefaultBufferSize(IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask), true);
    return recSize;
}

static uint32_t RecGetWriteBufferSize(const TLS_Ctx *ctx)
{
    uint32_t recSize = RecGetDefaultBufferSize(IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask), false);
    return recSize;
}

uint32_t RecGetInitBufferSize(const TLS_Ctx *ctx, bool isRead)
{
    /* If the TLS protocol is used, there is no PMTU limit */
    return isRead ? RecGetReadBufferSize(ctx) : RecGetWriteBufferSize(ctx);
}

int32_t RecDerefBufList(TLS_Ctx *ctx)
{
    int32_t ret = RecBufListDereference(ctx->recCtx->appRecList);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return RecBufListDereference(ctx->recCtx->hsRecList);
}


static int32_t InnerRecRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    (void)recordType;
    (void)readLen;
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_NOTHING;
#endif

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return DtlsRecordRead(ctx, recordType, data, readLen, num);
    }
#endif
#ifdef HITLS_TLS_PROTO_TLS
    return TlsRecordRead(ctx, recordType, data, readLen, num);
#else
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17294, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "internal exception occurs", 0, 0, 0, 0);
    return HITLS_INTERNAL_EXCEPTION;
#endif
}
static int32_t InnerRecWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_NOTHING;
#endif

    uint32_t maxWriteSize;
    int32_t ret = REC_GetMaxWriteSize(ctx, &maxWriteSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17295, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetMaxWriteSize fail", 0, 0, 0, 0);
        return ret;
    }
    if (num > maxWriteSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15539, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record wrtie: plain length is too long.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_TOO_BIG_LENGTH);
        return HITLS_REC_ERR_TOO_BIG_LENGTH;
    }

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        /* DTLS */
        return DtlsRecordWrite(ctx, recordType, data, num);
    }
#endif
#ifdef HITLS_TLS_PROTO_TLS
    return TlsRecordWrite(ctx, recordType, data, num);
#else
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17296, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "internal exception occurs", 0, 0, 0, 0);
    return HITLS_INTERNAL_EXCEPTION;
#endif
}

static int32_t RecConnStatesInit(RecCtx *recordCtx)
{
    recordCtx->recRead = InnerRecRead;
    recordCtx->recWrite = InnerRecWrite;
    recordCtx->readStates.currentState = RecConnStateNew();
    if (recordCtx->readStates.currentState == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17297, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "StateNew fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    recordCtx->writeStates.currentState = RecConnStateNew();
    if (recordCtx->writeStates.currentState == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17298, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "StateNew fail", 0, 0, 0, 0);
        RecConnStateFree(recordCtx->readStates.currentState);
        recordCtx->readStates.currentState = NULL;
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    return HITLS_SUCCESS;
}

static int RecBufInit(TLS_Ctx *ctx, RecCtx *newRecCtx)
{
    newRecCtx->inBuf = RecBufNew(RecGetInitBufferSize(ctx, true));
    if (newRecCtx->inBuf == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15532, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    newRecCtx->outBuf = RecBufNew(RecGetInitBufferSize(ctx, false));
    if (newRecCtx->outBuf == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15533, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    newRecCtx->hsRecList = RecBufListNew();
    newRecCtx->appRecList = RecBufListNew();
    if (newRecCtx->hsRecList == NULL || newRecCtx->appRecList == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17299, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "BufListNew fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    return HITLS_SUCCESS;
}

static void RecDeInit(RecCtx *recordCtx)
{
    RecBufFree(recordCtx->outBuf);
    RecBufFree(recordCtx->inBuf);
    RecBufListFree(recordCtx->hsRecList);
    RecBufListFree(recordCtx->appRecList);

    RecConnStatesDeinit(recordCtx);
    RecConnStateFree(recordCtx->readStates.pendingState);
    RecConnStateFree(recordCtx->writeStates.pendingState);
    RecConnStateFree(recordCtx->readStates.outdatedState);
    RecConnStateFree(recordCtx->writeStates.outdatedState);

#ifdef HITLS_TLS_PROTO_DTLS12
    UnprocessedAppMsgListDeinit(&recordCtx->unprocessedAppMsgList);
#endif /* HITLS_TLS_PROTO_DTLS12 */
}

int32_t REC_Init(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_MEMALLOC_FAIL;
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17300, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "ctx null", 0, 0, 0, 0);
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
#ifdef HITLS_TLS_PROTO_DTLS12
    UnprocessedAppMsgListInit(&newRecCtx->unprocessedAppMsgList);
#endif
    ret = RecBufInit(ctx, newRecCtx);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    ret = RecConnStatesInit(newRecCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15534, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: init connect state fail.", 0, 0, 0, 0);
        goto ERR;
    }

    ctx->recCtx = newRecCtx;
    return HITLS_SUCCESS;
ERR:
    RecDeInit(newRecCtx);
    BSL_SAL_FREE(newRecCtx);
    return ret;
}

void REC_DeInit(TLS_Ctx *ctx)
{
    if (ctx != NULL && ctx->recCtx != NULL) {
        RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
        RecDeInit(recordCtx);
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
    if ((ctx == NULL) || (ctx->recCtx == NULL) || (data == NULL) || (ctx->alertCtx == NULL)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15535, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: input invalid parameter.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }
    return ctx->recCtx->recRead(ctx, recordType, data, readLen, num);
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
    return ctx->recCtx->recWrite(ctx, recordType, data, num);
}

static void FreeDataAndState(RecConnSuitInfo *clientSuitInfo, RecConnSuitInfo *serverSuitInfo,
    RecConnState *readState, RecConnState *writeState)
{
    BSL_SAL_CleanseData((void *)clientSuitInfo, sizeof(RecConnSuitInfo));
    BSL_SAL_CleanseData((void *)serverSuitInfo, sizeof(RecConnSuitInfo));
    RecConnStateFree(readState);
    RecConnStateFree(writeState);
}

int32_t REC_InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param)
{
    if (ctx == NULL || ctx->recCtx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_INTERNAL_EXCEPTION, BINLOG_ID15540, "Record: ctx null");
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
        (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17301, "StateNew fail");
        goto ERR;
    }

    /* 1.Generate a secret */
    ret = RecConnKeyBlockGen(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        param, &clientSuitInfo, &serverSuitInfo);
    if (ret != HITLS_SUCCESS) {
        (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17302, "KeyBlockGen fail");
        goto ERR;
    }

    /* 2.Set the corresponding read/write pending state */
    out = (param->isClient == true) ? &clientSuitInfo : &serverSuitInfo;
    in = (param->isClient == true) ? &serverSuitInfo : &clientSuitInfo;
    ret = RecConnStateSetCipherInfo(writeState, out);
    if (ret != HITLS_SUCCESS) {
        (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17303, "SetCipherInfo fail");
        goto ERR;
    }
    ret = RecConnStateSetCipherInfo(readState, in);
    if (ret != HITLS_SUCCESS) {
        (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17304, "SetCipherInfo fail");
        goto ERR;
    }

    /* Clear sensitive information */
    FreeDataAndState(&clientSuitInfo, &serverSuitInfo,
        recordCtx->readStates.pendingState, recordCtx->writeStates.pendingState);
    recordCtx->readStates.pendingState = readState;
    recordCtx->writeStates.pendingState = writeState;
    return HITLS_SUCCESS;
ERR:
    /* Clear sensitive information */
    FreeDataAndState(&clientSuitInfo, &serverSuitInfo, readState, writeState);
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

#ifdef HITLS_TLS_PROTO_TLS13
int32_t REC_TLS13InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param, bool isOut)
{
    if (ctx == NULL || ctx->recCtx == NULL || param == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15542, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record: ctx null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnSuitInfo suitInfo = {0};
    RecConnState *state = RecConnStateNew();
    if (state == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17305, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "StateNew fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* 1.Generate a secret */
    int32_t ret = RecTLS13ConnKeyBlockGen(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx), param, &suitInfo);
    if (ret != HITLS_SUCCESS) {
        RecConnStateFree(state);
        return ret;
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
        return ret;
    }

    RecConnStateFree(curState->pendingState);
    curState->pendingState = state;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */

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

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        if (isOut) {
            ++recordCtx->writeEpoch;
            RecConnSetEpoch(states->currentState, recordCtx->writeEpoch);
        } else {
            ++recordCtx->readEpoch;
            RecConnSetEpoch(states->currentState, recordCtx->readEpoch);
        }
    }
#endif /* HITLS_TLS_PROTO_DTLS12 */

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15544, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "Record: active pending state.", 0, 0, 0, 0);
    return HITLS_SUCCESS;
}

int32_t REC_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len)
{
    if (ctx == NULL || ctx->recCtx == NULL || len == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15545, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Record: input null pointer.",
            0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *len = REC_MAX_PLAIN_TEXT_LENGTH;
    return HITLS_SUCCESS;
}

REC_Type REC_GetUnexpectedMsgType(TLS_Ctx *ctx)
{
    return ctx->recCtx->unexpectedMsgType;
}

void RecClearAlertCount(TLS_Ctx *ctx, REC_Type recordType)
{
    if (recordType != REC_TYPE_ALERT) {
        ALERT_ClearWarnCount(ctx);
    }
    return;
}