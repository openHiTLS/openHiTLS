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
#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "tls.h"
#include "record.h"
#include "hs_ctx.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif
#include "hs.h"
#include "rec_crypto.h"


RecConnState *GetWriteConnState(const TLS_Ctx *ctx)
{
    /** Obtain the record structure. */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->writeStates.currentState;
}

static void OutbufUpdate(uint32_t *start, uint32_t startvalue, uint32_t *end, uint32_t endvalue)
{
    /** Commit the record to be written */
    *start = startvalue;
    *end = endvalue;
    return;
}

static int32_t CheckEncryptionLimits(TLS_Ctx *ctx, RecConnState *state)
{
    (void)ctx;
    if (state->suiteInfo != NULL &&
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        ctx->isKeyUpdateRequest == false &&
#endif
        (state->suiteInfo->cipherAlg == HITLS_CIPHER_AES_128_GCM ||
        state->suiteInfo->cipherAlg == HITLS_CIPHER_AES_256_GCM) &&
        RecConnGetSeqNum(state) > REC_MAX_AES_GCM_ENCRYPTION_LIMIT) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ENCRYPTED_NUMBER_OVERFLOW);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16188, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "AES-GCM record encrypted times overflow", 0, 0, 0, 0);
        return HITLS_REC_ENCRYPTED_NUMBER_OVERFLOW;
    }
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_DTLS12
// Write the data message.
static int32_t DatagramWrite(TLS_Ctx *ctx, RecBuf *buf)
{
    uint32_t total = buf->end - buf->start;

    /* Attempt to write */
    uint32_t sendLen = 0u;
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_WRITING;
#endif
    int32_t ret = BSL_UIO_Write(ctx->uio, &(buf->buf[buf->start]), total, &sendLen);
    /* Two types of failures occur in the packet transfer scenario:
    * a. The bottom layer directly returns a failure message.
    * b. Only some data packets are sent.
    * (sendLen != total) && (sendLen != 0) checks whether the returned result is null, but only part of the data is
       sent */
    if ((ret != BSL_SUCCESS) || ((sendLen != 0) && (sendLen != total))) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15664, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record send: IO exception. %d\n", ret, 0, 0, 0);
        return HITLS_REC_ERR_IO_EXCEPTION;
    }

    if (sendLen == 0) {
        return HITLS_REC_NORMAL_IO_BUSY;
    }

    buf->start = 0;
    buf->end = 0;
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_NOTHING;
#endif
    return HITLS_SUCCESS;
}

void DtlsPlainMsgGenerate(REC_TextInput *plainMsg, const TLS_Ctx *ctx,
    REC_Type recordType, const uint8_t *data, uint32_t plainLen, uint64_t epochSeq)
{
    plainMsg->type = recordType;
    plainMsg->text = data;
    plainMsg->textLen = plainLen;
    plainMsg->negotiatedVersion = ctx->negotiatedInfo.version;
#ifdef HITLS_TLS_FEATURE_ETM
    plainMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMac;
#endif

    if (ctx->negotiatedInfo.version == 0) {
        plainMsg->version = HITLS_VERSION_DTLS10;
        if (IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask)) {
            plainMsg->version = HITLS_VERSION_TLCP_DTLCP11;
        }
    } else {
        plainMsg->version = ctx->negotiatedInfo.version;
    }

    BSL_Uint64ToByte(epochSeq, plainMsg->seq);
}

static inline void DtlsRecordHeaderPack(uint8_t *outBuf, REC_Type recordType, uint16_t version,
    uint64_t epochSeq, uint32_t cipherTextLen)
{
    outBuf[0] = recordType;
    BSL_Uint16ToByte(version, &outBuf[1]);

    BSL_Uint64ToByte(epochSeq, &outBuf[REC_DTLS_RECORD_EPOCH_OFFSET]);
    BSL_Uint16ToByte((uint16_t)cipherTextLen, &outBuf[REC_DTLS_RECORD_LENGTH_OFFSET]);
}

static int32_t DtlsTrySendMessage(TLS_Ctx *ctx, RecCtx *recordCtx, REC_Type recordType, RecConnState *state)
{
    /* Notify the uio whether the service message is being sent. rfc6083 4.4. Stream Usage: For non-app messages, the
     * sctp stream id number must be 0 */
    bool isAppMsg = (recordType == REC_TYPE_APP);
    (void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_MASK_APP_MESSAGE, sizeof(isAppMsg), &isAppMsg);

    int32_t ret = DatagramWrite(ctx, recordCtx->outBuf);
    if (ret != HITLS_SUCCESS) {
        /* Does not cache messages in the DTLS */
        recordCtx->outBuf->start = 0;
        recordCtx->outBuf->end = 0;
        return ret;
    }

#if defined(HITLS_BSL_UIO_UDP)
    ret = RecDerefBufList(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_TLS_FEATURE_MODE_RELEASE_BUFFERS
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_RELEASE_BUFFERS) != 0 && (recordType == REC_TYPE_APP)) {
        RecTryFreeRecBuf(ctx, true);
    }
#endif
    /** Add the record sequence */
    RecConnSetSeqNum(state, state->seq + 1);

    return HITLS_SUCCESS;
}

// Write a record for the DTLS protocol
int32_t DtlsRecordWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    /** Obtain the record structure */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *state = GetWriteConnState(ctx);

    if (state->seq > REC_DTLS_SN_MAX_VALUE) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_SN_WRAPPING);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15665, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: sequence number wrap.", 0, 0, 0, 0);
        return HITLS_REC_ERR_SN_WRAPPING;
    }

    uint32_t cipherTextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(ctx, state->suiteInfo, num, false);
    if (cipherTextLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15666, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: cipherTextLen(0) error.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }
    int32_t ret = RecIoBufInit(ctx, recordCtx, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    const uint32_t outBufLen = REC_DTLS_RECORD_HEADER_LEN + cipherTextLen;
    if (outBufLen > recordCtx->outBuf->bufSize) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_BUFFER_NOT_ENOUGH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15667, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS record write error: msg len = %u, buf len = %u.", outBufLen, recordCtx->outBuf->bufSize, 0, 0);
        return HITLS_REC_ERR_BUFFER_NOT_ENOUGH;
    }

    /* Before encryption, construct plaintext parameters */
    REC_TextInput plainMsg = {0};
    uint64_t epochSeq = REC_EPOCHSEQ_CAL(RecConnGetEpoch(state), state->seq);
    DtlsPlainMsgGenerate(&plainMsg, ctx, recordType, data, num, epochSeq);

    /** Obtain the cache address */
    uint8_t *outBuf = &recordCtx->outBuf->buf[0];

    DtlsRecordHeaderPack(outBuf, recordType, plainMsg.version, epochSeq, cipherTextLen);

    ret = CheckEncryptionLimits(ctx, state);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /** Encrypt the record body */
    ret = RecConnEncrypt(ctx, state, &plainMsg, &outBuf[REC_DTLS_RECORD_HEADER_LEN], cipherTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17280, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnEncrypt fail", 0, 0, 0, 0);
        return ret;
    }

    OutbufUpdate(&recordCtx->outBuf->start, 0, &recordCtx->outBuf->end, outBufLen);

#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(1, 0, RECORD_HEADER, outBuf, REC_DTLS_RECORD_HEADER_LEN,
                              ctx, ctx->config.tlsConfig.msgArg);
#endif

    return DtlsTrySendMessage(ctx, recordCtx, recordType, state);
}
#endif /* HITLS_TLS_PROTO_DTLS12 */

#ifdef HITLS_TLS_PROTO_TLS
// Writes data to the UIO of the TLS context.
int32_t StreamWrite(TLS_Ctx *ctx, RecBuf *buf)
{
    uint32_t total = buf->end - buf->start;
    int32_t ret = BSL_SUCCESS;
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_WRITING;
#endif
    do {
        uint32_t sendLen = 0u;
        ret = BSL_UIO_Write(ctx->uio, &(buf->buf[buf->start]), total, &sendLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15668, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Record send: IO exception. %d\n", ret, 0, 0, 0);
            return HITLS_REC_ERR_IO_EXCEPTION;
        }

        if (sendLen == 0) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }

        buf->start += sendLen;
        total -= sendLen;
    } while (buf->start < buf->end);

    buf->start = 0;
    buf->end = 0;
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_NOTHING;
#endif

    return HITLS_SUCCESS;
}

static void TlsPlainMsgGenerate(REC_TextInput *plainMsg, const TLS_Ctx *ctx,
    REC_Type recordType, const uint8_t *data, uint32_t plainLen)
{
    plainMsg->type = recordType;
    plainMsg->text = data;
    plainMsg->textLen = plainLen;
    plainMsg->negotiatedVersion = ctx->negotiatedInfo.version;
#ifdef HITLS_TLS_FEATURE_ETM
    plainMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMacWrite;
#endif
    if (ctx->negotiatedInfo.version != 0) {
        plainMsg->version =
#ifdef HITLS_TLS_PROTO_TLS13
        (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) ? HITLS_VERSION_TLS12 :
#endif
            ctx->negotiatedInfo.version;
    } else {
        plainMsg->version =
#ifdef HITLS_TLS_PROTO_TLS13
            (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13) ? HITLS_VERSION_TLS12 :
#endif
            ctx->config.tlsConfig.maxVersion;
    }

    if (ctx->hsCtx != NULL && ctx->hsCtx->state == TRY_SEND_CLIENT_HELLO &&
        ctx->state != CM_STATE_RENEGOTIATION &&
#ifdef HITLS_TLS_PROTO_TLS13
        ctx->hsCtx->haveHrr == false &&
#endif
#ifdef HITLS_TLS_PROTO_TLCP11
        ctx->config.tlsConfig.maxVersion != HITLS_VERSION_TLCP_DTLCP11 &&
#endif
        ctx->config.tlsConfig.maxVersion > HITLS_VERSION_TLS10) {
        plainMsg->version = HITLS_VERSION_TLS10;
    }

    BSL_Uint64ToByte(GetWriteConnState(ctx)->seq, plainMsg->seq);
}

static inline void TlsRecordHeaderPack(uint8_t *outBuf, REC_Type recordType, uint16_t version, uint32_t cipherTextLen)
{
    outBuf[0] = recordType;
    BSL_Uint16ToByte(version, &outBuf[1]);
    BSL_Uint16ToByte((uint16_t)cipherTextLen, &outBuf[REC_TLS_RECORD_LENGTH_OFFSET]);
}

static int32_t SendRecord(TLS_Ctx *ctx, RecCtx *recordCtx, RecConnState *state, uint64_t seq, REC_Type recordType)
{
    (void)recordType;
    int32_t ret = StreamWrite(ctx, recordCtx->outBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_FEATURE_MODE_RELEASE_BUFFERS
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_RELEASE_BUFFERS) != 0 && (recordType == REC_TYPE_APP)) {
        RecTryFreeRecBuf(ctx, true);
    }
#endif

    /** Add the record sequence */
    RecConnSetSeqNum(state, seq + 1);
    return HITLS_SUCCESS;
}

int32_t REC_OutBufFlush(TLS_Ctx *ctx)
{
    RecBuf *writeBuf = ctx->recCtx->outBuf;
    if (writeBuf == NULL || writeBuf->start == writeBuf->end) {
        return HITLS_SUCCESS; // No data to flush
    }
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return HITLS_SUCCESS;
    }
    RecConnState *state = GetWriteConnState(ctx);
    /* The Recordtype is REC_TYPE_HANDSHAKE to not relase outbuffer in HITLS_MODE_RELEASE_BUFFERS mode */
    int32_t ret = SendRecord(ctx, ctx->recCtx, state, state->seq, REC_TYPE_HANDSHAKE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ctx->recCtx->pendingData = NULL;
    ctx->recCtx->pendingDataSize = 0;
    return HITLS_SUCCESS;
}

static int32_t SequenceCompare(RecConnState *state, uint64_t value)
{
    if (state->isWrapped == true) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_SN_WRAPPING);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15670, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: sequence number wrap.", 0, 0, 0, 0);
        return HITLS_REC_ERR_SN_WRAPPING;
    }
    if (state->seq == value) {
        state->isWrapped = true;
    }
    return HITLS_SUCCESS;
}

static int32_t LengthCheck(uint32_t ciphertextLen, const uint32_t outBufLen, RecBuf *writeBuf)
{
    if (ciphertextLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15671, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: cipherTextLen(0) error.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }
    if (outBufLen > writeBuf->bufSize) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_BUFFER_NOT_ENOUGH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15672, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: buffer is not enough.", 0, 0, 0, 0);
        return HITLS_REC_ERR_BUFFER_NOT_ENOUGH;
    }
    return HITLS_SUCCESS;
}
static const uint8_t *GetPlainMsgData(RecordPlaintext *recPlaintext, const uint8_t *data)
{
    (void)recPlaintext;
    return
#ifdef HITLS_TLS_PROTO_TLS13
        recPlaintext->isTlsInnerPlaintext ? recPlaintext->plainData :
#endif
        data;
}
// Write a record in the TLS protocol, serialize a record message, and send the message
int32_t TlsRecordWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    RecConnState *state = GetWriteConnState(ctx);
    RecordPlaintext recPlaintext = {0};
    REC_TextInput plainMsg = {0};
    int32_t ret = SequenceCompare(state, REC_TLS_SN_MAX_VALUE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = RecIoBufInit(ctx, (RecCtx *)ctx->recCtx, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    RecBuf *writeBuf = ctx->recCtx->outBuf;
    /* Check whether the cache exists */
    if (writeBuf->end > writeBuf->start) {
        return SendRecord(ctx, ctx->recCtx, state, state->seq, recordType);
    }
    const RecCryptoFunc *funcs = RecGetCryptoFuncs(state->suiteInfo);
    ret = funcs->encryptPreProcess(ctx, recordType, data, num, &recPlaintext);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17281, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encryptPreProcess fail", 0, 0, 0, 0);
        return ret;
    }

    uint32_t ciphertextLen = funcs->calCiphertextLen(ctx, state->suiteInfo, recPlaintext.plainLen, false);
    const uint32_t outBufLen = REC_TLS_RECORD_HEADER_LEN + ciphertextLen;
    ret = LengthCheck(ciphertextLen, outBufLen, writeBuf);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(recPlaintext.plainData);
        return ret;
    }
    /* If the value is not tls13, use the input parameter data */
    const uint8_t *plainMsgData = GetPlainMsgData(&recPlaintext, data);
    (void)TlsPlainMsgGenerate(&plainMsg, ctx, recPlaintext.recordType, plainMsgData, recPlaintext.plainLen);
    (void)TlsRecordHeaderPack(writeBuf->buf, recPlaintext.recordType, plainMsg.version, ciphertextLen);

    ret = CheckEncryptionLimits(ctx, state);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(recPlaintext.plainData);
        return ret;
    }

    /** Encrypt the record body */
    ret = RecConnEncrypt(ctx, state, &plainMsg, writeBuf->buf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);
    BSL_SAL_FREE(recPlaintext.plainData);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(1, plainMsg.version, RECORD_HEADER, writeBuf->buf, REC_TLS_RECORD_HEADER_LEN, ctx,
                              ctx->config.tlsConfig.msgArg);
#endif
    OutbufUpdate(&writeBuf->start, 0, &writeBuf->end, outBufLen);

    return SendRecord(ctx, ctx->recCtx, state, state->seq, recordType);
}
#endif /* HITLS_TLS_PROTO_TLS */

#ifdef HITLS_TLS_FEATURE_FLIGHT
int32_t REC_FlightTransmit(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    ret = REC_QueryMtu(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
    if (ret == BSL_UIO_IO_BUSY) {
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        bool exceeded = false;
        (void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_UDP_MTU_EXCEEDED, sizeof(bool), &exceeded);
        if (exceeded) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17362, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Record write: get EMSGSIZE error.", 0, 0, 0, 0);
            ctx->needQueryMtu = true;
        }
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
        return HITLS_REC_NORMAL_IO_BUSY;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16110, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "fail to send handshake message in bUio.", 0, 0, 0, 0);
        return HITLS_REC_ERR_IO_EXCEPTION;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_FLIGHT */