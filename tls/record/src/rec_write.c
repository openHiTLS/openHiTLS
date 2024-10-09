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
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "uio_base.h"
#include "record.h"
#include "hs_ctx.h"
#include "indicator.h"
#include "hs.h"

/* 16384 + 1: RFC8446 5.4. Record Padding the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1 octets. */
#define MAX_PADDING_LEN 16385

typedef struct {
    REC_Type recordType; /* Protocol type */
    uint32_t plainLen;   /* message length */
    uint8_t *plainData;  /* message data */
    /* Length of the tls1.3 padding content. Currently, the value is 0. The value can be used as required */
    uint64_t recPaddingLength;
    bool isTlsInnerPlaintext; /* Whether it is a TLSInnerPlaintext message for tls1.3 */
} RecordPlaintext;            /* Record protocol data before encryption */

static int32_t CheckEncryptionLimits(const TLS_Ctx *ctx, RecConnState *state)
{
    if (ctx->isKeyUpdateRequest == false && state->suiteInfo != NULL &&
        (state->suiteInfo->cipherAlg == HITLS_CIPHER_AES_128_GCM ||
        state->suiteInfo->cipherAlg == HITLS_CIPHER_AES_256_GCM) &&
        RecConnGetSeqNum(state) > REC_MAX_AES_GCM_ENCRYPTION_LIMIT) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ENCRYPTED_NUMBER_OVERFLOW);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15663, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "AES-GCM record encrypted times overflow", 0, 0, 0, 0);
        return HITLS_REC_ENCRYPTED_NUMBER_OVERFLOW;
    }
    return HITLS_SUCCESS;
}

#ifndef HITLS_NO_DTLS12
// Write the data message.
static int32_t DatagramWrite(TLS_Ctx *ctx, RecBuf *buf)
{
    uint32_t total = buf->end - buf->start;

    /* Attempt to write */
    uint32_t sendLen = 0u;
    ctx->rwstate = HITLS_WRITING;
    int32_t ret = BSL_UIO_Write(ctx->uio, &(buf->buf[buf->start]), total, &sendLen);
    /* Two types of failures occur in the packet transfer scenario:
    * a. The bottom layer directly returns a failure message.
    * b. Only some data messages are sent.
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
    ctx->rwstate = HITLS_NOTHING;
    return HITLS_SUCCESS;
}

RecConnState *DtlsGetWriteConnState(const TLS_Ctx *ctx)
{
    /** Obtain the record structure */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->writeStates.currentState;
}

void DtlsPlainMsgGenerate(REC_TextInput *plainMsg, const TLS_Ctx *ctx,
    REC_Type recordType, const uint8_t *data, uint32_t plainLen, uint64_t epochSeq)
{
    plainMsg->type = recordType;
    plainMsg->text = data;
    plainMsg->textLen = plainLen;
    plainMsg->negotiatedVersion = ctx->negotiatedInfo.version;
    plainMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMac;

    if (ctx->negotiatedInfo.version == 0) {
        plainMsg->version = HITLS_VERSION_DTLS10;
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

static inline int32_t DtlsRecordMaskAppMsg(const TLS_Ctx *ctx, REC_Type recordType)
{
    if (BSL_UIO_GetTransportType(ctx->uio) == BSL_UIO_SCTP) {
        bool isAppMsg = (recordType == REC_TYPE_APP);
        int32_t ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_MARK_APP_MESSAGE, sizeof(isAppMsg), &isAppMsg);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_MSAK_APP_MSG);
            return HITLS_REC_ERR_MSAK_APP_MSG;
        }
        return HITLS_SUCCESS;
    }
    return HITLS_SUCCESS;
}

static int32_t DtlsRecOutBufInit(RecCtx *recordCtx, uint32_t bufSize)
{
    if (recordCtx->outBuf == NULL) {
        recordCtx->outBuf = RecBufNew(bufSize);
        if (recordCtx->outBuf == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t DtlsTrySendMessage(TLS_Ctx *ctx, RecCtx *recordCtx, REC_Type recordType, RecConnState *state)
{
    /* Notify the uio whether the service message is being sent. rfc6083 4.4. Stream Usage: For non-app messages, the
     * sctp stream id number must be 0 */
    int32_t ret = DtlsRecordMaskAppMsg(ctx, recordType);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = DatagramWrite(ctx, recordCtx->outBuf);
    if (ret != HITLS_SUCCESS) {
        /* Does not cache messages in the DTLS */
        recordCtx->outBuf->start = 0;
        recordCtx->outBuf->end = 0;
        return ret;
    }

    /** Add the record sequence */
    RecConnSetSeqNum(state, state->seq + 1);

    return HITLS_SUCCESS;
}

// Write a record for the DTLS protocol
int32_t DtlsRecordWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    /** Obtain the record structure */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *state = DtlsGetWriteConnState(ctx);

    if (state->seq > REC_DTLS_SN_MAX_VALUE) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_SN_WRAPPING);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15665, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: sequence number wrap.", 0, 0, 0, 0);
        return HITLS_REC_ERR_SN_WRAPPING;
    }

    uint32_t ciphertextLen = RecConnCalcCiphertextLen(state, num, ctx->negotiatedInfo.isEncryptThenMac);
    if (ciphertextLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15666, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: cipherTextLen(0) error.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }
    int32_t ret = DtlsRecOutBufInit(recordCtx, RecGetInitBufferSize(ctx));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    const uint32_t outBufLen = REC_DTLS_RECORD_HEADER_LEN + ciphertextLen;
    if (outBufLen > recordCtx->outBuf->bufSize) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_BUFFER_NOT_ENOUGH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15667, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS record write error: msg len = %u, buf len = %u.",
            outBufLen, recordCtx->outBuf->bufSize, 0, 0);
        return HITLS_REC_ERR_BUFFER_NOT_ENOUGH;
    }

    /* Before encryption, construct plaintext parameters */
    REC_TextInput plainMsg = {0};
    uint64_t epochSeq = REC_EPOCHSEQ_CAL(RecConnGetEpoch(state), state->seq);
    DtlsPlainMsgGenerate(&plainMsg, ctx, recordType, data, num, epochSeq);

    /** Obtain the cache address */
    uint8_t *outBuf = &recordCtx->outBuf->buf[0];

    DtlsRecordHeaderPack(outBuf, recordType, plainMsg.version, epochSeq, ciphertextLen);

    ret = CheckEncryptionLimits(ctx, state);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /** Encrypt the record body */
    ret = RecConnEncrypt(state, &plainMsg, &outBuf[REC_DTLS_RECORD_HEADER_LEN], ciphertextLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /** Commit the record to be written */
    recordCtx->outBuf->start = 0;
    recordCtx->outBuf->end = outBufLen;

    INDICATOR_MessageIndicate(1, 0, RECORD_HEADER, outBuf, REC_DTLS_RECORD_HEADER_LEN,
                              ctx, ctx->config.tlsConfig.msgArg);

    return DtlsTrySendMessage(ctx, recordCtx, recordType, state);
}
#endif

// Writes data to the UIO of the TLS context.
int32_t StreamWrite(TLS_Ctx *ctx, RecBuf *buf)
{
    uint32_t total = buf->end - buf->start;
    int32_t ret = BSL_SUCCESS;
    ctx->rwstate = HITLS_WRITING;
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
    } while (buf->start < buf->end);

    buf->start = 0;
    buf->end = 0;
    ctx->rwstate = HITLS_NOTHING;

    return HITLS_SUCCESS;
}

static inline RecConnState *TlsGetWriteConnState(const TLS_Ctx *ctx)
{
    return ctx->recCtx->writeStates.currentState;
}

static void TlsPlainMsgGenerate(REC_TextInput *plainMsg, TLS_Ctx *ctx,
    REC_Type recordType, const uint8_t *data, uint32_t plainLen, uint64_t seq)
{
    plainMsg->type = recordType;
    plainMsg->text = data;
    plainMsg->textLen = plainLen;
    plainMsg->negotiatedVersion = ctx->negotiatedInfo.version;
    plainMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMacWrite;

    if (ctx->negotiatedInfo.version != 0) {
        plainMsg->version = (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) ?
            HITLS_VERSION_TLS12 : ctx->negotiatedInfo.version;
    } else {
        plainMsg->version = (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13) ?
            HITLS_VERSION_TLS12 : ctx->config.tlsConfig.maxVersion;
    }

    if (ctx->hsCtx != NULL && ctx->hsCtx->state == TRY_SEND_CLIENT_HELLO &&
        ctx->state != CM_STATE_RENEGOTIATION && ctx->hsCtx->haveHrr == false &&
#ifndef HITLS_NO_TLCP11
        ctx->config.tlsConfig.maxVersion != HITLS_VERSION_TLCP11 &&
#endif
        ctx->config.tlsConfig.maxVersion > HITLS_VERSION_TLS10) {
        plainMsg->version = HITLS_VERSION_TLS10;
    }

    BSL_Uint64ToByte(seq, plainMsg->seq);
}

static inline void TlsRecordHeaderPack(uint8_t *outBuf, REC_Type recordType, uint16_t version, uint32_t cipherTextLen)
{
    outBuf[0] = recordType;
    BSL_Uint16ToByte(version, &outBuf[1]);
    BSL_Uint16ToByte((uint16_t)cipherTextLen, &outBuf[REC_TLS_RECORD_LENGTH_OFFSET]);
}

/**
 * @brief   Construct TLSInnerPlaintext (TLS1.3 RFC8446 5.2. Record Payload Protection)
 *    struct {
 *            opaque content[TLSPlaintext.length];
 *            ContentType type;
 *            uint8 zeros[length_of_padding];
 *        } TLSInnerPlaintext;
 */
static int32_t RecPackTlsInnerPlaintext(TLS_Ctx *ctx, uint8_t recordType, const uint8_t *data, uint32_t plainLen,
    RecordPlaintext *recPlaintext)
{
    recPlaintext->recordType = recordType;
    recPlaintext->plainLen = plainLen;
    recPlaintext->plainData = NULL;
    /* Currently, the padding length is set to 0. If required, the padding length can be customized */
    if (ctx->config.tlsConfig.recordPaddingCb == NULL) {
        recPlaintext->recPaddingLength = 0;
    } else {
        recPlaintext->recPaddingLength =
            ctx->config.tlsConfig.recordPaddingCb(ctx, recordType, plainLen, ctx->config.tlsConfig.recordPaddingArg);
    }

    recPlaintext->isTlsInnerPlaintext = false;

    RecConnState *writeState = TlsGetWriteConnState(ctx);
    /* If the length of the ciphertext is 0, encryption and decryption are not performed */
    uint32_t ciphertextLen =
        RecConnCalcCiphertextLen(writeState, 0, ctx->negotiatedInfo.isEncryptThenMacWrite);
    /* If the negotiation version is tls1.3 and encryption is required, you need to create
     * a TLSInnerPlaintext message */
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13 || ciphertextLen == 0) {
        return HITLS_SUCCESS;
    }

    INDICATOR_MessageIndicate(
        0, HS_GetVersion(ctx), RECORD_INNER_CONTENT_TYPE, &recordType, 1, ctx, ctx->config.tlsConfig.msgArg);

    /* TlsInnerPlaintext see rfc 8446 section 5.2 */
    recPlaintext->isTlsInnerPlaintext = true;

    /* tlsInnerPlaintext length = content length + record type length (1) + padding length */
    uint32_t tlsInnerPlaintextLen = plainLen + sizeof(uint8_t) + (uint32_t)recPlaintext->recPaddingLength;
    if (tlsInnerPlaintextLen > MAX_PADDING_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_RECORD_OVERFLOW);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15669, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Pack TlsInnerPlaintext length(%u) MUST NOT exceed 2^14 + 1 octets.", tlsInnerPlaintextLen, 0, 0, 0);
        return HITLS_REC_RECORD_OVERFLOW;
    }

    uint8_t *tlsInnerPlaintext = BSL_SAL_Calloc(1u, tlsInnerPlaintextLen);
    if (tlsInnerPlaintext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    if (memcpy_s(tlsInnerPlaintext, tlsInnerPlaintextLen, data, plainLen) != EOK) {
        BSL_SAL_FREE(tlsInnerPlaintext);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    tlsInnerPlaintext[plainLen] = recordType;

    /* Padding is calloc when the memory is applied for. Therefore, the number of buffs to be supplemented is 0. You do
     * not need to perform any operation */
    recPlaintext->plainLen = tlsInnerPlaintextLen;
    recPlaintext->plainData = tlsInnerPlaintext;
    recPlaintext->recordType = (uint8_t)REC_TYPE_APP; /* tls1.3 Hide the actual record type during encryption */
    return HITLS_SUCCESS;
}

static int32_t SendRecord(TLS_Ctx *ctx, RecCtx *recordCtx, RecConnState *state, uint64_t seq)
{
    int32_t ret = StreamWrite(ctx, recordCtx->outBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /** Add the record sequence */
    RecConnSetSeqNum(state, seq + 1);
    return HITLS_SUCCESS;
}

// Write a record in the TLS protocol, serialize a record message, and send the message
int32_t TlsRecordWrite(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    RecBuf *writeBuf = ctx->recCtx->outBuf;
    RecConnState *state = TlsGetWriteConnState(ctx);
    RecordPlaintext recPlaintext = {0};
    REC_TextInput plainMsg = {0};
    if (state->seq >= REC_TLS_SN_MAX_VALUE) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_SN_WRAPPING);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15670, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: sequence number wrap.", 0, 0, 0, 0);
        return HITLS_REC_ERR_SN_WRAPPING;
    }
    /* Check whether the cache exists */
    if (writeBuf->end > writeBuf->start) {
        return SendRecord(ctx, ctx->recCtx, state, state->seq);
    }
    /* Construct a TLSInnerPlaintext message */
    int32_t ret = RecPackTlsInnerPlaintext(ctx, recordType, data, num, &recPlaintext);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t ciphertextLen = RecConnCalcCiphertextLen(state, recPlaintext.plainLen,
        ctx->negotiatedInfo.isEncryptThenMacWrite);
    if (ciphertextLen == 0) {
        BSL_SAL_FREE(recPlaintext.plainData);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15671, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: cipherTextLen(0) error.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }
    const uint32_t outBufLen = REC_TLS_RECORD_HEADER_LEN + ciphertextLen;
    if (outBufLen > writeBuf->bufSize) {
        BSL_SAL_FREE(recPlaintext.plainData);
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_BUFFER_NOT_ENOUGH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15672, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: buffer is not enough.", 0, 0, 0, 0);
        return HITLS_REC_ERR_BUFFER_NOT_ENOUGH;
    }
    /* If the value is not tls13, use the input parameter data */
    const uint8_t *plainMsgData = recPlaintext.isTlsInnerPlaintext ? recPlaintext.plainData : data;
    (void)TlsPlainMsgGenerate(&plainMsg, ctx, recPlaintext.recordType, plainMsgData, recPlaintext.plainLen, state->seq);
    (void)TlsRecordHeaderPack(writeBuf->buf, recPlaintext.recordType, plainMsg.version, ciphertextLen);

    ret = CheckEncryptionLimits(ctx, state);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(recPlaintext.plainData);
        return ret;
    }

    /** Encrypt the record body */
    ret = RecConnEncrypt(state, &plainMsg, writeBuf->buf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);
    BSL_SAL_FREE(recPlaintext.plainData);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    INDICATOR_MessageIndicate(1, recordType, RECORD_HEADER, writeBuf->buf, REC_TLS_RECORD_HEADER_LEN, ctx,
                              ctx->config.tlsConfig.msgArg);

    /** Commit the record to be written */
    writeBuf->start = 0;
    writeBuf->end = outBufLen;

    return SendRecord(ctx, ctx->recCtx, state, state->seq);
}
