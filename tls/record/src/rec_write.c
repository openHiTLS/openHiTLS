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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "tls.h"
#include "record.h"
#include "hs_ctx.h"
#include "hs_common.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif
#include "rec_crypto.h"
#ifdef HITLS_TLS_FEATURE_DTLS_CID
#include "dtls_cid.h"
#endif
#include "rec_crypto_aead.h"
#ifdef HITLS_TLS_FEATURE_QUIC_TLS
#include "quic_tls_internal.h"
#endif

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
}

static uint64_t GetCipherLimit(uint32_t cipherAlg)
{
    switch (cipherAlg) {
        case HITLS_CIPHER_AES_128_GCM:
        case HITLS_CIPHER_AES_256_GCM:
            return REC_MAX_AES_GCM_ENCRYPTION_LIMIT;
        case HITLS_CIPHER_AES_128_CCM:
        case HITLS_CIPHER_AES_256_CCM:
        case HITLS_CIPHER_AES_128_CCM8:
        case HITLS_CIPHER_AES_256_CCM8:
            return REC_MAX_AES_CCM_ENCRYPTION_LIMIT;
        case HITLS_CIPHER_CHACHA20_POLY1305:
            return 0;
        case HITLS_CIPHER_SM4_GCM:
            return REC_MAX_SM4_GCM_ENCRYPTION_LIMIT;
        case HITLS_CIPHER_SM4_CCM:
            return REC_MAX_SM4_CCM_ENCRYPTION_LIMIT;
        default:
            return 0;
    }
}

static void CheckEncryptionLimits(TLS_Ctx *ctx, RecConnState *state)
{
    if (!IS_TLS13_FAMILY_CTX(ctx)) {
        return;
    }
    if (state->suiteInfo == NULL) {
        return;
    }
    uint64_t limit = GetCipherLimit(state->suiteInfo->cipherAlg);
    if (limit == 0) {
        return;
    }
#if defined(HITLS_TLS_FEATURE_KEY_UPDATE)
    uint64_t seq = RecConnGetSeqNum(state);
    if (seq >= limit - 1 && ctx->config.tlsConfig.isAutoKeyUpdateEnabled && ctx->isKeyUpdateRequest == false) {
        /* Auto KeyUpdate is best effort. If the current state cannot send it immediately, keep this write path moving. */
        (void)HITLS_KeyUpdate(ctx, HITLS_UPDATE_NOT_REQUESTED);
    }
#endif
}

static const uint8_t *GetPlainMsgData(RecordPlaintext *recPlaintext, const uint8_t *data)
{
    (void)recPlaintext;
    return
#if defined(HITLS_TLS_PROTO_TLS13_FAMILY)
        recPlaintext->isTlsInnerPlaintext ? recPlaintext->plainData :
#endif
        data;
}

#if defined(HITLS_TLS_PROTO_DATAGRAM)
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
    plainMsg->isEncryptThenMac = ctx->recCtx->writeStates.currentState->isEncryptThenMac;
#endif
    if (ctx->negotiatedInfo.version == 0) {
        plainMsg->version = HITLS_VERSION_DTLS10;
        if (IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask)) {
            plainMsg->version = HITLS_VERSION_TLCP_DTLCP11;
        } else if (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_DTLS13) {
            plainMsg->version = HITLS_VERSION_DTLS12;
        }
    } else {
        plainMsg->version = ctx->negotiatedInfo.version;
        if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
            plainMsg->version = HITLS_VERSION_DTLS12;
        }
    }

    BSL_Uint64ToByte(epochSeq, plainMsg->seq);
}

#ifdef HITLS_TLS_PROTO_DTLS13
static int32_t Dtls13RecordHeaderPack(TLS_Ctx *ctx, uint8_t *outBuf, RecConnState *state, const uint8_t *cipherText,
    uint32_t cipherTextLen, bool protectSeq)
{
    size_t offset = 0;
    uint8_t firstByte = REC_DTLS13_UNI_HEADER_FIX_BITS;  // 0x00100000: DTLS 1.3 mask
    if (state->suiteInfo == NULL) {
        return HITLS_REC_INVLAID_RECORD;
    }
    firstByte |= (RecConnGetEpoch(state) & REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK);
    uint8_t cidLen = 0;
#ifdef HITLS_TLS_FEATURE_DTLS_CID
    cidLen = ctx->negotiatedInfo.peerCidEntry.cidLen;
#endif
    if (cidLen > 0) {
        firstByte |= REC_DTLS13_UNI_HEADER_CID_BIT;
    }
    firstByte |= REC_DTLS13_UNI_HEADER_SEQ_BIT;
    uint8_t snLen = 2;  // default 2 bytes
    firstByte |= REC_DTLS13_UNI_HEADER_LEN_BIT;

    outBuf[offset++] = firstByte;
#ifdef HITLS_TLS_FEATURE_DTLS_CID
    if (cidLen > 0) {
        memcpy(&outBuf[offset], ctx->negotiatedInfo.peerCidEntry.cidVal, cidLen);
        offset += cidLen;
    }
#endif

    uint8_t seq[2];
    BSL_Uint16ToByte(state->seq, seq);
    if (protectSeq) {
        int32_t ret = Dtls13CryptSequenceNumber(ctx, state->suiteInfo, cipherText, cipherTextLen, seq, snLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        memcpy(&outBuf[offset], seq, snLen);
    } else {
        memcpy(&outBuf[offset], seq, snLen);
    }
    offset += snLen;
    BSL_Uint16ToByte((uint16_t)cipherTextLen, &outBuf[offset]);
    offset += 2; // body length 2 bytes
    return HITLS_SUCCESS;
}
#endif

static inline int32_t DtlsRecordHeaderPack(TLS_Ctx *ctx, uint8_t *outBuf, REC_Type recordType, uint16_t version,
    RecConnState *state, uint8_t *cipherText, uint32_t cipherTextLen)
{
    (void)ctx;
    (void)cipherText;
    (void)cipherTextLen;
    uint16_t epoch = RecConnGetEpoch(state);
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 && epoch > 0) {
        return Dtls13RecordHeaderPack(ctx, outBuf, state, cipherText, cipherTextLen, true);
    }
#endif
    outBuf[0] = recordType;
    BSL_Uint16ToByte(version, &outBuf[1]);
    uint64_t epochSeq = REC_EPOCHSEQ_CAL(epoch, state->seq);
    BSL_Uint64ToByte(epochSeq, &outBuf[REC_DTLS_RECORD_EPOCH_OFFSET]);
    BSL_Uint16ToByte((uint16_t)cipherTextLen, &outBuf[REC_DTLS_RECORD_LENGTH_OFFSET]);
    return HITLS_SUCCESS;
}

static int32_t DtlsTrySendMessage(TLS_Ctx *ctx, RecCtx *recordCtx, REC_Type recordType, RecConnState *state,
    uint64_t epochSeq)
{
    (void)recordType;
#ifdef HITLS_BSL_UIO_SCTP
    /* Notify the uio whether the service message is being sent. rfc6083 4.4. Stream Usage: For non-app messages, the
     * sctp stream id number must be 0 */
    if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        bool isAppMsg = (recordType == REC_TYPE_APP);
        (void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_MASK_APP_MESSAGE, sizeof(isAppMsg), &isAppMsg);
    }
#endif /* HITLS_BSL_UIO_SCTP */
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
    recordCtx->lastWriteEpochSeq = epochSeq;
    recordCtx->hasLastWriteEpochSeq = true;
    /** Add the record sequence */
    RecConnSetSeqNum(state, state->seq + 1);

    return HITLS_SUCCESS;
}

static uint32_t RecGetWriteHeaderLen(const TLS_Ctx *ctx, RecConnState *state)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    (void)ctx;
    (void)state;
#endif
    uint32_t headerLen = REC_DTLS_RECORD_HEADER_LEN;
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 &&
        IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) &&
        RecConnGetEpoch(state) > 0) {
        uint32_t cidLen = 0;
#ifdef HITLS_TLS_FEATURE_DTLS_CID
        cidLen = ctx->negotiatedInfo.peerCidEntry.cidLen;
#endif
        headerLen = REC_DTLS13_UNI_HEADER_LENGTH + cidLen;
    }
#endif
    return headerLen;
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
    const RecCryptoFunc *funcs = RecGetCryptoFuncs(state->suiteInfo);
    int32_t ret;
    const uint8_t *plainMsgData = data;
    uint32_t plainLen = num;
#ifdef HITLS_TLS_PROTO_DTLS13
    RecordPlaintext recPlaintext = {0};
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 && state->suiteInfo != NULL && RecConnGetEpoch(state) > 0) {
        ret = funcs->encryptPreProcess(ctx, recordType, data, num, &recPlaintext);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        plainLen = recPlaintext.plainLen;
    }
    plainMsgData = GetPlainMsgData(&recPlaintext, data);
#endif
    uint32_t cipherTextLen = funcs->calCiphertextLen(ctx, state->suiteInfo, plainLen, false);
    if (cipherTextLen == 0) {
#ifdef HITLS_TLS_PROTO_DTLS13
        BSL_SAL_ClearFree(recPlaintext.plainData, recPlaintext.plainLen);
#endif
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15666, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: cipherTextLen(0) error.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }
    ret = RecIoBufInit(ctx, recordCtx, false);
    if (ret != HITLS_SUCCESS) {
#ifdef HITLS_TLS_PROTO_DTLS13
        BSL_SAL_ClearFree(recPlaintext.plainData, recPlaintext.plainLen);
#endif
        return ret;
    }
    /* Before encryption, construct plaintext parameters */
    REC_TextInput plainMsg = {0};
    uint64_t epochSeq = REC_EPOCHSEQ_CAL(RecConnGetEpoch(state), state->seq);
    REC_Type plainType = recordType;
#ifdef HITLS_TLS_PROTO_DTLS13
    /* DTLS 1.3 encryptPreProcess wraps the payload into DTLSInnerPlaintext and reports
     * APP as the outer record type. AAD must use that outer type to match the receiver. */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 && state->suiteInfo != NULL && RecConnGetEpoch(state) > 0) {
        plainType = recPlaintext.recordType;
    }
#endif
    DtlsPlainMsgGenerate(&plainMsg, ctx, plainType, plainMsgData, plainLen, epochSeq);
    uint32_t headerLen = RecGetWriteHeaderLen(ctx, state);
    const uint32_t outBufLen = headerLen + cipherTextLen;
    if (outBufLen > recordCtx->outBuf->bufSize) {
#ifdef HITLS_TLS_PROTO_DTLS13
        BSL_SAL_ClearFree(recPlaintext.plainData, recPlaintext.plainLen);
#endif
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_BUFFER_NOT_ENOUGH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15667, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS record write error: msg len = %u, buf len = %u.", outBufLen, recordCtx->outBuf->bufSize, 0, 0);
        return HITLS_REC_ERR_BUFFER_NOT_ENOUGH;
    }

    /** Obtain the cache address */
    uint8_t *outBuf = &recordCtx->outBuf->buf[0];

#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 && RecConnGetEpoch(state) > 0) {
        ret = Dtls13RecordHeaderPack(ctx, outBuf, state, NULL, cipherTextLen, false);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_ClearFree(recPlaintext.plainData, recPlaintext.plainLen);
            return ret;
        }
        memcpy(plainMsg.dtls13Aad, outBuf, headerLen);
        plainMsg.dtls13AadLen = headerLen;
        BSL_Uint64ToByte(state->seq, plainMsg.dtls13Seq);
    }
#endif

    CheckEncryptionLimits(ctx, state);

    /** Encrypt the record body */
    ret = RecConnEncrypt(ctx, state, &plainMsg, &outBuf[headerLen], cipherTextLen);
#ifdef HITLS_TLS_PROTO_DTLS13
    BSL_SAL_ClearFree(recPlaintext.plainData, recPlaintext.plainLen);
#endif
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17280, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnEncrypt fail", 0, 0, 0, 0);
        return ret;
    }
    ret = DtlsRecordHeaderPack(ctx, outBuf, recordType, plainMsg.version, state, &outBuf[headerLen], cipherTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17283, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DtlsRecordHeaderPack fail", 0, 0, 0, 0);
        return ret;
    }
    OutbufUpdate(&recordCtx->outBuf->start, 0, &recordCtx->outBuf->end, outBufLen);

#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(1, 0, RECORD_HEADER, outBuf, headerLen,
                              ctx, ctx->config.tlsConfig.msgArg);
#endif

    return DtlsTrySendMessage(ctx, recordCtx, recordType, state, epochSeq);
}
#endif /* HITLS_TLS_PROTO_DATAGRAM */

int32_t REC_GetLastWriteRecordNum(const TLS_Ctx *ctx, RecordNumber *recordNum)
{
#if defined(HITLS_TLS_PROTO_DATAGRAM)
    if (ctx == NULL || ctx->recCtx == NULL || recordNum == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    if (!IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }
    if (!ctx->recCtx->hasLastWriteEpochSeq) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }
    recordNum->epoch = REC_EPOCH_GET(ctx->recCtx->lastWriteEpochSeq);
    recordNum->sequenceNumber = REC_SEQ_GET(ctx->recCtx->lastWriteEpochSeq);
    return HITLS_SUCCESS;
#else
    (void)ctx;
    (void)recordNum;
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
#endif
}

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
    plainMsg->isEncryptThenMac = GetWriteConnState(ctx)->isEncryptThenMac;
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

    if (ctx->isClient && ctx->negotiatedInfo.version == 0 && ctx->state != CM_STATE_RENEGOTIATION &&
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
        BSL_SAL_ClearFree(recPlaintext.plainData, recPlaintext.plainLen);
        return ret;
    }
    /* If the value is not tls13, use the input parameter data */
    const uint8_t *plainMsgData = GetPlainMsgData(&recPlaintext, data);
    (void)TlsPlainMsgGenerate(&plainMsg, ctx, recPlaintext.recordType, plainMsgData, recPlaintext.plainLen);
    (void)TlsRecordHeaderPack(writeBuf->buf, recPlaintext.recordType, plainMsg.version, ciphertextLen);

    CheckEncryptionLimits(ctx, state);

    /** Encrypt the record body */
    ret = RecConnEncrypt(ctx, state, &plainMsg, writeBuf->buf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);
    BSL_SAL_ClearFree(recPlaintext.plainData, recPlaintext.plainLen);
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
#ifdef HITLS_TLS_FEATURE_QUIC_TLS
    /*
     * QUIC mode: the flight boundary is reused as the flush signal for the QUIC stack's
     * buffered CRYPTO data; the record UIO below is never involved.
     */
    if (QUIC_TLS_IsMode(ctx)) {
        QUIC_TLS_Ctx *quicTlsCtx = ctx->quicTlsCtx;
        /* Avoid emitting an empty flight when no addHandshakeData callback has succeeded since the last flush. */
        if (!quicTlsCtx->flightPending) {
            return HITLS_SUCCESS;
        }
        /* Reuse the record flight boundary while letting the QUIC stack transmit its buffered CRYPTO data. */
        int32_t callbackRet = quicTlsCtx->cbs.flushFlight(ctx, quicTlsCtx->callbackArg);
        if (callbackRet != HITLS_SUCCESS) {
            return QUIC_TLS_CallbackFailed(HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT, callbackRet);
        }
        /* Clear the marker only after a successful callback; a failed flush remains pending. */
        quicTlsCtx->flightPending = false;
        return HITLS_SUCCESS;
    }
#endif
    int32_t ret = HITLS_SUCCESS;
#if defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP)
    /* Reset the buffer uio size */
    ret = REC_QueryMtu(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_TLS_PROTO_DATAGRAM && HITLS_BSL_UIO_UDP */
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
    if (ret == BSL_UIO_IO_BUSY) {
#ifdef HITLS_TLS_FEATURE_MTU_QUERY
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
#endif /* HITLS_TLS_FEATURE_MTU_QUERY */
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
