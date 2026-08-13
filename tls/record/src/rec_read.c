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
#include <string.h>
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "rec_alert.h"
#include "tls_config.h"
#include "record.h"
#include "rec_header.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif
#include "hs.h"
#include "hs_common.h"
#include "rec_crypto.h"
#include "rec_crypto_aead.h"
#include "bsl_list.h"
#include "hitls.h"
#ifdef HITLS_TLS_FEATURE_DTLS_CID
#include "dtls_cid.h"
#endif

RecConnState *GetReadConnState(const TLS_Ctx *ctx)
{
    /** Obtains the record structure. */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->readStates.currentState;
}

RecConnState *GetReadOutdatedState(const TLS_Ctx *ctx)
{
    /** Obtains the record structure. */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->readStates.outdatedState;
}

RecConnState *GetReadPendingState(const TLS_Ctx *ctx)
{
    /** Obtains the record structure. */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->readStates.pendingState;
}

#ifdef HITLS_TLS_PROTO_DTLS13
static int32_t Dtls13HandleHandshakeAck(TLS_Ctx *ctx, const RecHdr *hdr)
{
    if (!IS_DTLS13_CTX(ctx) || !IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return HITLS_SUCCESS;
    }
    RecordNumber recordNum = {
        .epoch = REC_EPOCH_GET(hdr->epochSeq),
        .sequenceNumber = BSL_ByteToUint64(hdr->dtls13Seq),
    };
    return REC_Dtls13AckListAppend(ctx, &recordNum);
}

static int32_t Dtls13TrySendRetransAckOnEpoch2(TLS_Ctx *ctx, uint64_t epoch)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13 || ctx->isClient || epoch != 2) {
        return HITLS_SUCCESS;
    }

    RecConnState *state = GetReadConnState(ctx);
    if (state == NULL || RecConnGetEpoch(state) <= 2) {
        return HITLS_SUCCESS;
    }

    REC_Dtls13SetNeedSendRetransAck(ctx);
    return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}
#endif

#if defined(HITLS_TLS_PROTO_DATAGRAM)
static uint32_t RecGetReadHeaderLen(uint8_t firstByte, uint32_t cidLen)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    (void)firstByte;
    (void)cidLen;
#endif
    uint32_t headerLen = 0;
#ifdef HITLS_TLS_PROTO_DTLS13
    if (REC_DTLS13_UNI_HEADER_FIX_BITS_TYPE(firstByte)) {
        headerLen = 1;
        headerLen += ((firstByte & REC_DTLS13_UNI_HEADER_CID_BIT) == REC_DTLS13_UNI_HEADER_CID_BIT) ? cidLen : 0;
        headerLen += ((firstByte & REC_DTLS13_UNI_HEADER_SEQ_BIT) == REC_DTLS13_UNI_HEADER_SEQ_BIT) ? 2 : 1;
        headerLen += ((firstByte & REC_DTLS13_UNI_HEADER_LEN_BIT) == REC_DTLS13_UNI_HEADER_LEN_BIT) ? 2 : 0;
    } else {
#endif
        /* DTLSv1.2 and Plaintext DTLSv1.3 record header */
        headerLen = REC_DTLS_RECORD_HEADER_LEN;
#ifdef HITLS_TLS_PROTO_DTLS13
    }
#endif
    return headerLen;
}
#endif

static uint64_t GetDecryptionLimit(uint32_t cipherAlg)
{
    switch (cipherAlg) {
        case HITLS_CIPHER_AES_128_GCM:
        case HITLS_CIPHER_AES_256_GCM:
            return REC_MAX_AES_GCM_DECRYPTION_LIMIT;
        case HITLS_CIPHER_AES_128_CCM:
        case HITLS_CIPHER_AES_256_CCM:
            return REC_MAX_AES_CCM_DECRYPTION_LIMIT;
        case HITLS_CIPHER_AES_128_CCM8:
        case HITLS_CIPHER_AES_256_CCM8:
            return REC_MAX_AES_CCM8_DECRYPTION_LIMIT;
        case HITLS_CIPHER_CHACHA20_POLY1305:
            return REC_MAX_CHACHA20_DECRYPTION_LIMIT;
        default:
            return 0;
    }
}

static int32_t CheckDecryptionLimits(TLS_Ctx *ctx, RecConnState *state)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13) {
        return HITLS_SUCCESS;
    }
    if (state->suiteInfo == NULL) {
        return HITLS_SUCCESS;
    }
    uint64_t limit = GetDecryptionLimit(state->suiteInfo->cipherAlg);
    if (limit == 0) {
        return HITLS_SUCCESS;
    }
    state->decryptFailCount++;
    if (state->decryptFailCount > limit) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_DECRYPT_FAILED_LIMIT);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17282, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "record decryption authentication failures overflow", 0, 0, 0, 0);
        return HITLS_REC_DECRYPT_FAILED_LIMIT;
    }
#if defined(HITLS_TLS_FEATURE_KEY_UPDATE)
    if (ctx->config.tlsConfig.isAutoKeyUpdateEnabled && !ctx->isKeyUpdateRequest &&
        !ctx->isWaitKeyUpdate && state->decryptFailCount >= limit - limit / 10) {
        (void)HITLS_KeyUpdate(ctx, HITLS_UPDATE_REQUESTED);
    }
#endif
    return HITLS_SUCCESS;
}

static bool IsNeedtoRead(const TLS_Ctx *ctx, const RecBuf *inBuf, RecHdr *hdr)
{
    (void)ctx;
    (void)hdr;
    uint32_t headLen = REC_TLS_RECORD_HEADER_LEN;
    uint32_t remain = inBuf->end - inBuf->start;
#if defined(HITLS_TLS_PROTO_DATAGRAM)
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        if (remain == 0) {
            return true;
        }
        uint8_t *msg = &inBuf->buf[inBuf->start];
        headLen = RecGetReadHeaderLen(msg[0],
#ifdef HITLS_TLS_PROTO_DTLS13
        hdr->cidLen
#else
        0
#endif
        );
    }
#endif
    uint32_t lengthOffset = headLen - sizeof(uint16_t);
    if (remain < headLen) {
        return true;
    }
    uint8_t *recordHeader = &inBuf->buf[inBuf->start];
    uint32_t recordLen = BSL_ByteToUint16(&recordHeader[lengthOffset]);
    if (remain < headLen + recordLen) {
        return true;
    }
    return false;
}

bool REC_HaveReadSuiteInfo(const TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->recCtx == NULL || ctx->recCtx->readStates.currentState == NULL) {
        return false;
    }
    return ctx->recCtx->readStates.currentState->suiteInfo != NULL;
}

static REC_Type RecCastUintToRecType(TLS_Ctx *ctx, uint8_t value, uint16_t epoch)
{
    (void)ctx;
    (void)epoch;
    REC_Type type;
    /* Convert to the record type */
    switch (value) {
        case 20u:
            type = REC_TYPE_CHANGE_CIPHER_SPEC;
            break;
        case 21u:
            type = REC_TYPE_ALERT;
            break;
        case 22u:
            type = REC_TYPE_HANDSHAKE;
            break;
        case 23u:
            type = REC_TYPE_APP;
            break;
        case 26u:
            type = REC_TYPE_ACK;
            break;
        default:
            type = REC_TYPE_UNKNOWN;
            break;
    }
#if defined(HITLS_TLS_PROTO_TLS13_FAMILY)
    RecConnState *state = GetReadConnState(ctx);
    if (epoch == 0 && RecConnGetEpoch(state) == 2 && IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return type;
    }

    if (IS_TLS13_FAMILY_VERSION(GET_VERSION_FROM_CTX(ctx)) && state->suiteInfo != NULL) {
        if (type != REC_TYPE_APP && type != REC_TYPE_ALERT &&
            (!IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) || type != REC_TYPE_ACK) &&
            (type != REC_TYPE_CHANGE_CIPHER_SPEC || ctx->hsCtx == NULL)) {
            type = REC_TYPE_UNKNOWN;
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13_FAMILY */
    return type;
}
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
uint32_t REC_GetMaxReadSize(TLS_Ctx *ctx)
{
    uint32_t readSize = REC_MAX_PLAIN_LENGTH;
    if (ctx != NULL && ctx->negotiatedInfo.recordSizeLimit != 0) {
        readSize = ctx->negotiatedInfo.recordSizeLimit;
        if (IS_TLS13_FAMILY_VERSION(GET_VERSION_FROM_CTX(ctx))) {
            readSize--;
        }
    }
    return readSize;
}
#else
#define REC_GetMaxReadSize(ctx) REC_MAX_PLAIN_LENGTH
#endif
static int32_t ProcessDecryptedRecord(TLS_Ctx *ctx, uint32_t dataLen,
    const REC_TextInput *encryptedMsg)
{
    /* The TLSPlaintext.length MUST NOT exceed 2^14. An endpoint that receives a record that exceeds
    this length MUST terminate the connection with a record_overflow alert */
    if (dataLen > REC_GetMaxReadSize(ctx)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16165, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLSPlaintext.length exceeds 2^14", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }

    if (encryptedMsg->type != REC_TYPE_APP && dataLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16166, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

    if (!IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) &&
        ctx->negotiatedInfo.version != HITLS_VERSION_TLS13 &&
        ctx->method.isRecvCCS(ctx) &&
        encryptedMsg->type != REC_TYPE_HANDSHAKE) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_ERR_DATA_BETWEEN_CCS_AND_FINISHED;
    }
    return HITLS_SUCCESS;
}

static int32_t EmptyRecordProcess(TLS_Ctx *ctx, uint8_t type)
{
    if (REC_HaveReadSuiteInfo(ctx)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17255, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encryptedMsg->textLen is 0", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    if (type == REC_TYPE_ALERT || type == REC_TYPE_APP) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17256, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "type err", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }
    ctx->recCtx->emptyRecordCnt += 1;
    if (ctx->recCtx->emptyRecordCnt > ctx->config.tlsConfig.emptyRecordsNum) {
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID16187, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "get too many empty records", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    } else {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
}

#ifdef HITLS_TLS_PROTO_DTLS13
int32_t Dtls13ReconstructSequenceNumber(TLS_Ctx *ctx, uint64_t epoch, uint16_t incompleteSeq, uint8_t seqLen, uint64_t *reconstructedSeq)
{
    RecConnState *state = GetReadConnState(ctx);
    uint16_t currentEpoch = RecConnGetEpoch(state);
    uint64_t currentSeq = 0;
    if (currentEpoch == (uint16_t)epoch) {
        currentSeq = state->seq;
    } else if (currentEpoch > 0 && currentEpoch - 1 == (uint16_t)epoch) {
        RecConnState *outdated = GetReadOutdatedState(ctx);
        if (outdated == NULL) {
            return HITLS_REC_DECODE_ERROR;
        }
        currentSeq = outdated->seq;
    } else if (currentEpoch + 1 == (uint16_t)epoch) {
        RecConnState *pending = GetReadPendingState(ctx);
        if (pending == NULL) {
            return HITLS_REC_DECODE_ERROR;
        }
        currentSeq = pending->seq;
    } else {
        return HITLS_REC_DECODE_ERROR;
    }
    uint64_t expectedSeq = currentSeq + 1;

    uint64_t partialMask = (seqLen == 2) ? 0xFFFFULL : 0xFFULL;
    uint16_t expectedPartial = expectedSeq & partialMask;
    uint16_t receivedPartial = incompleteSeq & partialMask;

    uint64_t highBits = expectedSeq & ~partialMask;
    if (receivedPartial == expectedPartial) {
        *reconstructedSeq = expectedSeq;
    } else {
        uint64_t modulus = partialMask + 1;
        uint64_t candidateSeq = highBits | receivedPartial;
        uint64_t candidateSeq1 = candidateSeq - modulus;
        uint64_t candidateSeq2 = candidateSeq + modulus;
        uint64_t tempSeq = candidateSeq;
        uint64_t diff = (candidateSeq > expectedSeq) ? (candidateSeq - expectedSeq) : (expectedSeq - candidateSeq);
        uint64_t diff1 = (candidateSeq1 > expectedSeq) ? (candidateSeq1 - expectedSeq) : (expectedSeq - candidateSeq1);
        uint64_t diff2 = (candidateSeq2 > expectedSeq) ? (candidateSeq2 - expectedSeq) : (expectedSeq - candidateSeq2);
        if (diff > diff1 || diff > diff2) {
            tempSeq = (diff1 < diff2) ? candidateSeq1 : candidateSeq2;
        }
        *reconstructedSeq = tempSeq;
    }
    return HITLS_SUCCESS;
}

static int32_t Dtls13GetCurrentOrOutdatedReadState(TLS_Ctx *ctx, uint16_t epoch, RecConnState **state)
{
    *state = GetReadConnState(ctx);
    uint16_t currentEpoch = RecConnGetEpoch(*state);
    if (currentEpoch > 0 && currentEpoch - 1 == epoch) {
        RecConnState *outdated = GetReadOutdatedState(ctx);
        if (outdated == NULL) {
            return HITLS_REC_DECODE_ERROR;
        }
        *state = outdated;
    }
    return HITLS_SUCCESS;
}

static bool Dtls13NeedDecryptRecordSeq(const REC_TextInput *encryptedMsg, uint16_t epoch)
{
    uint8_t zeroSeq[8] = {0};
    return epoch > 0 && memcmp(encryptedMsg->dtls13Seq, zeroSeq, sizeof(zeroSeq)) == 0;
}

static uint32_t Dtls13GetSeqOffset(const TLS_Ctx *ctx)
{
    uint8_t cidLen = 0;
#if defined(HITLS_TLS_FEATURE_DTLS_CID)
    cidLen = ctx->negotiatedInfo.isCidNegotiated ? ctx->negotiatedInfo.localCidEntry.cidLen : 0;
#else
    (void)ctx;
#endif
    return 1u + cidLen;
}

static void Dtls13SyncRecordSeqToHeader(const REC_TextInput *encryptedMsg, RecHdr *hdr)
{
    if (hdr == NULL) {
        return;
    }
    memcpy(hdr->dtls13Seq, encryptedMsg->dtls13Seq, sizeof(encryptedMsg->dtls13Seq));
    memcpy(hdr->dtls13Aad, encryptedMsg->dtls13Aad, encryptedMsg->dtls13AadLen);
}

static int32_t Dtls13DecryptRecordSeq(TLS_Ctx *ctx, RecConnState *state, REC_TextInput *encryptedMsg, RecHdr *hdr,
    uint16_t epoch)
{
    if (!Dtls13NeedDecryptRecordSeq(encryptedMsg, epoch)) {
        return HITLS_SUCCESS;
    }

    bool seqBit = (encryptedMsg->dtls13Aad[0] & REC_DTLS13_UNI_HEADER_SEQ_BIT) != 0;
    uint8_t seqLen = seqBit ? 2 : 1;
    uint32_t seqOffset = Dtls13GetSeqOffset(ctx);
    uint8_t decryptedSn[2];
    memcpy(decryptedSn, &encryptedMsg->dtls13Aad[seqOffset], seqLen);

    int32_t ret = Dtls13CryptSequenceNumber(ctx, state->suiteInfo, encryptedMsg->text, encryptedMsg->textLen,
        decryptedSn, seqLen);
    if (ret != HITLS_SUCCESS) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    uint16_t incompleteSeq = (seqLen == 2) ? BSL_ByteToUint16(decryptedSn) : decryptedSn[0];
    uint64_t reconstructedSeq = 0;
    ret = Dtls13ReconstructSequenceNumber(ctx, epoch, incompleteSeq, seqLen, &reconstructedSeq);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (seqLen == 2) {
        BSL_Uint16ToByte((uint16_t)(reconstructedSeq & 0xFFFFULL), &encryptedMsg->dtls13Aad[seqOffset]);
    } else {
        encryptedMsg->dtls13Aad[seqOffset] = (uint8_t)(reconstructedSeq & 0xFFULL);
    }
    BSL_Uint64ToByte(reconstructedSeq, encryptedMsg->dtls13Seq);
    Dtls13SyncRecordSeqToHeader(encryptedMsg, hdr);
    return HITLS_SUCCESS;
}

static int32_t Dtls13PrepareReadState(TLS_Ctx *ctx, REC_TextInput *encryptedMsg, RecHdr *hdr, RecConnState **state)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13) {
        *state = GetReadConnState(ctx);
        return HITLS_SUCCESS;
    }

    uint16_t epoch = REC_EPOCH_GET(BSL_ByteToUint64(encryptedMsg->seq));
    int32_t ret = Dtls13GetCurrentOrOutdatedReadState(ctx, epoch, state);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* Epoch-0 classic-header records have no encrypted sequence number. */
    return Dtls13DecryptRecordSeq(ctx, *state, encryptedMsg, hdr, epoch);
}

static bool Dtls13IsEpoch0Record(const TLS_Ctx *ctx, const REC_TextInput *encryptedMsg)
{
    return ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 &&
        REC_EPOCH_GET(BSL_ByteToUint64(encryptedMsg->seq)) == 0;
}
#endif

static void FreeHeldRecordBuf(RecBuf *decryptBuf)
{
    if (decryptBuf->isHoldBuffer) {
        BSL_SAL_FREE(decryptBuf->buf);
    }
}

static int32_t RecordPrepareDecryptBuf(TLS_Ctx *ctx, RecConnState *state, const RecCryptoFunc *funcs,
    REC_TextInput *encryptedMsg, RecBuf *decryptBuf)
{
    uint32_t offset = 0;
    uint32_t minBufLen = 0;
    int32_t ret = funcs->calPlantextBufLen(ctx, state->suiteInfo, encryptedMsg->textLen, &offset, &minBufLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16266, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Invalid record length %u", encryptedMsg->textLen, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    if ((minBufLen > decryptBuf->bufSize || ctx->peekFlag != 0) && minBufLen != 0) {
        decryptBuf->buf = BSL_SAL_Calloc(minBufLen, sizeof(uint8_t));
        if (decryptBuf->buf == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17257, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Calloc fail", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
        decryptBuf->bufSize = minBufLen;
        decryptBuf->isHoldBuffer = true;
    }
    decryptBuf->end = decryptBuf->bufSize;
    return HITLS_SUCCESS;
}

static int32_t RecordDecryptPayload(TLS_Ctx *ctx, RecConnState *state, const RecCryptoFunc *funcs,
    REC_TextInput *encryptedMsg, RecBuf *decryptBuf)
{
#ifdef HITLS_TLS_PROTO_DTLS13
    if (Dtls13IsEpoch0Record(ctx, encryptedMsg)) {
        return funcs->decrypt(ctx, state, encryptedMsg, decryptBuf->buf, &decryptBuf->end);
    }
#else
    (void)funcs;
#endif
    int32_t ret = RecConnDecrypt(ctx, state, encryptedMsg, decryptBuf->buf, &decryptBuf->end);
    if (ret == HITLS_SUCCESS || !IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return ret;
    }

    int32_t limitRet = CheckDecryptionLimits(ctx, state);
    return (limitRet != HITLS_SUCCESS) ? limitRet : ret;
}

static bool NeedDecryptPostProcess(TLS_Ctx *ctx, const REC_TextInput *encryptedMsg)
{
    if (!IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return true;
    }
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 &&
        REC_EPOCH_GET(BSL_ByteToUint64(encryptedMsg->seq)) > 0) {
        return true;
    }
#else
    (void)encryptedMsg;
#endif
    return false;
}

static void RecordUpdateReadSeqAfterDecrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *encryptedMsg)
{
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
        uint64_t receivedSeq = BSL_ByteToUint64(encryptedMsg->dtls13Seq);
        if (receivedSeq > RecConnGetSeqNum(state)) {
            RecConnSetSeqNum(state, receivedSeq);
        }
        return;
    }
#else
    (void)ctx;
    (void)encryptedMsg;
#endif
    RecConnSetSeqNum(state, RecConnGetSeqNum(state) + 1);
}

static int32_t RecordDecryptPostProcess(TLS_Ctx *ctx, RecConnState *state, const RecCryptoFunc *funcs,
    REC_TextInput *encryptedMsg, RecBuf *decryptBuf)
{
    if (!NeedDecryptPostProcess(ctx, encryptedMsg)) {
        return HITLS_SUCCESS;
    }

    int32_t ret = funcs->decryptPostProcess(ctx, state->suiteInfo, encryptedMsg, decryptBuf->buf, &decryptBuf->end);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    RecordUpdateReadSeqAfterDecrypt(ctx, state, encryptedMsg);
    return HITLS_SUCCESS;
}

static int32_t RecordDecrypt(TLS_Ctx *ctx, RecBuf *decryptBuf, REC_TextInput *encryptedMsg, RecHdr *hdr)
{
    (void)hdr;
    if (encryptedMsg->textLen == 0) {
        return EmptyRecordProcess(ctx, encryptedMsg->type);
    } else {
        ctx->recCtx->emptyRecordCnt = 0;
    }

    int32_t ret = HITLS_SUCCESS;
    RecConnState *state = GetReadConnState(ctx);
#ifdef HITLS_TLS_PROTO_DTLS13
    ret = Dtls13PrepareReadState(ctx, encryptedMsg, hdr, &state);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
    const RecCryptoFunc *funcs = RecGetCryptoFuncs(state->suiteInfo);
#ifdef HITLS_TLS_PROTO_DTLS13
    /* DTLS 1.3 epoch-0 records carry plaintext; bypass AEAD decryption. */
    if (Dtls13IsEpoch0Record(ctx, encryptedMsg)) {
        funcs = RecGetCryptoFuncs(NULL);
    }
#endif
    ret = RecordPrepareDecryptBuf(ctx, state, funcs, encryptedMsg, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = RecordDecryptPayload(ctx, state, funcs, encryptedMsg, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    ret = RecordDecryptPostProcess(ctx, state, funcs, encryptedMsg, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    ret = ProcessDecryptedRecord(ctx, decryptBuf->end, encryptedMsg);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    return HITLS_SUCCESS;
ERR:
    FreeHeldRecordBuf(decryptBuf);
    return ret;
}

static int32_t RecordUnexpectedMsg(TLS_Ctx *ctx, RecBuf *decryptBuf, REC_Type recordType)
{
    int32_t ret = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    ctx->recCtx->unexpectedMsgType = recordType;
    switch (recordType) {
        case REC_TYPE_HANDSHAKE:
            ret = RecBufListAddBuffer(ctx->recCtx->hsRecList, decryptBuf);
            break;
        case REC_TYPE_APP:
            ret = RecBufListAddBuffer(ctx->recCtx->appRecList, decryptBuf);
            break;
        default:
            ret = ctx->method.unexpectedMsgProcessCb(ctx, recordType,
                decryptBuf->buf, decryptBuf->end, false);
            if (decryptBuf->isHoldBuffer) {
                BSL_SAL_FREE(decryptBuf->buf);
            }
            if (recordType == REC_TYPE_ACK && ret == HITLS_SUCCESS) {
                return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
            }
            return ret;
    }
    if (ret != HITLS_SUCCESS) {
        if (decryptBuf->isHoldBuffer) {
            BSL_SAL_FREE(decryptBuf->buf);
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17258, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "process recordType fail", 0, 0, 0, 0);
        return ret;
    }
    ret = RecDerefBufList(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17259, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecDerefBufList fail", 0, 0, 0, 0);
        return ret;
    }
    return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}

#if defined(HITLS_TLS_PROTO_DATAGRAM)
int32_t DtlsCheckVersionField(const TLS_Ctx *ctx, uint16_t version, uint8_t type)
{
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
        if (version == HITLS_VERSION_DTLS13) {
            return HITLS_SUCCESS;
        }
        if (version == HITLS_VERSION_DTLS12 &&
            (type == (uint8_t)REC_TYPE_HANDSHAKE || type == (uint8_t)REC_TYPE_ALERT ||
            type == (uint8_t)REC_TYPE_ACK || type == (uint8_t)REC_TYPE_CHANGE_CIPHER_SPEC)) {
            return HITLS_SUCCESS;
        }
        BSL_ERR_PUSH_ERROR(HITLS_REC_INVALID_PROTOCOL_VERSION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15437, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with illegal version(0x%x).", version, 0, 0, 0);
        return HITLS_REC_INVALID_PROTOCOL_VERSION;
    }

#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == 0u && IS_DTLS13_CTX(ctx) && version == HITLS_VERSION_DTLS13) {
        return HITLS_SUCCESS;
    }
#endif

    /* Tolerate alerts with non-negotiated version. For example, after the server sends server hello, the client
     * replies with an earlier version alert */
    if (ctx->negotiatedInfo.version == 0u || type == (uint8_t)REC_TYPE_ALERT) {
        if ((version != HITLS_VERSION_DTLS10) && (version != HITLS_VERSION_DTLS12) &&
            (version != HITLS_VERSION_TLCP_DTLCP11)) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_INVALID_PROTOCOL_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15436, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get a record with illegal version(0x%x).", version, 0, 0, 0);
            return HITLS_REC_INVALID_PROTOCOL_VERSION;
        }
    } else {
        if (version != ctx->negotiatedInfo.version) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_INVALID_PROTOCOL_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15437, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get a record with illegal version(0x%x).", version, 0, 0, 0);
            return HITLS_REC_INVALID_PROTOCOL_VERSION;
        }
    }
    return HITLS_SUCCESS;
}

int32_t DtlsCheckRecordHeader(TLS_Ctx *ctx, const RecHdr *hdr)
{
    /** Check the DTLS version, release the resource and return if the version is incorrect */
    int32_t ret = DtlsCheckVersionField(ctx, hdr->version, hdr->type);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17261, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DtlsCheckVersionField fail, ret %d", ret, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
    }

    REC_Type recType = RecCastUintToRecType(ctx, hdr->type, REC_EPOCH_GET(hdr->epochSeq));
    if ((recType == REC_TYPE_UNKNOWN &&
        (ctx->recReadCb == NULL || !IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask)) &&
        hdr->version != HITLS_VERSION_DTLS13) ||
        hdr->bodyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15438, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid type or body length(0)", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

    RecConnState *state = GetReadConnState(ctx);

    uint32_t maxLenth = (state->suiteInfo != NULL) ? REC_MAX_CIPHER_TEXT_LEN : REC_MAX_PLAIN_LENGTH;
    if (hdr->bodyLen > maxLenth) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_TOO_BIG_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15439, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }
#ifdef HITLS_BSL_UIO_SCTP
    uint16_t epoch = REC_EPOCH_GET(hdr->epochSeq);
    if (epoch == 0 && hdr->type == REC_TYPE_APP && BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15440, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a UNEXPECTED record msg: epoch 0's app msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_ERR_RECV_UNEXPECTED_MSG;
    }
#endif /* HITLS_BSL_UIO_SCTP */
    return HITLS_SUCCESS;
}

/**
* @brief Read message data.
*
* @param uio [IN] UIO object.
* @param inBuf [IN] inBuf Read the buffer.
*
* @retval HITLS_SUCCESS is successfully read.
* @retval HITLS_REC_ERR_IO_EXCEPTION I/O error
* @retval HITLS_REC_NORMAL_RECV_BUF_EMPTY Uncached data needs to be reread.
 */
static int32_t ReadDatagram(TLS_Ctx *ctx, RecBuf *inBuf)
{
    if (inBuf->end > inBuf->start) {
        return HITLS_SUCCESS;
    }
    /* Attempt to read the message: The message is read of the whole message */
    uint32_t recvLen = 0u;
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_READING;
#endif
#ifdef HITLS_TLS_FEATURE_FLIGHT
    int32_t ret = BSL_UIO_Read(ctx->rUio, &(inBuf->buf[0]), inBuf->bufSize, &recvLen);
#else
    int32_t ret = BSL_UIO_Read(ctx->uio, &(inBuf->buf[0]), inBuf->bufSize, &recvLen);
#endif
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15441, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record read: uio err.%d", ret, 0, 0, 0);
        return HITLS_REC_ERR_IO_EXCEPTION;
    }
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_NOTHING;
#endif
    if (recvLen == 0) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }

    inBuf->start = 0;
    // successfully read
    inBuf->end = recvLen;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_DTLS13

int32_t Dtls13ReconstructEpoch(TLS_Ctx *ctx, uint8_t epochBits, uint64_t *reconstructedEpoch)
{
    RecConnState *state = GetReadConnState(ctx);
    uint16_t currentEpoch = RecConnGetEpoch(state);
    uint8_t currentEpochBits = currentEpoch & REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK;
    if (epochBits == currentEpochBits) {
        *reconstructedEpoch = currentEpoch;
        return HITLS_SUCCESS;
    }
    // Handshake
    if (currentEpoch < 3) {
        if (currentEpoch == 2 && epochBits == 3) {
            *reconstructedEpoch = 3;
            return HITLS_SUCCESS;
        }
        if (epochBits == 2) {
            *reconstructedEpoch = 2;
            return HITLS_SUCCESS;
        }
        return HITLS_REC_DECODE_ERROR;
    }
    // handshake fininshed
    uint16_t candidateEpoch = currentEpoch - 1;
    for (uint16_t i = 0; i <= 3 ; i++) {
        if (candidateEpoch > i && ((candidateEpoch - i) & REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK) == epochBits) {
            *reconstructedEpoch = candidateEpoch - i;
            return HITLS_SUCCESS;
        }
    }
    return HITLS_REC_DECODE_ERROR;
}

/**
 * @brief Validate and consume the CID field of a DTLS 1.3 unified-header record.
 *
 * Implements the C-bit handling required by RFC 9147 §4.2. The on-wire C bit must
 * agree with the locally negotiated (receive) CID. Mismatches are reported as
 * HITLS_REC_DECODE_ERROR; the caller (RecordSendAlertMsg) silently discards them
 * for DTLS per RFC 6347 §4.1.2.7.
 *
 *   | C bit | local recv cidLen | meaning                          | return                         |
 *   |-------|-------------------|----------------------------------|--------------------------------|
 *   |   1   |       > 0         | record carries a CID             | SUCCESS, else DECODE_ERROR     |
 *   |   1   |       == 0        | we have no CID to receive        | DECODE_ERROR                   |
 *   |   0   |       > 0         | CID negotiated but not carried   | DECODE_ERROR                   |
 *   |   0   |       == 0        | no CID in use                    | SUCCESS                        |
 */
static int32_t Dtls13ProcessCidBit(TLS_Ctx *ctx, const uint8_t *msg,
                                   uint32_t len, uint32_t *offset, RecHdr *hdr)
{
    (void)ctx;
    bool cidBit = ((msg[0] & REC_DTLS13_UNI_HEADER_CID_BIT) == REC_DTLS13_UNI_HEADER_CID_BIT);
#ifdef HITLS_TLS_FEATURE_DTLS_CID
    uint8_t expectedCidLen = ctx->negotiatedInfo.isCidNegotiated ? ctx->negotiatedInfo.localCidEntry.cidLen : 0;
#else
    uint8_t expectedCidLen = 0;
#endif

    if (cidBit) {
        /* RFC 9147 §9: "If no CID is negotiated, then the receiver MUST reject any
         * records it receives that contain a CID." The C bit is set but no CID is
         * negotiated: an invalid record (the caller silently discards it for DTLS,
         * per RFC 6347 §4.1.2.7). */
        if (expectedCidLen == 0) {
            return HITLS_REC_DECODE_ERROR;
        }
        /* Header truncated: the announced CID runs past the buffer. */
        if (*offset + expectedCidLen > len) {
            return HITLS_REC_DECODE_ERROR;
        }
#ifdef HITLS_TLS_FEATURE_DTLS_CID
        if (!DTLS_CID_IsExpectedCid(ctx, &msg[*offset], expectedCidLen)) {
            return HITLS_REC_DECODE_ERROR;
        }
#endif
        memcpy(hdr->cid, &msg[*offset], expectedCidLen);
        hdr->cidLen = expectedCidLen;
        *offset += hdr->cidLen;
    } else if (expectedCidLen > 0) {
        /* RFC 9147 §4: "If a Connection ID is negotiated, then it MUST be contained in
         * all datagrams." The C bit is clear despite a non-empty CID being negotiated:
         * an invalid record (the caller silently discards it; the peer's retransmission
         * recovers). */
        return HITLS_REC_DECODE_ERROR;
    }

    return HITLS_SUCCESS;
}

static int32_t Dtls13GetRecordUnifiedHeader(TLS_Ctx *ctx, const uint8_t *msg, uint32_t len, RecHdr *hdr)
{
    uint8_t firstByte = msg[0];
    bool seqBit = ((firstByte & REC_DTLS13_UNI_HEADER_SEQ_BIT) == REC_DTLS13_UNI_HEADER_SEQ_BIT);
    bool lengthBit = ((firstByte & REC_DTLS13_UNI_HEADER_LEN_BIT) == REC_DTLS13_UNI_HEADER_LEN_BIT);
    uint8_t epochBits = firstByte & REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK;

    uint32_t offset = 1;
    int32_t cidRet = Dtls13ProcessCidBit(ctx, msg, len, &offset, hdr);
    if (cidRet != HITLS_SUCCESS) {
        return cidRet;
    }
    uint8_t seqLen = seqBit ? 2 : 1;
    if (offset + seqLen > len) {
        return HITLS_REC_DECODE_ERROR;
    }
    offset += seqLen;

    if (lengthBit) {
        if (offset + sizeof(uint16_t) > len) {
            return HITLS_REC_DECODE_ERROR;
        }
        hdr->bodyLen = BSL_ByteToUint16(&msg[offset]);
        offset += 2;
    } else {
        hdr->bodyLen = len - offset;
    }
    if (hdr->bodyLen == 0 || offset + hdr->bodyLen > len) {
        return HITLS_REC_DECODE_ERROR;
    }
    if (offset > sizeof(hdr->dtls13Aad)) {
        return HITLS_REC_DECODE_ERROR;
    }
    memcpy(hdr->dtls13Aad, msg, offset);
    hdr->dtls13AadLen = offset;

    /* Reconstruct epoch first, then select the correct read state (current or outdated)
     * before decrypting the sequence number. RFC 9147 §4.2.2 / §4.2.3 */
    uint64_t epoch = 0;
    int32_t ret = Dtls13ReconstructEpoch(ctx, epochBits, &epoch);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (epoch == 0) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
    ret = Dtls13TrySendRetransAckOnEpoch2(ctx, epoch);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    hdr->epochSeq = REC_EPOCHSEQ_CAL(epoch, 0);
    /* Unified header has no plaintext content type; type is recovered from the
     * decrypted DTLSInnerPlaintext (RFC 9147 §4). Mark APP here so RecCastUintToRecType
     * accepts the header; the real type is filled in by decryptPostProcess. */
    hdr->type = REC_TYPE_UNKNOWN;
    hdr->version = HITLS_VERSION_DTLS13;
    hdr->headerLen = (uint16_t)offset;
    return HITLS_SUCCESS;
}
#endif

static int32_t DtlsGetRecordHeader(TLS_Ctx *ctx, const uint8_t *msg, uint32_t len, RecHdr *hdr)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    (void)ctx;
#endif
    uint32_t headerLen = RecGetReadHeaderLen(msg[0],
#ifdef HITLS_TLS_PROTO_DTLS13
        hdr->cidLen
#else
        0
#endif
    );
    if (len < headerLen) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_DECODE_ERROR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15442, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DtlsGetRecordHeader length err: len %u < headerLen %u.", len, headerLen, 0, 0);
        return HITLS_REC_DECODE_ERROR;
    }
    hdr->headerLen = headerLen;
#ifdef HITLS_TLS_PROTO_DTLS13
    if (IS_DTLS13_CTX(ctx) &&
        msg[0] != REC_TYPE_ALERT && msg[0] != REC_TYPE_HANDSHAKE &&
        msg[0] != REC_TYPE_ACK && msg[0] != REC_TYPE_CHANGE_CIPHER_SPEC) {
        if (!REC_DTLS13_UNI_HEADER_FIX_BITS_TYPE(msg[0])) {
            return HITLS_REC_DECODE_ERROR;
        }
        return Dtls13GetRecordUnifiedHeader(ctx, msg, len, hdr);
    }
#endif
    /* Parse the record header */
    hdr->type = msg[0];
    hdr->version = BSL_ByteToUint16(&msg[1]);
    hdr->bodyLen = BSL_ByteToUint16(
        &msg[REC_DTLS_RECORD_LENGTH_OFFSET]);  // The 11th to 12th bytes of DTLS are the message length.
    hdr->epochSeq = BSL_ByteToUint64(&msg[REC_DTLS_RECORD_EPOCH_OFFSET]);
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
        BSL_Uint64ToByte(REC_SEQ_GET(hdr->epochSeq), hdr->dtls13Seq);
    }
#endif
    hdr->headerLen = REC_DTLS_RECORD_HEADER_LEN;
    return HITLS_SUCCESS;
}

/**
 * @brief Attempt to read a dtls record message.
 *
 * @param ctx [IN] TLS context
 * @param recordBody [OUT] record body
 * @param hdr [OUT] record head
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_REC_NORMAL_RECV_BUF_EMPTY needs to be read again
 * @retval HITLS_REC_ERR_IO_EXCEPTION I/O error
 */
static int32_t TryReadOneDtlsRecord(TLS_Ctx *ctx, uint8_t **recordBody, RecHdr *hdr)
{
    int32_t ret;
    /** Obtain the record structure information */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
#ifdef HITLS_TLS_PROTO_DTLS13
#ifdef HITLS_TLS_FEATURE_DTLS_CID
    hdr->cidLen = ctx->negotiatedInfo.isCidNegotiated ? ctx->negotiatedInfo.localCidEntry.cidLen : 0;
#else
    hdr->cidLen = 0;
#endif
#endif
    if (IsNeedtoRead(ctx, recordCtx->inBuf, hdr)) {
        ret = RecDerefBufList(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    /** Read the datagram message: The message may contain multiple records */
    ret = ReadDatagram(ctx, recordCtx->inBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint8_t *msg = &recordCtx->inBuf->buf[recordCtx->inBuf->start];
    uint32_t len = recordCtx->inBuf->end - recordCtx->inBuf->start;
    ret = DtlsGetRecordHeader(ctx, msg, len, hdr);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17262, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DtlsGetRecordHeader fail, ret %d, discard", ret, 0, 0, 0);
        RecBufClean(recordCtx->inBuf);
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }

#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(0, 0, RECORD_HEADER, msg, hdr->headerLen, ctx,
                              ctx->config.tlsConfig.msgArg);
#endif

    /* Check whether the record length is greater than the buffer size */
    if ((uint32_t)hdr->headerLen + hdr->bodyLen > len) {
        RecBufClean(recordCtx->inBuf);
        BSL_ERR_PUSH_ERROR(HITLS_REC_DECODE_ERROR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15443, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "TryReadOneDtlsRecord headerLen %u + bodyLen %u > len %u.", hdr->headerLen, hdr->bodyLen,
                              len, 0);
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }

    /** Release the read record */
    recordCtx->inBuf->start += hdr->headerLen + hdr->bodyLen;

    /** Update the read content */
    *recordBody = msg + hdr->headerLen;

    return HITLS_SUCCESS;
}

static inline void GenerateCryptMsg(const TLS_Ctx *ctx,
    const RecHdr *hdr, const uint8_t *recordBody, REC_TextInput *cryptMsg)
{
    cryptMsg->negotiatedVersion = ctx->negotiatedInfo.version;
#ifdef HITLS_TLS_FEATURE_ETM
    cryptMsg->isEncryptThenMac = ctx->recCtx->readStates.currentState->isEncryptThenMac;
#endif
    cryptMsg->type = hdr->type;
    cryptMsg->version = hdr->version;
    cryptMsg->text = recordBody;
    cryptMsg->textLen = hdr->bodyLen;
    BSL_Uint64ToByte(hdr->epochSeq, cryptMsg->seq);
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
        memcpy(cryptMsg->dtls13Aad, hdr->dtls13Aad, hdr->dtls13AadLen);
        cryptMsg->dtls13AadLen = hdr->dtls13AadLen;
        memcpy(cryptMsg->dtls13Seq, hdr->dtls13Seq, sizeof(cryptMsg->dtls13Seq));
    }
#endif
}

#if defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP)
static bool IsExistUnprocessedMsg(RecCtx *recCtx)
{
    UnprocessedMsg *UnprocessedMsgList = &recCtx->UnprocessedMsgList;
    /* Check whether there are cached app messages. */
    if (UnprocessedMsgList->count == 0) {
        return false;
    }

    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    UnprocessedMsg *cur = NULL;
    uint16_t curEpoch = recCtx->readEpoch;
    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(UnprocessedMsgList->head)) {
        cur = BSL_LIST_ENTRY(node, UnprocessedMsg, head);
        uint16_t epoch = REC_EPOCH_GET(cur->hdr.epochSeq);
        if (curEpoch == epoch) {
            /* The app message of the current epoch needs to be processed */
            return true;
        }
    }
    return false;
}

int32_t RecordBufferUnprocessedMsg(RecCtx *recordCtx, RecHdr *hdr, uint8_t *recordBody)
{
    int32_t ret = UnprocessedMsgListAppend(&recordCtx->UnprocessedMsgList, hdr, recordBody);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17263, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "recv normal disorder message", 0, 0, 0, 0);
    return HITLS_REC_NORMAL_RECV_DISORDER_MSG;
}
#endif /* HITLS_TLS_PROTO_DATAGRAM && HITLS_BSL_UIO_UDP */

#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP)
static int32_t Dtls13HandleDifferentEpochRecord(TLS_Ctx *ctx, RecCtx *recordCtx, uint8_t *recordBody, RecHdr *hdr,
    uint16_t epoch)
{
    if (!IS_DTLS13_CTX(ctx)) {
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }
    if (recordCtx->readEpoch == 0 && epoch == 2 && ctx->isClient) {
        return RecordBufferUnprocessedMsg(recordCtx, hdr, recordBody);
    }
    if (recordCtx->readEpoch == 2 && epoch == 3) {
        return RecordBufferUnprocessedMsg(recordCtx, hdr, recordBody);
    }
    if (((recordCtx->readEpoch > 3 && recordCtx->readEpoch - 1 == epoch) ||
        (recordCtx->readEpoch == 2 && epoch == 0 && !ctx->isClient)) &&
        GetReadConnState(ctx)->window.window == 0) {
        return HITLS_SUCCESS;
    }
    return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}
#endif

static int32_t DtlsProcessDifferentEpochRecord(TLS_Ctx *ctx, RecCtx *recordCtx, uint8_t *recordBody, RecHdr *hdr,
    uint16_t epoch)
{
#if defined(HITLS_TLS_PROTO_TLS13_FAMILY)
    if (IS_TLS13_FAMILY_CTX(ctx) &&
        hdr->type == REC_TYPE_CHANGE_CIPHER_SPEC && epoch == 0) {
        return HITLS_SUCCESS;
    }
#endif
#ifdef HITLS_BSL_UIO_SCTP
    /* Discard out-of-order messages in SCTP scenarios */
    if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }
#endif /* HITLS_BSL_UIO_SCTP */
#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP)
    int32_t ret = Dtls13HandleDifferentEpochRecord(ctx, recordCtx, recordBody, hdr, epoch);
    if (ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
        return ret;
    }
#endif
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    /* Only the messages of the next epoch are cached */
    if ((recordCtx->readEpoch + 1) == epoch) {
        return RecordBufferUnprocessedMsg(recordCtx, hdr, recordBody);
    }
#endif
    /* After receiving the message of the previous epoch, the system discards the message. */
    return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
}

static int32_t DtlsProcessCurrentEpochRecord(TLS_Ctx *ctx, RecCtx *recordCtx, uint8_t *recordBody, RecHdr *hdr)
{
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    bool isCcsRecv = ctx->method.isRecvCCS(ctx);
    /* App messages arrive earlier than finished messages and need to be cached */
    if (ctx->hsCtx != NULL && isCcsRecv == true && (hdr->type == REC_TYPE_APP || hdr->type == REC_TYPE_ALERT)) {
        return RecordBufferUnprocessedMsg(recordCtx, hdr, recordBody);
    }
#else
    (void)ctx;
    (void)recordCtx;
    (void)recordBody;
    (void)hdr;
#endif
    return HITLS_SUCCESS;
}

static int32_t DtlsRecordHeaderProcess(TLS_Ctx *ctx, uint8_t *recordBody, RecHdr *hdr)
{
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    int32_t ret = DtlsCheckRecordHeader(ctx, hdr);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint16_t epoch = REC_EPOCH_GET(hdr->epochSeq);
    if (epoch != recordCtx->readEpoch) {
        return DtlsProcessDifferentEpochRecord(ctx, recordCtx, recordBody, hdr, epoch);
    }
    return DtlsProcessCurrentEpochRecord(ctx, recordCtx, recordBody, hdr);
}

static uint8_t *GetUnprocessedMsg(RecCtx *recordCtx, REC_Type recordType, RecHdr *hdr)
{
    (void)recordCtx;
    (void)recordType;
    (void)hdr;
    uint8_t *recordBody = NULL;
#if defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP)
    uint16_t curEpoch = recordCtx->readEpoch;
    if (IsExistUnprocessedMsg(recordCtx)) {
        UnprocessedMsg *appMsg = UnprocessedMsgGet(&recordCtx->UnprocessedMsgList, curEpoch, recordType);
        if (appMsg == NULL) {
            return NULL;
        }
        memcpy(hdr, &appMsg->hdr, sizeof(RecHdr));
        recordBody = appMsg->recordBody;
        appMsg->recordBody = NULL;
        UnprocessedMsgFree(appMsg);
    }
#endif
    return recordBody;
}

#if defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP) && \
    defined(HITLS_TLS_FEATURE_ANTI_REPLAY)
static int32_t AntiReplay(TLS_Ctx *ctx, RecHdr *hdr)
{
    /* In non-UDP scenarios, anti-replay check is not required */
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        return HITLS_SUCCESS;
    }

    RecConnState *state = GetReadConnState(ctx);
    uint16_t epoch = REC_EPOCH_GET(hdr->epochSeq);
    uint64_t secquence = REC_SEQ_GET(hdr->epochSeq);
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
        uint16_t currentEpoch = RecConnGetEpoch(state);
        if (currentEpoch > 0 && currentEpoch - 1 == epoch) {
            RecConnState *outdated = GetReadOutdatedState(ctx);
            if (outdated != NULL) {
                state = outdated;
            } else {
                return HITLS_REC_DECODE_ERROR;
            }
        }
        secquence = BSL_ByteToUint64(hdr->dtls13Seq);
    }
#endif
    if (RecAntiReplayCheck(&state->window, secquence) == true) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }

    if (ctx->isDtlsListen && epoch != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17264, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "epoch err", 0, 0, 0, 0);
        return HITLS_REC_ERR_RECV_UNEXPECTED_MSG;
    }

    return HITLS_SUCCESS;
}
#endif

static int32_t DtlsTryReadAndCheckRecordMessage(TLS_Ctx *ctx, uint8_t **recordBody, RecHdr *hdr)
{
    int32_t ret = HITLS_SUCCESS;
    /* Read the new record message */
    ret = TryReadOneDtlsRecord(ctx, recordBody, hdr);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check the record message header. If the message header is not the expected message, cache the message */
    return DtlsRecordHeaderProcess(ctx, *recordBody, hdr);
}

static int32_t DtlsGetRecord(TLS_Ctx *ctx, REC_Type recordType, RecHdr *hdr, uint8_t **recordBody, uint8_t **cachRecord)
{
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    int32_t ret = RecIoBufInit(ctx, recordCtx, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* Check if there are cached messages that need to be processed */
    *recordBody = GetUnprocessedMsg(recordCtx, recordType, hdr);
    *cachRecord = *recordBody;
    /* There are no cached messages to process */
    if (*recordBody == NULL) {
        ret = DtlsTryReadAndCheckRecordMessage(ctx, recordBody, hdr);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP) && \
    defined(HITLS_TLS_FEATURE_ANTI_REPLAY)
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13) {
        ret = AntiReplay(ctx, hdr);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_FREE(*cachRecord);
        }
    }
#endif
    return ret;
}

static int32_t DtlsProcessBufList(TLS_Ctx *ctx, REC_Type recordType, RecBufList *bufList, RecBuf *decryptBuf)
{
    (void)recordType;
    int32_t ret = RecBufListAddBuffer(bufList, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        if (decryptBuf->isHoldBuffer) {
            BSL_SAL_FREE(decryptBuf->buf);
        }
        return ret;
    }
    ret = RecDerefBufList(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_DTLS13
static void Dtls13SyncHeaderAfterDecrypt(TLS_Ctx *ctx, RecHdr *hdr, const REC_TextInput *cryptMsg)
{
    memcpy(hdr->dtls13Seq, cryptMsg->dtls13Seq, sizeof(cryptMsg->dtls13Seq));
    memcpy(hdr->dtls13Aad, cryptMsg->dtls13Aad, sizeof(cryptMsg->dtls13Aad));
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
        uint64_t seq = BSL_ByteToUint64(hdr->dtls13Seq);
        hdr->epochSeq = REC_EPOCHSEQ_CAL(REC_EPOCH_GET(hdr->epochSeq), seq);
    }
}

static int32_t Dtls13HandleHandshakeAfterDecrypt(TLS_Ctx *ctx, RecHdr *hdr, const REC_TextInput *cryptMsg,
    RecBuf *decryptBuf)
{
    if (!IS_DTLS13_CTX(ctx) || !IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) ||
        cryptMsg->type != REC_TYPE_HANDSHAKE) {
        return HITLS_SUCCESS;
    }

    int32_t ret = Dtls13HandleHandshakeAck(ctx, hdr);
    if (ret != HITLS_SUCCESS) {
        FreeHeldRecordBuf(decryptBuf);
    }
    return ret;
}

static int32_t Dtls13DiscardOutdatedHandshake(TLS_Ctx *ctx, const RecHdr *hdr, const REC_TextInput *cryptMsg,
    RecBuf *decryptBuf)
{
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 &&
        cryptMsg->type == REC_TYPE_HANDSHAKE &&
        ctx->recCtx->readEpoch > 3 &&
        ctx->recCtx->readEpoch - 1 == REC_EPOCH_GET(hdr->epochSeq)) {
        FreeHeldRecordBuf(decryptBuf);
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
    return HITLS_SUCCESS;
}
#endif

#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP) && defined(HITLS_TLS_FEATURE_ANTI_REPLAY)
static int32_t Dtls13AntiReplayAfterDecrypt(TLS_Ctx *ctx, RecHdr *hdr, RecBuf *decryptBuf)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13 || REC_EPOCH_GET(hdr->epochSeq) == 0) {
        return HITLS_SUCCESS;
    }

    /* RFC 9147: update the window only after the record has been deprotected successfully. */
    int32_t ret = AntiReplay(ctx, hdr);
    if (ret != HITLS_SUCCESS) {
        FreeHeldRecordBuf(decryptBuf);
    }
    return ret;
}
#endif

#if defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP) && \
    defined(HITLS_TLS_FEATURE_ANTI_REPLAY)
static int32_t DtlsUpdateAntiReplayWindow(TLS_Ctx *ctx, const RecHdr *hdr, RecBuf *decryptBuf)
{
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP) || REC_EPOCH_GET(hdr->epochSeq) == 0) {
        return HITLS_SUCCESS;
    }
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) {
        RecConnState *state = NULL;
        int32_t ret = Dtls13GetCurrentOrOutdatedReadState(ctx, REC_EPOCH_GET(hdr->epochSeq), &state);
        if (ret != HITLS_SUCCESS) {
            FreeHeldRecordBuf(decryptBuf);
            return ret;
        }
        RecAntiReplayUpdate(&state->window, BSL_ByteToUint64(hdr->dtls13Seq));
        return HITLS_SUCCESS;
    }
#else
    (void)decryptBuf;
#endif
    RecAntiReplayUpdate(&GetReadConnState(ctx)->window, REC_SEQ_GET(hdr->epochSeq));
    return HITLS_SUCCESS;
}
#endif

static int32_t DtlsRecordReadPostDecrypt(TLS_Ctx *ctx, REC_Type recordType, RecHdr *hdr, REC_TextInput *cryptMsg,
    RecBuf *decryptBuf)
{
    int32_t ret = HITLS_SUCCESS;
    (void)ret;
    (void)ctx;
    (void)hdr;
#ifdef HITLS_TLS_PROTO_DTLS13
    Dtls13SyncHeaderAfterDecrypt(ctx, hdr, cryptMsg);
#endif
#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP) && defined(HITLS_TLS_FEATURE_ANTI_REPLAY)
    ret = Dtls13AntiReplayAfterDecrypt(ctx, hdr, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_TLS_PROTO_DTLS13
    ret = Dtls13HandleHandshakeAfterDecrypt(ctx, hdr, cryptMsg, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#if defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP) && \
    defined(HITLS_TLS_FEATURE_ANTI_REPLAY)
    ret = DtlsUpdateAntiReplayWindow(ctx, hdr, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_TLS_PROTO_DTLS13
    ret = Dtls13DiscardOutdatedHandshake(ctx, hdr, cryptMsg, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_TLS_PROTO_DFX_ALERT_NUMBER
    ctx->method.clearAlert(ctx, cryptMsg->type);
#endif
#ifdef HITLS_TLS_FEATURE_MODE_RELEASE_BUFFERS
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_RELEASE_BUFFERS) != 0 && recordType == REC_TYPE_APP) {
        RecTryFreeRecBuf(ctx, false);
    }
#endif
    if (recordType == cryptMsg->type) {
        return HITLS_SUCCESS;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16513, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "REC_Type: expect %d, receive  %d", recordType, cryptMsg->type, 0, 0);
    return RecordUnexpectedMsg(ctx, decryptBuf, cryptMsg->type);
}

static int32_t DtlsReturnRecordBuffer(TLS_Ctx *ctx, REC_Type recordType, RecBufList *bufList, RecBuf *decryptBuf,
    uint8_t *data, uint32_t *len, uint32_t bufSize)
{
    if (decryptBuf->buf == data) {
        *len = decryptBuf->end;
        return HITLS_SUCCESS;
    }

    int32_t ret = DtlsProcessBufList(ctx, recordType, bufList, decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return RecBufListGetBuffer(bufList, data, bufSize, len, (ctx->peekFlag != 0 && recordType == REC_TYPE_APP));
}

/**
 * @brief Read a record in the DTLS protocol.
 *
 * @param ctx [IN] TLS context
 * @param recordType [IN] Record type
 * @param data [OUT] Read data
 * @param len [OUT] Length of the data to be read
 * @param bufSize [IN] buffer length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_REC_NORMAL_RECV_BUF_EMPTY needs to be read again
 * @retval HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval HITLS_REC_NORMAL_RECV_UNEXPECT_MSG Unexpected message received
 * @retval HITLS_REC_NORMAL_RECV_DISORDER_MSG Receives out-of-order messages.
 *
 */
int32_t DtlsRecordRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *len, uint32_t bufSize)
{
    RecBufList *bufList = (recordType == REC_TYPE_HANDSHAKE) ? ctx->recCtx->hsRecList : ctx->recCtx->appRecList;
    if (!RecBufListEmpty(bufList)) {
        return RecBufListGetBuffer(bufList, data, bufSize, len, (ctx->peekFlag != 0 && (recordType == REC_TYPE_APP)));
    }
    RecHdr hdr = {0};
    /* Pointer for storing buffered messages, which is used during release */
    uint8_t *recordBody = NULL;
    uint8_t *cachRecord = NULL;
    int32_t ret = DtlsGetRecord(ctx, recordType, &hdr, &recordBody, &cachRecord);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#if defined(HITLS_TLS_PROTO_TLS13_FAMILY)
    if (IS_TLS13_FAMILY_CTX(ctx) &&
        hdr.type == REC_TYPE_CHANGE_CIPHER_SPEC) {
        BSL_SAL_FREE(cachRecord);
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
#endif
    /* Construct parameters before decryption */
    REC_TextInput cryptMsg = {0};
    GenerateCryptMsg(ctx, &hdr, recordBody, &cryptMsg);
    RecBuf decryptBuf = { .buf = data, .bufSize = bufSize };
    ret = RecordDecrypt(ctx, &decryptBuf, &cryptMsg, &hdr);
    BSL_SAL_FREE(cachRecord);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = DtlsRecordReadPostDecrypt(ctx, recordType, &hdr, &cryptMsg, &decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return DtlsReturnRecordBuffer(ctx, recordType, bufList, &decryptBuf, data, len, bufSize);
}

#endif /* HITLS_TLS_PROTO_DATAGRAM */

#ifdef HITLS_TLS_PROTO_TLS
static int32_t VersionProcess(TLS_Ctx *ctx, uint16_t version, uint8_t type)
{
    if ((ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) && (version != HITLS_VERSION_TLS12)) {
            /* If the negotiated version is tls1.3, the record version must be tls1.2 */
            BSL_ERR_PUSH_ERROR(HITLS_REC_INVALID_PROTOCOL_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15448, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get a record with illegal version(0x%x).", version, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_REC_INVALID_PROTOCOL_VERSION;
    } else if ((ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) && (version != ctx->negotiatedInfo.version)) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_INVALID_PROTOCOL_VERSION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15449, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with illegal version(0x%x).", version, 0, 0, 0);
        if (((version & 0xff00u) == (ctx->negotiatedInfo.version & 0xff00u)) && type == REC_TYPE_ALERT) {
            return HITLS_SUCCESS;
        }
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
        return HITLS_REC_INVALID_PROTOCOL_VERSION;
    }
    return HITLS_SUCCESS;
}

int32_t TlsCheckVersionField(TLS_Ctx *ctx, uint16_t version, uint8_t type)
{
    if (ctx->negotiatedInfo.version == 0u) {
#ifdef HITLS_TLS_PROTO_TLCP11
        if (((version >> 8u) != HITLS_VERSION_TLS_MAJOR) && (version != HITLS_VERSION_TLCP_DTLCP11)) {
#else
        if ((version >> 8u) != HITLS_VERSION_TLS_MAJOR) {
#endif
            BSL_ERR_PUSH_ERROR(HITLS_REC_INVALID_PROTOCOL_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16132, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get a record with illegal version(0x%x).", version, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
            return HITLS_REC_INVALID_PROTOCOL_VERSION;
        }
    } else {
        return VersionProcess(ctx, version, type);
    }
    return HITLS_SUCCESS;
}

int32_t TlsCheckRecordHeader(TLS_Ctx *ctx, const RecHdr *recordHdr)
{
    if (RecCastUintToRecType(ctx, recordHdr->type, 0) == REC_TYPE_UNKNOWN &&
        (ctx->recReadCb == NULL || !IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask))) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15450, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid type", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

    int32_t ret = TlsCheckVersionField(ctx, recordHdr->version, recordHdr->type);
    if (ret != HITLS_SUCCESS) {
        return HITLS_REC_INVALID_PROTOCOL_VERSION;
    }

    if (recordHdr->bodyLen + REC_TLS_RECORD_HEADER_LEN > RecGetInitBufferSize(ctx, true)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15451, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }

    if (recordHdr->bodyLen + REC_TLS_RECORD_HEADER_LEN > ctx->recCtx->inBuf->bufSize) {
        ret = RecBufResize(ctx->recCtx->inBuf, recordHdr->bodyLen + REC_TLS_RECORD_HEADER_LEN);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#if defined(HITLS_TLS_PROTO_TLS13_FAMILY)
    if (IS_TLS13_FAMILY_CTX(ctx) && recordHdr->bodyLen > REC_MAX_TLS13_ENCRYPTED_LEN) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16125, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }
#endif
    return HITLS_SUCCESS;
}

/**
 * @brief   Read data from the uio of the TLS context into inBuf
 *
 * @param   ctx [IN] TLS context
 * @param   inBuf [IN] inBuf Read buffer.
 * @param   len [IN] len The length to read, it takes the value of the record header length (5
 * bytes) or the entire record length (header + body)
 *
 * @retval  HITLS_SUCCESS Read successfully
 * @retval  HITLS_REC_ERR_IO_EXCEPTION IO error
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY No cached data needs to be re-read
 * @retval  HITLS_REC_NORMAL_IO_EOF
 */
int32_t StreamRead(TLS_Ctx *ctx, RecBuf *inBuf, uint32_t len)
{
    uint32_t bytesInRbuf = inBuf->end - inBuf->start;
    bool readAheadFlag = (ctx->config.tlsConfig.readAhead != 0);
    if (bytesInRbuf == 0) {
        inBuf->start = 0;
        inBuf->end = 0;
    }

    // there are enough data in the read buffer
    if (bytesInRbuf >= len) {
        return HITLS_SUCCESS;
    }
    // right-side available space is less then required len, move data leftwards
    if (inBuf->bufSize - inBuf->end < len) {
        for (uint32_t i = 0; i < bytesInRbuf; i++) {
            inBuf->buf[i] = inBuf->buf[inBuf->start + i];
        }

        inBuf->start = 0;
        inBuf->end = bytesInRbuf;
    }
    uint32_t upperBnd = (!readAheadFlag && inBuf->bufSize >= inBuf->start + len - inBuf->end)
                            ? inBuf->start + len
                            : inBuf->bufSize;
    do {
        uint32_t recvLen = 0u;
#ifdef HITLS_TLS_CONFIG_STATE
        ctx->rwstate = HITLS_READING;
#endif

#ifdef HITLS_TLS_FEATURE_FLIGHT
        int32_t ret = BSL_UIO_Read(ctx->rUio, &(inBuf->buf[inBuf->end]), upperBnd - inBuf->end, &recvLen);
#else
        int32_t ret = BSL_UIO_Read(ctx->uio,  &(inBuf->buf[inBuf->end]), upperBnd - inBuf->end, &recvLen);
#endif
        if (ret != BSL_SUCCESS) {
            if (ret == BSL_UIO_IO_EOF) {
                return HITLS_REC_NORMAL_IO_EOF;
            }
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15452, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Fail to call BSL_UIO_Read in StreamRead: [%d]", ret, 0, 0, 0);
            return HITLS_REC_ERR_IO_EXCEPTION;
        }

#ifdef HITLS_TLS_CONFIG_STATE
        ctx->rwstate = HITLS_NOTHING;
#endif
        if (recvLen == 0) {
            return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
        }

        inBuf->end += recvLen;
    } while (inBuf->end - inBuf->start < len);

    return HITLS_SUCCESS;
}

/**
 * @brief Attempt to read a tls record message.
 *
 * @param ctx [IN] TLS context
 * @param recordBody [OUT] record body
 * @param hdr [OUT] record head
 *
 * @retval HITLS_SUCCESS
 * @retval HITLS_REC_NORMAL_RECV_BUF_EMPTY needs to be read again
 * @retval HITLS_REC_ERR_IO_EXCEPTION I/O error
 */
int32_t TryReadOneTlsRecord(TLS_Ctx *ctx, uint8_t **recordBody, RecHdr *recHeader)
{
    /* Buffer for reading data */
    RecBuf *inBuf = ctx->recCtx->inBuf;
    if (IsNeedtoRead(ctx, inBuf, recHeader)) {
        RecDerefBufList(ctx);
    }
    // read record header
    int32_t ret = StreamRead(ctx, inBuf, REC_TLS_RECORD_HEADER_LEN);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    const uint8_t *recordHeader = &inBuf->buf[inBuf->start];
    recHeader->type = recordHeader[0];
    recHeader->version = BSL_ByteToUint16(recordHeader + sizeof(uint8_t));
    recHeader->bodyLen = BSL_ByteToUint16(recordHeader + REC_TLS_RECORD_LENGTH_OFFSET);

    ret = TlsCheckRecordHeader(ctx, recHeader);
    /* TlsCheckRecordHeader may reszie the buffer in inBuf */
    recordHeader = &inBuf->buf[inBuf->start];
    if (ret != HITLS_SUCCESS) {
#ifdef HITLS_TLS_FEATURE_INDICATOR
        INDICATOR_MessageIndicate(0, 0, RECORD_HEADER, recordHeader, REC_TLS_RECORD_HEADER_LEN, ctx,
            ctx->config.tlsConfig.msgArg);
#endif
        return ret;
    }

#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(0, recHeader->version, RECORD_HEADER, recordHeader, REC_TLS_RECORD_HEADER_LEN, ctx,
        ctx->config.tlsConfig.msgArg);
#endif

    uint32_t recHeaderAndBodyLen = REC_TLS_RECORD_HEADER_LEN + (uint32_t)recHeader->bodyLen;

    // read a whole record: head + body
    ret = StreamRead(ctx, inBuf, recHeaderAndBodyLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    *recordBody = &inBuf->buf[inBuf->start] + REC_TLS_RECORD_HEADER_LEN;

    inBuf->start += recHeaderAndBodyLen;
    return HITLS_SUCCESS;
}

int32_t RecordDecryptPrepare(TLS_Ctx *ctx, uint16_t version, REC_Type recordType, REC_TextInput *cryptMsg)
{
    (void)recordType;
    (void)version;
    RecConnState *state = GetReadConnState(ctx);
    if (state->isWrapped == true) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_SN_WRAPPING);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15454, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record read: sequence number wrap.", 0, 0, 0, 0);
        return HITLS_REC_ERR_SN_WRAPPING;
    }
    if (state->seq == REC_TLS_SN_MAX_VALUE) {
        state->isWrapped = true;
    }

    if (ctx->peekFlag != 0 && recordType != REC_TYPE_APP) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16170, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Peek mode applies only if record type is application.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    RecHdr recordHeader = { 0 };
    uint8_t *recordBody = NULL;
    // read header and body from ctx
    int32_t ret = TryReadOneTlsRecord(ctx, &recordBody, &recordHeader);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t recordBodyLen = (uint32_t)recordHeader.bodyLen;
#ifdef HITLS_TLS_PROTO_TLS13
    if (GET_VERSION_FROM_CTX(ctx) == HITLS_VERSION_TLS13) {
        if ((recordHeader.type == REC_TYPE_CHANGE_CIPHER_SPEC || recordHeader.type == REC_TYPE_ALERT) &&
            recordBodyLen != 0) {
            ctx->recCtx->unexpectedMsgType = recordHeader.type;
            /* In the TLS1.3 scenario, process unencrypted CCS and Alert messages received */
            return ctx->method.unexpectedMsgProcessCb(ctx, recordHeader.type, recordBody, recordBodyLen, true);
        }
    }
#endif

    cryptMsg->negotiatedVersion = ctx->negotiatedInfo.version;
#ifdef HITLS_TLS_FEATURE_ETM
    cryptMsg->isEncryptThenMac = state->isEncryptThenMac;
#endif
    cryptMsg->type = recordHeader.type;
    cryptMsg->version = recordHeader.version;
    cryptMsg->text = recordBody;
    cryptMsg->textLen = recordBodyLen;
    BSL_Uint64ToByte(state->seq, cryptMsg->seq);
    return HITLS_SUCCESS;
}

/**
 * @brief Read a record in the TLS protocol.
 * @attention: Handle record and handle transporting state to receive unexpected record type messages
 * @param ctx [IN] TLS context
 * @param recordType [IN] Record type
 * @param data [OUT] Read data
 * @param readLen [OUT] Length of the read data
 * @param num [IN] The read buffer has num bytes
 *
 * @retval HITLS_SUCCESS
 * @retval HITLS_REC_NORMAL_RECV_BUF_EMPTY Need to re-read
 * @retval HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval HITLS_REC_ERR_SN_WRAPPING The sequence number is rewound.
 * @retval HITLS_REC_NORMAL_RECV_UNEXPECT_MSG Unexpected message received.
 *
 */
int32_t TlsRecordRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    RecBufList *bufList = (recordType == REC_TYPE_HANDSHAKE) ? ctx->recCtx->hsRecList : ctx->recCtx->appRecList;
    if (!RecBufListEmpty(bufList)) {
        return RecBufListGetBuffer(bufList, data, num, readLen, (ctx->peekFlag != 0 && (recordType == REC_TYPE_APP)));
    }

    int32_t ret = RecIoBufInit(ctx, (RecCtx *)ctx->recCtx, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    REC_TextInput encryptedMsg = { 0 };
    ret = RecordDecryptPrepare(ctx, ctx->negotiatedInfo.version, recordType, &encryptedMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    RecBuf decryptBuf = {0};
    decryptBuf.buf = data;
    decryptBuf.bufSize = num;
    ret = RecordDecrypt(ctx, &decryptBuf, &encryptedMsg, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_TLS_PROTO_DFX_ALERT_NUMBER
    ctx->method.clearAlert(ctx, encryptedMsg.type);
#endif
#ifdef HITLS_TLS_FEATURE_MODE_RELEASE_BUFFERS
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_RELEASE_BUFFERS) != 0 && (recordType == REC_TYPE_APP)) {
        RecTryFreeRecBuf(ctx, false);
    }
#endif
    /* An unexpected message is received */
    if (recordType != encryptedMsg.type) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17260, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "expect type %d, receive type %d", recordType, encryptedMsg.type, 0, 0);
        return RecordUnexpectedMsg(ctx, &decryptBuf, encryptedMsg.type);
    }
    if (decryptBuf.buf == data) {
        /* Update the read length */
        *readLen = decryptBuf.end;
        return HITLS_SUCCESS;
    }
    ret = RecBufListAddBuffer(bufList, &decryptBuf);
    if (ret != HITLS_SUCCESS) {
        if (decryptBuf.isHoldBuffer) {
            BSL_SAL_FREE(decryptBuf.buf);
        }
        return ret;
    }
    return RecBufListGetBuffer(bufList, data, num, readLen, (ctx->peekFlag != 0 && (recordType == REC_TYPE_APP)));
}
#endif /* HITLS_TLS_PROTO_TLS */

uint32_t APP_GetReadPendingBytes(const TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->recCtx == NULL || RecBufListEmpty(ctx->recCtx->appRecList)) {
        return 0;
    }
    RecBuf *recBuf = (RecBuf *)BSL_LIST_FirstNodeData(ctx->recCtx->appRecList);
    if (recBuf == NULL) {
        return 0;
    }
    return recBuf->end - recBuf->start;
}
