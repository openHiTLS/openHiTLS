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
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "rec_alert.h"
#include "tls_config.h"
#include "record.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif
#include "hs.h"
#include "rec_crypto.h"
#include "bsl_list.h"

RecConnState *GetReadConnState(const TLS_Ctx *ctx)
{
    /** Obtains the record structure. */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->readStates.currentState;
}

static bool IsNeedtoRead(const TLS_Ctx *ctx, const RecBuf *inBuf)
{
    (void)ctx;
    uint32_t headLen = REC_TLS_RECORD_HEADER_LEN;
#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        headLen = REC_DTLS_RECORD_HEADER_LEN;
    }
#endif
    uint32_t lengthOffset = headLen - sizeof(uint16_t);
    uint32_t remain = inBuf->end - inBuf->start;
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


static REC_Type RecCastUintToRecType(TLS_Ctx *ctx, uint8_t value)
{
    (void)ctx;
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
        default:
            type = REC_TYPE_UNKNOWN;
            break;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    RecConnState *state = GetReadConnState(ctx);
    if (GET_VERSION_FROM_CTX(ctx) == HITLS_VERSION_TLS13 && state->suiteInfo != NULL) {
        if (type != REC_TYPE_APP && type != REC_TYPE_ALERT &&
            (type != REC_TYPE_CHANGE_CIPHER_SPEC || ctx->hsCtx == NULL)) {
            type = REC_TYPE_UNKNOWN;
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    return type;
}
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
uint32_t REC_GetMaxReadSize(TLS_Ctx *ctx)
{
    uint32_t readSize = REC_MAX_PLAIN_LENGTH;
    if (ctx != NULL && ctx->negotiatedInfo.recordSizeLimit != 0) {
        readSize = ctx->negotiatedInfo.recordSizeLimit;
        if (GET_VERSION_FROM_CTX(ctx) == HITLS_VERSION_TLS13) {
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

static int32_t RecordDecrypt(TLS_Ctx *ctx, RecBuf *decryptBuf, REC_TextInput *encryptedMsg)
{
    if (encryptedMsg->textLen == 0) {
        return EmptyRecordProcess(ctx, encryptedMsg->type);
    } else {
        ctx->recCtx->emptyRecordCnt = 0;
    }

    RecConnState *state = GetReadConnState(ctx);
    const RecCryptoFunc *funcs = RecGetCryptoFuncs(state->suiteInfo);
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
    /* The decrypted record body is in data */
    ret = RecConnDecrypt(ctx, state, encryptedMsg, decryptBuf->buf, &decryptBuf->end);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    if (!IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        ret = funcs->decryptPostProcess(ctx, state->suiteInfo, encryptedMsg, decryptBuf->buf, &decryptBuf->end);
        if (ret != HITLS_SUCCESS) {
            goto ERR;
        }
        RecConnSetSeqNum(state, RecConnGetSeqNum(state) + 1);
    }
    ret = ProcessDecryptedRecord(ctx, decryptBuf->end, encryptedMsg);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    return HITLS_SUCCESS;
ERR:
    if (decryptBuf->isHoldBuffer) {
        BSL_SAL_FREE(decryptBuf->buf);
    }
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
        case REC_TYPE_CHANGE_CIPHER_SPEC:
        case REC_TYPE_ALERT:
        default:
            ret = ctx->method.unexpectedMsgProcessCb(ctx, recordType,
                decryptBuf->buf, decryptBuf->end, false);
            if (decryptBuf->isHoldBuffer) {
                BSL_SAL_FREE(decryptBuf->buf);
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

#ifdef HITLS_TLS_PROTO_DTLS12
int32_t DtlsCheckVersionField(const TLS_Ctx *ctx, uint16_t version, uint8_t type)
{
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

    if (RecCastUintToRecType(ctx, hdr->type) == REC_TYPE_UNKNOWN || hdr->bodyLen == 0) {
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

static int32_t DtlsGetRecordHeader(const uint8_t *msg, uint32_t len, RecHdr *hdr)
{
    if (len < REC_DTLS_RECORD_HEADER_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_DECODE_ERROR);
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID15442, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Record:dtls packet's length err.", 0, 0, 0, 0);
        return HITLS_REC_DECODE_ERROR;
    }

    /* Parse the record header */
    hdr->type = msg[0];
    hdr->version = BSL_ByteToUint16(&msg[1]);
    hdr->bodyLen = BSL_ByteToUint16(
        &msg[REC_DTLS_RECORD_LENGTH_OFFSET]);  // The 11th to 12th bytes of DTLS are the message length.
    hdr->epochSeq = BSL_ByteToUint64(&msg[REC_DTLS_RECORD_EPOCH_OFFSET]);
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
    if (IsNeedtoRead(ctx, recordCtx->inBuf)) {
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

    ret = DtlsGetRecordHeader(msg, len, hdr);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17262, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DtlsGetRecordHeader fail, ret %d", ret, 0, 0, 0);
        RecBufClean(recordCtx->inBuf);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
    }

#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(0, 0, RECORD_HEADER, msg, REC_DTLS_RECORD_HEADER_LEN, ctx,
                              ctx->config.tlsConfig.msgArg);
#endif

    /* Check whether the record length is greater than the buffer size */
    if ((REC_DTLS_RECORD_HEADER_LEN + (uint32_t)hdr->bodyLen) > len) {
        RecBufClean(recordCtx->inBuf);
        BSL_ERR_PUSH_ERROR(HITLS_REC_DECODE_ERROR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15443, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record:dtls packet's length err.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }

    /** Release the read record */
    recordCtx->inBuf->start += REC_DTLS_RECORD_HEADER_LEN + hdr->bodyLen;

    /** Update the read content */
    *recordBody = msg + REC_DTLS_RECORD_HEADER_LEN;

    return HITLS_SUCCESS;
}

static inline void GenerateCryptMsg(const TLS_Ctx *ctx,
    const RecHdr *hdr, const uint8_t *recordBody, REC_TextInput *cryptMsg)
{
    cryptMsg->negotiatedVersion = ctx->negotiatedInfo.version;
#ifdef HITLS_TLS_FEATURE_ETM
    cryptMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMac;
#endif
    cryptMsg->type = hdr->type;
    cryptMsg->version = hdr->version;
    cryptMsg->text = recordBody;
    cryptMsg->textLen = hdr->bodyLen;
    BSL_Uint64ToByte(hdr->epochSeq, cryptMsg->seq);
}

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
/**
 * @brief Check whether there are unprocessed handshake messages in the cache.
 *
 * @param unprocessedHsMsg [IN] Unprocessed handshake message handle
 * @param curEpoch [IN] Current epoch
 *
 * @retval true: cached
 * @retval false No cache
 */
static bool IsExistUnprocessedHsMsg(RecCtx *recCtx)
{
    uint16_t curEpoch = recCtx->readEpoch;
    UnprocessedHsMsg *unprocessedHsMsg = &recCtx->unprocessedHsMsg;

    /* Check whether there are cached handshake messages. */
    if (unprocessedHsMsg->recordBody == NULL) {
        return false;
    }

    uint16_t epoch = REC_EPOCH_GET(unprocessedHsMsg->hdr.epochSeq);
    if (curEpoch == epoch) {
        /* The handshake message of the current epoch needs to be processed */
        return true;
    }

    if (curEpoch > epoch) {
        /* Expired messages need to be cleaned up */
        (void)memset_s(&unprocessedHsMsg->hdr, sizeof(unprocessedHsMsg->hdr), 0, sizeof(unprocessedHsMsg->hdr));
        BSL_SAL_FREE(unprocessedHsMsg->recordBody);
    }

    return false;
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */

static bool IsExistUnprocessedAppMsg(RecCtx *recCtx)
{
    UnprocessedAppMsg *unprocessedAppMsgList = &recCtx->unprocessedAppMsgList;
    /* Check whether there are cached app messages. */
    if (unprocessedAppMsgList->count == 0) {
        return false;
    }

    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    UnprocessedAppMsg *cur = NULL;
    uint16_t curEpoch = recCtx->readEpoch;
    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(unprocessedAppMsgList->head)) {
        cur = LIST_ENTRY(node, UnprocessedAppMsg, head);
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
    if (hdr->type == REC_TYPE_HANDSHAKE) {
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        CacheNextEpochHsMsg(&recordCtx->unprocessedHsMsg, hdr, recordBody);
#endif
    } else {
        int32_t ret = UnprocessedAppMsgListAppend(&recordCtx->unprocessedAppMsgList, hdr, recordBody);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17263, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "recv normal disorder message", 0, 0, 0, 0);
    return HITLS_REC_NORMAL_RECV_DISORDER_MSG;
}

static int32_t DtlsRecordHeaderProcess(TLS_Ctx *ctx, uint8_t *recordBody, RecHdr *hdr)
{
    int32_t ret = HITLS_SUCCESS;
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;

    ret = DtlsCheckRecordHeader(ctx, hdr);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint16_t epoch = REC_EPOCH_GET(hdr->epochSeq);
    if (epoch != recordCtx->readEpoch) {
#ifdef HITLS_BSL_UIO_SCTP
        /* Discard out-of-order messages in SCTP scenarios */
        if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
            return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        }
#endif /* HITLS_BSL_UIO_SCTP */
#if defined(HITLS_BSL_UIO_UDP)
        /* Only the messages of the next epoch are cached */
        if ((recordCtx->readEpoch + 1) == epoch) {
            return RecordBufferUnprocessedMsg(recordCtx, hdr, recordBody);
        }
        /* After receiving the message of the previous epoch, the system discards the message. */
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
#endif
    }

    bool isCcsRecv = ctx->method.isRecvCCS(ctx);
    /* App messages arrive earlier than finished messages and need to be cached */
    if (ctx->hsCtx != NULL && isCcsRecv == true && (hdr->type == REC_TYPE_APP || hdr->type == REC_TYPE_ALERT)) {
        return RecordBufferUnprocessedMsg(recordCtx, hdr, recordBody);
    }

    return HITLS_SUCCESS;
}

static uint8_t *GetUnprocessedMsg(RecCtx *recordCtx, REC_Type recordType, RecHdr *hdr)
{
    uint8_t *recordBody = NULL;
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    if ((recordType == REC_TYPE_HANDSHAKE) && IsExistUnprocessedHsMsg(recordCtx)) {
        (void)memcpy_s(hdr, sizeof(RecHdr), &recordCtx->unprocessedHsMsg.hdr, sizeof(RecHdr));
        recordBody = recordCtx->unprocessedHsMsg.recordBody;
        recordCtx->unprocessedHsMsg.recordBody = NULL;
    }
#endif

    uint16_t curEpoch = recordCtx->readEpoch;
    if ((recordType == REC_TYPE_APP) && IsExistUnprocessedAppMsg(recordCtx)) {
        UnprocessedAppMsg *appMsg = UnprocessedAppMsgGet(&recordCtx->unprocessedAppMsgList, curEpoch);
        if (appMsg == NULL) {
            return NULL;
        }
        (void)memcpy_s(hdr, sizeof(RecHdr), &appMsg->hdr, sizeof(RecHdr));
        recordBody = appMsg->recordBody;
        appMsg->recordBody = NULL;
        UnprocessedAppMsgFree(appMsg);
    }
    return recordBody;
}

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
static int32_t AntiReplay(TLS_Ctx *ctx, RecHdr *hdr)
{
    /* In non-UDP scenarios, anti-replay check is not required */
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        return HITLS_SUCCESS;
    }

    RecConnState *state = GetReadConnState(ctx);
    uint16_t epoch = REC_EPOCH_GET(hdr->epochSeq);
    uint64_t secquence = REC_SEQ_GET(hdr->epochSeq);
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
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    ret = AntiReplay(ctx, hdr);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(*cachRecord);
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
    /* Construct parameters before decryption */
    REC_TextInput cryptMsg = {0};
    GenerateCryptMsg(ctx, &hdr, recordBody, &cryptMsg);
    RecBuf decryptBuf = { .buf = data, .bufSize = bufSize };
    ret = RecordDecrypt(ctx, &decryptBuf, &cryptMsg);
    BSL_SAL_FREE(cachRecord);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#if defined(HITLS_BSL_UIO_UDP)
    /* In UDP scenarios, update the sliding window flag */
    if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        RecAntiReplayUpdate(&GetReadConnState(ctx)->window, REC_SEQ_GET(hdr.epochSeq));
    }
#endif
    ctx->method.clearAlert(ctx, cryptMsg.type);
#ifdef HITLS_TLS_FEATURE_MODE_RELEASE_BUFFERS
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_RELEASE_BUFFERS) != 0 && (recordType == REC_TYPE_APP)) {
        RecTryFreeRecBuf(ctx, false);
    }
#endif
    /* An unexpected packet is received */
    // decryptBuf.isHoldBuffer == false
    if (recordType != cryptMsg.type) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16513, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "expect type %d, receive type %d", recordType, cryptMsg.type, 0, 0);
        return RecordUnexpectedMsg(ctx, &decryptBuf, cryptMsg.type);
    }
    if (decryptBuf.buf == data) {
        /* Update the read length */
        *len = decryptBuf.end;
        return HITLS_SUCCESS;
    }
    ret = DtlsProcessBufList(ctx, recordType, bufList, &decryptBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return RecBufListGetBuffer(bufList, data, bufSize, len, (ctx->peekFlag != 0 && (recordType == REC_TYPE_APP)));
}

#endif /* HITLS_TLS_PROTO_DTLS12 */

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
    if (RecCastUintToRecType(ctx, recordHdr->type) == REC_TYPE_UNKNOWN) {
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
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 && recordHdr->bodyLen > REC_MAX_TLS13_ENCRYPTED_LEN) {
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
    if (IsNeedtoRead(ctx, inBuf)) {
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
    cryptMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMac;
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
    ret = RecordDecrypt(ctx, &decryptBuf, &encryptedMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ctx->method.clearAlert(ctx, encryptedMsg.type);
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
    RecBuf *recBuf = (RecBuf *)BSL_LIST_GET_FIRST(ctx->recCtx->appRecList);
    if (recBuf == NULL) {
        return 0;
    }
    return recBuf->end - recBuf->start;
}