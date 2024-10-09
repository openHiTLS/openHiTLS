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
#include "rec_alert.h"
#include "record.h"
#include "indicator.h"
#include "hs_ctx.h"
#include "hs.h"

RecConnState *TlsGetReadConnState(const TLS_Ctx *ctx)
{
    /** Obtains the record structure. */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->readStates.currentState;
}

static REC_Type RecCastUintToRecType(TLS_Ctx *ctx, uint8_t value)
{
    REC_Type type;
    RecConnState *state = TlsGetReadConnState(ctx);
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
    if (HS_GetVersion(ctx) == HITLS_VERSION_TLS13 && state->suiteInfo != NULL) {
        if (type != REC_TYPE_APP && type != REC_TYPE_ALERT &&
            (type != REC_TYPE_CHANGE_CIPHER_SPEC || (ctx->hsCtx != NULL && ctx->hsCtx->haveHrr))) {
            type = REC_TYPE_UNKNOWN;
        }
    }

    return type;
}

#ifndef HITLS_NO_DTLS12
int32_t DtlsCheckVersionField(const TLS_Ctx *ctx, uint16_t version, uint8_t type)
{
    /* Tolerate alerts with non-negotiated version. For example, after the server sends server hello, the client
     * replies with an earlier version alert */
    if (ctx->negotiatedInfo.version == 0u || type == (uint8_t)REC_TYPE_ALERT) {
        if ((version != HITLS_VERSION_DTLS10) && (version != HITLS_VERSION_DTLS12)) {
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
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
    }

    if (RecCastUintToRecType(ctx, hdr->type) == REC_TYPE_UNKNOWN || hdr->bodyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15438, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid type or body length(0)", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

    if (hdr->bodyLen > REC_MAX_CIPHER_TEXT_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_TOO_BIG_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15439, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }

    uint16_t epoch = REC_EPOCH_GET(hdr->epochSeq);
    if (epoch == 0 && hdr->type == REC_TYPE_APP) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15440, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a UNEXPECTE record msg: epoch 0's app msg.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

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
    ctx->rwstate = HITLS_READING;
    int32_t ret = BSL_UIO_Read(ctx->rUio, &(inBuf->buf[0]), inBuf->bufSize, &recvLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15441, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record read: uio err.%d", ret, 0, 0, 0);
        return HITLS_REC_ERR_IO_EXCEPTION;
    }
    ctx->rwstate = HITLS_NOTHING;
    if (recvLen == 0) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }

    inBuf->start = 0;
    inBuf->end = recvLen; // successfully read
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
    /** Obtain the record structure information */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;

    /** Read the datagram message: The message may contain multiple records */
    int32_t ret = ReadDatagram(ctx, recordCtx->inBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t *msg = &recordCtx->inBuf->buf[recordCtx->inBuf->start];
    uint32_t len = recordCtx->inBuf->end - recordCtx->inBuf->start;

    ret = DtlsGetRecordHeader(msg, len, hdr);
    if (ret != HITLS_SUCCESS) {
        RecBufClean(recordCtx->inBuf);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
    }

    INDICATOR_MessageIndicate(0, 0, RECORD_HEADER, msg, REC_DTLS_RECORD_HEADER_LEN, ctx,
                              ctx->config.tlsConfig.msgArg);

    /* Check whether the record length is greater than the buffer size */
    if ((REC_DTLS_RECORD_HEADER_LEN + (uint32_t)hdr->bodyLen) > len) {
        RecBufClean(recordCtx->inBuf);
        BSL_ERR_PUSH_ERROR(HITLS_REC_DECODE_ERROR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15443, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record:dtls packet's length err.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
    }

    /** Release the read record */
    recordCtx->inBuf->start += REC_DTLS_RECORD_HEADER_LEN + hdr->bodyLen;

    /** Update the read content */
    *recordBody = msg + REC_DTLS_RECORD_HEADER_LEN;

    return HITLS_SUCCESS;
}

static inline void DtlsGenerateCryptMsg(TLS_Ctx *ctx, RecHdr *hdr, const uint8_t *recordBody, REC_TextInput *cryptMsg)
{
    cryptMsg->negotiatedVersion = ctx->negotiatedInfo.version;
    cryptMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMac;
    cryptMsg->type = hdr->type;
    cryptMsg->version = hdr->version;
    cryptMsg->text = recordBody;
    cryptMsg->textLen = hdr->bodyLen;
    BSL_Uint64ToByte(hdr->epochSeq, cryptMsg->seq);
}

RecConnState *DtlsGetReadConnState(const TLS_Ctx *ctx)
{
    /** Obtain the record structure */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    return recordCtx->readStates.currentState;
}

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

static bool IsExistUnprocessedAppMsg(RecCtx *recCtx)
{
    UnprocessedAppMsg *unprocessedAppMsgList = &recCtx->unprocessedAppMsgList;
    if (unprocessedAppMsgList->count != 0) {
        return true;
    }
    return false;
}

static int32_t RecordBufferUnprocessedMsg(RecCtx *recordCtx, RecHdr *hdr, uint8_t *recordBody)
{
    if (hdr->type == REC_TYPE_HANDSHAKE) {
        CacheNextEpochHsMsg(&recordCtx->unprocessedHsMsg, hdr, recordBody);
    } else {
        int32_t ret = UnprocessedAppMsgListAppend(&recordCtx->unprocessedAppMsgList, hdr, recordBody);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_REC_NORMAL_RECV_DISORDER_MSG;
}

static int32_t DtlsRecordHeaderProcess(TLS_Ctx *ctx, uint8_t *recordBody, RecHdr *hdr)
{
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    int32_t transportType = BSL_UIO_GetTransportType(ctx->uio);

    int32_t ret = DtlsCheckRecordHeader(ctx, hdr);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint16_t epoch = REC_EPOCH_GET(hdr->epochSeq);
    if (epoch != recordCtx->readEpoch) {
        /* Discard out-of-order messages in SCTP scenarios */
        if (transportType == BSL_UIO_SCTP) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15444, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
                "sctp record disorder: expect epoch = %u, get epoch = %u, drop this record.",
                recordCtx->readEpoch, epoch, 0, 0);
            return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        }
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
    if ((recordType == REC_TYPE_HANDSHAKE) && IsExistUnprocessedHsMsg(recordCtx)) {
        (void)memcpy_s(hdr, sizeof(RecHdr), &recordCtx->unprocessedHsMsg.hdr, sizeof(RecHdr));
        recordBody = recordCtx->unprocessedHsMsg.recordBody;
        recordCtx->unprocessedHsMsg.recordBody = NULL;
    }

    if ((recordType == REC_TYPE_APP) && IsExistUnprocessedAppMsg(recordCtx)) {
        UnprocessedAppMsg *appMsg = UnprocessedAppMsgGet(&recordCtx->unprocessedAppMsgList);
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

static int32_t RecInBufInit(RecCtx *recordCtx, uint32_t bufSize)
{
    if (recordCtx->inBuf == NULL) {
        recordCtx->inBuf = RecBufNew(bufSize);
        if (recordCtx->inBuf == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t DtlsTryReadAndCheckRecordMessage(TLS_Ctx *ctx, uint8_t **recordBody, RecHdr *hdr)
{
    /* Read the new record message */
    int32_t ret = TryReadOneDtlsRecord(ctx, recordBody, hdr);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check the record message header. If the message header is not the expected message, cache the message */
    ret = DtlsRecordHeaderProcess(ctx, *recordBody, hdr);
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
    RecHdr hdr = {0};
    uint8_t *recordBody = NULL;
    uint8_t *cachRecord = NULL; /* Pointer for storing buffered messages, which is used during release */
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    int32_t ret = RecInBufInit(recordCtx, RecGetInitBufferSize(ctx));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check if there are cached messages that need to be processed */
    recordBody = GetUnprocessedMsg(recordCtx, recordType, &hdr);
    cachRecord = recordBody;
    /* There are no cached messages to process */
    if (recordBody == NULL) {
        ret = DtlsTryReadAndCheckRecordMessage(ctx, &recordBody, &hdr);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    /* Construct parameters before decryption */
    REC_TextInput cryptMsg = {0};
    DtlsGenerateCryptMsg(ctx, &hdr, recordBody, &cryptMsg);

    /* Decryption */
    uint32_t dataLen = bufSize;
    RecConnState *state = DtlsGetReadConnState(ctx);
    ret = RecConnDecrypt(ctx, state, &cryptMsg, data, &dataLen);
    BSL_SAL_FREE(cachRecord);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (hdr.type != REC_TYPE_APP && dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15435, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

    /* An unexpected packet is received */
    if (recordType != hdr.type) {
        return ctx->method.unexpectedMsgProcessCb(ctx, hdr.type, data, dataLen);
    }

    /* Update the read length */
    *len = dataLen;

    return HITLS_SUCCESS;
}

#endif

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
#ifndef HITLS_NO_TLCP11
        if (((version >> 8u) != HITLS_VERSION_TLS_MAJOR) && (version != HITLS_VERSION_TLCP11)) {
#else
        if ((version >> 8u) != HITLS_VERSION_TLS_MAJOR) {
#endif
            BSL_ERR_PUSH_ERROR(HITLS_REC_INVALID_PROTOCOL_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15867, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get a record with illegal version(0x%x).", version, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
            return HITLS_REC_INVALID_PROTOCOL_VERSION;
        }
    } else {
        return VersionProcess(ctx, version, type);
    }
    return HITLS_SUCCESS;
}

static int32_t TlsCheckRecordHeader(TLS_Ctx *ctx, const RecHdr *recordHdr)
{
    if (RecCastUintToRecType(ctx, recordHdr->type) == REC_TYPE_UNKNOWN) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15450, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid type", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

    int32_t ret = TlsCheckVersionField(ctx, recordHdr->version, recordHdr->type);
    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_REC_INVALID_PROTOCOL_VERSION;
    }

    if (recordHdr->bodyLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15347, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid type", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    if (recordHdr->bodyLen > REC_MAX_CIPHER_TEXT_LEN) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15451, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }

    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 && recordHdr->bodyLen > REC_MAX_TLS13_ENCRYPTED_LEN) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15896, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }

    return HITLS_SUCCESS;
}

/**
 * @brief   Read data from the uio of the TLS context into inBuf
 *
 * @param   ctx [IN] TLS context
 * @param   inBuf [IN] inBuf Read buffer.
 * @param   len [IN] len The length to be read, the main call usually takes the value of the record header length (5
 * bytes) and the entire record length (header+body)
 *
 * @retval  HITLS_SUCCESS Read successfully
 * @retval  HITLS_REC_ERR_IO_EXCEPTION IO error
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY No cached data needs to be re-read
 * @retval  HITLS_REC_NORMAL_IO_EOF
 */
int32_t StreamRead(TLS_Ctx *ctx, RecBuf *inBuf, uint32_t len)
{
    if (inBuf->end == inBuf->start) {
        inBuf->start = 0;
        inBuf->end = 0;
    }

    // there are enough data in the read buffer
    if (inBuf->end >= inBuf->start + len) {
        return HITLS_SUCCESS;
    }
    // right-side available space is less then required len, move data leftwards
    uint32_t leftSize = inBuf->bufSize - inBuf->end;
    uint32_t dataSize = inBuf->end - inBuf->start;
    if (leftSize < len) {
        for (uint32_t i = 0; i < dataSize; i++) {
            inBuf->buf[i] = inBuf->buf[inBuf->start + i];
        }

        inBuf->start = 0;
        inBuf->end = dataSize;
    }

    do {
        uint32_t recvLen = 0u;
        ctx->rwstate = HITLS_READING;
        int32_t ret = BSL_UIO_Read(ctx->rUio, &(inBuf->buf[inBuf->end]), inBuf->bufSize - inBuf->end, &recvLen);
        if (ret != BSL_SUCCESS) {
            if (ret == BSL_UIO_IO_EOF) {
                return HITLS_REC_NORMAL_IO_EOF;
            }
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15452, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Fail to call BSL_UIO_Read in StreamRead: [%d]", ret, 0, 0, 0);
            return HITLS_REC_ERR_IO_EXCEPTION;
        }

        ctx->rwstate = HITLS_NOTHING;
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
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_REC_NORMAL_RECV_BUF_EMPTY needs to be read again
 * @retval HITLS_REC_ERR_IO_EXCEPTION I/O error
 */
static int32_t TryReadOneTlsRecord(TLS_Ctx *ctx, uint8_t **recordBody, RecHdr *hdr)
{
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;

    RecBuf *inBuf = recordCtx->inBuf;

    // read record header
    int32_t ret = StreamRead(ctx, inBuf, REC_TLS_RECORD_HEADER_LEN);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    const uint8_t *recordHeader = &inBuf->buf[inBuf->start];
    hdr->type = recordHeader[0];
    hdr->version = BSL_ByteToUint16(recordHeader + sizeof(uint8_t));
    hdr->bodyLen = BSL_ByteToUint16(recordHeader + REC_TLS_RECORD_LENGTH_OFFSET);

    ret = TlsCheckRecordHeader(ctx, hdr);
    if (ret != HITLS_SUCCESS) {
        INDICATOR_MessageIndicate(0, 0, RECORD_HEADER, recordHeader, REC_TLS_RECORD_HEADER_LEN, ctx,
                                  ctx->config.tlsConfig.msgArg);
        return ret;
    }

    INDICATOR_MessageIndicate(0, hdr->version, RECORD_HEADER, recordHeader, REC_TLS_RECORD_HEADER_LEN, ctx,
                              ctx->config.tlsConfig.msgArg);

    // read a whole record: head + body
    ret = StreamRead(ctx, inBuf, REC_TLS_RECORD_HEADER_LEN + (uint32_t)hdr->bodyLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    *recordBody = &inBuf->buf[inBuf->start] + REC_TLS_RECORD_HEADER_LEN;

    inBuf->start += REC_TLS_RECORD_HEADER_LEN + (uint32_t)hdr->bodyLen;
    return HITLS_SUCCESS;
}

/**
 * @brief   Obtain the content and record message types from the decrypted TLSInnerPlaintext.
 *          After TLS1.3 decryption, the TLSInnerPlaintext structure is used. The padding needs to be
            removed and the actual message type needs to be obtained.
 *
 *    struct {
 *            opaque content[TLSPlaintext.length];
 *            ContentType type;
 *            uint8 zeros[length_of_padding];
 *        } TLSInnerPlaintext;
 *
 * @param   text [IN] Decrypted content (TLSInnerPlaintext)
 * @param   textLen [OUT] Input (length of TLSInnerPlaintext)
 *                        Length of the output content
 * @param   recType [OUT] Message body length
 *
 * @return  HITLS_SUCCESS succeeded
 *          HITLS_ALERT_FATAL Unexpected Message
 */
int32_t RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType)
{
    /* The receiver decrypts and scans the field from the end to the beginning until it finds a non-zero octet. This
     * non-zero byte is the message type of record If no non-zero bytes are found, an unexpected alert needs to be sent
     * and the chain is terminated
     */
    uint32_t len = *textLen;
    for (uint32_t i = len; i > 0; i--) {
        if (text[i - 1] != 0) {
            *recType = text[i - 1];
            // When the value is the same as the rectype index, the value is the length of the content
            *textLen = i - 1;
            return HITLS_SUCCESS;
        }
    }

    BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15453, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Recved  UNEXPECTED_MESSAGE.", 0, 0, 0, 0);
    return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
}

int32_t RecordDecryptPrepare(TLS_Ctx *ctx, uint16_t version, uint64_t seq, REC_TextInput *cryptMsg)
{
    if (seq >= REC_TLS_SN_MAX_VALUE) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_SN_WRAPPING);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15454, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record read: sequence number wrap.", 0, 0, 0, 0);
        return HITLS_REC_ERR_SN_WRAPPING;
    }

    RecHdr hdr = { 0 };
    uint8_t *recordBody = NULL;
    // read header and body from ctx
    int32_t ret = TryReadOneTlsRecord(ctx, &recordBody, &hdr);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (version == HITLS_VERSION_TLS13 && (hdr.type == REC_TYPE_CHANGE_CIPHER_SPEC || hdr.type == REC_TYPE_ALERT)) {
        /* In the TLS1.3 scenario, process unencrypted CCS and Alert messages received */
        return ctx->method.unexpectedMsgProcessCb(ctx, hdr.type, recordBody, (uint32_t)hdr.bodyLen);
    }

    cryptMsg->negotiatedVersion = ctx->negotiatedInfo.version;
    cryptMsg->isEncryptThenMac = ctx->negotiatedInfo.isEncryptThenMac;
    cryptMsg->type = hdr.type;
    cryptMsg->version = hdr.version;
    cryptMsg->text = recordBody;
    cryptMsg->textLen = hdr.bodyLen;
    BSL_Uint64ToByte(seq, cryptMsg->seq);
    return HITLS_SUCCESS;
}

/**
 * @brief   Read a record in the TLS protocol.
 * @attention: Handle record and handle transporting state to receive unexpected record type messages
 * @param ctx [IN] TLS context
 * @param recordType [IN] Record type
 * @param data [OUT] Read data
 * @param readLen [OUT] Length of the read data
 * @param   num [IN] The read buffer has num bytes
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_REC_NORMAL_RECV_BUF_EMPTY Need to re-read
 * @retval HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval HITLS_REC_ERR_SN_WRAPPING Rewind the sequence number.
 * @retval HITLS_REC_NORMAL_RECV_UNEXPECT_MSG Unexpected message received
 *
 */
int32_t TlsRecordRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    int32_t ret;
    RecConnState *state = TlsGetReadConnState(ctx);
    uint16_t version = ctx->negotiatedInfo.version;
    uint64_t seq = RecConnGetSeqNum(state);
    REC_TextInput encryptedMsg = {0};
    bool isEncThenMac = ctx->config.tlsConfig.isEncryptThenMac;
    ret = RecordDecryptPrepare(ctx, version, seq, &encryptedMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t dataLen = num;

    ret = RecConnDecrypt(ctx, state, &encryptedMsg, data, &dataLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* If the version is tls1.3 and encryption is required, you need to create a TLSInnerPlaintext message */
    if (version == HITLS_VERSION_TLS13 &&
        RecConnCalcCiphertextLen(state, 0, isEncThenMac) > 0) {
        /* tls1.3 You need to exclude the filled 0 to get the true record type */
        ret = RecParseInnerPlaintext(ctx, data, &dataLen, &encryptedMsg.type);
        INDICATOR_MessageIndicate(0, version, RECORD_INNER_CONTENT_TYPE, &encryptedMsg.type, 1, ctx,
                                  ctx->config.tlsConfig.msgArg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    /* Add a record sequence number */
    RecConnSetSeqNum(state, seq + 1);

    /* The TLSPlaintext.length MUST NOT exceed 2^14. An endpoint that receives a record that exceeds
    this length MUST terminate the connection with a record_overflow alert */
    if (dataLen > REC_MAX_PLAIN_LENGTH) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15802, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLSPlaintext.length exceeds 2^14", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }

    if (encryptedMsg.type != REC_TYPE_APP && dataLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15803, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    }

    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13 &&
        ctx->method.isRecvCCS(ctx) &&
        encryptedMsg.type != REC_TYPE_HANDSHAKE) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_ERR_DATA_BETWEEN_CCS_AND_FINISHED;
    }

    /* An unexpected message is received */
    if (recordType != encryptedMsg.type) {
        return ctx->method.unexpectedMsgProcessCb(ctx, encryptedMsg.type, data, dataLen);
    }

    /* Update the read length */
    *readLen = dataLen;
    return HITLS_SUCCESS;
}

int32_t REC_TlsReadNbytes(TLS_Ctx *ctx, REC_Type recordType, uint8_t *buf, uint32_t num)
{
    int32_t ret = 0;
    uint32_t readbytes = 0;
    RecCtx *recCtx = ctx->recCtx;
    RecBuf *recCtxBuf = recCtx->inBuf;
    uint32_t wantLen = num;
    uint8_t *readBuf = (uint8_t *)BSL_SAL_Calloc(1, REC_MAX_CIPHER_TEXT_LEN);
    if (readBuf == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    do {
        uint32_t offset = num - wantLen;
        if (!recCtx->hasReadBufDecrypted) {
            recCtxBuf->singleRecStart = 0;
            ret = REC_Read(ctx, recordType, readBuf, &readbytes, REC_MAX_CIPHER_TEXT_LEN);
            if (ret != HITLS_SUCCESS) {
                BSL_SAL_FREE(readBuf);
                return ret;
            }
            recCtx->hasReadBufDecrypted = true;
            (void)memcpy_s(recCtxBuf->buf, REC_MAX_CIPHER_TEXT_LEN, readBuf, readbytes);
            recCtxBuf->singleRecEnd = recCtxBuf->singleRecStart + readbytes;

            if (readbytes >= wantLen) {
                (void)memcpy_s(buf + offset, wantLen, recCtxBuf->buf + recCtxBuf->singleRecStart, wantLen);
                recCtxBuf->singleRecStart += wantLen;
                wantLen = 0;
            } else {
                (void)memcpy_s(buf + offset, wantLen, recCtxBuf->buf + recCtxBuf->singleRecStart, readbytes);
                recCtx->hasReadBufDecrypted = false;
                wantLen -= readbytes;
            }
        } else {
            uint32_t availableBytes = recCtxBuf->singleRecEnd - recCtxBuf->singleRecStart;
            if (availableBytes >= wantLen) {
                (void)memcpy_s(buf + offset, wantLen, recCtxBuf->buf + recCtxBuf->singleRecStart, wantLen);
                recCtxBuf->singleRecStart += wantLen;
                wantLen = 0;
            } else {
                (void)memcpy_s(buf + offset, wantLen, recCtxBuf->buf + recCtxBuf->singleRecStart,
                    availableBytes);
                wantLen -= availableBytes;
                recCtx->hasReadBufDecrypted = false;
                (void)memset_s(readBuf, REC_MAX_CIPHER_TEXT_LEN, 0, REC_MAX_CIPHER_TEXT_LEN);
            }
        }
    } while (wantLen > 0);
    BSL_SAL_FREE(readBuf);
    return HITLS_SUCCESS;
}