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
#ifdef HITLS_TLS_FEATURE_QUIC_TLS
#include <limits.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_log_internal.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_quic_tls.h"
#include "tls_binlog_id.h"
#include "tls.h"
#include "hs_ctx.h"
#include "quic_tls_internal.h"

/*
 * Per-level upper bound on CRYPTO data buffered by ProvideData at once.
 * (RFC 9001 s4.1.1 antisyn flooding guidance / DoS cap.)
 *
 * HITLS_HS_BUFFER_SIZE_LIMIT bounds one complete TLS handshake message after
 * the handshake message buffer grows. The QUIC input buffer is separate: it
 * may hold several consecutive messages from one flight until TLS consumes
 * them and advances buffer->offset.
 *
 * HANDSHAKE level:
 *  - before the endpoint role is committed, use the larger client bound;
 *  - a client may buffer both CertificateRequest and Certificate, each still
 *    limited to one HITLS_HS_BUFFER_SIZE_LIMIT-sized handshake message;
 *  - a server with client authentication receives one Certificate message.
 */
static uint32_t QuicTlsGetLevelInputLimit(const TLS_Ctx *tlsCtx, HITLS_QUIC_TLS_EncryptionLevel level)
{
    switch (level) {
        case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL:
        case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION:
            return QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT;
        case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE:
            if (tlsCtx->state == CM_STATE_IDLE || tlsCtx->isClient) {
                /*
                 * The factor 2 counts two separate certificate-sized messages in one server flight; it neither
                 * raises the per-message limit nor requires the QUIC stack to call ProvideData twice.
                 */
                uint32_t clientLimit = 2u * HITLS_HS_BUFFER_SIZE_LIMIT;
                return clientLimit > QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT ? clientLimit :
                                                                         QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT;
            }
            if (tlsCtx->config.tlsConfig.isSupportClientVerify &&
                HITLS_HS_BUFFER_SIZE_LIMIT > QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT) {
                return HITLS_HS_BUFFER_SIZE_LIMIT;
            }
            return QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT;
        default:
            return 0u;
    }
}

/*
 * Reserve means preparing enough contiguous capacity for a later append; this function does not copy the new data.
 * The live data occupies [offset, length), and space before offset may be reclaimed by compacting the buffer.
 */
static int32_t QuicTlsBufferReserve(QUIC_TLS_InputBuffer *buffer, uint32_t appendLen, uint32_t bufferSizeLimit)
{
    uint32_t used = buffer->length - buffer->offset;
    if (used > bufferSizeLimit || appendLen > bufferSizeLimit - used) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17416, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "QUIC CRYPTO receive buffer exceeds its %u-byte per-level limit; used=%u, append=%u.",
                              bufferSizeLimit, used, appendLen, 0);
        BSL_ERR_PUSH_ERROR(HITLS_REC_RECORD_OVERFLOW);
        return HITLS_REC_RECORD_OVERFLOW;
    }

    uint32_t required = used + appendLen;
    if (required <= buffer->capacity) {
        if (buffer->offset != 0 && appendLen > buffer->capacity - buffer->length) {
            /* Move unconsumed data to the front; memmove is required because the source and destination may overlap. */
            memmove(buffer->data, buffer->data + buffer->offset, used);
            buffer->offset = 0;
            buffer->length = used;
        }
        return HITLS_SUCCESS;
    }

    /* Grow geometrically when the live data and append cannot fit, stopping at the per-level hard limit. */
    uint32_t capacity = buffer->capacity == 0 ? 4096u : buffer->capacity;
    while (capacity < required) {
        if (capacity >= bufferSizeLimit / 2u) {
            capacity = bufferSizeLimit;
            break;
        }
        capacity *= 2u;
    }
    uint8_t *newData = BSL_SAL_Realloc(buffer->data, capacity, buffer->capacity);
    if (newData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    buffer->data = newData;
    /* Move the live window to the beginning so the appended bytes can start at the new length. */
    if (buffer->offset != 0 && used != 0) {
        memmove(buffer->data, buffer->data + buffer->offset, used);
    }
    buffer->capacity = capacity;
    buffer->offset = 0;
    buffer->length = used;
    return HITLS_SUCCESS;
}

static int32_t QuicTlsBufferAppend(QUIC_TLS_Ctx *quicTlsCtx, HITLS_QUIC_TLS_EncryptionLevel level,
                                   uint32_t bufferSizeLimit, const uint8_t *data, size_t dataLen)
{
    if (dataLen > UINT32_MAX) {
        return HITLS_REC_RECORD_OVERFLOW;
    }
    if (dataLen == 0) {
        return HITLS_SUCCESS;
    }
    QUIC_TLS_InputBuffer *buffer = &quicTlsCtx->input[level];
    int32_t ret = QuicTlsBufferReserve(buffer, (uint32_t)dataLen, bufferSizeLimit);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    memcpy(buffer->data + buffer->length, data, dataLen);
    buffer->length += (uint32_t)dataLen;
    return HITLS_SUCCESS;
}

static bool QuicTlsMethodIsComplete(const QUIC_TLS_Callbacks *cbs)
{
    return cbs->setReadSecret != NULL && cbs->setWriteSecret != NULL && cbs->addHandshakeData != NULL &&
           cbs->flushFlight != NULL && cbs->sendAlert != NULL;
}

static int32_t QuicTlsMethodParse(const HITLS_QUIC_TLS_Callbacks *callbacks, QUIC_TLS_Callbacks *cbs)
{
    for (const HITLS_QUIC_TLS_Callbacks *d = callbacks; d->id != 0; d++) {
        switch (d->id) {
            case HITLS_QUIC_TLS_FUNC_SET_READ_SECRET:
                cbs->setReadSecret = (HITLS_QUIC_TLS_SetReadSecretFunc)d->func;
                break;
            case HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET:
                cbs->setWriteSecret = (HITLS_QUIC_TLS_SetWriteSecretFunc)d->func;
                break;
            case HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA:
                cbs->addHandshakeData = (HITLS_QUIC_TLS_AddHandshakeDataFunc)d->func;
                break;
            case HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT:
                cbs->flushFlight = (HITLS_QUIC_TLS_FlushFlightFunc)d->func;
                break;
            case HITLS_QUIC_TLS_FUNC_SEND_ALERT:
                cbs->sendAlert = (HITLS_QUIC_TLS_SendAlertFunc)d->func;
                break;
            default:
                break;
        }
    }
    if (!QuicTlsMethodIsComplete(cbs)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17413, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "SetMethod requires registering all QUIC callbacks.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }
    return HITLS_SUCCESS;
}

// it can only be tls, not dtls
static bool QuicTlsConfigIsTls(const HITLS_Config *config)
{
    return (config->originVersionMask & TLS_VERSION_MASK) != 0 && !IS_SUPPORT_DATAGRAM(config->originVersionMask);
}

int32_t HITLS_QUIC_TLS_SetQuicTlsMethod(HITLS_Ctx *ctx, const HITLS_QUIC_TLS_Callbacks *callbacks, void *arg)
{
    TLS_Ctx *tlsCtx = (TLS_Ctx *)ctx;
    QUIC_TLS_Callbacks cbs = {0};
    if (ctx == NULL || callbacks == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (tlsCtx->state != CM_STATE_IDLE || !QuicTlsConfigIsTls(&tlsCtx->config.tlsConfig)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17419, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "HITLS_QUIC_TLS_SetQuicTlsMethod: failed, invalid tlsctx state or tls version.", 0, 0, 0,
                              0);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    int32_t ret = QuicTlsMethodParse(callbacks, &cbs);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    QUIC_TLS_Ctx *quicTlsCtx = tlsCtx->quicTlsCtx;
    if (quicTlsCtx == NULL) {
        quicTlsCtx = QUIC_TLS_CtxNew();
        if (quicTlsCtx == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        tlsCtx->quicTlsCtx = quicTlsCtx;
    }
#ifdef HITLS_TLS_FEATURE_PHA
    /* RFC 9001 Section 4.4 forbids post-handshake client authentication. */
    tlsCtx->config.tlsConfig.isSupportPostHandshakeAuth = false;
    tlsCtx->phaState = PHA_NONE;
#endif
#ifdef HITLS_TLS_FEATURE_FLIGHT
    /*
     * FLIGHT is force-enabled whenever QUIC-TLS is enabled (see hitls_define_dependencies.cmake),
     * but its buffered-UIO transmit path must stay off for a QUIC connection: QUIC owns
     * CRYPTO-stream buffering and sends TLS handshake bytes through the registered callbacks.
     * Keeping this runtime switch false makes the isFlightTransmitEnable call sites
     * (UIO init/deinit, record buffering) no-ops for QUIC, while REC_FlightTransmit still
     * dispatches QUIC to flushFlight. The switch stays off for the connection lifetime,
     * including reuse after HITLS_Clear.
     */
    tlsCtx->config.tlsConfig.isFlightTransmitEnable = false;
#endif
    quicTlsCtx->cbs = cbs;
    quicTlsCtx->callbackArg = arg;
    return HITLS_SUCCESS;
}

/* Append a copy of the provided CRYPTO-stream data to quicTlsCtx->input[level] for consumption by TLS. */
int32_t HITLS_QUIC_TLS_ProvideData(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level, const uint8_t *data,
                                   size_t dataLen)
{
    TLS_Ctx *tlsCtx = (TLS_Ctx *)ctx;
    if (ctx == NULL || (data == NULL && dataLen != 0)) {
        return HITLS_NULL_INPUT;
    }
    if (!QUIC_TLS_IsMode(tlsCtx)) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    if (level != tlsCtx->quicTlsCtx->readLevel) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17414, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "ProvideData level %u does not match expected read level %u.", level,
                              tlsCtx->quicTlsCtx->readLevel, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    uint32_t limit = QuicTlsGetLevelInputLimit(tlsCtx, level);
    return QuicTlsBufferAppend(tlsCtx->quicTlsCtx, level, limit, data, dataLen);
}

int32_t HITLS_QUIC_TLS_SetTransportParams(HITLS_Ctx *ctx, const uint8_t *params, size_t paramsLen)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_NULL_INPUT;
    }
    /* An empty local value is not a valid QUIC transport-parameters
     * configuration. Peer extensions remain opaque and may be empty. */
    if (paramsLen == 0) {
        return HITLS_INVALID_INPUT;
    }

    TLS_Ctx *tlsCtx = (TLS_Ctx *)ctx;
    bool initialHandshake =
        tlsCtx->state == CM_STATE_HANDSHAKING && tlsCtx->preState != CM_STATE_TRANSPORTING;
    if (!QUIC_TLS_IsMode(tlsCtx) || (tlsCtx->state != CM_STATE_IDLE && !initialHandshake) ||
        (tlsCtx->hsCtx != NULL && tlsCtx->hsCtx->extFlag.haveQuicTlsTransportParams)) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    if (paramsLen > UINT16_MAX) {
        return HITLS_INVALID_INPUT;
    }
    /* RFC 9001 Section 8.2: the transport parameters are carried as the
     * extension_data of the quic_transport_parameters(0x0039) extension in
     * the ClientHello and EncryptedExtensions messages. An RFC 8446
     * extension encodes its data length in a uint16 field, so the value can
     * be at most 65535 bytes; anything larger cannot be encoded and is
     * rejected here. */
    uint8_t *copy = BSL_SAL_Malloc((uint32_t)paramsLen);
    if (copy == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    memcpy(copy, params, paramsLen);
    QUIC_TLS_Ctx *quicTlsCtx = tlsCtx->quicTlsCtx;
    BSL_SAL_FREE(quicTlsCtx->localTransportParams);
    quicTlsCtx->localTransportParams = copy;
    quicTlsCtx->localTransportParamsLen = (uint32_t)paramsLen;
    return HITLS_SUCCESS;
}

int32_t HITLS_QUIC_TLS_GetPeerTransportParams(const HITLS_Ctx *ctx, const uint8_t **params, size_t *paramsLen)
{
    const TLS_Ctx *tlsCtx = (const TLS_Ctx *)ctx;
    if (ctx == NULL || params == NULL || paramsLen == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (!QUIC_TLS_IsMode(tlsCtx)) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    *params = tlsCtx->quicTlsCtx->peerTransportParams;
    *paramsLen = tlsCtx->quicTlsCtx->peerTransportParamsLen;
    return HITLS_SUCCESS;
}

HITLS_QUIC_TLS_EncryptionLevel HITLS_QUIC_TLS_GetReadLevel(const HITLS_Ctx *ctx)
{
    const TLS_Ctx *tlsCtx = (const TLS_Ctx *)ctx;
    if (!QUIC_TLS_IsMode(tlsCtx)) {
        return HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL;
    }
    return tlsCtx->quicTlsCtx->readLevel;
}

HITLS_QUIC_TLS_EncryptionLevel HITLS_QUIC_TLS_GetWriteLevel(const HITLS_Ctx *ctx)
{
    const TLS_Ctx *tlsCtx = (const TLS_Ctx *)ctx;
    if (!QUIC_TLS_IsMode(tlsCtx)) {
        return HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL;
    }
    return tlsCtx->quicTlsCtx->writeLevel;
}

size_t HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(const HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level)
{
    const TLS_Ctx *tlsCtx = (const TLS_Ctx *)ctx;
    if (tlsCtx == NULL) {
        return 0;
    }
    return QuicTlsGetLevelInputLimit(tlsCtx, level);
}
#endif /* HITLS_TLS_FEATURE_QUIC_TLS */
