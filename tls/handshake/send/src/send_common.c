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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "rec.h"
#include "record.h"
#include "transcript_hash.h"
#include "hs_ctx.h"
#include "hs.h"
#include "hs_msg.h"
#include "hs_dtls_timer.h"
#include "send_process.h"
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
#include "hs_kx.h"
#endif
#ifdef HITLS_TLS_FEATURE_DTLS_CID
#include "dtls_cid.h"
#endif
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif /* HITLS_TLS_FEATURE_INDICATOR */

#ifdef HITLS_TLS_PROTO_TLS
static int32_t TlsSendHandShakeMsg(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    int32_t ret = REC_RecOutBufReSet(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t maxRecPayloadLen = 0;
    ret = REC_GetMaxWriteSize(ctx, &maxRecPayloadLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17125, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetMaxWriteSize fail", 0, 0, 0, 0);
        return ret;
    }
    do {
        uint32_t singleWrite = hsCtx->msgLen - hsCtx->msgOffset;
        singleWrite = (singleWrite > maxRecPayloadLen) ? maxRecPayloadLen : singleWrite;
        ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, &hsCtx->msgBuf[hsCtx->msgOffset], singleWrite);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        hsCtx->msgOffset += singleWrite;
    } while (hsCtx->msgOffset != hsCtx->msgLen);
    hsCtx->msgOffset = 0;

    /* Add hash data */
    ret = VERIFY_Append(hsCtx->verifyCtx, hsCtx->msgBuf, hsCtx->msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15795, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify append fail when send handshake msg.", 0, 0, 0, 0);
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(1, GET_VERSION_FROM_CTX(ctx), REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen,
                              ctx, ctx->config.tlsConfig.msgArg);
    INDICATOR_StatusIndicate(ctx, ctx->isClient ? INDICATE_EVENT_STATE_CONNECT_LOOP : INDICATE_EVENT_STATE_ACCEPT_LOOP,
        INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */

    hsCtx->msgLen = 0;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS */
#if defined(HITLS_TLS_PROTO_DATAGRAM)
int32_t HS_DtlsSendFragmentHsMsg(TLS_Ctx *ctx, uint32_t maxRecPayloadLen, const uint8_t *msgData)
{
    int32_t ret = HITLS_SUCCESS;
    uint8_t *data = (uint8_t *)BSL_SAL_Calloc(1u, maxRecPayloadLen);
    if (data == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17126, "Calloc fail");
    }

    /* Copy the fragment header */
    if (DTLS_HS_MSG_HEADER_SIZE > maxRecPayloadLen) {
        BSL_SAL_FREE(data);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMCPY_FAIL, BINLOG_ID15796, "memcpy fail");
    }
    memcpy(data, msgData, DTLS_HS_MSG_HEADER_SIZE);

    uint32_t fragmentOffset = 0;
    uint32_t fragmentLen = 0;
    /* Obtain the length of the handshake msg body */
    uint32_t packetLen = BSL_ByteToUint24(&msgData[DTLS_HS_MSGLEN_ADDR]);

    while (packetLen > 0) {
        /* Calculate the fragment length */
        fragmentLen = packetLen;
        if (packetLen > (maxRecPayloadLen - DTLS_HS_MSG_HEADER_SIZE)) {
            fragmentLen = maxRecPayloadLen - DTLS_HS_MSG_HEADER_SIZE;
        }

        BSL_Uint24ToByte(fragmentOffset, &data[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
        BSL_Uint24ToByte(fragmentLen, &data[DTLS_HS_FRAGMENT_LEN_ADDR]);
        /* Write fragmented data */
        if (fragmentLen > maxRecPayloadLen - DTLS_HS_MSG_HEADER_SIZE) {
            BSL_SAL_ClearFree(data, maxRecPayloadLen);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMCPY_FAIL, BINLOG_ID17127, "memcpy fail");
        }
        memcpy(&data[DTLS_HS_MSG_HEADER_SIZE], &msgData[DTLS_HS_MSG_HEADER_SIZE + fragmentOffset], fragmentLen);

        /* Send to the record layer */
        ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, data, fragmentLen + DTLS_HS_MSG_HEADER_SIZE);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_ClearFree(data, maxRecPayloadLen);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17128, "Write fail");
        }

        fragmentOffset += fragmentLen;
        packetLen -= fragmentLen;
    }

    BSL_SAL_ClearFree(data, maxRecPayloadLen);
    return ret;
}

#ifdef HITLS_TLS_PROTO_DTLS12
static int32_t SendHsMsgWithPayload(TLS_Ctx *ctx, uint32_t maxRecPayloadLen, HS_Ctx *hsCtx)
{
    int32_t ret = HITLS_SUCCESS;
    /* No sharding required */
    if (maxRecPayloadLen >= hsCtx->msgLen) {
        /* Send to the record layer */
        ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15797, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "send handshake msg to record fail.", 0, 0, 0, 0);
            return ret;
        }
    } else {
        ret = HS_DtlsSendFragmentHsMsg(ctx, maxRecPayloadLen, hsCtx->msgBuf);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

static int32_t DtlsSendHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

#ifdef HITLS_BSL_UIO_UDP
    ret = REC_QueryMtu(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_BSL_UIO_UDP */
    ret = REC_RecOutBufReSet(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t maxRecPayloadLen = 0;
    ret = REC_GetMaxWriteSize(ctx, &maxRecPayloadLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17129, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetMaxWriteSize fail", 0, 0, 0, 0);
        return ret;
    }

    ret = SendHsMsgWithPayload(ctx, maxRecPayloadLen, hsCtx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_BSL_UIO_UDP
    /* Adding to the retransmission queue */
    if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        ret = RecRetransmitListAppendNode(ctx->recCtx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen, NULL);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_BSL_UIO_UDP */

    /* Add hash data */
    ret = VERIFY_AppendDtlsRaw(hsCtx->verifyCtx, hsCtx->msgBuf, hsCtx->msgLen, VERIFY_TRANSCRIPT_RAW);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15798, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify append fail when send handshake msg.", 0, 0, 0, 0);
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(1, GET_VERSION_FROM_CTX(ctx), REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen,
                              ctx, ctx->config.tlsConfig.msgArg);
    
    INDICATOR_StatusIndicate(ctx, ctx->isClient ? INDICATE_EVENT_STATE_CONNECT_LOOP : INDICATE_EVENT_STATE_ACCEPT_LOOP,
        INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */

    hsCtx->msgLen = 0;
    hsCtx->nextSendSeq++;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_PROTO_DATAGRAM */

#ifdef HITLS_TLS_PROTO_DTLS13
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
static int32_t Dtls13KeyUpdateAckCb(TLS_Ctx *ctx)
{
    int32_t ret = HS_TLS13UpdateTrafficSecret(ctx, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return REC_RetransmitListFlush(ctx);
}
#endif /* HITLS_TLS_FEATURE_KEY_UPDATE */

static REC_Dtls13RetransmitAckCb Dtls13GetRetransmitAckCb(const HS_Ctx *hsCtx)
{
    if (hsCtx == NULL || hsCtx->msgBuf == NULL || hsCtx->msgLen < DTLS_HS_MSG_HEADER_SIZE) {
        return NULL;
    }
    switch ((HS_MsgType)hsCtx->msgBuf[0]) {
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        case KEY_UPDATE:
            return Dtls13KeyUpdateAckCb;
#endif
#ifdef HITLS_TLS_FEATURE_DTLS_CID
        case NEW_CONNECTION_ID:
            return DTLS_CID_OnNewConnectionIdAcked;
        case REQUEST_CONNECTION_ID:
            return DTLS_CID_OnRequestConnectionIdAcked;
#endif
        default:
            return NULL;
    }
}

static int32_t Dtls13CheckHsSendSeq(TLS_Ctx *ctx, const HS_Ctx *hsCtx)
{
    if (hsCtx->nextSendSeq == DTLS_HS_MSG_SEQ_MAX) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15351, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS1.3 handshake send sequence wrap.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE;
    }
    return HITLS_SUCCESS;
}

static int32_t Dtls13SendHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    if (hsCtx == NULL || hsCtx->msgBuf == NULL || hsCtx->msgLen < DTLS_HS_MSG_HEADER_SIZE) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    bool isPostHandshakeSend = (ctx->state == CM_STATE_HANDSHAKING && ctx->preState == CM_STATE_TRANSPORTING);
    ret = Dtls13CheckHsSendSeq(ctx, hsCtx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = REC_RetransmitListPushWithAckCb(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen,
        Dtls13GetRetransmitAckCb(hsCtx));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (hsCtx->verifyCtx == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    ret = VERIFY_AppendDtlsRaw(hsCtx->verifyCtx, hsCtx->msgBuf, hsCtx->msgLen, VERIFY_TRANSCRIPT_DTLS13);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (isPostHandshakeSend) {
        ret = HS_StartTimer(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(1, GET_VERSION_FROM_CTX(ctx), REC_TYPE_HANDSHAKE, hsCtx->msgBuf, hsCtx->msgLen,
                              ctx, ctx->config.tlsConfig.msgArg);
    INDICATOR_StatusIndicate(ctx, ctx->isClient ? INDICATE_EVENT_STATE_CONNECT_LOOP : INDICATE_EVENT_STATE_ACCEPT_LOOP,
        INDICATE_VALUE_SUCCESS);
#endif
    hsCtx->msgLen = 0;
    hsCtx->nextSendSeq++;
    return HITLS_SUCCESS;
}
#endif

int32_t HS_SendMsg(TLS_Ctx *ctx)
{
    uint32_t version = GET_VERSION_FROM_CTX(ctx);
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    if (ctx->hsCtx->state == TRY_SEND_HELLO_VERIFY_REQUEST) {
        return DtlsSendHandShakeMsg(ctx);
    }
#ifdef HITLS_TLS_PROTO_DTLS13
    if (ctx->hsCtx->state == TRY_SEND_CLIENT_HELLO && ctx->hsCtx->haveHvr) {
        return DtlsSendHandShakeMsg(ctx);
    }
#endif /* HITLS_TLS_PROTO_DTLS13 */
#endif

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS
        case HITLS_VERSION_TLS12:
        case HITLS_VERSION_TLS13:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#if defined(HITLS_TLS_PROTO_DTLCP11)
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                return DtlsSendHandShakeMsg(ctx);
            }
#endif
#endif
            return TlsSendHandShakeMsg(ctx);
#endif /* HITLS_TLS_PROTO_TLS */
#ifdef HITLS_TLS_PROTO_DTLS13
        case HITLS_VERSION_DTLS13:
            return Dtls13SendHandShakeMsg(ctx);
#endif
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            return DtlsSendHandShakeMsg(ctx);
#endif
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15799, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Send handshake msg of unsupported version.", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
}
