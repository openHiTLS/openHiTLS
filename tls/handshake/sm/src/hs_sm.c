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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls.h"
#include "rec.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "parse.h"
#include "hs_state_recv.h"
#include "hs_state_send.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "uio_base.h"
#include "indicator.h"
#include "transcript_hash.h"
#include "recv_process.h"

static int32_t HandshakeDone(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* If isFlightTransmitEnable is enabled, the server CCS and Finish information stored in the bUio must be sent after
     * the handshake is complete */
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15959, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "fail to send the CCS and Finish message of server in bUio.", 0, 0, 0, 0);
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }

#ifndef HITLS_NO_DTLS12
    if (BSL_UIO_GetTransportType(ctx->uio) != BSL_UIO_SCTP) {
        return HITLS_SUCCESS;
    }

    bool isBuffEmpty = false;
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_SND_BUFF_IS_EMPTY, (int32_t)sizeof(isBuffEmpty), &isBuffEmpty);
    if (ret != BSL_SUCCESS) {
        return HITLS_UIO_SCTP_IS_SND_BUF_EMPTY_FAIL;
    }

    if (isBuffEmpty != true) {
        return HITLS_REC_NORMAL_IO_BUSY;
    }

    ret = HS_ActiveSctpAuthKey(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_DeletePreviousSctpAuthKey(ctx);
#endif

    return ret;
}

static bool IsHsSendState(HITLS_HandshakeState state)
{
    switch (state) {
        case TRY_SEND_HELLO_REQUEST:
        case TRY_SEND_CLIENT_HELLO:
        case TRY_SEND_HELLO_RETRY_REQUEST:
        case TRY_SEND_SERVER_HELLO:
        case TRY_SEND_ENCRYPTED_EXTENSIONS:
        case TRY_SEND_CERTIFICATE:
        case TRY_SEND_SERVER_KEY_EXCHANGE:
        case TRY_SEND_CERTIFICATE_REQUEST:
        case TRY_SEND_SERVER_HELLO_DONE:
        case TRY_SEND_CLIENT_KEY_EXCHANGE:
        case TRY_SEND_CERTIFICATE_VERIFY:
        case TRY_SEND_NEW_SESSION_TICKET:
        case TRY_SEND_CHANGE_CIPHER_SPEC:
        case TRY_SEND_END_OF_EARLY_DATA:
        case TRY_SEND_FINISH:
            return true;
        default:
            break;
    }

    return false;
}

static bool IsHsRecvState(HITLS_HandshakeState state)
{
    switch (state) {
        case TRY_RECV_CLIENT_HELLO:
        case TRY_RECV_SERVER_HELLO:
        case TRY_RECV_ENCRYPTED_EXTENSIONS:
        case TRY_RECV_CERTIFICATE:
        case TRY_RECV_SERVER_KEY_EXCHANGE:
        case TRY_RECV_CERTIFICATE_REQUEST:
        case TRY_RECV_SERVER_HELLO_DONE:
        case TRY_RECV_CLIENT_KEY_EXCHANGE:
        case TRY_RECV_CERTIFICATE_VERIFY:
        case TRY_RECV_NEW_SESSION_TICKET:
        case TRY_RECV_END_OF_EARLY_DATA:
        case TRY_RECV_FINISH:
            return true;
        default:
            break;
    }

    return false;
}

int32_t HS_DoHandshake(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    int32_t eventType = (ctx->isClient) ? INDICATE_EVENT_STATE_CONNECT_EXIT : INDICATE_EVENT_STATE_ACCEPT_EXIT;

    while (hsCtx->state != TLS_CONNECTED) {
        if (IsHsSendState(hsCtx->state)) {
            ret = HS_SendMsgProcess(ctx);
        } else if (IsHsRecvState(hsCtx->state)) {
            ret = HS_RecvMsgProcess(ctx);
        } else {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
            BSL_LOG_BINLOG_VARLEN(BINLOG_ID15884, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Handshake state unable to process, current state is %s.", HS_GetStateStr(hsCtx->state));
            ret = HITLS_MSG_HANDLE_STATE_ILLEGAL;
        }

        if (ret != HITLS_SUCCESS) {
            INDICATOR_StatusIndicate(ctx, eventType, ret);
            return ret;
        }
    }

    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_HANDSHAKE_DONE, INDICATE_VALUE_SUCCESS);

    ret = HandshakeDone(ctx);
    if (ret != HITLS_SUCCESS) {
        INDICATOR_StatusIndicate(ctx, eventType, ret);
        return ret;
    }

    INDICATOR_StatusIndicate(ctx, eventType, INDICATE_VALUE_SUCCESS);
    return HITLS_SUCCESS;
}

int32_t HS_CheckKeyUpdateState(const TLS_Ctx *ctx, uint32_t updateType)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }

    if (ctx->state != CM_STATE_TRANSPORTING) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }

    if (updateType != HITLS_UPDATE_REQUESTED && updateType != HITLS_UPDATE_NOT_REQUESTED) {
        return HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE;
    }

    return HITLS_SUCCESS;
}

int32_t HS_SendKeyUpdate(TLS_Ctx *ctx)
{
    // Pack and send the KeyUpdate message and update the application traffic secret used for sending the message
    int32_t ret = HS_HandleSendKeyUpdate(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ctx->isKeyUpdateRequest = false;
    ctx->keyUpdateType = HITLS_KEY_UPDATE_REQ_END;
    return HITLS_SUCCESS;
}

static int32_t RecvKeyUpdateMsgProcess(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }

    if (ctx->state != CM_STATE_TRANSPORTING) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    HS_Msg hsMsg = {0};
    // Parsing and updating the app traffic secret used by the local
    int32_t ret = HS_HandleRecvKeyUpdate(ctx, hsMsgInfo, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }

    /* Upon request for a received key update of the type UPDATE_REQUESTED,
     * Set the key update type for the local context to UPDATE_NOT_REQUESTED,
     * Then, the key update message is sent to the peer to update the traffic secret used by the local
     */
    if (hsMsg.body.keyUpdate.requestUpdate == HITLS_UPDATE_REQUESTED) {
        ctx->isKeyUpdateRequest = true;
        ctx->keyUpdateType = HITLS_UPDATE_NOT_REQUESTED;
        ret = HS_SendKeyUpdate(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

static int32_t RecvCertificateRequest(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, CM_State *state)
{
    if (ctx->state != CM_STATE_TRANSPORTING || ctx->phaState != PHA_EXTENSION || !ctx->isClient ||
        ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    int32_t ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15341, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_Init fail when recv certificate request.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    SAL_CRYPT_DigestFree(ctx->hsCtx->verifyCtx->hashCtx);
    ctx->hsCtx->verifyCtx->hashCtx = SAL_CRYPT_DigestCopy(ctx->phaHash);
    if (ctx->hsCtx->verifyCtx->hashCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15368, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }

    HS_Msg hsMsg = {0};
    ret = HS_ParseMsg(ctx, hsMsgInfo, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15342, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse tls1.3 key update msg fail.", 0, 0, 0, 0);
        HS_CleanMsg(&hsMsg);
        return ret;
    }
    ret = VERIFY_Append(ctx->hsCtx->verifyCtx, hsMsgInfo->rawMsg, hsMsgInfo->headerAndBodyLen);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }
    ctx->phaState = PHA_REQUESTED;
    HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
    ret = Tls13ClientRecvCertRequestProcess(ctx, &hsMsg);
    HS_CleanMsg(&hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    *state = CM_STATE_HANDSHAKING;
    return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}

static int32_t RecvCertificate(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, CM_State *state)
{
    if (ctx->state != CM_STATE_TRANSPORTING || ctx->phaState != PHA_REQUESTED ||
        ctx->isClient || ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    int32_t ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15340, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_Init fail when recv certificate.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    ctx->hsCtx->verifyCtx->hashCtx = ctx->phaCurHash;
    ctx->phaCurHash = NULL;

    HS_Msg hsMsg = {0};
    ret = HS_ParseMsg(ctx, hsMsgInfo, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15344, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse tls1.3 key update msg fail.", 0, 0, 0, 0);
        HS_CleanMsg(&hsMsg);
        return ret;
    }
    ret = VERIFY_Append(ctx->hsCtx->verifyCtx, hsMsgInfo->rawMsg, hsMsgInfo->headerAndBodyLen);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }
    HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
    ret = Tls13RecvCertificateProcess(ctx, &hsMsg);
    HS_CleanMsg(&hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    *state = CM_STATE_HANDSHAKING;
    return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}

static int32_t RecvRenegotiationReqProcess(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, CM_State *state)
{
    /* If the version is TLS1.3, ignore the message */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    /* If the message is not a renegotiation request, ignore the message */
    if ((ctx->isClient && (hsMsgInfo->type == CLIENT_HELLO)) ||
        (!ctx->isClient && (hsMsgInfo->type == HELLO_REQUEST))) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    /* Renegotiation request is processed only after security renegotiation is negotiated. Otherwise, no renegotiation
     * alarm is generated and the peer determines whether to disconnect the link */
    if (!ctx->negotiatedInfo.isSecureRenegotiation || !ctx->config.tlsConfig.isSupportRenegotiation) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_WARNING, ALERT_NO_RENEGOTIATION);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    if (ctx->hsCtx != NULL) {
        HS_DeInit(ctx);
    }
    int32_t ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15976, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_Init fail when recv renegotiation request.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ret = HS_HandleRecvRenegoReq(ctx, hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        HS_DeInit(ctx);
        return ret;
    }

    *state = CM_STATE_RENEGOTIATION;
    ctx->negotiatedInfo.isRenegotiation = true; /* Start renegotiation */
    ctx->negotiatedInfo.renegotiationNum++;
    return HITLS_SUCCESS;
}

static int32_t HsInitMsgBuf(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = (HS_Ctx *)BSL_SAL_Calloc(1u, sizeof(HS_Ctx));
    if (hsCtx == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->hsCtx = hsCtx;
    hsCtx->bufferLen = REC_MAX_PLAIN_LENGTH;
    hsCtx->msgBuf = BSL_SAL_Malloc(hsCtx->bufferLen);
    if (hsCtx->msgBuf == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    return HITLS_SUCCESS;
}

static int32_t DealUnexpectedMsgWrtType(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, CM_State *state)
{
    uint8_t *rawMsg = BSL_SAL_Malloc(ctx->hsCtx->bufferLen);
    if (rawMsg == NULL) {
        HS_DeInit(ctx);
        return HITLS_MEMALLOC_FAIL;
    }
    if (memcpy_s(rawMsg, ctx->hsCtx->bufferLen, hsMsgInfo->rawMsg, hsMsgInfo->headerAndBodyLen) != EOK) {
        HS_DeInit(ctx);
        BSL_SAL_Free(rawMsg);
        return HITLS_MEMCPY_FAIL;
    }
    hsMsgInfo->rawMsg = rawMsg;
    HS_DeInit(ctx);
    int32_t ret = 0;
    switch (hsMsgInfo->type) {
        case HELLO_REQUEST:
        case CLIENT_HELLO:
            ret = RecvRenegotiationReqProcess(ctx, hsMsgInfo, state);
            break;
        case KEY_UPDATE:
            ret = RecvKeyUpdateMsgProcess(ctx, hsMsgInfo);
            break;
        case CERTIFICATE_REQUEST:
            ret = RecvCertificateRequest(ctx, hsMsgInfo, state);
            break;
        case CERTIFICATE:
            ret = RecvCertificate(ctx, hsMsgInfo, state);
            break;
        case NEW_SESSION_TICKET:
            /* If the version is not TLS1.3, ignore the message */
            if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
                break;
            }
            ret = HS_HandleTLS13NewSessionTicket(ctx, hsMsgInfo);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
            BSL_LOG_BINLOG_VARLEN(BINLOG_ID15841, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Unexpected %s handshake state message.", HS_GetMsgTypeStr(hsMsgInfo->type));
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            ret = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }
    BSL_SAL_Free(rawMsg);
    return ret;
}

int32_t HS_RecvUnexpectedMsgProcess(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, CM_State *state)
{
    int32_t ret = HITLS_SUCCESS;
    HS_MsgInfo hsMsgInfo = { 0 };
    uint32_t headerLen = IS_DTLS_VERSION(ctx->negotiatedInfo.version) ? DTLS_HS_MSG_HEADER_SIZE : HS_MSG_HEADER_SIZE;

#ifndef HITLS_NO_DTLS12
    if (data[0] == FINISHED && IS_DTLS_VERSION(ctx->config.tlsConfig.maxVersion)) {
        ret = HS_ParseMsgHeader(ctx, data, len, &hsMsgInfo);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        return HITLS_SUCCESS;
    }
#endif

    if (ctx->hsCtx != NULL) {
        HS_DeInit(ctx);
    }
    ret = HsInitMsgBuf(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15977, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_Init fail when recv renegotiation request.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        HS_DeInit(ctx);
        return ret;
    }
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (memcpy_s(ctx->hsCtx->msgBuf, ctx->hsCtx->bufferLen, data, len) != EOK) {
        HS_DeInit(ctx);
        return HITLS_MEMCPY_FAIL;
    }
    uint32_t readbytes = len;
    if (readbytes < headerLen) {
        ret = REC_TlsReadNbytes(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf + readbytes, headerLen - readbytes);
        if (ret != HITLS_SUCCESS) {
            HS_DeInit(ctx);
            return ret;
        }
        readbytes = headerLen;
    }
    ret = HS_ParseMsgHeader(ctx, hsCtx->msgBuf, readbytes, &hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        HS_DeInit(ctx);
        return ret;
    }
    ctx->hasParsedHsMsgHeader = true;
    if (readbytes < hsMsgInfo.headerAndBodyLen) {
        ret = REC_TlsReadNbytes(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf + readbytes,
            hsMsgInfo.headerAndBodyLen - readbytes);
        if (ret != HITLS_SUCCESS) {
            HS_DeInit(ctx);
            return ret;
        }
    }

    return DealUnexpectedMsgWrtType(ctx, &hsMsgInfo, state);
}

bool HS_IsAppDataAllowed(TLS_Ctx *ctx)
{
    /* If the negotiated version is 0, it indicates that the handshake is the first time. In this case, an alert message
     * needs to be sent when the unexpected app message is received */
    if (ctx->negotiatedInfo.version == 0u || ctx->negotiatedInfo.renegotiationNum == 0) {
        return false;
    }

    /* App messages can be received before the server hello message is sent or received */
    uint32_t hsState = HS_GetState(ctx);
    if (ctx->isClient) {
        if (hsState == TRY_RECV_SERVER_HELLO) {
            return true;
        }
    } else {
        if (hsState == TRY_RECV_CLIENT_HELLO) {
            return true;
        }
    }
    return false;
}

int32_t HS_CheckPostHandshakeAuth(TLS_Ctx *ctx)
{
    int32_t ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
    SAL_CRYPT_DigestFree(ctx->hsCtx->verifyCtx->hashCtx);
    ctx->hsCtx->verifyCtx->hashCtx = SAL_CRYPT_DigestCopy(ctx->phaHash);
    if (ctx->hsCtx->verifyCtx->hashCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15369, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    return HITLS_SUCCESS;
}