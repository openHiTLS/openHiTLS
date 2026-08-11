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
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "tls_binlog_id.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "rec.h"
#include "rec_header.h"
#include "record.h"
#include "hs.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "hs_dtls_timer.h"
#include "transcript_hash.h"
#include "hs_reass.h"
#include "parse.h"
#include "recv_process.h"
#include "crypt.h"
#include "bsl_uio.h"
#include "hs_kx.h"
#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_TLS_FEATURE_DTLS_CID)
#include "dtls_cid.h"
#endif
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif /* HITLS_TLS_FEATURE_INDICATOR */

static int32_t CheckHsMsg(TLS_Ctx *ctx, HS_Msg *hsMsg, int32_t ret)
{
    if (ret == HITLS_SUCCESS) {
        HS_CleanMsg(ctx->hsCtx->hsMsg);
        if (ctx->hsCtx->hsMsg != hsMsg) {
            BSL_SAL_FREE(ctx->hsCtx->hsMsg);
        }
        ctx->hsCtx->hsMsg = NULL;
    }
    if (ctx->hsCtx->hsMsg == hsMsg) {
        ctx->hsCtx->hsMsg = BSL_SAL_Dump(hsMsg, sizeof(HS_Msg));
        if (ctx->hsCtx->hsMsg == NULL) {
            HS_CleanMsg(hsMsg);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17357, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "hsMsg dump fail.", 0, 0,
                                  0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
    }
    return ret;
}

#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
#ifdef HITLS_TLS_PROTO_DTLS13
static bool Dtls13CanReplyKeyUpdate(const TLS_Ctx *ctx)
{
    if (!IS_DTLS13_CTX(ctx)) {
        return true;
    }
    return ctx->recCtx != NULL && ctx->recCtx->writeEpoch < REC_EPOCH_MAX_VALUE &&
        ctx->dtls13NextSendSeq < DTLS_HS_MSG_SEQ_MAX;
}
#endif

static int32_t Tls13RecvKeyUpdateProcess(TLS_Ctx *ctx, const HS_Msg *hsMsg)
{
    HITLS_KeyUpdateRequest requestUpdateType = hsMsg->body.keyUpdate.requestUpdate;
    if ((requestUpdateType != HITLS_UPDATE_NOT_REQUESTED) &&
        (requestUpdateType != HITLS_UPDATE_REQUESTED)) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15354, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "(d)tls1.3 unexpected requestUpdateType(%u)", requestUpdateType, 0, 0, 0);
        return HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE;
    }

    /* Update and activate the app traffic secret used by the local after receiving the key update message */
    int32_t ret = HS_TLS13UpdateTrafficSecret(ctx, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15355, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "(d)tls1.3 in key update fail", 0, 0, 0, 0);
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15980, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "(d)tls1.3 recv key update success", 0, 0, 0, 0);
    ctx->isWaitKeyUpdate = false;

    if (hsMsg->body.keyUpdate.requestUpdate == HITLS_UPDATE_REQUESTED) {
#ifdef HITLS_TLS_PROTO_DTLS13
        /*
         * Local DTLS1.3 policy: do not enqueue a response KeyUpdate while any
         * post-handshake flight is still awaiting ACK. This is stricter than
         * RFC 9147's same-message-type rule, but keeps this endpoint from
         * having multiple outbound key generations simultaneously usable.
         */
        if (IS_DTLS13_CTX(ctx) && (!REC_RetransmitIsEmpty(ctx->recCtx) || !Dtls13CanReplyKeyUpdate(ctx))) {
            return HS_ChangeState(ctx, TLS_CONNECTED);
        }
#endif /* HITLS_TLS_PROTO_DTLS13 */
        ctx->isKeyUpdateRequest = true;
        ctx->keyUpdateType = HITLS_UPDATE_NOT_REQUESTED;
        return HS_ChangeState(ctx, TRY_SEND_KEY_UPDATE);
    }
    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_FEATURE_KEY_UPDATE */

#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_TLS_FEATURE_DTLS_CID)
/*
 * Apply peer-advertised CIDs after ParseNewConnectionId has validated the wire
 * structure. RFC 9147 Section 5.2 treats RequestConnectionId and
 * NewConnectionId as independent messages: receiving a NewConnectionId here
 * does NOT fulfill a previously sent RequestConnectionId. That fulfillment is
 * driven by the record-layer ACK via DTLS_CID_OnRequestConnectionIdAcked.
 */
static int32_t Dtls13RecvNewConnectionIdProcess(TLS_Ctx *ctx, const HS_Msg *hsMsg)
{
    /*
     * RFC 9147 Section 9 (lines 2258-2263):
     *   "Implementations which either did not negotiate the connection_id
     *    extension or which have negotiated receiving an empty CID MUST NOT
     *    send NewConnectionId. Implementations which detect a violation of
     *    these rules MUST terminate the connection with an 'unexpected_message'
     *    alert."
     */
    if (ctx->negotiatedInfo.peerCidEntry.cidLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17409, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "NewConnectionId rejected: peer negotiated an empty Connection ID before.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    const NewConnectionIdMsg *msg = &hsMsg->body.newConnectionId;
    int32_t ret = DTLS_CID_ProcessPeerNewConnectionId(ctx, msg->cids, msg->cidsLen, msg->usage);
    if (ret != HITLS_SUCCESS) {
        /* After parser validation only an allocation failure can reach here. */
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    return HS_ChangeState(ctx, TLS_CONNECTED);
}

/*
 * Peer RequestConnectionId:
 *   local CID empty          -> fatal unexpected_message (abort, RFC 9147 §5.2)
 *   numCids==0 / no callback -> TLS_CONNECTED
 *   callback armed NewConnectionId    -> TRY_SEND_NEW_CONNECTION_ID
 */
static int32_t Dtls13RecvRequestConnectionIdProcess(TLS_Ctx *ctx, const HS_Msg *hsMsg)
{
    /*
     * RFC 9147 Section 5.2:
     *   "Implementations MUST NOT send RequestConnectionId when sending an empty
     *    Connection ID. Implementations which detect a violation of these rules
     *    MUST terminate the connection with an 'unexpected_message' alert."
     */
    if (ctx->negotiatedInfo.localCidEntry.cidLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17408, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RequestConnectionId rejected: peer is sending an empty Connection ID.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    uint8_t numCids = hsMsg->body.requestConnectionId.numCids;
    if (numCids == 0) {
        /* Current API treats zero as a no-op request and does not call the application hook. */
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
    if (ctx->onRecvRequestCidCb == NULL) {
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }

    int32_t ret = ctx->onRecvRequestCidCb(ctx, numCids, ctx->onRecvRequestCidUserData);
    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    if (ctx->newCidState == DTLS_CID_MSG_STATE_PENDING) {
        /* The callback armed a NewConnectionId reply; let HS_DoHandshake send it. */
        return HS_ChangeState(ctx, TRY_SEND_NEW_CONNECTION_ID);
    }
    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_PROTO_DTLS13 && HITLS_TLS_FEATURE_DTLS_CID */

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS)
static bool IsUnexpectedHandshaking(const TLS_Ctx *ctx)
{
    return (ctx->state == CM_STATE_HANDSHAKING && ctx->preState == CM_STATE_TRANSPORTING);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS */

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t ProcessHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_SERVER
        case TRY_RECV_CLIENT_HELLO:
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
            return ServerRecvClientHelloProcess(ctx, hsMsg, true);
#else
            break;
#endif /* HITLS_TLS_PROTO_TLS_BASIC only for tls13 */
        case TRY_RECV_CLIENT_KEY_EXCHANGE:
            return ServerRecvClientKxProcess(ctx, hsMsg);
#ifdef HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY
        case TRY_RECV_CERTIFICATE_VERIFY:
            return ServerRecvClientCertVerifyProcess(ctx);
#endif
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case TRY_RECV_CERTIFICATE_REQUEST:
            return ClientRecvCertRequestProcess(ctx);
#ifdef HITLS_TLS_PROTO_DTLS12
        case TRY_RECV_HELLO_VERIFY_REQUEST:
            return DtlsClientRecvHelloVerifyRequestProcess(ctx, hsMsg);
#endif /* HITLS_TLS_PROTO_DTLS12 */
        case TRY_RECV_SERVER_HELLO:
            return ClientRecvServerHelloProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_KEY_EXCHANGE:
            return ClientRecvServerKxProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_HELLO_DONE:
            return ClientRecvServerHelloDoneProcess(ctx);
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case TRY_RECV_NEW_SESSION_TICKET:
            return Tls12ClientRecvNewSeesionTicketProcess(ctx, hsMsg);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#endif /* HITLS_TLS_HOST_CLIENT */
        case TRY_RECV_CERTIFICATE:
            return RecvCertificateProcess(ctx, hsMsg);
        case TRY_RECV_FINISH:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
#ifdef HITLS_TLS_PROTO_DTLS12
                if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                    return DtlsRecvFinishedProcess(ctx, hsMsg);
                }
#endif /* HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS_BASIC
                return Tls12ClientRecvFinishedProcess(ctx, hsMsg);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_PROTO_DTLS12
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                return DtlsRecvFinishedProcess(ctx, hsMsg);
            }
#endif /* HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS_BASIC
            return Tls12ServerRecvFinishedProcess(ctx, hsMsg);
#else
            break;
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#endif /* HITLS_TLS_HOST_SERVER */
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15350, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Handshake state error: should recv msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state));
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}

static int32_t ProcessReceivedHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if (hsMsg->type == HELLO_REQUEST) {
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
        if (ctx->hsCtx->state == TRY_RECV_HELLO_REQUEST) {
            ctx->negotiatedInfo.isRenegotiation = true; /* Start renegotiation */
            ctx->negotiatedInfo.renegotiationNum++;
            return HS_ChangeState(ctx, TRY_SEND_CLIENT_HELLO);
        }
#endif
        /* The HelloRequest message should be ignored during the handshake. */
        return HITLS_SUCCESS;
    }
    if (hsMsg->type == CLIENT_HELLO && IsUnexpectedHandshaking(ctx)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17028, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "refuse Renegotiation request from client", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_WARNING, ALERT_NO_RENEGOTIATION);
        (void)HS_ChangeState(ctx, TLS_CONNECTED);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }
    return ProcessHandshakeMsg(ctx, hsMsg);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#if defined(HITLS_TLS_PROTO_TLS13_FAMILY)
static int32_t Tls13ProcessReceivedHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if ((hsMsg->type == HELLO_REQUEST) && (ctx->isClient)) {
        /* The HelloRequest message should be ignored during the handshake. */
        return HITLS_SUCCESS;
    }

    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_SERVER
        case TRY_RECV_CLIENT_HELLO:
            return Tls13ServerRecvClientHelloProcess(ctx, hsMsg);
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case TRY_RECV_CERTIFICATE_REQUEST:
            return Tls13ClientRecvCertRequestProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_HELLO:
            return Tls13ClientRecvServerHelloProcess(ctx, hsMsg);
        case TRY_RECV_ENCRYPTED_EXTENSIONS:
            return Tls13ClientRecvEncryptedExtensionsProcess(ctx, hsMsg);
#endif /* HITLS_TLS_HOST_CLIENT */
        case TRY_RECV_CERTIFICATE:
            return Tls13RecvCertificateProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE_VERIFY:
            return Tls13RecvCertVerifyProcess(ctx);
        case TRY_RECV_FINISH:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
                return Tls13ClientRecvFinishedProcess(ctx, hsMsg);
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
            return Tls13ServerRecvFinishedProcess(ctx, hsMsg);
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        case TRY_RECV_KEY_UPDATE:
            return Tls13RecvKeyUpdateProcess(ctx, hsMsg);
#endif
        case TRY_RECV_NEW_SESSION_TICKET:
            return Tls13ClientRecvNewSessionTicketProcess(ctx, hsMsg);
#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_TLS_FEATURE_DTLS_CID)
        case TRY_RECV_NEW_CONNECTION_ID:
            return Dtls13RecvNewConnectionIdProcess(ctx, hsMsg);
        case TRY_RECV_REQUEST_CONNECTION_ID:
            return Dtls13RecvRequestConnectionIdProcess(ctx, hsMsg);
#endif
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15343, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "(d)tls1.3 handshake state error: should recv msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state), 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}
#endif /* HITLS_TLS_PROTO_TLS13_FAMILY */

int32_t ReadHsMessage(TLS_Ctx *ctx, uint32_t length)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (hsCtx == NULL || hsCtx->msgBuf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17029, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    if (hsCtx->msgLen >= length) {
        return HITLS_SUCCESS;
    }
    int32_t ret = HS_GrowMsgBuf(ctx, length, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t readLen = 0;
    do {
        readLen = 0;
        ret = REC_Read(ctx, REC_TYPE_HANDSHAKE, &hsCtx->msgBuf[hsCtx->msgLen], &readLen, length - hsCtx->msgLen);
        hsCtx->msgLen += readLen;
        if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
            break;
        }
    } while (ret == HITLS_SUCCESS && hsCtx->msgLen < length && readLen != 0);
    if (ret == HITLS_SUCCESS && hsCtx->msgLen < length) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
    return ret;
}

#ifdef HITLS_TLS_PROTO_TLS

static int32_t ReadThenParseTlsHsMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    int32_t ret = ReadHsMessage(ctx, HS_MSG_HEADER_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    HS_MsgInfo hsMsgInfo = {0};
    ret = HS_ParseMsgHeader(ctx, hsCtx->msgBuf, HS_MSG_HEADER_SIZE, &hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = ReadHsMessage(ctx, hsMsgInfo.headerAndBodyLen); // hsCtx->msgBuf always has enough buf
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HS_ParseMsg(ctx, &hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* The HelloRequest message is not included. */
    if (hsMsgInfo.type != HELLO_REQUEST && hsMsgInfo.type != KEY_UPDATE &&
#ifdef HITLS_TLS_FEATURE_DTLS_CID
        hsMsgInfo.type != NEW_CONNECTION_ID && hsMsgInfo.type != REQUEST_CONNECTION_ID &&
#endif
        !(GET_VERSION_FROM_CTX(ctx) == HITLS_VERSION_TLS13 && hsMsgInfo.type == NEW_SESSION_TICKET)) {
        /* Session hash is needed to compute ems, the VERIFY_Append must be dealt with beforehand */
        ret = VERIFY_Append(hsCtx->verifyCtx, hsCtx->msgBuf, hsMsgInfo.headerAndBodyLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17031, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "VERIFY_Append fail", 0,
                                  0, 0, 0);
            HS_CleanMsg(hsMsg);
            return ret;
        }
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(0, GET_VERSION_FROM_CTX(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo.rawMsg,
        hsMsgInfo.headerAndBodyLen, ctx, ctx->config.tlsConfig.msgArg);
    INDICATOR_StatusIndicate(ctx, ctx->isClient ? INDICATE_EVENT_STATE_CONNECT_LOOP : INDICATE_EVENT_STATE_ACCEPT_LOOP,
        INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
    hsCtx->msgLen = 0;
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS_BASIC
static int32_t Tls12TryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    memset(&hsMsg, 0, sizeof(HS_Msg));
    if (ctx->hsCtx->hsMsg == NULL) {
        ret = ReadThenParseTlsHsMsg(ctx, &hsMsg);
        if (ret != HITLS_SUCCESS) {
            HS_CleanMsg(&hsMsg);
            return ret;
        }
        ctx->hsCtx->hsMsg = &hsMsg;
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_A;
    }
    ret = ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
    return CheckHsMsg(ctx, &hsMsg, ret);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13TryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    memset(&hsMsg, 0, sizeof(HS_Msg));
    if (ctx->hsCtx->hsMsg == NULL) {
        ret = ReadThenParseTlsHsMsg(ctx, &hsMsg);
        if (ret != HITLS_SUCCESS) {
            HS_CleanMsg(&hsMsg);
            return ret;
        }
        ctx->hsCtx->hsMsg = &hsMsg;
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_A;
    }
    ret = Tls13ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
    return CheckHsMsg(ctx, &hsMsg, ret);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_PROTO_TLS */
#if defined(HITLS_TLS_PROTO_DATAGRAM)
static int32_t DtlsCheckTimeoutAndProcess(TLS_Ctx *ctx, int32_t retValue)
{
    (void)ctx;
#ifdef HITLS_BSL_UIO_UDP
    int32_t ret = HITLS_DtlsProcessTimeout(ctx);
    if (ret != HITLS_SUCCESS && ret != HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT) {
        return ret;
    }
#endif
    /* HITLS_REC_NORMAL_RECV_BUF_EMPTY is returned here, and the choice is given to the user instead of the next read,
     * Prevents users from waiting for a long time due to long timeout. */
    return retValue;
}

int32_t DtlsDisorderMsgProcess(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
#ifdef HITLS_BSL_UIO_SCTP
    /* The SCTP scenario must be sequenced. */
    if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15351, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "msg with unmatched sequence, recv %u, expect %u.", hsMsgInfo->sequence, ctx->hsCtx->expectRecvSeq, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE;
    }
#endif /* HITLS_BSL_UIO_SCTP */
#ifdef HITLS_BSL_UIO_UDP
    HS_Ctx *hsCtx = ctx->hsCtx;
    /* In the renegotiation state, the FINISHED message of the previous handshake should be discarded. */
    if (hsCtx->expectRecvSeq == 0 && hsMsgInfo->type == FINISHED && ctx->negotiatedInfo.version != HITLS_VERSION_DTLS13) {
        return HITLS_SUCCESS;
    }
    /* If the sequence number of the received message is greater than expected, the message is cached in the reassembly
     * queue. */
    if (hsMsgInfo->sequence > hsCtx->expectRecvSeq) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17033, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the message is need to cache in the reassembly queue", 0, 0, 0, 0);
        int32_t ret = HS_ReassAppend(ctx, hsMsgInfo);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        return HITLS_SUCCESS;
    }

    return HITLS_SUCCESS;
#else
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17034, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "internal exception occurs", 0, 0, 0, 0);
    return HITLS_INTERNAL_EXCEPTION;
#endif /* HITLS_BSL_UIO_UDP */
}

#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_TLS_FEATURE_PHA)
static int32_t Dtls13PreProcessPhaAfterStateChanged(TLS_Ctx *ctx)
{
    if (GET_VERSION_FROM_CTX(ctx) != HITLS_VERSION_DTLS13 ||
        ctx->state != CM_STATE_HANDSHAKING || ctx->preState != CM_STATE_TRANSPORTING) {
        return HITLS_SUCCESS;
    }

    HS_Ctx *hsCtx = ctx->hsCtx;
    if (hsCtx->state == TRY_RECV_CERTIFICATE_REQUEST && ctx->isClient && ctx->phaState == PHA_EXTENSION) {
        SAL_CRYPT_DigestFree(hsCtx->verifyCtx->hashCtx);
        hsCtx->verifyCtx->hashCtx = SAL_CRYPT_DigestCopy(ctx->phaHash);
        if (hsCtx->verifyCtx->hashCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16178, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
            return HITLS_CRYPT_ERR_DIGEST;
        }
        ctx->phaState = PHA_REQUESTED;
        return HITLS_SUCCESS;
    }

    if (hsCtx->state == TRY_RECV_CERTIFICATE && !ctx->isClient && ctx->phaState == PHA_REQUESTED) {
        SAL_CRYPT_DigestFree(hsCtx->verifyCtx->hashCtx);
        hsCtx->verifyCtx->hashCtx = ctx->phaCurHash;
        ctx->phaCurHash = NULL;
    }
    return HITLS_SUCCESS;
}
#endif

static int32_t DtlsCheckAndParseMsg(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, HS_Msg *hsMsg)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    int32_t ret = CheckHsMsgType(ctx, hsMsgInfo->type);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_TLS_FEATURE_PHA)
    ret = Dtls13PreProcessPhaAfterStateChanged(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif

    ret = HS_ParseMsg(ctx, hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(hsMsg);
        return ret;
    }

#ifdef HITLS_TLS_PROTO_DTLS13
    if (GET_VERSION_FROM_CTX(ctx) == HITLS_VERSION_DTLS13 && hsCtx->expectRecvSeq == DTLS_HS_MSG_SEQ_MAX) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15351, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS1.3 handshake receive sequence wrap.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        HS_CleanMsg(hsMsg);
        return HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE;
    }
#endif
    hsCtx->expectRecvSeq++; /* Auto-increment of the received message sequence number */
    return HITLS_SUCCESS;
}

static int32_t ReadDtlsHsMessage(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (hsCtx == NULL || hsCtx->msgBuf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17035, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    uint8_t *buf = &hsCtx->msgBuf[hsCtx->msgLen];
    uint32_t readLen = 0;
    if (hsCtx->msgLen < DTLS_HS_MSG_HEADER_SIZE) {
        ret = REC_Read(ctx, REC_TYPE_HANDSHAKE, buf, &readLen, (uint32_t)(DTLS_HS_MSG_HEADER_SIZE - hsCtx->msgLen));
        if (ret != HITLS_SUCCESS) {
            if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
                return ret;
            }
            if (hsCtx->msgLen == 0) {
                return DtlsCheckTimeoutAndProcess(ctx, ret);
            }
        }
        hsCtx->msgLen += readLen;
    }
    ret = HS_ParseMsgHeader(ctx, hsCtx->msgBuf, hsCtx->msgLen, hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = ReadHsMessage(ctx, hsMsgInfo->fragmentLength + DTLS_HS_MSG_HEADER_SIZE);
    if ((hsMsgInfo->fragmentLength + DTLS_HS_MSG_HEADER_SIZE) != hsCtx->msgLen || ret != HITLS_SUCCESS) {
        hsCtx->msgLen = 0;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15600, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS handshake msg length error, need to alert.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    return ret;
}

static bool DtlsIsRepeatedInitialClientHello(TLS_Ctx *ctx, const HS_MsgInfo *hsMsgInfo)
{
    return hsMsgInfo->sequence == 0 && ctx->hsCtx->expectRecvSeq == 1 &&
        ctx->hsCtx->state == TRY_RECV_CLIENT_HELLO && hsMsgInfo->type == CLIENT_HELLO &&
        !IsUnexpectedHandshaking(ctx) && ctx->state == CM_STATE_HANDSHAKING &&
        !BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP);
}

static void Dtls13CleanRetransmitOnNextFlight(TLS_Ctx *ctx, const HS_MsgInfo *hsMsgInfo)
{
    if (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13 &&
        hsMsgInfo->sequence >= ctx->hsCtx->expectRecvSeq &&
        !IsUnexpectedHandshaking(ctx)) {
        REC_RetransmitListClean(ctx->recCtx);
    }
}

static int32_t DtlsGetCompleteHandshakeMsg(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, uint32_t *msgLen)
{
    /* A zero output length means no complete message is ready for parsing. */
    *msgLen = 0;
    uint32_t reassMsgLen = 0;
    int32_t ret = HS_GetReassMsg(ctx, hsMsgInfo, &reassMsgLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (reassMsgLen != 0) {
        *msgLen = reassMsgLen;
        return HITLS_SUCCESS;
    }

    ret = ReadDtlsHsMessage(ctx, hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t recordMsgLen = ctx->hsCtx->msgLen;
    ctx->hsCtx->msgLen = 0;
    Dtls13CleanRetransmitOnNextFlight(ctx, hsMsgInfo);

    if (hsMsgInfo->sequence != ctx->hsCtx->expectRecvSeq) {
        if (GET_VERSION_FROM_CTX(ctx) == HITLS_VERSION_DTLS13) {
            return DtlsDisorderMsgProcess(ctx, hsMsgInfo);
        }
        /* When the hello verify request is lost, handle a repeated initial ClientHello as the first one. */
        if (DtlsIsRepeatedInitialClientHello(ctx, hsMsgInfo)) {
            ctx->hsCtx->expectRecvSeq = 0;
            ctx->hsCtx->nextSendSeq = 0;
        }

        /* SCTP messages are not out of order. Therefore, alert on out-of-order messages. */
        if (hsMsgInfo->sequence != ctx->hsCtx->expectRecvSeq && !IsUnexpectedHandshaking(ctx)) {
            return DtlsDisorderMsgProcess(ctx, hsMsgInfo);
        }
    }

    if (hsMsgInfo->fragmentLength != hsMsgInfo->length) {
        return HS_ReassAppend(ctx, hsMsgInfo);
    }
    *msgLen = recordMsgLen;
    return HITLS_SUCCESS;
}

static int32_t DtlsAppendHandshakeTranscript(TLS_Ctx *ctx, const HS_MsgInfo *hsMsgInfo,
    const uint8_t *rawMsg, uint32_t msgLen)
{
    if (hsMsgInfo->type == HELLO_REQUEST) {
        return HITLS_SUCCESS;
    }
#ifdef HITLS_TLS_FEATURE_DTLS_CID
    if (hsMsgInfo->type == NEW_CONNECTION_ID || hsMsgInfo->type == REQUEST_CONNECTION_ID) {
        return HITLS_SUCCESS;
    }
#endif
#ifdef HITLS_TLS_PROTO_DTLS13
    VERIFY_TranscriptStyle style = (ctx->negotiatedInfo.version == HITLS_VERSION_DTLS13) ?
        VERIFY_TRANSCRIPT_DTLS13 : VERIFY_TRANSCRIPT_RAW;
    return VERIFY_AppendDtlsRaw(ctx->hsCtx->verifyCtx, rawMsg, msgLen, style);
#else
    return VERIFY_AppendDtlsRaw(ctx->hsCtx->verifyCtx, rawMsg, msgLen, VERIFY_TRANSCRIPT_RAW);
#endif
}

static int32_t DtlsReadAndParseHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    /* Read the message with the expected sequence number from the reassembly queue. If no message exists, read the
     * message from the record layer */
    uint32_t msgLen = 0;
    HS_MsgInfo hsMsgInfo = {0};
    int32_t ret = DtlsGetCompleteHandshakeMsg(ctx, &hsMsgInfo, &msgLen);
    if (ret != HITLS_SUCCESS || msgLen == 0) {
        return ret;
    }
    const uint8_t *rawMsg = ctx->hsCtx->msgBuf;

    ret = DtlsCheckAndParseMsg(ctx, &hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* The HelloRequest message is not included. */
    ret = DtlsAppendHandshakeTranscript(ctx, &hsMsgInfo, rawMsg, msgLen);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(hsMsg);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17036, "VERIFY_Append fail");
    }
    ctx->hsCtx->hsMsg = hsMsg;
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(0, GET_VERSION_FROM_CTX(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo.rawMsg,
        hsMsgInfo.headerAndBodyLen, ctx, ctx->config.tlsConfig.msgArg);
    INDICATOR_StatusIndicate(ctx, ctx->isClient ? INDICATE_EVENT_STATE_CONNECT_LOOP : INDICATE_EVENT_STATE_ACCEPT_LOOP,
        INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_DTLS12
static int32_t DtlsTryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    memset(&hsMsg, 0, sizeof(HS_Msg));
    if (ctx->hsCtx->hsMsg == NULL) {
        ret = DtlsReadAndParseHandshakeMsg(ctx, &hsMsg);
        if (ret != HITLS_SUCCESS || ctx->hsCtx->hsMsg == NULL) {
            return ret;
        }
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_A;
    }

    ret = ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
    return CheckHsMsg(ctx, &hsMsg, ret);
}
#endif /* HITLS_TLS_PROTO_DTLS12 */

#ifdef HITLS_TLS_PROTO_DTLS13
static int32_t Dtls13TryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    (void)memset(&hsMsg, 0, sizeof(HS_Msg));
    if (ctx->hsCtx->hsMsg == NULL) {
        bool isTryRecvAnyMsg = ctx->hsCtx->state == TRY_RECV_MSG;
        ret = DtlsReadAndParseHandshakeMsg(ctx, &hsMsg);
        if (ret != HITLS_SUCCESS) {
            if (isTryRecvAnyMsg && (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
                (ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG && REC_GetUnexpectedMsgType(ctx) != REC_TYPE_ALERT))) {
                return HS_ChangeState(ctx, TLS_CONNECTED);
            }
            return ret;
        }
        if (ctx->hsCtx->hsMsg == NULL) {
            if (isTryRecvAnyMsg) {
                return HS_ChangeState(ctx, TLS_CONNECTED);
            }
            return HITLS_SUCCESS;
        }
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_A;
    }

    if (ctx->hsCtx->state == TRY_RECV_HELLO_VERIFY_REQUEST) {
#ifdef HITLS_TLS_PROTO_DTLS12
        ret = ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
#else
        ret = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
#endif
    } else {
        ret = Tls13ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
    }
    return CheckHsMsg(ctx, &hsMsg, ret);
}
#endif /* HITLS_TLS_PROTO_DTLS13 */
#endif /* HITLS_TLS_PROTO_DATAGRAM */

int32_t HandleResult(TLS_Ctx *ctx, int32_t ret)
{
    if (ret != HITLS_SUCCESS) {
        if (ctx->method.getAlertFlag(ctx)) {
            /* The alert has been processed. The handshake should be terminated. */
            return ret;
        }
        if (ret == HITLS_REC_NORMAL_RECV_DISORDER_MSG) {
            /* App messages and finished messages are out of order. The handshake proceeds. */
            return HITLS_SUCCESS;
        }
        if ((ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) &&
            REC_GetUnexpectedMsgType(ctx) == REC_TYPE_CHANGE_CIPHER_SPEC) {
            /* The CCS message is received. The handshake proceeds. */
            return HITLS_SUCCESS;
        }
        if ((ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) && REC_GetUnexpectedMsgType(ctx) == REC_TYPE_ACK) {
            return HITLS_SUCCESS;
        }
        /* Other errors are returned */
    }
    return ret;
}

int32_t HS_RecvMsgProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_FLIGHT
    /* If isFlightTransmitEnable is enabled, the handshake information stored in the bUio needs to be sent when the
     * receiving status is changed. */
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        ret = REC_FlightTransmit(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_FLIGHT */
    uint32_t version = GET_VERSION_FROM_CTX(ctx);

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS
        case HITLS_VERSION_TLS12:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#if defined(HITLS_TLS_PROTO_DTLS12)
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                ret = DtlsTryRecvHandShakeMsg(ctx);
                break;
            }
#endif
#endif /* HITLS_TLS_PROTO_TLCP11 */
#ifdef HITLS_TLS_PROTO_TLS_BASIC
            ret = Tls12TryRecvHandShakeMsg(ctx);
            break;
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
        case HITLS_VERSION_TLS13:
            ret = Tls13TryRecvHandShakeMsg(ctx);
            break;
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_PROTO_TLS */
#ifdef HITLS_TLS_PROTO_DTLS13
        case HITLS_VERSION_DTLS13:
            ret = Dtls13TryRecvHandShakeMsg(ctx);
            break;
#endif /* HITLS_TLS_PROTO_DTLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            ret = DtlsTryRecvHandShakeMsg(ctx);
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15352, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Handshake state recv error: unsupport TLS version.", 0, 0, 0, 0);
            return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }
    return HandleResult(ctx, ret);
}

#ifdef HITLS_TLS_PROTO_DTLS12
int32_t HS_DtlsRecvClientHello(TLS_Ctx *ctx)
{
    return DtlsTryRecvHandShakeMsg(ctx);
}
#endif /* HITLS_TLS_PROTO_DTLS12 */
