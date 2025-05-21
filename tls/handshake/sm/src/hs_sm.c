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
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif /* HITLS_TLS_FEATURE_INDICATOR */
#include "transcript_hash.h"
#include "recv_process.h"
#include "hs_dtls_timer.h"

static int32_t HandshakeDone(TLS_Ctx *ctx)
{
    (void)ctx;
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_FLIGHT
    /* If isFlightTransmitEnable is enabled, the server CCS and Finish information stored in the bUio must be sent after
     * the handshake is complete */
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16109, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "fail to send the CCS and Finish message of server in bUio.", 0, 0, 0, 0);
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
#endif /* HITLS_TLS_FEATURE_FLIGHT */
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)

    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        return HITLS_SUCCESS;
    }

    bool isBuffEmpty = false;
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_SND_BUFF_IS_EMPTY, sizeof(isBuffEmpty), &isBuffEmpty);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17188, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
            "SCTP_SND_BUFF_IS_EMPTY fail, ret %d", ret, 0, 0, 0);
        return HITLS_UIO_SCTP_IS_SND_BUF_EMPTY_FAIL;
    }

    if (isBuffEmpty != true) {
        return HITLS_REC_NORMAL_IO_BUSY;
    }

    // This branch is entered only when the hello request is just sent.
    if (!ctx->negotiatedInfo.isRenegotiation && ctx->userRenego) {
        return HITLS_SUCCESS;
    }

    ret = HS_ActiveSctpAuthKey(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_DeletePreviousSctpAuthKey(ctx);
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_SCTP */

    return ret;
}

static bool IsHsSendState(HITLS_HandshakeState state)
{
    switch (state) {
        case TRY_SEND_HELLO_REQUEST:
        case TRY_SEND_CLIENT_HELLO:
        case TRY_SEND_HELLO_RETRY_REQUEST:
        case TRY_SEND_SERVER_HELLO:
        case TRY_SEND_HELLO_VERIFY_REQUEST:
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
        case TRY_SEND_KEY_UPDATE:
        /* PAKE Client States */
        case TLS_HS_CLIENT_STATE_SEND_PAKE_MESSAGE:
        /* PAKE Server States */
        case TLS_HS_SERVER_STATE_SEND_PAKE_MESSAGE:
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
        case TRY_RECV_HELLO_VERIFY_REQUEST:
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
        case TRY_RECV_KEY_UPDATE:
        case TRY_RECV_HELLO_REQUEST:
        /* PAKE Client States */
        case TLS_HS_CLIENT_STATE_RECV_PAKE_MESSAGE:
        /* PAKE Server States */
        case TLS_HS_SERVER_STATE_RECV_PAKE_MESSAGE:
            return true;
        default:
            break;
    }

    return false;
}

/*
 * Helper function to determine if the negotiated ciphersuite is PAKE-based.
 * This function needs to be implemented based on how CipherSuiteInfo is structured
 * and how PAKE kxAlg is identified.
 */
static bool IsPakeCipherSuiteNegotiated(const TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_NULL) {
        return false; // Or some other default if not yet negotiated
    }
    return (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_SPAKE2P);
}


int32_t HS_DoHandshake(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
#ifdef HITLS_TLS_FEATURE_INDICATOR
    int32_t eventType = (ctx->isClient) ? INDICATE_EVENT_STATE_CONNECT_EXIT : INDICATE_EVENT_STATE_ACCEPT_EXIT;
#endif /* HITLS_TLS_FEATURE_INDICATOR */
    while (hsCtx->state != TLS_CONNECTED) {
        if (IsHsSendState(hsCtx->state)) {
            // Add PAKE server send state to IsHsSendState if not already there
            // Example: case TLS_HS_SERVER_STATE_SEND_PAKE_MESSAGE: return true;
            if (hsCtx->state == TLS_HS_SERVER_STATE_SEND_PAKE_MESSAGE && !ctx->isClient) {
                 // This case should be handled by HS_SendMsgProcess
            }
            ret = HS_SendMsgProcess(ctx);
        } else if (IsHsRecvState(hsCtx->state)) {
            // Add PAKE server recv state to IsHsRecvState if not already there
            // Example: case TLS_HS_SERVER_STATE_RECV_PAKE_MESSAGE: return true;
             if (hsCtx->state == TLS_HS_SERVER_STATE_RECV_PAKE_MESSAGE && !ctx->isClient) {
                 // This case should be handled by HS_RecvMsgProcess
            }
            ret = HS_RecvMsgProcess(ctx);
        } else if (hsCtx->state == TLS_HS_CLIENT_STATE_PROCESS_SERVER_PAKE ||
                   hsCtx->state == TLS_HS_CLIENT_STATE_PAKE_COMPLETE ||
                   hsCtx->state == TLS_HS_SERVER_STATE_VERIFY_CLIENT_PAKE_MAC || // May be part of RecvFinished
                   hsCtx->state == TLS_HS_SERVER_STATE_PAKE_COMPLETE) {
            
            if (hsCtx->state == TLS_HS_CLIENT_STATE_PAKE_COMPLETE && ctx->isClient) {
                BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Client PAKE exchange complete. Transitioning to send CCS.");
                ret = HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC); 
            } else if (hsCtx->state == TLS_HS_SERVER_STATE_PAKE_COMPLETE && !ctx->isClient) {
                // Server PAKE is complete after sending its PAKE message and deriving keys.
                // It then waits for Client CCS/Finished. Client's PAKE MAC is verified in Finished.
                // So, this state implies server is ready for client's CCS.
                BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Server PAKE exchange complete. Transitioning to recv Client CCS.");
                ret = HS_ChangeState(ctx, TRY_RECV_CHANGE_CIPHER_SPEC);
            } else if (hsCtx->state == TLS_HS_CLIENT_STATE_PROCESS_SERVER_PAKE && ctx->isClient) {
                // This state is handled by HITLS_HS_ClientRecvPakeServerMessage, which transitions out.
                // If HS_DoHandshake sees it, it's likely an incomplete transition or error.
                BSL_LOG_WARN(BSL_MODULE_TLS_HS, "State PROCESS_SERVER_PAKE reached in HS_DoHandshake loop.");
                // Fall through to error or handle as intermediate step if Recv function doesn't transition.
            } else if (hsCtx->state == TLS_HS_SERVER_STATE_VERIFY_CLIENT_PAKE_MAC && !ctx->isClient) {
                // This state would be set after receiving Client Finished.
                // The actual verification logic is in ServerRecvFinishedProcess.
                // If successful, ServerRecvFinishedProcess transitions to SEND_CCS or CONNECTED.
                // So HS_DoHandshake should not typically see this state.
                BSL_LOG_WARN(BSL_MODULE_TLS_HS, "State VERIFY_CLIENT_PAKE_MAC reached in HS_DoHandshake loop.");
            }
        } else {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
            BSL_LOG_BINLOG_VARLEN(BINLOG_ID15884, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Handshake state unable to process, current state is %s.", HS_GetStateStr(hsCtx->state));
            ret = HITLS_MSG_HANDLE_STATE_ILLEGAL;
        }

        if (ret != HITLS_SUCCESS) {
#ifdef HITLS_TLS_FEATURE_INDICATOR
            INDICATOR_StatusIndicate(ctx, eventType, ret);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
            return ret;
        }
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_HANDSHAKE_DONE, INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */

    ret = HandshakeDone(ctx);
    if (ret != HITLS_SUCCESS) {
#ifdef HITLS_TLS_FEATURE_INDICATOR
        INDICATOR_StatusIndicate(ctx, eventType, ret);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_StatusIndicate(ctx, eventType, INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
int32_t HS_CheckKeyUpdateState(TLS_Ctx *ctx, uint32_t updateType)
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

#endif /* HITLS_TLS_FEATURE_KEY_UPDATE */

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t HS_CheckAndProcess2MslTimeout(TLS_Ctx *ctx)
{
    /* In non-UDP scenarios, the 2MSL timer timeout does not need to be checked */
    if ((ctx->hsCtx == NULL) || !BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        return HITLS_SUCCESS;
    }

    int32_t ret = HITLS_SUCCESS;
    bool isTimeout = false;
    ret = HS_IsTimeout(ctx, &isTimeout);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17189, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_IsTimeout fail", 0, 0, 0, 0);
        return ret;
    }

    /* If the retransmission queue times out, the retransmission queue is cleared and the hsCtx memory is released */
    if (isTimeout) {
        REC_RetransmitListClean(ctx->recCtx);
        HS_DeInit(ctx);
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */

#ifdef HITLS_TLS_FEATURE_PHA
int32_t HS_CheckPostHandshakeAuth(TLS_Ctx *ctx)
{
    int32_t ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17190, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CONN_Init fail", 0, 0, 0, 0);
        return ret;
    }
    HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
    SAL_CRYPT_DigestFree(ctx->hsCtx->verifyCtx->hashCtx);
    ctx->hsCtx->verifyCtx->hashCtx = SAL_CRYPT_DigestCopy(ctx->phaHash);
    if (ctx->hsCtx->verifyCtx->hashCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16179, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PHA */