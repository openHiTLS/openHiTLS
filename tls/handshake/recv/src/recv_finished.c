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
#include "securec.h"
#include "hitls_build.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "rec.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "recv_process.h"
#include "hs_kx.h"
#ifdef HITLS_TLS_FEATURE_SESSION
#include "session_mgr.h"
#endif
#ifdef HITLS_TLS_FEATURE_SESSION
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
static int32_t SetSessionTicketInfo(TLS_Ctx *ctx)
{
    int32_t ret = 0;
    HS_Ctx *hsCtx = ctx->hsCtx;

    BSL_SAL_FREE(hsCtx->sessionId);
    hsCtx->sessionIdSize = 0;

    if (hsCtx->ticketSize == 0) {
        return HITLS_SUCCESS;
    }

    if (ctx->isClient) {
        uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE];
        ret = SESSMGR_GernerateSessionId(ctx, sessionId, HITLS_SESSION_ID_MAX_SIZE);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        HITLS_SESS_SetSessionId(ctx->session, sessionId, HITLS_SESSION_ID_MAX_SIZE);
    }

    ret = SESS_SetTicket(ctx->session, hsCtx->ticket, hsCtx->ticketSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID15970, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Session set ticket fail.", 0, 0, 0, 0);
    }
    return ret;
}
#endif

int32_t SetSessionTicketAndSessionID(TLS_Ctx *ctx, bool isTls13)
{
    int32_t ret = HITLS_SUCCESS;
    (void)ctx;
    (void)isTls13;
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    if (ctx->negotiatedInfo.isTicket && !isTls13) {
        ret = SetSessionTicketInfo(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif

#ifdef HITLS_TLS_FEATURE_SESSION_ID
    /* The default session length is 0. If the session length is not 0, insert the session length */
    if (ctx->hsCtx->sessionIdSize != 0 && !isTls13) {
        /* The session generated during the finish operation of TLS 1.3 cannot be used for session resume. In this
        * case, sessionId is blocked so that the HITLS_SESS_IsResumable return value is false */
        ret = HITLS_SESS_SetSessionId(ctx->session, ctx->hsCtx->sessionId, ctx->hsCtx->sessionIdSize);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    ret = HITLS_SESS_SetSessionIdCtx(
        ctx->session, ctx->config.tlsConfig.sessionIdCtx, ctx->config.tlsConfig.sessionIdCtxSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
    return ret;
}

static int32_t SessionConfig(TLS_Ctx *ctx)
{
    int32_t ret = 0;
    bool isTls13 = (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13);
    HS_Ctx *hsCtx = ctx->hsCtx;
    ret = SetSessionTicketAndSessionID(ctx, isTls13);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_FEATURE_SNI
    /* When the SNI negotiation is HITLS_ACCEPT_ERR_OK, save the client Hello server_name extension to the session
     * structure */
    if (ctx->negotiatedInfo.isSniStateOK && isTls13 == false) {
        ret = SESS_SetHostName(ctx->session, hsCtx->serverNameSize, hsCtx->serverName);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17076, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SetHostName fail", 0, 0, 0, 0);
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_SNI */
    (void)HITLS_SESS_SetProtocolVersion(ctx->session, ctx->negotiatedInfo.version);
    (void)HITLS_SESS_SetCipherSuite(ctx->session, ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite);

    uint32_t masterKeySize = MASTER_SECRET_LEN;
#ifdef HITLS_TLS_PROTO_TLS13
    if (isTls13) {
        masterKeySize = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (masterKeySize == 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17077, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "DigestSize fail", 0, 0, 0, 0);
            return HITLS_CRYPT_ERR_DIGEST;
        }
    }
#endif

    ret = HITLS_SESS_SetMasterKey(ctx->session, hsCtx->masterKey, masterKeySize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HITLS_SESS_SetHaveExtMasterSecret(ctx->session, (uint8_t)ctx->negotiatedInfo.isExtendedMasterSecret);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#if defined(HITLS_TLS_CONNECTION_INFO_NEGOTIATION) && defined(HITLS_TLS_FEATURE_SESSION)
    if (ctx->config.tlsConfig.isKeepPeerCert) {
        ret = SESS_SetPeerCert(ctx->session, hsCtx->peerCert, ctx->isClient);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        hsCtx->peerCert = NULL;
    }
#endif /* HITLS_TLS_CONNECTION_INFO_NEGOTIATION && HITLS_TLS_FEATURE_SESSION */

    return HITLS_SUCCESS;
}

int32_t HsSetSessionInfo(TLS_Ctx *ctx)
{
    int32_t ret = 0;
    TLS_SessionMgr *sessMgr = NULL;
    if (ctx->globalConfig != NULL) {
        sessMgr = ctx->globalConfig->sessMgr;
    }
    HITLS_SESS_CACHE_MODE mode = SESSMGR_GetCacheMode(sessMgr);
    if ((mode & HITLS_SESS_DISABLE_AUTO_CLEANUP) == 0) {
        SESSMGR_ClearTimeout(ctx->globalConfig, (uint64_t)BSL_SAL_CurrentSysTimeGet());
    }
    
    /* This parameter is not required for session multiplexing */
    if (ctx->negotiatedInfo.isResume == true) {
        return HITLS_SUCCESS;
    }

    HITLS_SESS_Free(ctx->session);

    ctx->session = HITLS_SESS_New();
    if (ctx->session == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15893, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Session malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    uint64_t timeout = SESSMGR_GetTimeout(sessMgr);
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    timeout = ctx->hsCtx->ticketLifetimeHint == 0 ? timeout : ctx->hsCtx->ticketLifetimeHint;
#endif
    HITLS_SESS_SetTimeout(ctx->session, timeout);
    ret = SessionConfig(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        return HITLS_SUCCESS;
    }
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
    /* The session cache does not store TLS1.3 sessions */
    if ((mode & HITLS_SESS_DISABLE_INTERNAL_STORE) == 0) {
        bool isStore =
            ctx->isClient == true ? (mode & HITLS_SESS_CACHE_CLIENT) != 0 : (mode & HITLS_SESS_CACHE_SERVER) != 0;
        SESSMGR_InsertSession(sessMgr, ctx->session, isStore);
        if (ctx->globalConfig != NULL && ctx->globalConfig->newSessionCb != NULL) {
            HITLS_SESS_UpRef(ctx->session);
            // It is convenient for users to take away and needs to be released by users
            if (ctx->globalConfig->newSessionCb(ctx, ctx->session) == 0) {
                /* If the user does not reference the session, the number of reference times decreases by 1 */
                HITLS_SESS_Free(ctx->session);
            }
        }
    }
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION */

int32_t CheckFinishedVerifyData(const FinishedMsg *finishedMsg, const uint8_t *verifyData, uint32_t verifyDataSize)
{
    if ((finishedMsg->verifyDataSize == 0u) || (verifyDataSize == 0u)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15737, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Finished data len cannot be zero.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN;
    }

    if (finishedMsg->verifyDataSize != verifyDataSize) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15738, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Finished data len unequal.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN;
    }

    if (memcmp(finishedMsg->verifyData, verifyData, verifyDataSize) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15739, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Finished data unequal.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL;
    }

    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_HOST_CLIENT
int32_t ClientRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = 0;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    VerifyCtx *verifyCtx = hsCtx->verifyCtx;
    const FinishedMsg *finished = &msg->body.finished;
    uint8_t verifyData[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataSize = MAX_DIGEST_SIZE;

    ret = VERIFY_GetVerifyData(verifyCtx, verifyData, &verifyDataSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15740, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client get server finished verify data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ret = CheckFinishedVerifyData(finished, verifyData, verifyDataSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15741, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client verify server finished data error.", 0, 0, 0, 0);
        if (ret == HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        } else {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
        }
        return HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL;
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    ret = HsSetSessionInfo(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15895, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set session information failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    /* CCS messages are not allowed to be received later. */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS_BASIC
int32_t Tls12ClientRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = ClientRecvFinishedProcess(ctx, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
        return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
    }

    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */

#ifdef HITLS_TLS_PROTO_DTLS12
int32_t DtlsClientRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
#ifdef HITLS_BSL_UIO_UDP
    if (ctx->preState == CM_STATE_TRANSPORTING && ctx->state == CM_STATE_HANDSHAKING) {
        int32_t ret = REC_RetransmitListFlush(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15888, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
            "recv post hs finished, send retransmit msg.", 0, 0, 0, 0);
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
#endif /* HITLS_BSL_UIO_UDP */
    int32_t ret = ClientRecvFinishedProcess(ctx, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_BSL_UIO_UDP
    /* Clear the retransmission queue */
    REC_RetransmitListClean(ctx->recCtx);
#endif /* HITLS_BSL_UIO_UDP */
    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
        return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
    }

    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13ClientRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = ClientRecvFinishedProcess(ctx, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_TLS13CalcServerFinishProcessSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17078, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CalcServerFinishProcessSecret fail", 0, 0, 0, 0);
        return ret;
    }

    /* Activate serverAppTrafficSecret to decrypt the App data sent by the server */
    uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    ret = HS_SwitchTrafficKey(ctx, ctx->serverAppTrafficSecret, hashLen, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17079, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SwitchTrafficKey fail", 0, 0, 0, 0);
        return ret;
    }

    if (ctx->hsCtx->isNeedClientCert) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
    }

    return HS_ChangeState(ctx, TRY_SEND_FINISH);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_CLIENT */

#ifdef HITLS_TLS_HOST_SERVER

int32_t ServerRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = 0;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    VerifyCtx *verifyCtx = hsCtx->verifyCtx;
    uint8_t verifyData[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataSize = MAX_DIGEST_SIZE;
    const FinishedMsg *finished = &msg->body.finished;

    ret = VERIFY_GetVerifyData(verifyCtx, verifyData, &verifyDataSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15742, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server get client finished verify data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ret = CheckFinishedVerifyData(finished, verifyData, verifyDataSize);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15743, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server verify client finished data error.", 0, 0, 0, 0);
        if (ret == HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
        } else {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        }
        return HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL;
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    ret = HsSetSessionInfo(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15897, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set session information failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS_BASIC
int32_t Tls12ServerRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = ServerRecvFinishedProcess(ctx, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }

    if (ctx->negotiatedInfo.isTicket == true) {
        return HS_ChangeState(ctx, TRY_SEND_NEW_SESSION_TICKET);
    }

    return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_DTLS12
int32_t DtlsServerRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
#ifdef HITLS_BSL_UIO_UDP
    if (ctx->preState == CM_STATE_TRANSPORTING && ctx->state == CM_STATE_HANDSHAKING) {
        int32_t ret = REC_RetransmitListFlush(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15885, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
            "recv post hs finished, send retransmit msg.", 0, 0, 0, 0);
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
#endif /* HITLS_BSL_UIO_UDP */
    int32_t ret = ServerRecvFinishedProcess(ctx, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_BSL_UIO_UDP
    /* Clear the retransmission queue */
    REC_RetransmitListClean(ctx->recCtx);
#endif /* HITLS_BSL_UIO_UDP */
#ifdef HITLS_TLS_FEATURE_SESSION
    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    if (ctx->negotiatedInfo.isTicket == true) {
        return HS_ChangeState(ctx, TRY_SEND_NEW_SESSION_TICKET);
    }
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
    return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
}
#endif
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13ServerRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    /** CCS messages are not allowed to be received */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
    ctx->plainAlertForbid = true;

    int32_t ret = ServerRecvFinishedProcess(ctx, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_PHA
    if (ctx->phaState == PHA_REQUESTED) {
        ctx->phaState = PHA_EXTENSION;
    } else
#endif /* HITLS_TLS_FEATURE_PHA */
    {
        /* Switch Application Traffic Secret */
        uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        ret = HS_SwitchTrafficKey(ctx, ctx->clientAppTrafficSecret, hashLen, false);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17080, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SwitchTrafficKey fail", 0, 0, 0, 0);
            return ret;
        }

        ret = HS_TLS13DeriveResumptionMasterSecret(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
#ifdef HITLS_TLS_FEATURE_PHA
        if (ctx->phaState == PHA_EXTENSION && ctx->config.tlsConfig.isSupportClientVerify) {
            SAL_CRYPT_DigestFree(ctx->phaHash);
            ctx->phaHash = SAL_CRYPT_DigestCopy(ctx->hsCtx->verifyCtx->hashCtx);
            if (ctx->phaHash == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16176, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
                return HITLS_CRYPT_ERR_DIGEST;
            }
        }
#endif /* HITLS_TLS_FEATURE_PHA */
    }
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    /* When ticketNums is 0, no ticket is sent */
    if (ctx->hsCtx->sentTickets < ctx->config.tlsConfig.ticketNums) {
        return HS_ChangeState(ctx, TRY_SEND_NEW_SESSION_TICKET);
    }
#endif
    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER */