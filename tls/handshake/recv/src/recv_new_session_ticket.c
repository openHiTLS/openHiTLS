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
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "hs_msg.h"
#include "hs_kx.h"
#include "session.h"

static int32_t UpdateTicket(TLS_Ctx *ctx, NewSessionTicketMsg *msg, uint8_t *psk, uint32_t pskSize)
{
    HITLS_Session *newSession = SESS_Copy(ctx->session);
    if (newSession == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16016, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy session info failed.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    SESS_SetStartTime(newSession, (uint64_t)BSL_SAL_CurrentSysTimeGet());
    HITLS_SESS_SetTimeout(newSession, msg->ticketLifetimeHint);

    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        SESS_SetTicketAgeAdd(newSession, msg->ticketAgeAdd);
        HITLS_SESS_SetMasterKey(newSession, psk, pskSize);
    }

    int32_t ret = SESS_SetTicket(newSession, msg->ticket, msg->ticketSize);
    if (ret != HITLS_SUCCESS) {
        HITLS_SESS_Free(newSession);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16017, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set ticket failed.", 0, 0, 0, 0);
        return ret;
    }

    HITLS_SESS_Free(ctx->session);
    ctx->session = newSession;

    /* The server may send multiple tickets. In this case, each ticket received will be notified to the user through
     * this callback, so that the client can obtain multiple sessions */
    if (ctx->globalConfig != NULL && ctx->globalConfig->newSessionCb != NULL) {
        HITLS_SESS_UpRef(newSession);  // It is convenient for users to take away and needs to be released by users
        if (ctx->globalConfig->newSessionCb(ctx, newSession) == 0) {
            /* If the user does not reference the session, the number of reference times decreases by 1 */
            HITLS_SESS_Free(newSession);
        }
    }

    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS_BASIC
int32_t Tls12ClientRecvNewSeesionTicketProcess(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    /* The processing of the msg is complete when the NewSeesionTick operation is performed */
    NewSessionTicketMsg *newSessionTicket = &hsMsg->body.newSessionTicket;

    if (newSessionTicket->ticketLifetimeHint != 0 && newSessionTicket->ticketSize != 0) {
        if (ctx->negotiatedInfo.isResume == true) {
            ret = UpdateTicket(ctx, newSessionTicket, NULL, 0);
            if (ret != HITLS_SUCCESS) {
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
                return ret;
            }
        } else {
            /* Saved in the context */
            hsCtx->ticketLifetimeHint = newSessionTicket->ticketLifetimeHint;
            hsCtx->ticketSize = newSessionTicket->ticketSize;
            hsCtx->ticket = newSessionTicket->ticket;

            newSessionTicket->ticket = NULL;
            newSessionTicket->ticketSize = 0;
        }
    }

    /* The server verify data needs to be calculated in advance */
    ret = VERIFY_CalcVerifyData(ctx, false, hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15971, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client Calculate server finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        (void)memset_s(hsCtx->masterKey, sizeof(hsCtx->masterKey), 0, sizeof(hsCtx->masterKey));
        return ret;
    }

    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);

    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13ClientRecvNewSessionTicketProcess(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if (!ctx->isClient) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID16018, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Unexpected msg: server recv new session ticket", HS_GetMsgTypeStr(hsMsg->type));
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    int32_t ret = HITLS_SUCCESS;
    NewSessionTicketMsg *msg = &hsMsg->body.newSessionTicket;

    /* If the value is 0, the ticket should be discarded immediately. After the TTO is backed up, the ctx->session field
     * is empty */
    if (msg->ticketLifetimeHint == 0 || ctx->session == NULL) {
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }

    uint8_t resumePsk[MAX_DIGEST_SIZE] = {0};
    uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (hashLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17081, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "DigestSize err", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    ret = HS_TLS13DeriveResumePsk(ctx, msg->ticketNonce, msg->ticketNonceSize, resumePsk, hashLen);
    if (ret != HITLS_SUCCESS) {
        (void)memset_s(resumePsk, MAX_DIGEST_SIZE, 0, MAX_DIGEST_SIZE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16015, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Derive resume psk failed.", 0, 0, 0, 0);
        return ret;
    }

    ret = UpdateTicket(ctx, msg, resumePsk, hashLen);
    (void)memset_s(resumePsk, MAX_DIGEST_SIZE, 0, MAX_DIGEST_SIZE);
    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */