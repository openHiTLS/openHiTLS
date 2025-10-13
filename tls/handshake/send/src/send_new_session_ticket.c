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
#if defined(HITLS_TLS_FEATURE_SESSION_TICKET) && defined(HITLS_TLS_HOST_SERVER)
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "rec.h"
#include "hs_ctx.h"
#include "hs_kx.h"
#include "hs_common.h"
#include "session_mgr.h"
#include "pack.h"
#include "send_process.h"

#ifdef HITLS_TLS_PROTO_TLS13
#define HITLS_ONE_WEEK_SECONDS (604800)
#endif
#ifdef HITLS_TLS_PROTO_TLS_BASIC
int32_t SendNewSessionTicketProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    HS_Ctx *hsCtx = ctx->hsCtx;
    TLS_SessionMgr *sessMgr = ctx->globalConfig->sessMgr;

    /* determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        hsCtx->ticketLifetimeHint = (uint32_t)SESSMGR_GetTimeout(sessMgr);
        BSL_SAL_FREE(hsCtx->ticket);
        hsCtx->ticketSize = 0;
        ret = SESSMGR_EncryptSessionTicket(ctx, sessMgr, ctx->session, &hsCtx->ticket, &hsCtx->ticketSize);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16046, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SESSMGR_EncryptSessionTicket return fail when send new session ticket msg.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }
        /* assemble message */
        ret = HS_PackMsg(ctx, NEW_SESSION_TICKET);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15978, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack new session ticket msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    /* writing Handshake message */
    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15979, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send new session ticket msg success.", 0, 0, 0, 0);
    /* update the state machine */
    return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13TicketGenerateConfigSession(TLS_Ctx *ctx, HITLS_Session **sessionPtr,
    uint8_t *resumePsk, uint32_t hashLen)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_Session *newSession = NULL;
    HS_Ctx *hsCtx = ctx->hsCtx;
    newSession = SESS_Copy(ctx->session);
    if (newSession == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16050, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy session info failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
    }

    SESS_SetStartTime(newSession, (uint64_t)BSL_SAL_CurrentSysTimeGet());
    HITLS_SESS_SetTimeout(newSession, (uint64_t)hsCtx->ticketLifetimeHint);
    HITLS_SESS_SetMasterKey(newSession, resumePsk, hashLen);
    ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), (uint8_t *)&hsCtx->ticketAgeAdd, sizeof(hsCtx->ticketAgeAdd));
    if (ret != HITLS_SUCCESS) {
        HITLS_SESS_Free(newSession);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16047, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "generate ticket_age_add value fail.", 0, 0, 0, 0);
        return ret;
    }
    SESS_SetTicketAgeAdd(newSession, hsCtx->ticketAgeAdd);
    *sessionPtr = newSession;
    return HITLS_SUCCESS;
}

int32_t Tls13TicketGenerate(TLS_Ctx *ctx)
{
    int32_t ret;
    HITLS_Session *newSession = NULL;
    HS_Ctx *hsCtx = ctx->hsCtx;
    TLS_SessionMgr *sessMgr = ctx->globalConfig->sessMgr;

    uint64_t timeout = SESSMGR_GetTimeout(sessMgr);
    /* TLS1.3 timeout period cannot exceed 604800 seconds, that is, seven days. */
    if (timeout > HITLS_ONE_WEEK_SECONDS) {
        hsCtx->ticketLifetimeHint = HITLS_ONE_WEEK_SECONDS;
    } else {
        hsCtx->ticketLifetimeHint = (uint32_t)timeout;
    }

    BSL_SAL_FREE(hsCtx->ticket);
    hsCtx->ticketSize = 0;
    uint8_t resumePsk[MAX_DIGEST_SIZE] = {0};
    uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (hashLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17154, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "DigestSize err", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }

    uint8_t ticketNonce[sizeof(hsCtx->nextTicketNonce)] = {0};
    BSL_Uint64ToByte(hsCtx->nextTicketNonce, ticketNonce);
    ret = HS_TLS13DeriveResumePsk(ctx, ticketNonce, sizeof(ticketNonce), resumePsk, hashLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17155, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DeriveResumePsk fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        (void)memset_s(resumePsk, MAX_DIGEST_SIZE, 0, MAX_DIGEST_SIZE);
        return ret;
    }
    ret = Tls13TicketGenerateConfigSession(ctx, &newSession, resumePsk, hashLen);
    if (ret != HITLS_SUCCESS) {
        (void)memset_s(resumePsk, MAX_DIGEST_SIZE, 0, MAX_DIGEST_SIZE);
        return ret;
    }

    ret = SESSMGR_EncryptSessionTicket(ctx, sessMgr, newSession, &hsCtx->ticket, &hsCtx->ticketSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16051, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Encrypt Session Ticket failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        HITLS_SESS_Free(newSession);
        (void)memset_s(resumePsk, MAX_DIGEST_SIZE, 0, MAX_DIGEST_SIZE);
        return ret;
    }

    HITLS_SESS_Free(ctx->session);
    ctx->session = newSession;
    (void)memset_s(resumePsk, MAX_DIGEST_SIZE, 0, MAX_DIGEST_SIZE);
    return HITLS_SUCCESS;
}

int32_t Tls13SendNewSessionTicketProcess(TLS_Ctx *ctx)
{
    int32_t ret;
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* determine whether to assemble a message */
    if (hsCtx->msgLen == 0) {
        ret = Tls13TicketGenerate(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        /* assemble message */
        ret = HS_PackMsg(ctx, NEW_SESSION_TICKET);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16052, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack new session ticket msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    /* After the handshake message is written and sent successfully, hsCtx->msgLen is set to 0. */
    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16053, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send new session ticket msg success.", 0, 0, 0, 0);

    hsCtx->sentTickets++;
    hsCtx->nextTicketNonce++;
    /* When the value of ticketNums is greater than 0, a ticket is sent after the session is resumed. */
    if (hsCtx->sentTickets >= ctx->config.tlsConfig.ticketNums || ctx->negotiatedInfo.isResume) {
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
    return HS_ChangeState(ctx, TRY_SEND_NEW_SESSION_TICKET);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET && HITLS_TLS_HOST_SERVER */