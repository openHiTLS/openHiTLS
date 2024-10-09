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
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "uio_base.h"
#include "rec.h"
#include "indicator.h"
#include "hs.h"
#include "change_cipher_spec.h"

struct CcsCtx {
    bool isReady;               /* Whether to allow receiving CCS */
    bool ccsRecvflag;           /* Indicates whether the CCS is received. */
    bool isAllowActiveCipher;   /* Flag for allow activating the receiving key suite */
    bool activeCipherFlag;      /* Flag for activating the receiving key suite */
};

bool CCS_IsRecv(const TLS_Ctx *ctx)
{
    return ctx->ccsCtx->ccsRecvflag;
}

void CCS_Recv(TLS_Ctx *ctx, const uint8_t *buf, uint32_t len)
{
    if (ctx->ccsCtx->isReady == false) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15612, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
            "Error: recv a unexpected change cipher spec message.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }

    /** The read length is abnormal. */
    if (len != 1u) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15613, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
            "the change cipher spec message length incorrect", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }

    /** Message exception. */
    if (buf[0] != 1u) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15614, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
            "the change cipher spec message incorrect", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }

    if (ctx->ccsCtx->ccsRecvflag == true && HS_GetVersion(ctx) != HITLS_VERSION_TLS13) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }

    if (ctx->ccsCtx->isAllowActiveCipher == true && ctx->ccsCtx->activeCipherFlag == false) {
        /** Enable key specification */
        if (REC_ActivePendingState(ctx, false) != HITLS_SUCCESS) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return;
        }
        ctx->ccsCtx->activeCipherFlag = true;
    }
    ctx->ccsCtx->ccsRecvflag = true;

    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_CHANGE_CIPHER_SPEC, buf, 1,
                              ctx, ctx->config.tlsConfig.msgArg);

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15615, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "got a change cipher spec message.", 0, 0, 0, 0);
    ctx->negotiatedInfo.isEncryptThenMacRead = ctx->negotiatedInfo.isEncryptThenMac;
    return;
}

int32_t CCS_Send(TLS_Ctx *ctx)
{
    int32_t ret;
    const uint8_t buf[1] = {1u};
    const uint32_t len = 1u;
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15616, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ctx is null.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

#ifndef HITLS_NO_DTLS12
    /*  rfc6083 4.7.  Handshake
        Before sending a ChangeCipherSpec message, all outstanding SCTP user
        messages MUST have been acknowledged by the SCTP peer and MUST NOT be
        revoked by the SCTP peer. */
    if ((BSL_UIO_GetTransportType(ctx->uio) == BSL_UIO_SCTP) &&
        (ctx->negotiatedInfo.isRenegotiation == true)) {
        bool isBuffEmpty = false;
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_SND_BUFF_IS_EMPTY, (int32_t)sizeof(isBuffEmpty), &isBuffEmpty);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_UIO_FAIL);
            return HITLS_UIO_FAIL;
        }
        /* When the SCTP sending buffer is not empty, the CCS cannot be sent. */
        if (isBuffEmpty != true) {
            BSL_ERR_PUSH_ERROR(HITLS_REC_NORMAL_IO_BUSY);
            return HITLS_REC_NORMAL_IO_BUSY;
        }
    }
#endif

    /** Write record */
    ret = REC_Write(ctx, REC_TYPE_CHANGE_CIPHER_SPEC, buf, len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    INDICATOR_MessageIndicate(1, HS_GetVersion(ctx), REC_TYPE_CHANGE_CIPHER_SPEC, buf, 1,
    ctx, ctx->config.tlsConfig.msgArg);

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15617, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "written a change cipher spec message.", 0, 0, 0, 0);
    return HITLS_SUCCESS;
}

int32_t CCS_Ctrl(TLS_Ctx *ctx, CCS_Cmd cmd)
{
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15618, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ctx is null.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    switch (cmd) {
        case CCS_CMD_RECV_READY:
            ctx->ccsCtx->isReady = true;
            break;
        case CCS_CMD_RECV_EXIT_READY:
            ctx->ccsCtx->isReady = false;
            ctx->ccsCtx->ccsRecvflag = false;
            ctx->ccsCtx->isAllowActiveCipher = false;
            ctx->ccsCtx->activeCipherFlag = false;
            break;
        case CCS_CMD_RECV_ACTIVE_CIPHER_SPEC:
            ctx->ccsCtx->isAllowActiveCipher = true;
            if (ctx->ccsCtx->ccsRecvflag == true && ctx->ccsCtx->activeCipherFlag == false) {
                /** Enable key specification */
                int32_t ret = REC_ActivePendingState(ctx, false);
                if (ret != HITLS_SUCCESS) {
                    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
                    return ret;
                }
                ctx->ccsCtx->activeCipherFlag = true;
            }
            break;
        default:
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15619, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ChangeCipherSpec error ctrl cmd", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_CCS_INVALID_CMD);
            return HITLS_CCS_INVALID_CMD;
    }
    return HITLS_SUCCESS;
}

int32_t CCS_Init(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15620, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ctx is null.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    // Prevent the ctx->ccsCtx from being initialized multiple times.
    if (ctx->ccsCtx != NULL) {
        return HITLS_SUCCESS;
    }
    ctx->ccsCtx = (struct CcsCtx *)BSL_SAL_Malloc(sizeof(struct CcsCtx));
    if (ctx->ccsCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15621, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ccs ctx malloc failed.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memset_s(ctx->ccsCtx, sizeof(struct CcsCtx), 0, sizeof(struct CcsCtx));
    return HITLS_SUCCESS;
}

void CCS_DeInit(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_FREE(ctx->ccsCtx);
    return;
}
