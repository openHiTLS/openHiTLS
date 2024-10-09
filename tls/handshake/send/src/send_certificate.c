/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "hs_kx.h"
#include "pack.h"
#include "send_process.h"

int32_t SendCertificateProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        /* Only the client can send a certificate message with an empty certificate */
        if ((ctx->isClient == false) && (SAL_CERT_GetCurrentCert(mgrCtx) == NULL)) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15760, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "no certificate could be used in server.", 0, 0, 0, 0);
            return HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE;
        }

        ret = HS_PackMsg(ctx, CERTIFICATE, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15761, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack certificate msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15762, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send certificate msg success.", 0, 0, 0, 0);

    if (ctx->isClient) {
        return HS_ChangeState(ctx, TRY_SEND_CLIENT_KEY_EXCHANGE);
    }
    if (IsNeedServerKeyExchange(ctx) == true) {
        return HS_ChangeState(ctx, TRY_SEND_SERVER_KEY_EXCHANGE);
    }
    /* The server sends CertificateRequest only when the isSupportClientVerify mode is enabled */
    if (ctx->config.tlsConfig.isSupportClientVerify) {
        /* isSupportClientOnceVerify specifies whether the CR is sent only in the initial handshake phase. */
        /* The value of certReqSendTime indicates the number of sent CR messages. If the value of certReqSendTime in the
         * renegotiation phase is 0 and isSupportClientOnceVerify is enabled, the CR messages will not be sent. */
        if (ctx->negotiatedInfo.certReqSendTime < 1 || !(ctx->config.tlsConfig.isSupportClientOnceVerify)) {
            return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
        }
    }
    return HS_ChangeState(ctx, TRY_SEND_SERVER_HELLO_DONE);
}

int32_t Tls13ClientSendCertificateProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        /** In the middlebox scenario, if the client does not send the hrr message, a CCS message needs to be sent
         * before the certificate */
        if (!ctx->hsCtx->haveHrr && ctx->phaState != PHA_REQUESTED) {
            ret = ctx->method.sendCCS(ctx);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
        if (ctx->phaState != PHA_REQUESTED) {
            /* CCS messages cannot be encrypted. Therefore, you need to activate the
                sending key of the client after sending CCS messages. */
            uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
            if (hashLen == 0) {
                return HITLS_CRYPT_ERR_DIGEST;
            }
            ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->clientHsTrafficSecret, hashLen, true);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }

        ret = HS_PackMsg(ctx, CERTIFICATE, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15763, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack tls1.3 client certificate msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15764, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 client certificate msg success.", 0, 0, 0, 0);

    /* If the certificate is empty, the certificate verify message does not need to be sent. */
    if (SAL_CERT_GetCurrentCert(ctx->config.tlsConfig.certMgrCtx) == NULL) {
        return HS_ChangeState(ctx, TRY_SEND_FINISH);
    }
    return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_VERIFY);
}

int32_t Tls13ServerSendCertificateProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        /* The server cannot send an empty certificate message */
        if (SAL_CERT_GetCurrentCert(ctx->config.tlsConfig.certMgrCtx) == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15765, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "no certificate could be used in server.", 0, 0, 0, 0);
            return HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE;
        }

        ret = HS_PackMsg(ctx, CERTIFICATE, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15766, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack server tls1.3 certificate msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15767, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 server certificate msg success.", 0, 0, 0, 0);

    return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_VERIFY);
}
