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
#include "tls.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "transcript_hash.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"
#include "hs_kx.h"


int32_t PrepareClientFinishedMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;

    ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15357, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client Calculate client finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
        return ret;
    }

    ret = HS_PackMsg(ctx, FINISHED, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15358, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client pack finished msg error.", 0, 0, 0, 0);
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t Tls12ClientSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;

    /** Determine whether the message needs to be packed. */
    if (hsCtx->msgLen == 0) {
        ret = PrepareClientFinishedMsg(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15359, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client send finished msg error.", 0, 0, 0, 0);
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15360, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "client send finished msg success.", 0, 0, 0, 0);

    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }

    if (ctx->negotiatedInfo.isTicket == true) {
        return HS_ChangeState(ctx, TRY_RECV_NEW_SESSION_TICKET);
    }

    ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15361, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client Calculate server finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}

static int32_t CalcVerifyData(TLS_Ctx *ctx)
{
    int32_t ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15362, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server Calculate server finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    return HITLS_SUCCESS;
}

int32_t Tls12ServerSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /** Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = CalcVerifyData(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = HS_PackMsg(ctx, FINISHED, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15363, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack finished msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15364, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server send finished msg fail.", 0, 0, 0, 0);
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15365, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send finished msg success.", 0, 0, 0, 0);
    if (ctx->negotiatedInfo.isResume == true) {
        /* Calculate the client verify data: used to verify the finished message of the client */
        ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15366, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "tls12 server Calculate client finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
            return ret;
        }
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }
    /* No CCS messages can be received */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);

    return HS_ChangeState(ctx, TLS_CONNECTED);
}

#ifndef HITLS_NO_DTLS12
static int32_t DtlsClientChangeStateAfterSendFinished(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;

    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }

    ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15367, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client Calculate server finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    if (ctx->negotiatedInfo.isTicket == true) {
        return HS_ChangeState(ctx, TRY_RECV_NEW_SESSION_TICKET);
    }

    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);

    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
#endif

#ifndef HITLS_NO_DTLS12
int32_t DtlsClientSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;

    /** Determine whether the message needs to be packed */
    if (ctx->hsCtx->msgLen == 0) {
        ret = PrepareClientFinishedMsg(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15370, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "client send finished msg success.", 0, 0, 0, 0);
    return DtlsClientChangeStateAfterSendFinished(ctx);
}
#endif

#ifndef HITLS_NO_DTLS12
static int32_t DtlsServerChangeStateAfterSendFinished(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;

    if (ctx->negotiatedInfo.isResume == true) {
        /* Calculate the client verify data: used to verify the finished message of the client */
        ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15371, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "dtls server Calculate client finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);

        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }

    /* No CCS messages can be received */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif

#ifndef HITLS_NO_DTLS12
int32_t DtlsServerSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /** Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15372, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server Calculate server finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }

        ret = HS_PackMsg(ctx, FINISHED, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15373, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack finished msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15374, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send finished msg success.", 0, 0, 0, 0);

    return DtlsServerChangeStateAfterSendFinished(ctx);
}
#endif

static int32_t Tls13ClientSendFinishPostProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    if (ctx->phaState == PHA_REQUESTED) {
        ctx->phaState = PHA_EXTENSION;
    } else {
        /* switch Application Traffic Secret */
        uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (hashLen == 0) {
            return HITLS_CRYPT_ERR_DIGEST;
        }
        ret = HS_SwitchTrafficKey(ctx, ctx->clientAppTrafficSecret, hashLen, true);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = HS_TLS13DeriveResumptionMasterSecret(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        if (ctx->phaState == PHA_EXTENSION && ctx->config.tlsConfig.isSupportPostHandshakeAuth) {
            SAL_CRYPT_DigestFree(ctx->phaHash);
            ctx->phaHash = SAL_CRYPT_DigestCopy(ctx->hsCtx->verifyCtx->hashCtx);
            if (ctx->phaHash == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15407, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
                return HITLS_CRYPT_ERR_DIGEST;
            }
        }
    }
    return HS_ChangeState(ctx, TLS_CONNECTED);
}

int32_t Tls13ClientSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /** Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        if ((!ctx->hsCtx->haveHrr) && (!ctx->hsCtx->isNeedClientCert)) {
            /** In the middlebox scenario, if the client does not send the hrr message and the certificate does not need
             * to be sent, a CCS message needs to be sent before the finished message */
            ret = ctx->method.sendCCS(ctx);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }

        /* If the certificate of the client is sent, the key has been activated when the certificate is sent. You do not
         * need to activate the key again */
        if (!ctx->hsCtx->isNeedClientCert && ctx->phaState != PHA_REQUESTED) {
            /* The CCS message cannot be encrypted. Therefore, the sending key of the client must be activated
             * after the CCS message is sent */
            uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
            if (hashLen == 0) {
                return HITLS_CRYPT_ERR_DIGEST;
            }
            ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->clientHsTrafficSecret, hashLen, true);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }

        ret = VERIFY_Tls13CalcVerifyData(ctx, true);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15375, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client calculate client finished data fail.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }

        ret = HS_PackMsg(ctx, FINISHED, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15376, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client pack tls1.3 finished msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15377, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "client send tls1.3 finished msg success.", 0, 0, 0, 0);

    return Tls13ClientSendFinishPostProcess(ctx);
}

static int32_t PrepareServerSendFinishedMsg(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    int32_t ret = VERIFY_Tls13CalcVerifyData(ctx, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15378, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server calculate server finished data fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ret = HS_PackMsg(ctx, FINISHED, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15379, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server pack tls1.3 finished msg fail.", 0, 0, 0, 0);
        return ret;
    }
    return ret;
}

int32_t Tls13ServerSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /** Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = PrepareServerSendFinishedMsg(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15380, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send tls1.3 finished msg success.", 0, 0, 0, 0);

    ret = HS_TLS13CalcServerFinishProcessSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* After the server sends the ServerFinish message, the clientTrafficSecret needs to be activated for decryption of
     * the received message from the peer */
    uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->clientHsTrafficSecret, hashLen, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Activating the local serverAppTrafficSecret-encrypted App Data */
    ret = HS_SwitchTrafficKey(ctx, ctx->serverAppTrafficSecret, hashLen, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (ctx->hsCtx->isNeedClientCert) {
        return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
    }

    /** Calculate the client verify data */
    ret = VERIFY_Tls13CalcVerifyData(ctx, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15381, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server calculate client finished data fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
