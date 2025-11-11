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
#include "tls.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "transcript_hash.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"
#include "hs_kx.h"
#include "hs_dtls_timer.h"

#ifdef HITLS_TLS_HOST_CLIENT
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t PrepareClientFinishedMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15357, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client Calculate client finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
        return ret;
    }

    ret = HS_PackMsg(ctx, FINISHED);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15358, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client pack finished msg error.", 0, 0, 0, 0);
    }
    return ret;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */

#ifdef HITLS_TLS_PROTO_TLS_BASIC

int32_t Tls12ClientSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* Determine whether the message needs to be packed. */
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
#ifdef HITLS_TLS_FEATURE_SESSION
    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    if (ctx->negotiatedInfo.isTicket == true) {
        return HS_ChangeState(ctx, TRY_RECV_NEW_SESSION_TICKET);
    }
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
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
#endif /* HITLS_TLS_PROTO_TLS_BASIC */

#ifdef HITLS_TLS_PROTO_DTLS12
static int32_t DtlsClientChangeStateAfterSendFinished(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_SESSION
    if (ctx->negotiatedInfo.isResume == true) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
#ifdef HITLS_BSL_UIO_UDP
        ret = HS_Start2MslTimer(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17133, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Start2MslTimer fail", 0, 0, 0, 0);
            return ret;
        }
#endif /* HITLS_BSL_UIO_UDP */
        return HS_ChangeState(ctx, TLS_CONNECTED);
    }
#endif /* HITLS_TLS_FEATURE_SESSION */

    ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15367, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client Calculate server finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
#ifdef HITLS_BSL_UIO_UDP
    ret = HS_StartTimer(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17134, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "StartTimer fail", 0, 0, 0, 0);
        return ret;
    }
#endif /* HITLS_BSL_UIO_UDP */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    if (ctx->negotiatedInfo.isTicket == true) {
        return HS_ChangeState(ctx, TRY_RECV_NEW_SESSION_TICKET);
    }
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);

    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}

int32_t DtlsClientSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = PrepareClientFinishedMsg(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)
    if (ctx->negotiatedInfo.isResume) {
        ret = HS_ActiveSctpAuthKey(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif
    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15370, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "client send finished msg success.", 0, 0, 0, 0);
    return DtlsClientChangeStateAfterSendFinished(ctx);
}
#endif /* HITLS_TLS_PROTO_DTLS12 */

#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13ClientSendFinishPostProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_PHA
    if (ctx->phaState == PHA_REQUESTED) {
        ctx->phaState = PHA_EXTENSION;
    } else
#endif /* HITLS_TLS_FEATURE_PHA */
    {
        /* switch Application Traffic Secret */
        uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (hashLen == 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17136, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "DigestSize fail", 0, 0, 0, 0);
            return HITLS_CRYPT_ERR_DIGEST;
        }
        ret = HS_SwitchTrafficKey(ctx, ctx->clientAppTrafficSecret, hashLen, true);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17137, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SwitchTrafficKey fail", 0, 0, 0, 0);
            return ret;
        }

        ret = HS_TLS13DeriveResumptionMasterSecret(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
#ifdef HITLS_TLS_FEATURE_PHA
        if (ctx->phaState == PHA_EXTENSION && ctx->config.tlsConfig.isSupportPostHandshakeAuth) {
            SAL_CRYPT_DigestFree(ctx->phaHash);
            ctx->phaHash = SAL_CRYPT_DigestCopy(ctx->hsCtx->verifyCtx->hashCtx);
            if (ctx->phaHash == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16177, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
                return HITLS_CRYPT_ERR_DIGEST;
            }
        }
#endif /* HITLS_TLS_FEATURE_PHA */
    }
    return HS_ChangeState(ctx, TLS_CONNECTED);
}

int32_t Tls13ClientSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        if ((ctx->config.tlsConfig.isMiddleBoxCompat && (!ctx->hsCtx->haveHrr)) && (!ctx->hsCtx->isNeedClientCert)) {
            /* In the middlebox scenario, if the client does not send the hrr message and the certificate does not need
             * to be sent, a CCS message needs to be sent before the finished message */
            ret = ctx->method.sendCCS(ctx);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }

        /* If the certificate of the client is sent, the key has been activated when the certificate is sent. You do not
         * need to activate the key again */
        if (!ctx->hsCtx->isNeedClientCert
#ifdef HITLS_TLS_FEATURE_PHA
                 && ctx->phaState != PHA_REQUESTED
#endif /* HITLS_TLS_FEATURE_PHA */
                 ) {
            /* The CCS message cannot be encrypted. Therefore, the sending key of the client must be activated
             * after the CCS message is sent */
            uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
            if (hashLen == 0) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17138, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "DigestSize fail", 0, 0, 0, 0);
                return HITLS_CRYPT_ERR_DIGEST;
            }
            ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->clientHsTrafficSecret, hashLen, true);
            if (ret != HITLS_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17139, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "SwitchTrafficKey fail", 0, 0, 0, 0);
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

        ret = HS_PackMsg(ctx, FINISHED);
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
#endif /* HITLS_TLS_PROTO_TLS13 */

#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_PROTO_TLS_BASIC
static int32_t CalcVerifyData(TLS_Ctx *ctx)
{
    int32_t ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15362, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server Calculate server finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    }
    return ret;
}

int32_t Tls12ServerSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = CalcVerifyData(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = HS_PackMsg(ctx, FINISHED);
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
#ifdef HITLS_TLS_FEATURE_SESSION
    if (ctx->negotiatedInfo.isResume == true) {
        ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15366, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server Calculate client finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
            return ret;
        }
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    /* No CCS messages can be received */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);

    return HS_ChangeState(ctx, TLS_CONNECTED);
}

#endif /* HITLS_TLS_PROTO_TLS_BASIC */


#ifdef HITLS_TLS_PROTO_DTLS12
static int32_t DtlsServerChangeStateAfterSendFinished(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    (void)ret;
#ifdef HITLS_TLS_FEATURE_SESSION
    if (ctx->negotiatedInfo.isResume == true) {
        /* Calculate the client verify data: used to verify the finished message of the client */
        ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15371, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server Calculate client finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
            return ret;
        }
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
#ifdef HITLS_BSL_UIO_UDP
        ret = HS_StartTimer(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17141, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "StartTimer fail", 0, 0, 0, 0);
            return ret;
        }
#endif /* HITLS_BSL_UIO_UDP */
        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    /* No CCS messages can be received */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
#ifdef HITLS_BSL_UIO_UDP
    ret = HS_Start2MslTimer(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17142, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Start2MslTimer fail", 0, 0, 0, 0);
        return ret;
    }
#endif /* HITLS_BSL_UIO_UDP */
    return HS_ChangeState(ctx, TLS_CONNECTED);
}

int32_t DtlsServerSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* Determine whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15372, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server Calculate server finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }

        ret = HS_PackMsg(ctx, FINISHED);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15373, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "server pack finished msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)
    if (!ctx->negotiatedInfo.isResume) {
        ret = HS_ActiveSctpAuthKey(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15374, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "server send finished msg success.", 0, 0, 0, 0);

    return DtlsServerChangeStateAfterSendFinished(ctx);
}
#endif /* HITLS_TLS_PROTO_DTLS12 */

#ifdef HITLS_TLS_PROTO_TLS13
static int32_t PrepareServerSendFinishedMsg(TLS_Ctx *ctx)
{
    int32_t ret = VERIFY_Tls13CalcVerifyData(ctx, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15378, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server calculate server finished data fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ret = HS_PackMsg(ctx, FINISHED);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15379, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server pack tls1.3 finished msg fail.", 0, 0, 0, 0);
    }
    return ret;
}

int32_t Tls13ServerSendFinishedProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* Determine whether the message needs to be packed */
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
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17145, "CalcServerFinishProcessSecret fail");
    }

    /* After the server sends the ServerFinish message, the clientTrafficSecret needs to be activated for decryption of
     * the received packet from the peer */
    uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (hashLen == 0) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CRYPT_ERR_DIGEST, BINLOG_ID17146, "DigestSize fail");
    }
    ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->clientHsTrafficSecret, hashLen, false);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17147, "SwitchTrafficKey fail");
    }

    /* Activating the local serverAppTrafficSecret-encrypted App Data */
    ret = HS_SwitchTrafficKey(ctx, ctx->serverAppTrafficSecret, hashLen, true);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17148, "SwitchTrafficKey fail");
    }

    if (ctx->hsCtx->isNeedClientCert) {
        return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
    }

    /* Calculate the client verify data */
    ret = VERIFY_Tls13CalcVerifyData(ctx, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15381, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server calculate client finished data fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER */