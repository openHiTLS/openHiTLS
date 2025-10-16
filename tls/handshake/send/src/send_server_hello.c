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
#ifdef HITLS_TLS_HOST_SERVER
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "session_mgr.h"
#include "hs_verify.h"
#include "transcript_hash.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"
#include "hs_kx.h"
#include "config_type.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
#ifdef HITLS_TLS_FEATURE_SESSION
static int32_t ServerPrepareSessionId(TLS_Ctx *ctx)
{
    /* Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    hsCtx->sessionId = (uint8_t *)BSL_SAL_Calloc(1u, HITLS_SESSION_ID_MAX_SIZE);
    if (hsCtx->sessionId == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15546, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "session Id malloc fail.", 0,
            0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    if (ctx->negotiatedInfo.isResume == false) {
        HITLS_SESS_CACHE_MODE sessCacheMode = SESSMGR_GetCacheMode(ctx->globalConfig->sessMgr);
        bool needSessionId = ((sessCacheMode & HITLS_SESS_CACHE_SERVER) != 0) &&
            (!ctx->negotiatedInfo.isTicket);
        if (needSessionId) {
            hsCtx->sessionIdSize = HITLS_SESSION_ID_MAX_SIZE;
            int32_t ret = SESSMGR_GernerateSessionId(ctx, hsCtx->sessionId, hsCtx->sessionIdSize);
            if (ret != HITLS_SUCCESS) {
                BSL_SAL_FREE(hsCtx->sessionId);
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
                return ret;
            }
        } else {
            /* If session ID resumption is not supported, the session ID is not sent when the first connection
             * is established */
            BSL_SAL_FREE(hsCtx->sessionId);
            hsCtx->sessionIdSize = 0;
        }
    } else {
        /* If the session is resumed, obtain the session ID from the session.
         * In the session ticket resumption mode, the session ID may not be obtained. Therefore, the return value is
         * not checked */
        hsCtx->sessionIdSize = HITLS_SESSION_ID_MAX_SIZE;
        HITLS_SESS_GetSessionId(ctx->session, hsCtx->sessionId, &hsCtx->sessionIdSize);
        if (hsCtx->sessionIdSize == 0) {
            BSL_SAL_FREE(hsCtx->sessionId);
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION */
static int32_t ServerChangeStateAfterSendHello(TLS_Ctx *ctx)
{
#ifdef HITLS_TLS_FEATURE_SESSION
    int32_t ret = HITLS_SUCCESS;
    if (ctx->negotiatedInfo.isResume == true) {
        ret = HS_ResumeKeyEstablish(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        if (ctx->negotiatedInfo.isTicket) {
            return HS_ChangeState(ctx, TRY_SEND_NEW_SESSION_TICKET);
        }
        return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    /* Check whether the server sends the certificate message. If the server does not need to send the certificate
     * message, update the status to the server key exchange */
    if (IsNeedCertPrepare(&ctx->negotiatedInfo.cipherSuiteInfo) == false) {
#ifdef HITLS_TLS_FEATURE_PSK
        /* There are multiple possible jumps after the ServerHello in the plain PSK negotiation */
        if (ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_PSK) {
            /* Special: If the server does not send the certificate and the plain PSK negotiation mode is used, the
             * system determines whether to send the SKE by checking whether the hint exists. There are multiple
             * redirection scenarios. */
            /* In the scenario of RSA PSK negotiation, whether SKE messages are sent depends on the existence of hints.
             * If RSA is used, the certificate sending phase is entered. The SKE status transition is not performed here
             */
            if (ctx->config.tlsConfig.pskIdentityHint != NULL) {
                return HS_ChangeState(ctx, TRY_SEND_SERVER_KEY_EXCHANGE);
            }
            return HS_ChangeState(ctx, TRY_SEND_SERVER_HELLO_DONE);
        }
#endif /* HITLS_TLS_FEATURE_PSK */
        return HS_ChangeState(ctx, TRY_SEND_SERVER_KEY_EXCHANGE);
    }
    return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
}
#if defined(HITLS_TLS_PROTO_TLS13) && defined(HITLS_TLS_PROTO_TLS_BASIC)
static int32_t DowngradeServerRandom(TLS_Ctx *ctx)
{
    /* Obtain server information */
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    uint32_t downgradeRandomLen = 0;
    uint32_t offset = 0;
    /* Obtain the random part to be rewritten */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS12) {
        const uint8_t *downgradeRandom = HS_GetTls12DowngradeRandom(&downgradeRandomLen);
        /* Some positions need to be rewritten to obtain random */
        offset = HS_RANDOM_SIZE - downgradeRandomLen;
        /* Rewrite the last eight bytes of the random */
        ret = memcpy_s(hsCtx->serverRandom + offset, HS_RANDOM_DOWNGRADE_SIZE, downgradeRandom, downgradeRandomLen);
    }
    return ret;
}
#endif /* HITLS_TLS_PROTO_TLS13 && HITLS_TLS_PROTO_TLS_BASIC */
int32_t ServerSendServerHelloProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Obtain server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /* Determine whether to pack a message */
    if (hsCtx->msgLen == 0) {
#ifdef HITLS_TLS_FEATURE_SESSION
        ret = ServerPrepareSessionId(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
#endif
        ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), hsCtx->serverRandom, HS_RANDOM_SIZE);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15548, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get server random error.", 0, 0, 0, 0);
            return ret;
        }
#if defined(HITLS_TLS_PROTO_TLS13) && defined(HITLS_TLS_PROTO_TLS_BASIC)
        TLS_Config *tlsConfig = &ctx->config.tlsConfig;
        /* If TLS 1.3 is supported but an earlier version is negotiated, the last eight bits of the random number need
         * to be rewritten */
        if (tlsConfig->maxVersion == HITLS_VERSION_TLS13) {
            ret = DowngradeServerRandom(ctx);
            if (ret != EOK) {
                BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16248, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "copy down grade random fail.", 0, 0, 0, 0);
                return HITLS_MEMCPY_FAIL;
            }
        }
#endif /* HITLS_TLS_PROTO_TLS13 && HITLS_TLS_PROTO_TLS_BASIC */
        /* Set the verify information. */
        ret = VERIFY_SetHash(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
            hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15549, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "set verify info fail.",
                0, 0, 0, 0);
            return ret;
        }

        ret = HS_PackMsg(ctx, SERVER_HELLO);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15550, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack server hello msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15551, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "send server hello msg success.",
        0, 0, 0, 0);

    return ServerChangeStateAfterSendHello(ctx);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13ServerPrepareKeyShare(TLS_Ctx *ctx)
{
    KeyShareParam *keyShare = &ctx->hsCtx->kxCtx->keyExchParam.share;
    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;
    if ((kxCtx->peerPubkey == NULL) || /* If the peer public key is empty, keyshare does not need to be packed */
        (kxCtx->key != NULL)) { /* key is not empty, it indicates that the keyshare has been calculated and does not
                                   need to be calculated again */
        return HITLS_SUCCESS;
    }
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(&ctx->config.tlsConfig, keyShare->group);
    if (groupInfo == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16243, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "group info not found", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }
    if (groupInfo->isKem) {
        return HITLS_SUCCESS;
    }
    HITLS_ECParameters curveParams = {
        .type = HITLS_EC_CURVE_TYPE_NAMED_CURVE,
        .param.namedcurve = keyShare->group,
    };
    HITLS_CRYPT_Key *key = NULL;
     /* The ecdhe and dhe groups can invoke the same interface to generate keys. */
    key = SAL_CRYPT_GenEcdhKeyPair(ctx, &curveParams);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15552, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client generate key share key pair error.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
    }
    kxCtx->key = key;

    return HITLS_SUCCESS;
}

int32_t Tls13ServerSendServerHelloProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Obtain server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    /* Determine whether to pack a message */
    if (hsCtx->msgLen == 0) {
        ret = Tls13ServerPrepareKeyShare(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), hsCtx->serverRandom, HS_RANDOM_SIZE);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15553, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get server random error.", 0, 0, 0, 0);
            return ret;
        }

        /* Set the verify information */
        ret = VERIFY_SetHash(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
            hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15554, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "set verify info fail.",
                0, 0, 0, 0);
            return ret;
        }

        /* Server secret derivation */
        ret = HS_TLS13CalcServerHelloProcessSecret(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16190, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Derive-Sevret failed.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            return ret;
        }

        ret = HS_PackMsg(ctx, SERVER_HELLO);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15555, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack tls1.3 server hello msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_TLS13DeriveHandshakeTrafficSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15556, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 server hello msg success.", 0, 0, 0, 0);

    /* In the middlebox mode, If the scenario is not hrr, the CCS needs to be sent before the EE */
    if (ctx->config.tlsConfig.isMiddleBoxCompat && !ctx->hsCtx->haveHrr) {
        ctx->hsCtx->ccsNextState = TRY_SEND_ENCRYPTED_EXTENSIONS;
        return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
    }
    return HS_ChangeState(ctx, TRY_SEND_ENCRYPTED_EXTENSIONS);
}

int32_t Tls13ServerSendHelloRetryRequestProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    hsCtx->haveHrr = true; /* update state */

    /* Check whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        uint32_t hrrRandomLen = 0;
        const uint8_t *hrrRandom = HS_GetHrrRandom(&hrrRandomLen);
        if (memcpy_s(hsCtx->serverRandom, HS_RANDOM_SIZE, hrrRandom, hrrRandomLen) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15557, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "copy hello retry request random fail.", 0, 0, 0, 0);
            return HITLS_MEMCPY_FAIL;
        }

        /* Pack the message. The hello retry request is assembled in the server hello format */
        ret = HS_PackMsg(ctx, SERVER_HELLO);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15558, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack tls1.3 hello retry request msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15559, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 hello retry request msg success.", 0, 0, 0, 0);

    /* RFC 8446 4.4.1. Send the Hello Retry Request message and construct the Transcript-Hash data */
    ret = VERIFY_HelloRetryRequestVerifyProcess(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (!ctx->config.tlsConfig.isMiddleBoxCompat) {
        return HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
    }
    /* In middlebox mode, the peer sends CCS messages. Set this parameter to allow receiving CCS messages */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
    /* In middlebox mode, the server sends the CCS immediately after sending the hrr */
    ctx->hsCtx->ccsNextState = TRY_RECV_CLIENT_HELLO;
    return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER */