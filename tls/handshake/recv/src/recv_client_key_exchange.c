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
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_kx.h"
#include "hs_msg.h"
#include "hs_verify.h"
#include "hs_common.h"
#include "securec.h"
#include "bsl_sal.h"
#ifdef HITLS_TLS_FEATURE_PSK
static int32_t RetriveServerPsk(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg)
{
    uint8_t psk[HS_PSK_MAX_LEN] = {0};

    if ((!IsPskNegotiation(ctx)) == true) {
        return HITLS_SUCCESS;
    }

    if (ctx->config.tlsConfig.pskServerCb == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID17068, "unregistered pskServerCb");
    }

    uint32_t pskUsedLen = ctx->config.tlsConfig.pskServerCb(ctx, clientKxMsg->pskIdentity, psk, HS_PSK_MAX_LEN);
    if (pskUsedLen == 0 || pskUsedLen > HS_PSK_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_PSK_LEN);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MSG_HANDLE_ILLEGAL_PSK_LEN, BINLOG_ID17069, "pskUsedLen incorrect");
    }

    if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
        ctx->hsCtx->kxCtx->pskInfo = (PskInfo *)BSL_SAL_Calloc(1u, sizeof(PskInfo));
        if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
            (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17070, "Calloc fail");
        }
    }

    uint8_t *tmpIdentity = NULL;
    if (clientKxMsg->pskIdentity != NULL) {
        tmpIdentity = (uint8_t *)BSL_SAL_Calloc(1u, (clientKxMsg->pskIdentitySize + 1) * sizeof(uint8_t));
        if (tmpIdentity == NULL) {
            (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17071, "Calloc fail");
        }
        (void)memcpy_s(tmpIdentity, clientKxMsg->pskIdentitySize + 1, clientKxMsg->pskIdentity,
            clientKxMsg->pskIdentitySize);
        BSL_SAL_FREE(ctx->hsCtx->kxCtx->pskInfo->identity);
        ctx->hsCtx->kxCtx->pskInfo->identity = tmpIdentity;
        ctx->hsCtx->kxCtx->pskInfo->identityLen = clientKxMsg->pskIdentitySize;
    }

    uint8_t *tmpPsk = (uint8_t *)BSL_SAL_Dump(psk, pskUsedLen);
    if (tmpPsk == NULL) {
        (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17072, "Dump fail");
    }

    BSL_SAL_FREE(ctx->hsCtx->kxCtx->pskInfo->psk);
    ctx->hsCtx->kxCtx->pskInfo->psk = tmpPsk;
    ctx->hsCtx->kxCtx->pskInfo->pskLen = pskUsedLen;

    /* sensitive info cleanup */
    (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PSK */
static int32_t ProcessClientKxMsg(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg)
{
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_PSK
    ret = RetriveServerPsk(ctx, clientKxMsg);
    if (ret != HITLS_SUCCESS) {
        // log here
        return ret;
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    /** Process the key exchange packet from the client */
    switch (hsCtx->kxCtx->keyExchAlgo) {
#ifdef HITLS_TLS_SUITE_KX_ECDHE
        case HITLS_KEY_EXCH_ECDHE: /* ECDHE of TLCP is also in this branch */
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = HS_ProcessClientKxMsgEcdhe(ctx, clientKxMsg);
            break;
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = HS_ProcessClientKxMsgDhe(ctx, clientKxMsg);
            break;
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_RSA
        case HITLS_KEY_EXCH_RSA:
        case HITLS_KEY_EXCH_RSA_PSK:
            ret = HS_ProcessClientKxMsgRsa(ctx, clientKxMsg);
            break;
#endif /* HITLS_TLS_SUITE_KX_RSA */
        case HITLS_KEY_EXCH_PSK:
            ret = HITLS_SUCCESS;
            break;
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_KEY_EXCH_ECC:
            ret = HS_ProcessClientKxMsgSm2(ctx, clientKxMsg);
            break;
#endif
        default:
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17073, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "unknow keyExchAlgo", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG);
            ret = HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG;
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            break;
    }

    return ret;
}

static int32_t GenerateKeyMaterial(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = HITLS_SUCCESS;
    /** Obtain the server information */
    const ClientKeyExchangeMsg *clientKxMsg = &msg->body.clientKeyExchange;

    ret = ProcessClientKxMsg(ctx, clientKxMsg);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15820, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server process client key exchange msg fail.", 0, 0, 0, 0);
        return ret;
    }

    ret = HS_GenerateMasterSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15821, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server generate master secret fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    /** Server secret derivation */
    ret = HS_KeyEstablish(ctx, ctx->isClient);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15822, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server key establish fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)
    ret = HS_SetSctpAuthKey(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17074, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
            "SetSctpAuthKey fail", 0, 0, 0, 0);
    }
#endif /* HITLS_TLS_PROTO_DTLS12 */
    return ret;
}

int32_t ServerRecvClientKxProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = HITLS_SUCCESS;
    /** Obtain the server information */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    ret = GenerateKeyMaterial(ctx, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /**
     * According to RFC 5246 7.4.8: This message (referred to here as client cert verify) is only sent following
     * a client certificate that has signing capability.
     * In the case of dual-ended parity
     * 1) If the peer certificate is not empty, the system calculates the signature and switches to the cert verify
     * state. 2) If the peer certificate is empty, the client sends an empty certificate message after the server sends
     * a cert request message, In this case, the client does not send the cert verify message. Therefore, the client
     * needs to switch to the state of receiving the Finish message.
     */
    if (hsCtx->isNeedClientCert && hsCtx->peerCert != NULL) {
        return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_VERIFY);
    }
    ret = VERIFY_CalcVerifyData(ctx, true, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15823, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server Calculate client finished data error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_SERVER */