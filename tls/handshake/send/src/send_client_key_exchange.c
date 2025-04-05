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
#ifdef HITLS_TLS_HOST_CLIENT
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs.h"
#include "hs_kx.h"
#include "hs_common.h"
#include "pack.h"
#include "send_process.h"
#ifdef HITLS_TLS_SUITE_KX_RSA
int32_t GenerateRsaPremasterSecret(TLS_Ctx *ctx)
{
    uint32_t offset = 0;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *kxCtx = hsCtx->kxCtx;
    uint8_t *preMasterSecret = kxCtx->keyExchParam.rsa.preMasterSecret;

    /* The First two bytes are the highest version supported by client */
    BSL_Uint16ToByte(ctx->negotiatedInfo.clientVersion, preMasterSecret);
    offset = sizeof(uint16_t);
    /* 46-byte secure random value */
    return SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), &preMasterSecret[offset], MASTER_SECRET_LEN - offset);
}
#endif /* HITLS_TLS_SUITE_KX_RSA */
#ifdef HITLS_TLS_PROTO_TLCP11
int32_t GenerateEccPremasterSecret(TLS_Ctx *ctx)
{
    uint32_t offset = 0;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *kxCtx = hsCtx->kxCtx;
    uint8_t *premasterSecret = kxCtx->keyExchParam.ecc.preMasterSecret;

    /* The First two bytes are the highest version supported by client */
    BSL_Uint16ToByte(ctx->config.tlsConfig.maxVersion, premasterSecret);
    offset = sizeof(uint16_t);
    /* 46-byte secure random value */
    return SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), &premasterSecret[offset], MASTER_SECRET_LEN - offset);
}
#endif

/* Operations required before packaging CKE */
static int32_t PackMsgPrepare(TLS_Ctx *ctx)
{
    int32_t ret = 0;
    HS_Ctx *hsCtx = ctx->hsCtx;
#ifdef HITLS_TLS_SUITE_KX_RSA
    if (hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_RSA || hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_RSA_PSK) {
        ret = GenerateRsaPremasterSecret(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17120, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "GenerateRsaPremasterSecret fail", 0, 0, 0, 0);
            (void)memset_s(hsCtx->kxCtx->keyExchParam.rsa.preMasterSecret, MASTER_SECRET_LEN, 0, MASTER_SECRET_LEN);
            return ret;
        }
    }
#endif /* HITLS_TLS_SUITE_KX_RSA */
#ifdef HITLS_TLS_FEATURE_PSK
    /* If the PSK and RSA_PSK cipher suites are used, the server may not send the ServerKeyExchange message. Before
     * packing the ClientKeyExchange message, check whether the PSK has been obtained */
    if (hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_PSK || hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_RSA_PSK) {
        ret = CheckClientPsk(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17121, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "CheckClientPsk fail", 0, 0, 0, 0);
            (void)memset_s(hsCtx->kxCtx->keyExchParam.rsa.preMasterSecret, MASTER_SECRET_LEN, 0, MASTER_SECRET_LEN);
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_PSK */
#ifdef HITLS_TLS_PROTO_TLCP11
    if (hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_ECC) {
        ret = GenerateEccPremasterSecret(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17122, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "GenerateEccPremasterSecret fail", 0, 0, 0, 0);
            (void)memset_s(hsCtx->kxCtx->keyExchParam.ecc.preMasterSecret, MASTER_SECRET_LEN, 0, MASTER_SECRET_LEN);
            return ret;
        }
    }
#endif
    (void)hsCtx;
    return ret;
}

int32_t ClientSendClientKeyExchangeProcess(TLS_Ctx *ctx)
{
    int32_t ret = 0;
    HS_Ctx *hsCtx = ctx->hsCtx;
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;

    /* Check whether the message needs to be packed */
    if (hsCtx->msgLen == 0) {
        ret = PackMsgPrepare(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = HS_PackMsg(ctx, CLIENT_KEY_EXCHANGE, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15816, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client pack client key exchange msg error.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15817, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "client send client key exchange msg success.", 0, 0, 0, 0);

    ret = HS_GenerateMasterSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15818, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client generate master secret fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    /* Client derives key */
    ret = HS_KeyEstablish(ctx, ctx->isClient);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15819, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client key establish fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)
    ret = HS_SetSctpAuthKey(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17124, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
            "SetSctpAuthKey fail", 0, 0, 0, 0);
        return ret;
    }
#endif
    /**
     *  If no certificate request is received and no certificate is available,
     * the system proceeds to the next state.
     * RFC 5246 7.4.8: This message (here is client certificate verify) is only sent following
     * a client certificate that has signing capability.
     * Therefore, the client certificate verify message will not be sent if client certificate is empty.
     * For TLCP, SAL_CERT_GetCurrentCert MAY return NULL when dealing with cerificate request message,
     * Whether the client needing to be verified depends on the server configuration.
     */
    if (hsCtx->isNeedClientCert && (SAL_CERT_GetCurrentCert(mgrCtx) != NULL)) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_VERIFY);
    }
    return HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_CLIENT */