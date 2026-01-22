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
#if (defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY)) || \
    defined(HITLS_TLS_PROTO_TLS13)
#include "tls_binlog_id.h"
#include "bsl_log.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "cert_method.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "parse_msg.h"
#include "parse_common.h"
#include "hs_common.h"
#include "config_type.h"
#include "crypt_algid.h"

static int32_t CheckSignHashAlg(TLS_Ctx *ctx, uint16_t signHashAlg)
{
    int32_t ret = CheckPeerSignScheme(ctx, ctx->hsCtx->peerCert, signHashAlg);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(ctx, ret, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }

    TLS_Config *config = &ctx->config.tlsConfig;
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        const TLS_SigSchemeInfo *schemeInfo = ConfigGetSignatureSchemeInfo(config, signHashAlg);
        if (schemeInfo == NULL || ((schemeInfo->certVersionBits & TLS13_VERSION_BIT) == 0)) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16195, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "not allowed to use 0x%X signAlg tls1.3.", signHashAlg, 0, 0, 0);
            return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORT_SIGN_ALG, 0, NULL, ALERT_HANDSHAKE_FAILURE);
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    uint32_t i = 0;
    for (i = 0; i < config->signAlgorithmsSize; i++) {
        if (signHashAlg == config->signAlgorithms[i]) {
            break;
        }
    }

    if (i == config->signAlgorithmsSize) {
        return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORT_SIGN_ALG, BINLOG_ID15865,
            BINGLOG_STR("the signHashAlg match failed"), ALERT_HANDSHAKE_FAILURE);
    }

#ifdef HITLS_TLS_FEATURE_SECURITY
    if (SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signHashAlg, NULL) != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17159, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signHashAlg 0x%x SslCheck fail", signHashAlg, 0, 0, 0);
        return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORT_SIGN_ALG, 0, NULL, ALERT_HANDSHAKE_FAILURE);
    }
#endif

    return HITLS_SUCCESS;
}

static int32_t ParseCertificateVerifyPre(ParsePacket *pkt, uint16_t *signHashAlg)
{
    const char *logStr = BINGLOG_STR("parse cert verifypre fail");
    /* 2-byte signature hash algorithm + 2-byte signature data length.
       If the message length is less than 4 bytes, a failure message is returned. */
    if (pkt->bufLen < 4u) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16964, logStr, ALERT_DECODE_ERROR);
    }
    if (pkt->ctx->negotiatedInfo.version >= HITLS_VERSION_TLS12) {
        int32_t ret = ParseBytesToUint16(pkt, signHashAlg);
        if (ret != HITLS_SUCCESS) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16965, logStr, ALERT_DECODE_ERROR);
        }

        if (CheckSignHashAlg(pkt->ctx, *signHashAlg) != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_SIGN_ALG);
            return HITLS_PARSE_UNSUPPORT_SIGN_ALG;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t KeyMatchSignAlg(TLS_Ctx *ctx, HITLS_SignHashAlgo signScheme, HITLS_CERT_KeyType keyType,
    HITLS_CERT_Key *key)
{
    (void)key;
    HITLS_CERT_KeyType certKeyType = HS_SignScheme2CertKeyType(ctx, signScheme);
    if (certKeyType != keyType) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16197, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signScheme not matche key, signScheme is 0x%X, certKeyType is %u, keyType is %u", signScheme, certKeyType,
            keyType, 0);
        return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORT_SIGN_ALG, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }

    /* check curve matches signature algorithm, only check ec key for tls1.3 */
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        return HITLS_SUCCESS;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    HITLS_Config *config = &ctx->config.tlsConfig;
    const TLS_SigSchemeInfo *schemeInfo = ConfigGetSignatureSchemeInfo(config, signScheme);
    if (schemeInfo == NULL) {
        return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORT_SIGN_ALG, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }
    if (schemeInfo->paraId == CRYPT_PKEY_PARAID_MAX) {
        return HITLS_SUCCESS;
    }
    int32_t paramId = CRYPT_PKEY_PARAID_MAX;
    int32_t ret = SAL_CERT_KeyCtrl(config, key, CERT_KEY_CTRL_GET_PARAM_ID, NULL, (void *)&paramId);
    if (ret != HITLS_SUCCESS || paramId != schemeInfo->paraId) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16198,
            BINGLOG_STR("paramId mismatch sigScheme"), ALERT_INTERNAL_ERROR);
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    return HITLS_SUCCESS;
}

static int VerifySignData(TLS_Ctx *ctx, uint16_t signHashAlg, const uint8_t *sign, uint16_t signSize)
{
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (ctx->hsCtx == NULL || ctx->hsCtx->peerCert == NULL) {
        return ParseErrorProcess(ctx, HITLS_PARSE_VERIFY_SIGN_FAIL, BINLOG_ID15866,
            BINGLOG_STR("no peer certificate"), ALERT_CERTIFICATE_REQUIRED);
    }

    HITLS_CERT_X509 *cert = SAL_CERT_PAIR_GET_X509(ctx->hsCtx->peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(&ctx->config.tlsConfig, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16966, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GET_PUB_KEY fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    HITLS_SignHashAlgo signScheme = signHashAlg;
    HITLS_CERT_KeyType keyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    ret = SAL_CERT_KeyCtrl(&ctx->config.tlsConfig, pubkey, CERT_KEY_CTRL_GET_TYPE, NULL, (void *)&keyType);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        return ParseErrorProcess(ctx, ret, BINLOG_ID16072,
            BINGLOG_STR("SAL_CERT_KeyCtrl fails"), ALERT_INTERNAL_ERROR);
    }

    if (signScheme == 0) {
        /** If the value of the signature hash algorithm is 0, the peer does not send the signature algorithm.
            In this case, we need to obtain the default signature algorithm through the certificate. */
        signScheme = SAL_CERT_GetDefaultSignHashAlgo(keyType);
        if (signScheme == CERT_SIG_SCHEME_UNKNOWN) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16073, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "no available signature scheme, key type = %u.", keyType, 0, 0, 0);
            SAL_CERT_KeyFree(mgrCtx, pubkey);
            return ParseErrorProcess(ctx, HITLS_PARSE_VERIFY_SIGN_FAIL, 0, NULL, ALERT_INTERNAL_ERROR);
        }
    }

    /* check whether the signature scheme matches the certificate key */
    if (KeyMatchSignAlg(ctx, signScheme, keyType, pubkey) != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16967, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "KeyMatchSignAlg fail", 0, 0, 0, 0);
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        return HITLS_PARSE_VERIFY_SIGN_FAIL;
    }

    /** verifying certificate data */
    ret = VERIFY_VerifySignData(ctx, pubkey, signScheme, sign, signSize);
    SAL_CERT_KeyFree(mgrCtx, pubkey);
    return ret;
}

int32_t ParseCertificateVerify(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    uint16_t signHashAlg = 0;
    uint32_t offset = 0;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &offset};

    int32_t ret = ParseCertificateVerifyPre(&pkt, &signHashAlg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    const char *logStr = BINGLOG_STR("parse cert verify fail");
    uint16_t signSize = 0;
    ret = ParseBytesToUint16(&pkt, &signSize);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16968, logStr, ALERT_DECODE_ERROR);
    }

    if ((signSize != (pkt.bufLen - *pkt.bufOffset)) || (signSize == 0)) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16969, logStr, ALERT_DECODE_ERROR);
    }

    const uint8_t *sign = &pkt.buf[*pkt.bufOffset];

    ret = VerifySignData(pkt.ctx, signHashAlg, sign, signSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    CertificateVerifyMsg *msg = &hsMsg->body.certificateVerify;
    msg->signHashAlg = signHashAlg;
    msg->signSize = signSize;
    BSL_SAL_FREE(msg->sign);
    msg->sign = BSL_SAL_Dump(sign, signSize);
    if (msg->sign == NULL) {
        return ParseErrorProcess(pkt.ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID16970,
            BINGLOG_STR("Dump fail"), ALERT_INTERNAL_ERROR);
    }
    pkt.ctx->peerInfo.peerSignHashAlg = signHashAlg;
    return HITLS_SUCCESS;
}

void CleanCertificateVerify(CertificateVerifyMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->sign);
}
#endif /* (HITLS_TLS_HOST_SERVER && HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY) || HITLS_TLS_PROTO_TLS13 */