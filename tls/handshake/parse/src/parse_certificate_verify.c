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
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "cert_method.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "parse_msg.h"

/* rfc8446 section 4.2.3 and 4.4.3 do not allow sha1 and PKCS1 */
static HITLS_SignHashAlgo g_tls13AllowSignHashAlgo[] = {
    CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
    CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
    CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384,
    CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512,
    CERT_SIG_SCHEME_ED25519,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384,
    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512
};

static int32_t CheckSignHashAlg(TLS_Ctx *ctx, uint16_t signHashAlg)
{
    TLS_Config *config = &ctx->config.tlsConfig;

    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        bool find = false;
        for (uint32_t i = 0; i < (sizeof(g_tls13AllowSignHashAlgo) / sizeof(g_tls13AllowSignHashAlgo[0])); i++) {
            if (signHashAlg == g_tls13AllowSignHashAlgo[i]) {
                find = true;
                break;
            }
        }
        if (!find) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_SIGN_ALG);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15565, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "not allowed to use 0x%X signAlg tls1.3.", signHashAlg, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            return HITLS_PARSE_UNSUPPORT_SIGN_ALG;
        }
    }

    for (uint32_t i = 0; i < config->signAlgorithmsSize; i++) {
        if (signHashAlg == config->signAlgorithms[i]) {
            return HITLS_SUCCESS;
        }
    }

    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_SIGN_ALG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15865, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "the signHashAlg in certificate verify msg matching failed.", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
    return HITLS_PARSE_UNSUPPORT_SIGN_ALG;
}

static int32_t ParseCertificateVerifyPre(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
    uint16_t *signHashAlg, uint32_t *offset)
{
    /* 2-byte signature hash algorithm + 2-byte signature data length.
       If the message length is less than 4 bytes, return an error code. */
    if (bufLen < 4u) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP11) {
        *signHashAlg = BSL_ByteToUint16(buf);

        *offset = sizeof(uint16_t);

        if (CheckSignHashAlg(ctx, *signHashAlg) != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_SIGN_ALG);
            return HITLS_PARSE_UNSUPPORT_SIGN_ALG;
        }
    }
    return HITLS_SUCCESS;
}

static bool KeyMatchSignAlg(TLS_Ctx *ctx, HITLS_SignHashAlgo signScheme, HITLS_CERT_KeyType keyType,
    HITLS_CERT_Key *key)
{
    HITLS_CERT_KeyType certKeyType = SAL_CERT_SignScheme2CertKeyType(signScheme);
    if (certKeyType != keyType) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_SIGN_ALG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15567, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signScheme not matche key, signScheme is 0x%X, certKeyType is %u, keyType is %u", signScheme, certKeyType,
            keyType, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return false;
    }

    /* check curve matches signature algorithm, only check ec key for tls1.3 */
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13 || keyType != TLS_CERT_KEY_TYPE_ECDSA) {
        return true;
    }

    int32_t ret;
    HITLS_Config *config = &ctx->config.tlsConfig;
    HITLS_NamedGroup keyCureName = HITLS_NAMED_GROUP_BUTT;
    ret = SAL_CERT_KeyCtrl(config, key, CERT_KEY_CTRL_GET_CURVE_NAME, NULL, (void *)&keyCureName);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15568, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get ec pubkey curve name failed when verify sign data.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return false;
    }

    HITLS_NamedGroup signCureName = CFG_GetEcdsaCurveNameBySchemes(signScheme);
    if (signCureName != HITLS_NAMED_GROUP_BUTT && keyCureName != signCureName) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_SIGN_ALG);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15569, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "key curve does not matches sigAlg, signScheme is 0x%X, keyCureName is %u, signCureName is %u.", signScheme,
            keyCureName, signCureName, 0);
        return false;
    }

    return true;
}

static int VerifySignData(TLS_Ctx *ctx, uint16_t signHashAlg, const uint8_t *sign, uint16_t signSize)
{
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (ctx->hsCtx->peerCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_VERIFY_SIGN_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15866, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "no peer certificate when parse certificate verify.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_CERTIFICATE_REQUIRED);
        return HITLS_PARSE_VERIFY_SIGN_FAIL;
    }

    HITLS_CERT_X509 *cert = SAL_CERT_PairGetX509(ctx->hsCtx->peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(&ctx->config.tlsConfig, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    HITLS_SignHashAlgo signScheme = signHashAlg;
    HITLS_CERT_KeyType keyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    ret = SAL_CERT_KeyCtrl(&ctx->config.tlsConfig, pubkey, CERT_KEY_CTRL_GET_TYPE, NULL, (void *)&keyType);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16031, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CERT_KeyCtrl fails when verifying data.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        return ret;
    }

    if (signScheme == 0) {
        /** If the value of the signature hash algorithm is 0, the peer does not send the signature algorithm.
            In this case, we need to obtain the default signature algorithm through the certificate. */
        signScheme = SAL_CERT_GetDefaultSignHashAlgo(keyType);
        if (signScheme == CERT_SIG_SCHEME_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_VERIFY_SIGN_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16034, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "no available signature scheme when verify sign data, key type = %u.", keyType, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            SAL_CERT_KeyFree(mgrCtx, pubkey);
            return HITLS_PARSE_VERIFY_SIGN_FAIL;
        }
    }

    /* check whether the signature scheme matches the certificate key */
    if (KeyMatchSignAlg(ctx, signScheme, keyType, pubkey) != true) {
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        return HITLS_PARSE_VERIFY_SIGN_FAIL;
    }

    /** verifying certificate data */
    ret = VERIFY_VerifySignData(ctx, pubkey, signScheme, sign, signSize);
    SAL_CERT_KeyFree(mgrCtx, pubkey);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}

int32_t ParseCertificateVerify(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    uint16_t signHashAlg = 0;
    uint32_t offset = 0;

    int32_t ret = ParseCertificateVerifyPre(ctx, buf, bufLen, &signHashAlg, &offset);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint16_t signSize = BSL_ByteToUint16(&buf[offset]);
    offset += sizeof(uint16_t);

    if ((signSize != (bufLen - offset)) || (signSize == 0)) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    const uint8_t *sign = &buf[offset];

    ret = VerifySignData(ctx, signHashAlg, sign, signSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    CertificateVerifyMsg *msg = &hsMsg->body.certificateVerify;
    msg->signHashAlg = signHashAlg;
    msg->signSize = signSize;
    msg->sign = BSL_SAL_Dump(sign, signSize);
    if (msg->sign == NULL) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->peerInfo.peerSignHashAlg = signHashAlg;
    return HITLS_SUCCESS;
}

void CleanCertificateVerify(CertificateVerifyMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->sign);

    return;
}
