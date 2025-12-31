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
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_config.h"
#include "tls_config.h"
#include "cert_method.h"
#include "cert.h"
#include "cipher_suite.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "parse_msg.h"
#include "parse_common.h"

// Parse signature algorithm in the context message.
int32_t ParseSignAlgorithm(ParsePacket *pkt, uint16_t *signAlg)
{
    uint16_t signScheme = 0;
    TLS_Ctx *ctx = pkt->ctx;
    int32_t ret = ParseBytesToUint16(pkt, &signScheme);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15306,
            BINGLOG_STR("parse signAlgorithm failed in serverKeyEx."), ALERT_DECODE_ERROR);
    }

    ret = CheckPeerSignScheme(ctx, ctx->hsCtx->peerCert, signScheme);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, ret, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }

    uint32_t i = 0;
    /* If the client_hello message contains the signature_algorithms extension, the server_key_exchange message must use
     * the signature algorithm in the extension. */
    for (i = 0; i < ctx->config.tlsConfig.signAlgorithmsSize; i++) {
        if (ctx->config.tlsConfig.signAlgorithms[i] == signScheme) {
            break;
        }
    }
    if (i == ctx->config.tlsConfig.signAlgorithmsSize) {
        /* Handshake failed because it is not an extended signature algorithm. */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15307, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check serverKeyEx signature algo fail: 0x%x is not included in client hello.",
            signScheme, 0, 0, 0);
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_UNSUPPORT_SIGN_ALG, 0, NULL, ALERT_HANDSHAKE_FAILURE);
    }

#ifdef HITLS_TLS_FEATURE_SECURITY
    if (SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signScheme, NULL) != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17132, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signScheme 0x%x SslCheck fail", signScheme, 0, 0, 0);
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_UNSUPPORT_SIGN_ALG, 0, NULL, ALERT_HANDSHAKE_FAILURE);
    }
#endif

    *signAlg = signScheme;

    return HITLS_SUCCESS;
}

// Parse the signature in the ECDHE kx message.
int32_t ParseSignature(ParsePacket *pkt, uint16_t *signSize, uint8_t **signData)
{
    int32_t ret = ParseTwoByteLengthField(pkt, signSize, signData);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15308,
            BINGLOG_STR("parse serverkeyEx signature failed."), ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15311,
            BINGLOG_STR("signData malloc fail."), ALERT_UNKNOWN);
    }

    if (pkt->bufLen != *pkt->bufOffset) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15308,
            BINGLOG_STR("parse serverkeyEx signature failed."), ALERT_DECODE_ERROR);
    }

    if (*signSize == 0) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15310,
            BINGLOG_STR("length of server signSize is 0."), ALERT_ILLEGAL_PARAMETER);
    }

    return HITLS_SUCCESS;
}

static void GetServerKeyExSignParam(const ServerKeyExchangeMsg *msg,
    CERT_SignParam *signParam, HITLS_SignHashAlgo *signScheme)
{
    if (msg->keyExType == HITLS_KEY_EXCH_ECDHE) {
        *signScheme = msg->keyEx.ecdh.signAlgorithm;
        signParam->sign = msg->keyEx.ecdh.signData;
        signParam->signLen = msg->keyEx.ecdh.signSize;
    } else if (msg->keyExType == HITLS_KEY_EXCH_DHE) {
        *signScheme = msg->keyEx.dh.signAlgorithm;
        signParam->sign = msg->keyEx.dh.signData;
        signParam->signLen = msg->keyEx.dh.signSize;
    }

    return;
}

int32_t VerifySignature(TLS_Ctx *ctx, const uint8_t *kxData, uint32_t kxDataLen, ServerKeyExchangeMsg *msg)
{
    CERT_SignParam signParam = {0};
    HITLS_SignHashAlgo signScheme = 0;

    GetServerKeyExSignParam(msg, &signParam, &signScheme);

    /* Obtain the signature algorithm and hash algorithm */
    if (!CFG_GetSignParamBySchemes(ctx, signScheme, &signParam.signAlgo, &signParam.hashAlgo)) {
        return ParseErrorProcess(ctx, HITLS_PARSE_GET_SIGN_PARA_ERR, BINLOG_ID15312,
            BINGLOG_STR("get sign param fail."), ALERT_ILLEGAL_PARAMETER);
    }
    /* Obtain all signature data (random number + server kx content). */
    uint8_t *data = HS_PrepareSignData(ctx, kxData, kxDataLen, &signParam.dataLen);
    if (data == NULL) {
        return ParseErrorProcess(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15313,
            BINGLOG_STR("data malloc fail."), ALERT_INTERNAL_ERROR);
    }

    if (ctx->hsCtx->peerCert == NULL) {
        BSL_SAL_FREE(data);
        return ParseErrorProcess(ctx, HITLS_PARSE_VERIFY_SIGN_FAIL, BINLOG_ID17013,
            BINGLOG_STR("peerCert null"), ALERT_CERTIFICATE_REQUIRED);
    }

    HITLS_CERT_X509 *cert = SAL_CERT_PAIR_GET_X509(ctx->hsCtx->peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(&(ctx->config.tlsConfig), cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17014, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GET_PUB_KEY fail", 0, 0, 0, 0);
        BSL_SAL_FREE(data);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    signParam.data = data;
    ret = SAL_CERT_VerifySign(ctx, pubkey, &signParam);
    SAL_CERT_KeyFree(ctx->config.tlsConfig.certMgrCtx, pubkey);
    BSL_SAL_FREE(data);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(ctx, HITLS_PARSE_VERIFY_SIGN_FAIL, BINLOG_ID15314,
            BINGLOG_STR("verify signature fail."), ALERT_DECRYPT_ERROR);
    }
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_SUITE_KX_ECDHE

static int32_t ParseEcdhePublicKey(ParsePacket *pkt, ServerEcdh *ecdh)
{
    const char *logStr = BINGLOG_STR("parse ecdhe public key fail.");
    uint8_t pubKeySize = 0;
    int32_t ret = ParseBytesToUint8(pkt, &pubKeySize);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15298,
            logStr, ALERT_DECODE_ERROR);
    }

#ifdef HITLS_TLS_PROTO_TLCP11
    if (pkt->ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        ecdh->ecPara.param.namedcurve = HITLS_EC_GROUP_SM2;
    }
#endif /* HITLS_TLS_PROTO_TLCP11 */
    if ((ecdh->ecPara.type == HITLS_EC_CURVE_TYPE_NAMED_CURVE) &&
        (pubKeySize != HS_GetCryptLength(pkt->ctx, HITLS_CRYPT_INFO_CMD_GET_PUBLIC_KEY_LEN,
            ecdh->ecPara.param.namedcurve))) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15300, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ecdhe server pubkey length error, curve id = %u, pubkey len = %u.",
            ecdh->ecPara.param.namedcurve, pubKeySize, 0, 0);
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_ECDH_PUBKEY_ERR, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }

    uint8_t *pubKey = NULL;
    ret = ParseBytesToArray(pkt, &pubKey, pubKeySize);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15299,
            logStr, ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15301,
            BINGLOG_STR("pubKey malloc fail."), ALERT_UNKNOWN);
    }

    ecdh->pubKey = pubKey;
    ecdh->pubKeySize = pubKeySize;
    return HITLS_SUCCESS;
}

int32_t ParseEcParameters(ParsePacket *pkt, ServerEcdh *ecdh)
{
    const char *logStr = BINGLOG_STR("parse ecdhe curve type fail.");
    uint8_t curveType = 0;
    int32_t ret = ParseBytesToUint8(pkt, &curveType);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15292,
            logStr, ALERT_DECODE_ERROR);
    }

    /* In the TLCP, this content can choose not to be sent. */
    if (curveType == HITLS_EC_CURVE_TYPE_NAMED_CURVE) {
        uint16_t namedCurve = 0;
        ret = ParseBytesToUint16(pkt, &namedCurve);
        if (ret != HITLS_SUCCESS) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15291,
                logStr, ALERT_DECODE_ERROR);
        }
        ecdh->ecPara.param.namedcurve = namedCurve;
    } else {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_UNSUPPORT_KX_CURVE_TYPE, BINLOG_ID15293,
            BINGLOG_STR("unsupport curve type in server key exchange."), ALERT_ILLEGAL_PARAMETER);
    }

    ecdh->ecPara.type = curveType;
    return HITLS_SUCCESS;
}

static int32_t ParseEcdhePreSign(ParsePacket *pkt, ServerKeyExchangeMsg *msg)
{
    /* Parse the EC parameter in the ECDH message on the server */
    int32_t ret = ParseEcParameters(pkt, &msg->keyEx.ecdh);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* Parse DH public key from peer */
    ret = ParseEcdhePublicKey(pkt, &msg->keyEx.ecdh);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}

/**
 * @brief Parse the server ecdh message.
 *
 * @param pkt [IN] Context for parsing
 * @param msg [OUT] Parsed message structure
 *
 * @retval HITLS_SUCCESS Parsing succeeded.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 * @retval HITLS_PARSE_UNSUPPORT_KX_CURVE_TYPE Unsupported ECC curve type
 * @retval HITLS_PARSE_ECDH_PUBKEY_ERR Failed to parse the ECDH public key.
 * @retval HITLS_PARSE_ECDH_SIGN_ERR Failed to parse the EDH signature.
 * @retval HITLS_PARSE_GET_SIGN_PARA_ERR Failed to obtain the signature algorithm and hash algorithm.
 * @retval HITLS_PARSE_VERIFY_SIGN_FAIL Failed to verify the signature.
 */
static int32_t ParseServerEcdhe(ParsePacket *pkt, ServerKeyExchangeMsg *msg)
{
    TLS_Ctx *ctx = pkt->ctx;
    int32_t ret = ParseEcdhePreSign(pkt, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /*  ECDHE_PSK and ANON_ECDHE key exchange are not signed */
    if (ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_ECDHE_PSK ||
        ctx->negotiatedInfo.cipherSuiteInfo.authAlg == HITLS_AUTH_NULL) {
        if (pkt->bufLen != *pkt->bufOffset) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15317,
                BINGLOG_STR("parse serverkeyEx signature failed."), ALERT_DECODE_ERROR);
        }
        return HITLS_SUCCESS;
    }

    uint32_t keyExDataLen = *pkt->bufOffset;
    uint16_t signAlgorithm = ctx->negotiatedInfo.cipherSuiteInfo.signScheme;

    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP_DTLCP11) {
        ret = ParseSignAlgorithm(pkt, &signAlgorithm);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17015, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ParseSignAlgorithm fail", 0, 0, 0, 0);
            return ret;
        }
    }

    msg->keyEx.ecdh.signAlgorithm = signAlgorithm;

    ret = ParseSignature(pkt, &msg->keyEx.ecdh.signSize, &msg->keyEx.ecdh.signData);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_ECDH_SIGN_ERR, BINLOG_ID15318,
            BINGLOG_STR("parse ecdhe signature fail."), ALERT_UNKNOWN);
    }

    ret = VerifySignature(pkt->ctx, pkt->buf, keyExDataLen, msg);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17016, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "VerifySignature fail", 0, 0, 0, 0);
        return ret;
    }

    ctx->peerInfo.peerSignHashAlg = signAlgorithm;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE

/**
 * @brief Parse the p or g parameter in the DHE kx message.
 *
 * @param pkt [IN] Context for parsing
 * @param paraLen [OUT] Parsed parameter length
 * @param para [OUT] Parsed parameter
 *
 * @return The allocated parameter memory. If the parameter memory is NULL, the parsing fails.
 */
int32_t ParseDhePara(ParsePacket *pkt, uint16_t *paraLen, uint8_t **para)
{
    int32_t ret = ParseTwoByteLengthField(pkt, paraLen, para);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15294,
            BINGLOG_STR("dhe para length error."), ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15297,
            BINGLOG_STR("dhePara malloc fail."), ALERT_UNKNOWN);
    }

    if (*paraLen == 0) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15296,
            BINGLOG_STR("length of dhe para is 0."), ALERT_ILLEGAL_PARAMETER);
    }

    return HITLS_SUCCESS;
}

static int32_t ParseServerDhe(ParsePacket *pkt, ServerKeyExchangeMsg *msg)
{
    ServerDh *dh = &msg->keyEx.dh;
    const char *logStr = BINGLOG_STR("parse dhe param or PubKey fail. ret %d");
    TLS_Ctx *ctx = pkt->ctx;
    int32_t ret = ParseDhePara(pkt, &dh->plen, &dh->p);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15320, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, logStr, ret, 0, 0, 0);
        return HITLS_PARSE_DH_P_ERR;
    }

    ret = ParseDhePara(pkt, &dh->glen, &dh->g);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15321, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, logStr, ret, 0, 0, 0);
        return HITLS_PARSE_DH_G_ERR;
    }

    /* Parse DH public key from peer */
    ret = ParseDhePara(pkt, &dh->pubKeyLen, &dh->pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15322, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, logStr, ret, 0, 0, 0);
        return HITLS_PARSE_DH_PUBKEY_ERR;
    }

    /* DHE_PSK | ANON_DHE key exchange is not signed */
    if (ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_DHE_PSK ||
        ctx->negotiatedInfo.cipherSuiteInfo.authAlg == HITLS_AUTH_NULL) {
        if (pkt->bufLen != *pkt->bufOffset) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15323,
                BINGLOG_STR("parse serverkeyEx signature failed."), ALERT_DECODE_ERROR);
        }
        return HITLS_SUCCESS;
    }

    uint32_t kxDataLen = *pkt->bufOffset;

    dh->signAlgorithm = ctx->negotiatedInfo.cipherSuiteInfo.signScheme;
    ret = ParseSignAlgorithm(pkt, &dh->signAlgorithm);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17017, "ParseSignAlgorithm fail");
    }

    ret = ParseSignature(pkt, &dh->signSize, &dh->signData);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17018, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ParseSignature fail, ret %d", ret, 0, 0, 0);
        return HITLS_PARSE_DH_SIGN_ERR;
    }

    ret = VerifySignature(pkt->ctx, pkt->buf, kxDataLen, msg);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17019, "VerifySignature fail");
    }

    ctx->peerInfo.peerSignHashAlg = dh->signAlgorithm;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_FEATURE_PSK
/* In the case of psk negotiation, if ServerKeyExchange is received, the length of the identity hint must be parseed,
 * but the length may be empty */
static int32_t ParseServerIdentityHint(ParsePacket *pkt, ServerKeyExchangeMsg *msg)
{
    uint16_t identityHintLen = 0;
    uint8_t *identityHint = NULL;

    int32_t ret = ParseTwoByteLengthField(pkt, &identityHintLen, &identityHint);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17020, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse fail, ret %d", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17021, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse fail, ret %d", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    if (identityHintLen != 0) {
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID15324, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "receive server identity hint: %s.", identityHint);
    }

    msg->pskIdentityHint = identityHint;
    msg->hintSize = identityHintLen;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PSK */
#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t VerifyServerKxMsgEcc(ParsePacket *pkt, CERT_SignParam *signParam)
{
    uint8_t *sign = NULL;
    uint16_t signSize = 0;
    TLS_Ctx *ctx = pkt->ctx;
    /* Parse the signature data. The signature data is released after it is used up. The information is not maintained
     * in the ServerKeyExchangeMsg.keyEx.ecdh file */
    int32_t ret = ParseSignature(pkt, &signSize, &sign);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(sign);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16223, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse ecc signature fail.", 0, 0, 0, 0);
        return HITLS_PARSE_ECDH_SIGN_ERR;
    }
    HITLS_CERT_X509 *signCert = SAL_CERT_PAIR_GET_X509_EX(ctx->hsCtx->peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    ret = SAL_CERT_X509Ctrl(&(ctx->config.tlsConfig), signCert,
        CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(sign);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    signParam->sign = sign;
    signParam->signLen = signSize;
    ret = SAL_CERT_VerifySign(ctx, pubkey, signParam);
    SAL_CERT_KeyFree(ctx->config.tlsConfig.certMgrCtx, pubkey);
    BSL_SAL_FREE(sign);
    return ret;
}

/* Signature verification is complete and does not need to be exported to the ServerKeyExchangeMsg structure */
static int32_t ParseServerKxMsgEcc(ParsePacket *pkt)
{
    HITLS_SignAlgo signAlgo;
    HITLS_HashAlgo hashAlgo;
    TLS_Ctx *ctx = pkt->ctx;
    /* The algorithm suite has been determined. The error probability of this function is low. Therefore, the alert is
     * not required. */
    if (!CFG_GetSignParamBySchemes(ctx, ctx->negotiatedInfo.cipherSuiteInfo.signScheme, &signAlgo, &hashAlgo)) {
        return HITLS_PACK_SIGNATURE_ERR;
    }

    uint32_t certLen = 0;
    uint8_t *cert = SAL_CERT_ClntGmEncodeEncCert(ctx, ctx->hsCtx->peerCert, &certLen);
    if (cert == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_CERT_ERR_ENCODE, BINLOG_ID16206,
            BINGLOG_STR("encode encrypt cert failed."), ALERT_INTERNAL_ERROR);
    }
    uint32_t signDataLen = 0;
    uint8_t *signData = HS_PrepareSignDataTlcp(ctx, cert, certLen, &signDataLen);
    BSL_SAL_FREE(cert);
    if (signData == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID16207,
            BINGLOG_STR("data malloc fail."), ALERT_INTERNAL_ERROR);
    }

    CERT_SignParam signParam = {signAlgo, hashAlgo, signData, signDataLen, NULL, 0};
    int32_t ret = VerifyServerKxMsgEcc(pkt, &signParam);
    BSL_SAL_FREE(signData);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_VERIFY_SIGN_FAIL, BINLOG_ID16208,
            BINGLOG_STR("verify signature fail."), ALERT_DECRYPT_ERROR);
    }
    return HITLS_SUCCESS;
}
#endif

int32_t ParseServerKeyExchange(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    ServerKeyExchangeMsg *msg = &hsMsg->body.serverKeyExchange;
    msg->keyExType = hsCtx->kxCtx->keyExchAlgo;
    ParsePacket pkt = {.ctx = ctx, .buf = data, .bufLen = len, .bufOffset = &offset};
    (void)pkt;
#ifdef HITLS_TLS_FEATURE_PSK
    if (IsPskNegotiation(ctx)) {
        if ((ret = ParseServerIdentityHint(&pkt, msg)) != HITLS_SUCCESS) {
            // log here
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    switch (hsCtx->kxCtx->keyExchAlgo) {
#ifdef HITLS_TLS_SUITE_KX_ECDHE
        case HITLS_KEY_EXCH_ECDHE: /** contains the TLCP */
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = ParseServerEcdhe(&pkt, msg);
            break;
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = ParseServerDhe(&pkt, msg);
            break;
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_RSA
        /* PSK & RSA_PSK nego may pack identity hint inside ServerKeyExchange msg */
        case HITLS_KEY_EXCH_PSK:
        case HITLS_KEY_EXCH_RSA_PSK:
            break;
#endif /* HITLS_TLS_SUITE_KX_RSA */
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_KEY_EXCH_ECC:
            ret = ParseServerKxMsgEcc(&pkt);
            break;
#endif
        default:
            ret = HITLS_PARSE_UNSUPPORT_KX_ALG;
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            break;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15325, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse serverKeyExMsg fail. keyExchAlgo is %d", hsCtx->kxCtx->keyExchAlgo, 0, 0, 0);
    }

    return ret;
}

void CleanServerKeyExchange(ServerKeyExchangeMsg *msg)
{
    if (msg == NULL) {
        return;
    }
#ifdef HITLS_TLS_SUITE_KX_ECDHE
    if (msg->keyExType == HITLS_KEY_EXCH_ECDHE || msg->keyExType == HITLS_KEY_EXCH_ECDHE_PSK) {
        BSL_SAL_FREE(msg->keyEx.ecdh.pubKey);
        BSL_SAL_FREE(msg->keyEx.ecdh.signData);
    }
#endif
#ifdef HITLS_TLS_SUITE_KX_DHE
    if (msg->keyExType == HITLS_KEY_EXCH_DHE || msg->keyExType == HITLS_KEY_EXCH_DHE_PSK) {
        BSL_SAL_FREE(msg->keyEx.dh.p);
        BSL_SAL_FREE(msg->keyEx.dh.g);
        BSL_SAL_FREE(msg->keyEx.dh.pubkey);
        BSL_SAL_FREE(msg->keyEx.dh.signData);
    }
#endif
    BSL_SAL_FREE(msg->pskIdentityHint);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_CLIENT */