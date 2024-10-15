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
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
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

int32_t ParseEcdhNamedCurve(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, uint16_t *namedCurve, uint32_t *useLen)
{
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15291, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server keyExMsg is incorrect when parse named curve.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    *namedCurve = BSL_ByteToUint16(data);
    *useLen = sizeof(uint16_t);

    return HITLS_SUCCESS;
}

int32_t ParseEcParameters(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ServerEcdh *ecdh, uint32_t *useLen)
{
    if (len < (sizeof(uint8_t))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15292, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server keyExMsg is incorrect when parse curve type.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    int32_t ret;
    uint32_t bufOffset = 0;
    HITLS_ECCurveType curveType = data[bufOffset];
    bufOffset += sizeof(uint8_t);

    /* In the TLCP, this content can choose not to be sent. */
    if (curveType == HITLS_EC_CURVE_TYPE_NAMED_CURVE) {
        uint16_t namedCurve = 0;
        uint32_t offset = 0;
        ret = ParseEcdhNamedCurve(ctx, &data[bufOffset], len - bufOffset, &namedCurve, &offset);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += offset;
        ecdh->ecPara.param.namedcurve = namedCurve;
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_KX_CURVE_TYPE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15293, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "unsupport curve type when parse server key exchange msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_UNSUPPORT_KX_CURVE_TYPE;
    }

    ecdh->ecPara.type = curveType;
    *useLen = bufOffset;

    return HITLS_SUCCESS;
}

/**
 * @brief Parse the p or g parameter in the DHE kx message.
 *
 * @param ctx [IN] TLS context
 * @param data [IN] message buffer
 * @param len [IN] message buffer length
 * @param paraLen [OUT] Parsed parameter length
 * @param useLen [OUT] Parsed length
 *
 * @return Return the applied parameter memory. If the parameter memory is NULL, the parsing fails.
 */
uint8_t *ParseDhePara(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, uint16_t *paraLen, uint32_t *useLen)
{
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15294, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server keyExMsg is incorrect when parse dhe para.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    uint32_t bufOffset = 0;
    uint16_t tmpParaLen = BSL_ByteToUint16(&data[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (tmpParaLen > (len - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15295, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of dhe para is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    if (tmpParaLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15296, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of dhe para is 0.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return NULL;
    }

    uint8_t *dhePara = (uint8_t *)BSL_SAL_Dump(&data[bufOffset], tmpParaLen);
    if (dhePara == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15297, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dhePara malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
        return NULL;
    }

    bufOffset += tmpParaLen;
    *useLen = bufOffset;
    *paraLen = tmpParaLen;
    return dhePara;
}

int32_t ParseEcdhePublicKey(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ServerEcdh *ecdh, uint32_t *useLen)
{
    if (len < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15298, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse ecdhe server pubkey length error, remain len = %u, less than one byte.", len, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t offset = 0;
    uint32_t pubKeySize = data[offset];
    offset += sizeof(uint8_t);

    if (pubKeySize > (len - offset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15299, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check ecdhe server pubkey length error, pubkey len = %u, remain len = %u.",
            pubKeySize, len - offset, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP11) {
        ecdh->ecPara.param.namedcurve = HITLS_EC_GROUP_SM2;
    }

    if ((ecdh->ecPara.type == HITLS_EC_CURVE_TYPE_NAMED_CURVE) &&
        (pubKeySize != HS_GetNamedCurvePubkeyLen(ecdh->ecPara.param.namedcurve))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_ECDH_PUBKEY_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15300, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check ecdhe server pubkey length error, curve id = %u, pubkey len = %u.",
            ecdh->ecPara.param.namedcurve, pubKeySize, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_ECDH_PUBKEY_ERR;
    }

    uint8_t *pubKey = BSL_SAL_Malloc(pubKeySize);
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15301, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubKey malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(pubKey, pubKeySize, &data[offset], pubKeySize);
    offset += pubKeySize;

    ecdh->pubKey = pubKey;
    ecdh->pubKeySize = pubKeySize;
    *useLen = offset;
    return HITLS_SUCCESS;
}

// Parse the public key in the Kx message of the DHE server.
uint8_t *ParseDhePublicKey(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, uint32_t *pubKeySize, uint32_t *useLen)
{
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15302, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse dhe server pubkey length error, remain len = %u, less than one byte.", len, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    uint32_t bufOffset = 0;
    uint32_t msgPubKeySize = BSL_ByteToUint16(&data[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (msgPubKeySize > (len - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15303, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server kx pubKeySize is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    if (msgPubKeySize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15304, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server kx pubKeySize is 0.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return NULL;
    }

    uint8_t *pubKey = BSL_SAL_Malloc(msgPubKeySize);
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15305, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubKey malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
        return NULL;
    }
    (void)memcpy_s(pubKey, msgPubKeySize, &data[bufOffset], msgPubKeySize);
    bufOffset += msgPubKeySize;
    *useLen = bufOffset;
    *pubKeySize = msgPubKeySize;

    return pubKey;
}

// Parse SignAlgorithm in the kx message.
int32_t ParseSignAlgorithm(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, uint16_t *signAlg, uint32_t *useLen)
{
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15306, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server keyExMsg is incorrect when parse signAlgorithm.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint16_t signScheme = BSL_ByteToUint16(data);
    uint32_t i;
    /* If the client_hello message contains the signature_algorithms extension, the server_key_exchange message must use
     * the signature algorithm in the extension. */
    for (i = 0; i < ctx->config.tlsConfig.signAlgorithmsSize; i++) {
        if (ctx->config.tlsConfig.signAlgorithms[i] == signScheme) {
            break;
        }
    }
    if (i == ctx->config.tlsConfig.signAlgorithmsSize) {
        /* Handshake failed because it is not an extended signature algorithm. */
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_SIGN_ALG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15307, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check server key exchange signature algo fail: 0x%x is not included in client hello.",
            signScheme, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return HITLS_PARSE_UNSUPPORT_SIGN_ALG;
    }

    *signAlg = signScheme;
    *useLen = sizeof(uint16_t);

    return HITLS_SUCCESS;
}

// Parse the signature in the ECDHE kx message.
uint8_t *ParseSignature(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, uint16_t *signSize, uint32_t *useLen)
{
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15308, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server keyExMsg is incorrect when parse signature.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    uint32_t bufOffset = 0;
    uint16_t tmpSignSize = BSL_ByteToUint16(&data[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (tmpSignSize != (len - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15309, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server signSize is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    if (tmpSignSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15310, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of server signSize is 0.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return NULL;
    }

    uint8_t *signData = BSL_SAL_Malloc(tmpSignSize);
    if (signData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15311, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signData malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
        return NULL;
    }
    (void)memcpy_s(signData, tmpSignSize, &data[bufOffset], tmpSignSize);
    bufOffset += tmpSignSize;
    *useLen = bufOffset;
    *signSize = tmpSignSize;

    return signData;
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
    if (!CFG_GetSignParamBySchemes(ctx->negotiatedInfo.version, signScheme, &signParam.signAlgo, &signParam.hashAlgo)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_GET_SIGN_PARA_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15312, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sign param fail when parse server key exchange msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_GET_SIGN_PARA_ERR;
    }

    /* Obtain all signature data (random number + server kx content). */
    signParam.data = HS_PrepareSignData(ctx, kxData, kxDataLen, &signParam.dataLen);
    if (signParam.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15313, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "data malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
    }

    CERT_Pair *peerCert = ctx->hsCtx->peerCert;
    if (peerCert == NULL) {
        BSL_SAL_FREE(signParam.data);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_CERTIFICATE_REQUIRED);
        return HITLS_PARSE_VERIFY_SIGN_FAIL;
    }

    HITLS_CERT_X509 *cert = SAL_CERT_PairGetX509(peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(&(ctx->config.tlsConfig), cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(signParam.data);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ret = SAL_CERT_VerifySign(ctx, pubkey, &signParam);
    SAL_CERT_KeyFree(ctx->config.tlsConfig.certMgrCtx, pubkey);
    BSL_SAL_FREE(signParam.data);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_VERIFY_SIGN_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15314, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify signature fail when parse server key exchange msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
        return HITLS_PARSE_VERIFY_SIGN_FAIL;
    }
    return HITLS_SUCCESS;
}

static int32_t ParseEcParametersWrapper(TLS_Ctx *ctx, const uint8_t *data, uint32_t len,
    ServerEcdh *ecdh, uint32_t *useLen)
{
    int32_t ret = ParseEcParameters(ctx, data, len, ecdh, useLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15315, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse ecdhe curve type fail.", 0, 0, 0, 0);
        return ret;
    }
    return HITLS_SUCCESS;
}

int32_t ParseEcdhePublicKeyWrapper(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ServerEcdh *ecdh, uint32_t *useLen)
{
    int32_t ret = ParseEcdhePublicKey(ctx, data, len, ecdh, useLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15316, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse ecdhe public key fail.", 0, 0, 0, 0);
        return ret;
    }
    return HITLS_SUCCESS;
}

/**
 * @brief Parse the server ecdh message.
 *
 * @param ctx [IN] TLS context
 * @param data [IN] message buffer
 * @param len [IN] message buffer length
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
static int32_t ParseServerEcdhe(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ServerKeyExchangeMsg *msg)
{
    uint32_t useLen = 0;
    uint32_t bufOffset = 0;

    /* Parse the EC parameter in the ECDH message on the server */
    int32_t ret = ParseEcParametersWrapper(ctx, data, len, &msg->keyEx.ecdh, &useLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += useLen;

    /* Parse DH public key from peer */
    ret = ParseEcdhePublicKeyWrapper(ctx, &data[bufOffset], len - bufOffset, &msg->keyEx.ecdh, &useLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += useLen;

    /*  ECDHE_PSK and ANON_ECDHE key exchange are not signed */
    if (ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_ECDHE_PSK ||
        ctx->negotiatedInfo.cipherSuiteInfo.authAlg == HITLS_AUTH_NULL) {
        if (len != bufOffset) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15323, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse serverkeyEx signature failed.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }
        return HITLS_SUCCESS;
    }

    uint32_t keyExDataLen = bufOffset;
    uint16_t signAlgorithm = ctx->negotiatedInfo.cipherSuiteInfo.signScheme;

    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP11) {
        ret = ParseSignAlgorithm(ctx, &data[bufOffset], len - bufOffset, &signAlgorithm, &useLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15317, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse ecdhe sign algorithm fail.", 0, 0, 0, 0);
            return ret;
        }
        bufOffset += useLen;
    }

    msg->keyEx.ecdh.signAlgorithm = signAlgorithm;

    uint16_t signSize = 0;
    uint8_t *signData = ParseSignature(ctx, &data[bufOffset], len - bufOffset, &signSize, &useLen);
    if (signData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_ECDH_SIGN_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15318, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse ecdhe signature fail.", 0, 0, 0, 0);
        return HITLS_PARSE_ECDH_SIGN_ERR;
    }
    msg->keyEx.ecdh.signData = signData;
    msg->keyEx.ecdh.signSize = signSize;

    ret = VerifySignature(ctx, data, keyExDataLen, msg);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15319, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify signature fail when parse server key exchange msg.", 0, 0, 0, 0);
        return ret;
    }

    ctx->peerInfo.peerSignHashAlg = signAlgorithm;
    return HITLS_SUCCESS;
}

static uint8_t *ParseDheParaPWithLog(TLS_Ctx *ctx, const uint8_t *data, uint32_t len,
    uint16_t *paraLen, uint32_t *useLen)
{
    uint8_t *ret = ParseDhePara(ctx, data, len, paraLen, useLen);
    if (ret == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15320, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "p param malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
    }
    return ret;
}

static uint8_t *ParseDheParaGWithLog(TLS_Ctx *ctx, const uint8_t *data, uint32_t len,
    uint16_t *paraLen, uint32_t *useLen)
{
    uint8_t *ret = ParseDhePara(ctx, data, len, paraLen, useLen);
    if (ret == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15321, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "g param malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
    }
    return ret;
}

static int32_t ParseServerDhe(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ServerKeyExchangeMsg *msg)
{
    int32_t ret;
    uint32_t useLen, offset = 0u;
    ServerDh *dh = &msg->keyEx.dh;

    dh->p = ParseDheParaPWithLog(ctx, data, len, &dh->plen, &useLen);
    if (dh->p == NULL) {
        return HITLS_PARSE_DH_P_ERR;
    }
    offset += useLen;

    dh->g = ParseDheParaGWithLog(ctx, &data[offset], len - offset, &dh->glen, &useLen);
    if (dh->g == NULL) {
        return HITLS_PARSE_DH_G_ERR;
    }
    offset += useLen;

    /* Parse DH public key from peer */
    dh->pubkey = ParseDhePublicKey(ctx, &data[offset], len - offset, &dh->pubKeyLen, &useLen);
    if (dh->pubkey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15322, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse dh public key fail.", 0, 0, 0, 0);
        return HITLS_PARSE_DH_PUBKEY_ERR;
    }
    offset += useLen;

    /* DHE_PSK, ANON_DHE key exchange is not signed */
    if (ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_DHE_PSK ||
        ctx->negotiatedInfo.cipherSuiteInfo.authAlg == HITLS_AUTH_NULL) {
        return HITLS_SUCCESS;
    }

    uint32_t kxDataLen = offset;

    dh->signAlgorithm = ctx->negotiatedInfo.cipherSuiteInfo.signScheme;
    ret = ParseSignAlgorithm(ctx, &data[offset], len - offset, &dh->signAlgorithm, &useLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15323, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse dh sign algorithm fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += useLen;

    dh->signData = ParseSignature(ctx, &data[offset], len - offset, &dh->signSize, &useLen);
    if (dh->signData == NULL) {
        return HITLS_PARSE_DH_SIGN_ERR;
    }

    ret = VerifySignature(ctx, data, kxDataLen, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ctx->peerInfo.peerSignHashAlg = dh->signAlgorithm;
    return HITLS_SUCCESS;
}

/* In the case of psk negotiation, if ServerKeyExchange is received, the length of the identity hint must be parseed,
 * but the length may be empty */
static int32_t ParseServerIdentityHint(
    const uint8_t *data, uint32_t len, ServerKeyExchangeMsg *msg, uint32_t *usedLen)
{
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint32_t offset = 0u;
    uint16_t identityHintLen = BSL_ByteToUint16(&data[offset]);
    offset += sizeof(uint16_t);

    if (identityHintLen > len - offset) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    /* may receive no identity hint */
    uint8_t *identityHint = NULL;
    if (identityHintLen != 0) {
        identityHint = (uint8_t *)BSL_SAL_Dump(&data[offset], identityHintLen);
        if (identityHint == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID15324, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "receive server identity hint: %s.", identityHint);
    }
    msg->pskIdentityHint = identityHint;
    msg->hintSize = identityHintLen;

    *usedLen = sizeof(uint16_t) + identityHintLen;

    return HITLS_SUCCESS;
}

#ifndef HITLS_NO_TLCP11
static int32_t VerifyServerKxMsgEcc(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, CERT_SignParam *signParam)
{
    uint8_t *sign = NULL;
    uint16_t signSize = 0;
    uint32_t useLen = 0;
    /* Parse the signature data. The signature data is released after it is used up. The information is not maintained
     * in the ServerKeyExchangeMsg.keyEx.ecdh file */
    sign = ParseSignature(ctx, &data[0], len, &signSize, &useLen);
    if (sign == NULL) {
        return HITLS_PARSE_ECDH_SIGN_ERR;
    }
    HITLS_CERT_X509 *signCert = SAL_CERT_PairGetX509(ctx->hsCtx->peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(&(ctx->config.tlsConfig), signCert,
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
static int32_t ParseServerKxMsgEcc(TLS_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    HITLS_SignAlgo signAlgo;
    HITLS_HashAlgo hashAlgo;

    /* The algorithm suite has been determined. The error probability of this function is low. Therefore, the alert is
     * not required. */
    if (!CFG_GetSignParamBySchemes(
        ctx->negotiatedInfo.version, ctx->negotiatedInfo.cipherSuiteInfo.signScheme, &signAlgo, &hashAlgo)) {
        return HITLS_PACK_SIGNATURE_ERR;
    }

    uint32_t certLen = 0;
    uint8_t *cert = SAL_CERT_ClntGmEncodeEncCert(ctx, ctx->hsCtx->peerCert, &certLen);
    if (cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15326, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode encrypt cert failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_CERT_ERR_ENCODE;
    }
    uint32_t signDataLen = 0;
    uint8_t *signData = HS_PrepareSignDataTlcp(ctx, cert, certLen, &signDataLen);
    BSL_SAL_FREE(cert);
    if (signData == NULL) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15327, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "data malloc fail when parse server key exchange msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    CERT_SignParam signParam = {signAlgo, hashAlgo, signData, signDataLen, NULL, 0};
    int32_t ret = VerifyServerKxMsgEcc(ctx, data, len, &signParam);
    BSL_SAL_FREE(signData);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15328, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify signature fail when parse server key exchange msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
        return HITLS_PARSE_VERIFY_SIGN_FAIL;
    }
    return HITLS_SUCCESS;
}
#endif

int32_t ParseServerKeyExchange(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    int32_t ret;
    uint32_t offset = 0u;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    ServerKeyExchangeMsg *msg = &hsMsg->body.serverKeyExchange;
    msg->keyExType = hsCtx->kxCtx->keyExchAlgo;

    if (IsPskNegotiation(ctx)) {
        ret = ParseServerIdentityHint(data, len, msg, &offset);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    switch (hsCtx->kxCtx->keyExchAlgo) {
        case HITLS_KEY_EXCH_ECDHE: /** contains the TLCP */
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = ParseServerEcdhe(ctx, &data[offset], len - offset, msg);
            break;
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = ParseServerDhe(ctx, &data[offset], len - offset, msg);
            break;
        /* PSK & RSA_PSK nego may pack identity hint inside ServerKeyExchange msg */
        case HITLS_KEY_EXCH_PSK:
        case HITLS_KEY_EXCH_RSA_PSK:
            ret = HITLS_SUCCESS;
            break;
#ifndef HITLS_NO_TLCP11
        case HITLS_KEY_EXCH_ECC:
            ret = ParseServerKxMsgEcc(ctx, &data[offset], len - offset);
            break;
#endif
        default:
            ret = HITLS_PARSE_UNSUPPORT_KX_ALG;
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            break;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15325, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse server key exchange msg fail.", 0, 0, 0, 0);
        CleanServerKeyExchange(msg);
        return ret;
    }

    return HITLS_SUCCESS;
}

void CleanServerKeyExchange(ServerKeyExchangeMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    if (msg->keyExType == HITLS_KEY_EXCH_ECDHE || msg->keyExType == HITLS_KEY_EXCH_ECDHE_PSK) {
        BSL_SAL_FREE(msg->keyEx.ecdh.pubKey);
        BSL_SAL_FREE(msg->keyEx.ecdh.signData);
    } else if (msg->keyExType == HITLS_KEY_EXCH_DHE || msg->keyExType == HITLS_KEY_EXCH_DHE_PSK) {
        BSL_SAL_FREE(msg->keyEx.dh.p);
        BSL_SAL_FREE(msg->keyEx.dh.g);
        BSL_SAL_FREE(msg->keyEx.dh.pubkey);
        BSL_SAL_FREE(msg->keyEx.dh.signData);
    }

    BSL_SAL_FREE(msg->pskIdentityHint);

    return;
}
