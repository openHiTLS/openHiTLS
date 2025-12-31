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
#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "cipher_suite.h"
#include "crypt.h"
#include "cert.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "pack_common.h"

#if defined(HITLS_TLS_SUITE_KX_ECDHE) || defined(HITLS_TLS_SUITE_KX_DHE)
/* Determine whether additional parameter signatures are required. */
static bool IsNeedKeyExchParamSignature(const TLS_Ctx *ctx)
{
    /* Add the parameter signature only when the authentication algorithm is not HITLS_AUTH_NULL for the DHE and ECDHE
     * cipher suites */
    return ((ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_ECDHE ||
                ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_DHE) &&
            ctx->negotiatedInfo.cipherSuiteInfo.authAlg != HITLS_AUTH_NULL);
}
#endif

#if defined(HITLS_TLS_SUITE_KX_ECDHE) || defined(HITLS_TLS_SUITE_KX_DHE)
static int32_t SignKeyExchParams(TLS_Ctx *ctx, uint8_t *kxData, uint32_t kxDataLen, uint8_t *signBuf, uint32_t *signLen)
{
    uint32_t offset = 0u;
    HITLS_SignHashAlgo signScheme = ctx->negotiatedInfo.signScheme;
    HITLS_SignAlgo signAlgo;
    HITLS_HashAlgo hashAlgo;
    if (CFG_GetSignParamBySchemes(ctx, signScheme, &signAlgo, &hashAlgo) != true) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15496, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sign parm fail.", 0, 0, 0, 0);
        return HITLS_PACK_SIGNATURE_ERR;
    }

    uint32_t dataLen;
    /* Obtain all signature data (random number + server kx content) */
    uint8_t *data = HS_PrepareSignData(ctx, kxData, kxDataLen, &dataLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15495, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "prepare unsigned data fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP_DTLCP11)
#endif /* HITLS_TLS_PROTO_TLCP11 */
    {
        if (ctx->negotiatedInfo.version >= HITLS_VERSION_TLS12) {
            /* TLS1.2 and later versions require explicit hash and signature algorithms to be specified in messages, and
             * TLCP are not written */
            BSL_Uint16ToByte(signScheme, signBuf);
            offset += sizeof(uint16_t);
        }
    }
    /* Temporarily record the position of the signature length in the packet and fill it later */
    uint32_t signLenOffset = offset;
    offset += sizeof(uint16_t);

    /* Fill signature parameters */
    CERT_SignParam signParam = {0};
    signParam.signAlgo = signAlgo;
    signParam.hashAlgo = hashAlgo;
    signParam.data = data;
    signParam.dataLen = dataLen;
    signParam.sign = &signBuf[offset];
    signParam.signLen = (uint16_t)(*signLen - offset);
    /* Fill signature */
    HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(ctx->config.tlsConfig.certMgrCtx, false);
    int32_t ret = SAL_CERT_CreateSign(ctx, privateKey, &signParam);
    BSL_SAL_FREE(data);
    if ((ret != HITLS_SUCCESS) || (offset + signParam.signLen > *signLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15497, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "create signature fail.", 0, 0, 0, 0);
        return HITLS_PACK_SIGNATURE_ERR;
    }
    offset += signParam.signLen;
    BSL_Uint16ToByte((uint16_t)signParam.signLen, &signBuf[signLenOffset]);
    *signLen = offset;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE || HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_ECDHE

static uint32_t GetNamedCurveMsgLen(TLS_Ctx *ctx, uint32_t pubKeyLen)
{
    HITLS_Config *config = &(ctx->config.tlsConfig);

    /* Message length = Curve type (1 byte) + Curve ID (2 byte) + Public key length (1 byte) + Public key + Signature
     * length (2 byte) + Signature */
    uint32_t dataLen = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + pubKeyLen;

    /* ECDHE_PSK key exchange does not require signature */
    if (IsNeedKeyExchParamSignature(ctx)) {
        HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(config->certMgrCtx, false);
        uint32_t signatureLen = SAL_CERT_GetSignMaxLen(config, privateKey);
        if ((signatureLen == 0u) || (signatureLen > MAX_SIGN_SIZE)) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15499, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack ske error: invalid signature length = %u.", signatureLen, 0, 0, 0);
            return 0;
        }

        dataLen += sizeof(uint16_t) + signatureLen;
        /* A signature type needs to be added to TLS1.2/DTLS. The signature type does not need to be transferred */
        if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS12 || ctx->negotiatedInfo.version == HITLS_VERSION_DTLS12) {
            dataLen += sizeof(uint16_t);
        }
    }

    return dataLen;
}

static int32_t PackEcdhPublicKey(TLS_Ctx *ctx, uint32_t pubKeyLen, PackPacket *pkt)
{
    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;
    HITLS_ECParameters *ecParam = &(kxCtx->keyExchParam.ecdh.curveParams);
    /* Curve type and curve ID. Although these parameters are ignored in the TLCP, they are
     * filled in to ensure the uniform style. However, the client cannot depend on the value of this parameter */
    int32_t ret = PackAppendUint8ToBuf(pkt, (uint8_t)(ecParam->type));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackAppendUint16ToBuf(pkt, (uint16_t)(ecParam->param.namedcurve));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Public key length and public key content */
    uint32_t pubKeyLenOffset = 0;
    ret = PackStartLengthField(pkt, sizeof(uint8_t), &pubKeyLenOffset);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t *pubKeyBuf = NULL;
    ret = PackReserveBytes(pkt, pubKeyLen, &pubKeyBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t pubKeyUsedLen = 0;
    ret = SAL_CRYPT_EncodeEcdhPubKey(kxCtx->key, pubKeyBuf, pubKeyLen, &pubKeyUsedLen);
    if (ret != HITLS_SUCCESS || pubKeyLen != pubKeyUsedLen) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15501, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode ecdh key fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
    }
    (void)PackSkipBytes(pkt, pubKeyUsedLen);

    PackCloseUint8Field(pkt, pubKeyLenOffset);
	
    return HITLS_SUCCESS;
}
static int32_t PackServerKxMsgNamedCurve(TLS_Ctx *ctx, PackPacket *pkt)
{
    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;
    HITLS_ECParameters *ecParam = &(kxCtx->keyExchParam.ecdh.curveParams);
    uint32_t pubKeyLen =
        HS_GetCryptLength(ctx, HITLS_CRYPT_INFO_CMD_GET_PUBLIC_KEY_LEN, ecParam->param.namedcurve);
    if (pubKeyLen == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_INVALID_KX_PUBKEY_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15498, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack ske error: unsupport named curve = %u.", ecParam->param.namedcurve, 0, 0, 0);
        return HITLS_PACK_INVALID_KX_PUBKEY_LENGTH;
    }
    uint32_t dataLen = GetNamedCurveMsgLen(ctx, pubKeyLen);
    if (dataLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16941, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetNamedCurveMsgLen err", 0, 0, 0, 0);
        return HITLS_PACK_SIGNATURE_ERR;
    }

    /* If the length of bufLen does not meet the requirements, an error code is returned */
    uint32_t dataOffset = 0;
    int32_t ret = PackGetSubBuffer(pkt, 0, &dataOffset, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = PackEcdhPublicKey(ctx, pubKeyLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (IsNeedKeyExchParamSignature(ctx)) {
        uint32_t signDataLen = 0;
        (void)PackGetSubBuffer(pkt, dataOffset, &signDataLen, NULL);
        uint32_t signatureLen = dataLen - signDataLen;
        uint8_t *signBuf = NULL;
        ret = PackReserveBytes(pkt, signatureLen, &signBuf);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        uint8_t *signData = NULL;
        (void)PackGetSubBuffer(pkt, dataOffset, &signDataLen, &signData);
        ret = SignKeyExchParams(ctx, signData, signDataLen, signBuf, &signatureLen);
        if (ret != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15502, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "signature fail.", 0, 0, 0, 0);
            return HITLS_PACK_SIGNATURE_ERR;
        }
        (void)PackSkipBytes(pkt, signatureLen);
    }

    return HITLS_SUCCESS;
}

static int32_t PackServerKxMsgEcdhe(TLS_Ctx *ctx, PackPacket *pkt)
{
    HITLS_ECCurveType type = ctx->hsCtx->kxCtx->keyExchParam.ecdh.curveParams.type;
    switch (type) {
        case HITLS_EC_CURVE_TYPE_NAMED_CURVE:
            return PackServerKxMsgNamedCurve(ctx, pkt);
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSUPPORT_KX_CURVE_TYPE);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15503, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unsupport key exchange curve type.", 0, 0, 0, 0);
    return HITLS_PACK_UNSUPPORT_KX_CURVE_TYPE;
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t PackEccSignature(TLS_Ctx *ctx, PackPacket *pkt, HITLS_SignAlgo signAlgo,
                                HITLS_HashAlgo hashAlgo, uint8_t *data, uint32_t dataLen)
{
    HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(ctx->config.tlsConfig.certMgrCtx, false);
    uint32_t signatureLen = SAL_CERT_GetSignMaxLen(&(ctx->config.tlsConfig), privateKey);
    if ((signatureLen == 0u) || (signatureLen > MAX_SIGN_SIZE)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15508, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid signature length.", 0, 0, 0, 0);
        return HITLS_PACK_SIGNATURE_ERR;
    }

    /* Fill signature parameters */
    CERT_SignParam signParam = {0};
    signParam.signAlgo = signAlgo;
    signParam.hashAlgo = hashAlgo;
    signParam.data = data;
    signParam.dataLen = dataLen;
    uint8_t *signBuf = NULL;
    int32_t ret = PackReserveBytes(pkt, signatureLen, &signBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    signParam.sign = signBuf;
    signParam.signLen = signatureLen;

    ret = SAL_CERT_CreateSign(ctx, privateKey, &signParam);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_PACK_SIGNATURE_ERR, BINLOG_ID16221, "create sm2 signature fail");
    }

    ret = PackSkipBytes(pkt, signParam.signLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}
/* This function is invoked only by the TLCP */
static int32_t PackServerKxMsgEcc(TLS_Ctx *ctx, PackPacket *pkt)
{
    uint8_t *data = NULL;
    uint32_t dataLen, certLen;

    uint8_t *encCert = SAL_CERT_SrvrGmEncodeEncCert(ctx, &certLen);
    if (encCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_ENCODE);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_ENCODE, BINLOG_ID16942, "SAL_CERT_SrvrGmEncodeEncCert fail");
    }
    /* Obtain all signature data (random number + server kx content) */
    data = HS_PrepareSignDataTlcp(ctx, encCert, certLen, &dataLen);
    BSL_SAL_FREE(encCert);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16219, "prepare unsigned data fail");
    }

    HITLS_SignAlgo signAlgo;
    HITLS_HashAlgo hashAlgo;
    if (!CFG_GetSignParamBySchemes(ctx, ctx->negotiatedInfo.signScheme, &signAlgo, &hashAlgo)) {
        BSL_SAL_FREE(data);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_PACK_SIGNATURE_ERR, BINLOG_ID16220, "get sign parm fail");
    }
    /* The hash and signature algorithms do not need to be explicitly specified in messages by TLCP. The hash algorithm
     * obtained based on signScheme is used. */
    uint32_t signLenPosition = 0u; /* The records the position of the signature length in the message temporarily, and
                                        then fills the signature length in the message later */
    int32_t ret = PackStartLengthField(pkt, sizeof(uint16_t), &signLenPosition);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(data);
        return ret;
    }

    ret = PackEccSignature(ctx, pkt, signAlgo, hashAlgo, data, dataLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(data);
        return ret;
    }

    PackCloseUint16Field(pkt, signLenPosition);

    BSL_SAL_FREE(data);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLCP11 */

#ifdef HITLS_TLS_SUITE_KX_DHE
static int32_t PackKxPrimaryData(const TLS_Ctx *ctx, PackPacket *pkt)
{
    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;
    DhParam *dh = &ctx->hsCtx->kxCtx->keyExchParam.dh;
    uint32_t pubkeyLen = dh->plen;
    uint16_t plen = dh->plen;
    uint16_t glen = dh->glen;

    int32_t ret = PackReserveBytes(pkt, sizeof(uint16_t) + plen + sizeof(uint16_t) + glen, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, plen);
    (void)PackAppendDataToBuf(pkt, dh->p, plen);
    (void)PackAppendUint16ToBuf(pkt, glen);
    (void)PackAppendDataToBuf(pkt, dh->g, glen);

    uint32_t pubKeyLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &pubKeyLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t *reservedBuf = NULL;
    ret = PackReserveBytes(pkt, pubkeyLen, &reservedBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = SAL_CRYPT_EncodeDhPubKey(kxCtx->key, reservedBuf, pubkeyLen, &pubkeyLen);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_DH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15506, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode dhe key fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_ENCODE_DH_KEY;
    }

    ret = PackSkipBytes(pkt, pubkeyLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    PackCloseUint16Field(pkt, pubKeyLenPosition);

    return HITLS_SUCCESS;
}

static int32_t PackServerKxMsgDhePre(TLS_Ctx *ctx, uint32_t *signatureLen)
{
    if (IsNeedKeyExchParamSignature(ctx)) {
        HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(ctx->config.tlsConfig.certMgrCtx, false);
        *signatureLen = SAL_CERT_GetSignMaxLen(&(ctx->config.tlsConfig), privateKey);
        if ((*signatureLen == 0u) || (*signatureLen > MAX_SIGN_SIZE)) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15508, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "invalid signature length.", 0, 0, 0, 0);
            return HITLS_PACK_SIGNATURE_ERR;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t GetDheParameterLen(TLS_Ctx *ctx, uint32_t *outLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t dataLen = 0;
    DhParam *dh = &ctx->hsCtx->kxCtx->keyExchParam.dh;
    uint32_t pubkeyLen = dh->plen;
    uint16_t plen = dh->plen;
    uint16_t glen = dh->glen;

    if (pubkeyLen == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_INVALID_KX_PUBKEY_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15507, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid key exchange pubKey length.", 0, 0, 0, 0);
        return HITLS_PACK_INVALID_KX_PUBKEY_LENGTH;
    }

    /* DHE_PSK and ANON_DH do not need signatures */
    uint32_t signatureLen = 0;
    ret = PackServerKxMsgDhePre(ctx, &signatureLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    dataLen = sizeof(uint16_t) + plen + sizeof(uint16_t) + glen + sizeof(uint16_t) + pubkeyLen;
    if (IsNeedKeyExchParamSignature(ctx)) {
        dataLen += (sizeof(uint16_t) + signatureLen);
    }
#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12)
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS12 || ctx->negotiatedInfo.version == HITLS_VERSION_DTLS12) {
        dataLen += sizeof(uint16_t);   // TLS1.2/DTLS needs to add a signature type
    }
#endif /* HITLS_TLS_PROTO_TLS12 || HITLS_TLS_PROTO_DTLS12 */
    *outLen = dataLen;
    return HITLS_SUCCESS;
}

static int32_t PackServerKxMsgDhe(TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t dataLen = 0;
    ret = GetDheParameterLen(ctx, &dataLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Fill the following values in sequence: plen, p, glen, g, pubkeylen, pubkey, signature len, and signature */
    uint32_t dataOffset = 0;
    ret = PackGetSubBuffer(pkt, 0, &dataOffset, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackKxPrimaryData(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (IsNeedKeyExchParamSignature(ctx)) {
        uint32_t signDataLen = 0;
        (void)PackGetSubBuffer(pkt, dataOffset, &signDataLen, NULL);
        uint32_t signLen = dataLen - signDataLen;
        uint8_t *signBuf = NULL;
        ret = PackReserveBytes(pkt, signLen, &signBuf);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        uint8_t *signData = NULL;
        (void)PackGetSubBuffer(pkt, dataOffset, &signDataLen, &signData);
        ret = SignKeyExchParams(ctx, signData, signDataLen, signBuf, &signLen);
        if (ret != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15510, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "kx msg signature fail. ret %d", ret, 0, 0, 0);
            return HITLS_PACK_SIGNATURE_ERR;
        }
        ret = PackSkipBytes(pkt, signLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_FEATURE_PSK
static int32_t PackServerKxMsgPskIdentityHint(const TLS_Ctx *ctx, PackPacket *pkt)
{
    uint8_t *pskIdentityHint = ctx->config.tlsConfig.pskIdentityHint;
    /* The length of hintSize <= HS_PSK_IDENTITY_MAX_LEN is ensured during configuration. Therefore, the length of
     * uint16_t can be forcibly converted to the length of uint16_t */
    uint16_t pskIdentityHintSize = (uint16_t)ctx->config.tlsConfig.hintSize;

    /* append identity hint */
    /* for dhe_psk, ecdhe_psk, msg must contain the length of hint even if there is no hint to provide */
    int32_t ret = PackAppendUint16ToBuf(pkt, pskIdentityHintSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (pskIdentityHint != NULL && pskIdentityHintSize > 0) {
        ret = PackAppendDataToBuf(pkt, pskIdentityHint, pskIdentityHintSize);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PSK */
// Pack the ServerKeyExchange message.
int32_t PackServerKeyExchange(TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_PSK
    /* pack psk identity hint before dynamic key */
    if (IsPskNegotiation(ctx)) {
        ret = PackServerKxMsgPskIdentityHint(ctx, pkt);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    /* Pack a key exchange message */
    switch (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg) {
#ifdef HITLS_TLS_SUITE_KX_ECDHE
        case HITLS_KEY_EXCH_ECDHE:
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = PackServerKxMsgEcdhe(ctx, pkt);
            break;
#endif
#ifdef HITLS_TLS_SUITE_KX_DHE
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = PackServerKxMsgDhe(ctx, pkt);
            break;
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_RSA
        case HITLS_KEY_EXCH_RSA_PSK:
        case HITLS_KEY_EXCH_PSK:
            /* for psk and rsa_psk nego, ServerKeyExchange msg contains only identity hint */
            ret = HITLS_SUCCESS;
            break;
#endif /* HITLS_TLS_SUITE_KX_RSA */
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_KEY_EXCH_ECC:
            ret = PackServerKxMsgEcc(ctx, pkt);
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSUPPORT_KX_ALG);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15513, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "unsupport key exchange algorithm when pack server key exchange msg.", 0, 0, 0, 0);
            return HITLS_PACK_UNSUPPORT_KX_ALG;
    }

    return ret;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_SERVER */