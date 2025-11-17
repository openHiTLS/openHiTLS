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
#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "tls.h"
#include "crypt.h"
#include "cert_method.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "pack_common.h"

#ifdef HITLS_TLS_SUITE_KX_ECDHE
#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t PackDtlcpbytes(const TLS_Ctx *ctx, PackPacket *pkt)
{
    /* Considering compatibility. Three bytes are added to the client key exchange. */
    int32_t ret = HITLS_SUCCESS;
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        ret = PackAppendUint8ToBuf(pkt, HITLS_EC_CURVE_TYPE_NAMED_CURVE);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        ret = PackAppendUint16ToBuf(pkt, HITLS_EC_GROUP_SM2);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    return HITLS_SUCCESS;
}
#endif

static int32_t PackClientKxMsgNamedCurve(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t pubKeyLen;
    EcdhParam *ecdh = &(ctx->hsCtx->kxCtx->keyExchParam.ecdh);
    HITLS_ECParameters *curveParams = &ecdh->curveParams;
    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;

    pubKeyLen = SAL_CRYPT_GetCryptLength(ctx, HITLS_CRYPT_INFO_CMD_GET_PUBLIC_KEY_LEN, curveParams->param.namedcurve);
    if (pubKeyLen == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_INVALID_KX_PUBKEY_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15673, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid key exchange pubKey length.", 0, 0, 0, 0);
        return HITLS_PACK_INVALID_KX_PUBKEY_LENGTH;
    }

#ifdef HITLS_TLS_PROTO_TLCP11
    ret = PackDtlcpbytes(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif

    uint32_t pubKeyLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint8_t), &pubKeyLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t *reservedBuf = NULL;
    ret = PackReserveBytes(pkt, pubKeyLen, &reservedBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t pubKeyUsedLen = 0;
    ret = SAL_CRYPT_EncodeEcdhPubKey(kxCtx->key, reservedBuf, pubKeyLen, &pubKeyUsedLen);
    if (ret != HITLS_SUCCESS || pubKeyLen != pubKeyUsedLen) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15675, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode ecdh key fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
    }

    (void)PackSkipBytes(pkt, pubKeyUsedLen);

    PackCloseUint8Field(pkt, pubKeyLenPosition);

    return HITLS_SUCCESS;
}

static int32_t PackClientKxMsgEcdhe(const TLS_Ctx *ctx, PackPacket *pkt)
{
    HITLS_ECCurveType type = ctx->hsCtx->kxCtx->keyExchParam.ecdh.curveParams.type;
    switch (type) {
        case HITLS_EC_CURVE_TYPE_NAMED_CURVE:
            return PackClientKxMsgNamedCurve(ctx, pkt);
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSUPPORT_KX_CURVE_TYPE);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15676, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unsupport key exchange curve type.", 0, 0, 0, 0);
    return HITLS_PACK_UNSUPPORT_KX_CURVE_TYPE;
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
static int32_t PackClientKxMsgDhe(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    DhParam *dh = &ctx->hsCtx->kxCtx->keyExchParam.dh;
    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;

    uint32_t pubkeyLen = dh->plen;
    if (pubkeyLen == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_INVALID_KX_PUBKEY_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15677, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid key exchange pubKey length.", 0, 0, 0, 0);
        return HITLS_PACK_INVALID_KX_PUBKEY_LENGTH;
    }

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

    /* fill pubkey */
    ret = SAL_CRYPT_EncodeDhPubKey(kxCtx->key, reservedBuf, pubkeyLen, &pubkeyLen);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_DH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15679, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode dh pub key fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_ENCODE_DH_KEY;
    }

    ret = PackSkipBytes(pkt, pubkeyLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    PackCloseUint16Field(pkt, pubKeyLenPosition);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_RSA
int32_t PackClientKxMsgRsa(TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *kxCtx = hsCtx->kxCtx;
    uint8_t *preMasterSecret = kxCtx->keyExchParam.rsa.preMasterSecret;

    uint32_t encLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &encLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    HITLS_CERT_X509 *cert = SAL_CERT_PairGetX509(hsCtx->peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16929, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CERT_CTRL_GET_PUB_KEY fail", 0, 0, 0, 0);
        return ret;
    }

    /* Use CERT_KEY_CTRL_GET_SIGN_LEN to get encrypt length(Only by RSA and ECC) */
    uint32_t encryptLen = MAX_SIGN_SIZE;
    uint8_t *encBuf = NULL;
    ret = PackReserveBytes(pkt, encryptLen, &encBuf);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        return ret;
    }

    uint32_t encLen = encryptLen;
    ret = SAL_CERT_KeyEncrypt(ctx, pubkey, preMasterSecret, MASTER_SECRET_LEN, encBuf, &encLen);
    SAL_CERT_KeyFree(mgrCtx, pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16930, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "KeyEncrypt fail", 0, 0, 0, 0);
        return ret;
    }

    ret = PackSkipBytes(pkt, encLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    PackCloseUint16Field(pkt, encLenPosition);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_RSA */
#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t PackClientKxMsgEcc(TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *kxCtx = hsCtx->kxCtx;
    uint8_t *preMasterSecret = kxCtx->keyExchParam.ecc.preMasterSecret;

    uint32_t encLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &encLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Encrypt the PreMasterSecret using the public key of the server certificate */
    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *certMgrCtx = config->certMgrCtx;
    HITLS_CERT_X509 *certEnc = SAL_CERT_GetTlcpEncCert(hsCtx->peerCert);
    HITLS_CERT_Key *pubkey = NULL;
    ret = SAL_CERT_X509Ctrl(config, certEnc, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16218, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get encrypt cert public key failed.", 0, 0, 0, 0);
        return ret;
    }

    /* Use CERT_KEY_CTRL_GET_SIGN_LEN to get encrypt length(Only by RSA and ECC) */
    uint32_t encryptLen = MAX_SIGN_SIZE;
    uint8_t *encBuf = NULL;
    ret = PackReserveBytes(pkt, encryptLen, &encBuf);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(certMgrCtx, pubkey);
        return ret;
    }

    uint32_t encLen = encryptLen;
    ret = SAL_CERT_KeyEncrypt(ctx, pubkey, preMasterSecret, MASTER_SECRET_LEN, encBuf, &encLen);
    SAL_CERT_KeyFree(certMgrCtx, pubkey);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16932, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "KeyEncrypt fail", 0, 0, 0, 0);
        return ret;
    }

    ret = PackSkipBytes(pkt, encLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    PackCloseUint16Field(pkt, encLenPosition);

    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_FEATURE_PSK
static int32_t PackClientKxMsgIdentity(const TLS_Ctx *ctx, PackPacket *pkt)
{
    uint8_t *pskIdentity = ctx->hsCtx->kxCtx->pskInfo->identity;
    uint32_t pskIdentitySize = ctx->hsCtx->kxCtx->pskInfo->identityLen;

    /* append identity */
    int32_t ret = PackAppendUint16ToBuf(pkt, (uint16_t)pskIdentitySize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (pskIdentitySize > 0) {
        ret = PackAppendDataToBuf(pkt, pskIdentity, pskIdentitySize);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PSK */
// Pack the ClientKeyExchange message.

int32_t PackClientKeyExchange(TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_PSK
    /* PSK negotiation pre act: append identity */
    if (IsPskNegotiation(ctx)) {
        ret = PackClientKxMsgIdentity(ctx, pkt);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    /* Pack the key exchange message */
    switch (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg) {
#ifdef HITLS_TLS_SUITE_KX_ECDHE
        case HITLS_KEY_EXCH_ECDHE: /* TLCP is also included */
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = PackClientKxMsgEcdhe(ctx, pkt);
            break;
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = PackClientKxMsgDhe(ctx, pkt);
            break;
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_RSA
        case HITLS_KEY_EXCH_RSA:
        case HITLS_KEY_EXCH_RSA_PSK:
            ret = PackClientKxMsgRsa(ctx, pkt);
            break;
#endif /* HITLS_TLS_SUITE_KX_RSA */
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_KEY_EXCH_ECC:
            ret = PackClientKxMsgEcc(ctx, pkt);
            break;
#endif
        case HITLS_KEY_EXCH_PSK:
            ret = HITLS_SUCCESS;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSUPPORT_KX_ALG);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15681, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "unsupport key exchange algorithm when pack client key exchange.", 0, 0, 0, 0);
            return HITLS_PACK_UNSUPPORT_KX_ALG;
    }
    return ret;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_CLIENT */