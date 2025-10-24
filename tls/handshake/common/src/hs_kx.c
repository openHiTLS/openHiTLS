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

#include <string.h>
#include "hitls_build.h"
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "crypt.h"
#include "cert_method.h"
#include "session.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "hs_ctx.h"
#include "transcript_hash.h"
#include "hs_common.h"
#include "hs_kx.h"

KeyExchCtx *HS_KeyExchCtxNew(void)
{
    KeyExchCtx *keyExchCtx = (KeyExchCtx *)BSL_SAL_Malloc(sizeof(KeyExchCtx));
    if (keyExchCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15514, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "keyExchCtx malloc failed.", 0, 0, 0, 0);
        return NULL;
    }
    (void)memset_s(keyExchCtx, sizeof(KeyExchCtx), 0, sizeof(KeyExchCtx));
    return keyExchCtx;
}

void HS_KeyExchCtxFree(KeyExchCtx *keyExchCtx)
{
    if (keyExchCtx == NULL) {
        return;
    }
#ifdef HITLS_TLS_FEATURE_PSK
    if (keyExchCtx->pskInfo != NULL) {
        BSL_SAL_CleanseData(keyExchCtx->pskInfo->psk, keyExchCtx->pskInfo->pskLen);
        BSL_SAL_FREE(keyExchCtx->pskInfo->identity);
        BSL_SAL_FREE(keyExchCtx->pskInfo->psk);
        BSL_SAL_FREE(keyExchCtx->pskInfo);
    }
#endif /* HITLS_TLS_FEATURE_PSK */
#ifdef HITLS_TLS_PROTO_TLS13
    BSL_SAL_CleanseData(keyExchCtx->pskInfo13.psk, keyExchCtx->pskInfo13.pskLen);
    BSL_SAL_FREE(keyExchCtx->pskInfo13.psk);
    HITLS_SESS_Free(keyExchCtx->pskInfo13.resumeSession);
    keyExchCtx->pskInfo13.resumeSession = NULL;
    if (keyExchCtx->pskInfo13.userPskSess != NULL) {
        HITLS_SESS_Free(keyExchCtx->pskInfo13.userPskSess->pskSession);
        keyExchCtx->pskInfo13.userPskSess->pskSession = NULL;
        BSL_SAL_FREE(keyExchCtx->pskInfo13.userPskSess->identity);
        BSL_SAL_FREE(keyExchCtx->pskInfo13.userPskSess);
    }
    BSL_SAL_FREE(keyExchCtx->ciphertext);
#endif /* HITLS_TLS_PROTO_TLS13 */
    BSL_SAL_FREE(keyExchCtx->peerPubkey);
    SAL_CRYPT_FreeEcdhKey(keyExchCtx->secondKey);
    switch (keyExchCtx->keyExchAlgo) {
        case HITLS_KEY_EXCH_NULL:
        case HITLS_KEY_EXCH_ECDHE:
        case HITLS_KEY_EXCH_ECDH:
        case HITLS_KEY_EXCH_ECDHE_PSK:
            SAL_CRYPT_FreeEcdhKey(keyExchCtx->key);
            break;
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
        case HITLS_KEY_EXCH_DH:
            SAL_CRYPT_FreeDhKey(keyExchCtx->key);
            BSL_SAL_FREE(keyExchCtx->keyExchParam.dh.p);
            BSL_SAL_FREE(keyExchCtx->keyExchParam.dh.g);
            break;
        case HITLS_KEY_EXCH_RSA:
        default:
            break;
    }
    BSL_SAL_FREE(keyExchCtx);
    return;
}
#ifdef HITLS_TLS_HOST_CLIENT
#ifdef HITLS_TLS_SUITE_KX_ECDHE
static bool NamedCurveSupport(HITLS_NamedGroup inNamedGroup, const TLS_Config *config)
{
    for (uint32_t i = 0u; i < config->groupsSize; i++) {
        if (inNamedGroup == config->groups[i]) {
            return true;
        }
    }
    return false;
}

static int32_t ProcessServerKxMsgNamedCurve(TLS_Ctx *ctx, const ServerKeyExchangeMsg *serverKxMsg)
{
    HITLS_ECCurveType type = serverKxMsg->keyEx.ecdh.ecPara.type;
    HITLS_NamedGroup namedGroup = serverKxMsg->keyEx.ecdh.ecPara.param.namedcurve;

    if (NamedCurveSupport(namedGroup, &ctx->config.tlsConfig) == false) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_NAMED_CURVE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15515, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "no supported curves found.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_UNSUPPORT_NAMED_CURVE;
    }

    uint32_t peerPubkeyLen = serverKxMsg->keyEx.ecdh.pubKeySize;

    uint8_t *peerPubkey = BSL_SAL_Malloc(peerPubkeyLen);
    if (peerPubkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15516, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubkey malloc fail when process server kx msg named curve.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(peerPubkey, peerPubkeyLen, serverKxMsg->keyEx.ecdh.pubKey, peerPubkeyLen);

    ctx->hsCtx->kxCtx->keyExchParam.ecdh.curveParams.type = type;
    ctx->hsCtx->kxCtx->keyExchParam.ecdh.curveParams.param.namedcurve = namedGroup;
    HITLS_CRYPT_Key *key = SAL_CRYPT_GenEcdhKeyPair(ctx, &ctx->hsCtx->kxCtx->keyExchParam.ecdh.curveParams);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_ENCODE_ECDH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15517, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get ecdh key pair fail when process server kx msg named curve.", 0, 0, 0, 0);
        BSL_SAL_FREE(peerPubkey);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MSG_HANDLE_ERR_ENCODE_ECDH_KEY;
    }
    ctx->hsCtx->kxCtx->key = key;
    ctx->hsCtx->kxCtx->peerPubkey = peerPubkey;
    ctx->hsCtx->kxCtx->pubKeyLen = peerPubkeyLen;
    ctx->negotiatedInfo.negotiatedGroup = namedGroup;

    return HITLS_SUCCESS;
}

int32_t HS_ProcessServerKxMsgEcdhe(TLS_Ctx *ctx, const ServerKeyExchangeMsg *serverKxMsg)
{
    HITLS_ECCurveType type = serverKxMsg->keyEx.ecdh.ecPara.type;
    switch (type) {
        case HITLS_EC_CURVE_TYPE_NAMED_CURVE:
            return ProcessServerKxMsgNamedCurve(ctx, serverKxMsg);
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNKNOWN_CURVE_TYPE);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15518, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unknow the curve type in server kx msg.", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_UNKNOWN_CURVE_TYPE;
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
int32_t HS_ProcessServerKxMsgDhe(TLS_Ctx *ctx, const ServerKeyExchangeMsg *serverKxMsg)
{
    const ServerDh *dh = &serverKxMsg->keyEx.dh;
    HITLS_CRYPT_Key *key = SAL_CRYPT_GenerateDhKeyByParams(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        dh->p, dh->plen, dh->g, dh->glen);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ERR_ENCODE_DH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15519, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get dhe key pair fail when process server dhe kx msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MSG_HANDLE_ERR_ENCODE_DH_KEY;
    }

    uint8_t *pubkey = BSL_SAL_Dump(dh->pubkey, dh->pubKeyLen);
    if (pubkey == NULL) {
        SAL_CRYPT_FreeDhKey(key);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15520, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubkey malloc fail when process server dhe kx msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    ctx->hsCtx->kxCtx->keyExchParam.dh.plen = dh->plen;
    ctx->hsCtx->kxCtx->key = key;
    ctx->hsCtx->kxCtx->peerPubkey = pubkey;
    ctx->hsCtx->kxCtx->pubKeyLen = dh->pubKeyLen;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_DHE */
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_SUITE_KX_ECDHE
static int32_t ProcessClientKxMsgNamedCurve(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg)
{
    uint32_t peerPubkeyLen = clientKxMsg->dataSize;
    uint8_t *peerPubkey = BSL_SAL_Malloc(peerPubkeyLen);
    if (peerPubkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15521, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubkey malloc fail when process client kx msg named curve.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(peerPubkey, peerPubkeyLen, clientKxMsg->data, peerPubkeyLen);

    ctx->hsCtx->kxCtx->peerPubkey = peerPubkey;
    ctx->hsCtx->kxCtx->pubKeyLen = peerPubkeyLen;
    return HITLS_SUCCESS;
}

int32_t HS_ProcessClientKxMsgEcdhe(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg)
{
    HITLS_ECCurveType type = ctx->hsCtx->kxCtx->keyExchParam.ecdh.curveParams.type;
    switch (type) {
        case HITLS_EC_CURVE_TYPE_NAMED_CURVE:
            return ProcessClientKxMsgNamedCurve(ctx, clientKxMsg);
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNKNOWN_CURVE_TYPE);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15522, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unknow the curve type in client kx msg.", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_UNKNOWN_CURVE_TYPE;
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
int32_t HS_ProcessClientKxMsgDhe(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg)
{
    uint32_t peerPubkeyLen = clientKxMsg->dataSize;
    uint8_t *peerPubkey = BSL_SAL_Dump(clientKxMsg->data, peerPubkeyLen);
    if (peerPubkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15523, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubkey malloc fail when process client dhe kx msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    ctx->hsCtx->kxCtx->peerPubkey = peerPubkey;
    ctx->hsCtx->kxCtx->pubKeyLen = peerPubkeyLen;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_RSA
int32_t HS_ProcessClientKxMsgRsa(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *keyExchCtx = hsCtx->kxCtx;
    uint32_t secretLen = clientKxMsg->dataSize < MASTER_SECRET_LEN ? MASTER_SECRET_LEN : clientKxMsg->dataSize;
    uint8_t *premasterSecret = BSL_SAL_Calloc(1u, secretLen);
    if (premasterSecret == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15524, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Decrypt RSA-Encrypted Premaster Secret error: out of memory.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    uint8_t premaster[MASTER_SECRET_LEN];
    ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), premaster, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(premasterSecret);
        return ret;
    }

    CERT_MgrCtx *certMgrCtx = ctx->config.tlsConfig.certMgrCtx;
    HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(certMgrCtx, false);
    uint32_t valid = ~(uint32_t)SAL_CERT_KeyDecrypt(ctx, privateKey, clientKxMsg->data,
        clientKxMsg->dataSize, premasterSecret, &secretLen);
    valid &= Uint32ConstTimeEqual(secretLen, MASTER_SECRET_LEN);
    // Check the version in the premaster secret
    uint16_t version = ctx->negotiatedInfo.clientVersion;
    uint32_t versionCheck = Uint32ConstTimeEqual(version, HITLS_VERSION_TLS11) |
                            Uint32ConstTimeEqual(version, HITLS_VERSION_TLS12) |
                            Uint32ConstTimeEqual(version, HITLS_VERSION_DTLS12) |
                            ~Uint32ConstTimeIsZero((uint32_t)ctx->config.tlsConfig.needCheckPmsVersion);
    valid &= (~versionCheck) | Uint32ConstTimeEqual(version, BSL_ByteToUint16(premasterSecret));

    for (uint32_t i = 0; i < MASTER_SECRET_LEN; i++) {
        uint32_t mask = valid & Uint32ConstTimeLt(i, secretLen);
        keyExchCtx->keyExchParam.rsa.preMasterSecret[i] =
            Uint8ConstTimeSelect(mask, premasterSecret[i & mask], premaster[i]);
    }
    BSL_SAL_CleanseData(premasterSecret, secretLen);
    BSL_SAL_FREE(premasterSecret);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_RSA */

#ifdef HITLS_TLS_PROTO_TLCP11
int32_t HS_ProcessClientKxMsgSm2(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *keyExchCtx = hsCtx->kxCtx;
    uint8_t *preMasterSecret = BSL_SAL_Calloc(1u, clientKxMsg->dataSize);
    if (preMasterSecret == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16213, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Decrypt SM2-Encrypted PremasterSecret error: out of memory", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    uint32_t secretLen = clientKxMsg->dataSize;
    CERT_MgrCtx *certMgrCtx = ctx->config.tlsConfig.certMgrCtx;
    HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(certMgrCtx, true);
    ret = SAL_CERT_KeyDecrypt(ctx, privateKey, clientKxMsg->data, clientKxMsg->dataSize, preMasterSecret, &secretLen);
    if ((ret != HITLS_SUCCESS) || (secretLen != MASTER_SECRET_LEN)) {
        /* If the server fails to process the message, it is prohibited to send the alert message. The randomly
         * generated premaster secret must be used to continue the handshake */
        SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), keyExchCtx->keyExchParam.ecc.preMasterSecret, MASTER_SECRET_LEN);
        BSL_SAL_FREE(preMasterSecret);
        return HITLS_SUCCESS;
    }
    uint16_t clientVersion = BSL_ByteToUint16(preMasterSecret);
    // In any case, a TLS server MUST NOT generate an alert if processing an RSA-encrypted
    // premaster secret message fails, or the version number is not as expected.
    if (ctx->negotiatedInfo.clientVersion != clientVersion) {
        // If the version does not match, a 46-byte preMasterSecret is randomly generated
        uint16_t version = ctx->negotiatedInfo.clientVersion;
        uint32_t offset = 0u;
        // 8：right shift a byte
        keyExchCtx->keyExchParam.ecc.preMasterSecret[offset++] = (uint8_t)(version >> 8);
        keyExchCtx->keyExchParam.ecc.preMasterSecret[offset++] = (uint8_t)(version);
        SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), keyExchCtx->keyExchParam.ecc.preMasterSecret + offset, MASTER_SECRET_LEN - offset);
        BSL_SAL_CleanseData(preMasterSecret, secretLen);
        BSL_SAL_FREE(preMasterSecret);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15348, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse RSA-Encrypted Premaster Secret client version mismatch: msg clientVersion = %u, \
            ctx->negotiatedInfo.clientVersion = %u.", clientVersion, ctx->negotiatedInfo.clientVersion, 0, 0);
        return HITLS_SUCCESS;
    }

    (void)memcpy_s(keyExchCtx->keyExchParam.ecc.preMasterSecret, MASTER_SECRET_LEN, preMasterSecret, secretLen);
    BSL_SAL_CleanseData(preMasterSecret, secretLen);
    BSL_SAL_FREE(preMasterSecret);
    return HITLS_SUCCESS;
}
#endif
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_FEATURE_PSK
static int32_t AppendPsk(uint8_t *pskPmsBuf, uint32_t pskPmsBufLen, uint8_t *psk, uint32_t pskLen)
{
    uint32_t offset = 0u;
    uint8_t *pskPmsBufTmp = pskPmsBuf;

    BSL_Uint16ToByte((uint16_t)pskLen, pskPmsBufTmp);
    offset += sizeof(uint16_t);

    if (memcpy_s(&pskPmsBufTmp[offset], pskPmsBufLen - offset, psk, pskLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16828, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t GeneratePskPreMasterSecret(TLS_Ctx *ctx, uint8_t *pmsBuf, uint32_t pmsBufLen, uint32_t *pmsUsedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint8_t tmpPskPmsBufTmp[MAX_PRE_MASTER_SECRET_SIZE] = {0};

    uint8_t *psk = ctx->hsCtx->kxCtx->pskInfo->psk;
    uint32_t pskLen = ctx->hsCtx->kxCtx->pskInfo->pskLen;

    if (psk == NULL || pskLen > HS_PSK_MAX_LEN) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID16829, "input null");
    }

    switch (ctx->hsCtx->kxCtx->keyExchAlgo) {
        /* |shareKeyLen(2 byte)|shareKey|PskLen(2 byte)|psk| */
        case HITLS_KEY_EXCH_DHE_PSK:
        case HITLS_KEY_EXCH_ECDHE_PSK:
            /* Padding ShareKeyLen */
            BSL_Uint16ToByte((uint16_t)*pmsUsedLen, &tmpPskPmsBufTmp[offset]);
            offset += sizeof(uint16_t);
            /* Padding ShareKey */
            ret = memcpy_s(&tmpPskPmsBufTmp[offset], MAX_PRE_MASTER_SECRET_SIZE - offset, pmsBuf, *pmsUsedLen);
            offset += *pmsUsedLen;
            break;
        /* |48(2 byte)|version number(2 byte)|rand value(46 byte)|pskLen(2 byte)|psk| */
        case HITLS_KEY_EXCH_RSA_PSK:
            /* Padding the length (Version + RandValue). The value is fixed to 48 */
            BSL_Uint16ToByte(MASTER_SECRET_LEN, &tmpPskPmsBufTmp[offset]);
            offset = sizeof(uint16_t);
            /* Padding |Version|RandValue| */
            ret = memcpy_s(&tmpPskPmsBufTmp[offset], MAX_PRE_MASTER_SECRET_SIZE - offset, pmsBuf, *pmsUsedLen);
            offset += MASTER_SECRET_LEN;
            break;
        /* |N(2 byte)|N 0s|N(2 byte)|psk|, N stands for pskLen */
        case HITLS_KEY_EXCH_PSK:
            /* Padding pskLen */
            BSL_Uint16ToByte((uint16_t)pskLen, &tmpPskPmsBufTmp[offset]);
            offset = sizeof(uint16_t);
            /* padding pskLen with zeros */
            ret = memset_s(&tmpPskPmsBufTmp[offset], MAX_PRE_MASTER_SECRET_SIZE - offset, 0, pskLen);
            offset += pskLen;
            break;
        default:
            /* no key exchange algo matched */
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG, BINLOG_ID16830, "unknow keyExchAlgo");
    }

    if (ret != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16831, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "key exchange algo is %d, memcpy fail", ctx->hsCtx->kxCtx->keyExchAlgo, 0, 0, 0);
        goto ERR;
    }

    if (AppendPsk(&tmpPskPmsBufTmp[offset], MAX_PRE_MASTER_SECRET_SIZE - offset, psk, pskLen) != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16832, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "AppendPsk fail", 0, 0, 0, 0);
        goto ERR;
    }
    offset += (sizeof(uint16_t) + pskLen);

    if (memcpy_s(pmsBuf, pmsBufLen, tmpPskPmsBufTmp, offset) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16833, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        goto ERR;
    }
    *pmsUsedLen = offset;

    (void)memset_s(tmpPskPmsBufTmp, MAX_PRE_MASTER_SECRET_SIZE, 0, MAX_PRE_MASTER_SECRET_SIZE);

    return HITLS_SUCCESS;
ERR:
    (void)memset_s(tmpPskPmsBufTmp, MAX_PRE_MASTER_SECRET_SIZE, 0, MAX_PRE_MASTER_SECRET_SIZE);
    BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
    return HITLS_MEMCPY_FAIL;
}
#endif /* HITLS_TLS_FEATURE_PSK */

int32_t DeriveMasterSecret(TLS_Ctx *ctx, const uint8_t *preMasterSecret, uint32_t len)
{
    int32_t ret = HITLS_SUCCESS;
    const uint8_t masterSecretLabel[] = "master secret";
    const uint8_t exMasterSecretLabel[] = "extended master secret";
    uint8_t seed[HS_RANDOM_SIZE * 2] = {0}; // seed size is twice the random size
    uint32_t seedLen = sizeof(seed);
    bool isExtendedMasterSecret = ctx->negotiatedInfo.isExtendedMasterSecret;

    CRYPT_KeyDeriveParameters deriveInfo;
    deriveInfo.hashAlgo = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    deriveInfo.secret = preMasterSecret;
    deriveInfo.secretLen = len;

    if (isExtendedMasterSecret) {
        deriveInfo.label = exMasterSecretLabel;
        deriveInfo.labelLen = sizeof(exMasterSecretLabel) - 1u;
        ret = VERIFY_CalcSessionHash(
            ctx->hsCtx->verifyCtx, seed, &seedLen);  // Use session hash as seed for key deriviation
    } else {
        deriveInfo.label = masterSecretLabel;
        deriveInfo.labelLen = sizeof(masterSecretLabel) - 1u;
        ret = HS_CombineRandom(ctx->hsCtx->clientRandom, ctx->hsCtx->serverRandom, HS_RANDOM_SIZE, seed, seedLen);
    }
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID15525, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "get PRF seed fail.", 0, 0, 0, 0);
        return ret;
    }
    deriveInfo.seed = seed;
    deriveInfo.seedLen = seedLen;
    deriveInfo.libCtx = LIBCTX_FROM_CTX(ctx);
    deriveInfo.attrName = ATTRIBUTE_FROM_CTX(ctx);
    ret = SAL_CRYPT_PRF(&deriveInfo, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15526, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "failed to invoke the PRF function.", 0, 0, 0, 0);
        return ret;
    }
#ifdef HITLS_TLS_MAINTAIN_KEYLOG
    if (HITLS_LogSecret(ctx, MASTER_SECRET_LABEL, ctx->hsCtx->masterKey,
        MASTER_SECRET_LEN) != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15336, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "failed to LogSecret, MASTER_SECRET_LABEL.", 0, 0, 0, 0);
    }
#endif /* HITLS_TLS_MAINTAIN_KEYLOG */
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_SUITE_KX_ECDHE
static int32_t GenPremasterSecretFromEcdhe(TLS_Ctx *ctx, uint8_t *preMasterSecret, uint32_t *preMasterSecretLen)
{
#ifdef HITLS_TLS_PROTO_TLCP11
    int32_t ret = HITLS_SUCCESS;
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        HITLS_Config *config = &ctx->config.tlsConfig;
        CERT_MgrCtx *certMgrCtx = config->certMgrCtx;
        HITLS_CERT_Key *priKey = SAL_CERT_GetCurrentPrivateKey(certMgrCtx, true);
        if (priKey == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16834, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "GetCurrentPrivateKey fail", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_EXP_CERT);
            return HITLS_CERT_ERR_EXP_CERT;
        }
        HITLS_CRYPT_Key *peerPubKey = NULL;
        HITLS_CERT_X509 *cert = SAL_CERT_GetTlcpEncCert(ctx->hsCtx->peerCert);
        ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&peerPubKey);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16835, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "GET_PUB_KEY fail", 0, 0, 0, 0);
            return ret;
        }

        *preMasterSecretLen = MASTER_SECRET_LEN;
        HITLS_Sm2GenShareKeyParameters sm2ShareKeyParam = {ctx->hsCtx->kxCtx->key, ctx->hsCtx->kxCtx->peerPubkey,
            ctx->hsCtx->kxCtx->pubKeyLen, priKey, peerPubKey, ctx->isClient };
        ret = SAL_CRYPT_CalcSm2dhSharedSecret(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
            &sm2ShareKeyParam, preMasterSecret, preMasterSecretLen);
        SAL_CERT_KeyFree(certMgrCtx, peerPubKey);
        return ret;
    }
#endif
    return SAL_CRYPT_CalcEcdhSharedSecret(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        ctx->hsCtx->kxCtx->key, ctx->hsCtx->kxCtx->peerPubkey,
        ctx->hsCtx->kxCtx->pubKeyLen, preMasterSecret, preMasterSecretLen);
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
static int32_t GenPreMasterSecret(TLS_Ctx *ctx, uint8_t *preMasterSecret, uint32_t *preMasterSecretLen)
{
    int32_t ret = HITLS_SUCCESS;
    KeyExchCtx *keyExchCtx = ctx->hsCtx->kxCtx;
    (void)preMasterSecret;
    (void)preMasterSecretLen;
    switch (keyExchCtx->keyExchAlgo) {
#ifdef HITLS_TLS_SUITE_KX_ECDHE
        case HITLS_KEY_EXCH_ECDHE:
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = GenPremasterSecretFromEcdhe(ctx, preMasterSecret, preMasterSecretLen);
            break;
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = SAL_CRYPT_CalcDhSharedSecret(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx), keyExchCtx->key,
                keyExchCtx->peerPubkey, keyExchCtx->pubKeyLen,
                preMasterSecret, preMasterSecretLen);
            break;
#endif /* HITLS_TLS_SUITE_KX_DHE */
#ifdef HITLS_TLS_SUITE_KX_RSA
        case HITLS_KEY_EXCH_RSA:
        case HITLS_KEY_EXCH_RSA_PSK:
            if (memcpy_s(preMasterSecret, *preMasterSecretLen,
                keyExchCtx->keyExchParam.rsa.preMasterSecret, MASTER_SECRET_LEN) != EOK) {
                    BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
                    return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMCPY_FAIL, BINLOG_ID16836, "memcpy fail");
                }
            *preMasterSecretLen = MASTER_SECRET_LEN;
            break;
#endif /* HITLS_TLS_SUITE_KX_RSA */
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_KEY_EXCH_ECC:
            if (memcpy_s(preMasterSecret, *preMasterSecretLen,
                keyExchCtx->keyExchParam.ecc.preMasterSecret, MASTER_SECRET_LEN) != EOK) {
                    BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
                    return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMCPY_FAIL, BINLOG_ID16837, "memcpy fail");
                }
            *preMasterSecretLen = MASTER_SECRET_LEN;
            break;
#endif
        case HITLS_KEY_EXCH_PSK:
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG, BINLOG_ID16838, "unknow keyExchAlgo");
    }
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

int32_t HS_GenerateMasterSecret(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    uint8_t preMasterSecret[MAX_PRE_MASTER_SECRET_SIZE] = {0};
    /* key exchange algorithm contains psk, preMasterSecret: |uint16_t|MAX_OTHER_SECRET_SIZE|uint16_t|HS_PSK_MAX_LEN|
       key exchange algorithm not contains psk, preMasterSecret: |MAX_OTHER_SECRET_SIZE| */
    uint32_t preMasterSecretLen = MAX_OTHER_SECRET_SIZE;

    ret = GenPreMasterSecret(ctx, preMasterSecret, &preMasterSecretLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15527, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calc ecdh shared secret failed.", 0, 0, 0, 0);
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_PSK
    /* re-arrange preMasterSecret for psk negotiation */
    if (IsPskNegotiation(ctx)) {
        ret = GeneratePskPreMasterSecret(ctx, preMasterSecret, MAX_PRE_MASTER_SECRET_SIZE, &preMasterSecretLen);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_CleanseData(preMasterSecret, MAX_PRE_MASTER_SECRET_SIZE);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    ret = DeriveMasterSecret(ctx, preMasterSecret, preMasterSecretLen);
    BSL_SAL_CleanseData(preMasterSecret, MAX_PRE_MASTER_SECRET_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15528, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "derive master secret failed.", 0, 0, 0, 0);
    }
    return ret;
}

int32_t HS_SetInitPendingStateParam(const TLS_Ctx *ctx, bool isClient, REC_SecParameters *keyPara)
{
    const HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    const CipherSuiteInfo *cipherSuiteInfo = &ctx->negotiatedInfo.cipherSuiteInfo;
    keyPara->isClient = isClient;
    keyPara->prfAlg = cipherSuiteInfo->hashAlg;
    keyPara->macAlg = cipherSuiteInfo->macAlg;
    keyPara->cipherAlg = cipherSuiteInfo->cipherAlg;
    keyPara->cipherType = cipherSuiteInfo->cipherType;
    keyPara->fixedIvLength = cipherSuiteInfo->fixedIvLength; /** iv length. In the TLS1.2 AEAD algorithm, iv length is
                                                                the implicit IV length. */
    keyPara->encKeyLen = cipherSuiteInfo->encKeyLen;
    keyPara->macKeyLen = cipherSuiteInfo->macKeyLen; /** If the AEAD algorithm is used, the MAC key length is zero. */
    keyPara->blockLength = cipherSuiteInfo->blockLength;
    keyPara->recordIvLength = cipherSuiteInfo->recordIvLength; /** The explicit IV needs to be sent to the peer. */
    keyPara->macLen = cipherSuiteInfo->macLen;
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        uint32_t clientRandomSize = HS_RANDOM_SIZE;
        if (memcpy_s(keyPara->clientRandom, clientRandomSize, hsCtx->clientRandom, HS_RANDOM_SIZE) != EOK) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16114, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Client random value copy failed.", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
        uint32_t serverRandomSize = HS_RANDOM_SIZE;
        if (memcpy_s(keyPara->serverRandom, serverRandomSize, hsCtx->serverRandom, HS_RANDOM_SIZE) != EOK) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16115, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Server random value copy failed.", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
    }
    return HITLS_SUCCESS;
}

int32_t HS_KeyEstablish(TLS_Ctx *ctx, bool isClient)
{
    int32_t ret = HITLS_SUCCESS;
    REC_SecParameters keyPara;
    uint32_t masterSecretSize = MASTER_SECRET_LEN;

    ret = HS_SetInitPendingStateParam(ctx, isClient, &keyPara);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)memcpy_s(keyPara.masterSecret, masterSecretSize, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
    ret = REC_InitPendingState(ctx, &keyPara);

    (void)memset_s(keyPara.masterSecret, MASTER_SECRET_LEN, 0, MASTER_SECRET_LEN);
    return ret;
}
#ifdef HITLS_TLS_FEATURE_SESSION
int32_t HS_ResumeKeyEstablish(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    uint32_t masterKeySize = MAX_DIGEST_SIZE;
    int32_t ret = HITLS_SESS_GetMasterKey(ctx->session, hsCtx->masterKey, &masterKeySize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15529, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Resume session: get master secret failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    ret = HS_KeyEstablish(ctx, ctx->isClient);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15530, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server key establish fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)
    ret = HS_SetSctpAuthKey(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16839, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
            "SetSctpAuthKey fail", 0, 0, 0, 0);
    }
#endif
    return ret;
}
#endif /* HITLS_TLS_FEATURE_SESSION */
#ifdef HITLS_TLS_FEATURE_PSK
int32_t HS_ProcessServerKxMsgIdentityHint(TLS_Ctx *ctx, const ServerKeyExchangeMsg *serverKxMsg)
{
    if (ctx == NULL || serverKxMsg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16840, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    uint8_t psk[HS_PSK_MAX_LEN] = {0};
    uint8_t identity[HS_PSK_IDENTITY_MAX_LEN + 1] = {0};

    int32_t ret = HITLS_SUCCESS;
    do {
        if (ctx->config.tlsConfig.pskClientCb == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16841, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pskClientCb null", 0, 0, 0, 0);
            ret = HITLS_UNREGISTERED_CALLBACK;
            break;
        }

        uint32_t pskUsedLen = ctx->config.tlsConfig.pskClientCb(ctx, serverKxMsg->pskIdentityHint, identity,
            HS_PSK_IDENTITY_MAX_LEN, psk, HS_PSK_MAX_LEN);
        if (pskUsedLen == 0 || pskUsedLen > HS_PSK_MAX_LEN) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16842, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "psk len err", 0, 0, 0, 0);
            ret = HITLS_MSG_HANDLE_ILLEGAL_PSK_LEN;
            break;
        }

        uint32_t identityUsedLen = (uint32_t)strnlen((char *)identity, HS_PSK_IDENTITY_MAX_LEN + 1);
        if (identityUsedLen > HS_PSK_IDENTITY_MAX_LEN) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16843, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "identity len err", 0, 0, 0, 0);
            ret = HITLS_MSG_HANDLE_ILLEGAL_IDENTITY_LEN;
            break;
        }

        if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
            ctx->hsCtx->kxCtx->pskInfo = (PskInfo *)BSL_SAL_Calloc(1u, sizeof(PskInfo));
            if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16844, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "Calloc fail", 0, 0, 0, 0);
                ret = HITLS_MEMALLOC_FAIL;
                break;
            }
        }

        uint8_t *tmpIdentity = (uint8_t *)BSL_SAL_Calloc(1u, (identityUsedLen + 1) * sizeof(uint8_t));
        if (tmpIdentity == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16845, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc err", 0, 0, 0, 0);
            ret = HITLS_MEMALLOC_FAIL;
            break;
        }
        (void)memcpy_s(tmpIdentity, identityUsedLen + 1, identity, identityUsedLen);

        uint8_t *tmpPsk = (uint8_t *)BSL_SAL_Dump(psk, pskUsedLen);
        if (tmpPsk == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16846, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
            BSL_SAL_FREE(tmpIdentity);
            ret = HITLS_MEMALLOC_FAIL;
            break;
        }

        BSL_SAL_FREE(ctx->hsCtx->kxCtx->pskInfo->identity);
        ctx->hsCtx->kxCtx->pskInfo->identity = tmpIdentity;
        ctx->hsCtx->kxCtx->pskInfo->identityLen = identityUsedLen;

        BSL_SAL_FREE(ctx->hsCtx->kxCtx->pskInfo->psk);
        ctx->hsCtx->kxCtx->pskInfo->psk = tmpPsk;
        ctx->hsCtx->kxCtx->pskInfo->pskLen = pskUsedLen;
    } while (false);

    (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}
#endif /* HITLS_TLS_FEATURE_PSK */
