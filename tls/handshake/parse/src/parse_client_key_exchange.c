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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_crypt_type.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "parse_msg.h"
#include "parse_common.h"

#ifdef HITLS_TLS_SUITE_KX_ECDHE
/**
* @brief Parse the client ecdh message.
*
* @param ctx [IN] TLS context
* @param data [IN] message buffer
* @param len [IN] message buffer length
* @param hsMsg [OUT] Parsed message structure
*
* @retval HITLS_SUCCESS parsed successfully.
* @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
*/
static int32_t ParseClientKxMsgEcdhe(ParsePacket *pkt, ClientKeyExchangeMsg *msg)
{
    const char *logStr = BINGLOG_STR("clientKeyEx length error.");

    /* Considering compatibility, add 3 bytes to the client key exchange */
#ifdef HITLS_TLS_PROTO_TLCP11
    if (pkt->ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        // Curve type + Curve ID + Public key length
        uint8_t minLen = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t);
        if (pkt->bufLen - *pkt->bufOffset < minLen) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16222,
                logStr, ALERT_DECODE_ERROR);
        }
        // Ignore the three bytes
        *pkt->bufOffset += sizeof(uint8_t) + sizeof(uint16_t);
    }
#endif
    uint8_t pubKeySize = 0;
    int32_t ret = ParseOneByteLengthField(pkt, &pubKeySize, &msg->data);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15635,
            logStr, ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15637,
            BINGLOG_STR("pubKey malloc fail."), ALERT_UNKNOWN);
    }

    if ((pkt->bufLen != *pkt->bufOffset) || (pubKeySize == 0)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15636,
            BINGLOG_STR("length of client ecdh pubKeySize is incorrect."), ALERT_DECODE_ERROR);
    }

    msg->dataSize = pubKeySize;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
/**
* @brief Parse the Client Dhe message.
*
* @param ctx [IN] TLS context
* @param data [IN] message buffer
* @param len [IN] message buffer length
* @param hsMsg [OUT] Parsed message structure
*
* @retval HITLS_SUCCESS parsed successfully.
* @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
*/
static int32_t ParseClientKxMsgDhe(ParsePacket *pkt, ClientKeyExchangeMsg *msg)
{
    uint16_t pubKeySize = 0;
    int32_t ret = ParseTwoByteLengthField(pkt, &pubKeySize, &msg->data);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15638,
            BINGLOG_STR("clientKeyEx length error."), ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15640,
            BINGLOG_STR("pubKey malloc fail."), ALERT_UNKNOWN);
    }

    if ((pkt->bufLen != *pkt->bufOffset) || (pubKeySize == 0)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15639,
            BINGLOG_STR("length of client dh pubKeySize is incorrect."), ALERT_DECODE_ERROR);
    }

    msg->dataSize = (uint32_t)pubKeySize;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_DHE */
#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
static int32_t ParseClientKxMsgRsa(ParsePacket *pkt, ClientKeyExchangeMsg *msg)
{
    uint32_t encLen = pkt->bufLen - *pkt->bufOffset;
    const char *logStr = BINGLOG_STR("Parse RSA Premaster Secret error.");
    int32_t ret = 0;

    uint16_t parsedEncLen = 0;
    ret = ParseBytesToUint16(pkt, &parsedEncLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15641,
            logStr, ALERT_DECODE_ERROR);
    }
    encLen = parsedEncLen;

    if ((encLen != (pkt->bufLen - *pkt->bufOffset)) || (encLen == 0)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15642,
            logStr, ALERT_DECODE_ERROR);
    }

    ret = ParseBytesToArray(pkt, &msg->data, encLen);
    if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15643,
            BINGLOG_STR("pubKey malloc fail."), ALERT_UNKNOWN);
    }

    msg->dataSize = encLen;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_KX_RSA || HITLS_TLS_PROTO_TLCP11 */

#ifdef HITLS_TLS_FEATURE_PSK
static int32_t ParseClientKxMsgIdentity(ParsePacket *pkt, ClientKeyExchangeMsg *msg)
{
    uint16_t identityLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &identityLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16972, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ParseBytesToUint16 fail, ret %d", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    if ((identityLen > pkt->bufLen - *pkt->bufOffset) || (identityLen > HS_PSK_IDENTITY_MAX_LEN)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16973, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "identityLen err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *identity = NULL;
    if (identityLen != 0) {
        identity = (uint8_t *)BSL_SAL_Calloc(1u, (identityLen + 1) * sizeof(uint8_t));
        if (identity == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16974, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Calloc fail", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy_s(identity, identityLen + 1, &pkt->buf[*pkt->bufOffset], identityLen);
    }
    msg->pskIdentity = identity;
    msg->pskIdentitySize = identityLen;
    *pkt->bufOffset += identityLen;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PSK */
int32_t ParseClientKeyExchange(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    int32_t ret;
    uint32_t offset = 0u;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    ClientKeyExchangeMsg *msg = &hsMsg->body.clientKeyExchange;
    ParsePacket pkt = {.ctx = ctx, .buf = data, .bufLen = len, .bufOffset = &offset};
#ifdef HITLS_TLS_FEATURE_PSK
    if (IsPskNegotiation(ctx)) {
        ret = ParseClientKxMsgIdentity(&pkt, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    switch (hsCtx->kxCtx->keyExchAlgo) {
#ifdef HITLS_TLS_SUITE_KX_ECDHE
        case HITLS_KEY_EXCH_ECDHE:
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = ParseClientKxMsgEcdhe(&pkt, msg);
            break;
#endif /* HITLS_TLS_SUITE_KX_ECDHE */
#ifdef HITLS_TLS_SUITE_KX_DHE
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = ParseClientKxMsgDhe(&pkt, msg);
            break;
#endif /* HITLS_TLS_SUITE_KX_DHE */
#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
        case HITLS_KEY_EXCH_RSA:
        case HITLS_KEY_EXCH_RSA_PSK:
        case HITLS_KEY_EXCH_ECC:
            ret = ParseClientKxMsgRsa(&pkt, msg);
            break;
#endif /* HITLS_TLS_SUITE_KX_RSA || HITLS_TLS_PROTO_TLCP11 */
        case HITLS_KEY_EXCH_PSK:
            return HITLS_SUCCESS;
        default:
            ret = HITLS_PARSE_UNSUPPORT_KX_ALG;
            break;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15644, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse client key exchange msg fail.", 0, 0, 0, 0);
        CleanClientKeyExchange(msg);
    }

    return ret;
}

void CleanClientKeyExchange(ClientKeyExchangeMsg *msg)
{
    if (msg == NULL) {
        return;
    }
#ifdef HITLS_TLS_FEATURE_PSK
    BSL_SAL_FREE(msg->pskIdentity);
#endif /* HITLS_TLS_FEATURE_PSK */
    BSL_SAL_FREE(msg->data);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_SERVER */