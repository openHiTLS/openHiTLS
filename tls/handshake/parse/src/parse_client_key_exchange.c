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
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_crypt_type.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "parse_msg.h"


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
static int32_t ParseClientKxMsgEcdhe(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ClientKeyExchangeMsg *msg)
{
    if (len < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15635, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of client key exchange msg is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0;
    /* Compatible with OpenSSL, add 3 bytes to the client key exchange */

#ifndef HITLS_NO_TLCP11
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP11) {
        // Curve type + Curve ID + Public key length
        uint8_t minLen = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t);
        if (len < minLen) {
            BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15917, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "length of client key exchange msg is incorrect.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }
        // Ignore the three bytes
        bufOffset += sizeof(uint8_t) + sizeof(uint16_t);
    }
#endif
    uint8_t pubKeySize = data[bufOffset];
    bufOffset++;

    if ((pubKeySize != (len - bufOffset)) || (pubKeySize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15636, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of client ecdh pubKeySize is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    BSL_SAL_FREE(msg->data);
    msg->data = BSL_SAL_Malloc(pubKeySize);
    if (msg->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15637, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubKey malloc fail when parse client key exchange msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(msg->data, pubKeySize, &data[bufOffset], pubKeySize);
    msg->dataSize = pubKeySize;

    return HITLS_SUCCESS;
}

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
static int32_t ParseClientKxMsgDhe(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ClientKeyExchangeMsg *msg)
{
    if (len < (sizeof(uint16_t))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15638, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of client key exchange msg is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0;
    uint32_t pubKeySize = BSL_ByteToUint16(&data[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if ((pubKeySize != (len - bufOffset)) || (pubKeySize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15639, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of client dh pubKeySize is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    BSL_SAL_FREE(msg->data);
    msg->data = BSL_SAL_Malloc(pubKeySize);
    if (msg->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15640, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubKey malloc fail when parse client key exchange msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(msg->data, pubKeySize, &data[bufOffset], pubKeySize);
    msg->dataSize = pubKeySize;

    return HITLS_SUCCESS;
}

static int32_t ParseClientKxMsgRsa(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, ClientKeyExchangeMsg *msg)
{
    uint32_t offset = 0;
    uint32_t encLen = len;
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15641, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse RSA-Encrypted Premaster Secret error: msgLen = %u.", len, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    offset = sizeof(uint16_t);
    encLen = BSL_ByteToUint16(data);
    if ((encLen != (len - offset)) || (encLen == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15642, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse RSA-Encrypted Premaster Secret error: msgLen = %u, encLen = %u.", len, encLen, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    BSL_SAL_FREE(msg->data);
    msg->data = BSL_SAL_Dump(&data[offset], encLen);
    if (msg->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15643, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubKey malloc fail when parse client key exchange msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    msg->dataSize = encLen;

    return HITLS_SUCCESS;
}

static int32_t ParseClientKxMsgIdentity(const uint8_t *data, uint32_t len, ClientKeyExchangeMsg *msg,
    uint32_t *usedLen)
{
    if (len < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint32_t offset = 0u;
    uint16_t identityLen = BSL_ByteToUint16(&data[offset]);
    offset += sizeof(uint16_t);

    if ((identityLen > len - offset) || (identityLen > HS_PSK_IDENTITY_MAX_LEN)) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *identity = NULL;
    if (identityLen != 0) {
        identity = (uint8_t *)BSL_SAL_Calloc(1u, (identityLen + 1) * sizeof(uint8_t));
        if (identity == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        if (memcpy_s(identity, identityLen + 1, &data[offset], identityLen) != EOK) {
            BSL_SAL_FREE(identity);
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
    }
    msg->pskIdentity = identity;
    msg->pskIdentitySize = identityLen;
    offset += identityLen;

    *usedLen = offset;

    return HITLS_SUCCESS;
}

int32_t ParseClientKeyExchange(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    int32_t ret;
    uint32_t offset = 0u;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    ClientKeyExchangeMsg *msg = &hsMsg->body.clientKeyExchange;

    if (IsPskNegotiation(ctx)) {
        ret = ParseClientKxMsgIdentity(data, len, msg, &offset);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    switch (hsCtx->kxCtx->keyExchAlgo) {
        case HITLS_KEY_EXCH_ECDHE:
        case HITLS_KEY_EXCH_ECDHE_PSK:
            ret = ParseClientKxMsgEcdhe(ctx, &data[offset], len - offset, msg);
            break;
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_DHE_PSK:
            ret = ParseClientKxMsgDhe(ctx, &data[offset], len - offset, msg);
            break;
        case HITLS_KEY_EXCH_RSA:
        case HITLS_KEY_EXCH_RSA_PSK:
#ifndef HITLS_NO_TLCP11
        case HITLS_KEY_EXCH_ECC:
#endif
            ret = ParseClientKxMsgRsa(ctx, &data[offset], len - offset, msg);
            break;
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
        return ret;
    }

    return HITLS_SUCCESS;
}

void CleanClientKeyExchange(ClientKeyExchangeMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->pskIdentity);
    BSL_SAL_FREE(msg->data);
    return;
}
