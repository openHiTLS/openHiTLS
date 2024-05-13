/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_extensions.h"
#include "parse_extensions.h"

/**
 * @brief   Release the memory in the message structure.
 *
 * @param   msg [IN] message structure
 */
void CleanEncryptedExtensions(EncryptedExtensions *msg)
{
    if (msg == NULL) {
        return;
    }
    BSL_SAL_FREE(msg->supportedGroups);
    return;
}

static int32_t ParseEncryptedSupportGroups(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, EncryptedExtensions *msg)
{
    /* Has parsed extensions of the same type */
    if (msg->haveSupportedGroups == true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15709, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "external message type ClientSupportGroups in encrypted extension message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15710, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "external message length (supported groups) in encrypted extension message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    uint16_t groupLen = BSL_ByteToUint16(&buf[bufOffset]) / sizeof(uint16_t);
    bufOffset += sizeof(uint16_t);

    /* If the length of the message does not match the extended length, or the length is 0, return
       the handshake message error. */
    if (((groupLen * sizeof(uint16_t)) != (bufLen - sizeof(uint16_t))) || (groupLen == 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15711, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "external message length (supported groups) in encrypted extension message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->supportedGroups = (uint16_t *)BSL_SAL_Malloc(groupLen * sizeof(uint16_t));
    if (msg->supportedGroups == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15712, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "supportedGroups malloc fail when parse extensions msg.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    for (uint32_t i = 0; i < groupLen; i++) {
        msg->supportedGroups[i] = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
    }

    msg->supportedGroupsSize = groupLen;
    msg->haveSupportedGroups = true;

    return HITLS_SUCCESS;
}

static int32_t ParseEncryptedExBody(TLS_Ctx *ctx, uint16_t extMsgType, const uint8_t *buf, uint32_t extMsgLen,
    EncryptedExtensions *msg)
{
    switch (extMsgType) {
        case HS_EX_TYPE_SUPPORTED_GROUPS:
            return ParseEncryptedSupportGroups(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_EARLY_DATA:
            return ParseEmptyExtension(ctx, HS_EX_TYPE_EARLY_DATA, extMsgLen, &msg->haveEarlyData);
        case HS_EX_TYPE_SERVER_NAME:
            return ParseEmptyExtension(ctx, HS_EX_TYPE_SERVER_NAME, extMsgLen, &msg->haveServerName);
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS:
        case HS_EX_TYPE_KEY_SHARE:
        case HS_EX_TYPE_PRE_SHARED_KEY:
        case HS_EX_TYPE_STATUS_REQUEST:
        case HS_EX_TYPE_STATUS_REQUEST_V2:
        case HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES:
        case HS_EX_TYPE_COOKIE:
        case HS_EX_TYPE_SUPPORTED_VERSIONS:
        case HS_EX_TYPE_TRUSTED_CA_LIST:
        case HS_EX_TYPE_OID_FILTERS:
        case HS_EX_TYPE_POST_HS_AUTH:
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS_CERT:
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16056, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Illegal extension received", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORTED_EXTENSION);
            return HITLS_PARSE_UNSUPPORTED_EXTENSION;
        default:
            break;
    }

    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORTED_EXTENSION);
    return HITLS_PARSE_UNSUPPORTED_EXTENSION;
}

// Parse the EncryptedExtensions extension message
int32_t ParseEncryptedEx(TLS_Ctx *ctx, EncryptedExtensions *msg, const uint8_t *buf, uint32_t bufLen)
{
    uint32_t bufOffset = 0u;
    int32_t ret;

    while (bufOffset < bufLen) {
        uint32_t extMsgLen = 0u;
        uint16_t extMsgType = HS_EX_TYPE_END;
        ret = ParseExHeader(ctx, &buf[bufOffset], bufLen - bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            CleanEncryptedExtensions(msg);
            return ret;
        }
        bufOffset += HS_EX_HEADER_LEN;

        ret = ParseEncryptedExBody(ctx, extMsgType, &buf[bufOffset], extMsgLen, msg);
        if (ret != HITLS_SUCCESS) {
            CleanEncryptedExtensions(msg);
            return ret;
        }
        bufOffset += extMsgLen;
    }

    if (bufOffset != bufLen) {
        CleanEncryptedExtensions(msg);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15714, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the extension len of encrypted extensions msg is incorrect", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return HITLS_SUCCESS;
}

// Parse the EncryptedExtensions message.
int32_t ParseEncryptedExtensions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    if ((buf == NULL) || (hsMsg == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15908, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of handshake message (encrypted Extensions) is not enough for version.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Parse the EncryptedExtensions extension message */
    EncryptedExtensions *msg = &hsMsg->body.encryptedExtensions;
    uint32_t bufOffset = 0u;

    /* Obtain the extended message length */
    uint16_t exMsgLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (bufLen - bufOffset != exMsgLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15715, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the external message length of handshake message (encrypted extensions) is incorrect", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return ParseEncryptedEx(ctx, msg, &buf[bufOffset], exMsgLen);
}
