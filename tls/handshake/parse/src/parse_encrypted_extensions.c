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
#if defined(HITLS_TLS_HOST_CLIENT) && defined(HITLS_TLS_PROTO_TLS13)
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "rec.h"
#include "hs.h"
#include "hs_extensions.h"
#include "hs_common.h"
#include "parse_extensions.h"
#include "parse_common.h"
#include "custom_extensions.h"

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
#ifdef HITLS_TLS_FEATURE_ALPN
    BSL_SAL_FREE(msg->alpnSelected);
#endif /* HITLS_TLS_FEATURE_ALPN */
    return;
}

static int32_t ParseEncryptedSupportGroups(ParsePacket *pkt, EncryptedExtensions *msg)
{
    /* Has parsed extensions of the same type */
    if (msg->haveSupportedGroups == true) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_DUPLICATE_EXTENDED_MSG, BINLOG_ID15709,
            BINGLOG_STR("ClientSupportGroups repeated"), ALERT_ILLEGAL_PARAMETER);
    }

    uint16_t groupLen = 0;
    const char *logStr = BINGLOG_STR("parse supported groups len fail.");
    int32_t ret = ParseBytesToUint16(pkt, &groupLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15710, logStr, ALERT_DECODE_ERROR);
    }
    groupLen /= sizeof(uint16_t);

    /* If the length of the message does not match the extended length, or the length is 0,
       the handshake message error is returned */
    if (((groupLen * sizeof(uint16_t)) != (pkt->bufLen - sizeof(uint16_t))) || (groupLen == 0)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15711, logStr, ALERT_DECODE_ERROR);
    }

    BSL_SAL_FREE(msg->supportedGroups);
    msg->supportedGroups = (uint16_t *)BSL_SAL_Malloc(groupLen * sizeof(uint16_t));
    if (msg->supportedGroups == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15712,
            BINGLOG_STR("supportedGroups malloc fail"), ALERT_UNKNOWN);
    }

    for (uint32_t i = 0; i < groupLen; i++) {
        msg->supportedGroups[i] = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
        *pkt->bufOffset += sizeof(uint16_t);
    }

    msg->supportedGroupsSize = groupLen;
    msg->haveSupportedGroups = true;

    return HITLS_SUCCESS;
}

static int32_t ParseEncryptedExBody(TLS_Ctx *ctx, uint16_t extMsgType, const uint8_t *buf, uint32_t extMsgLen,
    EncryptedExtensions *msg)
{
    uint32_t bufOffset = 0u;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = extMsgLen, .bufOffset = &bufOffset};
    switch (extMsgType) {
        case HS_EX_TYPE_SUPPORTED_GROUPS:
            return ParseEncryptedSupportGroups(&pkt, msg);
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
        case HS_EX_TYPE_CERTIFICATE_AUTHORITIES:
        case HS_EX_TYPE_POST_HS_AUTH:
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS_CERT:
            return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORTED_EXTENSION, BINLOG_ID16239,
                BINGLOG_STR("Illegal extension received"), ALERT_ILLEGAL_PARAMETER);
#ifdef HITLS_TLS_FEATURE_ALPN
        case HS_EX_TYPE_APP_LAYER_PROTOCOLS:
            return ParseServerSelectedAlpnProtocol(
                &pkt, &msg->haveSelectedAlpn, &msg->alpnSelected, &msg->alpnSelectedSize);
#endif /* HITLS_TLS_FEATURE_ALPN */
        default:
            break;
    }
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), extMsgType, HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS)) {
        return ParseCustomExtensions(pkt.ctx, pkt.buf + *pkt.bufOffset, extMsgType, extMsgLen,
            HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS, NULL, 0);
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
    return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORTED_EXTENSION, BINLOG_ID16982,
        "unknow extension received", ALERT_UNSUPPORTED_EXTENSION);
}

// Parse the EncryptedExtensions extension message
int32_t ParseEncryptedEx(TLS_Ctx *ctx, EncryptedExtensions *msg, const uint8_t *buf, uint32_t bufLen)
{
    uint32_t bufOffset = 0u;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};

    while (bufOffset < bufLen) {
        uint32_t extMsgLen = 0u;
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extensionId = 0;
        int32_t ret = CheckForDuplicateExtension(&pkt, &extMsgType, &extMsgLen, &extensionId, msg->extensionTypeMask);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        if (extensionId != HS_EX_TYPE_ID_UNRECOGNIZED
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
            || !IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), extMsgType, HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS)
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
        ) {
            msg->extensionTypeMask |= 1ULL << extensionId;
            /* check whether the extension that is not sent is received. */
            if (!GetExtensionFlagValue(ctx, extensionId)) {
                BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17329, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "client did not send but get extension type %u.", extensionId, 0, 0, 0);
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
                return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
            }
        }

        ret = ParseEncryptedExBody(ctx, extMsgType, &buf[bufOffset], extMsgLen, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += extMsgLen;
    }

    if (bufOffset != bufLen) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16239,
            BINGLOG_STR("encrypted extensions len incorrect"), ALERT_DECODE_ERROR);
    }

    return HITLS_SUCCESS;
}

// Parse the EncryptedExtensions message.
int32_t ParseEncryptedExtensions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    if ((buf == NULL) || (hsMsg == NULL)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16983, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    /* Parse the EncryptedExtensions extension message */
    EncryptedExtensions *msg = &hsMsg->body.encryptedExtensions;
    uint32_t bufOffset = 0u;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};

    /* Obtain the extended message length */
    uint16_t exMsgLen = 0;
    const char *logStr = BINGLOG_STR("parse encrypted Extensions len fail.");
    int32_t ret = ParseBytesToUint16(&pkt, &exMsgLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16128, logStr, ALERT_DECODE_ERROR);
    }

    if (pkt.bufLen - *pkt.bufOffset != exMsgLen) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15715, logStr, ALERT_DECODE_ERROR);
    }

    return ParseEncryptedEx(pkt.ctx, msg, &pkt.buf[*pkt.bufOffset], exMsgLen);
}
#endif /* HITLS_TLS_HOST_CLIENT && HITLS_TLS_PROTO_TLS13 */
