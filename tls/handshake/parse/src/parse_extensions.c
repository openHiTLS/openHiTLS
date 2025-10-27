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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_extensions.h"
#include "parse_common.h"
#include "parse_extensions.h"

// Parse an empty extended message.
int32_t ParseEmptyExtension(TLS_Ctx *ctx, uint16_t extMsgType, uint32_t extMsgLen, bool *haveExtension)
{
    /* Parsed extensions of the same type */
    if (*haveExtension) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15120, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type:%d len:%lu in hello message is repeated.", extMsgType, extMsgLen, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    /* Parse the empty extended message */
    if (extMsgLen != 0u) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15121, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type:%d len:%lu in hello message is nonzero.", extMsgType, extMsgLen, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    *haveExtension = true;
    return HITLS_SUCCESS;
}

int32_t ParseExCookie(const uint8_t *buf, uint32_t bufLen, uint8_t **cookie, uint16_t *cookieLen)
{
    *cookie = NULL; // Initialize the function entry to prevent wild pointers

    uint32_t bufOffset = 0;
    if (bufLen < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17007, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen error", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Extract the cookie length */
    uint32_t tmpCookieLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    /* If the cookie length is incorrect, an error code is returned */
    if (tmpCookieLen != (bufLen - bufOffset) || tmpCookieLen == 0u) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17008, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen error", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the cookie */
    uint8_t *tmpCookie = BSL_SAL_Dump(&buf[bufOffset], tmpCookieLen);
    if (tmpCookie == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15161, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "cookie malloc fail.", 0, 0,
            0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    *cookie = tmpCookie;
    *cookieLen = (uint16_t)tmpCookieLen;
    return HITLS_SUCCESS;
}
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t ParseSecRenegoInfo(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint8_t **secRenegoInfo,
    uint8_t *secRenegoInfoSize)
{
    /* The message length is not enough to parse secRenegoInfo */
    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15184, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (renegotiation info) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Parse the length of secRenegoInfo */
    uint32_t bufOffset = 0;
    uint8_t tmpSize = buf[bufOffset];
    bufOffset++;

    if (tmpSize != (bufLen - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15185, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the renegotiation info size in the hello messag is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    if (tmpSize == 0) {
        return HITLS_SUCCESS;
    }

    /* Parse secRenegoInfo */
    uint8_t *tmpInfo = (uint8_t *)BSL_SAL_Dump(&buf[bufOffset], tmpSize);
    if (tmpInfo == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15186, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "secRenegoInfo malloc fail when parse renegotiation info.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
    }

    *secRenegoInfo = tmpInfo;
    *secRenegoInfoSize = tmpSize;
    return HITLS_SUCCESS;
}
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
/**
 * @brief Parse the extended message type and length.
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] message buffer, starting from the extension type.
 * @param bufLen [IN] Packet length
 * @param extMsgType [OUT] Extended message type
 * @param extMsgLen [OUT] Extended message length
 *
 * @retval HITLS_SUCCESS parsed successfully.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_PARSE_DUPLICATE_EXTENSIVE_MSG Extended message
 */
int32_t ParseExHeader(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint16_t *extMsgType, uint32_t *extMsgLen)
{
    if (bufLen < HS_EX_HEADER_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15189, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the extension len of client hello msg is incorrect", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    uint16_t type = 0u;
    uint32_t len = 0u;
    /* Obtain the message type */
    type = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);
    /* Obtain the message length */
    len = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15190, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "get extension message in hello, type:%d len:%lu.", type, len, 0, 0);
    if (len > (bufLen - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15191, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type:%d len:%lu in hello message is incorrect.", type, len, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Update the extended message type and length */
    *extMsgType = type;
    *extMsgLen = len;

    return HITLS_SUCCESS;
}

int32_t ParseDupExtProcess(TLS_Ctx *ctx, uint32_t logId, const void *format)
{
    BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
    if (format != NULL) {
        BSL_LOG_BINLOG_VARLEN(logId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "extension type %s is repeated.",
            format);
    }
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
    return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
}

int32_t ParseErrorExtLengthProcess(TLS_Ctx *ctx, uint32_t logId, const void *format)
{
    BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
    if (format != NULL) {
        BSL_LOG_BINLOG_VARLEN(logId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "%s extension message length is incorrect", format);
    }
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
    return HITLS_PARSE_INVALID_MSG_LEN;
}

bool GetExtensionFlagValue(TLS_Ctx *ctx, uint32_t hsExTypeId)
{
    switch (hsExTypeId) {
        case HS_EX_TYPE_ID_SERVER_NAME:                 return ctx->hsCtx->extFlag.haveServerName;
        case HS_EX_TYPE_ID_SUPPORTED_GROUPS:            return ctx->hsCtx->extFlag.haveSupportedGroups;
        case HS_EX_TYPE_ID_POINT_FORMATS:               return ctx->hsCtx->extFlag.havePointFormats;
        case HS_EX_TYPE_ID_SIGNATURE_ALGORITHMS:        return ctx->hsCtx->extFlag.haveSignatureAlgorithms;
        case HS_EX_TYPE_ID_EXTENDED_MASTER_SECRET:      return ctx->hsCtx->extFlag.haveExtendedMasterSecret;
        case HS_EX_TYPE_ID_SUPPORTED_VERSIONS:          return ctx->hsCtx->extFlag.haveSupportedVers;
        case HS_EX_TYPE_ID_CERTIFICATE_AUTHORITIES:     return ctx->hsCtx->extFlag.haveCA;
        case HS_EX_TYPE_ID_POST_HS_AUTH:                return ctx->hsCtx->extFlag.havePostHsAuth;
        case HS_EX_TYPE_ID_KEY_SHARE:                   return ctx->hsCtx->extFlag.haveKeyShare;
        case HS_EX_TYPE_ID_EARLY_DATA:                  return ctx->hsCtx->extFlag.haveEarlyData;
        case HS_EX_TYPE_ID_PSK_KEY_EXCHANGE_MODES:      return ctx->hsCtx->extFlag.havePskExMode;
        case HS_EX_TYPE_ID_PRE_SHARED_KEY:              return ctx->hsCtx->extFlag.havePreShareKey;
        case HS_EX_TYPE_ID_APP_LAYER_PROTOCOLS:         return ctx->hsCtx->extFlag.haveAlpn;
        case HS_EX_TYPE_ID_SESSION_TICKET:              return ctx->hsCtx->extFlag.haveTicket;
        case HS_EX_TYPE_ID_ENCRYPT_THEN_MAC:            return ctx->hsCtx->extFlag.haveEncryptThenMac;
        case HS_EX_TYPE_ID_SIGNATURE_ALGORITHMS_CERT:   return ctx->hsCtx->extFlag.haveSignatureAlgorithmsCert;
        case HS_EX_TYPE_ID_COOKIE:
        case HS_EX_TYPE_ID_RENEGOTIATION_INFO:
        default:
            break;
    }
    return true;
}

int32_t CheckForDuplicateExtension(ParsePacket *pkt, uint16_t *extMsgType, uint32_t *extMsgLen,
    uint32_t *extensionId, uint64_t extensionTypeMask)
{
    TLS_Ctx *ctx = pkt->ctx;
    int32_t ret = ParseExHeader(pkt->ctx, &pkt->buf[*pkt->bufOffset], pkt->bufLen - *pkt->bufOffset,
        extMsgType, extMsgLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    *pkt->bufOffset += HS_EX_HEADER_LEN;

    *extensionId = HS_GetExtensionTypeId(*extMsgType);
    // can not process duplication unknown ext, unknown ext is verified elsewhere
    if (((extensionTypeMask & (1ULL << *extensionId)) != 0) && *extensionId != HS_EX_TYPE_ID_UNRECOGNIZED) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17328, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension type %u is repeated.", *extensionId, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    return HITLS_SUCCESS;
}