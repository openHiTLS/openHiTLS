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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "bsl_list.h"
#include "hs_ctx.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "tls.h"
#include "hs.h"
#include "hs_extensions.h"
#include "hs_common.h"
#include "rec.h"
#include "parse_common.h"
#include "parse_extensions.h"
#include "custom_extensions.h"
//  Parses the point format message sent by the server
static int32_t ParseServerPointFormats(ParsePacket *pkt, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->havePointFormats == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15193, BINGLOG_STR("ServerPointFormats"));
    }

    uint8_t pointFormatsSize = 0;
    int32_t ret = ParseOneByteLengthField(pkt, &pointFormatsSize, &msg->pointFormats);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15194, BINGLOG_STR("ServerPointFormats"));
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15196,
            BINGLOG_STR("pointFormats malloc fail."), ALERT_UNKNOWN);
    }

    if ((pkt->bufLen != *pkt->bufOffset) || (pointFormatsSize == 0u)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15195, BINGLOG_STR("ServerPointFormats"));
    }

    msg->havePointFormats = true;
    msg->pointFormatsSize = pointFormatsSize;

    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLS13
static int32_t ParseServerPreShareKey(ParsePacket *pkt, ServerHelloMsg *msg)
{
    if (msg->haveSelectedIdentity == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15156, BINGLOG_STR("pre_shared_key"));
    }
    int32_t ret = ParseBytesToUint16(pkt, &msg->selectedIdentity);
    if (ret != HITLS_SUCCESS || pkt->bufLen != *pkt->bufOffset) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15157, BINGLOG_STR("pre_shared_key"));
    }

    msg->haveSelectedIdentity = true;

    return HITLS_SUCCESS;
}

int32_t ParseServerKeyShare(ParsePacket *pkt, ServerHelloMsg *msg)
{
    if (msg->haveKeyShare == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15158, BINGLOG_STR("ServerKeyShare"));
    }

    int32_t ret = ParseBytesToUint16(pkt, &msg->keyShare.group);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15159, BINGLOG_STR("ServerKeyShare"));
    }
#ifdef HITLS_TLS_SUITE_SM_TLS13
    if (pkt->ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == HITLS_SM4_GCM_SM3 ||
        pkt->ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == HITLS_SM4_CCM_SM3) {
        if (msg->keyShare.group != HITLS_EC_GROUP_CURVESM2) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
            return HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP;
        }
    }
#endif
    if (pkt->bufLen == *pkt->bufOffset) {
        msg->haveKeyShare = true;
        return HITLS_SUCCESS;  // If there is no subsequent content, the extension is the keyshare of hrr
    }
    uint16_t keyExchangeSize = 0;
    ret = ParseTwoByteLengthField(pkt, &keyExchangeSize, &msg->keyShare.keyExchange);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID16202, BINGLOG_STR("ServerKeyShare"));
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID16984,
            BINGLOG_STR("ServerKeyShare"), ALERT_INTERNAL_ERROR);
    }

    if ((pkt->bufLen != *pkt->bufOffset) || (keyExchangeSize == 0u)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15160, BINGLOG_STR("ServerKeyShare"));
    }

    msg->keyShare.keyExchangeSize = keyExchangeSize;
    msg->haveKeyShare = true;
    return HITLS_SUCCESS;
}

int32_t ParseServerCookie(ParsePacket *pkt, ServerHelloMsg *msg)
{
    if (msg->haveCookie == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15162, BINGLOG_STR("cookie"));
    }

    int32_t ret = ParseExCookie(pkt->buf, pkt->bufLen, &msg->cookie, &msg->cookieLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    msg->haveCookie = true;
    return HITLS_SUCCESS;
}
// Parse the SupportedVersions message.

static int32_t ParseServerSupportedVersions(ParsePacket *pkt, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveSupportedVersion == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15164, BINGLOG_STR("ServerSupportedVersions"));
    }
    int32_t ret = ParseBytesToUint16(pkt, &msg->supportedVersion);
    if (ret != HITLS_SUCCESS || pkt->bufLen != *pkt->bufOffset) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16985, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ParseBytesToUint16 fail, ret %d", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->haveSupportedVersion = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */

// Parses the extended master secret sent by the serve
static int32_t ParseServerExtMasterSecret(ParsePacket *pkt, ServerHelloMsg *msg)
{
    /* Parse the empty extended message */
    return ParseEmptyExtension(pkt->ctx, HS_EX_TYPE_EXTENDED_MASTER_SECRET, pkt->bufLen,
        &msg->haveExtendedMasterSecret);
}
#ifdef HITLS_TLS_FEATURE_ALPN
int32_t ParseServerSelectedAlpnProtocol(
    ParsePacket *pkt, bool *haveSelectedAlpn, uint8_t **alpnSelected, uint16_t *alpnSelectedSize)
{
    /* Parsed extensions of the same type */
    if (*haveSelectedAlpn == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15197, BINGLOG_STR("selected alpn protocol"));
    }

    uint16_t selectedAlpnListLen = 0;
    uint8_t selectedAlpnLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &selectedAlpnListLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15198, BINGLOG_STR("alpn"));
    }
    uint32_t offset = *pkt->bufOffset;
    ret = ParseBytesToUint8(pkt, &selectedAlpnLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID16253, BINGLOG_STR("alpn"));
    }

    /* If the length of the packet does not match the extended length, or the length is 0, the handshake message error
     * is returned */
    if (((selectedAlpnListLen * sizeof(uint8_t)) != (pkt->bufLen - sizeof(uint16_t))) || (selectedAlpnListLen == 0)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15199, BINGLOG_STR("alpn"));
    }
    /* According to the protocol rfc7301, The alpn extension returned by s end is allowed to contain only one protocol
     * name, and returns a handshake message error */
    /* Check whether the listsize of the alpn list returned by the server is anpn size + sizeof(uint8_t) */
    if (selectedAlpnLen != selectedAlpnListLen - sizeof(uint8_t)) {
        return ParseErrorProcess(pkt->ctx, HITLS_MSG_HANDLE_ALPN_UNRECOGNIZED, BINLOG_ID16121,
            BINGLOG_STR("the number of Protocol in ALPN extensions is incorrect."), ALERT_DECODE_ERROR);
    }

    /* The length of bufLen meets： alpnLen | alpn | 0 */
    *alpnSelected = (uint8_t *)BSL_SAL_Calloc(selectedAlpnLen + 1, sizeof(uint8_t));
    if (*alpnSelected == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15200,
            BINGLOG_STR("selected alpn proto malloc fail."), ALERT_UNKNOWN);
    }

    (void)memcpy_s(*alpnSelected, selectedAlpnLen + 1, &pkt->buf[offset], selectedAlpnLen + 1);

    *alpnSelectedSize = selectedAlpnLen + 1;
    *haveSelectedAlpn = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_FEATURE_SNI
/**
 * @brief server hello ServerName extension item
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] message buffer
 * @param bufLen [IN] message length
 * @param msg [OUT] Parsed message
 *
 * @retval HITLS_SUCCESS parsed successfully.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_PARSE_DUPLICATE_EXTENSIVE_MSG Extended message
 */
static int32_t ParseServerServerName(ParsePacket *pkt, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveServerName == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15202, BINGLOG_STR("ServerName"));
    }

    /* If the message length is incorrect, an error code is returned */
    /* rfc6066
     *  When the server decides to receive server_name, the server should include an extension of type "server_name" in
     * the (extended) server hello. The'extension_data' field for this extension should be empty
     */
    if (pkt->bufLen != 0) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15203, BINGLOG_STR("ServerName"));
    }
    msg->haveServerName = true;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SNI */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t ParseServerSecRenegoInfo(ParsePacket *pkt, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveSecRenego == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15204, BINGLOG_STR("renegotiation info"));
    }

    uint8_t secRenegoInfoSize = 0;
    uint8_t *secRenegoInfo = NULL;
    int32_t ret = ParseSecRenegoInfo(pkt->ctx, pkt->buf, pkt->bufLen, &secRenegoInfo, &secRenegoInfoSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    msg->secRenegoInfo = secRenegoInfo;
    msg->secRenegoInfoSize = secRenegoInfoSize;
    msg->haveSecRenego = true;
    return HITLS_SUCCESS;
}
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
static int32_t ParseServerTicket(ParsePacket *pkt, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveTicket == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15964, BINGLOG_STR("ticket"));
    }
#ifdef HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET
    if (pkt->ctx->config.tlsConfig.sessionTicketExtCb != NULL) {
        int32_t ret = pkt->ctx->config.tlsConfig.sessionTicketExtCb(pkt->ctx, pkt->buf, pkt->bufLen,
                                                                 pkt->ctx->config.tlsConfig.sessionTicketExtCbArg);
        if (ret == 0) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_SESSION_TICKET_FAIL, BINLOG_ID17378,
                BINGLOG_STR("parse ticket extension failed."), ALERT_HANDSHAKE_FAILURE);
        }
    }
#endif /* HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET */
    /* The ticket extended data length of server hello can only be empty */
    if (pkt->bufLen != 0) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15965, BINGLOG_STR("tiket"));
    }

    msg->haveTicket = true;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_ETM
static int32_t ParseServerEncryptThenMac(ParsePacket *pkt, ServerHelloMsg *msg)
{
    return ParseEmptyExtension(pkt->ctx, HS_EX_TYPE_ENCRYPT_THEN_MAC, pkt->bufLen, &msg->haveEncryptThenMac);
}
#endif /* HITLS_TLS_FEATURE_ETM */

/**
 * @brief   Parses the extended message from server
 *
 * @param ctx [IN] TLS context
 * @param extMsgType [IN] Extended message type
 * @param buf [IN] message buffer
 * @param extMsgLen [IN] Extended message length
 * @param msg [OUT] Structure of the parsed extended message
 *
 * @retval HITLS_SUCCESS parsed successfully.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_PARSE_DUPLICATE_EXTENSIVE_MSG Extended message
 * @retval HITLS_PARSE_UNSUPPORTED_EXTENSION: unsupported extended field
 */
static int32_t ParseServerExBody(TLS_Ctx *ctx, uint16_t extMsgType, const uint8_t *buf, uint32_t extMsgLen,
    ServerHelloMsg *msg)
{
    uint32_t bufOffset = 0u;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = extMsgLen, .bufOffset = &bufOffset};
    switch (extMsgType) {
        case HS_EX_TYPE_POINT_FORMATS:
            return ParseServerPointFormats(&pkt, msg);
#ifdef HITLS_TLS_FEATURE_SNI
        case HS_EX_TYPE_SERVER_NAME:
            return ParseServerServerName(&pkt, msg);
#endif /* HITLS_TLS_FEATURE_SNI */
        case HS_EX_TYPE_EXTENDED_MASTER_SECRET:
            return ParseServerExtMasterSecret(&pkt, msg);
#ifdef HITLS_TLS_FEATURE_ALPN
        case HS_EX_TYPE_APP_LAYER_PROTOCOLS:
            return ParseServerSelectedAlpnProtocol(
                &pkt, &msg->haveSelectedAlpn, &msg->alpnSelected, &msg->alpnSelectedSize);
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_PROTO_TLS13
        case HS_EX_TYPE_KEY_SHARE:
            return ParseServerKeyShare(&pkt, msg);
        case HS_EX_TYPE_PRE_SHARED_KEY:
            return ParseServerPreShareKey(&pkt, msg);
        case HS_EX_TYPE_COOKIE:
            return ParseServerCookie(&pkt, msg);
        case HS_EX_TYPE_SUPPORTED_VERSIONS:
            return ParseServerSupportedVersions(&pkt, msg);
#endif /* HITLS_TLS_PROTO_TLS13 */
        case HS_EX_TYPE_RENEGOTIATION_INFO:
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
            return ParseServerSecRenegoInfo(&pkt, msg);
#else
            return HITLS_SUCCESS;
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case HS_EX_TYPE_SESSION_TICKET:
            return ParseServerTicket(&pkt, msg);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_ETM
        case HS_EX_TYPE_ENCRYPT_THEN_MAC:
            return ParseServerEncryptThenMac(&pkt, msg);
#endif /* HITLS_TLS_FEATURE_ETM */
#ifdef HITLS_TLS_PROTO_TLS13
        case HS_EX_TYPE_SUPPORTED_GROUPS:
            return HITLS_SUCCESS;
#endif /* HITLS_TLS_PROTO_TLS13 */
        default:
            break;
    }
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), extMsgType,
        HITLS_EX_TYPE_TLS1_2_SERVER_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO | HITLS_EX_TYPE_HELLO_RETRY_REQUEST)) {
        return ParseCustomExtensions(pkt.ctx, pkt.buf + *pkt.bufOffset, extMsgType, extMsgLen,
            HITLS_EX_TYPE_TLS1_2_SERVER_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO | HITLS_EX_TYPE_HELLO_RETRY_REQUEST, NULL, 0);
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
    // You need to send an alert when an unknown extended field is encountered
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15205, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unknown extension message type:%d len:%lu in server hello message.", extMsgType, extMsgLen, 0, 0);
    return ParseErrorProcess(pkt.ctx, HITLS_PARSE_UNSUPPORTED_EXTENSION, 0, NULL, ALERT_UNSUPPORTED_EXTENSION);
}

int32_t ParseServerExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    /* Initialize the message parsing length */
    uint32_t bufOffset = 0u;
    int32_t ret = HITLS_SUCCESS;

    /* Parse the extended message from server */
    while (bufOffset < bufLen) {
        uint32_t extMsgLen = 0u;
        uint16_t extMsgType = HS_EX_TYPE_END;
        ret = ParseExHeader(ctx, &buf[bufOffset], bufLen - bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += HS_EX_HEADER_LEN;

        uint32_t extensionId = HS_GetExtensionTypeId(extMsgType);
        ret = CheckForDuplicateExtension(msg->extensionTypeMask, extensionId, ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        if (extensionId != HS_EX_TYPE_ID_UNRECOGNIZED
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
            || !IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), extMsgType,
                HITLS_EX_TYPE_TLS1_2_SERVER_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO |
                HITLS_EX_TYPE_HELLO_RETRY_REQUEST)
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
        ) {
            if (!GetExtensionFlagValue(ctx, extensionId)) {
                BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17330, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "client did not send but get extension type %u.", extensionId, 0, 0, 0);
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
                return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
            }
            msg->extensionTypeMask |= 1ULL << extensionId;
        }

        ret = ParseServerExBody(ctx, extMsgType, &buf[bufOffset], extMsgLen, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += extMsgLen;
    }

    // The extended content is the last field of the serverHello message. No other data should follow.
    if (bufOffset != bufLen) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15206,
            BINGLOG_STR("parse extension failed."), ALERT_DECODE_ERROR);
    }

    return HITLS_SUCCESS;
}

void CleanServerHelloExtension(ServerHelloMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->pointFormats);
#ifdef HITLS_TLS_FEATURE_ALPN
    BSL_SAL_FREE(msg->alpnSelected);
#endif /* HITLS_TLS_FEATURE_ALPN */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
    BSL_SAL_FREE(msg->secRenegoInfo);
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_PROTO_TLS13
    BSL_SAL_FREE(msg->cookie);
    BSL_SAL_FREE(msg->keyShare.keyExchange);
#endif /* HITLS_TLS_PROTO_TLS13 */
    return;
}
#endif /* HITLS_TLS_HOST_CLIENT */
