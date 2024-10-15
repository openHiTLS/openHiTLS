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
#include "bsl_list.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "tls.h"
#include "hs_extensions.h"
#include "parse_common.h"
#include "hs_ctx.h"
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

static int32_t ParseClientExtMasterSecret(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    (void)buf;
    return ParseEmptyExtension(ctx, HS_EX_TYPE_EXTENDED_MASTER_SECRET, bufLen,
        &msg->extension.flag.haveExtendedMasterSecret);
}

static void SetRevMsgExtServernameInfo(ClientHelloMsg *msg, uint8_t serverNameType, uint8_t *serverName,
    uint16_t serverNameLen)
{
    serverName[serverNameLen - 1] = '\0';
    msg->extension.content.serverName = serverName;
    msg->extension.content.serverNameSize = serverNameLen;
    msg->extension.content.serverNameType = serverNameType;
    msg->extension.flag.haveServerName = true;
}

static int32_t ParseClientServerNamePre(TLS_Ctx *ctx, uint32_t bufLen, const ClientHelloMsg *msg)
{
    if (ctx == NULL || msg == NULL) {
        return HITLS_NULL_INPUT;
    }
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveServerName == true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15122, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type Client ServerName in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15123, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the ServerName length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return HITLS_SUCCESS;
}

static int32_t ParseClientServerNameIndication(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    const uint32_t baseSize = sizeof(uint8_t) + sizeof(uint16_t); // serverNameType and serverName Length
    uint32_t bufOffset = 0;
    bool haveParseHostName = false;
    while (bufOffset + baseSize < bufLen) {
        /* Parse serverNameType */
        uint8_t serverNameType = buf[bufOffset];
        bufOffset += sizeof(uint8_t);
        /* Parse serverName Length */
        uint16_t serverNameLen = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        if (bufLen < bufOffset + serverNameLen) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_SERVER_NAME_ERR;
        }
        if (serverNameType != 0) {
            bufOffset += serverNameLen;
            continue;
        }
        if (haveParseHostName || serverNameLen == 0 || serverNameLen > 0xff ||
            strnlen((const char *)&buf[bufOffset], serverNameLen) != serverNameLen) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            return HITLS_PARSE_SERVER_NAME_ERR;
        }
        haveParseHostName = true;
        uint8_t *serverName = (uint8_t *)BSL_SAL_Calloc((serverNameLen + 1), sizeof(uint8_t));
        if (serverName == NULL) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15127, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "calloc server_name memory fail when parse extensions msg.", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy_s(serverName, serverNameLen + 1, &buf[bufOffset], serverNameLen);
        SetRevMsgExtServernameInfo(msg, serverNameType, serverName, serverNameLen + 1);
        bufOffset += serverNameLen;
    }
    if (bufOffset != bufLen) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_SERVER_NAME_ERR;
    }
    if (!msg->extension.flag.haveServerName) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_SERVER_NAME_ERR;
    }
    return HITLS_SUCCESS;
}

// Parse the ServerName extension item of client hello.
static int32_t ParseClientServerName(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    int32_t ret = ParseClientServerNamePre(ctx, bufLen, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t bufOffset = 0u;
    /* Parse serverNameList Size */
    uint32_t serverNameListSize = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);
    if ((serverNameListSize != bufLen - bufOffset) || (serverNameListSize < sizeof(uint8_t) + sizeof(uint16_t))) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15124, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the server_name List size is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return ParseClientServerNameIndication(ctx, &buf[bufOffset], serverNameListSize, msg);
}

// Parse the extension item of the client hello signature algorithm.
static int32_t ParseClientSignatureAlgorithms(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveSignatureAlgorithms == true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15128, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type ClientSignatureAlgorithms in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15129, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the signatureAlgorithms length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    /* Parse signatureAlgorithmsSize */
    uint16_t signAlgBufLen = BSL_ByteToUint16(&buf[bufOffset]);
    uint16_t signatureAlgorithmsSize = signAlgBufLen / sizeof(uint16_t);
    bufOffset += sizeof(uint16_t);
    // Add exception handling. The value of signAlgBufLen cannot be an odd number. Each algorithm occupies two bytes.
    /* If the message length does not match the extended length or the length is 0, return an error code. */
    if (((signAlgBufLen & 1) != 0) || ((signatureAlgorithmsSize * sizeof(uint16_t)) != (bufLen - bufOffset)) ||
        (signatureAlgorithmsSize == 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15130, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the signatureAlgorithmsSize is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Parse signatureAlgorithms */
    uint16_t *signatureAlgorithms = (uint16_t *)BSL_SAL_Calloc(signatureAlgorithmsSize, sizeof(uint16_t));
    if (signatureAlgorithms == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15131, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signatureAlgorithms malloc fail when parse extensions msg.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    for (uint32_t i = 0; i < signatureAlgorithmsSize; i++) {
        signatureAlgorithms[i] = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
    }

    msg->extension.content.signatureAlgorithmsSize = signatureAlgorithmsSize;
    msg->extension.content.signatureAlgorithms = signatureAlgorithms;
    msg->extension.flag.haveSignatureAlgorithms = true;

    return HITLS_SUCCESS;
}

// Parse the supported group messages.
static int32_t ParseClientSupportGroups(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveSupportedGroups == true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15132, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type ClientSupportGroups in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15133, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (supported groups) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    uint16_t groupBufLen = BSL_ByteToUint16(&buf[bufOffset]);
    uint16_t groupLen = groupBufLen / sizeof(uint16_t);
    bufOffset += sizeof(uint16_t);

    /* If the length of the message does not match the extended length, or the length is 0, return an error code */
    if ((groupBufLen & 1) != 0 || ((groupLen * sizeof(uint16_t)) != (bufLen - sizeof(uint16_t))) || (groupLen == 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15134, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (supported groups) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->extension.content.supportedGroups = (uint16_t *)BSL_SAL_Calloc(groupLen, sizeof(uint16_t));
    if (msg->extension.content.supportedGroups == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15135, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "supportedGroups malloc fail when parse extensions msg.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    for (uint32_t i = 0; i < groupLen; i++) {
        msg->extension.content.supportedGroups[i] = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
    }

    msg->extension.content.supportedGroupsSize = groupLen;
    msg->extension.flag.haveSupportedGroups = true;
    BSL_SAL_FREE(ctx->peerInfo.groups);
    ctx->peerInfo.groups = (uint16_t *)BSL_SAL_Dump(msg->extension.content.supportedGroups, groupLen *
        sizeof(uint16_t));
    if (ctx->peerInfo.groups == NULL) {
        BSL_SAL_FREE(msg->extension.content.supportedGroups);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15136, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "supportedGroups dump fail when parse extensions msg.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->peerInfo.groupsSize = groupLen;
    return HITLS_SUCCESS;
}

// Parse the client message in point format.
static int32_t ParseClientPointFormats(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.havePointFormats == true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15137, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type ClientPointFormats in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint8_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15138, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (point formats) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtains the length of the point format. */
    uint32_t bufOffset = 0;
    uint8_t pointFormatsSize = buf[0];
    bufOffset += sizeof(uint8_t);

    /* If the point format length does not match the extended length, or the length is 0, a handshake message error is
     * returned */
    if ((pointFormatsSize != (bufLen - bufOffset)) || (pointFormatsSize == 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15139, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (point formats) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Parse the client message in point format */
    msg->extension.content.pointFormats = BSL_SAL_Calloc(pointFormatsSize, sizeof(uint8_t));
    if (msg->extension.content.pointFormats == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15140, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pointFormats malloc fail when parse extensions msg.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    for (uint8_t index = 0; index < pointFormatsSize; index++) {
        msg->extension.content.pointFormats[index] = buf[bufOffset];
        bufOffset += sizeof(uint8_t);
    }
    msg->extension.flag.havePointFormats = true;
    msg->extension.content.pointFormatsSize = pointFormatsSize;
    ctx->haveClientPointFormats = true;

    return HITLS_SUCCESS;
}

static int32_t ParseClientAlpnProposeList(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveAlpn == true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15141, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type alpn list in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15142, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (alpn) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    uint16_t alpnLen = BSL_ByteToUint16(&buf[bufOffset]) / sizeof(uint8_t);
    bufOffset += sizeof(uint16_t);

    /* If the message length does not match the extended length, or the message length is less than 2 bytes, return a
     * handshake message error */
    if (((alpnLen * sizeof(uint8_t)) != (bufLen - sizeof(uint16_t))) || (alpnLen < 2)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15143, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (alpn) %d in client hello message is incorrect.", alpnLen, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t alpnListOffset = bufOffset;
    do {
        uint8_t alpnStringLen = buf[alpnListOffset];
        alpnListOffset += alpnStringLen + 1;
        if (alpnListOffset > bufLen || alpnStringLen == 0) { /* can't exceed alpn extension buffer; can't be empty */
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15144, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "alpn string len %hd in client hello message is incorrect.", alpnStringLen, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }
    } while (bufLen - alpnListOffset != 0); /* remaining len of alpn extension buffer */

    msg->extension.content.alpnList = (uint8_t *)BSL_SAL_Dump(&buf[bufOffset], alpnLen);
    if (msg->extension.content.alpnList == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15145, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "alpn list malloc fail when parse extensions msg.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    msg->extension.content.alpnListSize = alpnLen;
    msg->extension.flag.haveAlpn = true;

    return HITLS_SUCCESS;
}

int32_t ParseIdentities(TLS_Ctx *ctx, PreSharedKey *preSharedKey, const uint8_t *buf, uint32_t bufLen)
{
    uint32_t bufOffset = 0u;
    PreSharedKey *tmp = preSharedKey;

    while (bufOffset + sizeof(uint16_t) < bufLen) {
        /* Create a linked list node */
        PreSharedKey *node = (PreSharedKey *)BSL_SAL_Calloc(1, sizeof(PreSharedKey));
        if (node == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        LIST_ADD_AFTER(&tmp->pskNode, &node->pskNode);
        tmp = node;

        /* Parse the identityLen length */
        uint16_t identitySize = BSL_ByteToUint16(&buf[bufOffset]);
        node->identitySize = identitySize;
        bufOffset += sizeof(uint16_t);

        if ((bufOffset + identitySize + sizeof(uint32_t)) > bufLen) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15146, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ParseIdentities error. bufLen = %d, identitySize = %d.", bufLen, identitySize, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }
        /* Parse identity */
        node->identity = (uint8_t *)BSL_SAL_Calloc(1u, (node->identitySize + 1) * sizeof(uint8_t));
        if (node->identity == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }

        (void)memcpy_s(node->identity, node->identitySize + 1, &buf[bufOffset], identitySize);
        bufOffset += node->identitySize;

        node->obfuscatedTicketAge = BSL_ByteToUint32(&buf[bufOffset]);
        bufOffset += sizeof(uint32_t);
    }

    if (bufOffset != bufLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15147, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "IdentityEntry error. bufLen = %d ", bufLen, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    return HITLS_SUCCESS;
}

void CleanKeyShare(KeyShare *keyShare)
{
    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    KeyShare *cur = NULL;
    KeyShare *cache = keyShare;
    if (cache != NULL) {
        LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(cache->head))
        {
            cur = LIST_ENTRY(node, KeyShare, head);
            LIST_REMOVE(node);
            BSL_SAL_FREE(cur->keyExchange);
            BSL_SAL_FREE(cur);
        }
        BSL_SAL_FREE(keyShare);
    }
}

/* rfc8446 4.2.8  Clients MUST NOT offer multiple KeyShareEntry values
   for the same group.  Clients MUST NOT offer any KeyShareEntry values
   for groups not listed in the client's "supported_groups" extension.
   Servers MAY check for violations of these rules and abort the
   handshake with an "illegal_parameter" alert if one is violated. */
static bool KeyShareGroupAdd(uint16_t *groupSet, uint32_t groupSetCapacity, uint32_t *groupSetSize, uint16_t group)
{
    for (uint32_t i = 0; (i < *groupSetSize) && (i + 1 < groupSetCapacity); i++) {
        if (groupSet[i] == group) {
            return false;
        }
    }
    groupSet[*groupSetSize] = group;
    *groupSetSize = *groupSetSize + 1;
    return true;
}

/**
 * @brief Parse KeyShareEntry and create a linked list node,
 * @attention The caller needs to pay attention to the function. If the function fails to be returned, the caller
 *            releases the call.
 *
 * @param keyShare [OUT] Linked list header
 * @param buf [IN] message buffer
 * @param bufLen [IN] message length
 *
 * @return HITLS_SUCCESS parsed successfully.
 */
int32_t ParseKeyShare(KeyShare *keyshare, const uint8_t *buf, uint32_t bufLen, ALERT_Description *alert)
{
    uint32_t bufOffset = 0u;
    KeyShare *node = keyshare;
    uint16_t *groupSet = (uint16_t *)BSL_SAL_Calloc(bufLen, sizeof(uint8_t));
    if (groupSet == NULL) {
        *alert = ALERT_INTERNAL_ERROR;
        return HITLS_MEMALLOC_FAIL;
    }
    uint32_t groupSetSize = 0;
    int32_t ret = HITLS_SUCCESS;
    while (bufOffset + sizeof(uint16_t) + sizeof(uint16_t) < bufLen) {
        KeyShare *tmpNode = (KeyShare *)BSL_SAL_Calloc(1u, sizeof(KeyShare));
        if (tmpNode == NULL) {
            *alert = ALERT_INTERNAL_ERROR;
            ret = HITLS_MEMALLOC_FAIL;
            break;
        }
        LIST_INIT(&tmpNode->head);
        LIST_ADD_AFTER(&node->head, &tmpNode->head);
        node = tmpNode;
        node->group = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        if (!KeyShareGroupAdd(groupSet, bufLen / sizeof(uint16_t), &groupSetSize, node->group)) {
            *alert = ALERT_ILLEGAL_PARAMETER;
            ret = HTILS_PARSE_DUPLICATED_KEY_SHARE;
            break;
        }
        node->keyExchangeSize = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        /* parse keyExchange */
        if (node->keyExchangeSize == 0 || bufOffset + node->keyExchangeSize > bufLen) {
            *alert = ALERT_DECODE_ERROR;
            ret = HITLS_PARSE_INVALID_MSG_LEN;
            break;
        }
        node->keyExchange = (uint8_t *)BSL_SAL_Dump(&buf[bufOffset], node->keyExchangeSize);
        if (node->keyExchange == NULL) {
            *alert = ALERT_INTERNAL_ERROR;
            ret = HITLS_MEMALLOC_FAIL;
            break;
        }
        bufOffset += node->keyExchangeSize;
    }
    BSL_SAL_FREE(groupSet);
    if (ret == HITLS_SUCCESS && bufOffset != bufLen) {
        *alert = ALERT_DECODE_ERROR;
        ret = HITLS_PARSE_INVALID_MSG_LEN;
    }
    return ret;
}

// Parse the KeyShare message.
static int32_t ParseClientKeyShare(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    uint32_t bufOffset = 0u;
    int32_t ret = HITLS_SUCCESS;
    ALERT_Description alert = ALERT_UNKNOWN;
    do {
        /* Parsed extensions of the same type */
        if (msg->extension.flag.haveKeyShare == true) {
            ret = HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
            alert = ALERT_ILLEGAL_PARAMETER;
            break;
        }
        if (bufLen < sizeof(uint16_t)) {
            ret = HITLS_PARSE_INVALID_MSG_LEN;
            alert = ALERT_DECODE_ERROR;
            break;
        }
        uint16_t keyShareLen = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        if (keyShareLen + bufOffset != bufLen) {
            ret = HITLS_PARSE_INVALID_MSG_LEN;
            alert = ALERT_DECODE_ERROR;
            break;
        }
        /* If the client requests hrr, keyshare can be empty */
        if (keyShareLen == 0) {
            break;
        }
        /** Create the header of the linked list of keyShareEntry */
        msg->extension.content.keyShare = (KeyShare *)BSL_SAL_Calloc(1u, sizeof(KeyShare));
        if (msg->extension.content.keyShare == NULL) {
            ret = HITLS_MEMALLOC_FAIL;
            alert = ALERT_INTERNAL_ERROR;
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15150, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "keyShare malloc fail when parse client keyshare.", 0, 0, 0, 0);
            break;
        }
        LIST_INIT(&msg->extension.content.keyShare->head);
        ret = ParseKeyShare(msg->extension.content.keyShare, &buf[bufOffset], keyShareLen, &alert);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15151, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse client key share fail.", 0, 0, 0, 0);
            break;
        }
    } while (false);
    msg->extension.flag.haveKeyShare = true;
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, alert);
    }
    return ret;
}

// Parse the SupportedVersions message.
static int32_t ParseClientSupportedVersions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* parsed extensions of the same type */
    if (msg->extension.flag.haveSupportedVers == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15152, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type ClientSupportedVersions in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15153, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (supported groups) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    /** Obtain the length of supportedVersions */
    uint8_t len = buf[bufOffset];
    bufOffset++;

    if ((len == 0) || ((len % sizeof(uint16_t)) != 0) || (len + bufOffset != bufLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15154, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "supportedVersionsSize is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->extension.content.supportedVersions = (uint16_t *)BSL_SAL_Calloc(1u, len);
    if (msg->extension.content.supportedVersions == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15155, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "supportedVersions malloc fail when parse extensions msg.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
    }

    for (uint32_t i = 0; i < len / sizeof(uint16_t); i++) {
        msg->extension.content.supportedVersions[i] = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
    }

    msg->extension.content.supportedVersionsCount = len / sizeof(uint16_t);
    msg->extension.flag.haveSupportedVers = true;

    return HITLS_SUCCESS;
}

static int32_t ParseServerPreShareKey(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    if (msg->haveSelectedIdentity == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15156, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type pre_shared_key in server hello message is repeated", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen != sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15157, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (pre_shared_key) in server hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    uint32_t bufOffset = 0u;
    msg->selectedIdentity = BSL_ByteToUint16(&buf[bufOffset]);
    msg->haveSelectedIdentity = true;

    return HITLS_SUCCESS;
}
static int32_t ParseServerKeySharePre(TLS_Ctx *ctx, uint32_t bufLen, const ServerHelloMsg *msg)
{
    if (msg->haveKeyShare == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15158, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type ServerKeyShare in server hello message is repeated", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15159, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (ServerKeyShare) in server hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    return HITLS_SUCCESS;
}

static int32_t ParseServerKeyShare(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    int32_t ret = ParseServerKeySharePre(ctx, bufLen, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t bufOffset = 0u;
    /* parse group */
    msg->keyShare.group = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (bufLen == bufOffset) {
        msg->haveKeyShare = true;
        return HITLS_SUCCESS;  // If there is no subsequent content, the extension is the keyshare of hrr
    }
    if (bufLen < bufOffset + sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15125, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ParseServerKeyShare error. invalid msg len", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    /* parse keyExchangeSize */
    uint16_t keyExchangeSize = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);
    if ((bufOffset + keyExchangeSize) != bufLen || (keyExchangeSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15160, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ParseServerKeyShare error. bufLen = %d, keyExchangeSize = %d.", bufLen, keyExchangeSize, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* parse keyExchange */
    msg->keyShare.keyExchange = (uint8_t *)BSL_SAL_Calloc(keyExchangeSize, sizeof(uint8_t));
    if (msg->keyShare.keyExchange == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
    }
    msg->keyShare.keyExchangeSize = keyExchangeSize;
    (void)memcpy_s(msg->keyShare.keyExchange, msg->keyShare.keyExchangeSize, &buf[bufOffset], keyExchangeSize);
    msg->haveKeyShare = true;
    return HITLS_SUCCESS;
}

int32_t ParseExCookie(const uint8_t *buf, uint32_t bufLen, uint8_t **cookie, uint16_t *cookieLen)
{
    *cookie = NULL; // Initialize the function entry to prevent wild pointers

    uint32_t bufOffset = 0;
    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Extract the cookie length */
    uint32_t tmpCookieLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    /* If the cookie length is incorrect, return an error code */
    if (tmpCookieLen != (bufLen - bufOffset) || tmpCookieLen == 0u) {
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
    *cookieLen = tmpCookieLen;
    return HITLS_SUCCESS;
}

static int32_t ParseServerCookie(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    if (msg->haveCookie == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15162, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type cookie in server hello message is repeated", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    int32_t ret = ParseExCookie(buf, bufLen, &msg->cookie, &msg->cookieLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    msg->haveCookie = true;
    return HITLS_SUCCESS;
}
// Parse the SupportedVersions message.

static int32_t ParseServerSupportedVersions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveSupportedVersion == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15164, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type ServerSupportedVersions in hello message is repeated", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen != sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->supportedVersion = BSL_ByteToUint16(&buf[0]);
    msg->haveSupportedVersion = true;

    return HITLS_SUCCESS;
}

static int32_t ParseBinders(TLS_Ctx *ctx, PreSharedKey *preSharedKey, const uint8_t *buf, uint32_t bufLen)
{
    uint32_t bufOffset = 0u;
    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    PreSharedKey *cur = NULL;
    PreSharedKey *cache = preSharedKey;

    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(cache->pskNode))
    {
        cur = LIST_ENTRY(node, PreSharedKey, pskNode);
        if (bufLen < bufOffset + sizeof(uint8_t)) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }
        uint8_t binderLen = buf[bufOffset];
        bufOffset += sizeof(uint8_t);

        if (binderLen > (bufLen - bufOffset)) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15165, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "the binder length of handshake message is incorrect.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }

        cur->binderSize = binderLen;
        cur->binder = (uint8_t *)BSL_SAL_Calloc(cur->binderSize, sizeof(uint8_t));
        if (cur->binder == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15166, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse pre_share_key binder malloc fail extensions msg.", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }

        (void)memcpy_s(cur->binder, cur->binderSize, &buf[bufOffset], binderLen);
        bufOffset += binderLen;
    }

    if (bufLen != bufOffset) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15167, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (binder)  is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return HITLS_SUCCESS;
}
static int32_t ParseClientPreSharedKeyPre(TLS_Ctx *ctx, uint32_t bufLen, const ClientHelloMsg *msg)
{
    if (msg->extension.flag.havePreShareKey == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15168, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type pre share key in client hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15169, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (pre share key) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    return HITLS_SUCCESS;
}

static int32_t ParseClientPreSharedKey(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    int32_t ret = ParseClientPreSharedKeyPre(ctx, bufLen, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t bufOffset = 0u;
    /* Obtain the length of the pskid list len */
    uint16_t identitiesLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (bufLen <= identitiesLen + bufOffset || identitiesLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15170, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (pre share key) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Create the header of the PskIdentity linked list */
    PreSharedKey *offeredPsks = (PreSharedKey *)BSL_SAL_Calloc(1, sizeof(PreSharedKey));
    if (offeredPsks == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    msg->extension.content.preSharedKey = offeredPsks;
    LIST_INIT(&offeredPsks->pskNode);
    ret = ParseIdentities(ctx, offeredPsks, &buf[bufOffset], identitiesLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += identitiesLen;
    msg->truncateHelloLen = &buf[bufOffset] - ctx->hsCtx->msgBuf;
    if (bufLen < sizeof(uint16_t) + bufOffset) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    /* Obtain the length of the binder list len */
    uint16_t bindersLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);
    if (bufLen != bufOffset + bindersLen) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    ret = ParseBinders(ctx, offeredPsks, &buf[bufOffset], bindersLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15171, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse binders extensions msg.", 0, 0, 0, 0);
        return ret;
    }
    msg->extension.flag.havePreShareKey = true;
    return HITLS_SUCCESS;
}

static int32_t ParseClientPskKeyExModes(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.havePskExMode == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15175, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type pskKeyExchangeMode in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15176, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (pskKeyExchangeMode) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    /** Obtain the pskKeyExchangeMode length */
    uint8_t len = buf[bufOffset];
    bufOffset += sizeof(uint8_t);
    if (bufLen != bufOffset + len) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->extension.content.keModes = (uint8_t *)BSL_SAL_Calloc(len, sizeof(uint8_t));
    if (msg->extension.content.keModes == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15177, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pskKeyExchangeMode malloc fail when parse extensions msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    for (uint32_t i = 0; i < len; i++) {
        msg->extension.content.keModes[i] = buf[bufOffset];
        bufOffset += sizeof(uint8_t);
    }

    msg->extension.content.keModesSize = len;
    msg->extension.flag.havePskExMode = true;

    return HITLS_SUCCESS;
}

static int32_t ParseClientCookie(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveCookie == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15178, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type cookie in client hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    int32_t ret = ParseExCookie(buf, bufLen, &msg->extension.content.cookie,
        &msg->extension.content.cookieLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    msg->extension.flag.haveCookie = true;
    return HITLS_SUCCESS;
}

static int32_t ParseClientPostHsAuth(TLS_Ctx *ctx, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.havePostHsAuth == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15182, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type post_handshake_auth in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    /* The length of the extended data field of the rfc 8446 "post_handshake_auth" extension is 0. */
    if (bufLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15183, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (post_handshake_auth) in client hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->extension.flag.havePostHsAuth = true;

    return HITLS_SUCCESS;
}

static int32_t ParseSecRenegoInfo(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint8_t **secRenegoInfo,
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

static int32_t ParseClientSecRenegoInfo(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveSecRenego == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15187, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type renegotiation info in client hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    uint8_t secRenegoInfoSize = 0;
    uint8_t *secRenegoInfo = NULL;
    int32_t ret = ParseSecRenegoInfo(ctx, buf, bufLen, &secRenegoInfo, &secRenegoInfoSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    msg->extension.content.secRenegoInfo = secRenegoInfo;
    msg->extension.content.secRenegoInfoSize = secRenegoInfoSize;
    msg->extension.flag.haveSecRenego = true;
    return HITLS_SUCCESS;
}

static int32_t ParseClientEncryptThenMac(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    (void)buf;
    return ParseEmptyExtension(ctx, HS_EX_TYPE_ENCRYPT_THEN_MAC, bufLen, &msg->extension.flag.haveEncryptThenMac);
}

static int32_t ParseClientTicket(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    uint8_t *ticket = NULL; /* ticket */

    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveTicket == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15148, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type tiket externsion in server hello is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen != 0) {
        ticket = (uint8_t *)BSL_SAL_Dump(&buf[0], bufLen);
        if (ticket == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15149, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse server hello sesionticket message: malloc ticket failed.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    msg->extension.content.ticket = ticket;
    msg->extension.content.ticketSize = bufLen;
    msg->extension.flag.haveTicket = true;
    return HITLS_SUCCESS;
}
// parses the extension message from client
static int32_t ParseClientExBody(TLS_Ctx *ctx, uint16_t extMsgType, const uint8_t *buf, uint32_t extMsgLen,
    ClientHelloMsg *msg)
{
    switch (extMsgType) {
        case HS_EX_TYPE_SERVER_NAME:
            return ParseClientServerName(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_POINT_FORMATS:
            return ParseClientPointFormats(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_SUPPORTED_GROUPS:
            return ParseClientSupportGroups(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_EXTENDED_MASTER_SECRET:
            return ParseClientExtMasterSecret(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS:
            return ParseClientSignatureAlgorithms(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_APP_LAYER_PROTOCOLS:
            return ParseClientAlpnProposeList(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_SUPPORTED_VERSIONS:
            return ParseClientSupportedVersions(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_PRE_SHARED_KEY:
            return ParseClientPreSharedKey(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES:
            return ParseClientPskKeyExModes(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_COOKIE:
            return ParseClientCookie(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_POST_HS_AUTH:
            return ParseClientPostHsAuth(ctx, extMsgLen, msg);
        case HS_EX_TYPE_KEY_SHARE:
            return ParseClientKeyShare(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_RENEGOTIATION_INFO:
            return ParseClientSecRenegoInfo(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_ENCRYPT_THEN_MAC:
            return ParseClientEncryptThenMac(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_SESSION_TICKET:
            return ParseClientTicket(ctx, buf, extMsgLen, msg);
        default:
            break;
    }

    // Ignore unknown extensions
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15188, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "unknown extension message type:%d len:%lu in client hello message.", extMsgType, extMsgLen, 0, 0);
    return HITLS_SUCCESS;
}

/**
 * @brief Parse the extended message type and length.
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] message buffer, starting from the extension type.
 * @param bufLen [IN] message length
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

int32_t ParseClientExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    uint32_t bufOffset = 0u;
    int32_t ret = HITLS_SUCCESS;

    /* Parse the extended message from client */
    while (bufOffset < bufLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        ret = ParseExHeader(ctx, &buf[bufOffset], bufLen - bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += HS_EX_HEADER_LEN;

        ret = ParseClientExBody(ctx, extMsgType, &buf[bufOffset], extMsgLen, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += extMsgLen;
        /* rfc8446 4.2.11. The "pre_shared_key" extension MUST be the last extension in the
        ClientHello (this facilitates implementation as described below).
        Servers MUST check that it is the last extension and otherwise fail
        the handshake with an "illegal_parameter" alert. */
        if (extMsgType == HS_EX_TYPE_PRE_SHARED_KEY && bufOffset != bufLen) {
            BSL_ERR_PUSH_ERROR(HTILS_PARSE_PRE_SHARED_KEY_FAILED);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15163, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "psk is not the last extension.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            return HTILS_PARSE_PRE_SHARED_KEY_FAILED;
        }
    }

    /* The extended content is the last field of the clientHello message and no other data is allowed. If the parsed
     * length is inconsistent with the buffer length, return an error code */
    if (bufOffset != bufLen) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15192, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the extension len of client hello msg is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return HITLS_SUCCESS;
}

void CleanPreShareKey(PreSharedKey *preSharedKey)
{
    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    PreSharedKey *cur = NULL;
    PreSharedKey *cache = preSharedKey;
    if (cache != NULL) {
        LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(cache->pskNode))
        {
            cur = LIST_ENTRY(node, PreSharedKey, pskNode);
            LIST_REMOVE(node);
            BSL_SAL_FREE(cur->identity);
            BSL_SAL_FREE(cur->binder);
            BSL_SAL_FREE(cur);
        }
        BSL_SAL_FREE(preSharedKey);
    }
}

void CleanClientHelloExtension(ClientHelloMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    /* Release the Client Hello extension message structure */
    BSL_SAL_FREE(msg->extension.content.supportedGroups);
    BSL_SAL_FREE(msg->extension.content.pointFormats);
    BSL_SAL_FREE(msg->extension.content.signatureAlgorithms);
    BSL_SAL_FREE(msg->extension.content.alpnList);
    BSL_SAL_FREE(msg->extension.content.supportedVersions);
    BSL_SAL_FREE(msg->extension.content.cookie);
    BSL_SAL_FREE(msg->extension.content.keModes);
    BSL_SAL_FREE(msg->extension.content.serverName);
    BSL_SAL_FREE(msg->extension.content.secRenegoInfo);
    BSL_SAL_FREE(msg->extension.content.ticket);

    CleanKeyShare(msg->extension.content.keyShare);
    msg->extension.content.keyShare = NULL;
    CleanPreShareKey(msg->extension.content.preSharedKey);
    msg->extension.content.preSharedKey = NULL;
    return;
}

//  Parses the point format message sent by the server
static int32_t ParseServerPointFormats(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->havePointFormats == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15193, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type ServerPointFormats in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15194, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length tag (point formats) in server hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Extract the length of the point format */
    uint32_t bufOffset = 0;
    uint8_t pointFormatsSize = buf[0];
    bufOffset += sizeof(uint8_t);

    /* If the point format length does not match the extended length, or the length is 0,
     * return a handshake message error */
    if ((pointFormatsSize != (bufLen - bufOffset)) || (pointFormatsSize == 0u)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15195, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (point formats) in server hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->pointFormats = BSL_SAL_Calloc(pointFormatsSize, sizeof(uint8_t));
    if (msg->pointFormats == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15196, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pointFormats malloc fail when parse extensions msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    for (uint8_t index = 0; index < pointFormatsSize; index++) {
        msg->pointFormats[index] = buf[bufOffset];
        bufOffset += sizeof(uint8_t);
    }

    msg->havePointFormats = true;
    msg->pointFormatsSize = pointFormatsSize;

    return HITLS_SUCCESS;
}

// Parses the extended master secret sent by the serve
static int32_t ParseServerExtMasterSecret(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    (void)buf;
    /* Parse the empty extended message */
    return ParseEmptyExtension(ctx, HS_EX_TYPE_EXTENDED_MASTER_SECRET, bufLen, &msg->haveExtendedMasterSecret);
}

static int32_t ParseServerSelectedAlpnProtocol(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveSelectedAlpn == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15197, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type selected alpn protocol in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    /* If the message length is incorrect, return an error code */
    if (bufLen < sizeof(uint16_t) + sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15198, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (supported groups) in server hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0u;
    uint16_t selectedAlpnListLen = BSL_ByteToUint16(&buf[bufOffset]) / sizeof(uint8_t);
    bufOffset += sizeof(uint16_t);
    uint16_t selectedAlpnLen = (uint16_t)(buf[bufOffset] / sizeof(uint8_t));
    bufOffset += sizeof(uint8_t);

    /* If the length of the message does not match the extended length, or the length is 0, return an error code */
    if (((selectedAlpnListLen * sizeof(uint8_t)) != (bufLen - sizeof(uint16_t))) || (selectedAlpnListLen == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15199, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message length (supported groups) in server hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    /* According to the protocol rfc7301, The alpn extension returned by server is allowed to contain only one protocol
     * name, and returns a handshake message error */
    /* Check whether the listsize of the alpn list returned by the server is anpn size + sizeof(uint8_t) */
    if (selectedAlpnLen != selectedAlpnListLen - sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ALPN_UNRECOGNIZED);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15201, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the number of Protocol in ALPN extensions of server hello message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_MSG_HANDLE_ALPN_UNRECOGNIZED;
    }

    /* The length of bufLen meets:  alpnLen | alpn | 0 */
    msg->alpnSelected = (uint8_t *)BSL_SAL_Calloc(selectedAlpnLen + 1, sizeof(uint8_t));
    if (msg->alpnSelected == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15200, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "selected alpn proto malloc fail when parse extensions msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    (void)memcpy_s(msg->alpnSelected, selectedAlpnLen + 1, &buf[bufOffset], selectedAlpnLen);

    msg->alpnSelectedSize = selectedAlpnLen;
    msg->haveSelectedAlpn = true;

    return HITLS_SUCCESS;
}

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
static int32_t ParseServerServerName(TLS_Ctx *ctx, uint32_t bufLen, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveServerName == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15202, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type Sever ServerName in hello message is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    /* If the message length is incorrect, return an error code */
    /* rfc6066
     *  When the server decides to receive server_name, the server should include an extension of type "server_name" in
     * the (extended) server hello. The'extension_data' field for this extension should be empty
     */
    if (bufLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15203, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the ServerName length of server hello is incorrect. it should be zero", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    msg->haveServerName = true;
    return HITLS_SUCCESS;
}

static int32_t ParseServerSecRenegoInfo(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->haveSecRenego == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15204, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type renegotiation info in server hello is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    uint8_t secRenegoInfoSize = 0;
    uint8_t *secRenegoInfo = NULL;
    int32_t ret = ParseSecRenegoInfo(ctx, buf, bufLen, &secRenegoInfo, &secRenegoInfoSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    msg->secRenegoInfo = secRenegoInfo;
    msg->secRenegoInfoSize = secRenegoInfoSize;
    msg->haveSecRenego = true;
    return HITLS_SUCCESS;
}

static int32_t ParseServerTicket(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    (void)buf;
    /* Parsed extensions of the same type */
    if (msg->haveTicket == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15179, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "extension message type tiket externsion in server hello is repeated.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }

    /* The ticket extended data length of server hello can only be empty */
    if (bufLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15965, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the tiket length of server hello is incorrect. it should be zero", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->haveTicket = true;
    return HITLS_SUCCESS;
}

static int32_t ParseServerEncryptThenMac(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    (void)buf;
    return ParseEmptyExtension(ctx, HS_EX_TYPE_ENCRYPT_THEN_MAC, bufLen, &msg->haveEncryptThenMac);
}

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
    switch (extMsgType) {
        case HS_EX_TYPE_SERVER_NAME:
            return ParseServerServerName(ctx, extMsgLen, msg);
        case HS_EX_TYPE_POINT_FORMATS:
            return ParseServerPointFormats(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_EXTENDED_MASTER_SECRET:
            return ParseServerExtMasterSecret(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_APP_LAYER_PROTOCOLS:
            return ParseServerSelectedAlpnProtocol(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_KEY_SHARE:
            return ParseServerKeyShare(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_PRE_SHARED_KEY:
            return ParseServerPreShareKey(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_COOKIE:
            return ParseServerCookie(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_SUPPORTED_VERSIONS:
            return ParseServerSupportedVersions(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_RENEGOTIATION_INFO:
            return ParseServerSecRenegoInfo(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_SESSION_TICKET:
            return ParseServerTicket(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_ENCRYPT_THEN_MAC:
            return ParseServerEncryptThenMac(ctx, buf, extMsgLen, msg);
        case HS_EX_TYPE_SUPPORTED_GROUPS:
            return HITLS_SUCCESS;
        default:
            break;
    }

    // You need to send an alert when an unknown extended field is encountered
    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORTED_EXTENSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15205, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unknown extension message type:%d len:%lu in server hello message.", extMsgType, extMsgLen, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
    return HITLS_PARSE_UNSUPPORTED_EXTENSION;
}

int32_t ParseServerExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ServerHelloMsg *msg)
{
    /* Initialize the message parsing length */
    uint32_t bufOffset = 0u;
    int32_t ret = HITLS_SUCCESS;

    /* Parse the extended message from server */
    while (bufOffset < bufLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        ret = ParseExHeader(ctx, &buf[bufOffset], bufLen - bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += HS_EX_HEADER_LEN;

        ret = ParseServerExBody(ctx, extMsgType, &buf[bufOffset], extMsgLen, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += extMsgLen;
    }

    // The extended content is the last field of the serverHello message. No other data should follow.
    if (bufOffset != bufLen) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15206, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the extension len of server hello msg is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return HITLS_SUCCESS;
}

void CleanServerHelloExtension(ServerHelloMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->pointFormats);
    BSL_SAL_FREE(msg->alpnSelected);
    BSL_SAL_FREE(msg->secRenegoInfo);
    BSL_SAL_FREE(msg->cookie);
    BSL_SAL_FREE(msg->keyShare.keyExchange);
    return;
}
