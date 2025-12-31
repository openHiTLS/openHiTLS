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
#include "hs_common.h"
#include "parse_common.h"
#include "hs_ctx.h"
#include "alert.h"
#include "parse_extensions.h"
#include "custom_extensions.h"


static int32_t StorePeerSupportGroup(TLS_Ctx *ctx, ClientHelloMsg *msg)
{
    (void)ctx;
    (void)msg;
#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
    BSL_SAL_FREE(ctx->peerInfo.groups);
    ctx->peerInfo.groups = (uint16_t *)BSL_SAL_Dump(
        msg->extension.content.supportedGroups, msg->extension.content.supportedGroupsSize * sizeof(uint16_t));
    if (ctx->peerInfo.groups == NULL) {
        BSL_SAL_FREE(msg->extension.content.supportedGroups);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15136, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "supportedGroups dump fail when parse extensions msg.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->peerInfo.groupsSize = msg->extension.content.supportedGroupsSize;
#endif
    return HITLS_SUCCESS;
}

// Parse the supported group messages.
static int32_t ParseClientSupportGroups(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveSupportedGroups == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15132, BINGLOG_STR("ClientSupportGroups"));
    }

    uint16_t groupBufLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &groupBufLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15133, BINGLOG_STR("supported groups"));
    }

    uint16_t groupLen = groupBufLen / sizeof(uint16_t);

    /* If the length of the packet does not match the extended length, or the length is 0, the handshake message error
     * is returned */
    if (((groupBufLen & 1) != 0) || ((groupLen * sizeof(uint16_t)) != (pkt->bufLen - sizeof(uint16_t))) ||
        (groupLen == 0)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15134, BINGLOG_STR("supported groups"));
    }

    msg->extension.content.supportedGroups = (uint16_t *)BSL_SAL_Calloc(groupLen, sizeof(uint16_t));
    if (msg->extension.content.supportedGroups == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15135,
            BINGLOG_STR("supportedGroups malloc fail."), ALERT_UNKNOWN);
    }

    for (uint32_t i = 0; i < groupLen; i++) {
        msg->extension.content.supportedGroups[i] = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
        *pkt->bufOffset += sizeof(uint16_t);
    }

    msg->extension.content.supportedGroupsSize = groupLen;
    msg->extension.flag.haveSupportedGroups = true;

    return StorePeerSupportGroup(pkt->ctx, msg);
}

// Parse the extension item of the client hello signature algorithm.
static int32_t ParseClientSignatureAlgorithms(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveSignatureAlgorithms == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15128, BINGLOG_STR("ClientSignatureAlgorithms"));
    }

    uint16_t signAlgBufLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &signAlgBufLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15129, BINGLOG_STR("signatureAlgorithms"));
    }

    uint16_t signatureAlgorithmsSize = signAlgBufLen / sizeof(uint16_t);

    // Add exception handling. The value of signAlgBufLen cannot be an odd number. Each algorithm occupies two bytes.
    /* If the packet length does not match the extended length or the length is 0, a handshake message error is
     * returned. */
    if (((signAlgBufLen & 1) != 0) || (signAlgBufLen != (pkt->bufLen - *pkt->bufOffset)) ||
        (signatureAlgorithmsSize == 0)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15130, BINGLOG_STR("signatureAlgorithms"));
    }

    /* Parse signatureAlgorithms */
    uint16_t *signatureAlgorithms = (uint16_t *)BSL_SAL_Calloc(signatureAlgorithmsSize, sizeof(uint16_t));
    if (signatureAlgorithms == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15131,
            BINGLOG_STR("signatureAlgorithms malloc fail."), ALERT_UNKNOWN);
    }
    for (uint32_t i = 0; i < signatureAlgorithmsSize; i++) {
        signatureAlgorithms[i] = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
        *pkt->bufOffset += sizeof(uint16_t);
    }

    msg->extension.content.signatureAlgorithmsSize = signatureAlgorithmsSize;
    msg->extension.content.signatureAlgorithms = signatureAlgorithms;
    BSL_SAL_FREE(pkt->ctx->peerInfo.signatureAlgorithms);
    pkt->ctx->peerInfo.signatureAlgorithms =
        BSL_SAL_Dump(signatureAlgorithms, signatureAlgorithmsSize * sizeof(uint16_t));
    if (pkt->ctx->peerInfo.signatureAlgorithms == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID17382,
            BINGLOG_STR("signatureAlgorithms malloc fail."), ALERT_UNKNOWN);
    }
    pkt->ctx->peerInfo.signatureAlgorithmsSize = signatureAlgorithmsSize;
    msg->extension.flag.haveSignatureAlgorithms = true;
    return HITLS_SUCCESS;
}

// Parse the client message in point format.
static int32_t ParseClientPointFormats(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.havePointFormats == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15137, BINGLOG_STR("ClientPointFormats"));
    }

    uint8_t pointFormatsSize = 0;
    int32_t ret = ParseOneByteLengthField(pkt, &pointFormatsSize, &msg->extension.content.pointFormats);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15138, BINGLOG_STR("point formats"));
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15140,
            BINGLOG_STR("pointFormats malloc fail."), ALERT_UNKNOWN);
    }

    if ((pkt->bufLen != *pkt->bufOffset) || (pointFormatsSize == 0u)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15139, BINGLOG_STR("point formats"));
    }

    msg->extension.flag.havePointFormats = true;
    msg->extension.content.pointFormatsSize = pointFormatsSize;
    pkt->ctx->haveClientPointFormats = true;

    return HITLS_SUCCESS;
}

static int32_t ParseClientExtMasterSecret(ParsePacket *pkt, ClientHelloMsg *msg)
{
    return ParseEmptyExtension(pkt->ctx, HS_EX_TYPE_EXTENDED_MASTER_SECRET, pkt->bufLen,
        &msg->extension.flag.haveExtendedMasterSecret);
}
#ifdef HITLS_TLS_FEATURE_SNI
static void SetRevMsgExtServernameInfo(ClientHelloMsg *msg, uint8_t serverNameType, uint8_t *serverName,
    uint16_t serverNameLen)
{
    serverName[serverNameLen - 1] = '\0';
    msg->extension.content.serverName = serverName;
    msg->extension.content.serverNameSize = serverNameLen;
    msg->extension.content.serverNameType = serverNameType;
    msg->extension.flag.haveServerName = true;
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
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16986, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "bufLen err", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_SERVER_NAME_ERR;
        }
        if (serverNameType != 0) {
            bufOffset += serverNameLen;
            continue;
        }
        if (haveParseHostName || serverNameLen == 0 || serverNameLen > 0xff ||
            strnlen((const char *)&buf[bufOffset], serverNameLen) != serverNameLen) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16987, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "serverNameLen err", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            return HITLS_PARSE_SERVER_NAME_ERR;
        }
        haveParseHostName = true;
        uint8_t *serverName = (uint8_t *)BSL_SAL_Calloc((serverNameLen + 1), sizeof(uint8_t));
        if (serverName == NULL) {
            return ParseErrorProcess(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15127,
                BINGLOG_STR("server_name malloc fail."), ALERT_INTERNAL_ERROR);
        }
        (void)memcpy_s(serverName, serverNameLen + 1, &buf[bufOffset], serverNameLen);
        SetRevMsgExtServernameInfo(msg, serverNameType, serverName, serverNameLen + 1);
        bufOffset += serverNameLen;
    }
    if (bufOffset != bufLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16988, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "bufOffset err", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_SERVER_NAME_ERR;
    }
    if (!msg->extension.flag.haveServerName) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16989, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "it is not have server name", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_SERVER_NAME_ERR;
    }
    return HITLS_SUCCESS;
}

// Parse the ServerName extension item of client hello.
static int32_t ParseClientServerName(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveServerName == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15122, BINGLOG_STR("Client ServerName"));
    }

    uint16_t serverNameListSize = 0;
    int32_t ret = ParseBytesToUint16(pkt, &serverNameListSize);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15123, BINGLOG_STR("ServerName"));
    }

    if ((serverNameListSize != pkt->bufLen - *pkt->bufOffset) ||
        (serverNameListSize < sizeof(uint8_t) + sizeof(uint16_t))) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15124, BINGLOG_STR("ServerName"));
    }

    return ParseClientServerNameIndication(pkt->ctx, &pkt->buf[*pkt->bufOffset], (uint32_t)serverNameListSize, msg);
}
#endif /* HITLS_TLS_FEATURE_SNI */
#ifdef HITLS_TLS_FEATURE_ALPN
static int32_t ParseClientAlpnProposeList(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveAlpn == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15141, BINGLOG_STR("alpn list"));
    }
    uint16_t alpnLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &alpnLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15142, BINGLOG_STR("alpn"));
    }

    /* If the message length does not match the extended length, or the message length is less than 2 bytes, a handshake
     * message error is returned */
    if (((alpnLen * sizeof(uint8_t)) != (pkt->bufLen - sizeof(uint16_t))) || (alpnLen < 2)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15143, BINGLOG_STR("alpn"));
    }

    uint32_t alpnListOffset = *pkt->bufOffset;
    do {
        uint8_t alpnStringLen = pkt->buf[alpnListOffset];
        alpnListOffset += alpnStringLen + 1;
        if (alpnListOffset > pkt->bufLen || alpnStringLen == 0) {
            /* can't exceed alpn extension buffer; can't be empty */
            return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15144, BINGLOG_STR("alpn"));
        }
    } while (pkt->bufLen - alpnListOffset != 0); /* remaining len of alpn extension buffer */

    BSL_SAL_FREE(msg->extension.content.alpnList);
    msg->extension.content.alpnList = (uint8_t *)BSL_SAL_Dump(&pkt->buf[*pkt->bufOffset], alpnLen);
    if (msg->extension.content.alpnList == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15145,
            BINGLOG_STR("alpn list malloc fail."), ALERT_UNKNOWN);
    }

    msg->extension.content.alpnListSize = alpnLen;
    msg->extension.flag.haveAlpn = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t ParseIdentities(TLS_Ctx *ctx, PreSharedKey *preSharedKey, const uint8_t *buf, uint32_t bufLen)
{
    uint32_t bufOffset = 0u;
    PreSharedKey *tmp = preSharedKey;

    while (bufOffset + sizeof(uint16_t) < bufLen) {
        /* Create a linked list node */
        PreSharedKey *node = (PreSharedKey *)BSL_SAL_Calloc(1, sizeof(PreSharedKey));
        if (node == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16990, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Calloc fail", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
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
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16991, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Calloc fail", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
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
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16992, "Calloc fail");
    }
    uint32_t groupSetSize = 0;
    int32_t ret = HITLS_SUCCESS;
    while (bufOffset + sizeof(uint16_t) + sizeof(uint16_t) < bufLen) {
        KeyShare *tmpNode = (KeyShare *)BSL_SAL_Calloc(1u, sizeof(KeyShare));
        if (tmpNode == NULL) {
            *alert = ALERT_INTERNAL_ERROR;
            BSL_SAL_FREE(groupSet);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16993, "Calloc fail");
        }
        LIST_INIT(&tmpNode->head);
        LIST_ADD_AFTER(&node->head, &tmpNode->head);
        node = tmpNode;
        node->group = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        if (!KeyShareGroupAdd(groupSet, bufLen / sizeof(uint16_t), &groupSetSize, node->group)) {
            *alert = ALERT_ILLEGAL_PARAMETER;
            BSL_SAL_FREE(groupSet);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_PARSE_DUPLICATED_KEY_SHARE, BINLOG_ID16994, "key share repeated");
        }
        node->keyExchangeSize = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        /* parse keyExchange */
        if (node->keyExchangeSize == 0 || bufOffset + node->keyExchangeSize > bufLen) {
            *alert = ALERT_DECODE_ERROR;
            BSL_SAL_FREE(groupSet);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16995, "keyExchangeSize error");
        }
        BSL_SAL_FREE(node->keyExchange);
        node->keyExchange = (uint8_t *)BSL_SAL_Dump(&buf[bufOffset], node->keyExchangeSize);
        if (node->keyExchange == NULL) {
            *alert = ALERT_INTERNAL_ERROR;
            BSL_SAL_FREE(groupSet);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16996, "Dump fail");
        }
        bufOffset += node->keyExchangeSize;
    }
    BSL_SAL_FREE(groupSet);
    if (ret == HITLS_SUCCESS && bufOffset != bufLen) {
        *alert = ALERT_DECODE_ERROR;
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16997, "bufLen error");
    }
    return ret;
}

// Parse the KeyShare message.
int32_t ParseClientKeyShare(ParsePacket *pkt, ClientHelloMsg *msg)
{
    uint32_t bufOffset = 0u;
    int32_t ret = HITLS_SUCCESS;
    ALERT_Description alert = ALERT_UNKNOWN;
    do {
        /* Parsed extensions of the same type */
        if (msg->extension.flag.haveKeyShare == true) {
            return RETURN_ALERT_PROCESS(pkt->ctx, HITLS_PARSE_DUPLICATE_EXTENDED_MSG, BINLOG_ID16998,
                "KeyShare repeated", ALERT_ILLEGAL_PARAMETER);
        }
        if (pkt->bufLen < sizeof(uint16_t)) {
            return RETURN_ALERT_PROCESS(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16999,
                "bufLen error", ALERT_DECODE_ERROR);
        }
        uint16_t keyShareLen = BSL_ByteToUint16(&pkt->buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        if (keyShareLen + bufOffset != pkt->bufLen) {
            return RETURN_ALERT_PROCESS(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17000,
                "bufLen error", ALERT_DECODE_ERROR);
        }
        /* If the client requests hrr, keyshare can be empty */
        if (keyShareLen == 0) {
            break;
        }
        /** Create the header of the linked list of keyShareEntry */
        msg->extension.content.keyShare = (KeyShare *)BSL_SAL_Calloc(1u, sizeof(KeyShare));
        if (msg->extension.content.keyShare == NULL) {
            return RETURN_ALERT_PROCESS(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15150,
                "calloc fail", ALERT_INTERNAL_ERROR);
        }
        LIST_INIT(&msg->extension.content.keyShare->head);
        ret = ParseKeyShare(msg->extension.content.keyShare, &pkt->buf[bufOffset], keyShareLen, &alert);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15151, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse client key share fail.", 0, 0, 0, 0);
            break;
        }
    } while (false);
    msg->extension.flag.haveKeyShare = true;
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        pkt->ctx->method.sendAlert(pkt->ctx, ALERT_LEVEL_FATAL, alert);
    }
    return ret;
}

// Parse the SupportedVersions message.
int32_t ParseClientSupportedVersions(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* parsed extensions of the same type */
    if (msg->extension.flag.haveSupportedVers == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15152, BINGLOG_STR("ClientSupportedVersions"));
    }

    uint8_t len = 0;
    int32_t ret = ParseBytesToUint8(pkt, &len);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15153, BINGLOG_STR("SupportVersion"));
    }

    if ((len == 0) || ((len % sizeof(uint16_t)) != 0) || (len + *pkt->bufOffset != pkt->bufLen)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15154, BINGLOG_STR("SupportVersion"));
    }

    msg->extension.content.supportedVersions = (uint16_t *)BSL_SAL_Calloc(1u, len);
    if (msg->extension.content.supportedVersions == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15155,
            BINGLOG_STR("SupportVersion malloc fail."), ALERT_INTERNAL_ERROR);
    }

    for (uint32_t i = 0; i < len / sizeof(uint16_t); i++) {
        msg->extension.content.supportedVersions[i] = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
        *pkt->bufOffset += sizeof(uint16_t);
    }

    msg->extension.content.supportedVersionsCount = len / sizeof(uint16_t);
    msg->extension.flag.haveSupportedVers = true;

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
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17001, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "bufLen error", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
            return HITLS_PARSE_INVALID_MSG_LEN;
        }
        uint8_t binderLen = buf[bufOffset];
        bufOffset += sizeof(uint8_t);

        if (binderLen > (bufLen - bufOffset)) {
            return ParseErrorExtLengthProcess(ctx, BINLOG_ID15165, BINGLOG_STR("binder in pre share key"));
        }

        cur->binderSize = binderLen;
        cur->binder = (uint8_t *)BSL_SAL_Calloc(cur->binderSize, sizeof(uint8_t));
        if (cur->binder == NULL) {
            return ParseErrorProcess(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15166,
                BINGLOG_STR("pre_share_key malloc fail."), ALERT_UNKNOWN);
        }

        (void)memcpy_s(cur->binder, cur->binderSize, &buf[bufOffset], binderLen);
        bufOffset += binderLen;
    }

    if (bufLen != bufOffset) {
        return ParseErrorExtLengthProcess(ctx, BINLOG_ID15167, BINGLOG_STR("binder in pre share key"));
    }

    return HITLS_SUCCESS;
}

static int32_t ParseClientPreSharedKey(ParsePacket *pkt, ClientHelloMsg *msg)
{
    if (msg->extension.flag.havePreShareKey == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15168, BINGLOG_STR("pre share key"));
    }

    uint16_t identitiesLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &identitiesLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15169, BINGLOG_STR("pre share key"));
    }

    if (pkt->bufLen <= identitiesLen + *pkt->bufOffset || identitiesLen == 0) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15170, BINGLOG_STR("pre share key"));
    }

    /* Create the header of the PskIdentity linked list */
    PreSharedKey *offeredPsks = (PreSharedKey *)BSL_SAL_Calloc(1, sizeof(PreSharedKey));
    if (offeredPsks == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17002, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    msg->extension.content.preSharedKey = offeredPsks;
    LIST_INIT(&offeredPsks->pskNode);
    ret = ParseIdentities(pkt->ctx, offeredPsks, &pkt->buf[*pkt->bufOffset], identitiesLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    *pkt->bufOffset += identitiesLen;
    msg->truncateHelloLen = &pkt->buf[*pkt->bufOffset] - pkt->ctx->hsCtx->msgBuf;
    if (pkt->bufLen < sizeof(uint16_t) + *pkt->bufOffset) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17003, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen error", 0, 0, 0, 0);
        pkt->ctx->method.sendAlert(pkt->ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    /* Obtain the length of the binder list len */
    uint16_t bindersLen = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
    *pkt->bufOffset += sizeof(uint16_t);
    if (pkt->bufLen != *pkt->bufOffset + bindersLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17004, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen error", 0, 0, 0, 0);
        pkt->ctx->method.sendAlert(pkt->ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    ret = ParseBinders(pkt->ctx, offeredPsks, &pkt->buf[*pkt->bufOffset], bindersLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15171, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse binders extensions msg.", 0, 0, 0, 0);
        return ret;
    }
    msg->extension.flag.havePreShareKey = true;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
static int32_t ParseClientTrustedCaList(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Refer to the CAList parsing method of the CertificateRequest Msg. */
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveCA == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15172, BINGLOG_STR("certificate_authorities"));
    }

    uint16_t distinguishedNamesLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &distinguishedNamesLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15173, BINGLOG_STR("CaList"));
    }
    /*  https://www.rfc-editor.org/rfc/rfc8446#section-4.2.4
        opaque DistinguishedName<1..2^16-1>
        struct {
          DistinguishedName authorities<3..2^16-1>
        } CertificateAuthoritiesExtension
    */
    if (distinguishedNamesLen != (pkt->bufLen - *pkt->bufOffset) || (distinguishedNamesLen < 3)) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15174, BINGLOG_STR("CaList"));
    }

    FreeDNList(msg->extension.content.caList);
    msg->extension.content.caList = ParseDNList(&pkt->buf[*pkt->bufOffset], distinguishedNamesLen);
    if (msg->extension.content.caList == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17005, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ParseDNList fail", 0, 0, 0, 0);
        pkt->ctx->method.sendAlert(pkt->ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_CA_LIST_ERR);
        return HITLS_PARSE_CA_LIST_ERR;
    }
    HITLS_TrustedCAList *tmp = pkt->ctx->peerInfo.caList;
    pkt->ctx->peerInfo.caList = msg->extension.content.caList;
    msg->extension.content.caList = tmp;
    msg->extension.flag.haveCA = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */

static int32_t ParseClientPskKeyExModes(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.havePskExMode == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15175, BINGLOG_STR("pskKeyExchangeMode"));
    }

    uint8_t len = 0;
    int32_t ret = ParseOneByteLengthField(pkt, &len, &msg->extension.content.keModes);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15176, BINGLOG_STR("pskKeyExchangeMode"));
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15177,
            BINGLOG_STR("pskKeyExchangeMode malloc fail."), ALERT_UNKNOWN);
    }

    if ((pkt->bufLen != *pkt->bufOffset) || (len == 0u)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17006, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen error", 0, 0, 0, 0);
        pkt->ctx->method.sendAlert(pkt->ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->extension.content.keModesSize = len;
    msg->extension.flag.havePskExMode = true;

    return HITLS_SUCCESS;
}

static int32_t ParseClientCookie(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveCookie == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15178, BINGLOG_STR("cookie"));
    }

    int32_t ret = ParseExCookie(pkt->buf, pkt->bufLen, &msg->extension.content.cookie,
        &msg->extension.content.cookieLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    msg->extension.flag.haveCookie = true;
    return HITLS_SUCCESS;
}

static int32_t ParseClientPostHsAuth(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.havePostHsAuth == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15182, BINGLOG_STR("post_handshake_auth"));
    }

    /* The length of the extended data field of the rfc 8446 "post_handshake_auth" extension is 0. */
    if (pkt->bufLen != 0) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID15183, BINGLOG_STR("post_handshake_auth"));
    }

    msg->extension.flag.havePostHsAuth = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t ParseClientSecRenegoInfo(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveSecRenego == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15187, BINGLOG_STR("renegotiation info"));
    }

    uint8_t secRenegoInfoSize = 0;
    uint8_t *secRenegoInfo = NULL;
    int32_t ret = ParseSecRenegoInfo(pkt->ctx, pkt->buf, pkt->bufLen, &secRenegoInfo, &secRenegoInfoSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    msg->extension.content.secRenegoInfo = secRenegoInfo;
    msg->extension.content.secRenegoInfoSize = secRenegoInfoSize;
    msg->extension.flag.haveSecRenego = true;
    return HITLS_SUCCESS;
}
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_ETM
static int32_t ParseClientEncryptThenMac(ParsePacket *pkt, ClientHelloMsg *msg)
{
    return ParseEmptyExtension(pkt->ctx, HS_EX_TYPE_ENCRYPT_THEN_MAC, pkt->bufLen,
        &msg->extension.flag.haveEncryptThenMac);
}
#endif /* HITLS_TLS_FEATURE_ETM */

#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
static int32_t ParseClientTicket(ParsePacket *pkt, ClientHelloMsg *msg)
{
    uint8_t *ticket = NULL; /* ticket */

    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveTicket == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID15975, BINGLOG_STR("tiket"));
    }
#ifdef HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET
    if (pkt->ctx->config.tlsConfig.sessionTicketExtCb != NULL) {
        int32_t ret = pkt->ctx->config.tlsConfig.sessionTicketExtCb(pkt->ctx, pkt->buf, pkt->bufLen,
                                                                 pkt->ctx->config.tlsConfig.sessionTicketExtCbArg);
        if (ret == 0) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_SESSION_TICKET_FAIL, BINLOG_ID17379,
                BINGLOG_STR("parse ticket extension failed."), ALERT_INTERNAL_ERROR);
        }
    }
#endif /* HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET */
    if (pkt->bufLen != 0) {
        ticket = (uint8_t *)BSL_SAL_Dump(&pkt->buf[0], pkt->bufLen);
        if (ticket == NULL) {
            return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15976,
                BINGLOG_STR("ticket malloc fail."), ALERT_INTERNAL_ERROR);
        }
    }

    msg->extension.content.ticket = ticket;
    msg->extension.content.ticketSize = pkt->bufLen;
    msg->extension.flag.haveTicket = true;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */

#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
static int32_t ParseClientRecordSizeLimit(ParsePacket *pkt, ClientHelloMsg *msg)
{
    /* Parsed extensions of the same type */
    if (msg->extension.flag.haveRecordSizeLimit == true) {
        return ParseDupExtProcess(pkt->ctx, BINLOG_ID16243, BINGLOG_STR("recordSizeLimit"));
    }

    int32_t ret = ParseBytesToUint16(pkt, &msg->extension.content.recordSizeLimit);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorExtLengthProcess(pkt->ctx, BINLOG_ID16244, BINGLOG_STR("recordSizeLimit"));
    }

    /*
     * Endpoints MUST NOT send a "record_size_limit" extension with a value
     * smaller than 64.  An endpoint MUST treat receipt of a smaller value
     * as a fatal error and generate an "illegal_parameter" alert.
     */
    msg->extension.flag.haveRecordSizeLimit = true;
    return HITLS_SUCCESS;
}
#endif

// parses the extension message from client
static int32_t ParseClientExBody(TLS_Ctx *ctx, uint16_t extMsgType, const uint8_t *buf, uint32_t extMsgLen,
    ClientHelloMsg *msg)
{
    uint32_t bufOffset = 0u;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = extMsgLen, .bufOffset = &bufOffset};
    static struct {
        uint16_t exMsgType;            /**< Extension type of message*/
        int32_t (*parseFunc)(ParsePacket *, ClientHelloMsg *);      /**< Hook for packing extensions*/
    } extMsgList [] = {
        { .exMsgType = HS_EX_TYPE_POINT_FORMATS, .parseFunc = ParseClientPointFormats },
        { .exMsgType = HS_EX_TYPE_SUPPORTED_GROUPS, .parseFunc = ParseClientSupportGroups },
        { .exMsgType = HS_EX_TYPE_SIGNATURE_ALGORITHMS, .parseFunc = ParseClientSignatureAlgorithms},
#ifdef HITLS_TLS_FEATURE_SNI
        { .exMsgType = HS_EX_TYPE_SERVER_NAME, .parseFunc = ParseClientServerName},
#endif /* HITLS_TLS_FEATURE_SNI */

        { .exMsgType = HS_EX_TYPE_EXTENDED_MASTER_SECRET, .parseFunc = ParseClientExtMasterSecret},
#ifdef HITLS_TLS_FEATURE_ALPN
        { .exMsgType = HS_EX_TYPE_APP_LAYER_PROTOCOLS, .parseFunc = ParseClientAlpnProposeList},
#endif
#ifdef HITLS_TLS_PROTO_TLS13
        { .exMsgType = HS_EX_TYPE_SUPPORTED_VERSIONS, .parseFunc = ParseClientSupportedVersions},
        { .exMsgType = HS_EX_TYPE_PRE_SHARED_KEY, .parseFunc = ParseClientPreSharedKey},
        { .exMsgType = HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES, .parseFunc = ParseClientPskKeyExModes},
        { .exMsgType = HS_EX_TYPE_COOKIE, .parseFunc = ParseClientCookie},
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
        { .exMsgType = HS_EX_TYPE_CERTIFICATE_AUTHORITIES, .parseFunc = ParseClientTrustedCaList},
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */
        { .exMsgType = HS_EX_TYPE_POST_HS_AUTH, .parseFunc = ParseClientPostHsAuth},
        { .exMsgType = HS_EX_TYPE_KEY_SHARE, .parseFunc = ParseClientKeyShare},
#endif /* HITLS_TLS_PROTO_TLS13 */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
        { .exMsgType = HS_EX_TYPE_RENEGOTIATION_INFO, .parseFunc = ParseClientSecRenegoInfo},
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        { .exMsgType = HS_EX_TYPE_SESSION_TICKET, .parseFunc = ParseClientTicket},
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_ETM
        { .exMsgType = HS_EX_TYPE_ENCRYPT_THEN_MAC, .parseFunc = ParseClientEncryptThenMac},
#endif /* HITLS_TLS_FEATURE_ETM */
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
        { .exMsgType = HS_EX_TYPE_RECORD_SIZE_LIMIT, .parseFunc = ParseClientRecordSizeLimit},
#endif
    };
    for (uint32_t index = 0; index < sizeof(extMsgList) / sizeof(extMsgList[0]); index++) {
        if (extMsgList[index].exMsgType == extMsgType) {
            return extMsgList[index].parseFunc(&pkt, msg);
        }
    }
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), extMsgType, HITLS_EX_TYPE_CLIENT_HELLO)) {
        return ParseCustomExtensions(pkt.ctx, pkt.buf + *pkt.bufOffset, extMsgType, extMsgLen,
            HITLS_EX_TYPE_CLIENT_HELLO, NULL, 0);
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
    // Ignore unknown extensions
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15188, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "unknown extension message type:%d len:%lu in client hello message.", extMsgType, extMsgLen, 0, 0);
    return HITLS_SUCCESS;
}

int32_t ParseClientExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    uint32_t bufOffset = 0u;
    uint8_t extensionCount = 0;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};

    /* Parse the extended message from client */
    while (bufOffset < bufLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        uint32_t extensionId = 0;
        int32_t ret = CheckForDuplicateExtension(&pkt, &extMsgType, &extMsgLen, &extensionId, msg->extensionTypeMask);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        if (extensionId != HS_EX_TYPE_ID_UNRECOGNIZED
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
            || !IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), extMsgType, HITLS_EX_TYPE_CLIENT_HELLO)
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
        ) {
            msg->extensionTypeMask |= 1ULL << extensionId;
        }

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
            return ParseErrorProcess(ctx, HITLS_PARSE_PRE_SHARED_KEY_FAILED, BINLOG_ID16136,
                BINGLOG_STR("psk is not the last extension."), ALERT_ILLEGAL_PARAMETER);
        }
        extensionCount++;
    }

    /* The extended content is the last field of the clientHello packet and no other data is allowed. If the parsed
     * length is inconsistent with the buffer length, an error code is returned */
    if (bufOffset != bufLen) {
        return ParseErrorExtLengthProcess(ctx, BINLOG_ID15192, BINGLOG_STR("client hello"));
    }
#ifdef HITLS_TLS_FEATURE_CLIENT_HELLO_CB
    if (ctx->globalConfig != NULL && ctx->globalConfig->clientHelloCb != NULL) {
        msg->extensionBuff = BSL_SAL_Dump(buf, bufLen);
        if (msg->extensionBuff == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return ParseErrorProcess(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID17356,
                BINGLOG_STR("extensionBuff dump fail."), ALERT_INTERNAL_ERROR);
        }
        msg->extensionBuffLen = bufLen;
        msg->extensionCount = extensionCount;
    }
#else
    (void)extensionCount;
#endif /* HITLS_TLS_FEATURE_CLIENT_HELLO_CB */
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLS13
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
#endif /* HITLS_TLS_PROTO_TLS13 */
void CleanClientHelloExtension(ClientHelloMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    /* Release the Client Hello extension message structure */
    BSL_SAL_FREE(msg->extension.content.supportedGroups);
    BSL_SAL_FREE(msg->extension.content.pointFormats);
    BSL_SAL_FREE(msg->extension.content.signatureAlgorithms);
#ifdef HITLS_TLS_FEATURE_ALPN
    BSL_SAL_FREE(msg->extension.content.alpnList);
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_FEATURE_SNI
    BSL_SAL_FREE(msg->extension.content.serverName);
#endif /* HITLS_TLS_FEATURE_SNI */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
    BSL_SAL_FREE(msg->extension.content.secRenegoInfo);
#endif
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    BSL_SAL_FREE(msg->extension.content.ticket);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_PROTO_TLS13
    BSL_SAL_FREE(msg->extension.content.signatureAlgorithmsCert);
    BSL_SAL_FREE(msg->extension.content.supportedVersions);
    BSL_SAL_FREE(msg->extension.content.keModes);
    BSL_SAL_FREE(msg->extension.content.cookie);
    CleanKeyShare(msg->extension.content.keyShare);
    msg->extension.content.keyShare = NULL;
    CleanPreShareKey(msg->extension.content.preSharedKey);
    msg->extension.content.preSharedKey = NULL;
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
    FreeDNList(msg->extension.content.caList);
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */
    msg->extension.content.caList = NULL;
#endif /* HITLS_TLS_PROTO_TLS13 */
}
#endif /* HITLS_TLS_HOST_SERVER */
