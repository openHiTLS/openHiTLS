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
#include "hitls_error.h"
#include "hitls_config.h"
#include "hs_msg.h"
#include "hs.h"
#include "parse_common.h"
#include "parse_extensions.h"
#include "parse_msg.h"


#define SINGLE_CIPHER_SUITE_SIZE 2u                 /* Length of the signature cipher suite */
#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
static int32_t StoreClientCipherSuites(TLS_Ctx *ctx, ClientHelloMsg *msg)
{
    uint32_t scsvCount = 0;
    scsvCount += msg->haveEmptyRenegoScsvCipher ? 1 : 0;
    scsvCount += msg->haveFallBackScsvCipher ? 1 : 0;
    if (scsvCount == msg->cipherSuitesSize) {
        BSL_SAL_FREE(ctx->peerInfo.cipherSuites);
        ctx->peerInfo.cipherSuitesSize = 0;
        return HITLS_SUCCESS;
    }
    uint32_t tmpSize = 0;
    BSL_SAL_FREE(ctx->peerInfo.cipherSuites);
    uint32_t peerCipherSuitesSize = ((uint32_t)msg->cipherSuitesSize - scsvCount) * sizeof(uint16_t);
    ctx->peerInfo.cipherSuites = (uint16_t *)BSL_SAL_Malloc(peerCipherSuitesSize);
    if (ctx->peerInfo.cipherSuites == NULL) {
        BSL_SAL_FREE(msg->cipherSuites);
        ctx->peerInfo.cipherSuitesSize = 0;
        return ParseErrorProcess(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID16237,
            BINGLOG_STR("peer cipherSuites dump fail"), ALERT_UNKNOWN);
    }
    for (uint16_t index = 0u; index < msg->cipherSuitesSize; index++) {
        if (msg->cipherSuites[index] == TLS_EMPTY_RENEGOTIATION_INFO_SCSV ||
            msg->cipherSuites[index] == TLS_FALLBACK_SCSV) {
            continue;
        }
        ctx->peerInfo.cipherSuites[tmpSize] = msg->cipherSuites[index];
        tmpSize += 1;
    }
    ctx->peerInfo.cipherSuitesSize = (uint16_t)tmpSize;
    return HITLS_SUCCESS;
}
#endif

/**
 * @brief Parse the cipher suite list of Client Hello messages.
 *
 * @param pkt [IN] parse context
 * @param msg [OUT] Client Hello Structure
 *
 * @retval HITLS_SUCCESS parsed successfully.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 */
static int32_t ParseClientHelloCipherSuites(ParsePacket *pkt, ClientHelloMsg *msg)
{
    uint16_t cipherSuitesLen = 0;
    int32_t ret = ParseBytesToUint16(pkt, &cipherSuitesLen);
    const char *logStr = BINGLOG_STR("parse cipherSuites failed.");
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15700,
            logStr, ALERT_DECODE_ERROR);
    }
    if (((uint32_t)cipherSuitesLen > (pkt->bufLen - *pkt->bufOffset)) ||
        (cipherSuitesLen % SINGLE_CIPHER_SUITE_SIZE) != 0u) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15342,
            logStr, ALERT_DECODE_ERROR);
    }
    if (cipherSuitesLen == 0u) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15701,
            logStr, ALERT_ILLEGAL_PARAMETER);
    }

    msg->cipherSuitesSize = cipherSuitesLen / SINGLE_CIPHER_SUITE_SIZE;
    BSL_SAL_FREE(msg->cipherSuites);
    msg->cipherSuites = (uint16_t *)BSL_SAL_Malloc(((uint32_t)msg->cipherSuitesSize) * sizeof(uint16_t));
    if (msg->cipherSuites == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15702,
            BINGLOG_STR("cipherSuites malloc fail"), ALERT_UNKNOWN);
    }
    /* Parse the cipher suite */
    for (uint16_t index = 0u; index < msg->cipherSuitesSize; index++) {
        msg->cipherSuites[index] = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
        *pkt->bufOffset += sizeof(uint16_t);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15703, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "got cipher suite from client:0x%x.", msg->cipherSuites[index], 0, 0, 0);
        if (msg->cipherSuites[index] == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            msg->haveEmptyRenegoScsvCipher = true;
        }
        if (msg->cipherSuites[index] == TLS_FALLBACK_SCSV) {
            msg->haveFallBackScsvCipher = true;
        }
    }
#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
    ret = StoreClientCipherSuites(pkt->ctx, msg);
#endif
    return ret;
}

/**
 * @brief List of compression methods for parsing Client Hello messages
 *
 * @param pkt [IN] parse context
 * @param msg [OUT] Client Hello Structure
 *
 * @retval HITLS_SUCCESS parsed successfully.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 */
static int32_t ParseClientHelloCompressionMethods(ParsePacket *pkt, ClientHelloMsg *msg)
{
    uint8_t compressionMethodsLen = 0;
    const char *logStr = BINGLOG_STR("parse compressionMethod failed.");
    int32_t ret = ParseBytesToUint8(pkt, &compressionMethodsLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15704,
            logStr, ALERT_DECODE_ERROR);
    }

    if ((compressionMethodsLen > (pkt->bufLen - *pkt->bufOffset)) || (compressionMethodsLen == 0u)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15705,
            logStr, ALERT_DECODE_ERROR);
    }
    
    ret = ParseBytesToArray(pkt, &msg->compressionMethods, compressionMethodsLen);
    if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID16146,
            BINGLOG_STR("compressionMethods malloc fail."), ALERT_UNKNOWN);
    }

    msg->compressionMethodsSize = compressionMethodsLen;

    for (uint32_t i = 0; i < compressionMethodsLen; i++) {
        if (msg->compressionMethods[i] == 0u) {
            return HITLS_SUCCESS;
        }
    }

    return ParseErrorProcess(pkt->ctx, HITLS_MSG_HANDLE_INVALID_COMPRESSION_METHOD, BINLOG_ID16238,
        logStr, ALERT_DECODE_ERROR);
}

/**
* @brief Parse the Client Hello extension messages.
*
* @param pkt [IN] parse context
* @param msg [OUT] Client Hello Structure
*
* @retval HITLS_SUCCESS parsed successfully.
* @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
* @retval HITLS_PARSE_DUPLICATE_EXTENSIVE_MSG Extended message
*/
static int32_t ParseClientHelloExtensions(ParsePacket *pkt, ClientHelloMsg *msg)
{
    uint16_t exMsgLen = 0;
    int32_t ret = ParseExtensionCommon(pkt, &exMsgLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (exMsgLen == 0u) {
        return HITLS_SUCCESS;
    }

    return ParseClientExtension(pkt->ctx, &pkt->buf[*pkt->bufOffset], exMsgLen, msg);
}

int32_t ParseClientHello(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    ClientHelloMsg *msg = &hsMsg->body.clientHello;
    uint32_t bufOffset = 0;
    ParsePacket pkt = {.ctx = ctx, .buf = data, .bufLen = len, .bufOffset = &bufOffset};
    /* Parse the version number. The version number occupies two bytes */
    int32_t ret = ParseVersion(&pkt, &msg->version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ctx->negotiatedInfo.clientVersion = msg->version;
    /* Parse the random number. The random number occupies 32 bytes */
    ret = ParseRandom(&pkt, msg->randomValue, HS_RANDOM_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ParseSessionId(&pkt, &msg->sessionIdSize, &msg->sessionId);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        /* Cookies need to be parsed in DTLS */
        ret = ParseCookie(&pkt, &msg->cookieLen, &msg->cookie);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif
    /* Parse the cipher suite. After the parsing is complete, update the msg->cipherSuitesSize and msg->cipherSuites */
    ret = ParseClientHelloCipherSuites(&pkt, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* Parse compression method */
    ret = ParseClientHelloCompressionMethods(&pkt, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (len == bufOffset) {
        return HITLS_SUCCESS;
    }
    return ParseClientHelloExtensions(&pkt, msg);
}

void CleanClientHello(ClientHelloMsg *msg)
{
    // The value of msg->refCnt is not 0, indicating that the ClientHelloMsg resource is hosted in the hrr scenario
    if (msg == NULL || msg->refCnt != 0) {
        return;
    }

    BSL_SAL_FREE(msg->sessionId);
    BSL_SAL_FREE(msg->cookie);
    BSL_SAL_FREE(msg->cipherSuites);
    BSL_SAL_FREE(msg->compressionMethods);
    BSL_SAL_FREE(msg->extensionBuff);
    CleanClientHelloExtension(msg);

    return;
}
#endif /* HITLS_TLS_HOST_SERVER */