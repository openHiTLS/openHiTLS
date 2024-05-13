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
#include "hitls_config.h"
#include "hs_msg.h"
#include "hs.h"
#include "parse_common.h"
#include "parse_extensions.h"
#include "parse_msg.h"


#define SINGLE_CIPHER_SUITE_SIZE 2u                 /* Length of the signature cipher suite */

/**
 * @brief Parse the cipher suite list of Client Hello messages.
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] message buffer. The first two bytes are Cipher Suites Length.
 * @param bufLen [IN] Maximum message length
 * @param msg [OUT] Client Hello Structure
 * @param readLen [OUT] Length of the parsed message
 *
 * @retval HITLS_SUCCESS parsed successfully.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 */
static int32_t ParseClientHelloCipherSuites(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
                                            ClientHelloMsg *msg, uint32_t *readLen)
{
    const uint8_t *msgBuf = buf;
    uint32_t bufOffset = 0;

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15700, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the cipher suite length */
    uint16_t cipherSuitesLen = BSL_ByteToUint16(&msgBuf[bufOffset]);
    bufOffset += sizeof(uint16_t);
    if (((uint32_t)cipherSuitesLen > (bufLen - bufOffset)) || ((cipherSuitesLen % SINGLE_CIPHER_SUITE_SIZE) != 0u) ||
        (cipherSuitesLen == 0u)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15701, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the cipherSuites length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    msg->cipherSuitesSize = cipherSuitesLen / SINGLE_CIPHER_SUITE_SIZE;
    BSL_SAL_FREE(msg->cipherSuites);
    msg->cipherSuites = (uint16_t *)BSL_SAL_Malloc(((uint32_t)msg->cipherSuitesSize) * sizeof(uint16_t));
    if (msg->cipherSuites == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15702, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cipherSuites malloc fail when parse client hello msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    /* Parse the cipher suite */
    for (uint16_t index = 0u; index < msg->cipherSuitesSize; index++) {
        msg->cipherSuites[index] = BSL_ByteToUint16(&msgBuf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15703, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "got cipher suite from client:0x%x.", msg->cipherSuites[index], 0, 0, 0);
        if (msg->cipherSuites[index] == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            msg->haveScsvCipher = true;
        }
    }
    *readLen = bufOffset;

    return HITLS_SUCCESS;
}

/**
 * @brief List of compression methods for parsing Client Hello messages
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] message buffer. The first two bytes are the Compression Methods Length.
 * @param bufLen [IN] Maximum message length
 * @param readLen [OUT] Length of the parsed message
 *
 * @retval HITLS_SUCCESS parsed successfully.
 * @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 */
static int32_t ParseClientHelloCompressionMethods(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
    ClientHelloMsg *msg, uint32_t *readLen)
{
    const uint8_t *msgBuf = buf;
    uint32_t bufOffset = 0;

    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15704, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the compression method length */
    uint8_t compressionMethodsLen = msgBuf[bufOffset];
    bufOffset += sizeof(uint8_t);
    if ((compressionMethodsLen > (bufLen - bufOffset)) || (compressionMethodsLen == 0u)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15705, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the compression length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    BSL_SAL_FREE(msg->compressionMethods);
    msg->compressionMethods = (uint8_t *)BSL_SAL_Dump(&msgBuf[bufOffset], compressionMethodsLen);
    if (msg->compressionMethods == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15570, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "compressionMethods malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    msg->compressionMethodsSize = compressionMethodsLen;

    bufOffset += compressionMethodsLen;
    *readLen = bufOffset;
    return HITLS_SUCCESS;
}

/**
* @brief Parse the Client Hello extension messages.
*
* @param ctx [IN] TLS context
* @param buf [IN] message buffer, starting from Extensions Length
* @param bufLen [IN] Maximum message length
* @param msg [OUT] Client Hello Structure
* @param readLen [OUT] Length of the parsed message
*
* @retval HITLS_SUCCESS parsed successfully.
* @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
* @retval HITLS_PARSE_DUPLICATE_EXTENSIVE_MSG Extended message
*/
static int32_t ParseClientHelloExtensions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, ClientHelloMsg *msg)
{
    const uint8_t *msgBuf = buf;
    uint32_t bufOffset = 0;

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15707, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the external message length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the extended message length */
    uint16_t exMsgLen = BSL_ByteToUint16(&msgBuf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    if (exMsgLen != (bufLen - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15708, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the external message length of client hello is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    if (exMsgLen == 0u) {
        return HITLS_SUCCESS;
    }

    return ParseClientExtension(ctx, &msgBuf[bufOffset], exMsgLen, msg);
}

static int32_t WhetherParseClientExtensions(TLS_Ctx *ctx, uint32_t bufOffset, const uint8_t *data, uint32_t len,
    ClientHelloMsg *msg)
{
    int32_t ret;
    /* If the parsing is complete, return success. */
    if (len == bufOffset) {
        // ClientHello is optionally followed by extension data
        return HITLS_SUCCESS;
    }

    ret = ParseClientHelloExtensions(ctx, &data[bufOffset], len - bufOffset, msg);
    if (ret != HITLS_SUCCESS) {
        CleanClientHello(msg);
    }
    return ret;
}

int32_t ParseClientHello(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    ClientHelloMsg *msg = &hsMsg->body.clientHello;
    uint32_t bufOffset = 0, readLen = 0;
    /* Parse the version number. The version number occupies two bytes */
    int32_t ret = ParseVersion(ctx, data, len, &msg->version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += sizeof(uint16_t);

    ctx->negotiatedInfo.clientVersion = msg->version;
    /* Parse the random number. The random number occupies 32 bytes */
    ret = ParseRandom(ctx, &data[bufOffset], len - bufOffset, msg->randomValue, HS_RANDOM_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += HS_RANDOM_SIZE;

    ret = ParseSessionId(ctx, &data[bufOffset], len - bufOffset, &msg->sessionId, &msg->sessionIdSize, &readLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += readLen;
#ifndef HITLS_NO_DTLS12
    if (IS_DTLS_VERSION(HS_GetVersion(ctx))) {
        /* Cookies need to be parsed in DTLS */
        ret = ParseCookie(ctx, &data[bufOffset], len - bufOffset, &msg->cookie, &msg->cookieLen, &readLen);
        if (ret != HITLS_SUCCESS) {
            CleanClientHello(msg);
            return ret;
        }
        bufOffset += readLen;
    }
#endif
    /* Parse the cipher suite. After the parsing is complete, update the msg->cipherSuitesSize and msg->cipherSuites */
    ret = ParseClientHelloCipherSuites(ctx, &data[bufOffset], len - bufOffset, msg, &readLen);
    if (ret != HITLS_SUCCESS) {
        CleanClientHello(msg);
        return ret;
    }
    bufOffset += readLen;
    /* Parse compression method */
    ret = ParseClientHelloCompressionMethods(ctx, &data[bufOffset], len - bufOffset, msg, &readLen);
    if (ret != HITLS_SUCCESS) {
        CleanClientHello(msg);
        return ret;
    }
    bufOffset += readLen;

    return WhetherParseClientExtensions(ctx, bufOffset, data, len, msg);
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

    CleanClientHelloExtension(msg);

    return;
}
