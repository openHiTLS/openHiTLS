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
#include "bsl_bytes.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hs_common.h"
#include "parse_common.h"

int32_t ParseVersion(ParsePacket *pkt, uint16_t *version)
{
    int32_t ret = ParseBytesToUint16(pkt, version);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15645,
            BINGLOG_STR("parse version failed"), ALERT_DECODE_ERROR);
    }
    return HITLS_SUCCESS;
}

int32_t ParseRandom(ParsePacket *pkt, uint8_t *random, uint32_t randomSize)
{
    int32_t ret = ParseCopyBytesToArray(pkt, random, randomSize);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15646,
            BINGLOG_STR("parse random failed."), ALERT_DECODE_ERROR);
    }
    return HITLS_SUCCESS;
}

int32_t ParseSessionId(ParsePacket *pkt, uint8_t *idSize, uint8_t **id)
{
    int32_t ret = ParseOneByteLengthField(pkt, idSize, id);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15647,
            BINGLOG_STR("parse sessionId failed."), ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15651,
            BINGLOG_STR("sessionId malloc fail."), ALERT_UNKNOWN);
    }
    if (*idSize == 0u) {
        return HITLS_SUCCESS;
    }
    /* According to RFC 5246, the length of sessionId cannot exceed 32 bytes */
    if (*idSize > TLS_HS_MAX_SESSION_ID_SIZE) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15649,
            BINGLOG_STR("sessionId length over 32."), ALERT_DECODE_ERROR);
    }

    /* The session ID length must be greater than or equal to 24 bytes according to the company security redline */
    if (*idSize < TLS_HS_MIN_SESSION_ID_SIZE) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15650,
            BINGLOG_STR("sessionId length less than 24."), ALERT_DECODE_ERROR);
    }

    return HITLS_SUCCESS;
}

int32_t ParseCookie(ParsePacket *pkt, uint8_t *cookieLen, uint8_t **cookie)
{
    int32_t ret = ParseOneByteLengthField(pkt, cookieLen, cookie);
    if (ret == HITLS_PARSE_INVALID_MSG_LEN) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15652,
            BINGLOG_STR("parse cookie failed."), ALERT_DECODE_ERROR);
    } else if (ret == HITLS_MEMALLOC_FAIL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15654,
            BINGLOG_STR("cookie malloc failed."), ALERT_UNKNOWN);
    }
    return HITLS_SUCCESS;
}

int32_t ParseBytesToUint8(ParsePacket *pkt, uint8_t *object)
{
    if (pkt->bufLen - *pkt->bufOffset < sizeof(uint8_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16975, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen err", 0, 0, 0, 0);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    *object = (uint8_t)pkt->buf[*pkt->bufOffset];
    *pkt->bufOffset += sizeof(uint8_t);
    return HITLS_SUCCESS;
}

int32_t ParseBytesToUint16(ParsePacket *pkt, uint16_t *object)
{
    if (pkt->bufLen - *pkt->bufOffset < sizeof(uint16_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16976, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen err", 0, 0, 0, 0);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    *object = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
    *pkt->bufOffset += sizeof(uint16_t);
    return HITLS_SUCCESS;
}

int32_t ParseBytesToUint24(ParsePacket *pkt, uint32_t *object)
{
    if (pkt->bufLen - *pkt->bufOffset < UINT24_SIZE) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16977, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen err", 0, 0, 0, 0);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    *object = BSL_ByteToUint24(&pkt->buf[*pkt->bufOffset]);
    *pkt->bufOffset += UINT24_SIZE;
    return HITLS_SUCCESS;
}

int32_t ParseBytesToUint32(ParsePacket *pkt, uint32_t *object)
{
    if (pkt->bufLen - *pkt->bufOffset < sizeof(uint32_t)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16978, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen err", 0, 0, 0, 0);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    *object = BSL_ByteToUint32(&pkt->buf[*pkt->bufOffset]);
    *pkt->bufOffset += sizeof(uint32_t);
    return HITLS_SUCCESS;
}

int32_t ParseOneByteLengthField(ParsePacket *pkt, uint8_t *objectSize, uint8_t **object)
{
    int32_t ret = ParseBytesToUint8(pkt, objectSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ParseBytesToArray(pkt, object, *objectSize);
}

int32_t ParseTwoByteLengthField(ParsePacket *pkt, uint16_t *objectSize, uint8_t **object)
{
    int32_t ret = ParseBytesToUint16(pkt, objectSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ParseBytesToArray(pkt, object, *objectSize);
}

int32_t ParseBytesToArray(ParsePacket *pkt, uint8_t **object, uint32_t length)
{
    BSL_SAL_FREE(*object);
    if (pkt->bufLen - *pkt->bufOffset < length) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16979, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen err", 0, 0, 0, 0);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    if (length == 0) {
        return HITLS_SUCCESS;
    }

    *object = (uint8_t *)BSL_SAL_Malloc(length);
    if (*object == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16980, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Malloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    (void)memcpy_s(*object, length, &pkt->buf[*pkt->bufOffset], length);
    *pkt->bufOffset += length;

    return HITLS_SUCCESS;
}

int32_t ParseCopyBytesToArray(ParsePacket *pkt, uint8_t *object, uint32_t length)
{
    if (pkt->bufLen - *pkt->bufOffset < length) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16981, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "bufLen err", 0, 0, 0, 0);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    (void)memcpy_s(object, length, &pkt->buf[*pkt->bufOffset], length);
    *pkt->bufOffset += length;
    return HITLS_SUCCESS;
}

int32_t ParseErrorProcess(TLS_Ctx *ctx, int32_t err, uint32_t logId, const void *format,
    ALERT_Description description)
{
#ifndef HITLS_BSL_LOG
    (void)logId;
#endif
    BSL_ERR_PUSH_ERROR(err);
    if (format != NULL) {
        BSL_LOG_BINLOG_FIXLEN(logId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, format, 0, 0, 0, 0);
    }
    if (description != ALERT_UNKNOWN) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, description);
    }
    return err;
}

int32_t CheckPeerSignScheme(HITLS_Ctx *ctx, CERT_Pair *peerCert, uint16_t signScheme)
{
    if (peerCert == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_PARSE_UNSUPPORT_SIGN_ALG, BINLOG_ID17160, "peerCert null");
    }
    HITLS_Config *config = &ctx->config.tlsConfig;
    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(config, peerCert->cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17140, "get pubkey fail");
    }
    uint32_t keyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_TYPE, NULL, (void *)&keyType);
    SAL_CERT_KeyFree(config->certMgrCtx, pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17099, "get pubkey type fail");
    }

    if (keyType != HS_SignScheme2CertKeyType(ctx, signScheme)) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_PARSE_UNSUPPORT_SIGN_ALG, BINLOG_ID17156, "signScheme err");
    }

    return HITLS_SUCCESS;
}

int32_t ParseExtensionCommon(ParsePacket *pkt, uint16_t *exMsgLen)
{
    const char *logStr = BINGLOG_STR("parse extension length failed.");
    int32_t ret = ParseBytesToUint16(pkt, exMsgLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15707,
            logStr, ALERT_DECODE_ERROR);
    }

    if (*exMsgLen != (pkt->bufLen - *pkt->bufOffset)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15708,
            logStr, ALERT_DECODE_ERROR);
    }

    return HITLS_SUCCESS;
}