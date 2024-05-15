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
#include "bsl_bytes.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "parse_common.h"


int32_t ParseVersion(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint16_t *version)
{
    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15645, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of handshake message is not enough for version.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    *version = BSL_ByteToUint16(buf);

    return HITLS_SUCCESS;
}

int32_t ParseRandom(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint8_t *random, uint32_t randomSize)
{
    if (bufLen < randomSize) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15646, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of handshake message is not enough for random.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    (void)memcpy_s(random, randomSize, buf, randomSize);

    return HITLS_SUCCESS;
}

static int32_t CheckBufLen(TLS_Ctx *ctx, uint32_t bufLen)
{
    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15647, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of handshake message is not enough for sessionId size.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    return HITLS_SUCCESS;
}

int32_t ParseSessionId(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
                       uint8_t **id, uint8_t *idSize, uint32_t *readLen)
{
    *id = NULL;

    int32_t ret = CheckBufLen(ctx, bufLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t bufOffset = 0;
    /* Extract the sessionId length */
    uint8_t sessionIdSize = buf[bufOffset];
    bufOffset += sizeof(uint8_t);

    if (sessionIdSize == 0u) {
        *idSize = sessionIdSize;
        *readLen = bufOffset;
        return HITLS_SUCCESS;
    }

    /* If the sessionId length is incorrect, return an error code */
    if (sessionIdSize > (bufLen - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15648, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the sessionId length of handshake message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* According to RFC 5246, the length of sessionId cannot exceed 32 bytes */
    if (sessionIdSize > TLS_HS_MAX_SESSION_ID_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15649, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the sessionId length of handshake message over 32.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* The session ID length must be greater than or equal to 24 bytes according to the company security redline */
    if (sessionIdSize < TLS_HS_MIN_SESSION_ID_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15650, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the sessionId length of handshake message less than 24.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the session ID */
    uint8_t *sessionId = BSL_SAL_Malloc(sessionIdSize);
    if (sessionId == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15651, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "sessionId malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(sessionId, sessionIdSize, &buf[bufOffset], sessionIdSize);

    /* Update the buffer offset length */
    bufOffset += sessionIdSize;

    *id = sessionId;
    *idSize = sessionIdSize;
    *readLen = bufOffset;
    return HITLS_SUCCESS;
}

int32_t ParseCookie(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
                    uint8_t **cookie, uint8_t *cookieLen, uint32_t *readLen)
{
    *cookie = NULL;

    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15652, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of handshake message is not enough for cookie size.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t bufOffset = 0;

    /* Extract the cookie length */
    uint8_t tmpCookieLen = buf[bufOffset];
    bufOffset += sizeof(uint8_t);

    if (tmpCookieLen == 0u) {
        *cookieLen = tmpCookieLen;
        *readLen = bufOffset;
        return HITLS_SUCCESS;
    }

    /* If the cookie length is incorrect, return an error code */
    if (tmpCookieLen > (bufLen - bufOffset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15653, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the cookie length of handshake message is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Get the cookie */
    uint8_t *tmpCookie = BSL_SAL_Malloc(tmpCookieLen);
    if (tmpCookie == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15654, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cookie malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(tmpCookie, tmpCookieLen, &buf[bufOffset], tmpCookieLen);

    /* Update the buffer offset length */
    bufOffset += tmpCookieLen;

    *cookie = tmpCookie;
    *cookieLen = tmpCookieLen;
    *readLen = bufOffset;
    return HITLS_SUCCESS;
}
