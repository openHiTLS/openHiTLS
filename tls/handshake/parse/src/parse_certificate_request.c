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
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "parse_msg.h"
#include "hs_extensions.h"
#include "parse_extensions.h"


#define SINGLE_SIG_HASH_ALG_SIZE 2u

// Parse the certificate type field in the certificate request message.
static int32_t ParseClientCertificateType(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
    CertificateRequestMsg *msg, uint32_t *useLen)
{
    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15455, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of certificate request msg is incorrect when parse client certificate type.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the certificate type length */
    uint32_t bufOffset = 0;
    msg->certTypesSize = buf[bufOffset];
    bufOffset += sizeof(uint8_t);
    if (((uint32_t)msg->certTypesSize > (bufLen - bufOffset)) || (msg->certTypesSize == 0u)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15456, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the certificate type size in the certificate request is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the certificate type */
    msg->certTypes = BSL_SAL_Dump(&buf[bufOffset], msg->certTypesSize);
    if (msg->certTypes == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15457, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certTypes malloc fail when parse certificate request.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    bufOffset += msg->certTypesSize;
    *useLen = bufOffset;

    return HITLS_SUCCESS;
}

// Parse the signature algorithm field in the certificate request message.
static int32_t ParseSignatureAndHashAlgo(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
    CertificateRequestMsg *msg, uint32_t *useLen)
{
    uint32_t bufOffset = 0;

    /* An extension of the same type has already been parsed */
    if (msg->haveSignatureAndHashAlgo == true) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_DUPLICATE_EXTENDED_MSG);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_PARSE_DUPLICATE_EXTENDED_MSG;
    }
    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15458, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of certificate request msg is incorrect when parse signature and hashAlgo.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the length of the signature hash algorithm */
    uint16_t signatureAndHashAlgLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);
    if (((uint32_t)signatureAndHashAlgLen > (bufLen - bufOffset)) ||
        ((signatureAndHashAlgLen % SINGLE_SIG_HASH_ALG_SIZE) != 0u) || (signatureAndHashAlgLen == 0u)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15459, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the signature and Hash algorithm length in certificate request msg is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Parse the length of the signature algorithm */
    msg->signatureAlgorithmsSize = signatureAndHashAlgLen / SINGLE_SIG_HASH_ALG_SIZE;
    msg->signatureAlgorithms = (uint16_t *)BSL_SAL_Malloc(signatureAndHashAlgLen);
    if (msg->signatureAlgorithms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15460, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signatureAlgorithms malloc fail when parse certificate request.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    /* Extract the signature algorithm */
    for (uint16_t index = 0u; index < msg->signatureAlgorithmsSize; index++) {
        msg->signatureAlgorithms[index] = BSL_ByteToUint16(&buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
    }
    *useLen = bufOffset;

    msg->haveSignatureAndHashAlgo = true;
    return HITLS_SUCCESS;
}

int32_t ParseCertificateRequest(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t bufOffset = 0;
    uint32_t useLen = 0;
    CertificateRequestMsg *msg = &hsMsg->body.certificateReq;

    ret = ParseClientCertificateType(ctx, buf, bufLen, msg, &useLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    bufOffset += useLen;

    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP11) {
        ret = ParseSignatureAndHashAlgo(ctx, &buf[bufOffset], bufLen - bufOffset, msg, &useLen);
        if (ret != HITLS_SUCCESS) {
            CleanCertificateRequest(msg);
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

void CleanCertificateRequest(CertificateRequestMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    /* release Certificate request message */
    BSL_SAL_FREE(msg->certificateReqCtx);
    BSL_SAL_FREE(msg->certTypes);
    BSL_SAL_FREE(msg->signatureAlgorithms);
    return;
}

static int32_t ParseCertificateRequestExBody(TLS_Ctx *ctx, uint16_t extMsgType, const uint8_t *buf, uint32_t extMsgLen,
    CertificateRequestMsg *msg)
{
    uint32_t usedLen = 0u;
    switch (extMsgType) {
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS:
            return ParseSignatureAndHashAlgo(ctx, buf, extMsgLen, msg, &usedLen);
        default:
            break;
    }

    return HITLS_SUCCESS;
}

int32_t ParseTls13CertificateRequestExtensions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen,
    CertificateRequestMsg *msg)
{
    if (bufLen == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15472, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the extension len of tls1.3 CertificateRequest msg could not be 0.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Initialize the message parsing length */
    uint32_t bufOffset = 0u;
    int32_t ret;

    /* Parse the extended message on the server */
    while (bufOffset < bufLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        ret = ParseExHeader(ctx, &buf[bufOffset], bufLen - bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += HS_EX_HEADER_LEN;

        ret = ParseCertificateRequestExBody(ctx, extMsgType, &buf[bufOffset], extMsgLen, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += extMsgLen;
    }

    /* The extended content is the last field in the CertificateRequest message. No further data should be displayed. If
     * the parsed length is inconsistent with the cache length, return an error code. */
    if (bufOffset != bufLen) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15473, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the extension len of CertificateRequest msg is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    return HITLS_SUCCESS;
}

int32_t Tls13ParseCertificateRequest(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15852, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of tls1.3 certificate request msg is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    int32_t ret;
    uint32_t bufOffset = 0;
    CertificateRequestMsg *msg = &hsMsg->body.certificateReq;

    /* Obtain the certificate_request_context_length */
    uint8_t certReqCtxLen = buf[bufOffset];
    msg->certificateReqCtxSize = (uint32_t)certReqCtxLen;
    bufOffset++;

    /* If the message length is incorrect, return an error code. */
    if (bufOffset + certReqCtxLen + sizeof(uint16_t) > bufLen) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /* Obtain the certificate_request_context value */
    if (certReqCtxLen > 0) {
        msg->certificateReqCtx = BSL_SAL_Calloc(certReqCtxLen, sizeof(uint8_t));
        if (msg->certificateReqCtx == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy_s(msg->certificateReqCtx, certReqCtxLen, &buf[bufOffset], certReqCtxLen);
        bufOffset += certReqCtxLen;
    }

    /* Obtain the extended message length */
    uint16_t exMsgLen = BSL_ByteToUint16(&buf[bufOffset]);
    bufOffset += sizeof(uint16_t);

    /* If the buffer length does not match the extended length, return an error code. */
    if (exMsgLen != (bufLen - bufOffset)) {
        BSL_SAL_FREE(msg->certificateReqCtx);
        msg->certificateReqCtxSize = 0;
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15474, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the external message length of handshake message (tls1.3 CertificateRequest) is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    ret = ParseTls13CertificateRequestExtensions(ctx, &buf[bufOffset], bufLen - bufOffset, msg);
    if (ret != HITLS_SUCCESS) {
        CleanCertificateRequest(msg);
        return ret;
    }

    return HITLS_SUCCESS;
}