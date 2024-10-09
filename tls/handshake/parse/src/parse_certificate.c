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
#include "hs_msg.h"
#include "hs_common.h"
#include "parse_msg.h"

/**
 * @brief   Parse the certificate signature
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] message to be parsed
 * @param bufLen [IN] buffer length
 * @param readLen [OUT] Parsed length
 *
 * @return Return the memory of the applied certificate. If NULL is returned, the parsing fails.
 */
CERT_Item *ParseSingleCert(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint32_t *readLen)
{
    if (bufLen <= CERT_LEN_TAG_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15586, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse cert data error: data len= %u, less than 3.", bufLen, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    uint32_t bufOffset = 0;
    uint32_t certLen = BSL_ByteToUint24(buf); /* Obtain the certificate length */
    bufOffset += CERT_LEN_TAG_SIZE;

    if ((certLen == 0) || (certLen > (bufLen - bufOffset))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15587, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse cert data error: data len= %u, cert len= %u.", bufLen, certLen, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return NULL;
    }

    /* Allocate memory for certificate messages */
    CERT_Item *item = (CERT_Item*)BSL_SAL_Calloc(1u, sizeof(CERT_Item));
    if (item == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15588, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CERT_Item malloc fail when parse certificate msg.", 0, 0, 0, 0);
        return NULL;
    }
    item->next = NULL;
    item->dataSize = certLen; /* Update the length of the certificate message */

    /* Extract the contents of the certificate message */
    item->data = BSL_SAL_Malloc(item->dataSize);
    if (item->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15589, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "item->data malloc fail when parse certificate msg.", 0, 0, 0, 0);
        BSL_SAL_FREE(item);
        return NULL;
    }
    (void)memcpy_s(item->data, item->dataSize, &buf[bufOffset], item->dataSize);
    bufOffset += certLen;

    /* Update certificate message parameters */
    *readLen = bufOffset;

    return item;
}

static int32_t ParseCertExtension(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint32_t *readLen)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        *readLen = 0;
        return HITLS_SUCCESS;
    }

    if (bufLen < sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15590, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of certificate extension is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t offset = 0;
    uint16_t certExLen = BSL_ByteToUint16(&buf[offset]);
    offset += sizeof(uint16_t) + certExLen;  // Skip extensions

    *readLen = offset;
    return HITLS_SUCCESS;
}

// Parse the certificate content
int32_t ParseCerts(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg, uint32_t *offset)
{
    int32_t ret;
    CertificateMsg *msg = &hsMsg->body.certificate;
    CERT_Item *cur = msg->cert;
    uint32_t tmpOffset = *offset;

    /* Parse the certificate message and save the certificate chain to the structure */
    while (tmpOffset < bufLen) {
        uint32_t readLen = 0u;

        CERT_Item *item = NULL;
        item = ParseSingleCert(ctx, &buf[tmpOffset], bufLen - tmpOffset, &readLen);
        if (item == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_CERT_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15591, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse certificate item fail.", 0, 0, 0, 0);
            return HITLS_PARSE_CERT_ERR;
        }

        /* Add the parsed certificate to the last node in the linked list */
        if (msg->cert == NULL) {
            msg->cert = item;
        } else {
            cur->next = item;
        }
        cur = item;
        tmpOffset += readLen;

        ret = ParseCertExtension(ctx, &buf[tmpOffset], bufLen - tmpOffset, &readLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15592, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse certificate extension fail.", 0, 0, 0, 0);
            return ret;
        }
        tmpOffset += readLen;

        msg->certCount++;
    }
    *offset = tmpOffset;

    return HITLS_SUCCESS;
}

/**
* @brief Parse the certificate message.
*
* @param ctx [IN] TLS context
* @param buf [IN] message buffer
* @param bufLen [IN] Maximum message length
* @param hsMsg [OUT] message structure
*
* @retval HITLS_SUCCESS parsed successfully.
* @retval HITLS_PARSE_CERT_ERR Failed to parse the certificate.
* @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseCertificate(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    /* The total length of the certificate can be parsed at least 3 bytes */
    if (bufLen < CERT_LEN_TAG_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15593, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of handshake message (certificate) is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    int32_t ret;
    uint32_t offset = 0;

    /* Obtain the lengths of all certificates */
    uint32_t allCertsLen = BSL_ByteToUint24(buf);
    if (allCertsLen != (bufLen - CERT_LEN_TAG_SIZE)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15594, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of all certificates is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /**
     * The client can send a certificate message without a certificate, so if the total length of the certificate is 0,
     * it directly returns success; If the client receives a certificate message of length 0, it is determined by the
     * processing layer, which is only responsible for parsing
     */
    if (allCertsLen == 0) {
        return HITLS_SUCCESS;
    }

    offset += CERT_LEN_TAG_SIZE; /* Initialize the buffer length offset. */

    ret = ParseCerts(ctx, buf, bufLen, hsMsg, &offset);
    if ((ret != HITLS_SUCCESS) || (offset != (allCertsLen + CERT_LEN_TAG_SIZE))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_CERT_ERR);
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID15595, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Certificate msg parse failed.", 0, 0, 0, 0);
        CleanCertificate(&hsMsg->body.certificate);
        return HITLS_PARSE_CERT_ERR;
    }

    return HITLS_SUCCESS;
}

int32_t Tls13ParseCertificateReqCtx(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg, uint32_t *offset)
{
    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    CertificateMsg *certMsg = &hsMsg->body.certificate;

    /* Obtain the certificates_request_context_length */
    uint16_t certReqCtxLen = buf[*offset];
    certMsg->certificateReqCtxSize = (uint32_t)certReqCtxLen;
    (*offset)++;
    /* At least the length and content of the total certificate length of 3 bytes + certificateReqCtx can be parsed */
    if (bufLen < CERT_LEN_TAG_SIZE + certReqCtxLen + sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15905, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the length of handshake message (tls 1.3 certificate) is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    /* Obtain the certificate_request_context value */
    if (certReqCtxLen > 0) {
        certMsg->certificateReqCtx = BSL_SAL_Calloc(certReqCtxLen, sizeof(uint8_t));
        if (certMsg->certificateReqCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15596, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "certificateReqCtx malloc fail when parse tls1.3 certificate msg.", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy_s(certMsg->certificateReqCtx, certReqCtxLen, &buf[*offset], certReqCtxLen);
        *offset += certReqCtxLen;
    }
    return HITLS_SUCCESS;
}

/**
* @brief Parse the certificate message.
*
* @param ctx [IN] TLS context
* @param buf [IN] message buffer
* @param bufLen [IN] Maximum message length
* @param hsMsg [OUT] message structure
*
* @retval HITLS_SUCCESS parsed successfully.
* @retval HITLS_PARSE_CERT_ERR Failed to parse the certificate.
* @retval HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect.
 */
int32_t Tls13ParseCertificate(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    CertificateMsg *certMsg = &hsMsg->body.certificate;
    uint32_t offset = 0;
    int32_t ret = Tls13ParseCertificateReqCtx(ctx, buf, bufLen, hsMsg, &offset);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Obtain the lengths of all certificates */
    uint32_t allCertsLen = BSL_ByteToUint24(&buf[offset]);
    if (allCertsLen != (bufLen - CERT_LEN_TAG_SIZE - offset)) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15597, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length of all tls1.3 certificates is incorrect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        CleanCertificate(&hsMsg->body.certificate);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    /**
     * The client can send a certificate message without a certificate, so if the total length of the certificate is 0,
     * it directly returns success; If the client receives a certificate message of length 0, it is determined by the
     * processing layer, which is only responsible for parsing
     */
    if (allCertsLen == 0) {
        return HITLS_SUCCESS;
    }

    offset += CERT_LEN_TAG_SIZE;

    ret = ParseCerts(ctx, buf, bufLen, hsMsg, &offset);
    if ((ret != HITLS_SUCCESS) ||
        (offset != (sizeof(uint8_t) + certMsg->certificateReqCtxSize + CERT_LEN_TAG_SIZE + allCertsLen))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_CERT_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15598, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Certificate msg parse failed.", 0, 0, 0, 0);
        CleanCertificate(&hsMsg->body.certificate);
        return HITLS_PARSE_CERT_ERR;
    }

    return HITLS_SUCCESS;
}

//  Clear the memory applied for in the certificate message structure.
void CleanCertificate(CertificateMsg *msg)
{
    if (msg == NULL) {
        return;
    }
    BSL_SAL_FREE(msg->certificateReqCtx);
    /* Obtain the certificate message */
    CERT_Item *next = msg->cert;
    /* Release the message until it is empty */
    while (next != NULL) {
        CERT_Item *temp = next->next;
        BSL_SAL_FREE(next->data);
        BSL_SAL_FREE(next);
        next = temp;
    }
    msg->cert = NULL;
    return;
}
