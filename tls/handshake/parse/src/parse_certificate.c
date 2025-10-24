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
#include "hitls_error.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "parse_msg.h"
#include "parse_common.h"
#include "hs_extensions.h"
#include "parse_extensions.h"
#include "custom_extensions.h"

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
int32_t ParseSingleCert(ParsePacket *pkt, CERT_Item **certItem)
{
    uint32_t certLen = 0;
    /* Obtain the certificate length */
    int32_t ret = ParseBytesToUint24(pkt, &certLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15586,
            BINGLOG_STR("Parse cert data len error."), ALERT_DECODE_ERROR);
    }

    if ((certLen == 0) || (certLen > (pkt->bufLen - *pkt->bufOffset))) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15587, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Parse cert data error: data len= %u, cert len= %u.", pkt->bufLen, certLen, 0, 0);
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, 0, NULL, ALERT_DECODE_ERROR);
    }

    CERT_Item *item = (CERT_Item*)BSL_SAL_Calloc(1u, sizeof(CERT_Item));
    if (item == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15588,
            BINGLOG_STR("CERT_Item malloc fail."), ALERT_UNKNOWN);
    }
    item->next = NULL;
    item->dataSize = certLen; /* Update the length of the certificate message */

    /* Extract the contents of the certificate message */
    item->data = BSL_SAL_Malloc(item->dataSize);
    if (item->data == NULL) {
        BSL_SAL_FREE(item);
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15589,
            BINGLOG_STR("item->data malloc fail."), ALERT_UNKNOWN);
    }
    (void)memcpy_s(item->data, item->dataSize, &pkt->buf[*pkt->bufOffset], item->dataSize);
    *pkt->bufOffset += certLen;
    *certItem = item;

    return HITLS_SUCCESS;
}

static int32_t ParseCertExtension(ParsePacket *pkt, CertificateMsg *msg, CERT_Item *item, uint32_t certIndex)
{
    (void)item;
    (void)certIndex;
    if (pkt->ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        return HITLS_SUCCESS;
    }

    uint16_t certExLen = 0;
    const char *logStr = BINGLOG_STR("length of certificate extension is incorrect.");
    int32_t ret = ParseBytesToUint16(pkt, &certExLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15590, logStr, ALERT_DECODE_ERROR);
    }
    if (*pkt->bufOffset + certExLen > pkt->bufLen) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16235, logStr, ALERT_DECODE_ERROR);
    }

    uint32_t offset = 0;
    while (offset < certExLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        ret = ParseExHeader(pkt->ctx, &pkt->buf[*pkt->bufOffset],
            pkt->bufLen - *pkt->bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            return ParseErrorProcess(pkt->ctx, ret, BINLOG_ID15330, logStr, ALERT_DECODE_ERROR);
        }
        *pkt->bufOffset += HS_EX_HEADER_LEN;
        offset += HS_EX_HEADER_LEN;
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
        if (IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(pkt->ctx), extMsgType, HITLS_EX_TYPE_TLS1_3_CERTIFICATE)) {
            HITLS_CERT_X509 *cert = SAL_CERT_X509Parse(LIBCTX_FROM_CTX(pkt->ctx),
                ATTRIBUTE_FROM_CTX(pkt->ctx), &pkt->ctx->config.tlsConfig, item->data, item->dataSize,
                TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_ASN1);
            if (cert == NULL) {
                return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15331,
                    "X509Parse fail", ALERT_DECODE_ERROR);
            }
            ret = ParseCustomExtensions(pkt->ctx, &pkt->buf[*pkt->bufOffset], extMsgType, extMsgLen,
                HITLS_EX_TYPE_TLS1_3_CERTIFICATE, cert, certIndex);
            SAL_CERT_X509Free(cert);
            if (ret != HITLS_SUCCESS) {
                return ParseErrorProcess(pkt->ctx, ret, BINLOG_ID15332, "ParseCustomExtensions fail",
                    ALERT_DECODE_ERROR);
            }
        } else
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
        {
            msg->extensionTypeMask |= 1ULL << HS_GetExtensionTypeId(extMsgType);
        }
        *pkt->bufOffset += extMsgLen;
        offset += extMsgLen;
    }

    if (offset != certExLen) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15463,
            BINGLOG_STR("extension len error"), ALERT_DECODE_ERROR);
    }

    return HITLS_SUCCESS;
}

int32_t ParseCerts(ParsePacket *pkt, HS_Msg *hsMsg)
{
    int32_t ret;
    CertificateMsg *msg = &hsMsg->body.certificate;
    CERT_Item *cur = msg->cert;

    /* Parse the certificate message and save the certificate chain to the structure */
    while (*pkt->bufOffset < pkt->bufLen) {
        CERT_Item *item = NULL;
        ret = ParseSingleCert(pkt, &item);
        if (ret != HITLS_SUCCESS) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_CERT_ERR, BINLOG_ID15591,
                BINGLOG_STR("parse certificate item fail."), ALERT_UNKNOWN);
        }

        /* Add the parsed certificate to the last node in the linked list */
        if (msg->cert == NULL) {
            msg->cert = item;
        } else if (cur != NULL) {
            cur->next = item;
        }
        cur = item;

        ret = ParseCertExtension(pkt, msg, item, msg->certCount);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15592, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse certificate extension fail.", 0, 0, 0, 0);
            return ret;
        }

        msg->certCount++;
    }

    return HITLS_SUCCESS;
}
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
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
    uint32_t offset = 0;
    uint32_t allCertsLen = 0;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &offset};
    const char *logStr = BINGLOG_STR("length of all certificates is incorrect.");
    /* Obtain the lengths of all certificates */
    int32_t ret = ParseBytesToUint24(&pkt, &allCertsLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15593, logStr, ALERT_DECODE_ERROR);
    }

    if (allCertsLen != (pkt.bufLen - CERT_LEN_TAG_SIZE)) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15594, logStr, ALERT_DECODE_ERROR);
    }

    /*
     * The client can send a certificate message without a certificate, so if the total length of the certificate is 0,
     * it directly returns success; If the client receives a certificate message of length 0, it is determined by the
     * processing layer, which is only responsible for parsing
     */
    if (allCertsLen == 0) {
        return HITLS_SUCCESS;
    }

    ret = ParseCerts(&pkt, hsMsg);
    if ((ret != HITLS_SUCCESS) || (*pkt.bufOffset != (allCertsLen + CERT_LEN_TAG_SIZE))) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_CERT_ERR, BINLOG_ID15595,
            BINGLOG_STR("Certificate msg parse failed."), ALERT_UNKNOWN);
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13ParseCertificateReqCtx(ParsePacket *pkt, HS_Msg *hsMsg)
{
    CertificateMsg *certMsg = &hsMsg->body.certificate;
    /* Obtain the certificates_request_context_length */
    uint8_t len = 0;
    int32_t ret = ParseBytesToUint8(pkt, &len);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16971,
            BINGLOG_STR("ParseBytesToUint8 fail"), ALERT_DECODE_ERROR);
    }
    uint16_t certReqCtxLen = (uint16_t)len;
    certMsg->certificateReqCtxSize = (uint32_t)certReqCtxLen;
    /* At least the length and content of the total certificate length of 3 bytes + certificateReqCtx can be parsed */
    if (pkt->bufLen < CERT_LEN_TAG_SIZE + certReqCtxLen + sizeof(uint8_t)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16129,
            BINGLOG_STR("the length of tls13 certificate message is incorrect"), ALERT_DECODE_ERROR);
    }
    /* Obtain the certificate_request_context value */
    if (certReqCtxLen > 0) {
        certMsg->certificateReqCtx = BSL_SAL_Calloc(certReqCtxLen, sizeof(uint8_t));
        if (certMsg->certificateReqCtx == NULL) {
            return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15596,
                BINGLOG_STR("certificateReqCtx malloc fail."), ALERT_UNKNOWN);
        }
        (void)memcpy_s(certMsg->certificateReqCtx, certReqCtxLen, &pkt->buf[*pkt->bufOffset], certReqCtxLen);
        *pkt->bufOffset += certReqCtxLen;
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
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &offset};
    int32_t ret = Tls13ParseCertificateReqCtx(&pkt, hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t allCertsLen = 0;
    ret = ParseBytesToUint24(&pkt, &allCertsLen);
    if (ret != HITLS_SUCCESS || (allCertsLen != (pkt.bufLen - *pkt.bufOffset))) {
        CleanCertificate(&hsMsg->body.certificate);
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15597,
            BINGLOG_STR("length of all tls1.3 certificates is incorrect."), ALERT_DECODE_ERROR);
    }

    /*
     * The client can send a certificate message without a certificate, so if the total length of the certificate is 0,
     * it directly returns success; If the client receives a certificate message of length 0, it is determined by the
     * processing layer, which is only responsible for parsing
     */
    if (allCertsLen == 0) {
        return HITLS_SUCCESS;
    }

    ret = ParseCerts(&pkt, hsMsg);
    if ((ret != HITLS_SUCCESS) ||
        (*pkt.bufOffset != (sizeof(uint8_t) + certMsg->certificateReqCtxSize + CERT_LEN_TAG_SIZE + allCertsLen))) {
        CleanCertificate(&hsMsg->body.certificate);
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_CERT_ERR, BINLOG_ID15598,
            BINGLOG_STR("Certificate msg parse failed."), ALERT_UNKNOWN);
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
//  Clear the memory applied for in the certificate message structure.
void CleanCertificate(CertificateMsg *msg)
{
    if (msg == NULL) {
        return;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    BSL_SAL_FREE(msg->certificateReqCtx);
#endif
    CERT_Item *next = msg->cert;
    while (next != NULL) {
        CERT_Item *temp = next->next;
        BSL_SAL_FREE(next->data);
        BSL_SAL_FREE(next);
        next = temp;
    }
    msg->cert = NULL;
    return;
}
