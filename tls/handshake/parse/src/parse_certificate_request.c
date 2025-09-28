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
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "parse_msg.h"
#include "hs_extensions.h"
#include "parse_extensions.h"
#include "parse_common.h"
#include "custom_extensions.h"

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12) || defined(HITLS_TLS_PROTO_TLS13)

#define SINGLE_SIG_HASH_ALG_SIZE 2u
// Parse the signature algorithm field in the certificate request message.
static int32_t ParseSignatureAndHashAlgo(ParsePacket *pkt, CertificateRequestMsg *msg)
{
    /* An extension of the same type has already been parsed */
    if (msg->haveSignatureAndHashAlgo == true) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_DUPLICATE_EXTENDED_MSG, BINLOG_ID16945,
            BINGLOG_STR("SignatureAndHashAlgo repeated"), ALERT_ILLEGAL_PARAMETER);
    }

    /* Obtain the length of the signature hash algorithm */
    uint16_t signatureAndHashAlgLen = 0;
    const char *logStr = BINGLOG_STR("parse signatureAndHashAlgLen fail.");
    int32_t ret = ParseBytesToUint16(pkt, &signatureAndHashAlgLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15458, logStr, ALERT_DECODE_ERROR);
    }
    if (((uint32_t)signatureAndHashAlgLen > (pkt->bufLen - *pkt->bufOffset)) ||
        ((signatureAndHashAlgLen % SINGLE_SIG_HASH_ALG_SIZE) != 0u) || (signatureAndHashAlgLen == 0u)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15459, logStr, ALERT_DECODE_ERROR);
    }

    /* Parse the length of the signature algorithm */
    pkt->ctx->peerInfo.signatureAlgorithmsSize = signatureAndHashAlgLen / SINGLE_SIG_HASH_ALG_SIZE;
    BSL_SAL_FREE(pkt->ctx->peerInfo.signatureAlgorithms);
    pkt->ctx->peerInfo.signatureAlgorithms = (uint16_t *)BSL_SAL_Malloc(signatureAndHashAlgLen);
    if (pkt->ctx->peerInfo.signatureAlgorithms == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15460,
            BINGLOG_STR("signatureAlgorithms malloc fail"), ALERT_UNKNOWN);
    }
    /* Extract the signature algorithm */
    for (uint16_t index = 0u; index < pkt->ctx->peerInfo.signatureAlgorithmsSize; index++) {
        pkt->ctx->peerInfo.signatureAlgorithms[index] = BSL_ByteToUint16(&pkt->buf[*pkt->bufOffset]);
        *pkt->bufOffset += sizeof(uint16_t);
    }
    msg->signatureAlgorithms = pkt->ctx->peerInfo.signatureAlgorithms;
    msg->signatureAlgorithmsSize = pkt->ctx->peerInfo.signatureAlgorithmsSize;
    msg->haveSignatureAndHashAlgo = true;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS12 || HITLS_TLS_PROTO_DTLS12 || HITLS_TLS_PROTO_TLS13 */

static void CaListNodeInnerDestroy(void *data)
{
    HITLS_TrustedCANode *tmpData = (HITLS_TrustedCANode *)data;
    BSL_SAL_FREE(tmpData->data);
    BSL_SAL_FREE(tmpData);
    return;
}

void FreeDNList(HITLS_TrustedCAList *caList)
{
    BslList *tmpCaList = (BslList *)caList;

    BSL_LIST_FREE(tmpCaList, CaListNodeInnerDestroy);

    return;
}

HITLS_TrustedCANode *ParseDN(const uint8_t *data, uint32_t len)
{
    HITLS_TrustedCANode *dnNode = (HITLS_TrustedCANode *)BSL_SAL_Calloc(1u, sizeof(HITLS_TrustedCANode));
    if (dnNode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15461, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse CA RDN error, out of memory.", 0, 0, 0, 0);
        return NULL;
    }
    dnNode->caType = HITLS_TRUSTED_CA_X509_NAME;
    dnNode->data = BSL_SAL_Dump(data, len);
    if (dnNode->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15462, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse CA RDN error, dump %u bytes data fail.", len, 0, 0, 0);
        BSL_SAL_FREE(dnNode);
        return NULL;
    }
    dnNode->dataSize = len;
    return dnNode;
}

HITLS_TrustedCAList *ParseDNList(const uint8_t *data, uint32_t len)
{
    int32_t ret;
    uint32_t dnLen;
    uint32_t offset = 0u;
    uint32_t distinguishedNamesLen = len;
    HITLS_TrustedCANode *tmpNode = NULL;

    HITLS_TrustedCAList *newCaList = BSL_LIST_New(sizeof(HITLS_TrustedCANode *));
    if (newCaList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15547, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc CA List fail.", 0, 0, 0, 0);
        return NULL;
    }

    while (distinguishedNamesLen > sizeof(uint16_t)) {
        /* Parse the DN length */
        dnLen = BSL_ByteToUint16(&data[offset]);
        offset += sizeof(uint16_t);
        /* Check whether the DN length is valid. */
        if ((dnLen == 0) || dnLen > (len - offset)) {
            BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15464, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "parse CA list error, distinguished name Length = %u, left len = %u.", dnLen, len - offset, 0, 0);
            goto ERR;
        }
        tmpNode = ParseDN(&data[offset], dnLen);
        if (tmpNode == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16947, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ParseDN fail", 0, 0, 0, 0);
            goto ERR;
        }
        ret = BSL_LIST_AddElement(newCaList, tmpNode, BSL_LIST_POS_END);
        if (ret != 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16948, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "AddElement fail", 0, 0, 0, 0);
            BSL_SAL_FREE(tmpNode->data);
            BSL_SAL_FREE(tmpNode);
            goto ERR;
        }
        /* Offset to the next DN data block */
        offset += dnLen;
        distinguishedNamesLen = len - offset;
    }

    if (distinguishedNamesLen != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16949, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "distinguishedNamesLen != 0", 0, 0, 0, 0);
        goto ERR;
    }

    return newCaList;
ERR:
    FreeDNList(newCaList);
    return NULL;
}

// Parse the identification name field in the certificate request packet.
static int32_t ParseDistinguishedName(ParsePacket *pkt, CertificateRequestMsg *msg)
{
    /* An extension of the same type has already been resolved */
    if (msg->haveDistinguishedName == true) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_DUPLICATE_EXTENDED_MSG, BINLOG_ID16950,
            BINGLOG_STR("DistinguishedName repeated"), ALERT_ILLEGAL_PARAMETER);
    }

    /* Obtain the DN list length */
    uint16_t distinguishedNamesLen = 0;
    const char *logStr = BINGLOG_STR("parse distinguishedNamesLen fail.");
    int32_t ret = ParseBytesToUint16(pkt, &distinguishedNamesLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15465, logStr, ALERT_DECODE_ERROR);
    }

    if (distinguishedNamesLen != (pkt->bufLen - *pkt->bufOffset)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15466, logStr, ALERT_DECODE_ERROR);
    }

    if (distinguishedNamesLen > 0u) {
        if (pkt->ctx->peerInfo.caList != NULL) {
            FreeDNList(pkt->ctx->peerInfo.caList);
            pkt->ctx->peerInfo.caList = NULL;
        }
        pkt->ctx->peerInfo.caList = ParseDNList(&pkt->buf[*pkt->bufOffset], distinguishedNamesLen);
        if (pkt->ctx->peerInfo.caList == NULL) {
            return ParseErrorProcess(pkt->ctx, HITLS_PARSE_CA_LIST_ERR, BINLOG_ID16951,
                BINGLOG_STR("ParseDNList fail"), ALERT_DECODE_ERROR);
        }
        *pkt->bufOffset += distinguishedNamesLen;
    }

    msg->haveDistinguishedName = true;
    return HITLS_SUCCESS;
}
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
// Parse the certificate type field in the certificate request message.
static int32_t ParseClientCertificateType(ParsePacket *pkt, CertificateRequestMsg *msg)
{
    const char *logStr = BINGLOG_STR("parse certTypesSize fail.");
    /* Obtain the certificate type length */
    int32_t ret = ParseBytesToUint8(pkt, &msg->certTypesSize);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15455, logStr, ALERT_DECODE_ERROR);
    }
    if (((uint32_t)msg->certTypesSize > (pkt->bufLen - *pkt->bufOffset)) || (msg->certTypesSize == 0u)) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15456, logStr, ALERT_DECODE_ERROR);
    }

    /* Obtain the certificate type */
    BSL_SAL_FREE(msg->certTypes);
    msg->certTypes = BSL_SAL_Dump(&pkt->buf[*pkt->bufOffset], msg->certTypesSize);
    if (msg->certTypes == NULL) {
        return ParseErrorProcess(pkt->ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15457,
            BINGLOG_STR("certTypes malloc fail"), ALERT_UNKNOWN);
    }
    *pkt->bufOffset += msg->certTypesSize;

    return HITLS_SUCCESS;
}

int32_t ParseCertificateRequest(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    uint32_t bufOffset = 0;
    CertificateRequestMsg *msg = &hsMsg->body.certificateReq;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};

    int32_t ret = ParseClientCertificateType(&pkt, msg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12)
    if (pkt.ctx->negotiatedInfo.version >= HITLS_VERSION_TLS12) {
        ret = ParseSignatureAndHashAlgo(&pkt, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_PROTO_TLS12 || HITLS_TLS_PROTO_DTLS12 */
    return ParseDistinguishedName(&pkt, msg);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */

#ifdef HITLS_TLS_PROTO_TLS13


static int32_t ParseCertificateRequestExBody(TLS_Ctx *ctx, uint16_t extMsgType, const uint8_t *buf, uint32_t extMsgLen,
    CertificateRequestMsg *msg)
{
    uint32_t bufOffset = 0u;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = extMsgLen, .bufOffset = &bufOffset};
    switch (extMsgType) {
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS:
            return ParseSignatureAndHashAlgo(&pkt, msg);
        case HS_EX_TYPE_CERTIFICATE_AUTHORITIES:
            return ParseDistinguishedName(&pkt, msg);
        default:
            break;
    }
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsParseNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), extMsgType, HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST)) {
        return ParseCustomExtensions(pkt.ctx, pkt.buf + *pkt.bufOffset, extMsgType, extMsgLen,
            HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST, NULL, 0);
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
    return HITLS_SUCCESS;
}

int32_t ParseTls13CertificateRequestExtensions(ParsePacket *pkt, CertificateRequestMsg *msg)
{
    if (pkt->bufLen - *pkt->bufOffset == 0u) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15472,
            BINGLOG_STR("the extension len of tls1.3 can not be 0"), ALERT_DECODE_ERROR);
    }

    /* Parse the extended packet on the server */
    while (*pkt->bufOffset < pkt->bufLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        int32_t ret =
            ParseExHeader(pkt->ctx, &pkt->buf[*pkt->bufOffset], pkt->bufLen - *pkt->bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        *pkt->bufOffset += HS_EX_HEADER_LEN;
        uint32_t extensionId = HS_GetExtensionTypeId(extMsgType);
        ret = CheckForDuplicateExtension(msg->extensionTypeMask, extensionId, pkt->ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        msg->extensionTypeMask |= 1ULL << extensionId;
        ret = ParseCertificateRequestExBody(pkt->ctx, extMsgType, &pkt->buf[*pkt->bufOffset], extMsgLen, msg);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        *pkt->bufOffset += extMsgLen;
    }

    /* The extended content is the last field in the CertificateRequest packet. No further data should be displayed. If
     * the parsed length is inconsistent with the cache length, an error code is returned */
    if (*pkt->bufOffset != pkt->bufLen) {
        return ParseErrorProcess(pkt->ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15473,
            BINGLOG_STR("extension len error"), ALERT_DECODE_ERROR);
    }

    return HITLS_SUCCESS;
}

int32_t Tls13ParseCertificateRequest(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    uint32_t bufOffset = 0;
    CertificateRequestMsg *msg = &hsMsg->body.certificateReq;
    ParsePacket pkt = {.ctx = ctx, .buf = buf, .bufLen = bufLen, .bufOffset = &bufOffset};

    /* Obtain the certificate_request_context_length */
    uint8_t certReqCtxLen = 0;
    int32_t ret = ParseBytesToUint8(&pkt, &certReqCtxLen);
    if (ret != HITLS_SUCCESS) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16130,
            BINGLOG_STR("tls13 certReq length error"), ALERT_DECODE_ERROR);
    }
    msg->certificateReqCtxSize = (uint32_t)certReqCtxLen;

    /* If the message length is incorrect, an error code is returned. */
    if (*pkt.bufOffset + certReqCtxLen + sizeof(uint16_t) > pkt.bufLen) {
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID16962,
            BINGLOG_STR("certReq length err"), ALERT_DECODE_ERROR);
    }

    /* Obtain the certificate_request_context value */
    if (certReqCtxLen > 0) {
        msg->certificateReqCtx = BSL_SAL_Calloc(certReqCtxLen, sizeof(uint8_t));
        if (msg->certificateReqCtx == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16963, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc err", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy_s(msg->certificateReqCtx, certReqCtxLen, &pkt.buf[*pkt.bufOffset], certReqCtxLen);
        *pkt.bufOffset += certReqCtxLen;
    }

    /* Obtain the extended message length */
    uint16_t exMsgLen = BSL_ByteToUint16(&pkt.buf[*pkt.bufOffset]);
    *pkt.bufOffset += sizeof(uint16_t);

    /* If the buffer length does not match the extended length, an error code is returned */
    if (exMsgLen != (pkt.bufLen - *pkt.bufOffset)) {
        BSL_SAL_FREE(msg->certificateReqCtx);
        msg->certificateReqCtxSize = 0;
        return ParseErrorProcess(pkt.ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15474,
            BINGLOG_STR("tls13 external message length error"), ALERT_DECODE_ERROR);
    }

    ret = ParseTls13CertificateRequestExtensions(&pkt, msg);
    if (ret != HITLS_SUCCESS) {
        CleanCertificateRequest(msg);
    }
    return ret;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
void CleanCertificateRequest(CertificateRequestMsg *msg)
{
    if (msg == NULL) {
        return;
    }

    BSL_SAL_FREE(msg->certTypes);
#ifdef HITLS_TLS_PROTO_TLS13
    BSL_SAL_FREE(msg->certificateReqCtx);
    BSL_SAL_FREE(msg->signatureAlgorithmsCert);
#endif /* HITLS_TLS_PROTO_TLS13 */
    return;
}
#endif /* HITLS_TLS_HOST_CLIENT */