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
#include <stdint.h>
#include "hitls_build.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hitls_cert_type.h"
#include "bsl_list.h"
#include "hitls_cert_type.h"
#include "bsl_list.h"
#include "pack_common.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif

#define BUFFER_GROW_FACTOR 2u

#ifdef HITLS_TLS_PROTO_DTLS12
/**
 * @brief Pack the packet header.
 *
 * @param type [IN] message type
 * @param sequence [IN] Sequence number (dedicated for DTLS)
 * @param length [IN] message body length
 * @param buf [OUT] message header
 */
void PackDtlsMsgHeader(HS_MsgType type, uint16_t sequence, uint32_t length, uint8_t *buf)
{
    buf[0] = (uint8_t)type & 0xffu;                               /** Type of the handshake message */
    BSL_Uint24ToByte(length, &buf[DTLS_HS_MSGLEN_ADDR]); /** Fills the length of the handshake message */
    BSL_Uint16ToByte(
        sequence, &buf[DTLS_HS_MSGSEQ_ADDR]); /** Two bytes starting from four bytes are the sn of the message */
    BSL_Uint24ToByte(
        0, &buf[DTLS_HS_FRAGMENT_OFFSET_ADDR]); /** The three bytes starting from 6 bytes are the fragment offset. */
    BSL_Uint24ToByte(
        length, &buf[DTLS_HS_FRAGMENT_LEN_ADDR]); /** Three bytes starting from 9 bytes are the fragment length. */
}
#endif /* HITLS_TLS_PROTO_DTLS12 */

#if defined(HITLS_TLS_FEATURE_SESSION_ID) || defined(HITLS_TLS_PROTO_TLS13)
/**
 * @brief Pack the message session ID.
 *
 * @param id [IN] Session ID
 * @param idSize [IN] Session ID length
 * @param buf [OUT] message buffer
 * @param bufLen [IN] Maximum message length
 * @param usedLen [OUT] Length of the packed message
 *
 * @retval HITLS_SUCCESS Assembly succeeded.
 * @retval HITLS_PACK_SESSIONID_ERR Failed to pack the sessionId.
 * @retval HITLS_MEMCPY_FAIL Memory Copy Failure
 */
int32_t PackSessionId(PackPacket *pkt, const uint8_t *id, uint32_t idSize)
{
    /* If the sessionId length does not meet the requirement, an error code is returned */
    if ((idSize != 0) && ((idSize > TLS_HS_MAX_SESSION_ID_SIZE) || (idSize < TLS_HS_MIN_SESSION_ID_SIZE))) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SESSIONID_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15849, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "session id size is incorrect when pace session id.", 0, 0, 0, 0);
        return HITLS_PACK_SESSIONID_ERR;
    }

    int32_t ret = PackAppendUint8ToBuf(pkt, (uint8_t)idSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* If the value of sessionId is 0, a success message is returned */
    if (idSize == 0u) {
        return HITLS_SUCCESS;
    }
    return PackAppendDataToBuf(pkt, id, idSize);
}
#endif /* #if HITLS_TLS_FEATURE_SESSION_ID || HITLS_TLS_PROTO_TLS13 */

#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
int32_t PackTrustedCAList(HITLS_TrustedCAList *caList, PackPacket *pkt)
{
    if (caList == NULL) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret = HITLS_SUCCESS;
    HITLS_TrustedCANode *node = (HITLS_TrustedCANode *)BSL_LIST_GET_FIRST(caList);
    while (node != NULL) {
        if (node->data != NULL && node->dataSize != 0) {
            ret = PackAppendUint16ToBuf(pkt, (uint16_t)node->dataSize);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }

            ret = PackAppendDataToBuf(pkt, node->data, node->dataSize);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
        node = (HITLS_TrustedCANode *)BSL_LIST_GET_NEXT(caList);
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */

#ifdef HITLS_TLS_PROTO_TLS13
int32_t PackCertificateReqCtx(const TLS_Ctx *ctx, PackPacket *pkt)
{
    /* Pack the length of certificate_request_context */
    int32_t ret = PackAppendUint8ToBuf(pkt, (uint8_t)ctx->certificateReqCtxSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the content of certificate_request_context */
    if (ctx->certificateReqCtxSize > 0) {
        ret = PackAppendDataToBuf(pkt, ctx->certificateReqCtx, ctx->certificateReqCtxSize);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */

int32_t PackHelloCommonField(const TLS_Ctx *ctx, PackPacket *pkt, uint16_t version, bool isClient)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_SECURITY
    ret = SECURITY_CfgCheck(&ctx->config.tlsConfig, HITLS_SECURITY_SECOP_VERSION, 0, version, NULL);
    if (ret != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16924, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CfgCheck fail, ret %d", ret, 0, 0, 0);
        ctx->method.sendAlert((TLS_Ctx *)(uintptr_t)ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSECURE_VERSION);
        return HITLS_PACK_UNSECURE_VERSION;
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */
    ret = PackAppendUint16ToBuf(pkt, version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackAppendDataToBuf(pkt, isClient ? ctx->hsCtx->clientRandom : ctx->hsCtx->serverRandom, HS_RANDOM_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#if defined(HITLS_TLS_FEATURE_SESSION_ID) || defined(HITLS_TLS_PROTO_TLS13)
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    ret = PackSessionId(pkt, hsCtx->sessionId, hsCtx->sessionIdSize);
    if (ret != HITLS_SUCCESS) {
        (void)memset_s(hsCtx->sessionId, hsCtx->sessionIdSize, 0, hsCtx->sessionIdSize);
        return ret;
    }
#else // Session recovery is not supported.
    /* SessionId (Session is not supported yet and the length field is initialized with a value of 0) */
    ret = PackAppendUint8ToBuf(pkt, 0);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
    return HITLS_SUCCESS;
}

static int32_t PackMsBufferGrow(PackPacket *pkt, uint32_t newSize)
{
    uint32_t oldDataSize = *pkt->bufLen;

    uint8_t *newAddr = BSL_SAL_Realloc(*pkt->buf, newSize, oldDataSize);
    if (newAddr == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    *pkt->buf = newAddr;
    *pkt->bufLen = newSize;
    return HITLS_SUCCESS;
}

static int32_t PackMsBufferPrepare(PackPacket *pkt, uint32_t msgSize)
{
    if (*pkt->bufLen - *pkt->bufOffset >= msgSize) {
        return HITLS_SUCCESS;
    }

    if (HITLS_HS_BUFFER_SIZE_LIMIT - *pkt->bufOffset < msgSize) {
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    uint32_t oldBufSize = *pkt->bufLen;
    uint32_t newBufSize = (msgSize > oldBufSize) ? msgSize : oldBufSize;
    if (newBufSize >= HITLS_HS_BUFFER_SIZE_LIMIT / BUFFER_GROW_FACTOR) {
        newBufSize = HITLS_HS_BUFFER_SIZE_LIMIT;
    } else {
        newBufSize = newBufSize * BUFFER_GROW_FACTOR;
    }
    return PackMsBufferGrow(pkt, newBufSize);
}

int32_t PackAppendUint8ToBuf(PackPacket *pkt, uint8_t value)
{
    int32_t ret = PackMsBufferPrepare(pkt, sizeof(uint8_t));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (*pkt->buf)[*pkt->bufOffset] = value;
    *pkt->bufOffset += sizeof(uint8_t);
    return HITLS_SUCCESS;
}

int32_t PackAppendUint16ToBuf(PackPacket *pkt, uint16_t value)
{
    int32_t ret = PackMsBufferPrepare(pkt, sizeof(uint16_t));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_Uint16ToByte(value, &(*pkt->buf)[*pkt->bufOffset]);
    *pkt->bufOffset += sizeof(uint16_t);
    return HITLS_SUCCESS;
}

int32_t PackAppendUint24ToBuf(PackPacket *pkt, uint32_t value)
{
    int32_t ret = PackMsBufferPrepare(pkt, UINT24_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_Uint24ToByte(value, &(*pkt->buf)[*pkt->bufOffset]);
    *pkt->bufOffset += UINT24_SIZE;
    return HITLS_SUCCESS;
}

int32_t PackAppendUint32ToBuf(PackPacket *pkt, uint32_t value)
{
    int32_t ret = PackMsBufferPrepare(pkt, sizeof(uint32_t));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_Uint32ToByte(value, &(*pkt->buf)[*pkt->bufOffset]);
    *pkt->bufOffset += sizeof(uint32_t);
    return HITLS_SUCCESS;
}

int32_t PackAppendUint64ToBuf(PackPacket *pkt, uint64_t value)
{
    int32_t ret = PackMsBufferPrepare(pkt, sizeof(uint64_t));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_Uint64ToByte(value, &(*pkt->buf)[*pkt->bufOffset]);
    *pkt->bufOffset += sizeof(uint64_t);
    return HITLS_SUCCESS;
}

int32_t PackAppendDataToBuf(PackPacket *pkt, const uint8_t *data, uint32_t size)
{
    int32_t ret = PackMsBufferPrepare(pkt, size);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)memcpy_s(&(*pkt->buf)[*pkt->bufOffset], *pkt->bufLen - *pkt->bufOffset, data, size);
    *pkt->bufOffset += size;
    return HITLS_SUCCESS;
}

int32_t PackReserveBytes(PackPacket *pkt, uint32_t size, uint8_t **reservedBuf)
{
    int32_t ret = PackMsBufferPrepare(pkt, size);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (reservedBuf != NULL) {
        *reservedBuf = &(*pkt->buf)[*pkt->bufOffset];
    }
    return HITLS_SUCCESS;
}

int32_t PackStartLengthField(PackPacket *pkt, uint32_t size, uint32_t *allocatedPosition)
{
    int32_t ret = PackMsBufferPrepare(pkt, size);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    *allocatedPosition = *pkt->bufOffset;
    *pkt->bufOffset += size;
    return HITLS_SUCCESS;
}

int32_t PackSkipBytes(PackPacket *pkt, uint32_t size)
{
    if (*pkt->bufLen - *pkt->bufOffset < size) {
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    *pkt->bufOffset += size;
    return HITLS_SUCCESS;
}

void PackCloseUint8Field(const PackPacket *pkt, uint32_t position)
{
    (*pkt->buf)[position] = (uint8_t)(*pkt->bufOffset - position - sizeof(uint8_t));
}

void PackCloseUint16Field(const PackPacket *pkt, uint32_t position)
{
    BSL_Uint16ToByte((uint16_t)(*pkt->bufOffset - position - sizeof(uint16_t)), &(*pkt->buf)[position]);
}

void PackCloseUint24Field(const PackPacket *pkt, uint32_t position)
{
    BSL_Uint24ToByte((uint32_t)(*pkt->bufOffset - position - UINT24_SIZE), &(*pkt->buf)[position]);
}

int32_t PackGetSubBuffer(const PackPacket *pkt, uint32_t start, uint32_t *length, uint8_t **buf)
{
    if (length == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (start > *pkt->bufOffset) {
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    *length = *pkt->bufOffset - start;

    if (buf != NULL) {
        *buf = &(*pkt->buf)[start];
    }

    return HITLS_SUCCESS;
}