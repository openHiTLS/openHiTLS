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
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hitls.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack_common.h"
#include "pack.h"
#include "frame_msg.h"
#include "pack_frame_msg.h"

#define RECORD_BUF_LEN  (18 * 1024)
#define TEST_CERT_LEN_TAG_SIZE 3

TLS_Ctx *NewFrameTlsCtx(void)
{
    TLS_Ctx *tlsCtx = (TLS_Ctx *)BSL_SAL_Calloc(1u, sizeof(HITLS_Ctx));
    if (tlsCtx == NULL) {
        return NULL;
    }

    tlsCtx->hsCtx = (HS_Ctx *)BSL_SAL_Calloc(1u, sizeof(HS_Ctx));
    if (tlsCtx->hsCtx == NULL) {
        BSL_SAL_FREE(tlsCtx);
        return NULL;
    }
    tlsCtx->hsCtx->clientRandom = tlsCtx->negotiatedInfo.clientRandom;
    tlsCtx->hsCtx->serverRandom = tlsCtx->negotiatedInfo.serverRandom;
    return tlsCtx;
}

int32_t GenClientHelloMandatoryCtx(TLS_Ctx *tlsCtx, FRAME_Msg *msg)
{
    ClientHelloMsg *clientHello = &msg->body.handshakeMsg.body.clientHello;
    TLS_Config *tlsConfig = &tlsCtx->config.tlsConfig;
    tlsConfig->maxVersion = clientHello->version;
    int32_t ret = memcpy_s(tlsCtx->hsCtx->clientRandom, HS_RANDOM_SIZE, clientHello->randomValue, HS_RANDOM_SIZE);
    if (ret != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    if (clientHello->sessionIdSize > 0) {
#if defined(HITLS_TLS_FEATURE_SESSION) || defined(HITLS_TLS_PROTO_TLS13)
        tlsCtx->hsCtx->sessionId = (uint8_t *)BSL_SAL_Dump(clientHello->sessionId, clientHello->sessionIdSize);
        if (tlsCtx->hsCtx->sessionId == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        tlsCtx->hsCtx->sessionIdSize = clientHello->sessionIdSize;
#endif
    }

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(tlsConfig->originVersionMask) && clientHello->cookieLen > 0) {
        tlsCtx->negotiatedInfo.cookieSize = clientHello->cookieLen;
        tlsCtx->negotiatedInfo.cookie = (uint8_t *)BSL_SAL_Dump(clientHello->cookie, clientHello->cookieLen);
        if (tlsCtx->negotiatedInfo.cookie == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
    }
#endif

    tlsConfig->cipherSuitesSize = clientHello->cipherSuitesSize;
    uint32_t suitsLen = clientHello->cipherSuitesSize * sizeof(uint16_t);
    tlsConfig->cipherSuites = (uint16_t *)BSL_SAL_Dump(clientHello->cipherSuites, suitsLen);
    if (tlsConfig->cipherSuites == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}

int32_t GenClientHelloExtensionCtx(TLS_Ctx *tlsCtx, FRAME_Msg *msg)
{
    ClientHelloMsg *clientHello = &msg->body.handshakeMsg.body.clientHello;
    TLS_Config *tlsConfig = &tlsCtx->config.tlsConfig;
    tlsConfig->isSupportExtendedMasterSecret = clientHello->extension.flag.haveExtendedMasterSecret;
    tlsConfig->signAlgorithmsSize = clientHello->extension.content.signatureAlgorithmsSize;
    if (tlsConfig->signAlgorithmsSize > 0) {
        uint32_t signAlgorithmsLen = tlsConfig->signAlgorithmsSize * sizeof(uint16_t);
        tlsConfig->signAlgorithms = (uint16_t *)BSL_SAL_Dump(clientHello->extension.content.signatureAlgorithms,
            signAlgorithmsLen);
        if (tlsConfig->signAlgorithms == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
    }

    tlsConfig->groupsSize = clientHello->extension.content.supportedGroupsSize;
    if (tlsConfig->groupsSize > 0) {
        uint32_t groupsLen = tlsConfig->groupsSize * sizeof(uint16_t);
        tlsConfig->groups = (uint16_t *)BSL_SAL_Dump(clientHello->extension.content.supportedGroups, groupsLen);
        if (tlsConfig->groups == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
    }

    tlsConfig->pointFormatsSize = clientHello->extension.content.pointFormatsSize;
    if (tlsConfig->pointFormatsSize > 0) {
        uint32_t pointFormatsLen = tlsConfig->pointFormatsSize * sizeof(uint8_t);
        tlsConfig->pointFormats = (uint8_t *)BSL_SAL_Dump(clientHello->extension.content.pointFormats, pointFormatsLen);
        if (tlsConfig->pointFormats == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
    }

    return HITLS_SUCCESS;
}

int32_t PackClientHelloMsg(FRAME_Msg *msg)
{
    TLS_Ctx *tlsCtx = NewFrameTlsCtx();
    if (tlsCtx == NULL) {
        return HITLS_MEMCPY_FAIL;
    }

    int32_t ret = GenClientHelloMandatoryCtx(tlsCtx, msg);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    // extended information
    ret = GenClientHelloExtensionCtx(tlsCtx, msg);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    uint32_t usedLen = 0;
    ret = HS_PackMsg(tlsCtx, CLIENT_HELLO, &msg->buffer[msg->len], REC_MAX_PLAIN_LENGTH, &usedLen);
    if (ret == HITLS_SUCCESS) {
        msg->len += usedLen;
    }

EXIT:
    HITLS_Free(tlsCtx);
    return ret;
}

int32_t PackServerHelloMsg(FRAME_Msg *msg)
{
    TLS_Ctx *tlsCtx = NewFrameTlsCtx();
    if (tlsCtx == NULL) {
        return HITLS_MEMCPY_FAIL;
    }

    ServerHelloMsg *serverHello = &msg->body.handshakeMsg.body.serverHello;
    tlsCtx->negotiatedInfo.version = serverHello->version;

    int32_t ret = 0;
    ret = memcpy_s(tlsCtx->hsCtx->serverRandom, HS_RANDOM_SIZE, serverHello->randomValue, HS_RANDOM_SIZE);
    if (ret != EOK) {
        goto EXIT;
    }

    if (serverHello->sessionIdSize > 0) {    // SessionId
#if defined(HITLS_TLS_FEATURE_SESSION) || defined(HITLS_TLS_PROTO_TLS13)
        tlsCtx->hsCtx->sessionId = (uint8_t *)BSL_SAL_Dump(serverHello->sessionId, serverHello->sessionIdSize);
        if (tlsCtx->hsCtx->sessionId == NULL) {
            ret = HITLS_MEMALLOC_FAIL;
            goto EXIT;
        }
        tlsCtx->hsCtx->sessionIdSize = serverHello->sessionIdSize;
#endif
    }

    tlsCtx->negotiatedInfo.cipherSuiteInfo.cipherSuite = serverHello->cipherSuite;
    tlsCtx->negotiatedInfo.isExtendedMasterSecret = serverHello->haveExtendedMasterSecret;

    uint32_t usedLen = 0;
    ret = HS_PackMsg(tlsCtx, SERVER_HELLO, &msg->buffer[msg->len], REC_MAX_PLAIN_LENGTH, &usedLen);
    if (ret == HITLS_SUCCESS) {
        msg->len += usedLen;
    }

EXIT:
    HITLS_Free(tlsCtx);
    return ret;
}

int32_t PackCertificateMsg(FRAME_Msg *msg)
{
    CertificateMsg *certificate = &msg->body.handshakeMsg.body.certificate;
    uint32_t allCertsLen = 0;                               // Total length of all certificates
    uint32_t offset = msg->len + DTLS_HS_MSG_HEADER_SIZE;   // Reserved packet header
    // Indicates the offset of the total length of the certificate chain.
    uint32_t certsLenOffset = offset;                       
    offset += TEST_CERT_LEN_TAG_SIZE;                       // Total length of the reserved certificate chain

    CERT_Item *cur = certificate->cert;
    while (cur != NULL) {
        BSL_Uint24ToByte(cur->dataSize, &msg->buffer[offset]);
        offset += TEST_CERT_LEN_TAG_SIZE;
        int32_t ret = memcpy_s(&msg->buffer[offset], RECORD_BUF_LEN - offset, cur->data, cur->dataSize);
        if (ret != EOK) {
            return HITLS_MEMCPY_FAIL;
        }

        offset += cur->dataSize;
        allCertsLen += TEST_CERT_LEN_TAG_SIZE + cur->dataSize;
        cur = cur->next;
    }
    // Indicates the total length of the certificate chain.
    BSL_Uint24ToByte(allCertsLen, &msg->buffer[certsLenOffset]);

    /* Assemble the packet header. */
    const uint32_t sequence = 1;
    const uint32_t bodyLen = TEST_CERT_LEN_TAG_SIZE + allCertsLen;
    PackDtlsMsgHeader(CERTIFICATE, sequence, bodyLen, &msg->buffer[msg->len]);
    msg->len += DTLS_HS_MSG_HEADER_SIZE + bodyLen;

    return HITLS_SUCCESS;
}

int32_t PackServerKxMsg(FRAME_Msg *msg)
{
    ServerKeyExchangeMsg *serverKx = &msg->body.handshakeMsg.body.serverKeyExchange;
    uint32_t offset = msg->len + DTLS_HS_MSG_HEADER_SIZE;   // Reserved packet header

    /* Curve Type and Curve ID */
    msg->buffer[offset] = (uint8_t)(serverKx->keyEx.ecdh.ecPara.type);
    offset += sizeof(uint8_t);
    BSL_Uint16ToByte((uint16_t)(serverKx->keyEx.ecdh.ecPara.param.namedcurve), &msg->buffer[offset]);
    offset += sizeof(uint16_t);

    /* Public key length and public key content */
    msg->buffer[offset] = (uint8_t)serverKx->keyEx.ecdh.pubKeySize;
    offset += sizeof(uint8_t);
    int32_t ret = memcpy_s(&msg->buffer[offset], RECORD_BUF_LEN - offset,
        serverKx->keyEx.ecdh.pubKey, serverKx->keyEx.ecdh.pubKeySize);
    if (ret != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += serverKx->keyEx.ecdh.pubKeySize;

    /* signature algorithm */
    BSL_Uint16ToByte(serverKx->keyEx.ecdh.signAlgorithm, &msg->buffer[offset]);
    offset += sizeof(uint16_t);

    /* Signature Length */
    BSL_Uint16ToByte(serverKx->keyEx.ecdh.signSize, &msg->buffer[offset]);
    offset += sizeof(uint16_t);

    ret = memcpy_s(&msg->buffer[offset], RECORD_BUF_LEN - offset,
        serverKx->keyEx.ecdh.signData, serverKx->keyEx.ecdh.signSize);
    if (ret != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += serverKx->keyEx.ecdh.signSize;

    /* Assemble the packet header. */
    const uint32_t sequence = msg->body.handshakeMsg.sequence;
    const uint32_t bodyLen = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + serverKx->keyEx.ecdh.pubKeySize +
        sizeof(uint16_t) + sizeof(uint16_t) + serverKx->keyEx.ecdh.signSize;
    PackDtlsMsgHeader(SERVER_KEY_EXCHANGE, sequence, bodyLen, &msg->buffer[msg->len]);
    msg->len += DTLS_HS_MSG_HEADER_SIZE + bodyLen;

    return HITLS_SUCCESS;
}

int32_t PackServerHelloDoneMsg(FRAME_Msg *msg)
{
    /* Assemble the packet header. */
    const uint32_t sequence = msg->body.handshakeMsg.sequence;
    const uint32_t bodyLen = 0;
    PackDtlsMsgHeader(SERVER_HELLO_DONE, sequence, bodyLen, &msg->buffer[msg->len]);
    msg->len += DTLS_HS_MSG_HEADER_SIZE + bodyLen;

    return HITLS_SUCCESS;
}

int32_t PackClientKxMsg(FRAME_Msg *msg)
{
    ClientKeyExchangeMsg *clientKx = &msg->body.handshakeMsg.body.clientKeyExchange;
    uint32_t offset = msg->len + DTLS_HS_MSG_HEADER_SIZE;   // Reserved packet header
    msg->buffer[offset] = (uint8_t)clientKx->dataSize;
    offset += sizeof(uint8_t);
    int32_t ret = memcpy_s(&msg->buffer[offset], RECORD_BUF_LEN - offset, clientKx->data, clientKx->dataSize);
    if (ret != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    /* Assemble the packet header. */
    const uint32_t sequence = msg->body.handshakeMsg.sequence;
    const uint32_t bodyLen = clientKx->dataSize + sizeof(uint8_t);
    PackDtlsMsgHeader(CLIENT_KEY_EXCHANGE, sequence, bodyLen, &msg->buffer[msg->len]);
    msg->len += DTLS_HS_MSG_HEADER_SIZE + bodyLen;

    return HITLS_SUCCESS;
}

int32_t PackFinishMsg(FRAME_Msg *msg)
{
    TLS_Ctx *tlsCtx = NewFrameTlsCtx();
    if (tlsCtx == NULL) {
        return HITLS_MEMCPY_FAIL;
    }

    FinishedMsg *finished = &msg->body.handshakeMsg.body.finished;
    int32_t ret = 0;
    tlsCtx->hsCtx->verifyCtx = (VerifyCtx*)BSL_SAL_Calloc(1u, sizeof(VerifyCtx));
    if (tlsCtx->hsCtx->verifyCtx == NULL) {
        ret = HITLS_MEMALLOC_FAIL;
        goto EXIT;
    }

    tlsCtx->hsCtx->verifyCtx->verifyDataSize = finished->verifyDataSize;
    ret = memcpy_s(tlsCtx->hsCtx->verifyCtx->verifyData, MAX_SIGN_SIZE,
        finished->verifyData, finished->verifyDataSize);
    if (ret != EOK) {
        goto EXIT;
    }

    uint32_t usedLen = 0;
    ret = HS_PackMsg(tlsCtx, FINISHED, &msg->buffer[msg->len], REC_MAX_PLAIN_LENGTH, &usedLen);
    if (ret == HITLS_SUCCESS) {
        msg->len += usedLen;
    }

EXIT:
    HITLS_Free(tlsCtx);
    return ret;
}

int32_t PackHandShakeMsg(FRAME_Msg *msg)
{
    HS_MsgType type = msg->body.handshakeMsg.type;
    uint32_t ret = HITLS_SUCCESS;
    switch (type) {
        case CLIENT_HELLO:
            ret = PackClientHelloMsg(msg);
            break;
        case SERVER_HELLO:
            ret = PackServerHelloMsg(msg);
            break;
        case CERTIFICATE:
            ret = PackCertificateMsg(msg);
            break;
        case SERVER_KEY_EXCHANGE:
            ret = PackServerKxMsg(msg);
            break;
        case SERVER_HELLO_DONE:
            ret = PackServerHelloDoneMsg(msg);
            break;
        case CLIENT_KEY_EXCHANGE:
            ret = PackClientKxMsg(msg);
            break;
        case FINISHED:
            ret = PackFinishMsg(msg);
            break;
        default:
            ret = HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG;
    }

    return ret;
}

int32_t PackCCSMsg(FRAME_Msg *msg)
{
    FRAME_CcsMsg *ccsMsg = &msg->body.ccsMsg;
    uint32_t offset = msg->len;
    msg->buffer[offset] = ccsMsg->type;
    msg->len += sizeof(uint8_t);

    return HITLS_SUCCESS;
}

int32_t PackAlertMsg(FRAME_Msg *msg)
{
    FRAME_AlertMsg *alertMsg = &msg->body.alertMsg;
    uint32_t offset = msg->len;
    msg->buffer[offset] = alertMsg->level;
    offset += sizeof(uint8_t);
    msg->buffer[offset] = alertMsg->description;
    msg->len += sizeof(uint8_t) + sizeof(uint8_t);
    return HITLS_SUCCESS;
}

int32_t PackAppData(FRAME_Msg *msg)
{
    FRAME_AppMsg *appMsg = &msg->body.appMsg;
    uint32_t offset = msg->len;
    BSL_Uint32ToByte(appMsg->len, &msg->buffer[offset]);
    offset += sizeof(uint32_t);
    int32_t ret = memcpy_s(&msg->buffer[offset], RECORD_BUF_LEN - offset, appMsg->buffer, appMsg->len);
    if (ret != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    msg->len += sizeof(uint32_t) + appMsg->len;
    return HITLS_SUCCESS;
}

// Pack header
int32_t PackRecordHeader(FRAME_Msg *msg)
{
    uint32_t offset = 0;
    msg->buffer[offset] = msg->type;
    offset += sizeof(uint8_t);
    BSL_Uint16ToByte(msg->version, &msg->buffer[offset]);
    offset += sizeof(uint16_t);

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_TRANSTYPE_DATAGRAM(msg->transportType)) {
        BSL_Uint64ToByte(msg->epochSeq, &msg->buffer[offset]);
        offset += sizeof(uint64_t);
    }
#endif

    BSL_Uint16ToByte(msg->bodyLen, &msg->buffer[offset]);
    offset += sizeof(uint16_t);
    msg->len = offset;
    return HITLS_SUCCESS;
}

int32_t PackFrameMsg(FRAME_Msg *msg)
{
    // Apply for an 18 KB buffer for storing the current message.
    msg->buffer = (uint8_t *)BSL_SAL_Calloc(1u, RECORD_BUF_LEN);
    if (msg->buffer == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    msg->len = RECORD_BUF_LEN;  // The length must be the same as the length of the applied 18 KB buffer.

    // pack Header
    PackRecordHeader(msg);

    // pack Body
    uint32_t ret = HITLS_SUCCESS;
    switch (msg->type) {
        case REC_TYPE_HANDSHAKE:
            ret = PackHandShakeMsg(msg);
            break;
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            ret = PackCCSMsg(msg);
            break;
        case REC_TYPE_ALERT:
            ret = PackAlertMsg(msg);
            break;
        case REC_TYPE_APP:
            ret = PackAppData(msg);
            break;
        default:
            break;
    }

    return ret;
}