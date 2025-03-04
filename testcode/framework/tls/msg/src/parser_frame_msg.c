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
#include "tls.h"
#include "conn_init.h"
#include "hs_ctx.h"
#include "parse.h"
#include "conn_init.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "parser_frame_msg.h"

void SendAlertStake(const TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    (void)ctx;
    (void)level;
    (void)description;
    return;
}

int32_t ParserRecordHeader(FRAME_Msg *frameMsg, const uint8_t *buffer, uint32_t len, uint32_t *parserLen)
{
    (void)len;
    uint32_t bufOffset = 0;

    frameMsg->type = buffer[bufOffset];
    bufOffset += sizeof(uint8_t);

    frameMsg->version = BSL_ByteToUint16(&buffer[bufOffset]);
    bufOffset += sizeof(uint16_t);

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_TRANSTYPE_DATAGRAM(frameMsg->transportType)) {
        frameMsg->epochSeq = BSL_ByteToUint64(&buffer[bufOffset]);
        bufOffset += sizeof(uint64_t);
    }
#endif

    frameMsg->bodyLen = BSL_ByteToUint16(&buffer[bufOffset]);
    bufOffset += sizeof(uint16_t);
    *parserLen = bufOffset;

    return HITLS_SUCCESS;
}

int32_t ParserHandShakeMsg(const FRAME_LinkObj *linkObj, FRAME_Msg *frameMsg,
    const uint8_t *buffer, uint32_t len, uint32_t *parserLen)
{
    int32_t ret;
    HS_MsgInfo hsMsgInfo = {0};
    HITLS_Ctx *sslCtx = FRAME_GetTlsCtx(linkObj);

    SendAlertCallback tmpAlertCallback = sslCtx->method.sendAlert;
    sslCtx->method.sendAlert = SendAlertStake;
    CONN_Init(sslCtx);
    ret = HS_ParseMsgHeader(sslCtx, buffer, len, &hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        sslCtx->method.sendAlert = tmpAlertCallback;
        return ret;
    }
    hsMsgInfo.rawMsg = buffer;
    ret = HS_ParseMsg(sslCtx, &hsMsgInfo, &frameMsg->body.handshakeMsg);
    if (ret != HITLS_SUCCESS) {
        sslCtx->method.sendAlert = tmpAlertCallback;
        return ret;
    }

    sslCtx->method.sendAlert = tmpAlertCallback;
    *parserLen += hsMsgInfo.length;
    return HITLS_SUCCESS;
}

int32_t ParserCCSMsg(FRAME_Msg *frameMsg, const uint8_t *buffer, uint32_t len, uint32_t *parserLen)
{
    (void)len;
    frameMsg->body.ccsMsg.type = buffer[0];
    *parserLen += sizeof(uint8_t);
    return HITLS_SUCCESS;
}

int32_t ParserAlertMsg(FRAME_Msg *frameMsg, const uint8_t *buffer, uint32_t len, uint32_t *parserLen)
{
    (void)len;
    uint32_t bufOffset = 0;
    frameMsg->body.alertMsg.level = buffer[bufOffset];
    bufOffset += sizeof(uint8_t);
    frameMsg->body.alertMsg.description = buffer[bufOffset];
    bufOffset += sizeof(uint8_t);
    *parserLen += bufOffset;
    return HITLS_SUCCESS;
}

int32_t ParserAppMsg(FRAME_Msg *frameMsg, const uint8_t *buffer, uint32_t len, uint32_t *parserLen)
{
    (void)len;
    uint32_t bufOffset = 0;
    uint32_t userDataLen = BSL_ByteToUint32(&buffer[bufOffset]);
    frameMsg->body.appMsg.len = userDataLen;
    bufOffset += sizeof(uint32_t);
    BSL_SAL_FREE(frameMsg->body.appMsg.buffer);
    frameMsg->body.appMsg.buffer = BSL_SAL_Dump(&buffer[bufOffset], userDataLen);
    if (frameMsg->body.appMsg.buffer == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    bufOffset += userDataLen;
    *parserLen += bufOffset;

    return HITLS_SUCCESS;
}

int32_t ParserRecordBody(const FRAME_LinkObj *linkObj, FRAME_Msg *frameMsg,
    const uint8_t *buffer, uint32_t len, uint32_t *parserLen)
{
    switch (frameMsg->type) {
        case REC_TYPE_HANDSHAKE:
            return ParserHandShakeMsg(linkObj, frameMsg, buffer, len, parserLen);
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            return ParserCCSMsg(frameMsg, buffer, len, parserLen);
        case REC_TYPE_ALERT:
            return ParserAlertMsg(frameMsg, buffer, len, parserLen);
        case REC_TYPE_APP:
            return ParserAppMsg(frameMsg, buffer, len, parserLen);
        default:
            break;
    }

    return HITLS_SUCCESS;
}

int32_t ParserTotalRecord(const FRAME_LinkObj *linkObj, FRAME_Msg *frameMsg,
    const uint8_t *buffer, uint32_t len, uint32_t *parserLen)
{
    int32_t ret = ParserRecordHeader(frameMsg, buffer, len, parserLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ParserRecordBody(linkObj, frameMsg, &buffer[*parserLen], len - *parserLen, parserLen);
}

void CleanRecordBody(FRAME_Msg *frameMsg)
{
    if (frameMsg->type == REC_TYPE_HANDSHAKE) {
        HS_CleanMsg(&frameMsg->body.handshakeMsg);
    } else if (frameMsg->type == REC_TYPE_APP) {
        BSL_SAL_FREE(frameMsg->body.appMsg.buffer);
    }
    BSL_SAL_FREE(frameMsg->buffer);
}
