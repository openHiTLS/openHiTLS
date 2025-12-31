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
#ifdef HITLS_TLS_PROTO_DTLS12
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_module_list.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hs_common.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_reass.h"

#define MAX_NUM_EXCEED_EXPECT 10

static const uint8_t g_startMaskMap[] = { 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80 };
static const uint8_t g_endMaskMap[] = { 0x1, 0x3, 0x7, 0xF, 0x1F, 0x3F, 0x7F, 0xFF };

static void SetReassBitMap(uint8_t *reassBitMap, uint32_t fragmentOffset, uint32_t fragmentLength)
{
    /* start indicates the first digit of the flag to be set, and end indicates the last digit of the flag to be set */
    uint32_t start = fragmentOffset;
    uint32_t end = fragmentOffset + fragmentLength - 1;
    /* When the length is less than 8, the bitmap is set by bit. When the length is greater than or equal to 8, the
     * bitmap is set in three steps */
    if (end - start < 8) {
        for (uint32_t i = start; i <= end; i++) {
            /** >>3 indicates divided by 8, & 7 is the remainder 8 */
            reassBitMap[(i) >> 3] |= 1 << (i & 7);
        }
    } else {
        uint32_t startOffset = start >> 3; /* bitmap to be set, >> 3 indicates the division by 8 */
        uint32_t endOffset = end >> 3;     /* last byte of the bitmap to be set, >> 3 is divided by 8 */
        /* Assign the first byte, &7 indicates the remainder 8 */
        reassBitMap[startOffset] |= g_startMaskMap[start & 7];
        /* Assign a value to the middle byte */
        uint32_t copyLen = endOffset - startOffset - 1;
        (void)memset_s(&reassBitMap[startOffset + 1], copyLen, 0xFF, copyLen);
        /* Assign the last byte, &7 indicates the remainder 8 */
        reassBitMap[endOffset] |= g_endMaskMap[end & 7];
    }
}

static bool IsReassComplete(const uint8_t *reassBitMap, uint32_t msgLen)
{
    uint32_t i;
    /* bit map from 0 to (msgLen-1) */
    uint32_t maxIndex = msgLen - 1;
    /* Check the last byte, >> 3 indicates the division by 8, and &7 indicates the remainder by 8 */
    if (reassBitMap[maxIndex >> 3] != g_endMaskMap[maxIndex & 7]) {
        return false;
    }
    /* Check the 0th byte to the last 2nd byte, >> 3 is divided by 8 */
    for (i = 0; i < (maxIndex >> 3); i++) {
        if (reassBitMap[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

HS_ReassQueue *HS_ReassNew(void)
{
    HS_ReassQueue *reassQueue = (HS_ReassQueue *)BSL_SAL_Calloc(1u, sizeof(HS_ReassQueue));
    if (reassQueue == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15751, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "reassQueue malloc fail when new a reassQueue.", 0, 0, 0, 0);
        return NULL;
    }
    LIST_INIT(&reassQueue->head);
    return reassQueue;
}

void HS_ReassFree(HS_ReassQueue *reassQueue)
{
    if (reassQueue == NULL) {
        return;
    }

    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    HS_ReassQueue *cur = NULL;
    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(reassQueue->head))
    {
        cur = LIST_ENTRY(node, HS_ReassQueue, head);
        LIST_REMOVE(&cur->head);        /* Delete the node from the queue. */
        BSL_SAL_FREE(cur->reassBitMap); /* Release node content. */
        BSL_SAL_FREE(cur->msg);         /* Release node content. */
        BSL_SAL_FREE(cur);              /* Release the node. */
    }
    BSL_SAL_FREE(reassQueue);
}

static HS_ReassQueue *GetReassNode(HS_ReassQueue *reassQueue, uint16_t sequence)
{
    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    HS_ReassQueue *cur = NULL;

    /* Find the node with the corresponding sequence number in the reassembly queue */
    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(reassQueue->head)) {
        cur = LIST_ENTRY(node, HS_ReassQueue, head);
        if (cur->sequence == sequence) {
            return cur;
        }
    }
    return NULL;
}

static HS_ReassQueue *ReassNodeNew(HS_ReassQueue *reassQueue, HS_MsgInfo *msgInfo)
{
    HS_ReassQueue *node = (HS_ReassQueue *)BSL_SAL_Calloc(1u, sizeof(HS_ReassQueue));
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15752, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "node malloc fail when inser a msg to reassQueue.", 0, 0, 0, 0);
        return NULL;
    }
    LIST_INIT(&node->head);

    if (msgInfo->length != 0) {
        /* 8 is the number of bits of one byte. The addition of 7 is used to supplement the number of bits. Ensure that
         * the correct allocated bytes are obtained after each number is divided by 8. */
        uint32_t bitMapSize = (msgInfo->length + 7) / 8;
        node->reassBitMap = BSL_SAL_Calloc(1u, bitMapSize);
        if (node->reassBitMap == NULL) {
            BSL_SAL_FREE(node);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15753, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "bitMap malloc fail when inser a msg to reassQueue.", 0, 0, 0, 0);
            return NULL;
        }
    }

    /* Apply for the space that can be used to cache the entire message */
    uint32_t msgLen = DTLS_HS_MSG_HEADER_SIZE + msgInfo->length;
    node->msg = BSL_SAL_Calloc(1u, msgLen);
    if (node->msg == NULL) {
        BSL_SAL_FREE(node->reassBitMap);
        BSL_SAL_FREE(node);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15754, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "msg malloc fail when inser a msg to reassQueue.", 0, 0, 0, 0);
        return NULL;
    }

    node->type = msgInfo->type;
    node->sequence = msgInfo->sequence;
    node->isReassComplete = false;
    node->msgLen = msgLen;

    /* Insert a new node */
    LIST_ADD_BEFORE(&reassQueue->head, &node->head);
    return node;
}

static int32_t ReassembleMsg(TLS_Ctx *ctx, HS_MsgInfo *msgInfo, HS_ReassQueue *node)
{
    /* Check message */
    uint32_t bufOffset = DTLS_HS_MSG_HEADER_SIZE + msgInfo->fragmentOffset;
    if ((node->msgLen < bufOffset) ||
        (node->type != msgInfo->type) ||
        ((node->msgLen - DTLS_HS_MSG_HEADER_SIZE) != msgInfo->length)) {
        BSL_ERR_PUSH_ERROR(HITLS_REASS_INVALID_FRAGMENT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15755, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "reassemble message fail, fragmentOffset %u; msgType %u, expect %u; msgLen %u",
            msgInfo->fragmentOffset, msgInfo->type, node->type, msgInfo->length);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15759, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "expect %u", node->msgLen - DTLS_HS_MSG_HEADER_SIZE, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_REASS_INVALID_FRAGMENT;
    }

    /* Copy the message header */
    if (msgInfo->fragmentOffset == 0u) {
        if (memcpy_s(&node->msg[0], node->msgLen, &msgInfo->rawMsg[0], DTLS_HS_MSG_HEADER_SIZE) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15756, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "msg header copy fail when append to reassQueue.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return HITLS_MEMCPY_FAIL;
        }
    }

    if (node->msgLen == DTLS_HS_MSG_HEADER_SIZE) {
        /* The message is empty and does not need to be reassembled */
        node->isReassComplete = true;
        return HITLS_SUCCESS;
    }

    /* Message reassembly */
    if (memcpy_s(&node->msg[bufOffset], node->msgLen - bufOffset,
                 &msgInfo->rawMsg[DTLS_HS_MSG_HEADER_SIZE], msgInfo->fragmentLength) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15757, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "msg copy fail when append to reassQueue.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMCPY_FAIL;
    }

    /* Set the bitmap and check whether the bitmap is complete */
    SetReassBitMap(node->reassBitMap, msgInfo->fragmentOffset, msgInfo->fragmentLength);
    if (IsReassComplete(node->reassBitMap, node->msgLen - DTLS_HS_MSG_HEADER_SIZE)) {
        /* Bitmap complete, updated fragment length */
        BSL_Uint24ToByte(msgInfo->length, &node->msg[DTLS_HS_FRAGMENT_LEN_ADDR]);
        node->isReassComplete = true;
    }

    return HITLS_SUCCESS;
}

int32_t HS_ReassAppend(TLS_Ctx *ctx, HS_MsgInfo *msgInfo)
{
    /* If the number of a message exceeds the expected number, discard the message to prevent unlimited memory
     * application */
    if (msgInfo->sequence > ctx->hsCtx->expectRecvSeq + MAX_NUM_EXCEED_EXPECT) {
        return HITLS_SUCCESS;
    }

    HS_ReassQueue *reassQueue = ctx->hsCtx->reassMsg;
    /* Check whether there are messages in the reassembly queue */
    HS_ReassQueue *node = GetReassNode(reassQueue, msgInfo->sequence);
    if (node == NULL) {
        /* If no message has the corresponding sequence number, create a new queue node to buffer the message */
        node = ReassNodeNew(reassQueue, msgInfo);
        if (node == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17027, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ReassNodeNew fail", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    return ReassembleMsg(ctx, msgInfo, node);
}

int32_t HS_GetReassMsg(TLS_Ctx *ctx, HS_MsgInfo *msgInfo, uint32_t *len)
{
    /* Check whether there are messages in the reassembly queue */
    HS_ReassQueue *node = GetReassNode(ctx->hsCtx->reassMsg, ctx->hsCtx->expectRecvSeq);
    if (node == NULL) {
        *len = 0;
        return HITLS_SUCCESS;
    }

    /* If a message exists, check whether the message is complete. If the message is incomplete, return the message and
     * continue to read the message from the record layer */
    if (!node->isReassComplete) {
        *len = 0;
        return HITLS_SUCCESS;
    }

    /* If the message is a complete message, copy the message */
    msgInfo->type = node->type;
    msgInfo->length = node->msgLen - DTLS_HS_MSG_HEADER_SIZE;
    msgInfo->sequence = node->sequence;
    msgInfo->fragmentOffset = 0u;
    msgInfo->fragmentLength = node->msgLen - DTLS_HS_MSG_HEADER_SIZE;
    int32_t ret = HS_ReSizeMsgBuf(ctx, node->msgLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (memcpy_s(ctx->hsCtx->msgBuf, ctx->hsCtx->bufferLen, node->msg, node->msgLen) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15758, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "msg copy fail when get a msg from reassQueue.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMCPY_FAIL;
    }
    msgInfo->rawMsg = ctx->hsCtx->msgBuf;
    *len = node->msgLen;             /* Set the message length. */
    LIST_REMOVE(&node->head);        /* Delete the node from the queue. */
    BSL_SAL_FREE(node->reassBitMap); /* Release node content. */
    BSL_SAL_FREE(node->msg);         /* Release node content. */
    BSL_SAL_FREE(node);              /* Release the node. */

    return HITLS_SUCCESS;
}

#endif /* end #ifdef HITLS_TLS_PROTO_DTLS12 */
