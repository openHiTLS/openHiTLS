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
#if defined(HITLS_TLS_PROTO_DATAGRAM)
#include <string.h>
#include "bsl_module_list.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "rec.h"
#include "rec_unprocessed_msg.h"

UnprocessedMsg *UnprocessedMsgNew(void)
{
    UnprocessedMsg *msg = (UnprocessedMsg *)BSL_SAL_Calloc(1, sizeof(UnprocessedMsg));
    if (msg == NULL) {
        return NULL;
    }

    BSL_LIST_INIT(&msg->head);
    return msg;
}

void UnprocessedMsgFree(UnprocessedMsg *msg)
{
    if (msg != NULL) {
        BSL_SAL_FREE(msg->recordBody);
        BSL_SAL_Free(msg);
    }
}

void UnprocessedMsgListInit(UnprocessedMsg *appMsgList)
{
    if (appMsgList == NULL) {
        return;
    }
    appMsgList->count = 0;
    appMsgList->recordBody = NULL;
    BSL_LIST_INIT(&appMsgList->head);
}

void UnprocessedMsgListDeinit(UnprocessedMsg *appMsgList)
{
    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    UnprocessedMsg *cur = NULL;

    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(appMsgList->head)) {
        cur = BSL_LIST_ENTRY(node, UnprocessedMsg, head);
        BSL_LIST_REMOVE(node);
        /* releasing nodes and deleting user data */
        UnprocessedMsgFree(cur);
    }
    appMsgList->count = 0;
}

int32_t UnprocessedMsgListAppend(UnprocessedMsg *appMsgList, const RecHdr *hdr, const uint8_t *recordBody)
{
    /* prevent oversize */
    if (appMsgList->count >= UNPROCESSED_APP_MSG_COUNT_MAX) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }

    UnprocessedMsg *appNode = UnprocessedMsgNew();
    if (appNode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15805, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Buffer app record: Malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    appNode->recordBody = (uint8_t*)BSL_SAL_Dump(recordBody, hdr->bodyLen);
    if (appNode->recordBody == NULL) {
        UnprocessedMsgFree(appNode);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15806, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Buffer app record: Malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    memcpy(&appNode->hdr, hdr, sizeof(RecHdr));

    LIST_ADD_BEFORE(&appMsgList->head, &appNode->head);

    appMsgList->count++;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15807, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Buffer app record: count is %u.", appMsgList->count, 0, 0, 0);
    return HITLS_SUCCESS;
}

/*
 * Check whether a cached record can be consumed by the current read path.
 *
 * A DTLS 1.3 unified-header record is cached as REC_TYPE_UNKNOWN because its
 * real content type is carried in the encrypted DTLSInnerPlaintext and is not
 * available until decryption.
 *
 * When the handshake path expects a HANDSHAKE record, only APP records are
 * deferred until Finished; all other records, including DTLS 1.3 UNKNOWN
 * records and ALERT records, must be returned for decryption and dispatch.
 * When the application path expects an APP record, every cached record can be
 * returned so that ALERT, post-handshake HANDSHAKE, and APP records are
 * dispatched by the common record processing path.
 */
static bool CanReadUnprocessedMsg(uint8_t expectedType, uint8_t actualType)
{
    return expectedType == REC_TYPE_UNKNOWN || actualType != REC_TYPE_APP || expectedType != REC_TYPE_HANDSHAKE;
}

/* Remove the first cached record matching the current epoch and read path. */
UnprocessedMsg *UnprocessedMsgGet(UnprocessedMsg *appMsgList, uint16_t curEpoch, uint8_t recordType)
{
    ListHead *next = appMsgList->head.next;
    if (next == &appMsgList->head) {
        return NULL;
    }

    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    UnprocessedMsg *cur = NULL;
    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(appMsgList->head)) {
        cur = BSL_LIST_ENTRY(node, UnprocessedMsg, head);
        uint16_t epoch = REC_EPOCH_GET(cur->hdr.epochSeq);
        if (curEpoch == epoch && CanReadUnprocessedMsg(recordType, cur->hdr.type)) {
            /* remove a node and release it by the outside */
            BSL_LIST_REMOVE(node);
            appMsgList->count--;
            return cur;
        }
    }
    return NULL;
}

#endif /* HITLS_TLS_PROTO_DATAGRAM */
