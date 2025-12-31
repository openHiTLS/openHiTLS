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
#include "bsl_module_list.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "rec.h"
#include "rec_unprocessed_msg.h"

#ifdef HITLS_BSL_UIO_UDP
void CacheNextEpochHsMsg(UnprocessedHsMsg *unprocessedHsMsg, const RecHdr *hdr, const uint8_t *recordBody)
{
    /* only out-of-order finished messages need to be cached */
    if (hdr->type != REC_TYPE_HANDSHAKE) {
        return;
    }

    /* only cache one */
    if (unprocessedHsMsg->recordBody != NULL) {
        return;
    }

    unprocessedHsMsg->recordBody = (uint8_t *)BSL_SAL_Dump(recordBody, hdr->bodyLen);
    if (unprocessedHsMsg->recordBody == NULL) {
        return;
    }

    (void)memcpy_s(&unprocessedHsMsg->hdr, sizeof(RecHdr), hdr, sizeof(RecHdr));
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15446, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "cache next epoch hs msg", 0, 0, 0, 0);
}
#endif /* HITLS_BSL_UIO_UDP */

UnprocessedAppMsg *UnprocessedAppMsgNew(void)
{
    UnprocessedAppMsg *msg = (UnprocessedAppMsg *)BSL_SAL_Calloc(1, sizeof(UnprocessedAppMsg));
    if (msg == NULL) {
        return NULL;
    }

    LIST_INIT(&msg->head);
    return msg;
}

void UnprocessedAppMsgFree(UnprocessedAppMsg *msg)
{
    if (msg != NULL) {
        BSL_SAL_FREE(msg->recordBody);
        BSL_SAL_FREE(msg);
    }
}

void UnprocessedAppMsgListInit(UnprocessedAppMsg *appMsgList)
{
    if (appMsgList == NULL) {
        return;
    }
    appMsgList->count = 0;
    appMsgList->recordBody = NULL;
    LIST_INIT(&appMsgList->head);
}

void UnprocessedAppMsgListDeinit(UnprocessedAppMsg *appMsgList)
{
    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    UnprocessedAppMsg *cur = NULL;

    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(appMsgList->head)) {
        cur = LIST_ENTRY(node, UnprocessedAppMsg, head);
        LIST_REMOVE(node);
        /* releasing nodes and deleting user data */
        UnprocessedAppMsgFree(cur);
    }
    appMsgList->count = 0;
}

int32_t UnprocessedAppMsgListAppend(UnprocessedAppMsg *appMsgList, const RecHdr *hdr, const uint8_t *recordBody)
{
    /* prevent oversize */
    if (appMsgList->count >= UNPROCESSED_APP_MSG_COUNT_MAX) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }

    UnprocessedAppMsg *appNode = UnprocessedAppMsgNew();
    if (appNode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15805, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Buffer app record: Malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    appNode->recordBody = (uint8_t*)BSL_SAL_Dump(recordBody, hdr->bodyLen);
    if (appNode->recordBody == NULL) {
        UnprocessedAppMsgFree(appNode);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15806, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Buffer app record: Malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(&appNode->hdr, sizeof(RecHdr), hdr, sizeof(RecHdr));

    LIST_ADD_BEFORE(&appMsgList->head, &appNode->head);

    appMsgList->count++;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15807, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Buffer app record: count is %u.", appMsgList->count, 0, 0, 0);
    return HITLS_SUCCESS;
}

UnprocessedAppMsg *UnprocessedAppMsgGet(UnprocessedAppMsg *appMsgList, uint16_t curEpoch)
{
    ListHead *next = appMsgList->head.next;
    if (next == &appMsgList->head) {
        return NULL;
    }

    ListHead *node = NULL;
    ListHead *tmpNode = NULL;
    UnprocessedAppMsg *cur = NULL;
    LIST_FOR_EACH_ITEM_SAFE(node, tmpNode, &(appMsgList->head)) {
        cur = LIST_ENTRY(node, UnprocessedAppMsg, head);
        uint16_t epoch = REC_EPOCH_GET(cur->hdr.epochSeq);
        if (curEpoch == epoch) {
            /* remove a node and release it by the outside */
            LIST_REMOVE(node);
            appMsgList->count--;
            return cur;
        }
    }
    return NULL;
}

#endif /* HITLS_TLS_PROTO_DTLS12 */
