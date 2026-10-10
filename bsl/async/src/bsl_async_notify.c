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

#ifdef HITLS_BSL_ASYNC

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "bsl_err_internal.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_async.h"
#include "bsl_async_internal.h"

/*
 * Notify context: lifecycle, callback, submit status and the
 * notify source registration with its three-state machine and change window. The framework never interprets, waits
 * on or
 * closes a handle: ownership stays with the crypto implementation, whose
 * cleanup callback runs exactly once per reclaimed node.
 *
 * Registration: every SetNotifySource call appends a new PENDING_ADD node
 * at the list head without consulting existing nodes, so duplicate
 * registrations under one key coexist and the newest node wins every key
 * lookup; the crypto implementation is expected to query with
 * GetNotifySource before registering to reuse a source.
 */

/* Run the node's cleanup (NULL skipped) and release it; the caller passes
 * the owning context because nodes carry no back pointer. */
static void NodeDestroy(BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyNode *node)
{
    if (node->cleanup != NULL) {
        node->cleanup(ctx, node->key, node->handle, node->userData);
    }
    BSL_SAL_FREE(node);
}

/* Key lookup by pointer equality. Nodes are prepended on registration, so
 * scanning from the first node resolves a duplicated key to its newest
 * registration. includePendingDel selects the flavor: Get and Clear skip
 * PENDING_DEL nodes (a deleting key behaves as absent); Clear re-checks with
 * them included for its idempotent success. */
static BSL_ASYNC_NotifyNode *FindNode(const BSL_ASYNC_NotifyCtx *ctx, const void *key, bool includePendingDel)
{
    BslListNode *listNode = BSL_LIST_FirstNode(ctx->sourceList);
    while (listNode != NULL) {
        BSL_ASYNC_NotifyNode *node = (BSL_ASYNC_NotifyNode *)listNode->data;
        if (node->key == key && (includePendingDel || node->state != BSL_ASYNC_SOURCE_STATE_PENDING_DEL)) {
            return node;
        }
        listNode = listNode->next;
    }
    return NULL;
}

static void ListRemoveNode(BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyNode *node)
{
    BslListNode *listNode = BSL_LIST_FirstNode(ctx->sourceList);
    while (listNode != NULL) {
        if ((BSL_ASYNC_NotifyNode *)listNode->data == node) {
            /* Detach frees the list wrapper only; a NULL free callback on
             * BSL_LIST_DeleteNode would make the list free the data itself
             * (bsl_list.c), which the caller still owns here. */
            BSL_LIST_DetachNode(ctx->sourceList, &listNode);
            return;
        }
        listNode = listNode->next;
    }
}

BSL_ASYNC_NotifyCtx *BSL_ASYNC_NotifyCtxNew(void)
{
    BSL_ASYNC_NotifyCtx *ctx = BSL_SAL_Calloc(1, sizeof(BSL_ASYNC_NotifyCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    ctx->sourceList = BSL_LIST_New(0);
    if (ctx->sourceList == NULL) {
        BSL_SAL_FREE(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    /* Zero initialization covers the initial values: no callback,
     * submit status UNSUPPORTED, empty change window. */
    ctx->submitStatus = BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED;
    return ctx;
}

void BSL_ASYNC_NotifyCtxFree(BSL_ASYNC_NotifyCtx *ctx)
{
    BslListNode *listNode = NULL;

    if (ctx == NULL) {
        return;
    }
    if (ctx->sourceList != NULL) {
        listNode = BSL_LIST_FirstNode(ctx->sourceList);
        while (listNode != NULL) {
            BslListNode *cur = listNode;
            BSL_ASYNC_NotifyNode *node = (BSL_ASYNC_NotifyNode *)listNode->data;
            listNode = listNode->next;
            BSL_LIST_DetachNode(ctx->sourceList, &cur);
            NodeDestroy(ctx, node);
        }
        BSL_SAL_FREE(ctx->sourceList);
    }
    BSL_SAL_FREE(ctx);
}

int32_t BSL_ASYNC_NotifyCtxSetCallback(BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyCallback callback, void *callbackArg)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    ctx->callback = callback;
    ctx->callbackArg = callbackArg;
    if (callback == NULL) {
        /* Clearing also drops the argument: no dangling pair remains. */
        ctx->callbackArg = NULL;
    }
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetCallback(const BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyCallback *callback,
                                       void **callbackArg)
{
    if (ctx == NULL || callback == NULL || callbackArg == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *callback = ctx->callback;
    *callbackArg = ctx->callbackArg;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxSetStatus(BSL_ASYNC_NotifyCtx *ctx, int32_t status)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (status != BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED && status != BSL_ASYNC_NOTIFY_STATUS_ERR &&
        status != BSL_ASYNC_NOTIFY_STATUS_OK && status != BSL_ASYNC_NOTIFY_STATUS_EAGAIN) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    ctx->submitStatus = status;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetStatus(const BSL_ASYNC_NotifyCtx *ctx, int32_t *status)
{
    if (ctx == NULL || status == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *status = ctx->submitStatus;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxSetNotifySource(BSL_ASYNC_NotifyCtx *ctx, const void *key, BSL_ASYNC_NotifyHandle handle,
                                           void *userData, BSL_ASYNC_NotifySourceCleanup cleanup)
{
    BSL_ASYNC_NotifyNode *node = NULL;

    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    /* Always prepend a new registration: no deduplication, no in-place
     * update and no retirement of previous nodes. Repeated registrations
     * under one key coexist until cleared or reclaimed, and key lookups
     * resolve to the newest node (FindNode scans from the head). A failure
     * leaves the list and both counters untouched. */
    node = BSL_SAL_Calloc(1, sizeof(BSL_ASYNC_NotifyNode));
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    node->key = key;
    node->handle = handle;
    node->userData = userData;
    node->cleanup = cleanup;
    node->state = BSL_ASYNC_SOURCE_STATE_PENDING_ADD;
    if (BSL_LIST_AddElement(ctx->sourceList, node, BSL_LIST_POS_BEGIN) != BSL_SUCCESS) {
        BSL_SAL_FREE(node);
        return BSL_MALLOC_FAIL;
    }
    ctx->pendingAddCount++;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetNotifySource(const BSL_ASYNC_NotifyCtx *ctx, const void *key,
                                           BSL_ASYNC_NotifyHandle *handle, void **userData)
{
    BSL_ASYNC_NotifyNode *node = NULL;

    if (ctx == NULL || key == NULL || handle == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    node = FindNode(ctx, key, false);
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_NOT_FOUND);
        return BSL_ASYNC_ERR_NOT_FOUND;
    }
    *handle = node->handle;
    if (userData != NULL) {
        *userData = node->userData;
    }
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetAllNotifySources(const BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyHandleList *list)
{
    BslListNode *listNode = NULL;
    uint32_t need = 0;
    uint32_t written = 0;

    if (ctx == NULL || list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    listNode = BSL_LIST_FirstNode(ctx->sourceList);
    while (listNode != NULL) {
        if (((BSL_ASYNC_NotifyNode *)listNode->data)->state != BSL_ASYNC_SOURCE_STATE_PENDING_DEL) {
            need++;
        }
        listNode = listNode->next;
    }
    list->numHandles = need;
    if (list->handles == NULL) {
        /* Counting phase of the two-phase query. */
        return BSL_SUCCESS;
    }
    if (list->capacity < need) {
        /* Report the required count, write nothing. */
        BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_CAPACITY_EXCEEDED);
        return BSL_ASYNC_ERR_CAPACITY_EXCEEDED;
    }
    listNode = BSL_LIST_FirstNode(ctx->sourceList);
    while (listNode != NULL) {
        BSL_ASYNC_NotifyNode *node = (BSL_ASYNC_NotifyNode *)listNode->data;
        if (node->state != BSL_ASYNC_SOURCE_STATE_PENDING_DEL) {
            list->handles[written] = node->handle;
            written++;
        }
        listNode = listNode->next;
    }
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxClearNotifySource(BSL_ASYNC_NotifyCtx *ctx, const void *key)
{
    BSL_ASYNC_NotifyNode *node = NULL;

    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    node = FindNode(ctx, key, false);
    if (node == NULL) {
        if (FindNode(ctx, key, true) != NULL) {
            return BSL_SUCCESS;
        }
        BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_NOT_FOUND);
        return BSL_ASYNC_ERR_NOT_FOUND;
    }
    if (node->state == BSL_ASYNC_SOURCE_STATE_PENDING_ADD) {
        /* Never observed by the waiter: remove immediately, no deletion is
         * reported. */
        ListRemoveNode(ctx, node);
        if (ctx->pendingAddCount > 0) {
            ctx->pendingAddCount--;
        }
        NodeDestroy(ctx, node);
        return BSL_SUCCESS;
    }
    node->state = BSL_ASYNC_SOURCE_STATE_PENDING_DEL;
    ctx->pendingDelCount++;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetChangedNotifySources(const BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyHandleList *addList,
                                                   BSL_ASYNC_NotifyHandleList *delList)
{
    BslListNode *listNode = NULL;
    uint32_t addWritten = 0;
    uint32_t delWritten = 0;

    if (ctx == NULL || addList == NULL || delList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    addList->numHandles = ctx->pendingAddCount;
    delList->numHandles = ctx->pendingDelCount;
    if (addList->handles == NULL && delList->handles == NULL) {
        /* Counting phase of the two-phase query: only the required
         * numbers are reported. */
        return BSL_SUCCESS;
    }
    if ((addList->handles != NULL && addList->capacity < ctx->pendingAddCount) ||
        (delList->handles != NULL && delList->capacity < ctx->pendingDelCount)) {
        /* Both counts are already reported; no array is written. */
        BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_CAPACITY_EXCEEDED);
        return BSL_ASYNC_ERR_CAPACITY_EXCEEDED;
    }
    listNode = BSL_LIST_FirstNode(ctx->sourceList);
    while (listNode != NULL) {
        BSL_ASYNC_NotifyNode *node = (BSL_ASYNC_NotifyNode *)listNode->data;
        if (node->state == BSL_ASYNC_SOURCE_STATE_PENDING_ADD && addList->handles != NULL) {
            addList->handles[addWritten] = node->handle;
            addWritten++;
        } else if (node->state == BSL_ASYNC_SOURCE_STATE_PENDING_DEL && delList->handles != NULL) {
            delList->handles[delWritten] = node->handle;
            delWritten++;
        }
        listNode = listNode->next;
    }
    /* Read-only by contract: node states and both counters are unchanged; the framework consumes the window at the resume point. */
    return BSL_SUCCESS;
}

void BSL_ASYNC_NotifyCtxConsumeChanges(BSL_ASYNC_NotifyCtx *ctx)
{
    BslListNode *listNode = NULL;
    BslListNode *next = NULL;

    if (ctx == NULL) {
        return;
    }
    listNode = BSL_LIST_FirstNode(ctx->sourceList);
    while (listNode != NULL) {
        next = listNode->next;
        BSL_ASYNC_NotifyNode *node = (BSL_ASYNC_NotifyNode *)listNode->data;
        if (node->state == BSL_ASYNC_SOURCE_STATE_PENDING_ADD) {
            /* The application registered the handle before resuming. */
            node->state = BSL_ASYNC_SOURCE_STATE_REGISTERED;
        } else if (node->state == BSL_ASYNC_SOURCE_STATE_PENDING_DEL) {
            /* Reclaim the node; the waiter deregistered before resuming. */
            BslListNode *cur = listNode;
            BSL_LIST_DetachNode(ctx->sourceList, &cur);
            NodeDestroy(ctx, node);
        }
        listNode = next;
    }
    ctx->pendingAddCount = 0;
    ctx->pendingDelCount = 0;
}

#endif // HITLS_BSL_ASYNC
