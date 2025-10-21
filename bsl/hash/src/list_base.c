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
#ifdef HITLS_BSL_HASH

#include <stdlib.h>
#include "bsl_errno.h"
#include "list_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* internal function definition */
static inline bool ListRawNodeInList(const ListRawNode *node)
{
    return (node->next != NULL) && (node->prev != NULL) &&
        ((const ListRawNode *)(node->next->prev) == node) &&
        ((const ListRawNode *)(node->prev->next) == node);
}

static inline bool IsListRawEmptyCheck(const RawList *list)
{
    return (&list->head)->next == &list->head;
}

static inline void ListRawAddAfterNode(ListRawNode *node, ListRawNode *where)
{
    node->next       = (where)->next;
    node->prev       = (where);
    where->next      = node;
    node->next->prev = node;
}

static inline void ListRawAddBeforeNode(ListRawNode *node, const ListRawNode *where)
{
    ListRawAddAfterNode(node, where->prev);
}

static inline bool IsListRawFirstNode(const RawList *list, const ListRawNode *node)
{
    return (const ListRawNode *)list->head.next == node;
}

static inline bool IsListRawLastNode(const RawList *list, const ListRawNode *node)
{
    return (const ListRawNode *)list->head.prev == node;
}

/* Deleting the list node, internal function, input parameter validation is not required. */
static void ListRawRemoveNode(const RawList *list, ListRawNode *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;

    if (list->freeFunc != NULL) {
        list->freeFunc((void *)node);
    }
}

int32_t ListRawInit(RawList *list, ListFreeFunc freeFunc)
{
    if (list == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }

    list->head.next = &list->head;
    list->head.prev = &list->head;
    list->freeFunc  = freeFunc;
    return BSL_SUCCESS;
}

int32_t ListRawClear(RawList *list)
{
    if (list == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }

    while (!IsListRawEmptyCheck(list)) {
        ListRawRemoveNode(list, (ListRawNode *)list->head.next);
    }

    return BSL_SUCCESS;
}

int32_t ListRawDeinit(RawList *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if (list != NULL) {
        ret = ListRawClear(list);
        list->freeFunc = NULL;
    }

    return ret;
}

bool ListRawEmpty(const RawList *list)
{
    return list == NULL ? true : IsListRawEmptyCheck(list);
}

static inline size_t ListRawSizeInner(const RawList *list)
{
    size_t size = 0;
    const ListRawNode *head = &list->head;
    for (const ListRawNode *node = head->next; node != head; node = node->next) {
        size++;
    }

    return size;
}

size_t ListRawSize(const RawList *list)
{
    return (list == NULL || IsListRawEmptyCheck(list) == true) ? 0 : ListRawSizeInner(list);
}

int32_t ListRawPushFront(RawList *list, ListRawNode *node)
{
    if (list == NULL || node == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }

    ListRawAddAfterNode(node, &(list->head));
    return BSL_SUCCESS;
}

int32_t ListRawPushBack(RawList *list, ListRawNode *node)
{
    if (list == NULL || node == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }

    ListRawAddBeforeNode(node, &(list->head));
    return BSL_SUCCESS;
}

int32_t ListRawInsert(const ListRawNode *curNode, ListRawNode *newNode)
{
    if ((curNode != NULL) && (newNode != NULL) && (curNode != newNode) && (ListRawNodeInList(curNode))) {
        ListRawAddBeforeNode(newNode, curNode);
        return BSL_SUCCESS;
    }

    return BSL_INTERNAL_EXCEPTION;
}

int32_t ListRawPopFront(RawList *list)
{
    if (list == NULL || IsListRawEmptyCheck(list) == true) {
        return BSL_INTERNAL_EXCEPTION;
    }
    ListRawNode *firstNode = list->head.next;
    ListRawRemoveNode(list, firstNode);
    return BSL_SUCCESS;
}

int32_t ListRawPopBack(RawList *list)
{
    if (list == NULL || IsListRawEmptyCheck(list) == true) {
        return BSL_INTERNAL_EXCEPTION;
    }
    ListRawNode *lastNode = list->head.prev;
    ListRawRemoveNode(list, lastNode);
    return BSL_SUCCESS;
}

static void ListRawRemoveInner(RawList *list, ListRawNode *node)
{
    if (node == NULL) {
        return;
    }
    node->prev->next = node->next;
    node->next->prev = node->prev;

    if ((list != NULL) && !IsListRawEmptyCheck(list) && (list->freeFunc != NULL)) {
        list->freeFunc((void *)node);
    }
}

int32_t ListRawRemove(RawList *list, ListRawNode *node)
{
    if (list == NULL || IsListRawEmptyCheck(list) == true) {
        return BSL_INTERNAL_EXCEPTION;
    }
    ListRawRemoveInner(list, node);
    return BSL_SUCCESS;
}

ListRawNode *ListRawFront(const RawList *list)
{
    return (list == NULL || IsListRawEmptyCheck(list) == true) ? NULL : list->head.next;
}

ListRawNode *ListRawBack(const RawList *list)
{
    return (list == NULL || IsListRawEmptyCheck(list) == true) ? NULL : list->head.prev;
}

ListRawNode *ListRawGetPrev(const RawList *list, const ListRawNode *node)
{
    return ((list == NULL) || (node == NULL) || (IsListRawEmptyCheck(list)) || (IsListRawFirstNode(list, node)) ||
        (!ListRawNodeInList(node)))
        ? NULL
        : node->prev;
}

ListRawNode *ListRawGetNext(const RawList *list, const ListRawNode *node)
{
    return ((list == NULL) || (node == NULL) || (IsListRawEmptyCheck(list)) || (IsListRawLastNode(list, node)) ||
        (!ListRawNodeInList(node)))
        ? NULL
        : node->next;
}

/* Linked list node search function. The type of the first parameter of nodeMatchFunc must be (ListRawNode *) */
ListRawNode *ListRawFindNode(const RawList *list, ListMatchFunc nodeMatchFunc, uintptr_t data)
{
    if (list == NULL || nodeMatchFunc == NULL) {
        return NULL;
    }
    const ListRawNode *head = (const ListRawNode *)(&list->head);
    ListRawNode *node = head->next;
    while ((const ListRawNode *)node != head) {
        if (nodeMatchFunc((void *)node, data)) {
            return node;
        }
        node = node->next;
    }

    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */
