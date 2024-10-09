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
    bool ret = false;

    if ((node->next != NULL) && (node->prev != NULL) &&
        ((const ListRawNode *)(node->next->prev) == node) &&
        ((const ListRawNode *)(node->prev->next) == node)) {
        ret = true;
    }

    return ret;
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
    bool ret = false;

    if ((const ListRawNode *)list->head.next == node) {
        ret = true;
    }

    return ret;
}

static inline bool IsListRawLastNode(const RawList *list, const ListRawNode *node)
{
    bool ret = false;

    if ((const ListRawNode *)list->head.prev == node) {
        ret = true;
    }

    return ret;
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
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if (list != NULL) {
        list->head.next = &list->head;
        list->head.prev = &list->head;
        list->freeFunc  = freeFunc;
        ret = BSL_SUCCESS;
    }

    return ret;
}

int32_t ListRawClear(RawList *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if (list != NULL) {
        while (!IsListRawEmptyCheck(list)) {
            ListRawRemoveNode(list, (ListRawNode *)list->head.next);
        }

        ret = BSL_SUCCESS;
    }

    return ret;
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
    bool ret = true;

    if (list != NULL) {
        ret = IsListRawEmptyCheck(list);
    }

    return ret;
}

static inline size_t ListRawSizeInner(const RawList *list)
{
    size_t size = 0;
    const ListRawNode *node = NULL, *head = NULL;

    head = &list->head;
    for (node = head->next; node != head; node = node->next) {
        size++;
    }

    return size;
}

size_t ListRawSize(const RawList *list)
{
    size_t size = 0;

    if ((list != NULL) && !IsListRawEmptyCheck(list)) {
        size = ListRawSizeInner(list);
    }

    return size;
}

int32_t ListRawPushFront(RawList *list, ListRawNode *node)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if ((list != NULL) && (node != NULL)) {
        ListRawAddAfterNode(node, &(list->head));
        ret = BSL_SUCCESS;
    }

    return ret;
}

int32_t ListRawPushBack(RawList *list, ListRawNode *node)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if ((list != NULL) && (node != NULL)) {
        ListRawAddBeforeNode(node, &(list->head));
        ret = BSL_SUCCESS;
    }

    return ret;
}

int32_t ListIRawnsert(const ListRawNode *curNode, ListRawNode *newNode)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if ((curNode != NULL) && (newNode != NULL) && (ListRawNodeInList(curNode))) {
        ListRawAddBeforeNode(newNode, curNode);
        ret = BSL_SUCCESS;
    }

    return ret;
}

int32_t ListRawPopFront(RawList *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListRawNode *firstNode = NULL;

    if ((list != NULL) && (!IsListRawEmptyCheck(list))) {
        firstNode = list->head.next;
        ListRawRemoveNode(list, firstNode);
        ret = BSL_SUCCESS;
    }

    return ret;
}

int32_t ListRawPopBack(RawList *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListRawNode *lastNode = NULL;

    if (list != NULL) {
        if (!IsListRawEmptyCheck(list)) {
            lastNode = list->head.prev;
            ListRawRemoveNode(list, lastNode);
            ret = BSL_SUCCESS;
        } else {
            ret = (int32_t)BSL_INTERNAL_EXCEPTION;
        }
    }

    return ret;
}

static void ListRawRemoveInner(RawList *list, ListRawNode *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;

    if ((list != NULL) && !IsListRawEmptyCheck(list) && (list->freeFunc != NULL)) {
        list->freeFunc((void *)node);
    }
}

int32_t ListRawRemove(RawList *list, ListRawNode *node)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if ((node != NULL) && (ListRawNodeInList(node))) {
        ListRawRemoveInner(list, node);
        ret = BSL_SUCCESS;
    }

    return ret;
}

ListRawNode *ListRawFront(const RawList *list)
{
    ListRawNode *front = NULL;

    if ((list != NULL) && (!IsListRawEmptyCheck(list))) {
        front = list->head.next;
    }

    return front;
}

ListRawNode *ListRawBack(const RawList *list)
{
    ListRawNode *back = NULL;

    if ((list != NULL) && (!IsListRawEmptyCheck(list))) {
        back = list->head.prev;
    }

    return back;
}

ListRawNode *ListRawGetPrev(const RawList *list, const ListRawNode *node)
{
    ListRawNode *prev = NULL;

    if ((list == NULL) || (node == NULL) ||
        (IsListRawEmptyCheck(list)) || (IsListRawFirstNode(list, node)) || (!ListRawNodeInList(node))) {
        prev = NULL;
    } else {
        prev = node->prev;
    }

    return prev;
}

ListRawNode *ListRawGetNext(const RawList *list, const ListRawNode *node)
{
    ListRawNode *next = NULL;

    if ((list == NULL) || (node == NULL) ||
        (IsListRawEmptyCheck(list)) || (IsListRawLastNode(list, node)) || (!ListRawNodeInList(node))) {
        next = NULL;
    } else {
        next = node->next;
    }

    return next;
}

/* Linked list node search function. The type of the first parameter of nodeMatchFunc must be (ListRawNode *) */
ListRawNode *ListRawFindNode(const RawList *list, ListMatchFunc nodeMatchFunc, uintptr_t data)
{
    ListRawNode *ans = NULL;
    ListRawNode *node = NULL;
    const ListRawNode *head = NULL;

    if ((list != NULL) && (nodeMatchFunc != NULL)) {
        head = (const ListRawNode *)(&list->head);
        node = head->next;
        while ((const ListRawNode *)node != head) {
            if (nodeMatchFunc((void *)node, data)) {
                ans = node;
                break;
            }
            node = node->next;
        }
    }

    return ans;
}

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */
