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
#include <stdint.h>
#include "list_base.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_hash_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BslListNodeSt ListNode;

int32_t BSL_ListInit(BSL_List *list, const ListDupFreeFuncPair *dataFunc)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if (list != NULL) {
        ret = ListRawInit(&list->rawList, NULL);

        if (dataFunc == NULL) {
            list->dataFunc.dupFunc = NULL;
            list->dataFunc.freeFunc = NULL;
        } else {
            list->dataFunc.dupFunc = dataFunc->dupFunc;
            list->dataFunc.freeFunc = dataFunc->freeFunc;
        }
    }

    return ret;
}

static int32_t ListRemoveNode(BSL_List *list, ListNode *node)
{
    int32_t ret;

    if (list->dataFunc.freeFunc != NULL) {
        (list->dataFunc.freeFunc((void *)(node->userdata)));
    }

    ret = ListRawRemove(&list->rawList, &node->rawNode);
    if (ret == BSL_SUCCESS) {
        BSL_SAL_FREE(node);
    }

    return ret;
}

int32_t BSL_ListClear(BSL_List *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListNode *node = NULL;
    const RawList *rawList = NULL;
    const ListRawNode *head = NULL;

    if (list != NULL) {
        rawList = &list->rawList;
        head = &rawList->head;
        while (!ListRawEmpty(rawList)) {
            node = BSL_CONTAINER_OF(head->next, ListNode, rawNode);
            ret = ListRemoveNode(list, node);
            if (ret != BSL_SUCCESS) {
                break;
            }
        }
    }

    return ret;
}

int32_t BSL_ListDeinit(BSL_List *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;

    if (list != NULL) {
        ret = BSL_ListClear(list);
        list->dataFunc.dupFunc = NULL;
        list->dataFunc.freeFunc = NULL;
    }

    return ret;
}

static int32_t ListWriteUserdata(const BSL_List *list, ListNode *node, uintptr_t userData, size_t userDataSize)
{
    int32_t ret;
    const void *copyBuff = NULL;

    if (list->dataFunc.dupFunc == NULL) {
        node->userdata = userData;
        ret = BSL_SUCCESS;
    } else {
        copyBuff = list->dataFunc.dupFunc((void *)userData, userDataSize);
        if (copyBuff == NULL) {
            ret = BSL_INTERNAL_EXCEPTION;
        } else {
            node->userdata = (uintptr_t)copyBuff;
            ret = BSL_SUCCESS;
        }
    }

    return ret;
}

static ListNode *NewNodeCreateByUserData(const BSL_List *list, uintptr_t userData, size_t userDataSize)
{
    ListNode *node = NULL;

    if (list != NULL) {
        node = (ListNode *)BSL_SAL_Malloc(sizeof(ListNode));
        if (node != NULL) {
            if (ListWriteUserdata(list, node, userData, userDataSize) != BSL_SUCCESS) {
                BSL_SAL_FREE(node);
                node = NULL;
            }
        }
    }

    return node;
}

int32_t BSL_ListPushFront(BSL_List *list, uintptr_t userData, size_t userDataSize)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListNode *node;

    node = NewNodeCreateByUserData(list, userData, userDataSize);
    if (node != NULL) {
        ret = ListRawPushFront(&list->rawList, &node->rawNode);
    }

    return ret;
}

int32_t BSL_ListPushBack(BSL_List *list, uintptr_t userData, size_t userDataSize)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListNode *node = NULL;

    if (list != NULL) {
        node = NewNodeCreateByUserData(list, userData, userDataSize);
        if (node != NULL) {
            ret = ListRawPushBack(&list->rawList, &node->rawNode);
        } else {
            ret = (int32_t)BSL_INTERNAL_EXCEPTION;
        }
    }

    return ret;
}

int32_t BSL_ListInsert(BSL_List *list, const BSL_ListIterator it, uintptr_t userData, size_t userDataSize)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListNode *node = NULL;

    if ((list != NULL) && (it != NULL)) {
        node = NewNodeCreateByUserData(list, userData, userDataSize);
        if (node != NULL) {
            ret = ListIRawnsert(&it->rawNode, &node->rawNode);
            if (ret != BSL_SUCCESS) {
                if (list->dataFunc.freeFunc != NULL) {
                    list->dataFunc.freeFunc((void *)(node->userdata));
                }
                BSL_SAL_FREE(node);
            }
        } else {
            ret = (int32_t)BSL_INTERNAL_EXCEPTION;
        }
    }

    return ret;
}

bool BSL_ListIsEmpty(const BSL_List *list)
{
    bool ret = true;

    if (list != NULL) {
        ret = ListRawEmpty(&list->rawList);
    }

    return ret;
}

int32_t BSL_ListPopFront(BSL_List *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListNode *firstNode = NULL;

    if (!BSL_ListIsEmpty(list)) {
        firstNode = BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
        ret = ListRemoveNode(list, firstNode);
    }

    return ret;
}

int32_t BSL_ListPopBack(BSL_List *list)
{
    int32_t ret = (int32_t)BSL_INTERNAL_EXCEPTION;
    ListNode *lastNode = NULL;

    if (!BSL_ListIsEmpty(list)) {
        lastNode = BSL_CONTAINER_OF(list->rawList.head.prev, ListNode, rawNode);
        ret = ListRemoveNode(list, lastNode);
    }

    return ret;
}

BSL_ListIterator BSL_ListIterErase(BSL_List *list, BSL_ListIterator it)
{
    int32_t ret = BSL_INTERNAL_EXCEPTION;
    BSL_ListIterator retIt;

    if (BSL_ListIsEmpty(list) || (it == NULL) || (it == (BSL_ListIterator)(&list->rawList.head))) {
        retIt = NULL;
    } else {
        retIt = BSL_CONTAINER_OF(it->rawNode.next, ListNode, rawNode);
        ret = ListRemoveNode(list, it);
    }

    if (ret != BSL_SUCCESS) {
        retIt = NULL;
    }

    return retIt;
}

uintptr_t BSL_ListFront(const BSL_List *list)
{
    uintptr_t frontData = 0;
    const ListNode *node = NULL;

    if (!BSL_ListIsEmpty(list)) {
        node = BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
        frontData = node->userdata;
    }

    return frontData;
}

uintptr_t BSL_ListBack(const BSL_List *list)
{
    uintptr_t backData = 0;
    const ListNode *node = NULL;

    if (!BSL_ListIsEmpty(list)) {
        node = BSL_CONTAINER_OF(list->rawList.head.prev, ListNode, rawNode);
        backData = node->userdata;
    }

    return backData;
}

BSL_ListIterator BSL_ListIterBegin(const BSL_List *list)
{
    BSL_ListIterator beginIterator = NULL;

    if (list != NULL) {
        beginIterator = BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
    }

    return beginIterator;
}

BSL_ListIterator BSL_ListIterEnd(BSL_List *list)
{
    BSL_ListIterator endIterator = NULL;

    if (list != NULL) {
        endIterator = (BSL_ListIterator)(&list->rawList.head);
    }

    return endIterator;
}

size_t BSL_ListSize(const BSL_List *list)
{
    size_t size = 0;

    if (list != NULL) {
        size = ListRawSize(&list->rawList);
    }

    return size;
}

BSL_ListIterator BSL_ListIterPrev(const BSL_List *list, const BSL_ListIterator it)
{
    BSL_ListIterator prev = NULL;

    if ((!BSL_ListIsEmpty(list)) && (it != NULL)) {
        prev = BSL_CONTAINER_OF(it->rawNode.prev, ListNode, rawNode);
    }

    return prev;
}

BSL_ListIterator BSL_ListIterNext(const BSL_List *list, const BSL_ListIterator it)
{
    BSL_ListIterator next = NULL;

    if ((!BSL_ListIsEmpty(list)) && (it != NULL)) {
        next = BSL_CONTAINER_OF(it->rawNode.next, ListNode, rawNode);
    }

    return next;
}

uintptr_t BSL_ListIterData(const BSL_ListIterator it)
{
    uintptr_t data = 0;

    if (it != NULL) {
        data = it->userdata;
    }

    return data;
}

/* Linked list node search function. The type of the first parameter of iterCmpFunc is userdata of each iterator. */
BSL_ListIterator BSL_ListIterFind(BSL_List *list, ListKeyCmpFunc iterCmpFunc, uintptr_t data)
{
    BSL_ListIterator it = NULL, headIt = NULL;
    BSL_ListIterator ans = NULL;

    if ((list != NULL) && (iterCmpFunc != NULL)) {
        headIt = (BSL_ListIterator)BSL_CONTAINER_OF(&list->rawList.head, ListNode, rawNode);
        it = BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
        while (it != headIt) {
            if (iterCmpFunc(it->userdata, data) == 0) {
                ans = it;
                break;
            }

            it = BSL_CONTAINER_OF(it->rawNode.next, ListNode, rawNode);
        }
    }

    return ans;
}

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */
