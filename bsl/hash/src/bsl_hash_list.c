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
    if (list->dataFunc.freeFunc != NULL) {
        (list->dataFunc.freeFunc((void *)(node->userdata)));
    }

    int32_t ret = ListRawRemove(&list->rawList, &node->rawNode);
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
    if (list->dataFunc.dupFunc == NULL) {
        node->userdata = userData;
        return BSL_SUCCESS;
    }
    const void *copyBuff = list->dataFunc.dupFunc((void *)userData, userDataSize);
    if (copyBuff == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }

    node->userdata = (uintptr_t)copyBuff;
    return BSL_SUCCESS;
}

static ListNode *NewNodeCreateByUserData(const BSL_List *list, uintptr_t userData, size_t userDataSize)
{
    if (list == NULL) {
        return NULL;
    }

    ListNode *node = (ListNode *)BSL_SAL_Malloc(sizeof(ListNode));
    if (node != NULL) {
        if (ListWriteUserdata(list, node, userData, userDataSize) != BSL_SUCCESS) {
            BSL_SAL_Free(node);
            node = NULL;
        }
    }

    return node;
}

static int32_t ListPush(BSL_List *list, uintptr_t userData, size_t userDataSize, bool isFront)
{
    ListNode *node = NewNodeCreateByUserData(list, userData, userDataSize);
    if (node == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }
    int32_t ret = isFront ? ListRawPushFront(&list->rawList, &node->rawNode) :
                            ListRawPushBack(&list->rawList, &node->rawNode);
    if (ret != BSL_SUCCESS) {
        if (list->dataFunc.freeFunc != NULL) {
            list->dataFunc.freeFunc((void *)(node->userdata));
        }
        BSL_SAL_Free(node);
    }
    return ret;
}

int32_t BSL_ListPushFront(BSL_List *list, uintptr_t userData, size_t userDataSize)
{
    return ListPush(list, userData, userDataSize, true);
}

int32_t BSL_ListPushBack(BSL_List *list, uintptr_t userData, size_t userDataSize)
{
    return ListPush(list, userData, userDataSize, false);
}

int32_t BSL_ListInsert(BSL_List *list, const BSL_ListIterator it, uintptr_t userData, size_t userDataSize)
{
    if (list == NULL || it == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }

    ListNode *node = NewNodeCreateByUserData(list, userData, userDataSize);
    if (node == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }

    int32_t ret = ListRawInsert(&it->rawNode, &node->rawNode);
    if (ret != BSL_SUCCESS) {
        if (list->dataFunc.freeFunc != NULL) {
            list->dataFunc.freeFunc((void *)(node->userdata));
        }
        BSL_SAL_Free(node);
    }
    return ret;
}

bool BSL_ListIsEmpty(const BSL_List *list)
{
    return list == NULL ? true : ListRawEmpty(&list->rawList);
}

int32_t BSL_ListPopFront(BSL_List *list)
{
    if (BSL_ListIsEmpty(list) == true) {
        return BSL_INTERNAL_EXCEPTION;
    }
    ListNode *firstNode = BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
    return ListRemoveNode(list, firstNode);
}

int32_t BSL_ListPopBack(BSL_List *list)
{
    if (BSL_ListIsEmpty(list) == true) {
        return BSL_INTERNAL_EXCEPTION;
    }
    ListNode *lastNode = BSL_CONTAINER_OF(list->rawList.head.prev, ListNode, rawNode);
    return ListRemoveNode(list, lastNode);
}

BSL_ListIterator BSL_ListIterErase(BSL_List *list, BSL_ListIterator it)
{
    if (BSL_ListIsEmpty(list) || (it == NULL) || (it == (BSL_ListIterator)(&list->rawList.head))) {
        return NULL;
    }
    BSL_ListIterator retIt = BSL_CONTAINER_OF(it->rawNode.next, ListNode, rawNode);
    return ListRemoveNode(list, it) == BSL_SUCCESS ? retIt : NULL;
}

uintptr_t BSL_ListFront(const BSL_List *list)
{
    if (BSL_ListIsEmpty(list) == true) {
        return (uintptr_t)0;
    }
    const ListNode *node = BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
    return node->userdata;
}

uintptr_t BSL_ListBack(const BSL_List *list)
{
    if (BSL_ListIsEmpty(list) == true) {
        return (uintptr_t)0;
    }

    const ListNode *node = BSL_CONTAINER_OF(list->rawList.head.prev, ListNode, rawNode);
    return node->userdata;
}

BSL_ListIterator BSL_ListIterBegin(const BSL_List *list)
{
    return list == NULL ? NULL : BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
}

BSL_ListIterator BSL_ListIterEnd(BSL_List *list)
{
    return list == NULL ? NULL : (BSL_ListIterator)(&list->rawList.head);
}

size_t BSL_ListSize(const BSL_List *list)
{
    return list == NULL ? 0 : ListRawSize(&list->rawList);
}

BSL_ListIterator BSL_ListIterPrev(const BSL_List *list, const BSL_ListIterator it)
{
    return (BSL_ListIsEmpty(list) == true || it == NULL) ? NULL : BSL_CONTAINER_OF(it->rawNode.prev, ListNode, rawNode);
}

BSL_ListIterator BSL_ListIterNext(const BSL_List *list, const BSL_ListIterator it)
{
    return (BSL_ListIsEmpty(list) == true || it == NULL) ? NULL : BSL_CONTAINER_OF(it->rawNode.next, ListNode, rawNode);
}

uintptr_t BSL_ListIterData(const BSL_ListIterator it)
{
    return it == NULL ? 0 : it->userdata;
}

/* Linked list node search function. The type of the first parameter of iterCmpFunc is userdata of each iterator. */
BSL_ListIterator BSL_ListIterFind(BSL_List *list, ListKeyCmpFunc iterCmpFunc, uintptr_t data)
{
    if (list == NULL || iterCmpFunc == NULL) {
        return NULL;
    }

    BSL_ListIterator headIt = (BSL_ListIterator)BSL_CONTAINER_OF(&list->rawList.head, ListNode, rawNode);
    BSL_ListIterator it = BSL_CONTAINER_OF(list->rawList.head.next, ListNode, rawNode);
    while (it != headIt) {
        if (iterCmpFunc(it->userdata, data) == 0) {
            return it;
        }

        it = BSL_CONTAINER_OF(it->rawNode.next, ListNode, rawNode);
    }

    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */
