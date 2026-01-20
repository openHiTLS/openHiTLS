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
#ifdef HITLS_BSL_LIST

#include "bsl_list_internal.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_list.h"

#define MAX_LIST_ELEM_CNT_DEFAULT 10000000

/* this global var limits the maximum node number of a list */
static int32_t g_maxListCount = MAX_LIST_ELEM_CNT_DEFAULT;

static int32_t BslListAddAfterCurr(BslList *pList, void *pData)
{
    BslListNode *newNode = NULL;

    /* check for missing argument */
    if (pList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    /* check if current is null */
    if (pList->curr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_INVALID_LIST_CURRENT);
        return BSL_LIST_INVALID_LIST_CURRENT;
    }

    /* allocate memory for new node */
    newNode = BSL_SAL_Calloc(1, sizeof(BslListNode));
    if (newNode == NULL) {
        return BSL_LIST_MALLOC_FAIL;
    }

    newNode->data = pData;

    /* add new node after current */
    newNode->next = pList->curr->next;
    newNode->prev = pList->curr;
    if ((pList->curr->next) != NULL) {
        pList->curr->next->prev = newNode;
    } else {
        pList->last = newNode;
    }

    pList->curr->next = newNode;

    pList->curr = newNode;
    pList->count++;
    return BSL_SUCCESS;
}

static int32_t BslListInsertBeforeCurr(BslList *pList, void *pData)
{
    BslListNode *pNewNode = NULL;

    /* check if current is null */
    /* check for missing argument */
    if (pList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (pList->curr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_INVALID_LIST_CURRENT);
        return BSL_LIST_INVALID_LIST_CURRENT;
    }

    /* allocate memory for new node */
    pNewNode = BSL_SAL_Calloc(1, sizeof(BslListNode));
    if (pNewNode == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return BSL_LIST_MALLOC_FAIL;
    }

    pNewNode->data = pData;

    /* add new node before current */
    pNewNode->next = pList->curr;
    pNewNode->prev = pList->curr->prev;
    if ((pList->curr->prev) != NULL) {
        pList->curr->prev->next = pNewNode;
    } else {
        pList->first = pNewNode;
    }

    pList->curr->prev = pNewNode;

    pList->curr = pNewNode;
    pList->count++;
    return BSL_SUCCESS;
}

int32_t BSL_LIST_AddElementInt(BslList *pList, void *pData, BslListPosition enPosition)
{
    BslListNode *pNewNode = NULL;

    if (pList->count >= g_maxListCount) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_FULL);
        return BSL_LIST_FULL;
    }

    if (pList->curr == NULL) {
        if (pList->first == NULL) {
            /* allocate memory for new node */
            pNewNode = BSL_SAL_Calloc(1, sizeof(BslListNode));
            if (pNewNode == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
                return BSL_LIST_MALLOC_FAIL;
            }

            pNewNode->data = pData;

            /* set the new node as the first and last node of list */
            pNewNode->next = NULL;
            pNewNode->prev = NULL;
            pList->first = pNewNode;
            pList->last = pNewNode;
            pList->curr = pNewNode;
            pList->count++;
            return BSL_SUCCESS;
        } else {
            if (enPosition == BSL_LIST_POS_AFTER) {
                pList->curr = pList->last;
            } else if (enPosition == BSL_LIST_POS_BEFORE) {
                pList->curr = pList->first;
            }
        }
    }

    if ((enPosition == BSL_LIST_POS_AFTER) || (enPosition == BSL_LIST_POS_END)) {
        if (enPosition == BSL_LIST_POS_END) {
            pList->curr = pList->last;
        }

        return BslListAddAfterCurr(pList, pData);
    } else {
        if (enPosition == BSL_LIST_POS_BEGIN) {
            pList->curr = pList->first;
        }

        return BslListInsertBeforeCurr(pList, pData);
    }
}

int32_t BSL_LIST_AddElement(BslList *pList, void *pData, BslListPosition enPosition)
{
    /* check for missing argument */
    if (pList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    /* we are doing a range checking. the same thing is done in another way for clarity */
    if (enPosition < BSL_LIST_POS_BEFORE || enPosition > BSL_LIST_POS_END) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    if (pData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_DATA_NOT_AVAILABLE);
        return BSL_LIST_DATA_NOT_AVAILABLE;
    }

    return BSL_LIST_AddElementInt(pList, pData, enPosition);
}

int32_t BSL_LIST_SetMaxElements(int32_t iMaxElements)
{
    if (iMaxElements < 0xffff || iMaxElements > 0xfffffff) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    g_maxListCount = iMaxElements;
    return BSL_SUCCESS;
}

int32_t BSL_LIST_GetMaxElements(void)
{
    return g_maxListCount;
}

void BSL_LIST_DeleteAll(BslList *pList, BSL_LIST_PFUNC_FREE pfFreeFunc)
{
    BslListNode *pNode = NULL;
    BslListNode *pNext = NULL;

    /* check for missing argument */
    if (pList == NULL) {
        return;
    }

    pNode = pList->first;

    /* delete each node one by one */
    while (pNode != NULL) {
        pNext = pNode->next;
        if (pfFreeFunc == NULL) {
            BSL_SAL_FREE(pNode->data);
        } else {
            pfFreeFunc(pNode->data);
            pNode->data = NULL;
        }

        BSL_SAL_FREE(pNode);
        pNode = pNext;
        pList->count--;
    }

    pList->first = (pList->last = (pList->curr = NULL));
}

void BSL_LIST_DeleteCurrent(BslList *pList, BSL_LIST_PFUNC_FREE pfFreeFunc)
{
    BslListNode *pNode = NULL;

    /* check for missing argument */
    if (pList == NULL) {
        return;
    }

    if (pList->curr != NULL) {
        /* delete current and set prev and next appropriately */
        if (pList->curr->next != NULL) {
            pList->curr->next->prev = pList->curr->prev;
        } else {
            pList->last = pList->curr->prev;
        }

        if (pList->curr->prev != NULL) {
            pList->curr->prev->next = pList->curr->next;
        } else {
            pList->first = pList->curr->next;
        }

        pNode = pList->curr;

        pList->curr = pList->curr->next;
        pList->count--;

        if (pfFreeFunc == NULL) {
            BSL_SAL_FREE(pNode->data);
        } else {
            pfFreeFunc(pNode->data);
        }

        BSL_SAL_FREE(pNode);
    }
}

void BSL_LIST_DetachCurrent(BslList *pList)
{
    /* check for missing argument */
    BslListNode *tmpCurr = NULL;
    if (pList == NULL) {
        return;
    }

    tmpCurr = pList->curr; // get the current node

    if (tmpCurr != NULL) {
        /* delete current and set prev and next appropriately */
        if (tmpCurr->next != NULL) { // check for last node
            // current node is not the last node
            tmpCurr->next->prev = tmpCurr->prev;

            // update the current node and point it to the next node
            pList->curr = tmpCurr->next;
        } else {
            // current node is the last node
            pList->last = tmpCurr->prev;

            // update the current node and point it to the last node
            pList->curr = pList->last;
        }

        if (tmpCurr->prev != NULL) { // check for the first node
            // current node is not the first node
            tmpCurr->prev->next = tmpCurr->next;
        } else {
            // current node is the first node
            pList->first = tmpCurr->next;
        }

        // we have already updated the pList->curr pointer appropriately
        pList->count--;

        // now we must free the temp current node
        BSL_SAL_FREE(tmpCurr);
    }
}

/**
 * @ingroup bsl_list
 * @brief Searches for an element and as well return immediately after internal error
 *
 * @param pList [IN] List in which object is searched for.
 * @param pSearchFor [IN] Object to be searched for.
 * @param pSearcher [IN] Search Function to be used.
 * @param pstErr [OUT] Update the Internal Error if Any. If pstErr is not equal to NULL. If NULL this will be ignored.
 * @retval void *
 */
static void *BSL_ListSearchInt(BslList *pList, const void *pSearchFor, BSL_LIST_PFUNC_CMP pSearcher, int32_t *pstErr)
{
    /* temporarily stores current node */
    BslListNode *pstTempCurr = NULL;

    /* check for missing argument */
    if (pList == NULL || pSearchFor == NULL) {
        return NULL;
    }

    pstTempCurr = pList->curr;

    /* parse all nodes one by one */
    for (pList->curr = pList->first; pList->curr != NULL; pList->curr = pList->curr->next) {
        if (pSearcher == NULL) {
            /* if pSearcher is NULL, use memcmp */
            if (memcmp(pList->curr->data, pSearchFor, (uint32_t)pList->dataSize) == 0) {
                return pList->curr->data;
            }
        } else {
            int32_t retVal = pSearcher(pList->curr->data, pSearchFor);
            if (retVal == SEC_INT_ERROR && pstErr != NULL) {
                *pstErr = SEC_INT_ERROR;
                return NULL;
            }

            if (retVal == 0) {
                return pList->curr->data;
            }
        }
    }

    /* no match found */
    pList->curr = pstTempCurr;

    return NULL;
}

void *BSL_LIST_Search(BslList *pList, const void *pSearchFor, BSL_LIST_PFUNC_CMP pSearcher, int32_t *pstErr)
{
    return BSL_ListSearchInt(pList, pSearchFor, pSearcher, pstErr);
}

void *BSL_LIST_SearchEx(BslList *pList, const void *pSearchFor, BSL_LIST_PFUNC_CMP pSearcher)
{
    return BSL_ListSearchInt(pList, pSearchFor, pSearcher, NULL);
}

void *BSL_LIST_GetIndexNode(uint32_t ulIndex, BslList *pList)
{
    if (pList == NULL) {
        return NULL;
    }

    if (ulIndex >= (uint32_t)pList->count) {
        return NULL;
    }

    if (BSL_LIST_GET_FIRST(pList) == NULL) {
        return NULL;
    }

    for (uint32_t ulIter = 0; ulIter < ulIndex; ulIter++) {
        if (BSL_LIST_GET_NEXT(pList) == NULL) {
            return NULL;
        }
    }

    return pList->curr->data;
}

BslList *BSL_LIST_Copy(BslList *pSrcList, BSL_LIST_PFUNC_DUP pFuncCpy, BSL_LIST_PFUNC_FREE pfFreeFunc)
{
    void *pDstData = NULL;

    if (pSrcList == NULL) {
        return NULL;
    }

    /* we will first get the source data and if successful go ahead */
    void *pSrcData = BSL_LIST_GET_FIRST(pSrcList);
    if (pSrcData == NULL) {
        return NULL;
    }

    BslList *pDstList = BSL_LIST_New(pSrcList->dataSize);
    if (pDstList == NULL) {
        return NULL;
    }

    for (int32_t i = 1; (pSrcData != NULL) && i <= BSL_LIST_COUNT(pSrcList); i++) {
        if (pFuncCpy != NULL) {
            pDstData = pFuncCpy(pSrcData);
        } else {
            uint32_t dataLen = (uint32_t)(pSrcList->dataSize);
            pDstData = BSL_SAL_Calloc(1, dataLen);
            /* we must do NULL check */
            if (pDstData == NULL) {
                BSL_LIST_FREE(pDstList, pfFreeFunc);
                return NULL;
            }

            (void)memcpy_s(pDstData, dataLen, pSrcData, dataLen);
        }

        if (pDstData == NULL) {
            BSL_LIST_FREE(pDstList, pfFreeFunc);
            return NULL;
        }

        if (BSL_LIST_AddElement(pDstList, pDstData, BSL_LIST_POS_AFTER) != BSL_SUCCESS) {
            if (pfFreeFunc != NULL) {
                pfFreeFunc(pDstData);
            } else {
                BSL_SAL_FREE(pDstData);
            }

            BSL_LIST_FREE(pDstList, pfFreeFunc);
            return NULL;
        }

        pSrcData = BSL_LIST_GET_NEXT(pSrcList);
    }

    return pDstList;
}

void BSL_LIST_DeleteAllAfterSort(BslList *pList)
{
    BslListNode *pNode = NULL;
    BslListNode *pNext = NULL;

    /* check for missing argument */
    if (pList == NULL) {
        return;
    }

    pNode = pList->first;

    /* delete each node one by one */
    while (pNode != NULL) {
        pNext = pNode->next;
        BSL_SAL_FREE(pNode);
        pNode = pNext;
        pList->count--;
    }

    pList->first = pList->last = pList->curr = NULL;
}

BslList *BSL_LIST_Sort(BslList *pList, BSL_LIST_PFUNC_CMP pfCmp)
{
    if (pfCmp == NULL) {
        return NULL;
    }

    int32_t iRet = BSL_ListSortInternal(pList, pfCmp);
    if (iRet != BSL_SUCCESS) {
        return NULL;
    }

    return pList;
}

void BSL_LIST_FreeWithoutData(BslList *pstList)
{
    BslListNode *node = NULL;
    BslListNode *next = NULL;

    if (pstList != NULL) {
        node = pstList->first;
        while (node != NULL) {
            next = node->next;
            BSL_SAL_FREE(node);
            node = next;
        }

        BSL_SAL_FREE(pstList);
    }
}

void BSL_LIST_RevList(BslList *pstList)
{
    struct BslListNode *pstTemp = NULL;

    if (pstList == NULL) {
        return;
    }

    pstList->curr = pstList->first;

    while (pstList->curr != NULL) {
        pstTemp = pstList->curr->next;
        pstList->curr->next = pstList->curr->prev;
        pstList->curr->prev = pstTemp;
        pstList->curr = pstTemp;
    }

    pstList->curr = pstList->first;
    pstList->first = pstList->last;
    pstList->last = pstList->curr;
    pstList->curr = pstList->first;
}

BslList *BSL_ListConcatToEmptyList(BslList *pDestList, const BslList *pSrcList)
{
    pDestList->count = pSrcList->count;
    pDestList->first = pSrcList->first;
    pDestList->last = pSrcList->last;
    pDestList->curr = pDestList->first;

    return pDestList;
}

BslList *BSL_ListConcatToNonEmptyList(BslList *pDestList, const BslList *pSrcList)
{
    if ((pDestList->count + pSrcList->count) > g_maxListCount) {
        return NULL;
    }

    pDestList->count += pSrcList->count;
    pSrcList->first->prev = pDestList->last;
    pDestList->last->next = pSrcList->first;
    pDestList->last = pSrcList->last;

    return pDestList;
}

BslList *BSL_LIST_Concat(BslList *pDestList, const BslList *pSrcList)
{
    if (pDestList == NULL || pSrcList == NULL) {
        return NULL;
    }

    if (pSrcList->count == 0) {
        return pDestList;
    }

    if (pDestList->count == 0) {
        return BSL_ListConcatToEmptyList(pDestList, pSrcList);
    }

    return BSL_ListConcatToNonEmptyList(pDestList, pSrcList);
}
#endif /* HITLS_BSL_LIST */
