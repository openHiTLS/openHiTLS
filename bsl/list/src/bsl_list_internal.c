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

#include <stdlib.h>
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_list_internal.h"

#define SEC_MAX_QSORT_SIZE (64 * 1024 * 1024)
#define SEC_MIN_QSORT_SIZE 10000

static uint32_t g_maxQsortElem = 100000;

BslList *BSL_LIST_New(int32_t dataSize)
{
    BslList *pstList = NULL;

    if (dataSize < 0) {
        return NULL;
    }
    pstList = BSL_SAL_Calloc(1, sizeof(BslList));
    if (pstList == NULL) {
        return NULL;
    }

    pstList->curr = NULL;
    pstList->last = NULL;
    pstList->first = NULL;
    pstList->dataSize = dataSize;
    pstList->count = 0;

    return pstList;
}

void *BSL_LIST_Prev(BslList *pstList)
{
    if (pstList == NULL) {
        return NULL;
    }

    if (pstList->curr != NULL) {
        pstList->curr = pstList->curr->prev;
    } else {
        pstList->curr = pstList->last;
    }

    if (pstList->curr != NULL) {
        return (void *)&(pstList->curr->data);
    }

    return NULL;
}

void *BSL_LIST_Next(BslList *pstList)
{
    if (pstList == NULL) {
        return NULL;
    }

    if (pstList->curr != NULL) {
        pstList->curr = pstList->curr->next;
    } else {
        pstList->curr = pstList->first;
    }

    if (pstList->curr != NULL) {
        return (void *)&(pstList->curr->data);
    }

    return NULL;
}

void *BSL_LIST_Last(BslList *pstList)
{
    if (pstList == NULL) {
        return NULL;
    }

    pstList->curr = pstList->last;

    if (pstList->curr != NULL) {
        return (void *)&(pstList->curr->data);
    }

    return NULL;
}

void *BSL_LIST_First(BslList *pstList)
{
    if (pstList == NULL) {
        return NULL;
    }

    pstList->curr = pstList->first;

    if (pstList->curr != NULL) {
        return (void *)&(pstList->curr->data);
    }

    return NULL;
}

void *BSL_LIST_Curr(const BslList *pstList)
{
    if (pstList == NULL || pstList->curr == NULL) {
        return NULL;
    }

    return (void *)&(pstList->curr->data);
}

int32_t BSL_LIST_GetElmtIndex(const void *elmt, BslList *pstList)
{
    int32_t idx = 0;
    void *tmpElmt = NULL;

    if (pstList == NULL) {
        return -1;  // -1 means that the corresponding element is not found
    }

    BslListNode *tmp = pstList->curr;
    for (pstList->curr = pstList->first; pstList->curr != NULL; pstList->curr = pstList->curr->next) {
        tmpElmt = pstList->curr->data;
        if (tmpElmt == NULL) {
            break;
        }
        if (tmpElmt != elmt) {
            idx++;
            continue;
        }

        pstList->curr = tmp;
        return idx;
    }

    pstList->curr = tmp;

    return -1;  // -1 means that the corresponding element is not found
}

int32_t BSL_ListSortInternal(BslList *pList, BSL_LIST_PFUNC_CMP cmp)
{
    void **sortArray = NULL;
    void *elmt = NULL;
    int32_t i;

    /* Make sure pList is not NULL */
    if (pList == NULL || g_maxQsortElem < (uint32_t)pList->count) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    /* Create array of elements so we can qsort the pList */
    sortArray = BSL_SAL_Calloc((uint32_t)(pList->count), sizeof(void *));
    if (sortArray == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return BSL_LIST_MALLOC_FAIL;
    }

    /* Copy the elements from the pList into the sort array */
    for (pList->curr = pList->first, i = 0; pList->curr != NULL; pList->curr = pList->curr->next, i++) {
        elmt = pList->curr->data;
        if (elmt == NULL || i >= pList->count) {
            break;
        }

        sortArray[i] = elmt;
    }
    /* sort encoded elements */
    qsort(sortArray, (uint32_t)pList->count, sizeof(void *), (int (*)(const void *, const void *))cmp);

    for (pList->curr = pList->first, i = 0; pList->curr != NULL; pList->curr = pList->curr->next, i++) {
        pList->curr->data = sortArray[i];
    }

    BSL_SAL_FREE(sortArray);

    /* Return the sorted pList */
    return BSL_SUCCESS;
}

int32_t BSL_LIST_SetMaxQsortCount(uint32_t uiQsortSize)
{
    if ((uiQsortSize > SEC_MAX_QSORT_SIZE) || (uiQsortSize < SEC_MIN_QSORT_SIZE)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    g_maxQsortElem = uiQsortSize;
    return BSL_SUCCESS;
}

uint32_t BSL_LIST_GetMaxQsortCount(void)
{
    return g_maxQsortElem;
}
#endif /* HITLS_BSL_LIST */
