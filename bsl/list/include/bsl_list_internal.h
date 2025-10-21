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

#ifndef BSL_LIST_INTERNAL_H
#define BSL_LIST_INTERNAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_LIST

#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Sort the list in ascending order of content */
int32_t BSL_ListSortInternal(BslList *pList, int32_t((*cmp)(const void *, const void *)));

/**
 * @ingroup bsl_list
 * @brief To return the data of the node at the given index in the list, starting at 0.
 *
 * @param[IN] ulIndex The index in the list.
 * @param[IN] pstListNode The list node.
 * @param[IN] pstList The list.
 *
 * @retval void* The element which was found. [void *]
 * @retval void* If none found. [NULL]
 */
void *BSL_LIST_GetIndexNodeEx(uint32_t ulIndex, const BslListNode *pstListNode, const BslList *pstList);

/**
 * @ingroup bsl_list
 * @brief This function searches a list based on the comparator function supplied (3rd param).
 * The second param is given to the comparator as its second param and each data item on the
 * list is given as its first param while searching. The comparator must return 0 to indicate a match.
 *
 * The Search callback function should return -2(SEC_INT_ERROR) if search should not be continued anymore.
 *
 * @param[IN] pList The list.
 * @param[IN] pSearchFor The element to be searched.
 * @param[IN] pSearcher The pointer to the comparison function of data.
 * @param[OUT] pstErr Error codes for internal error. [-2/0]
 *
 * @retval Void* The element which was found [Void*]
 * @retval Void* If none found [NULL]
 */
void *BSL_LIST_SearchEx(BslList *pList, const void *pSearchFor, BSL_LIST_PFUNC_CMP pSearcher);

 /**
 * @ingroup bsl_list
 * @brief This creates a new node before/after/At end /begin of the current node. If the list was already empty,
 * the node will be added as the only node.The current pointer is changed to point to the newly added node in the list.
 * If the current pointer is NULL then this operation fails.
 *
 * @param[IN] pList The list.
 * @param[IN] pData The element to be added.
 * @param[IN] enPosition Whether the element is to be added before/after the list
 *
 * @retval uint32_t, The error code
 *         BSL_LIST_INVALID_LIST_CURRENT: If current pointer is NULL
 *         BSL_LIST_DATA_NOT_AVAILABLE: If data pointer is NULL
 *         BSL_MALLOC_FAIL: If failure to allocate memory for new node
 *         BSL_SUCCESS: If successful
 */
int32_t BSL_LIST_AddElementInt(BslList *pList, void *pData, BslListPosition enPosition);

#define CURR_LIST_NODE(al) ((al)->curr)

#define SET_CURR_LIST_NODE(al, listNode) ((al)->curr = (listNode))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_BSL_LIST */

#endif // BSL_LIST_INTERNAL_H
