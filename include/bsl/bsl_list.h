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

/**
 * @defgroup bsl_list
 * @ingroup bsl
 * @brief linked list
 */

#ifndef BSL_LIST_H
#define BSL_LIST_H

#include <stdint.h>
#include "bsl_errno.h"
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* for handling ASN.1 SET OF type */

/**
 * @ingroup bsl_list
 *
 */
typedef struct BslListNode {
    struct BslListNode *prev; /**< The previous node in the list */
    struct BslListNode *next; /**< The next node in the list */
    void *data;               /**< This must be the last field of this structure */
} BslListNode;

/**
 * @ingroup bsl_list
 *
 */
typedef struct BslList {
    BslListNode *first;     /**< The first node in the list */
    BslListNode *last;      /**< The last node in the list */
    BslListNode *curr;      /**< The current node in the list */
    int32_t count;          /**< count of elements */
    int32_t dataSize;       /**< Memory needed for each node data */
} BslList;

/**
 * @ingroup bsl_list
 *
 * the enum for specifying whether to add the element before/after the
 * current element.  It is used in BSL_LIST_AddElement()
 * @datastruct BSL_LIST_POS_BEFORE Indication to to add the element before the current element.
 * @datastruct BSL_LIST_POS_AFTER Indication to to add the element after the current element.
 * @datastruct BSL_LIST_POS_BEGIN Indication to to add the element at the beginning of the list.
 * @datastruct BSL_LIST_POS_END Indication to to add the element at the end of the list.
 */
typedef enum {
    BSL_LIST_POS_BEFORE, /**< Indication to to add the element before the current element */
    BSL_LIST_POS_AFTER,  /**< Indication to to add the element after the current element */
    BSL_LIST_POS_BEGIN,  /**< Indication to to add the element at the beginning of the list */
    BSL_LIST_POS_END     /**< Indication to to add the element at the end of the list */
} BslListPosition;

/**
 * @ingroup bsl_list
 *
 * This is a pointer to the list comparison function used in BSL_LIST_Search function.
 * It takes two pointers and compares them based on a criteria. If the two are equal a zero is returned.
 * If the first should preceed the second, a negative is returned. Else a positive value is returned.
 */
typedef int32_t (*BSL_LIST_PFUNC_CMP)(const void *, const void *);

/**
 * @ingroup bsl_list
 *
 * This is a pointer to the free function.
 * The free function takes a pointer to data structure to be freed and must return void.
 */
typedef void (*BSL_LIST_PFUNC_FREE)(void *);

/**
 * @ingroup bsl_list
 *
 * This is a pointer to the Copy function.
 * The copy function takes a pointer to data structure to be freed and must return void.
 */
typedef void *(*BSL_LIST_PFUNC_DUP)(const void *);

/*
  The following macros return the specified element of the list.  They do
  not change the current list pointer.
 */
/* returns the current element */
#define BSL_LIST_CURR_ELMT(pList) ((pList) ? ((pList)->curr ? ((pList)->curr->data) : NULL) : NULL)

/* returns the next element */
#define BSL_LIST_NEXT_ELMT(pList) \
    ((pList) ? ((pList)->curr ? ((pList)->curr->next ? ((pList)->curr->next->data) : NULL) : NULL) : NULL)

/* returns the previous element */
#define BSL_LIST_PREV_ELMT(pList) \
    ((pList) ? ((pList)->curr ? ((pList)->curr->prev ? ((pList)->curr->prev->data) : NULL) : NULL) : NULL)

/* returns the last element */
#define BSL_LIST_LAST_ELMT(pList) ((pList) ? ((pList)->last ? ((pList)->last->data) : NULL) : NULL)

/* returns the first element */
#define BSL_LIST_FIRST_ELMT(pList) ((pList) ? ((pList)->first ? ((pList)->first->data) : NULL) : NULL)

/* checks if the list is NULL */
#define BSL_LIST_EMPTY(pList) (((pList) != NULL) ? ((pList)->count == 0) : 0)

/* returns the number of nodes in the list */
#define BSL_LIST_COUNT(pList) ((pList) ? ((pList)->count) : 0)

/* checks if current node is the end */
#define BSL_LIST_IS_END(pList) ((pList) ? (NULL == (pList)->curr) : 0)

/* checks if current node is the first one */
#define BSL_LIST_IS_START(pList) ((pList) ? ((pList)->first == (pList)->curr) : 0)

/* Get the next element */
#define BSL_LIST_GET_NEXT(pList) ((pList) ? (BSL_LIST_Next(pList) ? BSL_LIST_CURR_ELMT(pList) : NULL) : NULL)

/* Get the previous element */
#define BSL_LIST_GET_PREV(pList) ((pList) ? (BSL_LIST_Prev(pList) ? BSL_LIST_CURR_ELMT(pList) : NULL) : NULL)

/* Get the first element */
#define BSL_LIST_GET_FIRST(pList) ((pList) ? (BSL_LIST_First(pList) ? BSL_LIST_CURR_ELMT(pList) : NULL) : NULL)

/* Get the last element */
#define BSL_LIST_GET_LAST(pList) ((pList) ? (BSL_LIST_Last(pList) ? BSL_LIST_CURR_ELMT(pList) : NULL) : NULL)

/**
 * @ingroup bsl_list
 *
 * Delete all the nodes in the list and then frees the header
 */
#define BSL_LIST_FREE(pList, pFreeFunc)        \
    do {                                       \
        BSL_LIST_DeleteAll((pList), pFreeFunc); \
        if (NULL != (pList)) {             \
            BSL_SAL_Free(pList);                  \
            (pList) = NULL;                       \
        }                                      \
    } while (0)


#define SEC_INT_ERROR (-2)

/**
 * @ingroup bsl_list
 *
 * This function sets the max element in BSL_LIST.Default value is 10000000 (10 Million).
 *
 * @param iMaxElements [IN] Max allowed element in BSL_LIST. It should be in range[0xffff, 0xfffffff]
 * @retval #BSL_INVALID_ARG If input falls outside the range.
 * @retval #BSL_SUCCESS If successful.
 */
int32_t BSL_LIST_SetMaxElements(int32_t iMaxElements);

/**
 * @ingroup bsl_list
 *
 * This function returns the max allowed elements in BSL_LIST.
 *
 * @retval int32_t Max configured elements in BSL_LIST
 */
int32_t BSL_LIST_GetMaxElements(void);

/**
 * @ingroup bsl_list
 *
 * This function creates a new node before, after or at the begining or end of the current node. If the list was already
 * NULL, the node will be added as the only node.The current pointer is changed to point to the newly added node in the
 * list. If the current pointer is NULL then this operation fails.
 *
 * @param pList [IN] The list
 * @param pData [IN] The element to be added
 * @param enPosition [IN] Whether the element is to be added before or after the list
 * @retval The error code.
 * @retval #BSL_SUCCESS If successful.
 */
int32_t BSL_LIST_AddElement(BslList *pList, void *pData, BslListPosition enPosition);

/**
 * @ingroup bsl_list
 *
 * This function deletes all the nodes of the list but does not delete the list header.
 *
 * @param pList [IN] The list
 * @param pfFreeFunc [IN] The freefunction to free the data pointer in each node
 */
void BSL_LIST_DeleteAll(BslList *pList, BSL_LIST_PFUNC_FREE pfFreeFunc);

/**
 * @ingroup bsl_list
 *
 * This function deletes the current element of list.
 *
 * @param pList [IN] The list
 * @param pfFreeFunc [IN] The pointer to the free function of data
 */
void BSL_LIST_DeleteCurrent(BslList *pList, BSL_LIST_PFUNC_FREE pfFreeFunc);

/**
 * @ingroup bsl_list
 *
 * This function detaches the current element from the list, the current node will be freed, but the data contained
 * in the current node will not be freed.Also the pList->first, pList->curr and pList->last will be appropriately
 * updated. If the current node is the last node, then pList->curr will point to its previous node after detachment,
 * else it will point to its next node.
 *
 * @param pList [IN] The list
 */
void BSL_LIST_DetachCurrent(BslList *pList);

/**
 * @ingroup bsl_list
 *
 * This function searches a list based on the comparator function
 * supplied (3rd param). The second param is given to the
 * comparator as its second param and each data item on the
 * list is given as its first param while searching. The
 * comparator must return 0 to indicate a match.
 *
 * @param pList [IN] The list
 * @param pSearchFor [IN] The element to be searched
 * @param pSearcher [IN] The pointer to the comparison function of data
 * @retval Void* The element which was found [Void*]
 * @retval Void* If none found [NULL]
 */
void *BSL_LIST_Search(BslList *pList, const void *pSearchFor, BSL_LIST_PFUNC_CMP pSearcher, int32_t *pstErr);

/**
 * @ingroup bsl_list
 *
 * This function returns the node at the given index in the list, starting at 0.
 *
 * @param pList [IN] The list
 * @param ulIndex [IN] The index in the list
 * @retval Void* The element which was found [Void*]
 * @retval Void* If none found [NULL]
 */
void *BSL_LIST_GetIndexNode(uint32_t ulIndex, BslList *pList);

/**
 * @ingroup bsl_list
 *
 * This function dups a list by copying the list by creating a copy of list
 * and returns the destinaton list pointer.
 *
 * @param pSrcList [IN] The list
 * @param pFuncCpy [IN] The dup function for the data in the node
 * @param pfFreeFunc [IN] The pointer to the free function for the data in the node of data
 * @retval BslList* The duplicated List pointer [BslList*]
 * @retval BslList* If dup failed or memory allocation fails.[NULL]
 */
BslList *BSL_LIST_Copy(BslList *pSrcList, BSL_LIST_PFUNC_DUP pFuncCpy, BSL_LIST_PFUNC_FREE pfFreeFunc);

/**
 * @ingroup bsl_list
 *
 * This function sorts the list using the comparison function provided.
 *
 * @param pList [IN] The list
 * @param pfCmp [IN] The comparison function
 * @retval BslList* If unsuccessful [NULL]
 * @retval BslList* If successful [The destination sorted list]
 */
BslList *BSL_LIST_Sort(BslList *pList, BSL_LIST_PFUNC_CMP pfCmp);

/**
 * @ingroup bsl_list
 *
 * This function is used to create a new list.
 *
 * @param dataSize [IN] Size of the data inside the list node
 * @retval BslList* An NULL list [BslList*]
 */
BslList *BSL_LIST_New(int32_t dataSize);

/**
 * @ingroup bsl_list
 *
 * This function returns the data of the current element in the list.
 *
 * @param pstList [IN] Input list
 * @retval void* Data at the current element in the list [void*]
 * @retval void* If the current element does not exist in the list [NULL]
 * @retval void* If memory allocation fails. [NULL]
 */
void *BSL_LIST_Curr(const BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * This function returns the data at the first element of the list.
 *
 * @param pstList [IN] the list
 * @retval void* Data at the first element of the list [void*]
 * @retval void* If the first element does not exist [NULL]
 */
void *BSL_LIST_First(BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * This function returns the data at the last element of the list.
 *
 * @param pstList [IN] The list
 * @retval void* Data at the last element of the list [void*]
 * @retval void* If the last element does not exist [NULL]
 */
void *BSL_LIST_Last(BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * This function advances the current pointer by one and returns the data address of the new
 * current node. If the current pointer is off the list, the new current node
 * will be the first node of the list (unless the list is NULL).
 *
 * @param pstList [IN] The list
 * @retval void* Pointer to the next element in the list [void*]
 * @retval void* If the next element does not exist [NULL]
 */
void *BSL_LIST_Next(BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * backs up the current pointer by one and returns the data address of the new
 * current node. If the current pointer is off the list, the new current node
 * will be the last node of the list (unless the list is NULL).
 *
 * @param pstList [IN] The list
 * @retval void* Pointer to the previous element in the list [void*]
 * @retval void* If the previous element does not exist[NULL]
 */
void *BSL_LIST_Prev(BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * This function returns the index (starting a 0 for the first element)
 * of the given element in the given list.
 * Returns -1, if the element is not in the list.
 * Assumes that the list node contains a single pointer.
 *
 * @param elmt [IN] The element whose index is to be retrieved
 * @param pstList [IN] The list to which the element belongs to
 * @retval int32_t The index of the specified element in the given list [int32_t]
 * @retval int32_t If the element is not found in the list [-1]
 */
int32_t BSL_LIST_GetElmtIndex(const void *elmt, BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * This function is used to concatenate list 2 to list 1.
 *
 * @param pDestList [IN] The list to which the 2nd list is to be concatenated to.
 * @param pSrcList [IN] The list which is to be concatenated.
 * @retval BslList* The concatenated list. [BslList*]
 */
BslList *BSL_LIST_Concat(BslList *pDestList, const BslList *pSrcList);

/**
 * @ingroup bsl_list
 *
 * This function is used to free the Asn list.
 *
 * @param pstList [IN] list Pointer to the Asn list which has to be freed
 * @retval void This function does not return any value.
 */
void BSL_LIST_FreeWithoutData(BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * This function is used to  reverse the linked list.
 *
 * @param pstList [IN] Pointer to the list which has to be reversed
 * @retval void This function does not return any value.
 */
void BSL_LIST_RevList(BslList *pstList);

/**
 * @ingroup bsl_list
 *
 * This function set the max qsort Size.Default value is 100000
 *
 * @param uiQsortSize [IN] Max Buff Size. it should in range of [10000, 67108864] Default value is 100000
 * @retval int32_t BSL_SUCCESS on success BSL_INVALID_ARG on Failure.
 */
int32_t BSL_LIST_SetMaxQsortCount(uint32_t uiQsortSize);

/**
 * @ingroup bsl_list
 *
 * This function returns the MAX qsort Size
 *
 * @retval uint32_t Returns the max qsort Size.
 */
uint32_t BSL_LIST_GetMaxQsortCount(void);

/**
 * @ingroup bsl_list
 *
 * Delete all the nodes in the list.
 * But it does not delete the data pointers inside the list nodes.
 * It is used only after sort to delete the input list to the sort function.
 *
 * @param pList [IN] The list.
 */
void BSL_LIST_DeleteAllAfterSort(BslList *pList);

/**
 * @ingroup bsl_list
 *
 * This function returns the first element of the list.
 *
 * @param list [IN] The list.
 * @retval BslListNode* first element of the list [BslListNode*]
 * @retval BslListNode* If the first element does not exist [NULL]
 */
BslListNode *BSL_LIST_FirstNode(const BslList *list);

/**
 * @ingroup bsl_list
 *
 * This function returns the data of the passed list node.
 *
 * @param pstNode [IN] The node.
 * @retval void* Data of the passed list node. [void*]
 * @retval void* If the data is not present in the list node. [NULL]
 */
void *BSL_LIST_GetData(const BslListNode *pstNode);

/**
 * @ingroup bsl_list
 *
 * This function advances the current reference pointer by one and returns the
 * new current node. If the current reference pointer is off the list,
 * the new current node will be the first node of the list
 * (unless the list is NULL).
 *
 * @param pstList [IN] The list.
 * @param pstListNode [IN] The list node.
 * @retval BslListNode* Pointer to next element in the list. [void*]
 * @retval BslListNode* If the next element does not exist. [NULL]
 */
BslListNode *BSL_LIST_GetNextNode(const BslList *pstList, const BslListNode *pstListNode);

/**
 * @ingroup bsl_list
 *
 * This function backs up the current reference pointer by one and returns the
 * new current node.
 *
 * @param pstListNode [IN] The list node.
 * @retval BslListNode* Pointer to the previous element in the list
 * @retval BslListNode* If the previous element does not exist[NULL]
 */
BslListNode *BSL_LIST_GetPrevNode(const BslListNode *pstListNode);

/**
 * @ingroup bsl_list
 *
 * This function deletes the matching input node from the input list.
 *
 * @param pstList [IN] The list.
 * @param pstListNode [IN] The current reference node.
 * @param pfFreeFunc [IN] The pointer to the free function of data.
 */
void BSL_LIST_DeleteNode(BslList *pstList, const BslListNode *pstListNode, BSL_LIST_PFUNC_FREE pfFreeFunc);

/**
 * @ingroup bsl_list
 *
 * This function detaches the matching input node from the input list.
 * The node will be freed but, the data contained in the
 * node will not be freed, and also the pList->first, pList->curr,
 * and pList->last will be appropriately updated. If the matching node
 * is the last node, then pList->curr will point to its previous node
 * after detachment, else it will point to its next node.
 *
 * @param pstList [IN] The list.
 * @param pstListNode [in/out] when it is input parameter, it is the list node to be detached.
 */
void BSL_LIST_DetachNode(BslList *pstList, BslListNode **pstListNode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // BSL_LIST_H
