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
 * @defgroup bsl_list bidirectional linked list
 * @ingroup bsl
 */

#ifndef BSL_HASH_LIST_H
#define BSL_HASH_LIST_H

#include "hitls_build.h"
#ifdef HITLS_BSL_HASH

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_list
 * @brief User data copy function prototype
 * @attention Note: The source buffer length needs to be obtained by the caller.
 * Because the data type and length are unknown, the hook function needs to be implemented by the service side.
 * @param ptr [IN] Pointer to user data
 * @param size [IN] User data copy length
 * @retval Destination buffer. NULL indicates failure.
 */
typedef void *(*ListDupFunc)(void *ptr, size_t size);

/**
 * @ingroup bsl_list
 * @brief User memory release function prototype
 * @par Description: resource release function prototype, which is generally used to release memory in batches.
 * The memory may contain private resources, which need to be released by users.
 * @param ptr    [IN] Pointer to user data
 * @retval None
 */
typedef void (*ListFreeFunc)(void *ptr);

/**
 * @ingroup bsl_list
 * @brief Match the function prototype.
 * @par Description: used to match the query.
 * @attention Note: Only the function prototype is defined here. Because the user query matching mechanism is unknown,
 * the hook function needs to be implemented by the service side.
 * @param node    [IN] Algorithm structure node
 * @param data    [IN] Key information
 * @retval true: Matching succeeded.
 * @retval false Matching failure
 */
typedef bool (*ListMatchFunc)(const void *node, uintptr_t data);

/**
 * @ingroup bsl_list
 * @brief Compare function prototype
 * @par Description: Compare function prototype, which is used in sorting.
 * @attention Note: Only the comparison function prototype is defined here. The data type and length are unknown.
 * Therefore, the hook function needs to be implemented by the service side.
 * The current source code has a default comparison function. This function is not provided externally.
 * If the default comparison method is not specified, it will be invoked.
 * The comparison method is to convert the current data into a signed number for comparison,
 * that is, to process the case with negative numbers in ascending order.
 * If the data to be stored is of the unsigned integer type, The sorting result may not be expected at this time.
 * To compare data in this case, we need to customize the comparison function.
 * For example, for a BIGNUM A = uintptr_t(-1) and a BIGNUM B = 1ULL << 50, the current function considers A < B.
 * Actually, A is greater than B.
 * To sum up, the user should write the comparison function based on the data type
 * (including descending order or other comparison rules).
 */
typedef int32_t (*ListKeyCmpFunc)(uintptr_t key1, uintptr_t key2);

/**
 * @ingroup bsl_list
 * @brief Hook for saving memory application and release.
 */
typedef struct {
    ListDupFunc dupFunc;
    ListFreeFunc freeFunc;
} ListDupFreeFuncPair;

/**
 * @ingroup bsl_list
 * list header
 */
typedef struct BslListSt BSL_List;

/**
 * @ingroup bsl_list
 * Linked list iterator (node) definition
 */
typedef struct BslListNodeSt *BSL_ListIterator;

/**
 * @ingroup bsl_list
 * @brief Initialize the linked list.
 * @par Description: Initialize the linked list and
 *      register the user data dup function and user data resource free function as required.
 * @attention
 * 1. If the data to be stored is of the integer type and the length <= sizeof(uintptr_t),
 *    do not need to register dataFunc&dupFunc and assign it empty.
 * 2. If the user data is string or other customized complex data type
 *    and the data life cycle is shorter than the node life cycle, user must register dataFunc->dupFunc for data copy.
 * @param list       [IN] Linked list
 * @param dataFunc   [IN] User data copy and release function pair. If dataFunc and dupFunc are not registered,
 *                        the default data type is integer.
 * @retval #BSL_SUCCESS 0 indicates that the linked list is successfully initialized.
 */
int32_t BSL_ListInit(BSL_List *list, const ListDupFreeFuncPair *dataFunc);

/**
 * @ingroup bsl_list
 * @brief Clear the node in the linked list and delete all nodes.
 * @par Description: Clear the linked list node, delete all nodes, invoke the free function registered by the user
 *      to release user resources, and return to the status after initialization of the linked list.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The linked list is cleared successfully.
 */
int32_t BSL_ListClear(BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Deinitialize the linked list.
 * @par Description: Deinitialize the linked list: Delete all nodes,
 *      invoke the free function registered by the user to release user resources, and deregister the hook function.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The linked list is successfully de-initialized.
 */
int32_t BSL_ListDeinit(BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Check whether the linked list is empty.
 * @param list [IN] Linked list to be checked
 * @retval #true  1: The linked list is null or no data exists.
 * @retval #false 0: The linked list is not empty.
 * @li bsl_list.h: header file where the API declaration is located.
 */
bool BSL_ListIsEmpty(const BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Obtain the number of nodes in the linked list.
 * @param list [IN] Linked list
 * @retval Number of linked list nodes
 * @li bsl_list.h: header file where the API declaration is located.
 */
size_t BSL_ListSize(const BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Insert user data into the header of the linked list.
 * @param list         [IN] Linked list
 * @param userData     [IN] Data to be inserted or pointer to user private data
 * @param userDataSize [IN] Data copy length. If the user has not registered the dupFunc, this parameter is not used.
 * @retval #BSL_SUCCESS Data is successfully inserted.
 * @li bsl_list.h: header file where this function declaration is located.
 */
int32_t BSL_ListPushFront(BSL_List *list, uintptr_t userData, size_t userDataSize);

/**
 * @ingroup bsl_list
 * @brief Insert user data to the end of the linked list.
 * @param list         [IN] Linked list
 * @param userData     [IN] Data to be inserted or pointer to user private data
 * @param userDataSize [IN] Data copy length. If the user has not registered the dupFunc, this parameter is not used.
 * @retval #BSL_SUCCESS Data is successfully inserted.
 * @li bsl_list.h: header file where this function declaration is located.
 */
int32_t BSL_ListPushBack(BSL_List *list, uintptr_t userData, size_t userDataSize);

/**
 * @ingroup bsl_list
 * @brief POP a node from the header of the linked list.
 * @par Description: Remove the head node from the linked list and release the node memory.
 * If the free function is registered during initialization, the hook function is called to release private resources.
 * If the linked list is empty, nothing will be done.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The header is removed successfully.
 * @li bsl_list.h: header file where the API declaration is located.
 */
int32_t BSL_ListPopFront(BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief POP a node from the end of the linked list.
 * @par Description: Remove the tail node from the linked list and release the node memory.
 * If the free function is registered during initialization, the hook function is called to release private resources.
 * If the linked list is empty, nothing will be done.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The tail is removed successfully.
 * @li bsl_list.h: header file where the API declaration is located.
 */
int32_t BSL_ListPopBack(BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Access the header node of the linked list and return the user data of the header node.
 * @par Description: Access the header node of the linked list and return the user data of the header node.
 * @attention Note: If the linked list is empty,
 *                  it cannot be distinguished whether the linked list is empty and the returned data is 0.
 *                  Therefore, before calling this function, we must check whether the linked list is empty.
 * @param list [IN] Linked list
 * @retval User data/pointer of the head node. If the linked list is empty, 0 is returned.
 * @li bsl_list.h: header file where this function declaration is located.
 */
uintptr_t BSL_ListFront(const BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Access the tail node of the linked list and return the user data of the tail node.
 * @attention Note: If the linked list is empty,
 *                  it cannot be distinguished whether the linked list is empty and the returned data is 0.
 *                  Therefore, we must check whether the linked list is empty before calling this function.
 * @param list [IN] Linked list
 * @retval User data/pointer of the tail node. If the linked list is empty, 0 is returned.
 * @li bsl_list.h: header file where the API declaration is located.
 */
uintptr_t BSL_ListBack(const BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Obtain the iterator of the header node of the linked list.
 * @param list [IN] Linked list
 * @retval Head node iterator of the linked list. If the linked list is empty, it points to the header.
 * @li bsl_list.h: header file where this function declaration is located.
 */
BSL_ListIterator BSL_ListIterBegin(const BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Obtain the iterator of the next node of the tail.
 * @param list [IN] Linked list
 * @attention If the input list is NULL, NULL will be returned. Therefore, user need to use correct parameters.
 * @retval Next node iterator of the tail (pointing to the head of the linked list).
 * @li bsl_list.h: header file where the API declaration is located.
 */
BSL_ListIterator BSL_ListIterEnd(BSL_List *list);

/**
 * @ingroup bsl_list
 * @brief Obtain the iterator of the previous node.
 * @param list [IN] Linked list
 * @param it   [IN] Iterator
 * @attention If the input list is NULL or iterator it is not a valid part of the list, NULL is returned.
 *            Therefore, user need to use the correct parameter.
 * @retval list is not empty, return the previous node iterator.
 * @retval list is NULL, and NULL is returned.
 * @li bsl_list.h: header file where the API declaration is located.
 */
BSL_ListIterator BSL_ListIterPrev(const BSL_List *list, const BSL_ListIterator it);

/**
 * @ingroup bsl_list
 * @brief Obtain the iterator of the next node.
 * @param list [IN] Linked list
 * @param it   [IN] Iterator
 * @attention If the input list is NULL or iterator it is not a valid part of the list, NULL is returned.
 *            Therefore, user need to use the correct parameter.
 * @retval Returns the iterator of the next node if the value is not null.
 * @retval list is NULL, and NULL is returned.
 * @li bsl_list.h: header file where the API declaration is located.
 */
BSL_ListIterator BSL_ListIterNext(const BSL_List *list, const BSL_ListIterator it);

/**
 * @ingroup bsl_list
 * @brief Insert data before the node pointed to by the specified iterator.
 * @param list         [IN] Linked list
 * @param it           [IN] Current iterator position
 * @param userData     [IN] Data to be inserted or pointer to user private data
 * @param userDataSize [IN] Data copy length. If the user has not registered the dupFunc, this parameter is not used.
 * @retval #BSL_SUCCESS Data is successfully inserted.
 * @li bsl_list.h: header file where this function declaration is located.
 */
int32_t BSL_ListInsert(BSL_List *list, const BSL_ListIterator it, uintptr_t userData, size_t userDataSize);

/**
 * @ingroup bsl_list
 * @brief Delete a specified node from the linked list and release the node memory.
 * @par Description: Delete the specified node from the linked list and release the node memory.
 *                   If the free function is registered during initialization,
 *                   the hook function is invoked to release private resources such as handles and pointers in user data
 * @attention If the input list is NULL or iterator it is not a valid part of the list, NULL is returned.
 *            Therefore, user need to use the correct parameter.
 * @param list [IN] Linked list
 * @param it   [IN] Iterator of the node to be deleted.
 * @retval Next node iterator of the deleted node. If the deleted node is the tail node,
 *         the returned iterator points to the header of the linked list.
 * @li bsl_list.h: header file where this function declaration is located.
 */
BSL_ListIterator BSL_ListIterErase(BSL_List *list, BSL_ListIterator it);

/**
 * @ingroup bsl_list
 * @brief Obtain user data.
 * @attention The caller must ensure the validity of the parameter. If the input parameter is invalid, 0 is returned.
 *            The caller cannot distinguish whether the returned value 0 is normal data
 *            or whether the returned value is 0 due to invalid parameters.
 * @param it [IN] Linked list iterator
 * @retval User data
 * @li bsl_list.h: header file where this function declaration is located.
 */
uintptr_t BSL_ListIterData(const BSL_ListIterator it);

/**
 * @ingroup bsl_list
 * @brief Searches for the desired iterator, that is, the node pointer,
 *        based on the user-defined iterator matching function.
 * @par Description: Searches for the desired iterator, that is, the node pointer,
 *                   based on the user-defined iterator matching function.
 * @attention
 * 1. Traversefrom the header and call the matching function for each node in turn
 *    until the first matching node is found or the traversal ends at the tail of the linked list.
 * 2. The first input parameter address of the matching function hook entered by the user
 *    is the userdata of each node to be searched. The input parameter type is uintptr_t.
 * 3. If the input list is NULL or the comparison function is NULL, NULL is returned.
 *    Therefore, user need to use correct parameters.
 * @param list           [IN] Linked list
 * @param iterCmpFunc    [IN] Hook of match function.
 * @param data           [IN] Data information
 * @retval not NULL      Query succeeded, the matching node iterator is returned.
 * @retval NULL          Query failed.
 * @li bsl_list.h: header file where this function declaration is located.
 */
BSL_ListIterator BSL_ListIterFind(BSL_List *list, ListKeyCmpFunc iterCmpFunc, uintptr_t data);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */

#endif // BSL_HASH_LIST_H
