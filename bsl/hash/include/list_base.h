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
 * @defgroup list_base Raw bidirectional linked list
 * @ingroup bsl
 */

#ifndef LIST_BASE_H
#define LIST_BASE_H

#include "hitls_build.h"
#ifdef HITLS_BSL_HASH

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "bsl_hash_list.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_base
 * This struct is used to store the forward pointer and backward pointer of the node in the bidirectional linked list.
 * This linked list does not contain a substantial data area and is generally used to organize (concatenate) data nodes.
 */
struct ListTagRawListNode {
    struct ListTagRawListNode *next;     /* points to the next node */
    struct ListTagRawListNode *prev;     /* points to the previous node */
};

/**
 * @ingroup bsl_base
 * list node
 */
typedef struct ListTagRawListNode ListRawNode;

/**
 * @ingroup bsl_base
 * Linked list header, which cannot store data.
 */
typedef struct {
    ListRawNode  head;       /* list node */
    /* Node memory release function, which needs to release nodes and other private resources on node */
    ListFreeFunc freeFunc;
} RawList;

/**
 * @ingroup bsl_base
 * Linked list header, which can apply for data memory and is used by external functions.
 */
struct BslListSt {
    RawList rawList; /* Linked list header */
    ListDupFreeFuncPair dataFunc; /* used to store data */
};

/**
 * @ingroup bsl_base
 * Bidirectional linked list node.
 * This structure is used to store the forward pointer and backward pointer of the nodes in the bidirectional list,
 * and a small amount of user data or pointers.
 */
struct BslListNodeSt {
    ListRawNode rawNode;
    uintptr_t userdata;
};

/**
 * @ingroup bsl_base
 * @brief Initialize the linked list.
 * @par Description: Initializes the list, registers the private resource release function in user data as required.
 * This function does not apply for resources.
 * @attention
 * 1: The linked list nodes in the crawlist module are encapsulated and memory is applied for by users.
 *    The rawlist is only used to maintain the linked list, and its resources are released by users in freeFunc.
 * 2: When a user adds data, the parameter transferred to the rawlist is the ListRawNode node.
 *    Therefore, the parameter transferred to the freeFunc by the rawlist is also the ListRawNode node.
 * @param list [IN] Linked list.
 * @param freeFunc [IN] User resource release function.
 * @retval #BSL_SUCCESS 0. The linked list is successfully initialized.
 */
int32_t ListRawInit(RawList *list, ListFreeFunc freeFunc);

/**
 * @ingroup bsl_base
 * @brief Clear the node in the linked list and delete all nodes.
 * @par Description: Clear the linked list node, delete all nodes,
 * invoke the free function registered by the user to release private resources,
 * and return to the status after initialization of the linked list.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The linked list is cleared successfully.
 */
int32_t ListRawClear(RawList *list);

/**
 * @ingroup bsl_base
 * @brief Deinitialize the linked list.
 * @par Description: Deinitialize the linked list:
 * Delete all nodes, invoke the free function registered by the user to release private resources,
 * and deregister the hook function. But the list head is still there.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The linked list is successfully deinitialized.
 */
int32_t ListRawDeinit(RawList *list);

/**
 * @ingroup bsl_base
 * @brief Check whether the linked list is empty.
 * @param list [IN] Linked list to be checked
 * @retval #true 1. The linked list is empty or has no data.
 * @retval #false 0. The linked list is not empty.
 * @li bsl_base.h: header file where the function declaration is located.
 */
bool ListRawEmpty(const RawList *list);

/**
 * @ingroup bsl_base
 * @brief Obtain the number of nodes in the linked list.
 * @param list [IN] Linked list
 * @retval Number of linked list nodes
 * @li bsl_base.h: header file where the function declaration is located.
 */
size_t ListRawSize(const RawList *list);

/**
 * @ingroup bsl_base
 * @brief Insert a node at the header of the linked list.
 * @param list [IN] Linked list
 * @param node [IN] Node to be inserted
 * @retval #BSL_SUCCESS 0. Inserted successfully in the header of the linked list.
 */
int32_t ListRawPushFront(RawList *list, ListRawNode *node);

/**
 * @ingroup bsl_base
 * @brief Insert a node at the end of the linked list.
 * @param list [IN] Linked list
 * @param node [IN] Node to be inserted
 * @retval #BSL_SUCCESS 0. Inserted successfully in the tail of the linked list.
 */
int32_t ListRawPushBack(RawList *list, ListRawNode *node);

/**
 * @ingroup bsl_base
 * @brief Insert a node before a specified node.
 * @param curNode [IN] Specified node
 * @param newNode [IN] Node to be inserted
 * @retval #BSL_SUCCESS 0 indicates that the linked list is inserted successfully.
 */
int32_t ListIRawnsert(const ListRawNode *curNode, ListRawNode *newNode);

/**
 * @ingroup bsl_base
 * @brief POP a node from the header of the linked list.
 * @par Description: Removes the head node from the linked list.
 * If the free function is registered during initialization, the hook function is also called to release user resources.
 * If the linked list is empty, nothing will be done.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The header of the linked list is popped successfully.
 */
int32_t ListRawPopFront(RawList *list);

/**
 * @ingroup bsl_base
 * @brief POP a node from the end of the linked list.
 * @par Description: Remove the tail node from the linked list.
 * If the free function is registered during initialization, the hook function is also called to release user resources.
 * If the linked list is empty, nothing will be done.
 * @param list [IN] Linked list
 * @retval #BSL_SUCCESS 0. The tail of the linked list is popped successfully.
 */
int32_t ListRawPopBack(RawList *list);

/**
 * @ingroup bsl_base
 * @brief Delete a specified node from the linked list.
 * @par Description:
 * 1. If the list is NULL and the node is in the linked list, only the node is removed from the linked list.
 * 2. If the list is not null and the node is in the linked list, the node is removed from the linked list.
 *    If the free function is registered during initialization, the hook function is invoked to release user resources.
 * @param list [IN] Linked list
 * @param node [IN] Node to be deleted
 * @retval #BSL_SUCCESS 0. The linked list is deleted successfully.
 * @li bsl_base.h: header file where the function declaration is located.
 */
int32_t ListRawRemove(RawList *list, ListRawNode *node);

/**
 * @ingroup bsl_base
 * @brief Return the head node pointer.
 * @par Description: It is used only to access the head node and will not delete the node.
 * If the linked list is NULL, NULL is returned.
 * @param list [IN] Linked list
 * @attention If the input parameter is incorrect, NULL is returned. The user needs to use the correct parameter.
 * @retval not NULL  Pointer to the head node.
 * @retval NULL      The linked list is NULL.
 * @li bsl_base.h: header file where the function declaration is located.
 */
ListRawNode *ListRawFront(const RawList *list);

/**
 * @ingroup bsl_base
 * @brief Return the tail node pointer.
 * @par Description: It is used only to access the tail node and will not delete the tail node.
 * If the linked list is NULL, NULL is returned.
 * @param list [IN] Linked list
 * @attention If the input parameter is incorrect, NULL is returned. The user needs to use the correct parameter.
 * @retval not NULL  Pointer to the tail node.
 * @retval NULL      The linked list is NULL.
 * @li bsl_base.h: header file where the function declaration is located.
 */
ListRawNode *ListRawBack(const RawList *list);

/**
 * @ingroup bsl_base
 * @brief Obtain the previous node of the current node.
 * @par Description: Obtains the pointer of the previous node of the current node.
 * If the current node is the head node, NULL is returned.
 * @param list [IN] Linked list
 * @param node [IN] Current node
 * @attention If the input parameter is incorrect, NULL is returned. The user needs to use the correct parameter.
 * @retval Non-NULL  Previous node of the current node
 * @retval NULL      The previous node of the head node is empty.
 * @li bsl_base.h: header file where the function declaration is located.
 */
ListRawNode *ListRawGetPrev(const RawList *list, const ListRawNode *node);

/**
 * @ingroup bsl_base
 * @brief Obtain the next node of the current node.
 * @par Description: Obtains the pointer to the next node of the current node.
 * If the current node is the tail node, NULL is returned.
 * @param list [IN] Linked list
 * @param node [IN] Current node
 * @attention If the input parameter is incorrect, NULL is returned. The user needs to use the correct parameter.
 * @retval: non-NULL    node next to the current node
 * @retval: NULL        The next node of the tail node is null.
 * @li bsl_base.h: header file where the function declaration is located.
 */
ListRawNode *ListRawGetNext(const RawList *list, const ListRawNode *node);

/**
 * @ingroup bsl_base
 * @brief Searches for the desired node based on the node matching function defined by the user.
 * @par Description: Searches for the desired node based on the node matching function defined by the user.
 * @attention
 * 1. Traverse from the header of the linked list and call the matching function for each node in turn
 *    until the first matching node is found or the traversal ends at the tail of the linked list.
 * 2. Hook of the matching function entered by the user.
 *    Its first input parameter address is the value of each node to be searched.
 *    The input parameter type is ListRawNode *.
 * 3. For the implementation in the matching hook,
 *    needs to be offset to the user structure information according to the node address before matching and comparison.
 * 4. If the input parameter is incorrect, NULL is returned. The user needs to use the correct parameter.
 * @param list [IN] Linked list
 * @param nodeMatchFunc [IN] hook of match function.
 * @param data [IN] critical information
 * @retval non-NULL     The query is successful, the node pointer is returned.
 * @retval NULL         Query failed. No matching node is found.
 * @li bsl_base.h: header file where the function declaration is located.
 */
ListRawNode *ListRawFindNode(const RawList *list, ListMatchFunc nodeMatchFunc, uintptr_t data);

/**
 * @ingroup bsl_base
 * @brief This API obtains the start address of the structure through a member variable of the structure.
 * @par Description:
 * This API obtains the start address of the structure through a member variable of the structure.
 * This API is a special macro, and the input parameters depend on the implementation of the macro.
 * @attention
 * @param ptr [IN] The address of a member on a node. The value range is Data Type.
 * @param type [IN] The node type structure to which the transferred member belongs. The value range is Data Type.
 * @param member [IN] The name of a member variable in the structure. The value range is Data Type.
 * @retval Address of the same structure as the input parameter type.
 * @see none.
 */
#define BSL_CONTAINER_OF(ptr, type, member) \
    ((type *)((uintptr_t)(ptr) - (uintptr_t)(&(((type *)0)->member))))

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */

#endif // LIST_BASE_H
