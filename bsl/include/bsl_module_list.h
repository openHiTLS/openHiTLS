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

#ifndef BSL_MODULE_LIST_H
#define BSL_MODULE_LIST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This structure is used to store the forward and backward pointers of nodes in the bidirectional linked list.
 * This linked list does not contain substantial data areas and is generally used to organize (concatenate) data nodes.
 */
typedef struct ListHeadSt {
    struct ListHeadSt *next, *prev;
} ListHead;

/**
 * @brief initialize the linked list when the linked list is reused
 *
 * @param head [IN] The address of the head node of the list
 */
#define LIST_INIT(head) (head)->next = (head)->prev = (head)

/**
 * @brief Insert the 'item' node after the 'where' node.
          Before the change: where->A->B. After the change: where->item->A->B
 *
 * @param where [IN] The address where the item will be inserted after
 * @param item  [IN] Address of the node(item) to be inserted
 */
#define LIST_ADD_AFTER(where, item) do {  \
    (item)->next       = (where)->next; \
    (item)->prev       = (where);       \
    (where)->next      = (item);        \
    (item)->next->prev = (item);        \
} while (0)

/**
 * @brief Insert the 'item' node before the 'where' node.
 *        Before change: A->where->B. After change: A->item->where->B
 *
 * @param where [IN] The address where the item will be inserted before
 * @param item  [IN] Address of the node to be inserted
 */
#define LIST_ADD_BEFORE(where, item) LIST_ADD_AFTER((where)->prev, (item))

/**
 * @brief Delete the node item.
 *
 * @param item [IN] The address of the item to be removed
 */
#define LIST_REMOVE(item) do { \
    (item)->prev->next = (item)->next; \
    (item)->next->prev = (item)->prev; \
} while (0)

/**
 * @brief Check whether a list is empty
 *
 * @param head [IN] The address of the list to be checked.
 */
#define LIST_IS_EMPTY(head) ((head)->next == (head))

/**
 * @brief Travel through a list safety
 *
 * @param head [IN] Linked list to be traversed (The head of a list)
 * @param temp [IN] Point to the current node to safely delete the current node
 * @param item [IN] A temporary list node item for travelling the list
 */
#define LIST_FOR_EACH_ITEM_SAFE(item, temp, head) \
    for ((item) = (head)->next, (temp) = (item)->next; (item) != (head); (item) = (temp), (temp) = (item)->next)

/**
 * @brief Find the start address of the struct(large node) where the node is located
 * through a node (small node) in the linked list.
 *
 * @param item   [IN] The address of a list item
 * @param type   [IN] Type of the large node that contains the linked list node.
 * @param member [IN] Name of the list node in the structure
 *
 * Note:
 * Each struct variable forms a large node (including data and list nodes).
 * The large node is connected through the list(small node).
 *  ---------      ---------      ---------    --               ----
 * |  pre    |<---|  pre    |<---|  pre    |     |==>small node     |
 * |  next   |--->|  next   |--->|  next   |     |                  |
 *  ---------      ---------      ---------    --                   | ===> Large node
 * |  data1  |    |  data1  |    |  data1  |                        |
 * |  data2  |    |  data2  |    |  data2  |                        |
 *  ---------      ---------      ---------                      ----
 * The reason why the list is not directly used as the big node is that
 * the list (ListHead type) has only the head and tail pointers and does not contain the data area.
 * In this way, the list can be used for mounting any data and is universal.
 */
#define LIST_ENTRY(item, type, member) \
    ((type *)((uintptr_t)(char *)(item) - (uintptr_t)(&((type *)0)->member)))

#ifdef __cplusplus
}
#endif
#endif // BSL_MODULE_LIST_H