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

#ifndef AVL_H
#define AVL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_ERR

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *BSL_ElementData;

typedef void (*BSL_AVL_DATA_FREE_FUNC)(BSL_ElementData data);

/* AVL tree node structure */
typedef struct AvlTree {
    uint32_t height;
    uint64_t nodeId;
    struct AvlTree *rightNode;
    struct AvlTree *leftNode;
    BSL_ElementData data;
} BSL_AvlTree;

/**
 * @ingroup bsl_err
 * @brief Create a tree node.
 *
 * @par Description:
 * Create a tree node and set node data.
 *
 * @attention None
 * @param data [IN] Data pointer of the tree node
 * @retval BSL_AvlTree *curNode node returned after the application is successful.
 *         NULL application failed
 */
BSL_AvlTree *BSL_AVL_MakeLeafNode(BSL_ElementData data);

/**
 * @ingroup bsl_err
 * @brief Search for a node.
 *
 * @par Description:
 * Query the node in the AVL tree by nodeId.
 *
 * @attention None
 * @param root [IN] Pointer to the root node of the tree
 * @param nodeId [IN] node ID of the tree, as the key
 * @retval NULL No corresponding node is found.
 * @retval not NULL Pointer to the corresponding node.
 */
BSL_AvlTree *BSL_AVL_SearchNode(BSL_AvlTree *root, uint64_t nodeId);

/**
 * @ingroup bsl_err
 * @brief Create a node in the tree.
 *
 * @par Description:
 * Create a node in the tree.
 *
 * @attention If the nodeId already exists, the insertion fails.
 * @param root [IN] Pointer to the root node of the tree.
 * @param nodeId [IN] as the key of the created node
 * @param node [IN] Tree node
 * @retval The root node of a non-null tree or subtree
 */
BSL_AvlTree *BSL_AVL_InsertNode(BSL_AvlTree *root, uint64_t nodeId, BSL_AvlTree *node);

/**
 * @ingroup bsl_err
 * @brief Delete a specific tree node.
 *
 * @par Description:
 * Delete the nodeId corresponding tree node.
 *
 * @attention None
 * @param root [IN] Pointer to the root node of the tree.
 * @param nodeId [IN] Key of the node to be deleted
 * @param func [IN] Pointer to the function that releases the data of the deleted node.
 * @retval NULL All nodes in the tree have been deleted.
 * @retval not NULL Pointer to the root node of a tree or subtree.
 */
BSL_AvlTree *BSL_AVL_DeleteNode(BSL_AvlTree *root, uint64_t nodeId, BSL_AVL_DATA_FREE_FUNC func);

/**
 * @ingroup bsl_err
 * @brief Delete all nodes from the tree.
 *
 * @par Description:
 * Delete all nodes in the tree.
 *
 * @attention None
 * @param root [IN] Pointer to the root node of the tree
 * @param func [IN] Pointer to the function that releases the data of the deleted node.
 */
void BSL_AVL_DeleteTree(BSL_AvlTree *root, BSL_AVL_DATA_FREE_FUNC func);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_ERR */

#endif // AVL_H