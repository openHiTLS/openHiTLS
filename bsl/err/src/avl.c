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
#ifdef HITLS_BSL_ERR

#include "bsl_sal.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_binlog_id.h"
#include "avl.h"

// Maximum height of the AVL tree.
#define AVL_MAX_HEIGHT 64

static uint32_t GetMaxHeight(uint32_t a, uint32_t b)
{
    if (a >= b) {
        return a;
    } else {
        return b;
    }
}

static uint32_t GetAvlTreeHeight(const BSL_AvlTree *node)
{
    if (node == NULL) {
        return 0;
    } else {
        return node->height;
    }
}

static void UpdateAvlTreeHeight(BSL_AvlTree *node)
{
    if (node != NULL) {
        uint32_t leftHeight = GetAvlTreeHeight(node->leftNode);
        uint32_t rightHeight = GetAvlTreeHeight(node->rightNode);
        if (node->height >= AVL_MAX_HEIGHT) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05078, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "avl tree height exceed max limit", 0, 0, 0, 0);
            return;
        }
        node->height = GetMaxHeight(leftHeight, rightHeight) + 1u;
    }
}

BSL_AvlTree *BSL_AVL_MakeLeafNode(BSL_ElementData data)
{
    BSL_AvlTree *curNode = (BSL_AvlTree *)BSL_SAL_Malloc(sizeof(BSL_AvlTree));
    if (curNode == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05002, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "MALLOC for avl tree node failed", 0, 0, 0, 0);
        return NULL;
    }

    curNode->height = 1;
    curNode->rightNode = NULL;
    curNode->leftNode = NULL;
    curNode->data = data;

    return curNode;
}

/**
 * @brief AVL rotate left
 * @param root [IN] Root node to be rotated
 * @return rNode Root node after rotation
 */
static BSL_AvlTree *AVL_RotateLeft(BSL_AvlTree *root)
{
    /* Rotate Left
                        10                              20
                      5    20    --Rotate Left--->    10  30
                             30                      5      40
                              40

    In this case, the input root node is 10, and the output node is 20. */
    BSL_AvlTree *rNode = root->rightNode;
    BSL_AvlTree *lNode = rNode->leftNode;
    root->rightNode = lNode;
    rNode->leftNode = root;
    UpdateAvlTreeHeight(root);
    UpdateAvlTreeHeight(rNode);
    return rNode;
}

/**
 * @brief AVL rotate right
 * @param root [IN] Root node to be rotated
 * @return lNode Root node after rotation
 */
static BSL_AvlTree *AVL_RotateRight(BSL_AvlTree *root)
{
    /* Rotate Right
                        40                              30
                       /  \                            /  \
                     30    50   --Rotate Right--->   20    40
                   20  35                          10    35  50
                 10
    In this case, the input root node is 40, and the output node is 30. */
    BSL_AvlTree *lNode = root->leftNode;
    BSL_AvlTree *rNode = lNode->rightNode;
    root->leftNode = rNode;
    lNode->rightNode = root;
    UpdateAvlTreeHeight(root);
    UpdateAvlTreeHeight(lNode);
    return lNode;
}

/**
 * @brief AVL Right Balance
 * @param root [IN] Root node to be balanced
 * @return root: root node after balancing
 */
static BSL_AvlTree *AVL_RebalanceRight(BSL_AvlTree *root)
{
    // The height difference between the left and right subtrees is only 1.
    if ((GetAvlTreeHeight(root->leftNode) + 1u) >= GetAvlTreeHeight(root->rightNode)) {
        UpdateAvlTreeHeight(root);
        return root;
    }
    /* The height of the left subtree is greater than that of the right subtree. Rotate right and then left. */
    BSL_AvlTree *curNode = root->rightNode;
    if (GetAvlTreeHeight(curNode->leftNode) > GetAvlTreeHeight(curNode->rightNode)) {
        root->rightNode = AVL_RotateRight(curNode);
    }
    return AVL_RotateLeft(root);
}

/**
 * @brief AVL Left Balance
 * @param root [IN] Root node to be balanced
 * @return root: root node after balancing
 */
static BSL_AvlTree *AVL_RebalanceLeft(BSL_AvlTree *root)
{
    // The height difference between the left and right subtrees is only 1.
    if ((GetAvlTreeHeight(root->rightNode) + 1u) >= GetAvlTreeHeight(root->leftNode)) {
        UpdateAvlTreeHeight(root);
        return root;
    }
    /* The height of the right subtree is greater than that of the left subtree. Rotate left and then right. */
    BSL_AvlTree *curNode = root->leftNode;
    if (GetAvlTreeHeight(curNode->rightNode) > GetAvlTreeHeight(curNode->leftNode)) {
        root->leftNode = AVL_RotateLeft(curNode);
    }
    return AVL_RotateRight(root);
}

static void AVL_FreeData(BSL_ElementData data, BSL_AVL_DATA_FREE_FUNC freeFunc)
{
    if (freeFunc != NULL) {
        freeFunc(data);
    }
}

BSL_AvlTree *BSL_AVL_InsertNode(BSL_AvlTree *root, uint64_t nodeId, BSL_AvlTree *node)
{
    if (root == NULL) {
        node->nodeId = nodeId;
        return node;
    }

    if (root->nodeId > nodeId) {
        // If the nodeId is smaller than the root nodeId, insert the left subtree.
        root->leftNode = BSL_AVL_InsertNode(root->leftNode, nodeId, node);

        return AVL_RebalanceLeft(root);
    } else if (root->nodeId < nodeId) {
        // If the nodeId is greater than the root nodeId, insert the right subtree.
        root->rightNode = BSL_AVL_InsertNode(root->rightNode, nodeId, node);

        return AVL_RebalanceRight(root);
    }

    /* if the keys are the same and cannot be inserted */
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05003, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "AVL tree insert key nodeId(%llu) already exist", nodeId, 0, 0, 0);
    return NULL;
}

BSL_AvlTree *BSL_AVL_SearchNode(BSL_AvlTree *root, uint64_t nodeId)
{
    BSL_AvlTree *curNode = root;
    while (curNode != NULL) {
        // match the node
        if (curNode->nodeId == nodeId) {
            break;
        } else if (curNode->nodeId > nodeId) {
            // If the nodeId is smaller than the root nodeId, search the left subtree.
            curNode = curNode->leftNode;
        } else {
            // If the nodeId is greater than the root nodeId, search the right subtree.
            curNode = curNode->rightNode;
        }
    }

    // If the specified node cannot be found, NULL is returned.
    return curNode;
}

/**
 * @brief Delete the specified AVL node that has both the left and right subnodes.
 * @param rmNodeChild [IN] Child node of the AVL node to be deleted
 * removeNode [IN] Avl node to be deleted.
 * @return root Return the deleted root node of the AVL tree.
 */
static BSL_AvlTree *AVL_DeleteNodeWithTwoChilds(BSL_AvlTree *rmNodeChild, BSL_AvlTree *removeNode)
{
    if (rmNodeChild == NULL || removeNode == NULL) {
        return NULL;
    }

    if (rmNodeChild->rightNode == NULL) {
        // Connect the left node and the grandfather node regardless of whether rmNodeChild has a left node.
        BSL_AvlTree *curNode = rmNodeChild->leftNode;
        removeNode->nodeId = rmNodeChild->nodeId;
        removeNode->data = rmNodeChild->data;

        BSL_SAL_FREE(rmNodeChild);
        return curNode;
    }

    rmNodeChild->rightNode = AVL_DeleteNodeWithTwoChilds(rmNodeChild->rightNode, removeNode);
    return AVL_RebalanceLeft(rmNodeChild);
}

BSL_AvlTree *BSL_AVL_DeleteNode(BSL_AvlTree *root, uint64_t nodeId, BSL_AVL_DATA_FREE_FUNC func)
{
    if (root == NULL) {
        return root;
    }

    if (root->nodeId == nodeId) {
        if (root->leftNode == NULL) {
            if (root->rightNode == NULL) {
                // Both the left and right nodes are NULL.
                AVL_FreeData(root->data, func);
                BSL_SAL_FREE(root);
                return NULL;
            } else {
                // Only have the right node.
                BSL_AvlTree *curNode = root->rightNode;
                AVL_FreeData(root->data, func);
                BSL_SAL_FREE(root);
                return (curNode);
            }
        } else if (root->rightNode == NULL) {
            // Only have the right node.
            BSL_AvlTree *curNode = root->leftNode;
            AVL_FreeData(root->data, func);
            BSL_SAL_FREE(root);
            return (curNode);
        } else {
            // There are left and right nodes.
            AVL_FreeData(root->data, func);
            root->leftNode = AVL_DeleteNodeWithTwoChilds(root->leftNode, root);
            return AVL_RebalanceRight(root);
        }
    }

    if (root->nodeId > nodeId) {
        root->leftNode = BSL_AVL_DeleteNode(root->leftNode, nodeId, func);
        return AVL_RebalanceRight(root);
    } else {
        root->rightNode = BSL_AVL_DeleteNode(root->rightNode, nodeId, func);
        return AVL_RebalanceLeft(root);
    }
}

void BSL_AVL_DeleteTree(BSL_AvlTree *root, BSL_AVL_DATA_FREE_FUNC func)
{
    if (root == NULL) {
        return;
    }

    BSL_AVL_DeleteTree(root->leftNode, func);
    BSL_AVL_DeleteTree(root->rightNode, func);
    AVL_FreeData(root->data, func);
    BSL_SAL_FREE(root);
}

#endif /* HITLS_BSL_ERR */
