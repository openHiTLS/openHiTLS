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
 * @defgroup bsl_hash hash table
 * @ingroup bsl
 */

#ifndef BSL_HASH_H
#define BSL_HASH_H

#include "hitls_build.h"
#ifdef HITLS_BSL_HASH

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "bsl_hash_list.h"
#include "list_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_hash
 * @brief Handle of the hash table, which indicates the elements contained in the hash table.
 */
typedef struct BSL_HASH_Info BSL_HASH_Hash;

/**
 * @ingroup bsl_hash
 * @brief Definition of the iterator of the hash table, pointing to the hash node.
 */
typedef struct BSL_HASH_TagNode *BSL_HASH_Iterator;

/**
 * @ingroup bsl_hash
 * @brief Generates a hash table index based on the entered key.
 * @param key [IN] hash key
 */
typedef uint32_t (*BSL_HASH_CodeCalcFunc)(uintptr_t key);

/**
 * @ingroup bsl_hash
 * @brief This function is used to match the input data with the key.
 * Key1 stored in the hash table, and the key2 to be matched. If no, false is returned.
 * @param key1 [IN] Key stored in the hash table
 * @param key2 [IN] Key to be matched
 * @retval #true key1 matches key2.
 * @retval #false key1 and key2 do not match.
 */
typedef bool (*BSL_HASH_MatchFunc)(uintptr_t key1, uintptr_t key2);

/**
 * @ingroup bsl_hash
 * @brief Function for updating a node in the hash table.
 * @par Description: This function is used to update the value of an existing node in the hash table.
 * @attention
 * 1. This function is called when a key already exists in the hash table and needs to be updated.
 * 2. The user can provide a custom implementation of this function to handle specific update logic.
 * @param hash [IN] Handle of the hash table.
 * @param node [IN] Pointer to the node to be updated.
 * @param value [IN] New value or address for storing the new value.
 * @param valueSize [IN] Size of the new value. If the user has not registered a dupFunc, this parameter is not used.
 * @retval #BSL_SUCCESS The node was successfully updated.
 * @retval #BSL_INTERNAL_EXCEPTION Failed to update the node.
 * @par Dependency: None
 * @li bsl_hash.h: Header file where this function type is declared.
 */
typedef int32_t (*BSL_HASH_UpdateNodeFunc)(BSL_HASH_Hash *hash, BSL_HASH_Iterator node,
    uintptr_t value, uint32_t valueSize);

/**
 * @ingroup bsl_hash
 * @brief Hash function.
 * @par Description: Calculate the hash value based on the key value.
 * The hash value does not modulate the size of the hash table and cannot be directly used for hash indexing.
 * @attention
 * 1. The key is the input parameter when the user invokes other interfaces.
 * 2. If the key is an integer, you can use this function as the hashFunc parameter when creating a hash.
 * @param key [IN] Key to be calculated.
 * @param keySize [IN] Size of the key value.
 * @retval #Hash value calculated based on the user key. The hash value is not modulated by the hash table size
 * and cannot be directly used for hash indexing.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
uint32_t BSL_HASH_CodeCalc(void *key, uint32_t keySize);

/**
 * @ingroup bsl_hash
 * @brief Default integer hash function.
 * @par Default integer hash function.
 * @attention
 * 1. The key parameter is the input parameter when the user invokes other interfaces.
 * 2. If the key is an integer, you can use this function as the hashFunc parameter when creating a hash.
 * @param key [IN] Key to be calculated.
 * @param bktSize [IN] Hash bucket size.
 * @retval #Hash value calculated based on the user key.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
uint32_t BSL_HASH_CodeCalcInt(uintptr_t key);

/**
 * @ingroup bsl_hash
 * @brief Default string hash function.
 * @par Default string hash function.
 * @attention
 * 1. The key is an input parameter when the user invokes other interfaces.
 *    Ensure that the input key is a valid string start address.
 * 2. If the key is a string, you can use this function as the hashFunc parameter when creating a hash.
 * @param key [IN] Key to be calculated.
 * @param bktSize [IN] Hash bucket size.
 * @retval #Hash valueThe hash value calculated based on the user key.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
uint32_t BSL_HASH_CodeCalcStr(uintptr_t key);

/**
 * @ingroup bsl_hash
 * @brief Default integer matching function.
 * @par Default integer matching function.
 * @attention
 * 1. The key is the input parameter when the user invokes other interfaces.
 * 2. If the key is an integer, you can use this function as the matchFunc parameter when creating a hash.
 * @param key1 [IN] Key to be matched.
 * @param key2 [IN] Key to be matched.
 * @retval #true key1 matches key2.
 * @retval #false key1 and key2 do not match.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
bool BSL_HASH_MatchInt(uintptr_t key1, uintptr_t key2);

/**
 * @ingroup bsl_hash
 * @brief Default string matching function.
 * @par Default string matching function.
 * @attention
 * 1. Key1 is the input parameter when the user invokes other interfaces.
 *    Ensure that the input key1 is a valid string start address.
 * 2. If the key is a string, you can use this function as the matchFunc parameter when creating the hash.
 * @param key1 [IN] Key to be matched.
 * @param key2 [IN] Key to be matched.
 * @retval #true key1 matches key2.
 * @retval #false key1 and key2 do not match.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
bool BSL_HASH_MatchStr(uintptr_t key1, uintptr_t key2);

/**
 * @ingroup bsl_hash
 * @brief Create a hash table and return the handle of the hash table.
 * @attention
 * 1. Copy functions for keys and data:
 * You do not need to register the copy function in the following case:
 * a) Data is the int type and the length <= sizeof(uintptr_t).
 * The copy function must be registered in the following cases:
 * a) Data is the int type, but the length is greater than sizeof(uintptr_t);
 * b) string;
 * c) User-defined data structure.
 * 2. About the free function: Simply put, if the duplicate function is registered,
 *                             the corresponding free function must be registered.
 * 3. Provide the default integer and string hash functions: #BSL_HASH_CodeCalcInt and #BSL_HASH_CodeCalcStr.
 * 4. Provide default integer and string matching functions: #BSL_HASH_MatchInt and #BSL_HASH_MatchStr.
 * 5. The hash table will start with 16 buckets and automatically resize based on load factor.
 * @param bktSize [IN] Initial hash bucket size. If 0, default size is used.
 * @param hashCalcFunc [IN] Hash value calculation function.
 *                          If the value is NULL, the default key is an integer. Use #BSL_HASH_CodeCalcInt.
 * @param matchFunc [IN] hash key matching function.
 *                       If the value is NULL, the default key is an integer. Use #BSL_HASH_MatchInt.
 * @param keyFunc [IN] hash key copy and release function pair.
 *                     If the keyFunc->dupFunc is not registered, the key is an integer by default.
 * @param valueFunc [IN] hash data copy and release function pair.
 *                       If the user has not registered valueFunc->dupFunc, the data type is an integer by default.
 * @retval hash table handle. NULL indicates that the creation fails.
 * @par Dependency: None
 * @see #BSL_HASH_CodeCalcInt, #BSL_HASH_CodeCalcStr, #BSL_HASH_MatchInt, #BSL_HASH_MatchStr.
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
BSL_HASH_Hash *BSL_HASH_Create(uint32_t bktSize, BSL_HASH_CodeCalcFunc hashFunc, BSL_HASH_MatchFunc matchFunc,
    ListDupFreeFuncPair *keyFunc, ListDupFreeFuncPair *valueFunc);


/**
 * @ingroup bsl_hash
 * @brief Insert the hash data.
 * @par Description: Create a node and insert data (key and value) into the hash table.
 * @attention
 * 1. Duplicate keys are not supported.
 * 2. The key and value are integer values or addresses pointing to the user key or value.
 * 3. If the life cycle of the extended data is shorter than the life cycle of the node,
 *    you need to register the copy function and release function when creating the hash table.
 * @param hash          [IN] handle of the hash table
 * @param key           [IN] key or address for storing the key
 * @param keySize       [IN] Copy length of key. If the user has not registered the dupFunc, this parameter is not used.
 * @param value         [IN] value or the address for storing the value.
 * @param valueSize     [IN] Copy length of value. If user has not registered the dupFunc, this parameter is not used.
 * @retval #BSL_SUCCESS Succeeded in inserting the node.
 * @retval #BSL_INTERNAL_EXCEPTION Insertion fails.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
int32_t BSL_HASH_Insert(BSL_HASH_Hash *hash, uintptr_t key, uint32_t keySize, uintptr_t value, uint32_t valueSize);

/**
 * @ingroup bsl_hash
 * @brief Insert or update the hash data.
 * @par Description: This function is used to insert a nonexistent key into the hash table
 *                   or update the value corresponding to an existing key.
 * @attention
 * 1. Duplicate keys are supported.
 * 2. When the key does not exist, the usage of this function is the same as that of #BSL_HASH_Insert.
 * 3. When the key exists, this function updates the value.
 * @param hash          [IN] Handle of the hash table.
 * @param key           [IN] key or address for storing the key.
 * @param keySize       [IN] Copy length of key. If the user has not registered the dupFunc, this parameter is not used.
 * @param value         [IN] value or the address for storing the value.
 * @param valueSize     [IN] Copy length of value. If user has not registered the dupFunc, this parameter is not used.
 * @param updateNodeFunc [IN] Callback function for updating a node. If NULL, the default update function will be used.
 *                            This function allows custom logic for updating existing nodes.
 * @retval #BSL_SUCCESS Succeeded in inserting or updating the node.
 * @retval #BSL_INTERNAL_EXCEPTION Failed to insert or update the node.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
int32_t BSL_HASH_Put(BSL_HASH_Hash *hash, uintptr_t key, uint32_t keySize, uintptr_t value, uint32_t valueSize,
    BSL_HASH_UpdateNodeFunc updateNodeFunc);

/**
 * @ingroup bsl_hash
 * @brief Search for a node and return the node data.
 * @par Description: Searches for and returns node data based on the key.
 * @param hash          [IN] Handle of the hash table.
 * @param key           [IN] key or address for storing the key.
 * @param value         [OUT] Data found.
 * @retval #BSL_SUCCESS found successfully.
 * @retval #BSL_INTERNAL_EXCEPTION query failed.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
int32_t BSL_HASH_At(const BSL_HASH_Hash *hash, uintptr_t key, uintptr_t *value);

/**
 * @ingroup bsl_hash
 * @brief Search for the iterator where the key is located.
 * @par Description: Searches for and returns the iterator where the key is located based on the key.
 * @param hash    [IN] Handle of the hash table.
 * @param key     [IN] key or address for storing the key.
 * @retval If the key exists, the iterator (pointing to the address of the node) where the key is located is returned.
 *         In other cases, #BSL_HASH_IterEnd() is returned.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
BSL_HASH_Iterator BSL_HASH_Find(const BSL_HASH_Hash *hash, uintptr_t key);

/**
 * @ingroup bsl_hash
 * @brief Check whether the current hash table is empty.
 * @par Description: Check whether the current hash table is empty.
 *                   If the hash table is empty, true is returned. Otherwise, false is returned.
 * @param hash [IN] Handle of the hash table. The value range is valid pointer.
 * @retval #true, indicating that the hash table is empty.
 * @retval #false, indicating that the hash table is not empty.
 * @see #BSL_HASH_Size
 * @par Dependency: None
 * @li bsl_hash.h: header file where the interface declaration is stored.
 */
bool BSL_HASH_Empty(const BSL_HASH_Hash *hash);

/**
 * @ingroup bsl_hash
 * @brief Obtain the number of nodes in the hash table.
 * @par Description: Obtains the number of nodes in the hash table and returns the number of nodes.
 * @param hash [IN] Handle of the hash table. The value range is valid pointer.
 * @retval Number of hash nodes.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
uint32_t BSL_HASH_Size(const BSL_HASH_Hash *hash);

/**
 * @ingroup bsl_hash
 * @brief Remove a specified node from the hash table.
 * @par Description: Find the node based on the key, delete the node (release it),
 *                   and release the memory of the corresponding node.
 * @param hash [IN] Handle of the hash table. The value range is a valid pointer.
 * @param key  [IN] Remove a node key.
 * @retval If the key exists,
 *         the next iterator (pointing to the address of the node) of the iterator where the key is located is returned.
 *         Otherwise, #BSL_HASH_IterEnd() is returned.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
BSL_HASH_Iterator BSL_HASH_Erase(BSL_HASH_Hash *hash, uintptr_t key);

/**
 * @ingroup bsl_hash
 * @brief Delete all nodes in the hash table.
 * @par Description: Delete all nodes and reclaim the node memory. The hash table still exists, but there are no members
 * @attention Note: If the user data contains private resources, need to register the free hook function during creation
 * @param hash [IN] Handle of the hash table.
 * @retval none.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
void BSL_HASH_Clear(BSL_HASH_Hash *hash);

/**
 * @ingroup bsl_hash
 * @brief Delete the hash table.
 * @par Description: Delete the hash table. If a node exists in the table, delete the node first and reclaim the memory.
 * @attention Note: If the user data contains private resources, need to register the free hook function during creation
 * @param hash [IN] Handle of the hash table.
 * @retval none.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
void BSL_HASH_Destroy(BSL_HASH_Hash *hash);

/**
 * @ingroup bsl_hash
 * @brief Obtain the iterator of the first node in the hash table.
 * @par Description: Obtains the iterator where the first node in the hash table is located.
 * @param hash [IN] Handle of the hash table.
 * @retval Iterator of the first node. If the hash is empty, #BSL_HASH_IterEnd() is returned.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
BSL_HASH_Iterator BSL_HASH_IterBegin(const BSL_HASH_Hash *hash);

/**
 * @ingroup bsl_hash
 * @brief Obtain the iterator reserved after the last node in the hash table.
 * @par Description: Obtain the iterator reserved after the last node in the hash table.
 *                   This node points to the last reserved hash bucket, which has no members.
 * @param hash [IN] Handle of the hash table.
 * @retval Iterator reserved after the last node.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
BSL_HASH_Iterator BSL_HASH_IterEnd(const BSL_HASH_Hash *hash);

/**
 * @ingroup bsl_hash
 * @brief Obtain the iterator of the next node in the hash table.
 * @par Description: Obtains the iterator of the next node in the hash table.
 * @param hash     [IN] Handle of the hash table.
 * @param it       [IN] Current iterator.
 * @retval Next node iterator. If the current node is the last iterator, #BSL_HASH_IterEnd() is returned.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
BSL_HASH_Iterator BSL_HASH_IterNext(const BSL_HASH_Hash *hash, BSL_HASH_Iterator it);

/**
 * @ingroup bsl_hash
 * @brief Obtain the key of the iterator.
 * @par Description: Obtains the current key of the iterator in the hash table.
 * @attention
 * 1. When the hash pointer is null or iterator it is equal to #BSL_HASH_IterEnd(), this function returns 0.
 *    This function cannot distinguish whether the error code or user data,
 * 2. Before calling this function, ensure that hash is a valid pointer
 *    and iterator it is not equal to #BSL_HASH_IterEnd().
 * @param hash     [IN] Handle of the hash table.
 * @param it       [IN] Current iterator.
 * @retval Key corresponding to the iterator. If iterator it equals #BSL_HASH_IterEnd(), 0 is returned.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
uintptr_t BSL_HASH_HashIterKey(const BSL_HASH_Hash *hash, BSL_HASH_Iterator it);

/**
 * @ingroup bsl_hash
 * @brief Obtain the value of the iterator.
 * @par Description: Obtains the current value of the iterator in the hash table.
 * @attention
 * 1. When the hash pointer is null or it is equal to #BSL_HASH_IterEnd(), the interface returns 0.
 *    This function cannot distinguish whether the error code or user data,
 * 2. Before calling this function, ensure that hash is a valid pointer
 *    and iterator it is not equal to #BSL_HASH_IterEnd().
 * @param hash     [IN] Handle of the hash table.
 * @param it       [IN] Current iterator.
 * @retval Value corresponding to the iterator. If iterator it equals #BSL_HASH_IterEnd(), 0 is returned.
 * @par Dependency: None
 * @li bsl_hash.h: header file where this function's declaration is located.
 */
uintptr_t BSL_HASH_IterValue(const BSL_HASH_Hash *hash, BSL_HASH_Iterator it);

struct BSL_HASH_Info {
    ListDupFreeFuncPair keyFunc;        /**< key Copy and release function pair */
    ListDupFreeFuncPair valueFunc;      /**< value Copy and release function pair */
    BSL_HASH_MatchFunc matchFunc;       /**< matching function */
    BSL_HASH_CodeCalcFunc hashFunc;     /**< hash function */
    uint32_t initialSize;               /**< Initial bucket size (N0), must be power of 2 */
    uint32_t nextLevelSize;             /**< Next hash level size (N0 * 2^(level+1)) */
    uint32_t nextSplit;                 /**< Split pointer, index of next bucket to split */
    uint32_t bucketSize;                /**< Current total bucket size: N0 * 2^level + nextSplit */
    uint32_t hashCount;                 /**< number of entries in the hash table */
    RawList *listArray;                 /**< Pointer to dynamically allocated bucket array */
};

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */

#endif // BSL_HASH_H
