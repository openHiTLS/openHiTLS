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
#ifdef HITLS_BSL_HASH

#include "securec.h"
#include "bsl_sal.h"
#include "list_base.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "hash_local.h"
#include "bsl_hash.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define BSL_CSTL_HASH_OPTION3 3
#define BSL_CSTL_HASH_OPTION2 2
#define BSL_CSTL_HASH_OPTION1 1

struct BSL_HASH_TagNode {
    ListRawNode node; /**< Linked list node */
    uintptr_t key;    /**< Key or address for storing the key */
    uintptr_t value;  /**< value or address for storing the value */
};

typedef struct BSL_HASH_TagNode BSL_HASH_Node;

struct BSL_HASH_Info {
    ListDupFreeFuncPair keyFunc;       /**< key Copy and release function pair */
    ListDupFreeFuncPair valueFunc;     /**< value Copy and release function pair */
    BSL_HASH_MatchFunc matchFunc;      /**< matching function */
    BSL_HASH_CodeCalcFunc hashFunc;    /**< hash function */
    uint32_t bucketSize;               /**< hash table size */
    uint32_t hashCount;                /**< number of entries in the hash table */
    RawList listArray[0];              /**< linked list control block array*/
};

/* murmurhash algorithm */
/* define constants */
#define HASH_VC1 0xCC9E2D51
#define HASH_VC2 0x1B873593
#define HASH_HC1 0xE6546B64
#define HASH_HC2 0x85EBCA6B
#define HASH_HC3 0xC2B2AE35
#define HASH_HC4 5

#define CHAR_BIT 8
#define CHAR_FOR_PER_LOOP 4
#define HASH_V_ROTATE 15
#define HASH_H_ROTATE 13
#define SYS_BUS_WIDTH sizeof(uint32_t)
#define HASH_SEED 0x3B9ACA07 /* large prime 1000000007. The seed can be random or specified. */

enum BSL_CstlByte {
    ONE_BYTE = 1,
    TWO_BYTE = 2,
};

enum BSL_CstlShiftBit { SHIFT8 = 8, SHIFT13 = 13, SHIFT16 = 16, SHIFT24 = 24 };

static uint32_t BSL_HASH_Rotate(uint32_t v, uint32_t offset)
{
    return ((v << offset) | (v >> (SYS_BUS_WIDTH * CHAR_BIT - offset)));
}

static uint32_t BSL_HASH_MixV(uint32_t v)
{
    uint32_t res = v;
    res = res * HASH_VC1;
    res = BSL_HASH_Rotate(res, HASH_V_ROTATE);

    return res * HASH_VC2;
}

static uint32_t BSL_HASH_MixH(uint32_t h, uint32_t v)
{
    uint32_t res = h;

    res ^= v;
    res = BSL_HASH_Rotate(res, HASH_H_ROTATE);

    return res * HASH_HC4 + HASH_HC1;
}

uint32_t BSL_HASH_CodeCalc(void *key, uint32_t keySize)
{
    uint8_t *tmpKey = (uint8_t *)key;
    uint32_t i = 0;
    uint32_t v;
    uint32_t h = HASH_SEED;
    uint8_t c0, c1, c2, c3;
    uint32_t tmpLen = keySize - keySize % CHAR_FOR_PER_LOOP;

    while ((i + CHAR_FOR_PER_LOOP) <= tmpLen) {
        c0 = tmpKey[i++];
        c1 = tmpKey[i++];
        c2 = tmpKey[i++];
        c3 = tmpKey[i++];

        v = (uint32_t)c0 | ((uint32_t)c1 << SHIFT8) | ((uint32_t)c2 << SHIFT16) | ((uint32_t)c3 << SHIFT24);
        v = BSL_HASH_MixV(v);
        h = BSL_HASH_MixH(h, v);
    }

    v = 0;

    switch (keySize & BSL_CSTL_HASH_OPTION3) {
        case BSL_CSTL_HASH_OPTION3:
            v ^= ((uint32_t)tmpKey[i + TWO_BYTE] << SHIFT16);
            /* (keySize % 4) is equals 3, fallthrough, other branches are the same. */
            /* fall-through */
        case BSL_CSTL_HASH_OPTION2:
            v ^= ((uint32_t)tmpKey[i + ONE_BYTE] << SHIFT8);
            /* fall-through */
        case BSL_CSTL_HASH_OPTION1:
            v ^= tmpKey[i];
            v = BSL_HASH_MixV(v);
            h ^= v;
            break;
        default:
            break;
    }

    h ^= h >> SHIFT16;

    h *= HASH_HC2;
    h ^= h >> SHIFT13;
    h *= HASH_HC3;
    h ^= h >> SHIFT16;

    return h;
}

/* internal function definition */
static void BSL_HASH_HookRegister(BSL_HASH_Hash *hash, BSL_HASH_CodeCalcFunc hashFunc,
    BSL_HASH_MatchFunc matchFunc, ListDupFreeFuncPair *keyFunc, ListDupFreeFuncPair *valueFunc)
{
    ListDupFreeFuncPair *hashKeyFunc = &hash->keyFunc;
    ListDupFreeFuncPair *hashValueFunc = &hash->valueFunc;

    hash->hashFunc = hashFunc == NULL ? BSL_HASH_CodeCalcInt : hashFunc;
    hash->matchFunc = matchFunc == NULL ? BSL_HASH_MatchInt : matchFunc;

    if (keyFunc == NULL) {
        hashKeyFunc->dupFunc = NULL;
        hashKeyFunc->freeFunc = NULL;
    } else {
        hashKeyFunc->dupFunc = keyFunc->dupFunc;
        hashKeyFunc->freeFunc = keyFunc->freeFunc;
    }

    if (valueFunc == NULL) {
        hashValueFunc->dupFunc = NULL;
        hashValueFunc->freeFunc = NULL;
    } else {
        hashValueFunc->dupFunc = valueFunc->dupFunc;
        hashValueFunc->freeFunc = valueFunc->freeFunc;
    }
}

static inline BSL_HASH_Iterator BSL_HASH_IterEndGet(const BSL_HASH_Hash *hash)
{
    return (BSL_HASH_Iterator)(uintptr_t)(&hash->listArray[hash->bucketSize].head);
}

static BSL_HASH_Node *BSL_HASH_NodeCreate(
    const BSL_HASH_Hash *hash, uintptr_t key, uint32_t keySize, uintptr_t value, uint32_t valueSize)
{
    uintptr_t tmpKey;
    uintptr_t tmpValue;
    BSL_HASH_Node *hashNode = NULL;
    void *tmpPtr = NULL;

    hashNode = (BSL_HASH_Node *)BSL_SAL_Malloc(sizeof(BSL_HASH_Node));
    if (hashNode == NULL) {
        return NULL;
    }

    if (hash->keyFunc.dupFunc != NULL) {
        tmpPtr = hash->keyFunc.dupFunc((void *)key, keySize);
        tmpKey = (uintptr_t)tmpPtr;
        if (tmpKey == (uintptr_t)NULL) {
            BSL_SAL_FREE(hashNode);
            return NULL;
        }
    } else {
        tmpKey = key;
    }

    if (hash->valueFunc.dupFunc != NULL) {
        tmpPtr = hash->valueFunc.dupFunc((void *)value, valueSize);
        tmpValue = (uintptr_t)tmpPtr;
        if (tmpValue == (uintptr_t)NULL) {
            if (hash->keyFunc.freeFunc != NULL) {
                hash->keyFunc.freeFunc((void *)tmpKey);
            }

            BSL_SAL_FREE(hashNode);
            return NULL;
        }
    } else {
        tmpValue = value;
    }

    hashNode->key = tmpKey;
    hashNode->value = tmpValue;

    return hashNode;
}

static BSL_HASH_Node *BSL_HASH_FindNode(const RawList *list, uintptr_t key, BSL_HASH_MatchFunc matchFunc)
{
    BSL_HASH_Node *hashNode = NULL;
    ListRawNode *rawListNode = NULL;

    for (rawListNode = ListRawFront(list); rawListNode != NULL; rawListNode = ListRawGetNext(list, rawListNode)) {
        hashNode = BSL_CONTAINER_OF(rawListNode, BSL_HASH_Node, node);
        if (matchFunc(hashNode->key, key)) {
            return hashNode;
        }
    }

    return NULL;
}

static BSL_HASH_Iterator BSL_HASH_Front(const BSL_HASH_Hash *hash)
{
    uint32_t i = 0;
    const RawList *list = NULL;
    ListRawNode *rawListNode = NULL;

    while (i < hash->bucketSize) {
        list = &hash->listArray[i];
        rawListNode = ListRawFront(list);
        if (rawListNode != NULL) {
            return BSL_CONTAINER_OF(rawListNode, BSL_HASH_Node, node);
        }

        i++;
    }

    return BSL_HASH_IterEndGet(hash);
}

static BSL_HASH_Iterator BSL_HASH_Next(const BSL_HASH_Hash *hash, BSL_HASH_Iterator hashNode)
{
    uint32_t i;
    uint32_t hashCode;
    const RawList *list = NULL;
    ListRawNode *rawListNode = NULL;

    hashCode = hash->hashFunc(hashNode->key, hash->bucketSize);
    if (hashCode >= hash->bucketSize) {
        return BSL_HASH_IterEndGet(hash);
    }

    list = hash->listArray + hashCode;
    rawListNode = ListRawGetNext(list, &hashNode->node);
    if (rawListNode != NULL) {
        return BSL_CONTAINER_OF(rawListNode, BSL_HASH_Node, node);
    }

    for (i = hashCode + 1; i < hash->bucketSize; ++i) {
        list = &hash->listArray[i];
        rawListNode = ListRawFront(list);
        if (rawListNode != NULL) {
            return BSL_CONTAINER_OF(rawListNode, BSL_HASH_Node, node);
        }
    }

    return BSL_HASH_IterEndGet(hash);
}

static void BSL_HASH_NodeFree(BSL_HASH_Hash *hash, BSL_HASH_Node *node)
{
    ListFreeFunc keyFreeFunc = hash->keyFunc.freeFunc;
    ListFreeFunc valueFreeFunc = hash->valueFunc.freeFunc;

    if (keyFreeFunc != NULL) {
        keyFreeFunc((void *)node->key);
    }

    if (valueFreeFunc != NULL) {
        valueFreeFunc((void *)node->value);
    }

    BSL_SAL_FREE(node);
}

#ifdef HITLS_BIG_ENDIAN
static uintptr_t BSL_HASH_BigToLittleEndian(uintptr_t value)
{
    uintptr_t result = 0;
    size_t size = sizeof(uintptr_t);

    // Manually flip byte order
    for (size_t i = 0; i < size; i++) {
        // Extract the i-th byte from big-endian order (starting from the most significant bit)
        uintptr_t byte = (value >> CHAR_BIT * (size - 1 - i)) & 0xFF;
        // Place at the i-th position in little-endian order (starting from the least significant bit)
        result |= byte << (CHAR_BIT * i);
    }
    return result;
}
#endif


uint32_t BSL_HASH_CodeCalcInt(uintptr_t key, uint32_t bktSize)
{
    uintptr_t convertKey =
#ifdef HITLS_BIG_ENDIAN
        BSL_HASH_BigToLittleEndian(key);
#else
        key;
#endif
    return BSL_HASH_CodeCalc(&convertKey, sizeof(convertKey)) % bktSize;
}

bool BSL_HASH_MatchInt(uintptr_t key1, uintptr_t key2)
{
    return key1 == key2;
}

uint32_t BSL_HASH_CodeCalcStr(uintptr_t key, uint32_t bktSize)
{
    char *tmpKey = (char *)key;
    return BSL_HASH_CodeCalc(tmpKey, (uint32_t)strlen(tmpKey)) % bktSize;
}

bool BSL_HASH_MatchStr(uintptr_t key1, uintptr_t key2)
{
    char *tkey1 = (char *)key1;
    char *tkey2 = (char *)key2;

    return strcmp(tkey1, tkey2) == 0;
}

BSL_HASH_Hash *BSL_HASH_Create(uint32_t bktSize, BSL_HASH_CodeCalcFunc hashFunc, BSL_HASH_MatchFunc matchFunc,
    ListDupFreeFuncPair *keyFunc, ListDupFreeFuncPair *valueFunc)
{
    uint32_t i;
    uint32_t size;
    BSL_HASH_Hash *hash = NULL;
    RawList *listAddr = NULL;
    if (bktSize == 0U) {
        return NULL;
    }

    size = (bktSize + 1) * sizeof(RawList);
    if (IsMultiOverflow((bktSize + 1), sizeof(RawList)) || IsAddOverflow(size, sizeof(BSL_HASH_Hash))) {
        return NULL;
    }

    size += sizeof(BSL_HASH_Hash);
    hash = (BSL_HASH_Hash *)BSL_SAL_Malloc(size);
    if (hash == NULL) {
        return NULL;
    }

    (void)memset_s(hash, size, 0, size);
    hash->bucketSize = bktSize;
    BSL_HASH_HookRegister(hash, hashFunc, matchFunc, keyFunc, valueFunc);

    listAddr = hash->listArray;
    for (i = 0; i <= bktSize; ++i) {
        ListRawInit(listAddr + i, NULL);
    }

    return hash;
}

static int32_t BSL_HASH_InsertNode(
    BSL_HASH_Hash *hash, RawList *rawList, const BSL_CstlUserData *inputKey, const BSL_CstlUserData *inputValue)
{
    BSL_HASH_Node *hashNode = BSL_HASH_NodeCreate(
        hash, inputKey->inputData, inputKey->dataSize, inputValue->inputData, inputValue->dataSize);
    if (hashNode == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    ListRawPushBack(rawList, &hashNode->node);
    hash->hashCount++;

    return BSL_SUCCESS;
}

static int32_t BSL_HASH_UpdateNode(const BSL_HASH_Hash *hash, BSL_HASH_Node *node, uintptr_t value, uint32_t valueSize)
{
    uintptr_t tmpValue;
    void *tmpPtr = NULL;

    if (hash->valueFunc.dupFunc != NULL) {
        tmpPtr = hash->valueFunc.dupFunc((void *)value, valueSize);
        tmpValue = (uintptr_t)tmpPtr;
        if (tmpValue == (uintptr_t)NULL) {
            BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
            return BSL_INTERNAL_EXCEPTION;
        }

        if (hash->valueFunc.freeFunc != NULL) {
            hash->valueFunc.freeFunc((void *)node->value);
        }
    } else {
        tmpValue = value;
    }

    node->value = tmpValue;

    return BSL_SUCCESS;
}

static inline int32_t BSL_HASH_CodeCheck(const BSL_HASH_Hash *hash, uintptr_t key, uint32_t *hashCode)
{
    if (hash == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    *hashCode = hash->hashFunc(key, hash->bucketSize);
    if (*hashCode >= hash->bucketSize) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    return BSL_SUCCESS;
}

int32_t BSL_HASH_Insert(BSL_HASH_Hash *hash, uintptr_t key, uint32_t keySize, uintptr_t value, uint32_t valueSize)
{
    int32_t ret;
    uint32_t hashCode;
    BSL_HASH_Node *hashNode = NULL;
    RawList *rawList = NULL;
    BSL_CstlUserData inputKey;
    BSL_CstlUserData inputValue;

    ret = BSL_HASH_CodeCheck(hash, key, &hashCode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    rawList = &hash->listArray[hashCode];
    hashNode = BSL_HASH_FindNode(rawList, key, hash->matchFunc);
    if (hashNode != NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    inputKey.inputData = key;
    inputKey.dataSize = keySize;
    inputValue.inputData = value;
    inputValue.dataSize = valueSize;

    return BSL_HASH_InsertNode(hash, rawList, &inputKey, &inputValue);
}

int32_t BSL_HASH_Put(BSL_HASH_Hash *hash, uintptr_t key, uint32_t keySize, uintptr_t value, uint32_t valueSize,
    BSL_HASH_UpdateNodeFunc updateNodeFunc)
{
    int32_t ret;
    uint32_t hashCode;
    RawList *rawList = NULL;
    BSL_HASH_Node *hashNode = NULL;
    BSL_CstlUserData inputValue;
    BSL_CstlUserData inputKey;

    ret = BSL_HASH_CodeCheck(hash, key, &hashCode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    rawList = &hash->listArray[hashCode];
    hashNode = BSL_HASH_FindNode(rawList, key, hash->matchFunc);
    if (hashNode != NULL) {
        if (updateNodeFunc != NULL) {
            return updateNodeFunc(hash, hashNode, value, valueSize);
        } else {
            return BSL_HASH_UpdateNode(hash, hashNode, value, valueSize);
        }
    }

    inputKey.inputData = key;
    inputKey.dataSize = keySize;
    inputValue.inputData = value;
    inputValue.dataSize = valueSize;

    return BSL_HASH_InsertNode(hash, rawList, &inputKey, &inputValue);
}

int32_t BSL_HASH_At(const BSL_HASH_Hash *hash, uintptr_t key, uintptr_t *value)
{
    BSL_HASH_Node *hashNode = BSL_HASH_Find(hash, key);

    if (hashNode == BSL_HASH_IterEndGet(hash)) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    *value = hashNode->value;

    return BSL_SUCCESS;
}

BSL_HASH_Iterator BSL_HASH_Find(const BSL_HASH_Hash *hash, uintptr_t key)
{
    uint32_t hashCode;
    BSL_HASH_Node *hashNode = NULL;

    int32_t ret = BSL_HASH_CodeCheck(hash, key, &hashCode);
    if (ret != BSL_SUCCESS) {
        return hash == NULL ? NULL : BSL_HASH_IterEndGet(hash);
    }

    hashNode = BSL_HASH_FindNode(&hash->listArray[hashCode], key, hash->matchFunc);
    if (hashNode == NULL) {
        return BSL_HASH_IterEndGet(hash);
    }

    return hashNode;
}

bool BSL_HASH_Empty(const BSL_HASH_Hash *hash)
{
    return (hash == NULL) || (hash->hashCount == 0U);
}

uint32_t BSL_HASH_Size(const BSL_HASH_Hash *hash)
{
    return hash == NULL ? 0 : hash->hashCount;
}

BSL_HASH_Iterator BSL_HASH_Erase(BSL_HASH_Hash *hash, uintptr_t key)
{
    uint32_t hashCode;
    BSL_HASH_Node *hashNode = NULL;
    BSL_HASH_Node *nextHashNode = NULL;
    BSL_HASH_MatchFunc matchFunc = NULL;
    BSL_HASH_CodeCalcFunc hashFunc = NULL;

    if (hash == NULL) {
        return NULL;
    }

    hashFunc = hash->hashFunc;
    hashCode = hashFunc(key, hash->bucketSize);
    if (hashCode >= hash->bucketSize) {
        return BSL_HASH_IterEndGet(hash);
    }

    matchFunc = hash->matchFunc;
    hashNode = BSL_HASH_FindNode(&hash->listArray[hashCode], key, matchFunc);
    if (hashNode == NULL) {
        return BSL_HASH_IterEndGet(hash);
    }

    nextHashNode = BSL_HASH_Next(hash, hashNode);
    ListRawRemove(&hash->listArray[hashCode], &hashNode->node);
    BSL_HASH_NodeFree(hash, hashNode);
    --hash->hashCount;

    return nextHashNode;
}

void BSL_HASH_Clear(BSL_HASH_Hash *hash)
{
    uint32_t i;
    RawList *list = NULL;
    BSL_HASH_Node *hashNode = NULL;
    ListRawNode *rawListNode = NULL;

    if (hash == NULL) {
        return;
    }

    for (i = 0; i < hash->bucketSize; ++i) {
        list = &hash->listArray[i];
        while (!ListRawEmpty(list)) {
            rawListNode = ListRawFront(list);
            hashNode = BSL_CONTAINER_OF(rawListNode, BSL_HASH_Node, node);
            ListRawRemove(list, rawListNode);
            BSL_HASH_NodeFree(hash, hashNode);
        }
    }

    hash->hashCount = 0;
}

void BSL_HASH_Destory(BSL_HASH_Hash *hash)
{
    if (hash != NULL) {
        BSL_HASH_Clear(hash);
        BSL_SAL_Free(hash);
    }
}

BSL_HASH_Iterator BSL_HASH_IterBegin(const BSL_HASH_Hash *hash)
{
    return hash == NULL ? NULL : BSL_HASH_Front(hash);
}

BSL_HASH_Iterator BSL_HASH_IterEnd(const BSL_HASH_Hash *hash)
{
    return hash == NULL ? NULL : BSL_HASH_IterEndGet(hash);
}

BSL_HASH_Iterator BSL_HASH_IterNext(const BSL_HASH_Hash *hash, BSL_HASH_Iterator it)
{
    return (hash == NULL || it == BSL_HASH_IterEnd(hash)) ? BSL_HASH_IterEnd(hash) : BSL_HASH_Next(hash, it);
}

uintptr_t BSL_HASH_HashIterKey(const BSL_HASH_Hash *hash, BSL_HASH_Iterator it)
{
    return (it == NULL || it == BSL_HASH_IterEnd(hash)) ? 0 : it->key;
}

uintptr_t BSL_HASH_IterValue(const BSL_HASH_Hash *hash, BSL_HASH_Iterator it)
{
    return (it == NULL || it == BSL_HASH_IterEnd(hash)) ? 0 : it->value;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_BSL_HASH */
