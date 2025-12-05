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
#ifdef HITLS_CRYPTO_PROVIDER

#include <string.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "bsl_hash.h"
#include "list_base.h"
#include "crypt_errno.h"

#include "crypt_provider.h"
#include "crypt_provider_local.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"

#define HISH_SIZE 8
#define NOT_EQUAL_SIZE 2

// Store the information of the input attribute string
typedef struct {
    const char *attribute;              // Attribute string
    BSL_HASH_Hash *hash;                // Hash table
    uint32_t attributeNum;              // Number of attributes
    uint32_t mustAttributeNum;          // Number of mandatory attributes
    bool repeatFlag;                    // Repeat search flag
} InputAttributeStrInfo;

// Define the data structure for values
typedef struct {
    char *judgeStr;  // Judge string
    char *valueStr;  // Value string
} AttributeValue;

// Define a function to free AttributeValue resources
static void AttributeValueFree(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    AttributeValue *value = (AttributeValue *)ptr;
    BSL_SAL_FREE(value->judgeStr);
    BSL_SAL_FREE(value->valueStr);
    BSL_SAL_Free(value);
}

// Define a function to free the value list
static void FreeValueList(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    BslList *valueList = (BslList *)ptr;
    BSL_LIST_DeleteAll(valueList, AttributeValueFree);
    BSL_SAL_Free(valueList);
}

// Value copy callback function, essentially a function to create a new value list
static void *ValueDupFunc(void *ptr, size_t size)
{
    if (ptr == NULL || size == 0) {
        return NULL;
    }

    int32_t ret;
    AttributeValue *srcValue = (AttributeValue *)ptr;
    BslList *newList = BSL_LIST_New(sizeof(AttributeValue));
    if (newList == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    AttributeValue *newValue = BSL_SAL_Calloc(1, sizeof(AttributeValue));
    if (newValue == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    newValue->judgeStr = BSL_SAL_Dump(srcValue->judgeStr, BSL_SAL_Strnlen(srcValue->judgeStr, UINT32_MAX) + 1);
    newValue->valueStr = BSL_SAL_Dump(srcValue->valueStr, BSL_SAL_Strnlen(srcValue->valueStr, UINT32_MAX) + 1);

    if (newValue->judgeStr == NULL || newValue->valueStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    ret = BSL_LIST_AddElement(newList, newValue, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    return newList;

ERR:
    AttributeValueFree(newValue);
    BSL_SAL_Free(newList);
    return NULL;
}

// Key copy callback function
static void *KeyDupFunc(void *ptr, size_t size)
{
    if (size > UINT32_MAX) {
        return NULL;
    }
    return BSL_SAL_Dump(ptr, size);
}

// Key release callback function
static void KeyFreeFunc(void *ptr)
{
    BSL_SAL_FREE(ptr);
}

// Implement the BSL_HASH_UpdateNodeFunc callback function for BSL_HASH_Put to call
static int32_t UpdateAttributeValueNode(BSL_HASH_Hash *hash, BSL_HASH_Iterator node,
    uintptr_t value, uint32_t valueSize)
{
    if (hash == NULL || valueSize == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    AttributeValue *srcValue = (AttributeValue *)value;
    AttributeValue *newValue = BSL_SAL_Calloc(1, sizeof(AttributeValue));
    if (newValue == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    newValue->judgeStr = BSL_SAL_Dump(srcValue->judgeStr, BSL_SAL_Strnlen(srcValue->judgeStr, UINT32_MAX) + 1);
    newValue->valueStr = BSL_SAL_Dump(srcValue->valueStr, BSL_SAL_Strnlen(srcValue->valueStr, UINT32_MAX) + 1);
    if (newValue->judgeStr == NULL || newValue->valueStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        AttributeValueFree(newValue);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    BslList *valueList = (BslList *)(uintptr_t)BSL_HASH_IterValue(hash, node);
    int32_t ret = BSL_LIST_AddElement(valueList, (AttributeValue *)newValue, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        AttributeValueFree(newValue);
    }
    return ret;
}

// Get key-value pair positions
static int32_t GetAttributePositions(const char *attribute, int32_t start, int32_t *keyStart, int32_t *keyEnd,
                                     int32_t *judgeStart, int32_t *judgeEnd, int32_t *valueStart, int32_t *valueEnd)
{
    int32_t tmp = start;
    *keyStart = *keyEnd = *judgeStart = *judgeEnd = *valueStart = *valueEnd = start;

    // Find key
    while (attribute[tmp] != '\0' && attribute[tmp] != '=' && attribute[tmp] != '?' && attribute[tmp] != '!') {
        tmp++;
    }
    *keyEnd = tmp;
    if (*keyEnd <= *keyStart) {
        return CRYPT_PROVIDER_ERR_ATTRIBUTE;
    }

    // Find judge string
    *judgeStart = tmp;
    if (attribute[tmp] == '!' && attribute[tmp + 1] == '=') {
        tmp = tmp + NOT_EQUAL_SIZE;
    } else if (attribute[tmp] == '=' || attribute[tmp] == '?') {
        tmp++;
    } else {
        return CRYPT_PROVIDER_ERR_ATTRIBUTE;
    }
    *judgeEnd = tmp;
    if (*judgeEnd <= *judgeStart) {
        return CRYPT_PROVIDER_ERR_ATTRIBUTE;
    }

    // Find value
    *valueStart = tmp;
    while (attribute[tmp] != '\0' && attribute[tmp] != ',') {
        tmp++;
    }
    *valueEnd = tmp;
    if (*valueEnd <= *valueStart) {
        return CRYPT_PROVIDER_ERR_ATTRIBUTE;
    }

    return CRYPT_SUCCESS;
}

static int32_t ParseAttributeValue(const char *attribute, int32_t *startPos, char **key, AttributeValue **value)
{
    int32_t start = *startPos;
    char *tempKey = NULL;
    AttributeValue *tempValue = NULL;

    // Call the sub-function to get key-value pair positions
    int32_t keyStart, keyEnd, judgeStart, judgeEnd, valueStart, valueEnd;
    int32_t ret =
        GetAttributePositions(attribute, start, &keyStart, &keyEnd, &judgeStart, &judgeEnd, &valueStart, &valueEnd);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    int32_t keyLen = keyEnd - keyStart;
    int32_t judgeLen = judgeEnd - judgeStart;
    int32_t valueLen = valueEnd - valueStart;

    // Allocate space for keys and values
    tempValue = BSL_SAL_Calloc(1, sizeof(AttributeValue));
    if (tempValue == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    tempKey = BSL_SAL_Calloc(1, keyLen + 1);
    tempValue->judgeStr = BSL_SAL_Calloc(1, judgeLen + 1);
    tempValue->valueStr = BSL_SAL_Calloc(1, valueLen + 1);
    if (tempKey == NULL || tempValue->judgeStr == NULL || tempValue->valueStr == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // Copy the string corresponding to the key and value
    if (memcpy_s(tempKey, keyLen + 1, attribute + keyStart, keyLen) != EOK ||
        memcpy_s(tempValue->judgeStr, judgeLen + 1, attribute + judgeStart, judgeLen) != EOK ||
        memcpy_s(tempValue->valueStr, valueLen + 1, attribute + valueStart, valueLen) != EOK) {
        ret = CRYPT_MEM_CPY_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    *startPos = attribute[valueEnd] == '\0' ? valueEnd : valueEnd + 1;
    *key = tempKey;
    *value = tempValue;
    return CRYPT_SUCCESS;

ERR:
    BSL_SAL_FREE(tempKey);
    AttributeValueFree(tempValue);
    return ret;
}

static int32_t ParseAttributeString(InputAttributeStrInfo *attrInfo)
{
    int32_t ret;
    const char *attribute = attrInfo->attribute;
    BSL_HASH_Hash *hash = NULL;
    int32_t startPos = 0;
    char *key = NULL;
    AttributeValue *value = NULL;
    uint32_t tempMustAttributeNum = 0, tempAttributeNum = 0;

    ListDupFreeFuncPair keyFunc = {KeyDupFunc, KeyFreeFunc};
    ListDupFreeFuncPair valueFunc = {ValueDupFunc, FreeValueList};

    // Create a hash table with a bucket size of 8
    hash = BSL_HASH_Create(HISH_SIZE, BSL_HASH_CodeCalcStr, BSL_HASH_MatchStr, &keyFunc, &valueFunc);
    if (hash == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    while (attribute[startPos] != '\0') {
        // Extract a key-value pair
        ret = ParseAttributeValue(attribute, &startPos, &key, &value);
        // An unknown error occurred during the lookup
        if (ret != CRYPT_SUCCESS) {
            BSL_HASH_Destroy(hash);
            return ret;
        }

        tempAttributeNum++;
        if (value->judgeStr[0] == '=' || value->judgeStr[0] == '!') {
            tempMustAttributeNum++;
        }

        ret = BSL_HASH_Put(hash, (uintptr_t)key, BSL_SAL_Strnlen(key, UINT32_MAX) + 1,
                           (uintptr_t)value, sizeof(AttributeValue), UpdateAttributeValueNode);
        BSL_SAL_FREE(key);
        AttributeValueFree(value);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_HASH_Destroy(hash);
            return ret;
        }
    }
    if (tempAttributeNum == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_ATTRIBUTE);
        BSL_HASH_Destroy(hash);
        return CRYPT_PROVIDER_ERR_ATTRIBUTE;
    }
    attrInfo->attributeNum = tempAttributeNum;
    attrInfo->mustAttributeNum = tempMustAttributeNum;
    attrInfo->hash = hash;
    return CRYPT_SUCCESS;
}

static int32_t CompareAttributeValue(AttributeValue *value, AttributeValue *hashValue,
    uint32_t *comparedCount, uint32_t *satisfiedMustCount, int32_t *totalScore)
{
    if (hashValue->judgeStr[0] == '=') {
        if (strcmp(value->valueStr, hashValue->valueStr) == 0) {
            (*comparedCount)++;
            (*satisfiedMustCount)++;
        } else {
            return -1;
        }
    } else if (hashValue->judgeStr[0] == '!' && hashValue->judgeStr[1] == '=') {
        if (strcmp(value->valueStr, hashValue->valueStr) != 0) {
            (*comparedCount)++;
            (*satisfiedMustCount)++;
        } else {
            return -1;
        }
    } else if (hashValue->judgeStr[0] == '?') {
        (*comparedCount)++;
        if (strcmp(value->valueStr, hashValue->valueStr) == 0) {
            (*totalScore)++;
        }
    }
    return 0;
}

static int32_t CompareAttribute(BSL_HASH_Hash *hash, const char *attribute,
    uint32_t mustAttributeNum, uint32_t attributeNum)
{
    int32_t ret;
    int32_t startPos = 0;
    char *key = NULL;
    AttributeValue *value = NULL;
    uint32_t comparedCount = 0;
    uint32_t satisfiedMustCount = 0;
    int32_t totalScore = 0;

    while (attribute[startPos] != '\0') {
        ret = ParseAttributeValue(attribute, &startPos, &key, &value);
        if (ret != CRYPT_SUCCESS) {
            break;
        }

        BSL_HASH_Iterator it = BSL_HASH_Find(hash, (uintptr_t)key);
        if (it == BSL_HASH_IterEnd(hash)) {
            BSL_SAL_Free(key);
            AttributeValueFree(value);
            continue;
        }
        BslList *valueList = (BslList *)(uintptr_t)BSL_HASH_IterValue(hash, it);
        for (void *listValue = BSL_LIST_GET_FIRST(valueList);
            listValue != NULL; listValue = BSL_LIST_GET_NEXT(valueList)) {
            AttributeValue *hashValue = (AttributeValue *)listValue;
            ret = CompareAttributeValue(value, hashValue, &comparedCount,
                &satisfiedMustCount, &totalScore);
            if (ret == -1) {
                BSL_SAL_Free(key);
                AttributeValueFree(value);
                return -1;
            }

            if (comparedCount == attributeNum) {
                BSL_SAL_Free(key);
                AttributeValueFree(value);
                return (satisfiedMustCount < mustAttributeNum) ? -1 : totalScore;
            }
        }

        BSL_SAL_Free(key);
        AttributeValueFree(value);
    }

    if (satisfiedMustCount < mustAttributeNum) {
        return -1;
    }

    return totalScore;
}

static void FindHighestScoreFunc(CRYPT_EAL_LibCtx *localCtx, int32_t operaId, int32_t algId,
    InputAttributeStrInfo attrInfo, const CRYPT_EAL_Func **implFunc, CRYPT_EAL_ProvMgrCtx **mgrCtx)
{
    int32_t ret;
    int32_t totalScore = -1;
    int32_t index = 0;
    const char *attribute = attrInfo.attribute;
    BSL_HASH_Hash *hash = attrInfo.hash;
    uint32_t attributeNum = attrInfo.attributeNum;
    uint32_t mustAttributeNum = attrInfo.mustAttributeNum;
    bool repeatFlag = attrInfo.repeatFlag;

    CRYPT_EAL_ProvMgrCtx *node = BSL_LIST_GET_FIRST(localCtx->providers);
    for (; node!= NULL; node = BSL_LIST_GET_NEXT(localCtx->providers)) {
        CRYPT_EAL_AlgInfo *algInfos = NULL;
        ret = node->provQueryCb(node->provCtx, operaId, &algInfos);
        if (ret != CRYPT_SUCCESS) {
            continue;
        }
        for (index = 0; algInfos != NULL && algInfos[index].algId != 0; index++) {
            if (algInfos[index].algId != algId) {
                continue;
            }
            if (attribute == NULL) {
                *implFunc = algInfos[index].implFunc;
                *mgrCtx = node;
                return;
            }
            int32_t tempScore;
            tempScore = CompareAttribute(hash, algInfos[index].attr, mustAttributeNum, attributeNum);
            if (tempScore <= totalScore) {
                continue;
            }
            totalScore = tempScore;
            *implFunc = algInfos[index].implFunc;
            *mgrCtx = node;
            if (repeatFlag) {
                continue;
            }
            return;
        }
    }
}

int32_t CRYPT_EAL_CompareAlgAndAttr(CRYPT_EAL_LibCtx *localCtx, int32_t operaId,
    int32_t algId, const char *attribute, const CRYPT_EAL_Func **funcs, CRYPT_EAL_ProvMgrCtx **mgrCtx)
{
    int32_t ret;
    const CRYPT_EAL_Func *implFunc = NULL;
    CRYPT_EAL_ProvMgrCtx *ctx = NULL;
    InputAttributeStrInfo attrInfo = {0};

    if (attribute != NULL) {
        attrInfo.attribute = attribute;
        ret = ParseAttributeString(&attrInfo);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        attrInfo.repeatFlag = (attrInfo.attributeNum != attrInfo.mustAttributeNum) ? true : false;
    }
    ret = BSL_SAL_ThreadWriteLock(localCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_HASH_Destroy(attrInfo.hash);
        return ret;
    }
    
    FindHighestScoreFunc(localCtx, operaId, algId, attrInfo, &implFunc, &ctx);

    BSL_SAL_ThreadUnlock(localCtx->lock);
    BSL_HASH_Destroy(attrInfo.hash);
    if (implFunc == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    *funcs = implFunc;
    if (mgrCtx != NULL) {
        *mgrCtx = ctx;
    }
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_PROVIDER
