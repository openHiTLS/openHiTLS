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
#ifdef HITLS_BSL_OBJ
#include <stddef.h>
#include "securec.h"
#include "bsl_obj.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#ifdef HITLS_BSL_HASH
#include "bsl_hash.h"

// Hash table for signature algorithm mappings
BSL_HASH_Hash *g_signHashTable = NULL;
// Read-write lock for thread-safe access to g_signHashTable
static BSL_SAL_ThreadLockHandle g_signHashRwLock = NULL;
// Once control for thread-safe initialization
static uint32_t g_signHashInitOnce = BSL_SAL_ONCE_INIT;

#define BSL_OBJ_SIGN_HASH_BKT_SIZE 64u
#endif // HITLS_BSL_HASH

typedef struct BslSignIdMap {
    BslCid signId;
    BslCid asymId;
    BslCid hashId;
} BSL_SignIdMap;

static BSL_SignIdMap g_signIdMap[] = {
    {BSL_CID_MD5WITHRSA, BSL_CID_RSA, BSL_CID_MD5},
    {BSL_CID_SHA1WITHRSA, BSL_CID_RSA, BSL_CID_SHA1},
    {BSL_CID_SHA224WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA224},
    {BSL_CID_SHA256WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA256},
    {BSL_CID_SHA384WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA384},
    {BSL_CID_SHA512WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA512},
    {BSL_CID_RSASSAPSS, BSL_CID_RSA, BSL_CID_UNKNOWN},
    {BSL_CID_SM3WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SM3},
    {BSL_CID_DSAWITHSHA1, BSL_CID_DSA, BSL_CID_SHA1},
    {BSL_CID_DSAWITHSHA224, BSL_CID_DSA, BSL_CID_SHA224},
    {BSL_CID_DSAWITHSHA256, BSL_CID_DSA, BSL_CID_SHA256},
    {BSL_CID_DSAWITHSHA384, BSL_CID_DSA, BSL_CID_SHA384},
    {BSL_CID_DSAWITHSHA512, BSL_CID_DSA, BSL_CID_SHA512},
    {BSL_CID_ECDSAWITHSHA1, BSL_CID_ECDSA, BSL_CID_SHA1},
    {BSL_CID_ECDSAWITHSHA224, BSL_CID_ECDSA, BSL_CID_SHA224},
    {BSL_CID_ECDSAWITHSHA256, BSL_CID_ECDSA, BSL_CID_SHA256},
    {BSL_CID_ECDSAWITHSHA384, BSL_CID_ECDSA, BSL_CID_SHA384},
    {BSL_CID_ECDSAWITHSHA512, BSL_CID_ECDSA, BSL_CID_SHA512},
    {BSL_CID_SM2DSAWITHSM3, BSL_CID_SM2DSA, BSL_CID_SM3},
    {BSL_CID_SM2DSAWITHSHA1, BSL_CID_SM2DSA, BSL_CID_SHA1},
    {BSL_CID_SM2DSAWITHSHA256, BSL_CID_SM2DSA, BSL_CID_SHA256},
    {BSL_CID_ED25519, BSL_CID_ED25519, BSL_CID_SHA512},
};

#ifdef HITLS_BSL_HASH
static void FreeBslSignIdMap(void *data)
{
    BSL_SignIdMap *signIdMap = (BSL_SignIdMap *)data;
    BSL_SAL_Free(signIdMap);
}

static void *DupBslSignIdMap(void *data, size_t size)
{
    if (data == NULL || size != sizeof(BSL_SignIdMap)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }
    BSL_SignIdMap *signIdMap = (BSL_SignIdMap *)data;
    BSL_SignIdMap *newSignIdMap = BSL_SAL_Malloc(sizeof(BSL_SignIdMap));
    if (newSignIdMap == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    newSignIdMap->signId = signIdMap->signId;
    newSignIdMap->asymId = signIdMap->asymId;
    newSignIdMap->hashId = signIdMap->hashId;
    return (void *)newSignIdMap;
}

static void InitSignHashTableOnce(void)
{
    int32_t ret = BSL_SAL_ThreadLockNew(&g_signHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return;
    }

    ListDupFreeFuncPair valueFunc = {DupBslSignIdMap, FreeBslSignIdMap};
    g_signHashTable = BSL_HASH_Create(BSL_OBJ_SIGN_HASH_BKT_SIZE, NULL, NULL, NULL, &valueFunc);
    if (g_signHashTable == NULL) {
        (void)BSL_SAL_ThreadLockFree(g_signHashRwLock);
        g_signHashRwLock = NULL;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
    }
}
#endif

BslCid BSL_OBJ_GetHashIdFromSignId(BslCid signAlg)
{
    if (signAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    
    // First, search in the static g_signIdMap table
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].hashId;
        }
    }
#ifndef HITLS_BSL_HASH
    return BSL_CID_UNKNOWN;
#else
    if (g_signHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    // Second, search in the dynamic hash table with read lock
    BSL_SignIdMap *signIdMap = NULL;
    int32_t ret = BSL_SAL_ThreadReadLock(g_signHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_CID_UNKNOWN;
    }
    ret = BSL_HASH_At(g_signHashTable, (uintptr_t)signAlg, (uintptr_t *)&signIdMap);
    BslCid result = (ret == BSL_SUCCESS && signIdMap != NULL) ? signIdMap->hashId : BSL_CID_UNKNOWN;
    (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);

    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_FIND_HASH_TABLE);
    }

    return result;
#endif
}

BslCid BSL_OBJ_GetAsymAlgIdFromSignId(BslCid signAlg)
{
    if (signAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }

    // First, search in the static g_signIdMap table
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].asymId;
        }
    }

#ifndef HITLS_BSL_HASH
    return BSL_CID_UNKNOWN;
#else
    if (g_signHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    // Second, search in the dynamic hash table with read lock
    BSL_SignIdMap *signIdMap = NULL;
    int32_t ret = BSL_SAL_ThreadReadLock(g_signHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_CID_UNKNOWN;
    }
    ret = BSL_HASH_At(g_signHashTable, (uintptr_t)signAlg, (uintptr_t *)&signIdMap);
    BslCid asymCid = (ret == BSL_SUCCESS && signIdMap != NULL) ? signIdMap->asymId : BSL_CID_UNKNOWN;
    (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);
    
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_FIND_HASH_TABLE);
    }

    return asymCid;
#endif
}

BslCid BSL_OBJ_GetSignIdFromHashAndAsymId(BslCid asymAlg, BslCid hashAlg)
{
    if (asymAlg == BSL_CID_ED25519) {
        return BSL_CID_ED25519;
    }
    if (asymAlg == BSL_CID_UNKNOWN || hashAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    
    // First, search in the static g_signIdMap table
    for (uint32_t i = 0; i < sizeof(g_signIdMap) / sizeof(g_signIdMap[0]); i++) {
        if (g_signIdMap[i].asymId == asymAlg && g_signIdMap[i].hashId == hashAlg) {
            return g_signIdMap[i].signId;
        }
    }
#ifndef HITLS_BSL_HASH
    return BSL_CID_UNKNOWN;
#else
    if (g_signHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    
    // Second, search in the dynamic hash table with read lock
    BSL_SignIdMap *signIdMap = NULL;
    BslCid signCid = BSL_CID_UNKNOWN;
    int32_t ret = BSL_SAL_ThreadReadLock(g_signHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_CID_UNKNOWN;
    }
    BSL_HASH_Iterator iter = BSL_HASH_IterBegin(g_signHashTable);
    BSL_HASH_Iterator end = BSL_HASH_IterEnd(g_signHashTable);

    while (iter != end) {
        uintptr_t value = BSL_HASH_IterValue(g_signHashTable, iter);
        signIdMap = (BSL_SignIdMap *)value;
        if (signIdMap->asymId == asymAlg && signIdMap->hashId == hashAlg) {
            signCid = signIdMap->signId;
            break;
        }
        iter = BSL_HASH_IterNext(g_signHashTable, iter);
    }
    (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);

    if (signCid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_FIND_HASH_TABLE);
    }
    
    return signCid;
#endif
}

#ifdef HITLS_BSL_HASH
static bool IsSignIdInStaticTable(int32_t signId)
{
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signId == (int32_t)g_signIdMap[iter].signId) {
            return true;
        }
    }
    return false;
}

static int32_t IsSignIdInHashTable(int32_t signId)
{
    BSL_SignIdMap *signIdMap = NULL;
    int32_t ret = BSL_SAL_ThreadReadLock(g_signHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_HASH_At(g_signHashTable, (uintptr_t)signId, (uintptr_t *)&signIdMap);
    (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);
    if (ret != BSL_SUCCESS || signIdMap == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_FIND_HASH_TABLE);
        return BSL_OBJ_ERR_FIND_HASH_TABLE;
    }
    return BSL_SUCCESS;
}

// Inserts a new signature ID mapping into the hash table (using write lock)
static int32_t InsertSignIdMapping(int32_t signId, int32_t asymId, int32_t hashId)
{
    BSL_SignIdMap *signIdMap = NULL;
    BSL_SignIdMap newSignIdMap = {signId, asymId, hashId};
    int32_t ret = BSL_SAL_ThreadWriteLock(g_signHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_HASH_At(g_signHashTable, (uintptr_t)signId, (uintptr_t *)&signIdMap);
    if (ret == BSL_SUCCESS && signIdMap != NULL) {
        (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);
        return BSL_SUCCESS;
    }
    ret = BSL_HASH_Insert(g_signHashTable, (uintptr_t)signId, sizeof(BslCid),
        (uintptr_t)&newSignIdMap, sizeof(BSL_SignIdMap));
    if (ret != BSL_SUCCESS) {
        (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_INSERT_HASH_TABLE);
        return BSL_OBJ_ERR_INSERT_HASH_TABLE;
    }

    (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);
    return BSL_SUCCESS;
}

// Main function - now more concise
int32_t BSL_OBJ_CreateSignId(int32_t signId, int32_t asymId, int32_t hashId)
{
    // Parameter validation
    if (signId == BSL_CID_UNKNOWN || asymId == BSL_CID_UNKNOWN || hashId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    if (IsSignIdInStaticTable(signId)) {
        return BSL_SUCCESS;
    }

    int32_t ret = BSL_SAL_ThreadRunOnce(&g_signHashInitOnce, InitSignHashTableOnce);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (g_signHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_OBJ_INVALID_HASH_TABLE;
    }
    ret = IsSignIdInHashTable(signId);
    if (ret == BSL_SUCCESS) {
        return BSL_SUCCESS;
    }

    return InsertSignIdMapping(signId, asymId, hashId);
}

void BSL_OBJ_FreeSignHashTable(void)
{
    if (g_signHashTable != NULL) {
        int32_t ret = BSL_SAL_ThreadWriteLock(g_signHashRwLock);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return;
        }
        BSL_HASH_Destory(g_signHashTable);
        g_signHashTable = NULL;
        (void)BSL_SAL_ThreadUnlock(g_signHashRwLock);
        if (g_signHashRwLock != NULL) {
            (void)BSL_SAL_ThreadLockFree(g_signHashRwLock);
            g_signHashRwLock = NULL;
        }
        g_signHashInitOnce = BSL_SAL_ONCE_INIT;
    }
}
#endif // HITLS_BSL_HASH

#endif
