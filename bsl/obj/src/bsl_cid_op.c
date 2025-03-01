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
#include "bsl_hash.h"

BSL_HASH_Hash *g_signHashTable = NULL;
#define BSL_OBJ_SIGN_HASH_BKT_SIZE 64u
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
    {BSL_CID_SM2DSAWITHSM3, BSL_CID_SM2, BSL_CID_SM3},
    {BSL_CID_SM2DSAWITHSHA1, BSL_CID_SM2, BSL_CID_SHA1},
    {BSL_CID_SM2DSAWITHSHA256, BSL_CID_SM2, BSL_CID_SHA256},
};

BslCid BSL_OBJ_GetHashIdFromSignId(BslCid signAlg)
{
    if (signAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    /* First, search in the g_signIdMap */
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].hashId;
        }
    }
    /* Second, search in the g_signHashTable */
    if (g_signHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    BSL_SignIdMap *signIdMap = NULL;
    int32_t ret = BSL_HASH_At(g_signHashTable, (uintptr_t)signAlg, (uintptr_t *)&signIdMap);
    if (ret != BSL_SUCCESS) {
        return BSL_CID_UNKNOWN;
    }
    if (signIdMap != NULL && signIdMap->signId == signAlg) {
        return signIdMap->hashId;
    }

    return BSL_CID_UNKNOWN;
}

BslCid BSL_OBJ_GetAsymIdFromSignId(BslCid signAlg)
{
    if (signAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    /* First, search in the g_signIdMap */
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].asymId;
        }
    }
    /* Second, search in the g_signHashTable */
    if (g_signHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    BSL_SignIdMap *signIdMap = NULL;
    int32_t ret = BSL_HASH_At(g_signHashTable, (uintptr_t)signAlg, (uintptr_t *)&signIdMap);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_FIND_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    if (signIdMap != NULL && signIdMap->signId == signAlg) {
        return signIdMap->asymId;
    }

    return BSL_CID_UNKNOWN;
}

BslCid BSL_OBJ_GetSignIdFromHashAndAsymId(BslCid asymAlg, BslCid hashAlg)
{
    if (asymAlg == BSL_CID_UNKNOWN || hashAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    /* First, search in the g_signIdMap */  
    for (uint32_t i = 0; i < sizeof(g_signIdMap) / sizeof(g_signIdMap[0]); i++) {
        if (g_signIdMap[i].asymId == asymAlg && g_signIdMap[i].hashId == hashAlg) {
            return g_signIdMap[i].signId;
        }
    }
    /* Second, search in the g_signHashTable */
    if (g_signHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    BSL_SignIdMap *signIdMap = NULL;
    int32_t ret = BSL_HASH_At(g_signHashTable, (uintptr_t)asymAlg, (uintptr_t *)&signIdMap);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_FIND_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }
    if (signIdMap != NULL && signIdMap->asymId == asymAlg && signIdMap->hashId == hashAlg) {
        return signIdMap->signId;
    }
    return BSL_CID_UNKNOWN;
}

int32_t BSL_OBJ_CreateSignId(int32_t signId, int32_t asymId, int32_t hashId)
{
    if (signId == BSL_CID_UNKNOWN || asymId == BSL_CID_UNKNOWN || hashId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signId == (int32_t)g_signIdMap[iter].signId) {
            BSL_ERR_PUSH_ERROR(BSL_OBJ_IS_EXIST);
            return BSL_OBJ_IS_EXIST;
        }
    }

    if (g_signHashTable == NULL) {
        g_signHashTable = BSL_HASH_Create(BSL_OBJ_SIGN_HASH_BKT_SIZE, NULL, NULL, NULL, NULL);
        if (g_signHashTable == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }
    BSL_SignIdMap *signIdMap = NULL;
    int32_t ret = BSL_HASH_At(g_signHashTable, (uintptr_t)signId, (uintptr_t *)&signIdMap);
    if (ret == BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_IS_EXIST);
        return BSL_OBJ_IS_EXIST;
    }
    BSL_SignIdMap *newSignIdMap = (BSL_SignIdMap *)BSL_SAL_Calloc(1, sizeof(BSL_SignIdMap));
    if (newSignIdMap == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    newSignIdMap->signId = signId;
    newSignIdMap->asymId = asymId;
    newSignIdMap->hashId = hashId;
    ret = BSL_HASH_Insert(g_signHashTable, (uintptr_t)signId, sizeof(BslCid), (uintptr_t)newSignIdMap,
        sizeof(BSL_SignIdMap));
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(newSignIdMap);
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_INSERT_HASH_TABLE);
        return BSL_OBJ_ERR_INSERT_HASH_TABLE;
    }

    uint64_t asymAndHashKey = ((uint64_t)asymId << 32) | ((uint64_t)hashId & 0xFFFFFFFF);
    ret = BSL_HASH_Insert(g_signHashTable, (uintptr_t)asymAndHashKey, sizeof(uintptr_t), (uintptr_t)signId,
        sizeof(BslCid));
    if (ret != BSL_SUCCESS) {
        BSL_HASH_Erase(g_signHashTable, (uintptr_t)signId);
        BSL_SAL_Free(newSignIdMap);
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_INSERT_HASH_TABLE);
        return BSL_OBJ_ERR_INSERT_HASH_TABLE;
    }

    return BSL_SUCCESS;
}

void BSL_OBJ_FreeSignHashTable(void)
{
    if (g_signHashTable != NULL) {
        BSL_HASH_Destory(g_signHashTable);
        g_signHashTable = NULL;
    }
}

#endif
