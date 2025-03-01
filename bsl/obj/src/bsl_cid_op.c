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
#include "bsl_obj_internal.h"
#include "bsl_hash.h"

BSL_HASH_Hash *g_signHashTable = NULL;
typedef struct BslSignIdMap {
    BslCid signId;
    BslCid asymId;
    BslCid hashId;
} BSL_SignIdMap;

BSL_SignIdMap g_signIdMap[] = {
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
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].hashId;
        }
    }
    return BSL_CID_UNKNOWN;
}

BslCid BSL_OBJ_GetAsymIdFromSignId(BslCid signAlg)
{
    if (signAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].asymId;
        }
    }
    return BSL_CID_UNKNOWN;
}

int32_t BSL_OBJ_CreateSignId(BslCid signId, BslCid asymId, BslCid hashId)
{
    if (signId == BSL_CID_UNKNOWN || asymId == BSL_CID_UNKNOWN || hashId == BSL_CID_UNKNOWN) {
        return BSL_INTERNAL_EXCEPTION;
    }

    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signId == g_signIdMap[iter].signId) {
            return BSL_INTERNAL_EXCEPTION; // 已存在该签名ID
        }
    }

    if (g_signHashTable == NULL) {
        g_signHashTable = BSL_HASH_Create(32, BSL_HASH_CodeCalcInt, BSL_HASH_MatchInt, NULL, NULL);
        if (g_signHashTable == NULL) {
            return BSL_INTERNAL_EXCEPTION;
        }
    }

    BSL_SignIdMap *newMap = (BSL_SignIdMap *)BSL_SAL_Calloc(1, sizeof(BSL_SignIdMap));
    if (newMap == NULL) {
        if (BSL_HASH_Empty(g_signHashTable)) {
            BSL_HASH_Destory(g_signHashTable);
            g_signHashTable = NULL;
        }
        return BSL_INTERNAL_EXCEPTION;
    }

    newMap->signId = signId;
    newMap->asymId = asymId;
    newMap->hashId = hashId;

    int32_t ret = BSL_HASH_Insert(g_signHashTable, (uintptr_t)signId, sizeof(BslCid), 
                                  (uintptr_t)newMap, sizeof(BSL_SignIdMap));
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(newMap);
        return BSL_INTERNAL_EXCEPTION;
    }

    uintptr_t asymAndHashKey = ((uintptr_t)asymId << 32) | (uintptr_t)hashId;
    
    ret = BSL_HASH_Insert(g_signHashTable, asymAndHashKey, sizeof(uintptr_t), 
                          (uintptr_t)signId, sizeof(BslCid));
    if (ret != BSL_SUCCESS) {
        BSL_HASH_Erase(g_signHashTable, (uintptr_t)signId);
        BSL_SAL_Free(newMap);
        return BSL_INTERNAL_EXCEPTION;
    }

    return BSL_SUCCESS;
}

#endif
