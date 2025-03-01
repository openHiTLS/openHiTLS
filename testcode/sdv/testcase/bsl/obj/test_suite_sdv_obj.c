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

/* BEGIN_HEADER */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
/* END_HEADER */

extern BslOidInfo g_oidTable[];
extern uint32_t g_tableSize;
/**
 * @test SDV_BSL_OBJ_CID_OID_FUNC_TC001
 * @title check whether the relative sequence of cid and oid tables is corrent
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_CID_OID_FUNC_TC001()
{
    int32_t cidIndex = 0;
    int32_t oidIndex = 0;
    int32_t ret = 0;
    while (cidIndex < BSL_CID_MAX && oidIndex < (int32_t)g_tableSize) {
        if ((int32_t)g_oidTable[oidIndex].cid == cidIndex) {
            ret++;
            cidIndex++;
            oidIndex++;
            continue;
        }
        if ((int32_t)g_oidTable[oidIndex].cid > cidIndex) {
            cidIndex++;
            continue;
        }
        oidIndex++;
    }
    ASSERT_TRUE(ret == (int32_t)g_tableSize);
EXIT:
    return;
}

/* END_CASE */

/**
 * @test SDV_BSL_OBJ_CREATE_SIGN_ID_TC001
 * @title Test BSL_OBJ_CreateSignId functionality
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_CREATE_SIGN_ID_TC001()
{
    BslCid signId = BSL_CID_MAX - 1;
    BslCid asymId = BSL_CID_RSA;
    BslCid hashId = BSL_CID_SHA256;
    
    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, hashId), BSL_SUCCESS);
    
    BslCid retrievedAsymId = BSL_OBJ_GetAsymIdFromSignId(signId);
    ASSERT_EQ(asymId, retrievedAsymId);
    
    BslCid retrievedHashId = BSL_OBJ_GetHashIdFromSignId(signId);
    ASSERT_EQ(hashId, retrievedHashId);

    BslCid retrievedSignId = BSL_OBJ_GetSignIdFromHashAndAsymId(asymId, hashId);
    ASSERT_EQ(signId, retrievedSignId);
    
    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, hashId), BSL_OBJ_IS_EXIST);
    signId = BSL_CID_SHA256WITHRSAENCRYPTION;
    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, hashId), BSL_OBJ_IS_EXIST);

    ASSERT_EQ(BSL_OBJ_CreateSignId(BSL_CID_UNKNOWN, asymId, hashId), BSL_INVALID_ARG);
    
    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, BSL_CID_UNKNOWN, hashId), BSL_INVALID_ARG);
    
    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, BSL_CID_UNKNOWN), BSL_INVALID_ARG);

    BSL_OBJ_FreeSignHashTable();
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_CREATE_TC001
 * @title Test BSL_OBJ_Create functionality
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_CREATE_TC001()
{
    int32_t ret;
    BslOidString testOid;
    const char *testOidName = "TEST-OID";
    BslCid testCid = BSL_CID_MAX - 2;
    char testOidData[] = "\52\206\110\206\367\15\1\11\30";
    
    testOid.octetLen = sizeof(testOidData);
    testOid.octs = testOidData;
    testOid.flags = BSL_OID_GLOBAL;
    
    ret = BSL_OBJ_Create(&testOid, testOidName, testCid);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    BslCid retrievedCid = BSL_OBJ_GetCIDFromOid(&testOid);
    ASSERT_EQ(testCid, retrievedCid);
    
    BslOidString *retrievedOid = BSL_OBJ_GetOidFromCID(testCid);
    ASSERT_NOT_NULL(retrievedOid);
    ASSERT_EQ(testOid.octetLen, retrievedOid->octetLen);
    ASSERT_EQ(0, memcmp(testOid.octs, retrievedOid->octs, testOid.octetLen));
    
    const char *retrievedName = BSL_OBJ_GetOidNameFromOid(&testOid);
    ASSERT_NOT_NULL(retrievedName);
    ASSERT_STRING_EQUAL(testOidName, retrievedName);
    
    ASSERT_EQ(BSL_OBJ_Create(&testOid, testOidName, testCid), BSL_OBJ_IS_EXIST);
    
    ASSERT_EQ(BSL_OBJ_Create(NULL, testOidName, testCid), BSL_INVALID_ARG);
    
    ASSERT_EQ(BSL_OBJ_Create(&testOid, NULL, testCid), BSL_INVALID_ARG);
    
    ASSERT_EQ(BSL_OBJ_Create(&testOid, testOidName, BSL_CID_UNKNOWN), BSL_INVALID_ARG);
    
    ASSERT_EQ(BSL_OBJ_Create(&testOid, testOidName, BSL_CID_MAX), BSL_INVALID_ARG);
    
    BSL_OBJ_FreeHashTable();
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_HASH_TABLE_LOOKUP_TC001
 * @title Test hash table lookup functionality for OIDs and CIDs
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_HASH_TABLE_LOOKUP_TC001()
{
    int32_t ret;
    BslOidString testOid1, testOid2;
    const char *testOidName1 = "TEST-OID-1";
    const char *testOidName2 = "TEST-OID-2";
    BslCid testCid1 = BSL_CID_MAX - 3;
    BslCid testCid2 = BSL_CID_MAX - 4;
    
    char testOidData1[] = "\52\206\110\206\367\15\1\11\30";
    char testOidData2[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x21};

    testOid1.octetLen = sizeof(testOidData1);
    testOid1.octs = testOidData1;
    testOid1.flags = BSL_OID_GLOBAL;
    
    testOid2.octetLen = sizeof(testOidData2);
    testOid2.octs = testOidData2;
    testOid2.flags = BSL_OID_GLOBAL;
    
    ret = BSL_OBJ_Create(&testOid1, testOidName1, testCid1);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    ret = BSL_OBJ_Create(&testOid2, testOidName2, testCid2);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    BslCid retrievedCid1 = BSL_OBJ_GetCIDFromOid(&testOid1);
    ASSERT_EQ(testCid1, retrievedCid1);
    
    BslCid retrievedCid2 = BSL_OBJ_GetCIDFromOid(&testOid2);
    ASSERT_EQ(testCid2, retrievedCid2);
    
    BslOidString *retrievedOid1 = BSL_OBJ_GetOidFromCID(testCid1);
    ASSERT_NOT_NULL(retrievedOid1);
    ASSERT_EQ(testOid1.octetLen, retrievedOid1->octetLen);
    ASSERT_EQ(0, memcmp(testOid1.octs, retrievedOid1->octs, testOid1.octetLen));
    
    BslOidString *retrievedOid2 = BSL_OBJ_GetOidFromCID(testCid2);
    ASSERT_NOT_NULL(retrievedOid2);
    ASSERT_EQ(testOid2.octetLen, retrievedOid2->octetLen);
    ASSERT_EQ(0, memcmp(testOid2.octs, retrievedOid2->octs, testOid2.octetLen));
    
    const char *retrievedName1 = BSL_OBJ_GetOidNameFromOid(&testOid1);
    ASSERT_NOT_NULL(retrievedName1);
    ASSERT_STRING_EQUAL(testOidName1, retrievedName1);
    
    const char *retrievedName2 = BSL_OBJ_GetOidNameFromOid(&testOid2);
    ASSERT_NOT_NULL(retrievedName2);
    ASSERT_STRING_EQUAL(testOidName2, retrievedName2);
    
    BSL_OBJ_FreeHashTable();
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_CREATE_TC002
 * @title Test BSL_OBJ_Create with octal string notation
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_CREATE_TC002()
{
    int32_t ret;
    BslOidString testOid;
    const char *testOidName = "TEST-OID-OCTAL";
    BslCid testCid = BSL_CID_MAX - 5;
    
    // Initialize test OID with octal string notation
    testOid.octetLen = 9;
    testOid.octs = "\52\206\110\206\367\15\1\11\30"; // Similar format to existing OIDs
    testOid.flags = BSL_OID_GLOBAL;
    
    // Test case 1: Create a new OID mapping
    ret = BSL_OBJ_Create(&testOid, testOidName, testCid);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    // Verify the mapping was created correctly
    BslCid retrievedCid = BSL_OBJ_GetCIDFromOid(&testOid);
    ASSERT_EQ(testCid, retrievedCid);
    
    BslOidString *retrievedOid = BSL_OBJ_GetOidFromCID(testCid);
    ASSERT_NOT_NULL(retrievedOid);
    ASSERT_EQ(testOid.octetLen, retrievedOid->octetLen);
    ASSERT_EQ(0, memcmp(testOid.octs, retrievedOid->octs, testOid.octetLen));
    
    const char *retrievedName = BSL_OBJ_GetOidNameFromOid(&testOid);
    ASSERT_NOT_NULL(retrievedName);
    ASSERT_STRING_EQUAL(testOidName, retrievedName);
    
    // Clean up
    BSL_OBJ_FreeHashTable();
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_HASH_TABLE_LOOKUP_TC002
 * @title Test hash table lookup with multiple octal string OIDs
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_HASH_TABLE_LOOKUP_TC002()
{
    int32_t ret;
    BslOidString testOid1, testOid2;
    const char *testOidName1 = "TEST-OID-OCTAL-1";
    const char *testOidName2 = "TEST-OID-OCTAL-2";
    BslCid testCid1 = BSL_CID_MAX - 6;
    BslCid testCid2 = BSL_CID_MAX - 7;
    
    // Initialize test OIDs with octal string notation
    testOid1.octetLen = 9;
    testOid1.octs = "\52\206\110\206\367\15\1\11\31"; // Similar format to existing OIDs
    testOid1.flags = BSL_OID_GLOBAL;
    
    testOid2.octetLen = 9;
    testOid2.octs = "\52\206\110\206\367\15\1\11\32"; // Similar format to existing OIDs
    testOid2.flags = BSL_OID_GLOBAL;
    
    // Create multiple OID mappings
    ret = BSL_OBJ_Create(&testOid1, testOidName1, testCid1);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    ret = BSL_OBJ_Create(&testOid2, testOidName2, testCid2);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    // Test lookup by OID
    BslCid retrievedCid1 = BSL_OBJ_GetCIDFromOid(&testOid1);
    ASSERT_EQ(testCid1, retrievedCid1);
    
    BslCid retrievedCid2 = BSL_OBJ_GetCIDFromOid(&testOid2);
    ASSERT_EQ(testCid2, retrievedCid2);
    
    // Test lookup by CID
    BslOidString *retrievedOid1 = BSL_OBJ_GetOidFromCID(testCid1);
    ASSERT_NOT_NULL(retrievedOid1);
    ASSERT_EQ(testOid1.octetLen, retrievedOid1->octetLen);
    ASSERT_EQ(0, memcmp(testOid1.octs, retrievedOid1->octs, testOid1.octetLen));
    
    BslOidString *retrievedOid2 = BSL_OBJ_GetOidFromCID(testCid2);
    ASSERT_NOT_NULL(retrievedOid2);
    ASSERT_EQ(testOid2.octetLen, retrievedOid2->octetLen);
    ASSERT_EQ(0, memcmp(testOid2.octs, retrievedOid2->octs, testOid2.octetLen));
    
    // Test lookup by OID for name
    const char *retrievedName1 = BSL_OBJ_GetOidNameFromOid(&testOid1);
    ASSERT_NOT_NULL(retrievedName1);
    ASSERT_STRING_EQUAL(testOidName1, retrievedName1);
    
    const char *retrievedName2 = BSL_OBJ_GetOidNameFromOid(&testOid2);
    ASSERT_NOT_NULL(retrievedName2);
    ASSERT_STRING_EQUAL(testOidName2, retrievedName2);
    
    // Clean up
    BSL_OBJ_FreeHashTable();
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_CREATE_SIGN_ID_TC002
 * @title Test BSL_OBJ_CreateSignId with multiple mappings
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_CREATE_SIGN_ID_TC002()
{
    int32_t ret;
    
    // Create multiple sign ID mappings
    BslCid signId1 = BSL_CID_MAX - 8;
    BslCid asymId1 = BSL_CID_RSA;
    BslCid hashId1 = BSL_CID_SHA256;
    
    BslCid signId2 = BSL_CID_MAX - 9;
    BslCid asymId2 = BSL_CID_ECDSA;
    BslCid hashId2 = BSL_CID_SHA384;
    
    // Create first mapping
    ret = BSL_OBJ_CreateSignId(signId1, asymId1, hashId1);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    // Create second mapping
    ret = BSL_OBJ_CreateSignId(signId2, asymId2, hashId2);
    ASSERT_EQ(BSL_SUCCESS, ret);
    
    // Verify first mapping
    BslCid retrievedAsymId1 = BSL_OBJ_GetAsymIdFromSignId(signId1);
    ASSERT_EQ(asymId1, retrievedAsymId1);
    
    BslCid retrievedHashId1 = BSL_OBJ_GetHashIdFromSignId(signId1);
    ASSERT_EQ(hashId1, retrievedHashId1);
    
    BslCid retrievedSignId1 = BSL_OBJ_GetSignIdFromHashAndAsymId(asymId1, hashId1);
    ASSERT_EQ(signId1, retrievedSignId1);
    
    // Verify second mapping
    BslCid retrievedAsymId2 = BSL_OBJ_GetAsymIdFromSignId(signId2);
    ASSERT_EQ(asymId2, retrievedAsymId2);
    
    BslCid retrievedHashId2 = BSL_OBJ_GetHashIdFromSignId(signId2);
    ASSERT_EQ(hashId2, retrievedHashId2);
    
    BslCid retrievedSignId2 = BSL_OBJ_GetSignIdFromHashAndAsymId(asymId2, hashId2);
    ASSERT_EQ(signId2, retrievedSignId2);
    
    // Test non-existent mapping
    BslCid nonExistentSignId = BSL_CID_MAX - 10;
    retrievedAsymId1 = BSL_OBJ_GetAsymIdFromSignId(nonExistentSignId);
    ASSERT_EQ(BSL_CID_UNKNOWN, retrievedAsymId1);
    
    retrievedSignId1 = BSL_OBJ_GetSignIdFromHashAndAsymId(asymId1, hashId2);
    ASSERT_EQ(BSL_CID_UNKNOWN, retrievedSignId1);
    
    // Clean up
    BSL_OBJ_FreeSignHashTable();
EXIT:
    return;
}
/* END_CASE */