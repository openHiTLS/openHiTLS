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
#include <pthread.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
/* END_HEADER */

extern BslOidInfo g_oidTable[];
extern uint32_t g_tableSize;

static int32_t PthreadRunOnce(uint32_t *onceControl, BSL_SAL_ThreadInitRoutine initFunc)
{
    if (onceControl == NULL || initFunc == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }

    pthread_once_t *tmpOnce = (pthread_once_t *)onceControl;
    if (pthread_once(tmpOnce, initFunc) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

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
void SDV_BSL_OBJ_CREATE_SIGN_ID_TC001(void)
{
#ifndef HITLS_BSL_OBJ_CUSTOM
    SKIP_TEST();
#else
    BslCid signId = BSL_CID_MAX - 1;
    BslCid asymId = BSL_CID_RSA;
    BslCid hashId = BSL_CID_MAX - 2;

    TestMemInit();
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_RUN_ONCE_CB_FUNC, PthreadRunOnce);
    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, hashId), BSL_SUCCESS);

    BslCid retrievedAsymId = BSL_OBJ_GetAsymAlgIdFromSignId(signId);
    ASSERT_EQ(asymId, retrievedAsymId);

    BslCid retrievedHashId = BSL_OBJ_GetHashIdFromSignId(signId);
    ASSERT_EQ(hashId, retrievedHashId);

    BslCid retrievedSignId = BSL_OBJ_GetSignIdFromHashAndAsymId(asymId, hashId);
    ASSERT_EQ(signId, retrievedSignId);

    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, hashId), BSL_SUCCESS);
    signId = BSL_CID_SHA256WITHRSAENCRYPTION;
    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, hashId), BSL_SUCCESS);

    ASSERT_EQ(BSL_OBJ_CreateSignId(BSL_CID_UNKNOWN, asymId, hashId), BSL_INVALID_ARG);

    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, BSL_CID_UNKNOWN, hashId), BSL_INVALID_ARG);

    ASSERT_EQ(BSL_OBJ_CreateSignId(signId, asymId, BSL_CID_UNKNOWN), BSL_INVALID_ARG);

    BSL_OBJ_FreeSignHashTable();
EXIT:
    return;
#endif
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
#ifndef HITLS_BSL_OBJ_CUSTOM
    SKIP_TEST();
#else
    char *testOidName = "TEST-OID";
    BslCid testCid = BSL_CID_MAX + 1;
    char testOidData[] = "\52\206\110\206\367\15\1\11\30";
    BslOidString testOid = {9, testOidData, BSL_OID_GLOBAL};

    const char *aesOidName = "AES128-CBC";
    BslCid aesCid = BSL_CID_AES128_CBC;
    char aesOidData[] = "\140\206\110\1\145\3\4\1\2";

    TestMemInit();
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_RUN_ONCE_CB_FUNC, PthreadRunOnce);
    ASSERT_EQ(BSL_OBJ_Create(aesOidData, 9, aesOidName, aesCid), BSL_SUCCESS);

    ASSERT_EQ(BSL_OBJ_Create(testOidData, 9, testOidName, testCid), BSL_SUCCESS);

    BslCid retrievedCid = BSL_OBJ_GetCID(&testOid);
    ASSERT_EQ(testCid, retrievedCid);

    BslOidString *retrievedOid = BSL_OBJ_GetOID(testCid);
    ASSERT_TRUE(retrievedOid != NULL);
    ASSERT_EQ(testOid.octetLen, retrievedOid->octetLen);
    ASSERT_EQ(memcmp(testOid.octs, retrievedOid->octs, testOid.octetLen), 0);

    const char *retrievedName = BSL_OBJ_GetOidNameFromOid(&testOid);
    ASSERT_TRUE(retrievedName != NULL);
    ASSERT_EQ(strcmp(testOidName, retrievedName), 0);

    ASSERT_EQ(BSL_OBJ_Create(testOidData, 9, testOidName, testCid), BSL_SUCCESS);

    ASSERT_EQ(BSL_OBJ_Create(NULL, 9, testOidName, testCid), BSL_INVALID_ARG);

    ASSERT_EQ(BSL_OBJ_Create(testOidData, 9, NULL, testCid), BSL_INVALID_ARG);

    ASSERT_EQ(BSL_OBJ_Create(testOidData, 9, testOidName, BSL_CID_UNKNOWN), BSL_INVALID_ARG);
    
    BSL_OBJ_FreeHashTable();
EXIT:
    return;
#endif
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
#ifndef HITLS_BSL_OBJ_CUSTOM
    SKIP_TEST();
#else
    int32_t ret;
    BslOidString testOid1, testOid2;
    const char *testOidName1 = "TEST-OID-1";
    const char *testOidName2 = "TEST-OID-2";
    BslCid testCid1 = BSL_CID_MAX + 1;
    BslCid testCid2 = BSL_CID_MAX + 2;

    char testOidData1[] = "\52\206\110\206\367\15\1\11\31";
    char testOidData2[] = "\52\206\110\206\367\15\1\11\32";

    testOid1.octetLen = sizeof(testOidData1);
    testOid1.octs = testOidData1;
    testOid1.flags = BSL_OID_GLOBAL;
    
    testOid2.octetLen = sizeof(testOidData2);
    testOid2.octs = testOidData2;
    testOid2.flags = BSL_OID_GLOBAL;

    TestMemInit();
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_RUN_ONCE_CB_FUNC, PthreadRunOnce);
    ret = BSL_OBJ_Create(testOidData1, sizeof(testOidData1), testOidName1, testCid1);
    ASSERT_EQ(BSL_SUCCESS, ret);

    ret = BSL_OBJ_Create(testOidData2, sizeof(testOidData2), testOidName2, testCid2);
    ASSERT_EQ(BSL_SUCCESS, ret);

    BslCid retrievedCid1 = BSL_OBJ_GetCID(&testOid1);
    ASSERT_EQ(testCid1, retrievedCid1);

    BslCid retrievedCid2 = BSL_OBJ_GetCID(&testOid2);
    ASSERT_EQ(testCid2, retrievedCid2);

    BslOidString *retrievedOid1 = BSL_OBJ_GetOID(testCid1);
    ASSERT_TRUE(retrievedOid1 != NULL);
    ASSERT_EQ(testOid1.octetLen, retrievedOid1->octetLen);
    ASSERT_EQ(memcmp(testOid1.octs, retrievedOid1->octs, testOid1.octetLen), 0);

    BslOidString *retrievedOid2 = BSL_OBJ_GetOID(testCid2);
    ASSERT_TRUE(retrievedOid2 != NULL);
    ASSERT_EQ(testOid2.octetLen, retrievedOid2->octetLen);
    ASSERT_EQ(memcmp(testOid2.octs, retrievedOid2->octs, testOid2.octetLen), 0);

    const char *retrievedName1 = BSL_OBJ_GetOidNameFromOid(&testOid1);
    ASSERT_TRUE(retrievedName1 != NULL);
    ASSERT_EQ(strcmp(testOidName1, retrievedName1), 0);

    const char *retrievedName2 = BSL_OBJ_GetOidNameFromOid(&testOid2);
    ASSERT_TRUE(retrievedName2 != NULL);
    ASSERT_EQ(strcmp(testOidName2, retrievedName2), 0);

    BSL_OBJ_FreeHashTable();
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_GetOIDNUMBERICSTRING_FUNC_TC001
 * @title Test converting an ASN.1 OID to its numeric representation
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_GetOIDNUMBERICSTRING_FUNC_TC001(Hex *str, char *expect)
{
    char *oid = NULL;
    uint8_t *hexOid = NULL;
    TestMemInit();
    oid = BSL_OBJ_GetOidNumericString(str->x, str->len);
    ASSERT_TRUE(oid != NULL);
    ASSERT_EQ(memcmp(oid, expect, strlen(expect)), 0);

    uint32_t outLen = 0;
    hexOid = BSL_OBJ_GetOidFromNumericString(expect, strlen(expect), &outLen);
    ASSERT_TRUE(hexOid != NULL);
    ASSERT_EQ(outLen, str->len);
    ASSERT_COMPARE("test obj", hexOid, outLen, str->x, str->len);

EXIT:
    if (oid != NULL) {
        free(oid);
    }
    BSL_SAL_Free(hexOid);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_GetOIDNUMBERICSTRING_FUNC_TC002
 * @title Test converting an ASN.1 OID to its numeric representation (Counterexample)
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_GetOIDNUMBERICSTRING_FUNC_TC002(Hex *str)
{
    ASSERT_TRUE(BSL_OBJ_GetOidNumericString(str->x, str->len) == NULL);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OBJ_GetOIDNUMBERICSTRING_FUNC_TC001
 * @title Exception Parameter Testing for the BSL_OBJ_GetOidFromNumericString Function.
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_GETOID_FROM_NUMBERIC_FUNC_TC001(char *expect)
{
    TestMemInit();
    uint32_t outLen = 0;
    uint8_t *hexOid = NULL;
    ASSERT_TRUE(BSL_OBJ_GetOidFromNumericString(NULL, 0, &outLen) == NULL);
    ASSERT_TRUE(BSL_OBJ_GetOidFromNumericString(expect, strlen(expect), NULL) == NULL);
    hexOid = BSL_OBJ_GetOidFromNumericString(expect, strlen(expect), &outLen);
    ASSERT_TRUE(hexOid == NULL);
EXIT:
    BSL_SAL_FREE(hexOid);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_OID_LENGTH_CHECK_TC001
 * @title Verify that octetLen matches the actual length of octs in OID table
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OID_LENGTH_CHECK_TC001()
{
    static const int32_t KNOWN_EXCEPTIONS = 5;
    
    int32_t oidIndex = 0;
    int32_t totalCount = 0;
    int32_t passedCount = 0;
    BslOidInfo oidInfo;
    uint32_t octetLen;
    uint32_t actualLen;

    while (oidIndex < (int32_t)g_tableSize) {
        oidInfo = g_oidTable[oidIndex];
        octetLen = oidInfo.strOid.octetLen;
        actualLen = strlen(oidInfo.strOid.octs);
        
        totalCount++;
        if (octetLen == actualLen) {
            passedCount++;
        }
        oidIndex++;
    }

    ASSERT_TRUE(totalCount == passedCount + KNOWN_EXCEPTIONS);
EXIT:
    return;
}
/* END_CASE */