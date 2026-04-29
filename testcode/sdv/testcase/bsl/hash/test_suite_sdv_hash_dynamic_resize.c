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

#include <stdio.h>
#include <string.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_err.h"
#include "list_base.h"
#include "bsl_hash.h"
#include "bsl_hash_list.h"
#include "bsl_sal.h"
#include "stub_utils.h"

#define MAX_NAME_LEN 64
/* END_HEADER */
STUB_DEFINE_RET3(void *, BSL_SAL_Realloc, void *, uint32_t, uint32_t);

typedef struct userData {
    int id;
    char name[MAX_NAME_LEN];
} UserData;

void *UserHashKeyDupFunc(void *src, size_t size)
{
    char *retKey;
    char *tmpKey = (char *)src;

    if (size > MAX_NAME_LEN) {
        return NULL;
    }

    retKey = (char *)BSL_SAL_Calloc(1, size);
    ASSERT_TRUE((char *)retKey != (char *)NULL);
    ASSERT_TRUE(strcpy_s(retKey, size, tmpKey) == EOK);

EXIT:
    return (void *)retKey;
}

void *UserHashDataDupFunc(void *src, size_t size)
{
    UserData *ret = NULL;
    UserData *tmpSrc = (UserData *)src;

    ret = (UserData *)BSL_SAL_Calloc(1, sizeof(UserData));
    ASSERT_TRUE(ret != (UserData *)NULL);
    ASSERT_TRUE(memcpy_s(ret, size + 1, tmpSrc, size) == EOK);

EXIT:
    return ret;
}

static int insert_multiple_int_elements(BSL_HASH_Hash *hash, int start, int count)
{
    for (int i = start; i < start + count; i++) {
        uintptr_t key = (uintptr_t)i;
        uintptr_t value = (uintptr_t)(i * 2);

        if (BSL_HASH_Insert(hash, key, sizeof(key), value, sizeof(value)) != BSL_SUCCESS) {
            return BSL_INTERNAL_EXCEPTION;
        }
    }
    return BSL_SUCCESS;
}

static int verify_int_elements(BSL_HASH_Hash *hash, int start, int count)
{
    for (int i = start; i < start + count; i++) {
        uintptr_t key = (uintptr_t)i;
        uintptr_t expected_value = (uintptr_t)(i * 2);
        uintptr_t actual_value;

        if (BSL_HASH_At(hash, key, &actual_value) != BSL_SUCCESS) {
            return BSL_INTERNAL_EXCEPTION;
        }

        if (actual_value != expected_value) {
            return BSL_INTERNAL_EXCEPTION;
        }
    }
    return BSL_SUCCESS;
}

static void *STUB_BSL_SAL_Realloc_Fail(void *addr, uint32_t newSize, uint32_t oldSize)
{
    (void)addr;
    (void)newSize;
    (void)oldSize;
    return NULL;
}

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC001
 * @title Hash table basic creation and insertion test
 * @precon nan
 * @brief
 *    1. Create hash table with default configuration. Expected result 1.
 *    2. Insert 10 elements without triggering expansion. Expected result 2.
 *    3. Verify initial bucketSize and all elements accessible. Expected result 3.
 * @expect
 *    1. Hash table created with initialSize = 16
 *    2. Elements inserted successfully
 *    3. bucketSize remains 16, all elements accessible
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC001(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);
    ASSERT_TRUE(hash->bucketSize == 16);
    ASSERT_TRUE(hash->initialSize == 16);

    // Insert 10 elements (load factor = 62.5%, should NOT trigger expansion)
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 10) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Size(hash) == 10);
    ASSERT_TRUE(hash->bucketSize == 16);

    // Verify all elements are accessible
    ASSERT_TRUE(verify_int_elements(hash, 0, 10) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC002
 * @title Hash table single expansion test
 * @precon nan
 * @brief
 *    1. Create hash table with default configuration. Expected result 1.
 *    2. Insert 17 elements to trigger one expansion. Expected result 2.
 *    3. Verify bucketSize increased to 17 and nextSplit moved. Expected result 3.
 *    4. Verify all elements accessible after expansion. Expected result 4.
 * @expect
 *    1. Hash table created successfully
 *    2. Expansion triggered when load factor >= 100%
 *    3. bucketSize = 17, nextSplit = 1
 *    4. All elements remain accessible
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC002(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);
    ASSERT_TRUE(hash->bucketSize == 16);

    // Insert 17 elements to trigger one expansion
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 17) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Size(hash) == 17);

    // Verify expansion occurred: bucketSize should be 17
    ASSERT_TRUE(hash->bucketSize == 17);
    ASSERT_TRUE(hash->nextSplit == 1);

    // Verify all elements are accessible
    ASSERT_TRUE(verify_int_elements(hash, 0, 17) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC004
 * @title Hash table with string keys expansion test
 * @precon nan
 * @brief
 *    1. Create hash table with string keys and custom functions. Expected result 1.
 *    2. Insert 25 string elements to trigger expansion. Expected result 2.
 *    3. Verify bucketSize increased and all elements accessible. Expected result 3.
 * @expect
 *    1. Hash table with string keys created successfully
 *    2. Expansion triggered with string keys
 *    3. bucketSize > initialSize, all string elements accessible
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC004(void)
{
    TestMemInit();
    ListDupFreeFuncPair keyFunc = {UserHashKeyDupFunc, BSL_SAL_Free};
    ListDupFreeFuncPair valueFunc = {UserHashDataDupFunc, BSL_SAL_Free};

    BSL_HASH_Hash *hash = BSL_HASH_Create(0, BSL_HASH_CodeCalcStr, BSL_HASH_MatchStr, &keyFunc, &valueFunc);
    ASSERT_TRUE(hash != NULL);

    uint32_t initialBuckets = hash->bucketSize;

    // Create string keys and user data
    char keys[25][32];
    UserData values[25];

    for (int i = 0; i < 25; i++) {
        (void)snprintf_s(keys[i], sizeof(keys[i]), sizeof(keys[i]) - 1, "key_%d", i);
        values[i].id = i;
        (void)snprintf_s(values[i].name, sizeof(values[i].name), sizeof(values[i].name) - 1, "user_%d", i);
    }

    // Insert elements to trigger expansion
    for (int i = 0; i < 25; i++) {
        ASSERT_TRUE(BSL_HASH_Insert(hash, (uintptr_t)keys[i], strlen(keys[i]) + 1, (uintptr_t)&values[i],
                                    sizeof(UserData)) == BSL_SUCCESS);
    }

    ASSERT_TRUE(BSL_HASH_Size(hash) == 25);
    ASSERT_TRUE(hash->bucketSize > initialBuckets);

    // Verify all elements are accessible
    for (int i = 0; i < 25; i++) {
        uintptr_t retrievedValue;
        ASSERT_TRUE(BSL_HASH_At(hash, (uintptr_t)keys[i], &retrievedValue) == BSL_SUCCESS);
        UserData *userData = (UserData *)retrievedValue;
        ASSERT_TRUE(userData->id == values[i].id);
        ASSERT_TRUE(strcmp(userData->name, values[i].name) == 0);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC005
 * @title Hash table delete path does not shrink bucket count
 * @precon nan
 * @brief
 *    1. Create hash table with initial size 16. Expected result 1.
 *    2. Insert 16 elements (load factor = 100%). Expected result 2.
 *    3. Delete 9 elements. Expected result 3.
 *    4. Verify bucketSize does not change and remaining elements are accessible. Expected result 4.
 * @expect
 *    1. Hash table created with bucketSize = 16
 *    2. Elements inserted, bucketSize remains 16
 *    3. Deletion does not trigger shrinking
 *    4. All remaining elements accessible
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC005(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);

    // Verify initial state: bucketSize = 16
    ASSERT_TRUE(hash->bucketSize == 16);
    ASSERT_TRUE(hash->initialSize == 16);

    // Insert 16 elements (load factor = 16/16 = 100%, should NOT trigger expansion)
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 16) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Size(hash) == 16);
    ASSERT_TRUE(hash->bucketSize == 16);

    // Delete 9 elements: 16 - 9 = 7 elements remain
    uint32_t bucketSizeBeforeDelete = hash->bucketSize;
    for (int i = 0; i < 9; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 7);

    // Verify deletion does not change bucket size
    ASSERT_TRUE(hash->bucketSize == bucketSizeBeforeDelete);
    ASSERT_TRUE(hash->bucketSize == hash->initialSize);

    // Verify remaining 7 elements are still accessible
    ASSERT_TRUE(verify_int_elements(hash, 9, 7) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC006
 * @title Hash table expansion followed by deletion without shrinking
 * @precon nan
 * @brief
 *    1. Create hash table with initial size 16. Expected result 1.
 *    2. Insert 17 elements to trigger one expansion. Expected result 2.
 *    3. Verify bucketSize increased to 17. Expected result 3.
 *    4. Delete 10 elements. Expected result 4.
 *    5. Verify bucketSize is unchanged and data integrity is preserved. Expected result 5.
 * @expect
 *    1. Hash table created with bucketSize = 16
 *    2. Expansion triggered when load factor >= 100%
 *    3. bucketSize = 17 after one split
 *    4. Deletion does not trigger shrinking
 *    5. bucketSize remains unchanged, all data accessible
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC006(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);
    ASSERT_TRUE(hash->bucketSize == 16);

    // Insert 17 elements to trigger expansion
    // After 16 elements: load factor = 100%, next insert triggers split
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 17) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Size(hash) == 17);

    // Verify expansion occurred: bucketSize should be 17 (16 + 1 split)
    ASSERT_TRUE(hash->bucketSize == 17);
    ASSERT_TRUE(hash->nextSplit == 1);  // Split pointer moved

    // Delete 10 elements: 17 - 10 = 7 elements remain
    uint32_t bucketSizeAfterExpansion = hash->bucketSize;
    for (int i = 0; i < 10; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 7);

    // Verify deletion does not change bucket size
    ASSERT_TRUE(hash->bucketSize == bucketSizeAfterExpansion);

    // Verify remaining elements are accessible
    ASSERT_TRUE(verify_int_elements(hash, 10, 7) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC007
 * @title Hash table multiple expansions and deletions without shrinking
 * @precon nan
 * @brief
 *    1. Create hash table and trigger multiple expansions. Expected result 1.
 *    2. Verify bucketSize increases progressively. Expected result 2.
 *    3. Delete elements after multiple expansions. Expected result 3.
 *    4. Verify bucketSize remains unchanged. Expected result 4.
 *    5. Verify all remaining elements accessible. Expected result 5.
 * @expect
 *    1. Multiple expansions triggered correctly
 *    2. bucketSize increases with each split
 *    3. Deletion does not trigger shrinking
 *    4. bucketSize remains at the expanded value
 *    5. Data integrity maintained throughout
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC007(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);

    uint32_t initialBuckets = hash->bucketSize;
    ASSERT_TRUE(initialBuckets == 16);

    // Phase 1: Trigger multiple expansions
    // Insert 30 elements to trigger several splits
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 30) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Size(hash) == 30);

    uint32_t bucketSizeAfterExpansion = hash->bucketSize;
    // Verify expansion occurred
    ASSERT_TRUE(bucketSizeAfterExpansion > initialBuckets);
    // With 30 elements and load factor 100%, should have triggered multiple splits
    ASSERT_TRUE(bucketSizeAfterExpansion >= 30);

    // Verify all 30 elements are accessible
    ASSERT_TRUE(verify_int_elements(hash, 0, 30) == BSL_SUCCESS);

    // Phase 2: Delete elements
    // Delete 22 elements: 30 - 22 = 8 elements remain
    for (int i = 0; i < 22; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 8);

    uint32_t bucketSizeAfterDelete = hash->bucketSize;
    ASSERT_TRUE(bucketSizeAfterDelete == bucketSizeAfterExpansion);

    // Verify remaining 8 elements are accessible
    ASSERT_TRUE(verify_int_elements(hash, 22, 8) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC008
 * @title Hash table delete path keeps initial bucket count
 * @precon nan
 * @brief
 *    1. Create hash table with initial size 16. Expected result 1.
 *    2. Insert and delete to reach very low load factor. Expected result 2.
 *    3. Verify bucketSize stays at initialSize. Expected result 3.
 * @expect
 *    1. Hash table created with bucketSize = 16
 *    2. Low load factor does not trigger shrinking
 *    3. bucketSize remains at initialSize even with few elements
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC008(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);

    uint32_t initialBuckets = hash->bucketSize;
    ASSERT_TRUE(initialBuckets == 16);

    // Insert 10 elements
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 10) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Size(hash) == 10);

    // Delete 7 elements, leaving only 3
    // Load factor = 3/16 = 18.75%, well below 50%
    for (int i = 0; i < 7; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 3);

    // Verify bucketSize is still at initialSize (should not shrink below)
    ASSERT_TRUE(hash->bucketSize == initialBuckets);

    // Verify remaining elements are accessible
    ASSERT_TRUE(verify_int_elements(hash, 7, 3) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC009
 * @title Hash table repeated expansion and deletion cycles test
 * @precon nan
 * @brief
 *    1. Create hash table. Expected result 1.
 *    2. Perform multiple cycles of expansion and deletion. Expected result 2.
 *    3. Verify bucketSize only increases on expansion and stays unchanged on deletion. Expected result 3.
 *    4. Verify data integrity throughout all cycles. Expected result 4.
 * @expect
 *    1. Hash table created successfully
 *    2. Expansion and deletion work correctly in cycles
 *    3. bucketSize increases on insert pressure and remains unchanged on delete
 *    4. All elements remain accessible after each cycle
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC009(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);

    uint32_t initialBuckets = hash->bucketSize;

    // Cycle 1: Expand then delete
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 20) == BSL_SUCCESS);
    uint32_t bucketSizeExpanded1 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeExpanded1 > initialBuckets);

    for (int i = 0; i < 13; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    uint32_t bucketSizeAfterDelete1 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeAfterDelete1 == bucketSizeExpanded1);
    ASSERT_TRUE(verify_int_elements(hash, 13, 7) == BSL_SUCCESS);

    // Cycle 2: Expand again
    ASSERT_TRUE(insert_multiple_int_elements(hash, 100, 15) == BSL_SUCCESS);
    uint32_t bucketSizeExpanded2 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeExpanded2 >= bucketSizeAfterDelete1);
    ASSERT_TRUE(verify_int_elements(hash, 13, 7) == BSL_SUCCESS);
    ASSERT_TRUE(verify_int_elements(hash, 100, 15) == BSL_SUCCESS);

    // Cycle 2: Delete again
    for (int i = 13; i < 20; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    for (int i = 100; i < 110; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    uint32_t bucketSizeAfterDelete2 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeAfterDelete2 == bucketSizeExpanded2);
    ASSERT_TRUE(verify_int_elements(hash, 110, 5) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC010
 * @title Hash erase returns current end iterator after deleting the last iterator
 * @precon nan
 * @brief
 *    1. Create hash table with default configuration. Expected result 1.
 *    2. Insert 17 elements to reach bucketSize = 17 and nextSplit = 1. Expected result 2.
 *    3. Delete 8 elements so that only one tail iterator remains. Expected result 3.
 *    4. Erase the current last iterator. Expected result 4.
 *    5. Verify the returned iterator equals the current end iterator and bucketSize is unchanged. Expected result 5.
 * @expect
 *    1. Hash table created successfully
 *    2. Expansion occurred and bucketSize = 17
 *    3. size = 9 and bucket layout is unchanged
 *    4. Deleting the current last iterator does not shrink
 *    5. BSL_HASH_Erase returns the current BSL_HASH_IterEnd(hash)
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC010(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    BSL_HASH_Iterator it = NULL;
    BSL_HASH_Iterator lastIt = NULL;
    BSL_HASH_Iterator nextIt = NULL;
    uintptr_t lastKey;
    uint32_t bucketSizeBeforeLastErase;

    ASSERT_TRUE(hash != NULL);
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 17) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Size(hash) == 17);
    ASSERT_TRUE(hash->bucketSize == 17);
    ASSERT_TRUE(hash->nextSplit == 1);

    for (int i = 0; i < 8; i++) {
        (void)BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 9);
    ASSERT_TRUE(hash->bucketSize == 17);
    ASSERT_TRUE(hash->nextSplit == 1);

    for (it = BSL_HASH_IterBegin(hash); it != BSL_HASH_IterEnd(hash); it = BSL_HASH_IterNext(hash, it)) {
        lastIt = it;
    }
    ASSERT_TRUE(lastIt != NULL);
    ASSERT_TRUE(lastIt != BSL_HASH_IterEnd(hash));
    ASSERT_TRUE(BSL_HASH_IterNext(hash, lastIt) == BSL_HASH_IterEnd(hash));

    lastKey = BSL_HASH_HashIterKey(hash, lastIt);
    bucketSizeBeforeLastErase = hash->bucketSize;
    nextIt = BSL_HASH_Erase(hash, lastKey);

    ASSERT_TRUE(BSL_HASH_Size(hash) == 8);
    ASSERT_TRUE(hash->bucketSize == bucketSizeBeforeLastErase);
    ASSERT_TRUE(nextIt == BSL_HASH_IterEnd(hash));

    for (int i = 8; i < 17; i++) {
        if ((uintptr_t)i == lastKey) {
            continue;
        }
        uintptr_t value;
        ASSERT_TRUE(BSL_HASH_At(hash, (uintptr_t)i, &value) == BSL_SUCCESS);
        ASSERT_TRUE(value == (uintptr_t)(i * 2));
    }
    uintptr_t deletedValue = 0;
    ASSERT_TRUE(BSL_HASH_At(hash, lastKey, &deletedValue) != BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC011
 * @title Hash table creation rejects initial bucket size that overflows nextLevelSize
 * @precon nan
 * @brief
 *    1. Create a hash table with initial bucket size 0x80000000. Expected result 1.
 * @expect
 *    1. BSL_HASH_Create returns NULL because nextLevelSize would overflow uint32_t
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC011(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0x80000000U, NULL, NULL, NULL, NULL);

    ASSERT_TRUE(hash == NULL);
#if defined(HITLS_BSL_ERR)
    BSL_ERR_ClearError();
#endif

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC012
 * @title Hash table creation rejects bucket size whose actual allocation object overflows uint32 bytes
 * @precon nan
 * @brief
 *    1. Compute a bucket size where `(bktSize + 1) * sizeof(RawList)` still fits uint32,
 *       but `(nextLevelSize + 1) * sizeof(RawList)` does not. Expected result 1.
 *    2. Create the hash table with that bucket size. Expected result 2.
 * @expect
 *    1. Candidate bucket size is valid for the old partial check but invalid for the real allocation object
 *    2. BSL_HASH_Create returns NULL
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC012(void)
{
    uint32_t maxCount = UINT32_MAX / sizeof(RawList);
    uint32_t bktSize = (maxCount + 1) / 2;
    BSL_HASH_Hash *hash = NULL;

    TestMemInit();
    ASSERT_TRUE(bktSize <= (UINT32_MAX >> 1));
    ASSERT_TRUE((((uint64_t)bktSize + 1) * sizeof(RawList)) <= UINT32_MAX);
    ASSERT_TRUE(((((uint64_t)bktSize << 1) + 1) * sizeof(RawList)) > UINT32_MAX);

    hash = BSL_HASH_Create(bktSize, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash == NULL);
#if defined(HITLS_BSL_ERR)
    BSL_ERR_ClearError();
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC013
 * @title Resize arithmetic guard should reject uint32 overflow in hashCount * FACTOR
 * @precon nan
 * @brief
 *    1. Create hash table with default configuration. Expected result 1.
 *    2. Force hashCount to a value whose multiplication by FACTOR overflows uint32_t. Expected result 2.
 *    3. Insert a new key. Expected result 3.
 * @expect
 *    1. Hash table created successfully
 *    2. Internal state is prepared for overflow check
 *    3. Insert returns BSL_INTERNAL_EXCEPTION
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC013(void)
{
    BSL_HASH_Hash *hash = NULL;

    TestMemInit();
    hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);

    hash->hashCount = 42949673U;
    ASSERT_TRUE(BSL_HASH_Insert(hash, (uintptr_t)1, sizeof(uintptr_t), (uintptr_t)2, sizeof(uintptr_t))
        == BSL_INTERNAL_EXCEPTION);
#if defined(HITLS_BSL_ERR)
    BSL_ERR_ClearError();
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC014
 * @title Failed level-transition realloc should not advance split state
 * @precon nan
 * @brief
 *    1. Create a hash table with initial bucket size 1 and insert one element. Expected result 1.
 *    2. Stub BSL_SAL_Realloc to fail on the next level-transition split. Expected result 2.
 *    3. Attempt the insert that triggers the transition split. Expected result 3.
 *    4. Verify resize-related state remains unchanged and existing keys stay accessible. Expected result 4.
 * @expect
 *    1. Hash table starts with bucketSize 1, nextSplit 0, nextLevelSize 2
 *    2. Realloc failure is injected
 *    3. Insert returns BSL_INTERNAL_EXCEPTION
 *    4. bucketSize, nextSplit, nextLevelSize, and hashCount remain unchanged
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC014(void)
{
    BSL_HASH_Hash *hash = NULL;
    uintptr_t value = 0;
    uint32_t bucketSizeBefore;
    uint32_t nextSplitBefore;
    uint32_t nextLevelSizeBefore;
    uint32_t hashCountBefore;

    TestMemInit();
    hash = BSL_HASH_Create(1, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);
    ASSERT_TRUE(BSL_HASH_Insert(hash, (uintptr_t)0, sizeof(uintptr_t), (uintptr_t)10, sizeof(uintptr_t))
        == BSL_SUCCESS);

    bucketSizeBefore = hash->bucketSize;
    nextSplitBefore = hash->nextSplit;
    nextLevelSizeBefore = hash->nextLevelSize;
    hashCountBefore = hash->hashCount;

    STUB_REPLACE(BSL_SAL_Realloc, STUB_BSL_SAL_Realloc_Fail);
    ASSERT_TRUE(BSL_HASH_Insert(hash, (uintptr_t)1, sizeof(uintptr_t), (uintptr_t)12, sizeof(uintptr_t))
        == BSL_INTERNAL_EXCEPTION);
    STUB_RESTORE(BSL_SAL_Realloc);
#if defined(HITLS_BSL_ERR)
    BSL_ERR_ClearError();
#endif

    ASSERT_TRUE(hash->bucketSize == bucketSizeBefore);
    ASSERT_TRUE(hash->nextSplit == nextSplitBefore);
    ASSERT_TRUE(hash->nextLevelSize == nextLevelSizeBefore);
    ASSERT_TRUE(hash->hashCount == hashCountBefore);
    ASSERT_TRUE(BSL_HASH_At(hash, (uintptr_t)0, &value) == BSL_SUCCESS);
    ASSERT_TRUE(value == (uintptr_t)10);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    STUB_RESTORE(BSL_SAL_Realloc);
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC015
 * @title Iteration can delete all even keys without triggering shrink
 * @precon nan
 * @brief
 *    1. Create a hash table and insert 17 elements so bucketSize becomes 17. Expected result 1.
 *    2. Traverse the table with iterators and delete every even key. Expected result 2.
 *    3. Verify erase updates size only and does not change resize-related state. Expected result 3.
 *    4. Verify no even key remains and all odd keys are still accessible. Expected result 4.
 * @expect
 *    1. bucketSize = 17 and nextSplit = 1 after expansion
 *    2. Iterator-based conditional deletion completes without errors
 *    3. bucketSize, nextSplit, and nextLevelSize remain unchanged
 *    4. Only odd keys remain in the hash table
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC015(void)
{
    BSL_HASH_Hash *hash = NULL;
    BSL_HASH_Iterator it = NULL;
    uintptr_t key = 0;
    uintptr_t value = 0;
    uint32_t bucketSizeBefore;
    uint32_t nextSplitBefore;
    uint32_t nextLevelSizeBefore;

    TestMemInit();
    hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 17) == BSL_SUCCESS);
    ASSERT_TRUE(hash->bucketSize == 17);
    ASSERT_TRUE(hash->nextSplit == 1);

    bucketSizeBefore = hash->bucketSize;
    nextSplitBefore = hash->nextSplit;
    nextLevelSizeBefore = hash->nextLevelSize;

    for (it = BSL_HASH_IterBegin(hash); it != BSL_HASH_IterEnd(hash);) {
        key = BSL_HASH_HashIterKey(hash, it);
        if ((key % 2U) == 0U) {
            it = BSL_HASH_Erase(hash, key);
            continue;
        }
        it = BSL_HASH_IterNext(hash, it);
    }

    ASSERT_TRUE(BSL_HASH_Size(hash) == 8);
    ASSERT_TRUE(hash->bucketSize == bucketSizeBefore);
    ASSERT_TRUE(hash->nextSplit == nextSplitBefore);
    ASSERT_TRUE(hash->nextLevelSize == nextLevelSizeBefore);

    for (int i = 0; i < 17; i++) {
        if ((i % 2) == 0) {
            ASSERT_TRUE(BSL_HASH_At(hash, (uintptr_t)i, &value) != BSL_SUCCESS);
            continue;
        }
        ASSERT_TRUE(BSL_HASH_At(hash, (uintptr_t)i, &value) == BSL_SUCCESS);
        ASSERT_TRUE(value == (uintptr_t)(i * 2));
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */
