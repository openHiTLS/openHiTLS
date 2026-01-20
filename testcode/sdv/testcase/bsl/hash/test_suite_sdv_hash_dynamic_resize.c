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
#include "list_base.h"
#include "bsl_hash.h"
#include "bsl_hash_list.h"
#include "bsl_sal.h"

#define MAX_NAME_LEN 64
/* END_HEADER */
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
 * @title Hash table basic shrinking test
 * @precon nan
 * @brief
 *    1. Create hash table with initial size 16. Expected result 1.
 *    2. Insert 16 elements (load factor = 100%). Expected result 2.
 *    3. Delete 9 elements to trigger shrinking (load factor < 50%). Expected result 3.
 *    4. Verify bucketSize decreased and remaining elements accessible. Expected result 4.
 * @expect
 *    1. Hash table created with bucketSize = 16
 *    2. Elements inserted, bucketSize remains 16
 *    3. Shrinking triggered, bucketSize decreased
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
    // Load factor = 7/16 = 43.75% < 50%, SHOULD trigger shrinking
    uint32_t bucketSizeBeforeDelete = hash->bucketSize;
    for (int i = 0; i < 9; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 7);

    // Verify shrinking occurred: bucketSize should have decreased
    ASSERT_TRUE(hash->bucketSize == bucketSizeBeforeDelete);
    // Should not shrink below initialSize
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
 * @title Hash table expansion followed by shrinking test
 * @precon nan
 * @brief
 *    1. Create hash table with initial size 16. Expected result 1.
 *    2. Insert 17 elements to trigger one expansion. Expected result 2.
 *    3. Verify bucketSize increased to 17. Expected result 3.
 *    4. Delete 10 elements to trigger shrinking. Expected result 4.
 *    5. Verify bucketSize decreased and data integrity. Expected result 5.
 * @expect
 *    1. Hash table created with bucketSize = 16
 *    2. Expansion triggered when load factor >= 100%
 *    3. bucketSize = 17 after one split
 *    4. Shrinking triggered when load factor < 50%
 *    5. bucketSize decreased, all data accessible
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
    // Load factor = 7/17 ≈ 41% < 50%, SHOULD trigger shrinking
    uint32_t bucketSizeAfterExpansion = hash->bucketSize;
    for (int i = 0; i < 10; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 7);

    // Verify shrinking occurred
    ASSERT_TRUE(hash->bucketSize < bucketSizeAfterExpansion);

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
 * @title Hash table multiple expansions and shrinks test
 * @precon nan
 * @brief
 *    1. Create hash table and trigger multiple expansions. Expected result 1.
 *    2. Verify bucketSize increases progressively. Expected result 2.
 *    3. Delete elements to trigger multiple shrinks. Expected result 3.
 *    4. Verify bucketSize decreases but not below initialSize. Expected result 4.
 *    5. Verify all remaining elements accessible. Expected result 5.
 * @expect
 *    1. Multiple expansions triggered correctly
 *    2. bucketSize increases with each split
 *    3. Multiple shrinks triggered correctly
 *    4. bucketSize decreases but >= initialSize
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

    // Phase 2: Trigger shrinking by deleting elements
    // Delete 22 elements: 30 - 22 = 8 elements remain
    // Load factor will be much lower, triggering shrinks
    for (int i = 0; i < 22; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    ASSERT_TRUE(BSL_HASH_Size(hash) == 8);

    uint32_t bucketSizeAfterShrink = hash->bucketSize;
    // Verify shrinking occurred
    ASSERT_TRUE(bucketSizeAfterShrink < bucketSizeAfterExpansion);
    // Verify not shrunk below initial size
    ASSERT_TRUE(bucketSizeAfterShrink >= initialBuckets);

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
 * @title Hash table does not shrink below initialSize test
 * @precon nan
 * @brief
 *    1. Create hash table with initial size 16. Expected result 1.
 *    2. Insert and delete to reach very low load factor. Expected result 2.
 *    3. Verify bucketSize stays at initialSize. Expected result 3.
 * @expect
 *    1. Hash table created with bucketSize = 16
 *    2. Low load factor does not trigger shrink below initialSize
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
 * @title Hash table repeated expansion and shrinking cycles test
 * @precon nan
 * @brief
 *    1. Create hash table. Expected result 1.
 *    2. Perform multiple cycles of expansion and shrinking. Expected result 2.
 *    3. Verify bucketSize adjusts correctly in each cycle. Expected result 3.
 *    4. Verify data integrity throughout all cycles. Expected result 4.
 * @expect
 *    1. Hash table created successfully
 *    2. Expansion and shrinking work correctly in cycles
 *    3. bucketSize increases and decreases appropriately
 *    4. All elements remain accessible after each cycle
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_DYNAMIC_RESIZE_FUNC_TC009(void)
{
    TestMemInit();
    BSL_HASH_Hash *hash = BSL_HASH_Create(0, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(hash != NULL);

    uint32_t initialBuckets = hash->bucketSize;

    // Cycle 1: Expand then shrink
    ASSERT_TRUE(insert_multiple_int_elements(hash, 0, 20) == BSL_SUCCESS);
    uint32_t bucketSizeExpanded1 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeExpanded1 > initialBuckets);

    for (int i = 0; i < 13; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    uint32_t bucketSizeShrank1 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeShrank1 < bucketSizeExpanded1);
    ASSERT_TRUE(verify_int_elements(hash, 13, 7) == BSL_SUCCESS);

    // Cycle 2: Expand again
    ASSERT_TRUE(insert_multiple_int_elements(hash, 100, 15) == BSL_SUCCESS);
    uint32_t bucketSizeExpanded2 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeExpanded2 > bucketSizeShrank1);
    ASSERT_TRUE(verify_int_elements(hash, 13, 7) == BSL_SUCCESS);
    ASSERT_TRUE(verify_int_elements(hash, 100, 15) == BSL_SUCCESS);

    // Cycle 2: Shrink again
    for (int i = 13; i < 20; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    for (int i = 100; i < 110; i++) {
        BSL_HASH_Erase(hash, (uintptr_t)i);
    }
    uint32_t bucketSizeShrank2 = hash->bucketSize;
    ASSERT_TRUE(bucketSizeShrank2 < bucketSizeExpanded2);
    ASSERT_TRUE(verify_int_elements(hash, 110, 5) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */