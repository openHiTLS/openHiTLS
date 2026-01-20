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

#define BACKET_SIZE 64
#define MAX_NAME_LEN 64

typedef struct userData {
    int id;
    const char name[MAX_NAME_LEN];
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

int UserDataCmpFunc(uintptr_t data1, uintptr_t data2)
{
    return strcmp((const char*)data1, (const char*)data2);
}

void BslListFreeFunc(void *data)
{
    if (data != NULL) {
        BSL_SAL_Free(data);
    }
}

bool ListNodeCmpFunc(const void *node, uintptr_t data)
{
    const ListRawNode *t = (ListRawNode *)node;
    return (uintptr_t)(t->prev) == data;
}

/* END_HEADER */

/**
 * @test SDV_BSL_HASH_LIST_FUNC_TC001
 * @title Hash list normal capability test
 * @precon nan
 * @brief
 *    1. Call BSL_HASH_Create to create a hash list header. Expected result 1 is obtained.
 *    2. Call BSL_HASH_Insert to add data to the hash list. Expected result 2 is obtained.
 *    3. Call BSL_HASH_Size get list size. Expected result 3 is obtained.
 *    4. Call BSL_CstlHashErase BSL_CstlHashClear BSL_CstlHashDestory delete data,
 *       Expected result 4 is obtained.
 * @expect
 *    1. success
 *    2. BSL_SUCCESS
 *    3. size is 6
 *    4. success
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_LIST_FUNC_TC001(void)
{
    int i;
    BSL_HASH_Hash *hash;
    uintptr_t tmpValue;
    UserData *userValue;
    BSL_HASH_Iterator it;
    uintptr_t tmpKey;
    uint8_t key[6] = {28, 29, 30, 31, 32, 33};
    UserData value[6] = {{16, "bsl_cstl001"},
                         {18, "bsl_cstl002"},
                         {15, "bsl_cstl003"},
                         {17, "bsl_cstl004"},
                         {17, "bsl_cstl005"},
                         {16, "bsl_cstl001"}};
    ListDupFreeFuncPair valueFunc = {UserHashDataDupFunc, BSL_SAL_Free};
    TestMemInit();
    hash = BSL_HASH_Create(BACKET_SIZE, NULL, NULL, NULL, &valueFunc);
    ASSERT_TRUE(hash != (BSL_HASH_Hash *)NULL);

    for (i = 0; i < 5; i++) {
        ASSERT_TRUE(BSL_HASH_Insert(hash, key[i], 0, (uintptr_t)&value[i], sizeof(UserData)) == BSL_SUCCESS);
    }
    ASSERT_TRUE(BSL_HASH_Put(hash, key[i], 0, (uintptr_t)&value[i], sizeof(UserData), NULL) == BSL_SUCCESS);

    ASSERT_TRUE(BSL_HASH_Size(hash) == (size_t)6);

    ASSERT_TRUE(BSL_HASH_At(hash, key[4], &tmpValue) == BSL_SUCCESS);
    userValue = (UserData *)tmpValue;
    ASSERT_TRUE(userValue->id == value[4].id);
    ASSERT_TRUE(strcmp(userValue->name, value[4].name) == 0);

    it = BSL_HASH_Find(hash, key[4]);
    ASSERT_TRUE(it != BSL_HASH_IterEnd(hash));
    ASSERT_TRUE(BSL_HASH_HashIterKey(hash, it) == (uintptr_t)key[4]);

    userValue = (UserData *)BSL_HASH_IterValue(hash, it);
    ASSERT_TRUE(userValue != (UserData *)NULL);
    ASSERT_TRUE(userValue->id == value[4].id);
    ASSERT_TRUE(strcmp(userValue->name, value[4].name) == 0);

    (void)BSL_HASH_Erase(hash, key[4]);
    ASSERT_TRUE(BSL_HASH_Size(hash) == (size_t)5);

    for (it = BSL_HASH_IterBegin(hash); it != BSL_HASH_IterEnd(hash);) {
        tmpKey = BSL_HASH_HashIterKey(hash, it);
        it = BSL_HASH_Erase(hash, tmpKey);
    }

    ASSERT_TRUE(BSL_HASH_Size(hash) == (size_t)0);
    ASSERT_TRUE(TestIsErrStackEmpty());
   
EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_LIST_FUNC_TC002
 * @title Hash list normal capability test, key type is string.
 * @precon nan
 * @brief
 *    1. Call BSL_HASH_Create to create a hash list header. Expected result 1 is obtained.
 *    2. Call BSL_HASH_Insert to add data to the hash list. Expected result 2 is obtained.
 *    3. Call BSL_HASH_Size get list size. Expected result 3 is obtained.
 *    4. Call BSL_CstlHashErase BSL_CstlHashClear BSL_CstlHashDestory delete data,
 *       Expected result 4 is obtained.
 * @expect
 *    1. success
 *    2. BSL_SUCCESS
 *    3. size is 6
 *    4. success
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_LIST_FUNC_TC002(void)
{
    uint32_t i;
    BSL_HASH_Hash *hash;
    const char *key[6] = {"7201028", "7201029", "7201030", "7201031", "7201032", "7201033"};
    UserData value[6] = {{16, "bsl_cstl001"},
                         {18, "bsl_cstl002"},
                         {15, "bsl_cstl003"},
                         {17, "bsl_cstl004"},
                         {17, "bsl_cstl005"},
                         {16, "bsl_cstl001"}};
    char *tmpKey;
    uintptr_t tmpValue;
    UserData *userValue;
    BSL_HASH_Iterator it;
    ListDupFreeFuncPair keyFunc = {UserHashKeyDupFunc, BSL_SAL_Free};
    ListDupFreeFuncPair valueFunc = {UserHashDataDupFunc, BSL_SAL_Free};

    hash = BSL_HASH_Create(BACKET_SIZE, BSL_HASH_CodeCalcStr, BSL_HASH_MatchStr, &keyFunc, &valueFunc);
    ASSERT_TRUE(hash != (BSL_HASH_Hash *)NULL);

    for (i = 0; i < 6; i++) {
        ASSERT_TRUE(
            BSL_HASH_Insert(hash, (uintptr_t)key[i], strlen(key[i]) + 1, (uintptr_t)&value[i], sizeof(UserData)) ==
            BSL_SUCCESS);
    }

    ASSERT_TRUE(BSL_HASH_Put(hash, (uintptr_t)key[1], strlen(key[1]) + 1, (uintptr_t)&value[1], sizeof(UserData), NULL)
        == BSL_SUCCESS);
    ASSERT_TRUE(BSL_HASH_Empty(hash) == false);
    ASSERT_TRUE(BSL_HASH_Size(hash) == (size_t)6);
    ASSERT_TRUE(BSL_HASH_At(hash, (uintptr_t)key[4], &tmpValue) == BSL_SUCCESS);
    userValue = (UserData *)tmpValue;
    ASSERT_TRUE(userValue->id == value[4].id);
    ASSERT_TRUE(strcmp(userValue->name, value[4].name) == 0);

    it = BSL_HASH_Find(hash, (uintptr_t)key[4]);
    ASSERT_TRUE(it != BSL_HASH_IterEnd(hash));
    ASSERT_TRUE(strcmp((const char *)BSL_HASH_HashIterKey(hash, it), key[4]) == 0);

    userValue = (UserData *)BSL_HASH_IterValue(hash, it);
    ASSERT_TRUE(userValue != (UserData *)NULL);
    ASSERT_TRUE(userValue->id == value[4].id);
    ASSERT_TRUE(strcmp(userValue->name, value[4].name) == 0);

    (void)BSL_HASH_Erase(hash, (uintptr_t)key[4]);
    ASSERT_TRUE(BSL_HASH_Size(hash) == (size_t)5);

    for (it = BSL_HASH_IterBegin(hash); it != BSL_HASH_IterEnd(hash);) {
        tmpKey = (char *)BSL_HASH_HashIterKey(hash, it);
        it = BSL_HASH_Erase(hash, (uintptr_t)tmpKey);
    }

    ASSERT_TRUE(BSL_HASH_Size(hash) == (size_t)0);
    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    BSL_HASH_Destroy(hash);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_LIST_FUNC_TC003
 * @title bsl list normal capability test, key type is string.
 * @precon nan
 * @brief
 *    1. Call BSL_ListInit to create a hash list header. Expected result 1 is obtained.
 *    2. Call BSL_ListPushFront and BSL_ListPushBack to add data to the hash list. Expected result 2 is obtained.
 *    3. Perform find and delete. Expected result 3 is obtained.
 *    4. Call BSL_ListIterErase delete data. Expected result 4 is obtained.
 * @expect
 *    1. success
 *    2. BSL_SUCCESS
 *    3. success
 *    4. success
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_LIST_FUNC_TC003(void)
{
    uint32_t i;
    BSL_List *list = BSL_SAL_Calloc(1, sizeof(BSL_List));
    ASSERT_TRUE(list != NULL);
    const char *data[7] = {"7201028", "7201029", "7201030", "7201031", "7201032", "7201033", "777888"};

    BSL_ListIterator it = NULL;
    ListDupFreeFuncPair valueFunc = {UserHashKeyDupFunc, BSL_SAL_Free};

    ASSERT_EQ(BSL_ListInit(list, &valueFunc), BSL_SUCCESS);

    for (i = 0; i < 5; i++) {
        ASSERT_EQ( BSL_ListPushFront(list, (uintptr_t)data[i], strlen(data[i]) + 1), BSL_SUCCESS);
    }

    ASSERT_EQ(BSL_ListPushBack(list, (uintptr_t)data[i], strlen(data[i]) + 1), BSL_SUCCESS);

    ASSERT_TRUE(BSL_ListSize(list) == (size_t)i + 1);

    ASSERT_TRUE(strcmp((const char* )BSL_ListFront(list), data[4]) == 0);
    ASSERT_TRUE(strcmp((const char* )BSL_ListBack(list), data[5]) == 0);

    it = BSL_ListIterFind(list, UserDataCmpFunc, (uintptr_t)data[1]);
    ASSERT_TRUE(it != BSL_ListIterEnd(list));

    ASSERT_TRUE(strcmp((const char* )BSL_ListIterData(it), data[1]) == 0);
    ASSERT_TRUE(BSL_ListInsert(list, it, (uintptr_t)data[6], strlen(data[6]) + 1) == BSL_SUCCESS);

    ASSERT_TRUE(BSL_ListIterPrev(list, it) != NULL);
    ASSERT_TRUE(BSL_ListIterNext(list, it) != NULL);
    ASSERT_TRUE(BSL_ListIterBegin(list) != NULL);
    ASSERT_TRUE(BSL_ListIterEnd(list) != NULL);

    ASSERT_TRUE(BSL_ListPopFront(list) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_ListPopBack(list) == BSL_SUCCESS);

    ASSERT_TRUE(BSL_ListIterErase(list, it) != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_ListDeinit(list);
    BSL_SAL_Free(list);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_HASH_LIST_FUNC_TC004
 * @title raw list normal capability test.
 * @precon nan
 * @brief
 *    1. Call ListRawInit to create a raw list header. Expected result 1 is obtained.
 *    2. Call ListRawPushFront to add node to the list. Expected result 2 is obtained.
 *    3. Perform find and delete. Expected result 3 is obtained.
 *    4. Call ListRawDeinit delete list. Expected result 4 is obtained.
 * @expect
 *    1. create success
 *    2. add success
 *    3. success
 *    4. success
 */
/* BEGIN_CASE */
void SDV_BSL_HASH_LIST_FUNC_TC004(void)
{
    uint32_t i;
    ListRawNode *node = BSL_SAL_Calloc(6, sizeof(ListRawNode));
    ASSERT_TRUE(node != NULL);
    RawList *list = BSL_SAL_Calloc(1, sizeof(RawList));
    ASSERT_TRUE(list != NULL);

    ASSERT_EQ(ListRawInit(list, NULL), BSL_SUCCESS);

    for (i = 0; i < 6; i++) {
        ASSERT_EQ(ListRawPushFront(list, &node[i]), BSL_SUCCESS);
    }

    ListRawNode *it = ListRawBack(list);
    ASSERT_TRUE(it != NULL);
    ASSERT_TRUE(it->prev != NULL);

    it = ListRawGetPrev(list, &node[1]);
    ASSERT_TRUE(it != NULL);
    ASSERT_TRUE(it->next != NULL);

    it = ListRawFindNode(list, ListNodeCmpFunc, (uintptr_t)&node[1]);
    ASSERT_TRUE(it != NULL);

    ASSERT_EQ(ListRawPopFront(list), BSL_SUCCESS);
    ASSERT_EQ(ListRawPopBack(list), BSL_SUCCESS);

    ASSERT_EQ(ListRawDeinit(list), BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(list);
    BSL_SAL_Free(node);
    return;
}
/* END_CASE */
