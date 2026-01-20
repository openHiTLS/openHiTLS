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
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_list.h"
#include "bsl_list_internal.h"

/* END_HEADER */

typedef struct {
    int value;
    int key;
} LIST_NODE;

#define MAX_NAME_LEN 64

/* User Structure Definition */
typedef struct userListData {
    int id;
    char name[MAX_NAME_LEN];
} UserData;

static void EmptyFree(void *data)
{
    (void)data;
}

void UserDataFree(void *data)
{
    (void)data;
    return;
}

static int Compare(const void *data1, const void *data2)
{
    int val1 = **(int **)data1;
    int val2 = **(int **)data2;
    /* qsort requires: <0 if val1<val2, 0 if equal, >0 if val1>val2 */
    return (val1 > val2) - (val1 < val2);
}

static int32_t UserDataCompare(const void *data1, const void *data2)
{
    if (data1 == NULL || data2 == NULL) {
        return 1;
    }
    UserData *tmp1 = (UserData *)data1;
    UserData *tmp2 = (UserData *)data2;

    if (tmp1->id != tmp2->id) {
        return -1;
    }

    if (strlen(tmp1->name) != strlen(tmp2->name)) {
        return -1;
    }

    if (memcmp(tmp1->name, tmp2->name, strlen(tmp1->name)) != 0) {
        return -1;
    }
    return 0;
}

// data1:(pList)->curr->data, data2:pSearchFor
static int32_t UserDataCompareByName(const void *data1, const void *data2)
{
    if (data1 == NULL || data2 == NULL) {
        return 1;
    }
    UserData *tmp1 = (UserData *)data1;
    char *tmp2 = (char *)data2;

    if (strlen(tmp1->name) != strlen(tmp2)) {
        return -1;
    }

    if (memcmp(tmp1->name, tmp2, strlen(tmp2)) != 0) {
        return -1;
    }
    return 0;
}

static int32_t UserDataSort(const void *a, const void *b)
{
    if (a == NULL || b == NULL) {
        return -1;
    }
    UserData *tmp1 = *(UserData **)a;
    UserData *tmp2 = *(UserData **)b;
    return (tmp1->id - tmp2->id);
}

static void *UserDataCopy(const void *a)
{
    if (a == NULL) {
        return NULL;
    }
    UserData *src = (UserData *)a;
    UserData *dest = (UserData *)BSL_SAL_Malloc(sizeof(UserData));
    if (dest == NULL) {
        return NULL;
    }
    (void)memset_s(dest, sizeof(UserData), 0, sizeof(UserData));
    dest->id = src->id;
    if (memcpy_s(dest->name, MAX_NAME_LEN, src->name, strlen(src->name)) != EOK) {
        BSL_SAL_FREE(dest);
        return NULL;
    }
    return dest;
}

/**
 * @test SDV_BSL_LIST_FUNC_TC001
 * @title Linked list normal capability test
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_New to create a linked list header. Expected result 1 is obtained.
 *    2. Call BSL_LIST_AddElement to add data to the linked list. Expected result 2 is obtained.
 *    3. Repeat step 2 twice. Expected result 2 is obtained.
 *    4. Call BSL_LIST_COUNT to obtain the number of data records in the current linked list.
 *       Expected result 3 is obtained.
 *    5. Get the number of nodes in the list after delete the current element of list. Expected result 4 is obtained.
 *    6. Call BSL_LIST_Copy to copy data to the new linked list. Expected result 5 is obtained.
 * @expect
 *    1. success
 *    2. BSL_SUCCESS
 *    3. 3
 *    4. 2
 *    5. success
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_FUNC_TC001(void)
{
    TestMemInit();

    BslList *listHeader = BSL_LIST_New(sizeof(LIST_NODE));
    ASSERT_TRUE(listHeader != NULL);

    LIST_NODE *node1 = (LIST_NODE *)BSL_SAL_Malloc(sizeof(LIST_NODE));
    ASSERT_TRUE(node1 != NULL);

    node1->key = 1;
    node1->value = 2;

    int ret = BSL_LIST_AddElement(listHeader, node1, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    LIST_NODE *node2 = (LIST_NODE *)BSL_SAL_Malloc(sizeof(LIST_NODE));
    ASSERT_TRUE(node2 != NULL);

    node2->key = 1;
    node2->value = 2;

    ret = BSL_LIST_AddElement(listHeader, node2, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    LIST_NODE *node3 = (LIST_NODE *)BSL_SAL_Malloc(sizeof(LIST_NODE));
    ASSERT_TRUE(node3 != NULL);

    node3->key = 1;
    node3->value = 2;

    ret = BSL_LIST_AddElement(listHeader, node3, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    int num = BSL_LIST_COUNT(listHeader);
    ASSERT_TRUE(num == 3);

    BSL_LIST_DeleteCurrent(listHeader, NULL);

    num = BSL_LIST_COUNT(listHeader);
    ASSERT_TRUE(num == 2);

    BslList *destHeader = BSL_LIST_Copy(listHeader, NULL, NULL);
    ASSERT_TRUE(destHeader != NULL);

    num = BSL_LIST_COUNT(destHeader);
    ASSERT_TRUE(num == 2);
    BSL_LIST_FREE(destHeader, NULL);

    BSL_LIST_FREE(listHeader, NULL);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_FUNC_TC002
 * @title SDV_BSL_LIST_FUNC_TC002
 * @precon None
 * @brief List maximum element test.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_FUNC_TC002(void)
{
    int arr[] = {0};
    BslList *list = NULL;

    list = BSL_LIST_New(sizeof(int));
    ASSERT_TRUE(list != NULL);

    ASSERT_EQ(BSL_LIST_SetMaxElements(65535), BSL_SUCCESS);
    for (int i = 0; i < 65535; i++) {
        ASSERT_EQ(BSL_LIST_AddElement(list, arr, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    }
    ASSERT_EQ(BSL_LIST_COUNT(list), 65535);
    ASSERT_EQ(BSL_LIST_AddElement(list, arr, BSL_LIST_POS_AFTER), BSL_LIST_FULL);

EXIT:
    BSL_LIST_FREE(list, EmptyFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_MAX_ELEMENTS_FUNC_TC001
 * @title list max elements test
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_New to create the head node of the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_SetMaxElements to set the maximum number of data records stored in the linked list to 65535.
 *       Expected result 2 is obtained.
 *    3. Add 65535 records to the linked list. Expected result 3 is obtained.
 *    4. Obtain the maximum data volume supported by the current linked list. Expected result 4 is obtained.
 *    5. Obtain the number of data records in the current linked list. Expected result 5 is obtained.
 *    6. Add data to the linked list again. Expected result 6 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_SUCCESS
 *    3. BSL_SUCCESS
 *    4. 65535
 *    5. 65535
 *    6. BSL_LIST_FULL
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_MAX_ELEMENTS_FUNC_TC001(void)
{
    int arr[] = {0};
    BslList *list = NULL;

    list = BSL_LIST_New(-1);
    ASSERT_TRUE(list == NULL);

    list = BSL_LIST_New(sizeof(int));
    ASSERT_TRUE(list != NULL);

    ASSERT_EQ(BSL_LIST_SetMaxElements(65535), BSL_SUCCESS);
    for (int i = 0; i < 65535; i++) {
        ASSERT_EQ(BSL_LIST_AddElement(list, arr, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(BSL_LIST_GetMaxElements(), 65535);
    ASSERT_EQ(BSL_LIST_COUNT(list), 65535);
    ASSERT_EQ(BSL_LIST_AddElement(list, arr, BSL_LIST_POS_AFTER), BSL_LIST_FULL);

EXIT:
    BSL_LIST_FREE(list, EmptyFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_DETACH_FUNC_TC001
 * @title  list detach test
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_DetachCurrent to detach the current. Expected result 2 is obtained.
 *    3. Call BSL_LIST_DetachNode to detach a node. Expected result 3 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. success
 *    3. success
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_DETACH_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);

    UserData data[9] = {
        {1, "Alice"},
        {2, "Bob"},
        {3, "Celina"},
        {4, "Dave"},
        {5, "Emma"},
        {6, "Frank"},
        {7, "Grace"},
        {8, "Helen"},
        {9, "Iris"}
    };
    // Linked list IDs range from 1 to 9.
    for (int i = 0; i < 9; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }
    /*
     * The curr is the last node. After the node is detached and released,
     * last is the last but one node in the original linked list.
     */
    BSL_LIST_DetachCurrent(testList);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 8);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_LAST(testList), &data[7]) == 0);
    // Delete Dave.
    BslListNode *detachNode = testList->first->next->next->next;
    BSL_LIST_DetachNode(testList, &detachNode);
    ASSERT_TRUE(UserDataCompare(detachNode->data, &data[4]) == 0); // Dave's position became Emma.
    /* When the deleted node is the current node, the current node will be
     * updated to the next node first; otherwise, it will be updated to the previous node.
     */
    testList->curr = testList->last->prev;
    ASSERT_TRUE(UserDataCompare(BSL_LIST_CURR_ELMT(testList), &data[6]) == 0);
    ASSERT_TRUE(UserDataCompare(testList->curr->next->data, &data[7]) == 0);
    BSL_LIST_DetachNode(testList, &testList->curr);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_CURR_ELMT(testList), &data[7]) == 0);
    ASSERT_TRUE(UserDataCompare(testList->curr->prev->data, &data[5]) == 0);
    BSL_LIST_DetachNode(testList, &testList->curr);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_CURR_ELMT(testList), &data[5]) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_SEARCH_FUNC_TC001
 * @title  list search test
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_Search to search for specified data. Expected result 2 is obtained.
 *    3. Call BSL_LIST_Search to search for specified data. Expected result 3 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. Data search succeeded.
 *    3. Data search succeeded.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_SEARCH_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);

    UserData data[5] = {
        {1, "Alice"},
        {2, "Bob"},
        {3, "Celina"},
        {4, "Dave"},
        {5, "Emma"}
    };
    // The sequence of linked list IDs is 1 - 2 - 3 - 4 - 5.
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[2], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[1], BSL_LIST_POS_BEFORE) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[0], BSL_LIST_POS_BEGIN) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[4], BSL_LIST_POS_END) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[3], BSL_LIST_POS_BEFORE) == BSL_SUCCESS);

    int errNum = 0;
    UserData *tmp1 = BSL_LIST_Search(testList, "Celina", UserDataCompareByName, NULL);
    ASSERT_TRUE(UserDataCompare(tmp1, &data[2]) == 0);

    UserData *tmp2 = BSL_LIST_Search(testList, "Dave", UserDataCompareByName, &errNum);
    ASSERT_TRUE(UserDataCompare(tmp2, &data[3]) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_GET_NODE_FUNC_TC001
 * @title  list GET NODE interface testing
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_FirstNode to get the first node in the linked list. Expected result 2 is obtained.
 *    3. Call BSL_LIST_GetData to get data from the node. Expected result 3 is obtained.
 *    4. Call BSL_LIST_GetNextNode to get the next node. Expected result 4 is obtained.
 *    5. Call BSL_LIST_GetData to get data from the node. Expected result 5 is obtained.
 *    6. Call BSL_LIST_GetNextNode to get the next node. Expected result 6 is obtained.
 *    7. Call BSL_LIST_GetData to get data from the node. Expected result 7 is obtained.
 *    8. Call BSL_LIST_GetNextNode to get the prev node. Expected result 8 is obtained.
 *    9. Call BSL_LIST_GetData to get data from the node. Expected result 9 is obtained.
 *    10. Call BSL_LIST_Curr to get the current element in the list. Expected result 10 is obtained.
 *    11. Call BSL_LIST_GetIndexNode to get the node at the given index in the list.
 *        Expected result 11 is obtained.
 *    12. Call BSL_LIST_Curr to get the current element in the list. Expected result 12 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. The first node is obtained successfully.
 *    3. Succeeded in obtaining data from the node, which is the same as the original data.
 *    4. The next node is obtained successfully.
 *    5. Succeeded in obtaining data from the node, which is the same as the original data.
 *    6. The next node is obtained successfully.
 *    7. Succeeded in obtaining data from the node, which is the same as the original data.
 *    8. The prev node is obtained successfully.
 *    9. Succeeded in obtaining data from the node, which is the same as the original data.
 *    10. The current node is obtained successfully, which is the same as the original data.
 *    11. The index node is obtained successfully, which is the same as the original data.
 *    12. The current node is obtained successfully, which is the same as the original data.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_GET_NODE_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);

    UserData data[5] = {
        {1, "Alice"},
        {2, "Bob"},
        {3, "Celina"},
        {4, "Dave"},
        {5, "Emma"}
    };
    for (int i = 0; i < 5; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }

    BslListNode *tmp = BSL_LIST_FirstNode(NULL);
    ASSERT_TRUE(tmp == NULL);
    tmp = BSL_LIST_FirstNode(testList);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GetData(tmp), &data[0]) == 0);
    tmp = BSL_LIST_GetNextNode(NULL, (const BslListNode *)BSL_LIST_FirstNode(testList));
    ASSERT_TRUE(tmp == NULL);
    tmp = BSL_LIST_GetNextNode(testList, (const BslListNode *)BSL_LIST_FirstNode(testList));
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GetData(tmp), &data[1]) == 0);
    tmp = BSL_LIST_GetNextNode(testList, (const BslListNode *)tmp);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GetData(tmp), &data[2]) == 0);
    tmp = BSL_LIST_GetPrevNode(tmp);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GetData(tmp), &data[1]) == 0);

    // curr points to 4.
    UserData *curTmp = *(UserData **)BSL_LIST_Curr(testList);
    ASSERT_TRUE(UserDataCompare(curTmp, &data[4]) == 0);
    // The subscript of the list starts from 0.
    UserData *getTmp = BSL_LIST_GetIndexNode(3, testList);
    ASSERT_TRUE(UserDataCompare(&data[3], getTmp) == 0);
    // BSL_LIST_GetIndexNode changes the curr point to 3.
    curTmp = *(UserData **)BSL_LIST_Curr(testList);
    ASSERT_TRUE(UserDataCompare(curTmp, &data[3]) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_COPY_FUNC_TC001
 * @title  list Copy test
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_Copy to copy the linked list to the new linked list
 *       and check whether the data in the two linked lists is the same. Expected result 2 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. The data in the two linked lists is the same.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_COPY_FUNC_TC001(void)
{
    BslList *srcList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(srcList != NULL);

    UserData data[3] = { {1, "Alice"}, {2, "Bob"}, {3, "Celina"} };
    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(srcList, &data[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }

    BslList *destList = BSL_LIST_Copy(srcList, UserDataCopy, UserDataFree);

    UserData *srcTmp = BSL_LIST_GET_FIRST(srcList);
    UserData *destTmp = BSL_LIST_GET_FIRST(destList);
    ASSERT_TRUE(UserDataCompare((const void *)srcTmp, (const void *)destTmp) == 0);
    srcTmp = BSL_LIST_GET_LAST(srcList);
    destTmp = BSL_LIST_GET_LAST(destList);
    ASSERT_TRUE(UserDataCompare((const void *)srcTmp, (const void *)destTmp) == 0);
    ASSERT_TRUE(UserDataCompare(destList->first->next->data, srcList->first->next->data) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(destList, NULL);
    BSL_LIST_FREE(srcList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_SORT_FUNC_TC001
 * @title  list sort test
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_Sort to sort the linked list and view the sorting result. Expected result 2 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. Linked list sorting succeeded.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_SORT_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);

    UserData data[6] = { {3, "Celina"}, {2, "Bob"}, {1, "Alice"}, {6, "Frank"}, {4, "Dave"}, {5, "Emma"} };
    for (int i = 0; i < 6; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }

    BSL_LIST_Sort(testList, UserDataSort);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_FIRST(testList), &data[2]) == 0);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_LAST(testList), &data[3]) == 0);
    ASSERT_TRUE(UserDataCompare(testList->first->next->next->next->data, &data[4]) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_SORT_FUNC_TC002
 * @title list sort test
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_GetMaxQsortCount to get max qsort count. Expected result 2 is obtained.
 *    3. Call BSL_LIST_SetMaxQsortCount to set max qsort count. Expected result 3 is obtained.
 *    4. Call BSL_LIST_GetMaxQsortCount to get max qsort count. Expected result 4 is obtained.
 *    5. Call BSL_LIST_Sort to sort the linked list and view the sorting result. Expected result 5 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. The obtained count is the same as the default count.
 *    3. Succeeded in setting the max qsort count.
 *    4. The obtained count is the same as the count.
 *    5. Linked list sorting succeeded.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_SORT_FUNC_TC002(void)
{
    int arr[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    BslList *list1 = NULL;

    list1 = BSL_LIST_New(sizeof(int));
    ASSERT_TRUE(list1 != NULL);

    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 4, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 3, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 2, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 1, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 7, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 5, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 8, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(list1, arr + 6, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(BSL_LIST_GetMaxQsortCount(), 100000);
    ASSERT_EQ(BSL_LIST_SetMaxQsortCount(67108865), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_LIST_SetMaxQsortCount(10000), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_GetMaxQsortCount(), 10000);

    list1 = BSL_LIST_Sort(list1, Compare);
    ASSERT_TRUE(list1 != NULL);

    int *p = BSL_LIST_GET_FIRST(list1);
    ASSERT_TRUE(p != NULL && *p == 1);
    p = BSL_LIST_GET_NEXT(list1);
    ASSERT_TRUE(p != NULL && *p == 2);
    p = BSL_LIST_GET_NEXT(list1);
    ASSERT_TRUE(p != NULL && *p == 3);
    p = BSL_LIST_GET_NEXT(list1);
    ASSERT_TRUE(p != NULL && *p == 4);
    p = BSL_LIST_GET_NEXT(list1);
    ASSERT_TRUE(p != NULL && *p == 5);
    p = BSL_LIST_GET_NEXT(list1);
    ASSERT_TRUE(p != NULL && *p == 6);
    p = BSL_LIST_GET_NEXT(list1);
    ASSERT_TRUE(p != NULL && *p == 7);
    p = BSL_LIST_GET_NEXT(list1);
    ASSERT_TRUE(p != NULL && *p == 8);

EXIT:
    BSL_LIST_FREE(list1, EmptyFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_ADD_GET_FUNC_TC001
 * @title  The list add and GET* interfaces testing.
 * @precon nan
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_CURR_ELMT. Expected result 2 is obtained.
 *    3. Call BSL_LIST_NEXT_ELMT. Expected result 3 is obtained.
 *    4. Call BSL_LIST_PREV_ELMT. Expected result 4 is obtained.
 *    5. Call BSL_LIST_LAST_ELMT. Expected result 5 is obtained.
 *    6. Call BSL_LIST_FIRST_ELMT. Expected result 6 is obtained.
 *    7. Call BSL_LIST_GET_FIRST. Expected result 7 is obtained.
 *    8. Call BSL_LIST_GET_LAST. Expected result 8 is obtained.
 *    9. Call BSL_LIST_GET_CURRENT. Expected result 9 is obtained.
 *    10. Call BSL_LIST_GET_NEXT. Expected result 10 is obtained.
 *    11. Call BSL_LIST_GET_PREV. Expected result 11 is obtained.
 *    12. Call BSL_LIST_GetIndexNode. Expected result 12 is obtained.
 *    13. Call BSL_LIST_GetElmtIndex. Expected result 13 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2~13. SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_ADD_GET_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 0);

    UserData data[4] = {
        {1, "bsl_list_001"},
        {2, "bsl_list_002"},
        {3, "bsl_list_003"},
        {4, "bsl_list_004"},
    };
    // The sequence of linked list IDs is 3 - 2 - 1 - 4.
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[0], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[1], BSL_LIST_POS_BEFORE) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[2], BSL_LIST_POS_BEGIN) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[3], BSL_LIST_POS_END) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 4);

    // Obtaining the macro of a node does not change the value of curr.
    ASSERT_TRUE(UserDataCompare(BSL_LIST_CURR_ELMT(testList), &data[3]) == 0);
    ASSERT_TRUE(BSL_LIST_NEXT_ELMT(testList) == NULL);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_PREV_ELMT(testList), &data[0]) == 0);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_LAST_ELMT(testList), &data[3]) == 0);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_FIRST_ELMT(testList), &data[2]) == 0);
    // Note that the Get function changes the value of curr.
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_FIRST(testList), &data[2]) == 0);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_LAST(testList), &data[3]) == 0);
    UserData *curTmp = *(UserData **)BSL_LIST_Curr(testList);
    ASSERT_TRUE(UserDataCompare(curTmp, &data[3]) == 0);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_PREV(testList), &data[0]) == 0);
    // Therefore, this is the next of curr->prev.
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_NEXT(testList), &data[3]) == 0);
    // The curr points to 3
    curTmp = *(UserData **)BSL_LIST_Curr(testList);
    ASSERT_TRUE(UserDataCompare(curTmp, &data[3]) == 0);

    // The subscript of the list starts from 0.
    UserData *tmp = BSL_LIST_GetIndexNode(2, testList);
    ASSERT_TRUE(UserDataCompare(&data[0], tmp) == 0);

    // BSL_LIST_GetIndexNode changes curr to 2.
    curTmp = *(UserData **)BSL_LIST_Curr(testList);
    ASSERT_TRUE(UserDataCompare(curTmp, &data[0]) == 0);

    ASSERT_TRUE(BSL_LIST_GetElmtIndex(&data[1], testList) == 1);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_CONCAT_FUNC_TC001
 * @title  list concat test
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_Concat to combine two linked lists and compare whether the data in the linked lists is correct.
 *       Expected result 2 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. Linked list combination succeeded.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_CONCAT_FUNC_TC001(void)
{
    BslList *destList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(destList != NULL);
    BslList *srcList1 = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(srcList1 != NULL);
    BslList *srcList2 = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(srcList2 != NULL);

    UserData data[6] = { {1, "Alice"}, {2, "Bob"}, {3, "Celina"}, {4, "Dave"}, {5, "Emma"}, {6, "Frank"} };
    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(srcList1, &data[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }
    for (int i = 3; i < 6; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(srcList2, &data[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }
    // Add to an empty linked list
    destList = BSL_LIST_Concat(destList, srcList1);
    // Add to non-empty linked list
    destList = BSL_LIST_Concat(destList, srcList2);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_FIRST(destList), &data[0]) == 0);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_LAST(destList), &data[5]) == 0);
    ASSERT_TRUE(UserDataCompare(destList->first->next->next->next->data, &data[3]) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(destList, UserDataFree);
    BSL_SAL_FREE(srcList1);
    BSL_SAL_FREE(srcList2); // The nodes are free, so just use the free linked list itself.
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_REVERSE_FUNC_TC001
 * @title  list reverse test
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_RevList to reverse the linked list. Expected result 2 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. Succeeded in reversing the linked list.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_REVERSE_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);

    UserData data[3] = { {1, "Alice"}, {2, "Bob"}, {3, "Celina"} };

    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(testList, &data[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }

    BSL_LIST_RevList(testList);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_FIRST(testList), &data[2]) == 0);
    ASSERT_TRUE(UserDataCompare(BSL_LIST_GET_LAST(testList), &data[0]) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_DETELE_NODE_FUNC_TC001
 * @title  list delete test
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_FirstNode to get the first node in the linked list. Expected result 2 is obtained.
 *    3. Call BSL_LIST_DeleteNode to delete the first node. Expected result 3 is obtained.
 *    4. Call BSL_LIST_DeleteAll to delete all node. Expected result 4 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. Succeeded in reversing the linked list.
 *    3. The deletion is successful, and the number of nodes decreases by 1.
 *    4. The deletion is successful. The number of nodes is 0.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_DELETE_NODE_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);

    UserData data[3] = { {1, "Alice"}, {2, "Bob"}, {3, "Celina"} };

    UserData *data1 = BSL_SAL_Malloc(sizeof(UserData) * 3);
    ASSERT_TRUE(data1 != NULL);
    memcpy_s(data1, sizeof(UserData) * 3, data, sizeof(UserData) *3);

    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(testList, &data1[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }

    BslListNode *tmp = BSL_LIST_FirstNode(testList);
    BSL_LIST_DeleteNode(testList, tmp, UserDataFree);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 2);
    BSL_LIST_DeleteAll(testList, UserDataFree);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    free(data1);
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_DETELE_NODE_FUNC_TC002
 * @title  list delete test
 * @brief
 *    1. Call BSL_LIST_AddElement to add data to the linked list. Expected result 1 is obtained.
 *    2. Call BSL_LIST_DeleteAllAfterSort to delete all node. Expected result 2 is obtained.
 * @expect
 *    1. Data added successfully. return BSL_SUCCESS.
 *    2. The deletion is successful. The number of nodes is 0.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_DELETE_NODE_FUNC_TC002(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);

    UserData data[3] = { {1, "Alice"}, {2, "Bob"}, {3, "Celina"} };

    UserData *data1 = BSL_SAL_Malloc(sizeof(UserData) * 3);
    ASSERT_TRUE(data1 != NULL);
    memcpy_s(data1, sizeof(UserData) * 3, data, sizeof(UserData) *3);

    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(BSL_LIST_AddElement(testList, &data1[i], BSL_LIST_POS_AFTER) == BSL_SUCCESS);
    }

    BSL_LIST_DeleteAllAfterSort(testList);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    free(data1);
    BSL_LIST_FREE(testList, UserDataFree);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_LIST_API_TC001
 * @title  list previous node test
 * @brief
 *    1. Check if previous element is NULL. Expected result 1 is obtained.
 *    2. Call BSL_LIST_AddElement to add data to the linked list. Expected result 2 is obtained.
 *    3. Check if previous element is NULL. Expected result 3 is obtained.
 * @expect
 *    1. The previous node is NULL.
 *    2. Data added successfully. return BSL_SUCCESS.
 *    3. The previous node is not NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_LIST_Pre_API_TC001()
{
    int arr[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};

    /* when list is NULL */
    int **prv = BSL_LIST_Prev(NULL);
    ASSERT_EQ(prv, NULL);

    /* pstList->curr == NULL */
    BslList *list = BSL_LIST_New(sizeof(int));
    ASSERT_TRUE(list != NULL);
    prv = BSL_LIST_Prev(list);
    ASSERT_EQ(prv, NULL);

    /* pstList->curr != NULL,  pstList->curr->prev == NULL */
    ASSERT_EQ(BSL_LIST_AddElement(list, arr + 0, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    prv = BSL_LIST_Prev(list);
    ASSERT_EQ(prv, NULL);

    /* pstList->curr != NULL,  pstList->curr->prev != NULL */
    ASSERT_EQ(BSL_LIST_AddElement(list, arr + 1, BSL_LIST_POS_AFTER), BSL_SUCCESS);
    prv = BSL_LIST_Prev(list);
    ASSERT_TRUE(prv != NULL && **prv == 0);

    /* pstList->curr == NULL,  pstList->last != NULL */
    prv = BSL_LIST_Prev(list);
    ASSERT_EQ(prv, NULL);
    prv = BSL_LIST_Prev(list);
    ASSERT_TRUE(prv != NULL && **prv == 1);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_LIST_FREE(list, EmptyFree);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_LIST_Next_API_TC002
 * @title  list next node test
 * @brief
 *    1. Check if next node is NULL. Expected result 1 is obtained.
 *    2. Call BSL_LIST_AddElement to add data to the linked list. Expected result 2 is obtained.
 *    3. Check if next node is NULL. Expected result 3 is obtained.
 * @expect
 *    1. The next node is NULL.
 *    2. Data added successfully. return BSL_SUCCESS.
 *    3. The next node is not NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_LIST_Next_API_TC002()
{
    int arr[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};

    /* when list is NULL */
    int **next = BSL_LIST_Prev(NULL);
    ASSERT_EQ(next, NULL);

    /* pstList->curr == NULL */
    BslList *list = BSL_LIST_New(sizeof(int));
    ASSERT_TRUE(list != NULL);
    next = BSL_LIST_Next(list);
    ASSERT_EQ(next, NULL);

    /* pstList->curr != NULL,  pstList->curr->next == NULL */
    ASSERT_EQ(BSL_LIST_AddElement(list, arr + 0, BSL_LIST_POS_BEFORE), BSL_SUCCESS);
    next = BSL_LIST_Next(list);
    ASSERT_EQ(next, NULL);

    /* pstList->curr != NULL,  pstList->curr->next != NULL */
    ASSERT_EQ(BSL_LIST_AddElement(list, arr + 1, BSL_LIST_POS_BEFORE), BSL_SUCCESS);
    next = BSL_LIST_Next(list);
    ASSERT_TRUE(next != NULL && **next == 0);

    /* pstList->curr == NULL,  pstList->first != NULL */
    next = BSL_LIST_Next(list);
    ASSERT_EQ(next, NULL);
    next = BSL_LIST_Next(list);
    ASSERT_TRUE(next != NULL && **next == 1);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_LIST_FREE(list, EmptyFree);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_SET_MAX_FUNC_TC001
 * @title  list is* Interface test
 * @brief   1. BSL_LIST_SetMaxQsortCount
            2. BSL_LIST_GetMaxQsortCount
            3. BSL_LIST_SetMaxElements
            4. BSL_LIST_GetMaxElements
 * @expect  1. BSL_SUCCESS
            2. g_maxQsortElem = 100001
            3. BSL_SUCCESS
            4. g_maxListCount = 65536
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_SET_MAX_FUNC_TC001(void)
{
    ASSERT_TRUE(BSL_LIST_SetMaxQsortCount(100001) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_GetMaxQsortCount() == 100001);
    ASSERT_TRUE(BSL_LIST_SetMaxElements((1 << 16)) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_GetMaxElements() == (1 << 16));
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_INVALID_INPUT_FUNC_TC001
 * @title  list invalid or empty input parameter value test
 * @brief   0. BSL_LIST_AddElement
            1. BSL_LIST_AddElement
            2. BSL_LIST_Search
            3. BSL_LIST_Concat
            4. BSL_LIST_Sort
            5. BSL_LIST_Copy
            6. BSL_LIST_Copy
            7. BSL_LIST_GetData
            8. BSL_LIST_FirstNode
            9. BSL_LIST_GetNextNode
            10. BSL_LIST_GetPrevNode
            11. BSL_LIST_SetMaxQsortCount
            12. BSL_LIST_SetMaxElements
 * @expect  0. BSL_INVALID_ARG
            1. BSL_LIST_DATA_NOT_AVAILABLE
            2. NULL
            3. NULL
            4. NULL
            5. NULL
            6. NULL
            7. NULL
            8. NULL
            9. NULL
            10. BSL_LIST_GetPrevNode
            11. BSL_INVALID_ARG
            12. BSL_INVALID_ARG
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_INVALID_INPUT_FUNC_TC001(void)
{
    ASSERT_TRUE(BSL_LIST_AddElement(NULL, NULL, BSL_LIST_POS_BEFORE) == BSL_INVALID_ARG);

    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, NULL, BSL_LIST_POS_BEFORE) == BSL_LIST_DATA_NOT_AVAILABLE);

    ASSERT_TRUE(BSL_LIST_Search(NULL, NULL, UserDataCompare, NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_Concat(NULL, NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_Sort(NULL, NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_Copy(NULL, UserDataCopy, UserDataFree) == NULL);
    ASSERT_TRUE(BSL_LIST_Copy(testList, UserDataCopy, UserDataFree) == NULL);
    ASSERT_TRUE(BSL_LIST_GetData(NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_FirstNode(NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_GetNextNode(NULL, NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_GetPrevNode(NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_SearchEx(NULL, NULL, NULL) == NULL);
    ASSERT_TRUE(BSL_LIST_GetIndexNodeEx(0, NULL, NULL) == NULL);

    ASSERT_TRUE(BSL_LIST_SetMaxQsortCount(10) == BSL_INVALID_ARG);
    ASSERT_TRUE(BSL_LIST_SetMaxElements(10) == BSL_INVALID_ARG);
EXIT:
    BSL_SAL_FREE(testList);
}
/* END_CASE */

/**
 * @test SDV_BSL_LIST_DELETE_FUNC_TC001
 * @title  test the function of deleting a node.
 * @brief
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_DELETE_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);
 
    ASSERT_TRUE(BSL_LIST_AddElement(testList, "aaaa", BSL_LIST_POS_BEFORE) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, "bbbb", BSL_LIST_POS_BEFORE) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 2);
    BslListNode *tmpNode = NULL;
    for (BslListNode *node = BSL_LIST_FirstNode(testList); node != NULL;) {
        tmpNode = node;
        char *name = BSL_LIST_GetData(tmpNode);
        if (name == NULL) {
            continue;
        }
        node = BSL_LIST_GetNextNode(testList, tmpNode);
        if (strcmp(name, "aaaa") == 0) {
            BSL_LIST_DeleteNode(testList, (const BslListNode *)tmpNode, UserDataFree);
            continue;
        }
        if (strcmp(name, "bbbb") == 0) {
            BSL_LIST_DeleteNode(testList, (const BslListNode *)tmpNode, UserDataFree);
            continue;
        }
    }
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 0);
    ASSERT_TRUE(BSL_LIST_AddElement(testList, "cccc", BSL_LIST_POS_BEFORE) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LIST_COUNT(testList) == 1);
    BSL_LIST_DeleteCurrent(testList, UserDataFree);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_FREE(testList);
}
/* END_CASE */

/**
 * @test   SDV_BSL_LIST_FREE_WITHOUT_FUNC_TC001
 * @title  test BSL_LIST_FreeWithoutData functions
 * @precon nan
 * @brief
 *    1.Call BSL_LIST_New create a list, Expected result 1 is obtained.
 *    2.Call BSL_LIST_FreeWithoutData free normal list, Expected result 2 is obtained.
 *    3.Call BSL_LIST_FreeWithoutData free empty list, Expected result 2 is obtained.
 * @expect
 *    1. The list is created successfully.
 *    2. The list is free successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_LIST_FREE_WITHOUT_FUNC_TC001(void)
{
    BslList *testList = BSL_LIST_New(MAX_NAME_LEN);
    ASSERT_TRUE(testList != NULL);
    BSL_LIST_FreeWithoutData(testList);
    testList = NULL;
EXIT:
    BSL_LIST_FreeWithoutData(testList);
}
/* END_CASE */

