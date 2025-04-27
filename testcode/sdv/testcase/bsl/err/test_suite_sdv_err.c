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

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_err.h"
#include "avl.h"
#include "bsl_uio.h"

static int32_t PthreadRWLockNew(BSL_SAL_ThreadLockHandle *lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    pthread_rwlock_t *newLock;
    newLock = (pthread_rwlock_t *)BSL_SAL_Malloc(sizeof(pthread_rwlock_t));
    if (newLock == NULL) {
        return BSL_MALLOC_FAIL;
    }
    if (pthread_rwlock_init(newLock, NULL) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    *lock = newLock;
    return BSL_SUCCESS;
}

static void PthreadRWLockFree(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return;
    }
    pthread_rwlock_destroy((pthread_rwlock_t *)lock);
    BSL_SAL_FREE(lock);
}

static int32_t PthreadRWLockReadLock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_rdlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t PthreadRWLockWriteLock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_wrlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t PthreadRWLockUnlock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_unlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static uint64_t PthreadGetId(void)
{
    return (uint64_t)pthread_self();
}

static void PushErrorFixTimes(int32_t times)
{
    while (times) {
        BSL_ERR_PUSH_ERROR(times);
        times--;
    }
}

static void RegThreadFunc(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_NEW_CB_FUNC, PthreadRWLockNew);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_FREE_CB_FUNC, PthreadRWLockFree);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC, PthreadRWLockReadLock);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, PthreadRWLockWriteLock);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC, PthreadRWLockUnlock);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetId);
}

/* END_HEADER */

/**
 * @test SDV_BSL_ERR_FUNC_TC001
 * @title Error code test in single-thread mode
 * @precon Set the memory allocation and release functions.
 * @brief
 *    1. Initializes BSL_ERR. Expected result 1 is obtained.
 *    2. Invoke the interface to obtain the error when no error is pushed. Expected result 2 is obtained.
 *    3. Push an BSL_UIO_FAIL error when no memory function is registered. Expected result 3 is obtained.
 *    4. Push the BSL_UIO_FAIL and BSL_UIO_IO_EXCEPTION error and obtain last error. Expected result 4 is obtained.
 *    5. Peek last error file and error line. Expected result 5 is obtained.
 *    6. Get last error file and error line. Expected result 6 is obtained.
 *    7. Push an error after clear the error stack, and then obtain the error. Expected result 7 is obtained.
 *    8. Delete the error stack of the thread. Expected result 8 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_SUCCESS
 *    3. BSL_UIO_FAIL
 *    4. BSL_UIO_IO_EXCEPTION
 *    5. BSL_UIO_FAIL
 *    6. BSL_UIO_FAIL
 *    7. BSL_SUCCESS
 *    8. BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_FUNC_TC001(void)
{
    TestMemInit();
    int32_t err;

    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);

    /* no error is pushed */
    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);

    /* If no memory function is registered, push an error and allocate an error stack. */
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_UIO_FAIL);

    /* Push the BSL_UIO_FAIL and BSL_UIO_IO_EXCEPTION error to the error stack. */
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_UIO_IO_EXCEPTION, __FILENAME__, __LINE__);
    err = BSL_ERR_GetLastError();
    ASSERT_TRUE(err == BSL_UIO_IO_EXCEPTION);

    const char *file = NULL;
    uint32_t line = 0;
    err = BSL_ERR_PeekLastErrorFileLine(&file, &line);
    ASSERT_TRUE(err == BSL_UIO_FAIL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);

    file = NULL;
    line = 0;
    err = BSL_ERR_GetLastErrorFileLine(&file, &line);
    ASSERT_TRUE(err == BSL_UIO_FAIL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);

    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);

    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_ClearError();
    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);

    BSL_ERR_RemoveErrorStack(false);

    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);
EXIT:
    BSL_ERR_DeInit();
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_ERR_STACK_FUNC_TC001
 * @title  After stacks are not pushed or cleared, call BSL_ERR_GetLastError to query all error stacks.
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_CallBack_Ctrl to initialize the memory. Expected result 1 is obtained.
 *    2. Call BSL_SAL_CallBack_Ctrl to initialize the thread. Expected result 2 is obtained.
 *    3. Call BSL_ERR_Init for initialization. Expected result 3 is obtained.
 *    4. Call BSL_ERR_GetLastError to obtain stack information. Expected result 4 is obtained.
 *    5. Call ERR_PUSH_ERROR to push stack layer 5. Expected result 5 is obtained.
 *    6. Call BSL_ERR_ClearError to clear the stack. Expected result 6 is obtained.
 *    7. Call BSL_ERR_GetLastError to obtain stack information. Expected result 7 is obtained.
 *    8. Call BSL_ERR_RemoveErrorStack to delete the stack. Expected result 8 is obtained.
 *    9. Call BSL_ERR_GetLastError to obtain stack information. Expected result 9 is obtained.
 *    10. Call BSL_ERR_DeInit to deinitialize. Expected result 10 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_SUCCESS
 *    3. BSL_SUCCESS
 *    4. BSL_SUCCESS is returned when the error code is obtained.
 *    5. BSL_SUCCESS
 *    6. BSL_SUCCESS
 *    7. BSL_SUCCESS is returned when the error code is obtained.
 *    8. BSL_SUCCESS
 *    9. BSL_SUCCESS is returned when the error code is obtained.
 *    10. BSL_SUCCESS
 */
/* BEGIN_CASE */

void SDV_BSL_ERR_STACK_FUNC_TC001(int isRemoveAll)
{
    TestMemInit();
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_NEW_CB_FUNC, PthreadRWLockNew) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_FREE_CB_FUNC, PthreadRWLockFree) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC, PthreadRWLockReadLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, PthreadRWLockWriteLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC, PthreadRWLockUnlock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetId) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);

    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);
    PushErrorFixTimes(5);
    ASSERT_TRUE(BSL_ERR_PeekLastErrorFileLine(NULL, NULL) == 1);
    ASSERT_TRUE(BSL_ERR_GetLastErrorFileLine(NULL, NULL) == 1);
    ASSERT_TRUE(BSL_ERR_GetErrorFileLine(NULL, NULL) == 5);
    BSL_ERR_ClearError();
    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack((isRemoveAll == 1) ? true : false);
    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);

    BSL_ERR_PushError(1, "2", 3);
    uint32_t lineNo = 0;
    char *file = NULL;
    ASSERT_TRUE(BSL_ERR_PeekLastErrorFileLine(NULL, &lineNo) == 1);
    ASSERT_TRUE(lineNo == 0);
    ASSERT_TRUE(BSL_ERR_PeekErrorFileLine(NULL, &lineNo) == 1);
    ASSERT_TRUE(lineNo == 0);
    ASSERT_TRUE(BSL_ERR_PeekLastErrorFileLine((const char **)&file, &lineNo) == 1);
    ASSERT_TRUE(strcmp(file, "2") == 0);
    ASSERT_TRUE(lineNo == 3);
    lineNo = 0;
    ASSERT_TRUE(BSL_ERR_PeekErrorFileLine((const char **)&file, &lineNo) == 1);
    ASSERT_TRUE(strcmp(file, "2") == 0);
    ASSERT_TRUE(lineNo == 3);
    ASSERT_TRUE(BSL_ERR_GetError() == 1);
    BSL_ERR_PUSH_ERROR(BSL_SUCCESS);

    lineNo = 0;
    BSL_ERR_PushError(1, NULL, 3);
    ASSERT_TRUE(BSL_ERR_PeekLastErrorFileLine(NULL, &lineNo) == 1);
    ASSERT_TRUE(lineNo == 0);
    ASSERT_TRUE(BSL_ERR_PeekErrorFileLine(NULL, &lineNo) == 1);
    ASSERT_TRUE(lineNo == 0);
    ASSERT_TRUE(BSL_ERR_PeekLastErrorFileLine((const char **)&file, &lineNo) == 1);
    ASSERT_TRUE(strcmp(file, "NA") == 0);
    ASSERT_TRUE(lineNo == 0);
    ASSERT_TRUE(BSL_ERR_PeekErrorFileLine((const char **)&file, &lineNo) == 1);
    ASSERT_TRUE(strcmp(file, "NA") == 0);
    ASSERT_TRUE(lineNo == 0);
EXIT:
    BSL_ERR_ClearError();
    BSL_ERR_DeInit();
}
/* END_CASE */

/**
 * @test SDV_BSL_ERR_COMPATIBILITY_FUNC_TC001
 * @title Test the compatibility of the err module in different CMake versions.
 * @precon Set the memory allocation and release functions.
 * @brief
 *    1. Initializes BSL_ERR. Expected result 1 is obtained.
 *    2. Construct an exception to trigger the ERR module to push the stack. Expected result 2 is obtained.
 *    3. Obtains the push-stack information, Expected result 3 and 4 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_NULL_INPUT
 *    3. "uio_abstraction.c"
 *    4. BSL_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_COMPATIBILITY_FUNC_TC001(void)
{
#ifndef HITLS_BSL_UIO_PLT
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_NEW_CB_FUNC, PthreadRWLockNew) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_FREE_CB_FUNC, PthreadRWLockFree) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC, PthreadRWLockReadLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, PthreadRWLockWriteLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC, PthreadRWLockUnlock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetId) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    // Construct an exception to trigger the error code module to push the stack.
    ASSERT_TRUE(BSL_UIO_SetMethodType(NULL, 1) == BSL_NULL_INPUT);
    char *file = NULL;
    uint32_t line = 0;
    int32_t err = BSL_ERR_GetLastErrorFileLine((const char **)&file, &line);
    ASSERT_TRUE(strcmp(file, "uio_abstraction.c") == 0);
    ASSERT_TRUE(err == BSL_NULL_INPUT);
EXIT:
    BSL_ERR_ClearError();
    BSL_ERR_DeInit();
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_ERR_STACK_API_TC001
 * @title  BSL_ERR_ClearError interface testing
 * @precon  nan
 * @brief
 *    1.Call BSL_ERR_RemoveErrorStack to delete the stack. Expected result 2 is obtained.
 *    2.Call BSL_ERR_ClearError to clear the stack. Expected result 3 is obtained.
 *    3.Call BSL_ERR_ClearError repeatedly to clear the stack. Expected result 4 is obtained.
 * @expect
 *    1.BSL_SUCCESS
 *    2.SUCCESS
 *    3.SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_STACK_API_TC001(int isRemoveAll)
{
    TestMemInit();
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_NEW_CB_FUNC, PthreadRWLockNew) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_FREE_CB_FUNC, PthreadRWLockFree) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC, PthreadRWLockReadLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, PthreadRWLockWriteLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC, PthreadRWLockUnlock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetId) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);

    BSL_ERR_RemoveErrorStack((isRemoveAll == 1) ? true : false);
    BSL_ERR_ClearError();
    BSL_ERR_ClearError();
EXIT:
    BSL_ERR_DeInit();
}
/* END_CASE */

/**
 * @test SDV_BSL_ERR_MARK_FUNC_TC001
 * @title Registering and Obtaining Error Descriptions
 * @precon  nan
 * @brief
 *    1. Set flags. Expected result 1 is obtained.
 *    2. Push the error code on the stack. If no flag is set, invoke the pop to mark interface
 *       and obtain the latest error code. Expected result 2 is obtained.
 *    3. Push three error codes into the stack and set a flag for the second error code. Expected result 3 is obtained.
 *    4. Push three error codes into the stack, set flags for the second and third error codes, clear the latest flag,
 *       and invoke pop to mark to obtain the latest error code. Expected result 4 is obtained.
 * @expect
 *    1. Return BSL_ERR_ERR_NO_ERROR.
 *    2. Return BSL_ERR_ERR_NO_MARK, and the error code is 0.
 *    3. The flag is set successfully. The second error code is returned
 *       when the latest error code is obtained for the first time.
 *       The first error code is returned when the latest error code is obtained for the second time.
 *    4. The latest error code is the second error code.
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_MARK_FUNC_TC001(void)
{
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    int32_t ret;

    ret = BSL_ERR_SetMark();
    ASSERT_TRUE(ret == BSL_ERR_ERR_NO_STACK);

    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_BUSY);
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    ret = BSL_ERR_PopToMark();
    ASSERT_TRUE(ret == BSL_ERR_ERR_NO_MARK);
    ret = BSL_ERR_GetLastError();
    ASSERT_TRUE(ret == BSL_SUCCESS);

    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_BUSY);
    ret = BSL_ERR_SetMark();
    ASSERT_TRUE(ret == BSL_SUCCESS);
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    ret = BSL_ERR_PopToMark();
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ret = BSL_ERR_GetLastError();
    ASSERT_TRUE(ret == BSL_UIO_IO_BUSY);
    ret = BSL_ERR_GetLastError();
    ASSERT_TRUE(ret == BSL_UIO_FAIL);
    ret = BSL_ERR_GetLastError();
    ASSERT_TRUE(ret == BSL_SUCCESS);

    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_BUSY);
    ret = BSL_ERR_SetMark();
    ASSERT_TRUE(ret == BSL_SUCCESS);
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    ret = BSL_ERR_SetMark();
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ret = BSL_ERR_ClearLastMark();
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ret = BSL_ERR_PopToMark();
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ret = BSL_ERR_GetLastError();
    ASSERT_TRUE(ret == BSL_UIO_IO_BUSY);
EXIT:
    BSL_ERR_DeInit();
}
/* END_CASE */

/**
 * @test SDV_BSL_ERR_STRING_FUNC_TC001
 * @title Registering and Obtaining Error Descriptions
 * @precon  nan
 * @brief
 *    1. The registration list is empty. Expected result 1 is obtained.
 *    2. The registration list is not empty. The number of registrations is 0. Expected result 2 is obtained.
 *    3. The registration list is not empty, and the number of registrations is 2. Expected result 3 is obtained.
 *    4. Obtains the first error description. Expected result 4 is obtained.
 *    5. Obtains the second error description. Expected result 5 is obtained.
 * @expect
 *    1. Return BSL_NULL_INPUT.
 *    2. Return BSL_NULL_INPUT.
 *    3. Return BSL_SUCCESS.
 *    4. The result is the first error description.
 *    5. The result is the second error description.
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_STRING_FUNC_TC001(void)
{
    RegThreadFunc();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);

    ASSERT_TRUE(BSL_ERR_AddErrStringBatch(NULL, 0) == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_ERR_AddErrStringBatch((void *)-1, 0) == BSL_NULL_INPUT);

    const char *uioFail = "uio is failed";
    const char *tlvFail = "tlv needed type";
    const BSL_ERR_Desc descList[] = {
        {BSL_UIO_FAIL, uioFail},
        {BSL_TLV_ERR_NO_WANT_TYPE, tlvFail},
    };
    ASSERT_TRUE(BSL_ERR_AddErrStringBatch(descList, 2) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_ERR_GetString(BSL_UIO_FAIL) == uioFail);
    ASSERT_TRUE(BSL_ERR_GetString(BSL_TLV_ERR_NO_WANT_TYPE) == tlvFail);
EXIT:
    BSL_ERR_RemoveErrStringBatch();
    BSL_ERR_DeInit();
}
/* END_CASE */

/**
 * @test SDV_BSL_ERR_AVLLR_FUNC_TC001
 * @title A balanced binary tree is unbalanced due to insertion of nodes into the right subtree of the left subtree, and thus rotated to balance the test.
 * @brief
 *    1. insert 100
 *    2. insert 120
 *    3. insert 80
 *    4. insert 70
 *    5. insert 90
 *    6. insert 85
 *    7. delete 90
 *    8. delete 200
 *    9. delete 100
 *    10. delete 120
 * @expect
 *    1. root node is 100
 *    2. root node is 100
 *    3. root node is 100
 *    4. root node is 100
 *    5. root node is 100
 *    6. root node is 90
 *    7. root node is 85
 *    8. root node is 85
 *    9. root node is 85
 *    10. root node is 80
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_AVLLR_FUNC_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);

    BSL_AvlTree *root = NULL;

    root = BSL_AVL_InsertNode(root, 100, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 120, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 80, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 70, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 90, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 85, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 90);

    root = BSL_AVL_DeleteNode(root, 90, NULL);
    ASSERT_TRUE(root->nodeId == 85);
    root = BSL_AVL_DeleteNode(root, 200, NULL);
    ASSERT_TRUE(root->nodeId == 85);
    root = BSL_AVL_DeleteNode(root, 100, NULL);
    ASSERT_TRUE(root->nodeId == 85);
    root = BSL_AVL_DeleteNode(root, 120, NULL);
    ASSERT_TRUE(root->nodeId == 80);

    BSL_AVL_DeleteTree(root, NULL);

EXIT:
    BSL_ERR_DeInit();
}
/* END_CASE */

/**
 * @test SDV_BSL_ERR_AVLLL_FUNC_TC001
 * @title A balanced binary tree is unbalanced due to insertion of nodes into the left subtree of the left subtree, and thus rotated to balance the test.
 * @brief
 *    1. insert 100
 *    2. insert 120
 *    3. insert 80
 *    4. insert 70
 *    5. insert 90
 *    6. insert 65
 *    7. find 90
 *    8. find 67
 *    9. delete 70
 *    10. delete 65
 * @expect
 *    1. root node is 100
 *    2. root node is 100
 *    3. root node is 100
 *    4. root node is 100
 *    5. root node is 100, the structure of the tree is
                 100
                /   \
               /     \
              80     120
             /  \
           70    90
 *    6. root node is 80, the structure of the tree is
                 80
                /  \
               /    \
              70    100
             /     /   \
           65    90    120
 *    7. find
 *    8. Couldn't find
 *    9. root node is 80
 *    10. root node is 100
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_AVLLL_FUNC_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_AvlTree *root = NULL;

    root = BSL_AVL_InsertNode(root, 100, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 120, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 80, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 70, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 90, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 65, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 80);

    ASSERT_TRUE(BSL_AVL_SearchNode(root, 90) != NULL);
    ASSERT_TRUE(BSL_AVL_SearchNode(root, 67) == NULL);

    root = BSL_AVL_DeleteNode(root, 70, NULL);
    ASSERT_TRUE(root->nodeId == 80);
    root = BSL_AVL_DeleteNode(root, 65, NULL);
    ASSERT_TRUE(root->nodeId == 100);

    BSL_AVL_DeleteTree(root, NULL);

EXIT:
    BSL_ERR_DeInit();
}
/* END_CASE */

/**
 * @test SDV_BSL_ERR_AVLRL_FUNC_TC001
 * @title A balanced binary tree is unbalanced due to insertion of nodes into the left subtree of the right subtree, and thus rotated to balance the test.
 * @brief
 *    1. insert 100
 *    2. insert 80
 *    3. insert 120
 *    4. insert 110
 *    5. insert 130
 *    6. insert 105
 * @expect
 *    1. root node is 100
 *    2. root node is 100
 *    3. root node is 100
 *    4. root node is 100
 *    5. root node is 100
 *    6. root node is 110
 */
/* BEGIN_CASE */
void SDV_BSL_ERR_AVLRL_FUNC_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_AvlTree *root = NULL;

    root = BSL_AVL_InsertNode(root, 100, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 80, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 120, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 110, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 130, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 100);
    root = BSL_AVL_InsertNode(root, 105, BSL_AVL_MakeLeafNode(NULL));
    ASSERT_TRUE(root->nodeId == 110);

    BSL_AVL_DeleteTree(root, NULL);

EXIT:
    BSL_ERR_DeInit();
}
/* END_CASE */


