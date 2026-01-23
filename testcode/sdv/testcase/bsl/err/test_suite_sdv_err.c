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
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_err.h"
#include "avl.h"
#include "bsl_uio.h"
#include "hitls_pki_errno.h"
#include "crypt_errno.h"
#include "hitls_error.h"
#include "auth_errno.h"
#include "securec.h"


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

#define PTHREAD_ARBITRARY_ID 123456789101112 // 1 ~ 12

static uint64_t PthreadGetArbitraryId(void)
{
    return PTHREAD_ARBITRARY_ID;
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
    BSL_ERR_RemoveErrorStack(true);

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
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);

    file = NULL;
    line = 0;
    err = BSL_ERR_GetLastErrorFileLine(&file, &line);
    ASSERT_TRUE(err == BSL_UIO_FAIL);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);

    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);

    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_ClearError();
    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);

    BSL_ERR_RemoveErrorStack(false);

    ASSERT_TRUE(BSL_ERR_GetLastError() == BSL_SUCCESS);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
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
    BSL_ERR_RemoveErrorStack(true);

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
    ASSERT_TRUE(file != NULL && strcmp(file, "2") == 0 && lineNo == 3);
    
    lineNo = 0;
    file = NULL;
    ASSERT_TRUE(BSL_ERR_PeekErrorFileLine((const char **)&file, &lineNo) == 1);
    ASSERT_TRUE(file != NULL && strcmp(file, "2") == 0 && lineNo == 3);
    ASSERT_TRUE(BSL_ERR_GetError() == 1);
    BSL_ERR_PUSH_ERROR(BSL_SUCCESS);

    lineNo = 0;
    BSL_ERR_PushError(1, NULL, 3);
    ASSERT_TRUE(BSL_ERR_PeekLastErrorFileLine(NULL, &lineNo) == 1);
    ASSERT_TRUE(lineNo == 0);
    ASSERT_TRUE(BSL_ERR_PeekErrorFileLine(NULL, &lineNo) == 1);
    ASSERT_TRUE(lineNo == 0);
    file = NULL;
    ASSERT_TRUE(BSL_ERR_PeekLastErrorFileLine((const char **)&file, &lineNo) == 1);
    ASSERT_TRUE(file != NULL && strcmp(file, "NA") == 0 && lineNo == 0);
    file = NULL;
    ASSERT_TRUE(BSL_ERR_PeekErrorFileLine((const char **)&file, &lineNo) == 1);
    ASSERT_TRUE(file != NULL && strcmp(file, "NA") == 0 && lineNo == 0);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
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
    BSL_ERR_RemoveErrorStack(true);
    // Construct an exception to trigger the error code module to push the stack.
    ASSERT_TRUE(BSL_UIO_SetMethodType(NULL, 1) == BSL_NULL_INPUT);
    char *file = NULL;
    uint32_t line = 0;
    int32_t err = BSL_ERR_GetLastErrorFileLine((const char **)&file, &line);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, "uio_abstraction.c") == 0);
    ASSERT_TRUE(err == BSL_NULL_INPUT);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
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
    BSL_ERR_RemoveErrorStack(true);

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
    BSL_ERR_RemoveErrorStack(true);
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
    BSL_ERR_RemoveErrorStack(true);
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
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_RemoveErrStringBatch();

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
    BSL_AvlTree *root = NULL;
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);

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
EXIT:
    BSL_AVL_DeleteTree(root, NULL);
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
    BSL_AvlTree *root = NULL;
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);

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
EXIT:
    BSL_AVL_DeleteTree(root, NULL);
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
    BSL_AvlTree *root = NULL;
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
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
EXIT:
    BSL_AVL_DeleteTree(root, NULL);
    BSL_ERR_ClearError();
    BSL_ERR_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_PEEK_FUNC_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);

    // Test peek operations on empty stack
    ASSERT_TRUE(BSL_ERR_PeekLastError() == BSL_SUCCESS);

    // Push multiple errors to test peek operations
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_UIO_IO_BUSY, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_UIO_IO_EXCEPTION, __FILENAME__, __LINE__);

    // Test BSL_ERR_PeekError - should return the first (oldest) error
    int32_t firstError = BSL_ERR_PeekError();
    ASSERT_TRUE(firstError == BSL_UIO_FAIL);

    // Test BSL_ERR_PeekLastError - should return the last (newest) error
    int32_t lastError = BSL_ERR_PeekLastError();
    ASSERT_TRUE(lastError == BSL_UIO_IO_EXCEPTION);

    // Verify that peek operations don't modify the error stack
    // The errors should still be there in the same order
    ASSERT_TRUE(BSL_ERR_PeekError() == BSL_UIO_FAIL);
    ASSERT_TRUE(BSL_ERR_PeekLastError() == BSL_UIO_IO_EXCEPTION);

    // Verify the stack is intact by getting errors in order
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_UIO_FAIL);
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_UIO_IO_BUSY);
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_UIO_IO_EXCEPTION);
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_SUCCESS);

    // Test peek operations on empty stack again
    ASSERT_TRUE(BSL_ERR_PeekError() == BSL_SUCCESS);
    ASSERT_TRUE(BSL_ERR_PeekLastError() == BSL_SUCCESS);

EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_GET_LIB_FUNC_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);

    // Test BSL_ERR_GET_LIB with BSL_SUCCESS (should return 0)
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_SUCCESS) == 0);

    // Test BSL_ERR_GET_LIB with BSL module errors
    // BSL module errors have library ID BSL_ERR_LIB_BSL (3)
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_NULL_INPUT) == BSL_ERR_LIB_BSL);
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_MALLOC_FAIL) == BSL_ERR_LIB_BSL);
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_INVALID_ARG) == BSL_ERR_LIB_BSL);

    // Test with UIO errors (also BSL module)
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_UIO_FAIL) == BSL_ERR_LIB_BSL);
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_UIO_IO_BUSY) == BSL_ERR_LIB_BSL);
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_UIO_IO_EXCEPTION) == BSL_ERR_LIB_BSL);

    // Push errors and test BSL_ERR_GET_LIB with peek operations
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_MALLOC_FAIL, __FILENAME__, __LINE__);

    int32_t error = BSL_ERR_PeekError();
    ASSERT_TRUE(BSL_ERR_GET_LIB(error) == BSL_ERR_LIB_BSL);

    error = BSL_ERR_PeekLastError();
    ASSERT_TRUE(BSL_ERR_GET_LIB(error) == BSL_ERR_LIB_BSL);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_PEEK_COMBINED_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);

    // Push a sequence of different errors
    BSL_ERR_PushError(BSL_NULL_INPUT, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_MALLOC_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_UIO_IO_EXCEPTION, __FILENAME__, __LINE__);

    // Test peek operations and library identification
    int32_t firstError = BSL_ERR_PeekError();
    int32_t lastError = BSL_ERR_PeekLastError();

    ASSERT_TRUE(firstError == BSL_NULL_INPUT);
    ASSERT_TRUE(lastError == BSL_UIO_IO_EXCEPTION);

    // Verify library identification for peeked errors
    ASSERT_TRUE(BSL_ERR_GET_LIB(firstError) == BSL_ERR_LIB_BSL);
    ASSERT_TRUE(BSL_ERR_GET_LIB(lastError) == BSL_ERR_LIB_BSL);

    // Multiple peek operations should return the same results
    for (int i = 0; i < 3; i++) {
        ASSERT_TRUE(BSL_ERR_PeekError() == BSL_NULL_INPUT);
        ASSERT_TRUE(BSL_ERR_PeekLastError() == BSL_UIO_IO_EXCEPTION);
    }

    // Verify the complete error stack is still intact
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_MALLOC_FAIL);
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_UIO_FAIL);
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_UIO_IO_EXCEPTION);
    ASSERT_TRUE(BSL_ERR_GetError() == BSL_SUCCESS);

    // Test edge case: single error
    BSL_ERR_PushError(BSL_INVALID_ARG, __FILENAME__, __LINE__);
    
    int32_t singleError = BSL_ERR_PeekError();
    int32_t singleLastError = BSL_ERR_PeekLastError();
    
    // For single error, both should return the same value
    ASSERT_TRUE(singleError == BSL_INVALID_ARG);
    ASSERT_TRUE(singleLastError == BSL_INVALID_ARG);
    ASSERT_TRUE(singleError == singleLastError);
    
    // Verify library identification
    ASSERT_TRUE(BSL_ERR_GET_LIB(singleError) == BSL_ERR_LIB_BSL);

EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_GET_ERR_ALL_FUNC_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_RemoveErrStringBatch();

    // Register error descriptions
    const char *uioFailDesc = "UIO operation failed";
    const char *mallocFailDesc = "Memory allocation failed";
    const char *invalidArgDesc = "Invalid argument provided";
    const BSL_ERR_Desc descList[] = {
        {BSL_UIO_FAIL, uioFailDesc},
        {BSL_MALLOC_FAIL, mallocFailDesc},
        {BSL_INVALID_ARG, invalidArgDesc},
    };
    ASSERT_TRUE(BSL_ERR_AddErrStringBatch(descList, 3) == BSL_SUCCESS);

    const char *file = NULL;
    uint32_t lineNo = 0;
    const char *desc = NULL;

    // Test BSL_ERR_GetErrAll on empty stack
    int32_t error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_SUCCESS);

    // Push single error and test BSL_ERR_GetErrAll
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    uint32_t expectedLine = __LINE__ - 1;
    
    file = NULL;
    lineNo = 0;
    desc = NULL;
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_UIO_FAIL);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);
    ASSERT_TRUE(lineNo == expectedLine);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, uioFailDesc) == 0);

    // Verify error was removed from stack
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_SUCCESS);

    // Push multiple errors and test BSL_ERR_GetErrAll multiple times
    BSL_ERR_PushError(BSL_MALLOC_FAIL, __FILENAME__, __LINE__);
    uint32_t line1 = __LINE__ - 1;
    BSL_ERR_PushError(BSL_INVALID_ARG, __FILENAME__, __LINE__);
    uint32_t line2 = __LINE__ - 1;
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    uint32_t line3 = __LINE__ - 1;

    // First call should return the first error (MALLOC_FAIL)
    file = NULL;
    lineNo = 0;
    desc = NULL;
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_MALLOC_FAIL);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);
    ASSERT_TRUE(lineNo == line1);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, mallocFailDesc) == 0);

    // Second call should return the second error (INVALID_ARG)
    file = NULL;
    lineNo = 0;
    desc = NULL;
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_INVALID_ARG);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);
    ASSERT_TRUE(lineNo == line2);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, invalidArgDesc) == 0);

    // Third call should return the third error (UIO_FAIL)
    file = NULL;
    lineNo = 0;
    desc = NULL;
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_UIO_FAIL);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);
    ASSERT_TRUE(lineNo == line3);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, uioFailDesc) == 0);

    // Fourth call should return success (empty stack)
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_SUCCESS);

    // Test BSL_ERR_GetErrAll with NULL parameters
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    
    // Test with NULL file parameter
    lineNo = 0;
    desc = NULL;
    error = BSL_ERR_GetErrAll(NULL, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_UIO_FAIL);
    ASSERT_EQ(lineNo, 0);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, uioFailDesc) == 0);

    BSL_ERR_PushError(BSL_MALLOC_FAIL, __FILENAME__, __LINE__);
    
    // Test with NULL lineNo parameter
    file = NULL;
    desc = NULL;
    error = BSL_ERR_GetErrAll(&file, NULL, &desc);
    ASSERT_TRUE(error == BSL_MALLOC_FAIL);
    ASSERT_TRUE(file == NULL);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, mallocFailDesc) == 0);

    BSL_ERR_PushError(BSL_INVALID_ARG, __FILENAME__, __LINE__);
    uint32_t line4 = __LINE__ - 1;
    // Test with NULL desc parameter
    file = NULL;
    lineNo = 0;
    error = BSL_ERR_GetErrAll(&file, &lineNo, NULL);
    ASSERT_TRUE(error == BSL_INVALID_ARG);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);
    ASSERT_TRUE(lineNo == line4);

    // Test BSL_ERR_GetErrAll with errors that have no description
    BSL_ERR_PushError(BSL_UIO_IO_BUSY, __FILENAME__, __LINE__); // This error has no registered description
    
    file = NULL;
    lineNo = 0;
    desc = NULL;
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_UIO_IO_BUSY);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);
    ASSERT_TRUE(desc == NULL); // No description registered for this error

EXIT:
    BSL_ERR_RemoveErrStringBatch();
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_GET_ERR_ALL_EDGE_TC001(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_RemoveErrStringBatch();

    // Register some error descriptions
    const char *testDesc1 = "Test error 1";
    const char *testDesc2 = "Test error 2";
    const BSL_ERR_Desc descList[] = {
        {BSL_UIO_FAIL, testDesc1},
        {BSL_MALLOC_FAIL, testDesc2},
    };
    ASSERT_TRUE(BSL_ERR_AddErrStringBatch(descList, 2) == BSL_SUCCESS);

    const char *file = NULL;
    uint32_t lineNo = 0;
    const char *desc = NULL;
    int32_t error = 0;

    // Test BSL_ERR_GetErrAll with mixed file and line scenarios
    // Push error with NULL filename
    BSL_ERR_PushError(BSL_UIO_FAIL, NULL, 100);
    
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_UIO_FAIL);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, "NA") == 0); // Should return "NA" for NULL filename
    ASSERT_TRUE(lineNo == 0); // Should return 0 for line when filename is NULL
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, testDesc1) == 0);

    // Push error with valid filename and line 0
    BSL_ERR_PushError(BSL_MALLOC_FAIL, __FILENAME__, 0);
    
    file = NULL;
    lineNo = 0;
    desc = NULL;
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_MALLOC_FAIL);
    ASSERT_TRUE(file != NULL);
    ASSERT_TRUE(strcmp(file, __FILENAME__) == 0);
    ASSERT_TRUE(lineNo == 0);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, testDesc2) == 0);

    // Test BSL_ERR_GetErrAll with all NULL parameters
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    
    error = BSL_ERR_GetErrAll(NULL, NULL, NULL);
    ASSERT_TRUE(error == BSL_UIO_FAIL);

    // Test error stack integrity after partial reads
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_MALLOC_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_INVALID_ARG, __FILENAME__, __LINE__);

    // Read first error
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_UIO_FAIL);

    // Verify remaining errors are still in correct order
    error = BSL_ERR_GetError(); // Should get MALLOC_FAIL
    ASSERT_TRUE(error == BSL_MALLOC_FAIL);
    error = BSL_ERR_GetError(); // Should get INVALID_ARG
    ASSERT_TRUE(error == BSL_INVALID_ARG);
    error = BSL_ERR_GetError(); // Should get BSL_SUCCESS (empty)
    ASSERT_TRUE(error == BSL_SUCCESS);

    // Verify stack is empty
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_SUCCESS);

    // Test interaction with other error functions
    BSL_ERR_PushError(BSL_UIO_FAIL, __FILENAME__, __LINE__);
    BSL_ERR_PushError(BSL_MALLOC_FAIL, __FILENAME__, __LINE__);

    // Use BSL_ERR_GetErrAll to get first error
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_UIO_FAIL);

    // Use BSL_ERR_GetLastError to get remaining error
    error = BSL_ERR_GetLastError();
    ASSERT_TRUE(error == BSL_MALLOC_FAIL);

    // Stack should be empty now
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_TRUE(error == BSL_SUCCESS);

EXIT:
    BSL_ERR_RemoveErrStringBatch();
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
}
/* END_CASE */

/** @
* @test SDV_HITLS_CERT_ENHENCE_027
* @spec -
* @title Verifying the Capability of Obtaining Error Codes
* @precon nan
* @brief
1. Construct an error scenario and use BSL_ERR_PeekLastError to obtain the last error code.
2. Repeatedly invoke the BSL_ERR_PeekLastError interface to obtain the error code.
3. Use BSL_ERR_PeekError to obtain the first error code.
4. Repeatedly invoke the BSL_ERR_PeekError interface to obtain the error code.
5. Invoke the BSL_ERR_GetErrAll interface to obtain the corresponding information.
* @expect
1. Obtained successfully.
2. The obtained value is the same as that obtained for the first time.
3. The acquisition is successful.
4. The obtained value is the same as that obtained for the first time.
5. Obtained successfully.
* @prior Level 2
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_CERT_ENHENCE_027(void)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_RemoveErrStringBatch();

    ASSERT_TRUE(BSL_ERR_PeekLastError() == BSL_SUCCESS);

    BSL_ERR_PushError(BSL_UIO_FAIL, "file1.c", 0);
    BSL_ERR_PushError(BSL_UIO_IO_BUSY, "file2.c", 1);
    BSL_ERR_PushError(BSL_UIO_IO_EXCEPTION, "file3.c", 2);
    
    int32_t lastError = BSL_ERR_PeekLastError();
    ASSERT_TRUE(lastError == BSL_UIO_IO_EXCEPTION);
    lastError = BSL_ERR_PeekLastError();
    ASSERT_TRUE(lastError == BSL_UIO_IO_EXCEPTION);

    int32_t firstError = BSL_ERR_PeekError();
    ASSERT_TRUE(firstError == BSL_UIO_FAIL);
    firstError = BSL_ERR_PeekError();
    ASSERT_TRUE(firstError == BSL_UIO_FAIL);

    const char *uioFailDesc = "UIO operation failed";
    const char *mallocFailDesc = "Memory allocation failed";
    const char *invalidArgDesc = "Invalid argument provided";
    const BSL_ERR_Desc descList[] = {
        {BSL_UIO_FAIL, uioFailDesc},
        {BSL_UIO_IO_BUSY, mallocFailDesc},
        {BSL_INVALID_ARG, invalidArgDesc},
    };
    ASSERT_TRUE(BSL_ERR_AddErrStringBatch(descList, 3) == BSL_SUCCESS);

    const char *file = NULL;
    uint32_t lineNo = 0;
    const char *desc = NULL;
    const char *desc1 = NULL;
    const char *desc2 = NULL;

    int32_t error = BSL_ERR_GetErrAll(&file, &lineNo, &desc);
    ASSERT_EQ(error, BSL_UIO_FAIL);
    ASSERT_EQ(file, "file1.c");
    ASSERT_EQ(lineNo, 0);
    ASSERT_TRUE(desc != NULL);
    ASSERT_TRUE(strcmp(desc, uioFailDesc) == 0);
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc1);
    ASSERT_EQ(error, BSL_UIO_IO_BUSY);
    ASSERT_TRUE(desc1 != NULL);
    ASSERT_EQ(strcmp(desc1, mallocFailDesc), 0);
    error = BSL_ERR_GetErrAll(&file, &lineNo, &desc2);
    ASSERT_EQ(error, BSL_UIO_IO_EXCEPTION);
    ASSERT_TRUE(desc2 == NULL);

EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
}
/* END_CASE */

/** @
* @test SDV_HITLS_CERT_ENHENCE_028
* @spec -
* @title Error code home module verification
* @precon nan
* @brief
1. Set errno to the error codes of the five modules and obtain the corresponding module IDs.
* @expect
1. The value is obtained successfully. The ID is the module value corresponding to the error code.
* @prior Level 2
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_CERT_ENHENCE_028(void)
{
    TestMemInit();

    ASSERT_TRUE(BSL_ERR_GET_LIB(CRYPT_BN_BITS_TOO_MAX) == BSL_ERR_LIB_CRYPTO);
    ASSERT_TRUE(BSL_ERR_GET_LIB(HITLS_CRYPT_ERR_ENCRYPT) == BSL_ERR_LIB_TLS);
    ASSERT_TRUE(BSL_ERR_GET_LIB(BSL_UIO_FAIL) == BSL_ERR_LIB_BSL);
    ASSERT_TRUE(BSL_ERR_GET_LIB(HITLS_X509_ERR_VFY_GET_THISUPDATE_FAIL) == BSL_ERR_LIB_PKI);
    ASSERT_TRUE(BSL_ERR_GET_LIB(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE) == BSL_ERR_LIB_AUTH);
EXIT:
    return;
}
/* END_CASE */

int32_t g_errCode[] = { // Hex
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40};

uint32_t g_errCodeCount = sizeof(g_errCode) / sizeof(int32_t);

static const char *ExtractBaseName(const char *fullpath)
{
    if (fullpath == NULL) {
        return "unknown";
    }

    const char *nameStart = strrchr(fullpath, '/');
    if (nameStart == NULL) {
        nameStart = strrchr(fullpath, '\\');
    }
    
    if (nameStart != NULL) {
        nameStart++;
    } else {
        nameStart = fullpath;
    }
    return nameStart;
}

static void PushErrors(int32_t pushErrNum)
{
    int32_t pushLine = 1000; // Arbitrary line number for testing
    const char *fileBaseName = ExtractBaseName(__FILE__);
    for (int32_t n = 0; n < pushErrNum; n++) {
        BSL_ERR_PushError(g_errCode[n % g_errCodeCount], fileBaseName, pushLine);
    }
}

FILE *g_out = NULL;
int32_t ClearFileContent(char *outFilename)
{
    FILE *fp = fopen(outFilename, "w");
    if (fp == NULL) {
        return -1;
    }
    (void)fclose(fp);
    return BSL_SUCCESS;
}

int32_t AppendToFileInit(char *filename)
{
    if (g_out != NULL) {
        (void)fclose(g_out);
        g_out = NULL;
    }
    int32_t ret = ClearFileContent(filename);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    g_out = fopen(filename, "a");
    if (g_out == NULL) {
        return BSL_MALLOC_FAIL;
    }
    return BSL_SUCCESS;
}

void AppendToFile(uint64_t threadId, const char *file, uint32_t lineNo, int32_t errCode, bool mark)
{
    if (g_out == NULL) {
        return;
    }
    char str[256] = {0};
    int ret = snprintf_s(str, sizeof(str), sizeof(str) - 1,
                         "%" PRIu64 " %s:%-4u 0x%08X  %c\n",
                         threadId, file, lineNo, errCode, mark ? 'M' : ' ');
    if (ret < 0) {
        return;
    }
    size_t realLen = strlen(str);
    if (realLen > 0) {
        fwrite(str, 1, realLen, g_out);
        fflush(g_out);
    }
}

void ReleaseFileWriter(void)
{
    if (g_out != NULL) {
        fflush(g_out);
        (void)fclose(g_out);
        g_out = NULL;
    }
}

int32_t ReadEntireFile(const char *filename, uint8_t *buffer, uint32_t bufferSize, uint32_t *readLen)
{
    if (filename == NULL || buffer == NULL || readLen == NULL) {
        return BSL_INVALID_ARG;
    }
    
    *readLen = 0;
    
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        return BSL_MALLOC_FAIL;
    }
    
    if (fseek(fp, 0, SEEK_END) != 0) {
        return -1;
    }
    long fileSize = ftell(fp);
    if (fseek(fp, 0, SEEK_SET) != 0) {
        return -1;
    }
    
    if (fileSize < 0) {
        (void)fclose(fp);
        return -1;
    }
    uint32_t sizeToRead = (uint32_t)fileSize;
    if (sizeToRead >= bufferSize) {
        sizeToRead = bufferSize - 1;
    }

    size_t bytesRead = fread(buffer, 1, sizeToRead, fp);
    (void)fclose(fp);
    
    if (bytesRead == 0 && sizeToRead > 0) {
        return -1;
    }
    
    buffer[bytesRead] = '\0';
    *readLen = (uint32_t)bytesRead;
    
    return BSL_SUCCESS;
}

void StdPrintfOutputFunc(uint64_t threadId, const char *file, uint32_t lineNo, int32_t errCode, bool mark)
{
    printf("%" PRIu64 " %s:%-4u 0x%08X  %c\n",
           threadId, file, lineNo, errCode, mark ? 'M' : ' ');
}

/* BEGIN_CASE */
void SDV_BSL_ERR_OUTPUT_TC001(int pushErrNum, char *outFilename, char *inFilename)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetArbitraryId);

    char outFilebuff[256 * 20] = {0};
    char inFilebuff[256 * 20] = {0};

    PushErrors(pushErrNum); // Push errors pushErrNum times
    printf("%s pushErrNum=%d, default output null\n", __FUNCTION__, pushErrNum);
    BSL_ERR_OutputErrorStack(); // test OutputErrorStack when BSL_ERR_RegErrStackLog(NULL) by default

    BSL_ERR_RegErrStackLog(StdPrintfOutputFunc);
    printf("%s pushErrNum=%d, printf\n", __FUNCTION__, pushErrNum);
    BSL_ERR_OutputErrorStack(); // test OutputErrorStack when BSL_ERR_RegErrStackLog(printf)

    ASSERT_EQ(AppendToFileInit(outFilename), BSL_SUCCESS);
    BSL_ERR_RegErrStackLog(AppendToFile);
    BSL_ERR_OutputErrorStack(); // test OutputErrorStack when BSL_ERR_RegErrStackLog(AppendToFile)
    ReleaseFileWriter();

    // compare output file with fixed input file
    uint32_t outFileReadLen = 0;
    ASSERT_EQ(ReadEntireFile(outFilename, (uint8_t *)outFilebuff, sizeof(outFilebuff) - 1, &outFileReadLen),
              BSL_SUCCESS);
    uint32_t inFileLen = 0;
    ASSERT_EQ(ReadEntireFile(inFilename, (uint8_t *)inFilebuff, sizeof(inFilebuff) - 1, &inFileLen), BSL_SUCCESS);
    ASSERT_EQ(outFileReadLen, inFileLen);
    ASSERT_EQ(memcmp(outFilebuff, inFilebuff, outFileReadLen), 0);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_OUTPUT_TC002(int pushErrNum1, int pushErrNum2, char *outFilename, char *inFilename)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetArbitraryId);

    char outFilebuff[256 * 20] = {0};
    char inFilebuff[256 * 20] = {0};

    ASSERT_EQ(AppendToFileInit(outFilename), BSL_SUCCESS);
    BSL_ERR_RegErrStackLog(AppendToFile);
    PushErrors(pushErrNum1); // Push errors pushErrNum1 times
    ASSERT_EQ(BSL_ERR_SetMark(), BSL_SUCCESS);
    PushErrors(pushErrNum2); // Push errors pushErrNum2 times
    BSL_ERR_OutputErrorStack(); // test OutputErrorStack after SetMark
    ReleaseFileWriter();

    // compare output file with fixed input file
    uint32_t outFileReadLen = 0;
    ASSERT_EQ(ReadEntireFile(outFilename, (uint8_t *)outFilebuff, sizeof(outFilebuff) - 1, &outFileReadLen),
              BSL_SUCCESS);
    uint32_t inFileLen = 0;
    ASSERT_EQ(ReadEntireFile(inFilename, (uint8_t *)inFilebuff, sizeof(inFilebuff) - 1, &inFileLen), BSL_SUCCESS);
    ASSERT_EQ(outFileReadLen, inFileLen);
    ASSERT_EQ(memcmp(outFilebuff, inFilebuff, outFileReadLen), 0);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_OUTPUT_TC003(int pushErrNum, char *outFilename, char *inFilename)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetArbitraryId);

    char outFilebuff[256 * 20] = {0};
    char inFilebuff[256 * 20] = {0};

    ASSERT_EQ(AppendToFileInit(outFilename), BSL_SUCCESS);
    BSL_ERR_RegErrStackLog(AppendToFile);
    PushErrors(pushErrNum);
    (void)BSL_ERR_GetError();
    (void)BSL_ERR_GetLastError();
    BSL_ERR_OutputErrorStack(); // test OutputErrorStack after popping errors
    ReleaseFileWriter();

    // compare output file with fixed input file
    uint32_t outFileReadLen = 0;
    ASSERT_EQ(ReadEntireFile(outFilename, (uint8_t *)outFilebuff, sizeof(outFilebuff) - 1, &outFileReadLen),
              BSL_SUCCESS);
    uint32_t inFileLen = 0;
    ASSERT_EQ(ReadEntireFile(inFilename, (uint8_t *)inFilebuff, sizeof(inFilebuff) - 1, &inFileLen), BSL_SUCCESS);
    ASSERT_EQ(outFileReadLen, inFileLen);
    ASSERT_EQ(memcmp(outFilebuff, inFilebuff, outFileReadLen), 0);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ERR_OUTPUT_TC004(char *outFilename, char *inFilename)
{
    TestMemInit();
    ASSERT_TRUE(BSL_ERR_Init() == BSL_SUCCESS);
    BSL_ERR_RemoveErrorStack(true);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetId);

    char outFilebuff[256 * 20] = {0};
    char inFilebuff[256 * 20] = {0};

    ASSERT_EQ(AppendToFileInit(outFilename), BSL_SUCCESS);
    BSL_ERR_RegErrStackLog(AppendToFile);
    // test OutputErrorStack when avl tree root node of the error stack not exists
    BSL_ERR_OutputErrorStack();

    PushErrors(1);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetArbitraryId);
    // test when curNode == NULL
    BSL_ERR_OutputErrorStack();

    // test output "NA" filename and 0 line number
    BSL_ERR_PushError(BSL_UIO_FAIL, NULL, 0);
    BSL_ERR_OutputErrorStack(); // test OutputErrorStack after SetMark
    ReleaseFileWriter();

    // compare output file with fixed input file
    uint32_t outFileReadLen = 0;
    ASSERT_EQ(ReadEntireFile(outFilename, (uint8_t *)outFilebuff, sizeof(outFilebuff) - 1, &outFileReadLen),
              BSL_SUCCESS);
    uint32_t inFileLen = 0;
    ASSERT_EQ(ReadEntireFile(inFilename, (uint8_t *)inFilebuff, sizeof(inFilebuff) - 1, &inFileLen), BSL_SUCCESS);
    ASSERT_EQ(outFileReadLen, inFileLen);
    ASSERT_EQ(memcmp(outFilebuff, inFilebuff, outFileReadLen), 0);
EXIT:
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
    return;
}
/* END_CASE */