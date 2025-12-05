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

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_atomic.h"

#define TEST_THREAD_DEFAULT_TC001_WRITE_CNT 100000
#define TEST_WRITE_PID_CNT 2
#define TEST_READ_PID_CNT 2

int g_threadDefaultWrite001 = 0;
int g_threadDefaultRead001 = 0;
uint64_t g_threadDefaultId001 = 0;

static void *StdMalloc(uint32_t len)
{
    return malloc((size_t)len);
}

static int32_t pthreadRWLockNew(BSL_SAL_ThreadLockHandle *lock)
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

static void pthreadRWLockFree(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return;
    }
    pthread_rwlock_destroy((pthread_rwlock_t *)lock);
    BSL_SAL_FREE(lock);
}

static int32_t pthreadRWLockReadLock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_rdlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t pthreadRWLockWriteLock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_wrlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t pthreadRWLockUnlock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_unlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static uint64_t pthreadGetId(void)
{
    return (uint64_t)pthread_self();
}

#if defined(HITLS_BSL_SAL_PID) && defined(HITLS_BSL_SAL_LINUX)
static int32_t getProcessId(void)
{
    return (int32_t)getpid();
}
#endif

#ifdef HITLS_BSL_SAL_THREAD
static void *TEST_Read(void *arg)
{
    BSL_SAL_ThreadLockHandle lock = (BSL_SAL_ThreadLockHandle)arg;
    int32_t ret = BSL_SAL_ThreadReadLock(lock);
    g_threadDefaultRead001 = g_threadDefaultWrite001;
    BSL_SAL_ThreadUnlock(lock);
    ASSERT_TRUE(ret == BSL_SUCCESS);
EXIT:
    return NULL;
}

static void *TEST_Write(void *arg)
{
    BSL_SAL_ThreadLockHandle lock = (BSL_SAL_ThreadLockHandle)arg;
    int32_t ret = BSL_SUCCESS;
    for (size_t i = 0; i < TEST_THREAD_DEFAULT_TC001_WRITE_CNT; i++) {
        if (BSL_SAL_ThreadWriteLock(lock) != BSL_SUCCESS) {
            ret = BSL_SAL_ERR_UNKNOWN;
        }
        g_threadDefaultWrite001++;
        g_threadDefaultId001 = BSL_SAL_ThreadGetId();
        BSL_SAL_ThreadUnlock(lock);
    }

    ASSERT_TRUE(ret == BSL_SUCCESS);
EXIT:
    return NULL;
}
#endif

/* END_HEADER */

/**
 * @test SDV_BSL_SAL_REGMEM_API_TC001
 * @title Registering memory-related functions
 * @precon nan
 * @brief
 *    1. Call BSL_SAL_Malloc to allocate 0-byte space. Expected result 1 is obtained.
 *    2. Call BSL_SAL_Malloc to allocate 1-byte space. Expected result 2 is obtained.
 *    3. Call BSL_SAL_Calloc to allocate a large memory space. Expected result 3 is obtained.
 *    4. Call BSL_SAL_CallBack_Ctrl to transfer an exception parameter. Expected result 4 is obtained.
 *    5. Call BSL_SAL_CallBack_Ctrl to transfer an normal parameter. Expected result 5 is obtained.
 *    6. Call BSL_SAL_Malloc to allocate 8-byte space. Expected result 6 is obtained.
 *    7. Call BSL_SAL_FREE to free 8-byte space. Expected result 7 is obtained.
 * @expect
 *    1. Failed to apply for the memory. NULL is returned.
 *    2. Memory application succeeded.
 *    3. Failed to apply for the memory. NULL is returned.
 *    4. Failed to register the callback, return BSL_SAL_ERR_BAD_PARAM
 *    5. Registration callback succeeded, return BSL_SUCCESS.
 *    6. Memory application succeeded.
 *    7. The memory is released successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_REGMEM_API_TC001(void)
{
    void *ptr = NULL;

    ptr = BSL_SAL_Malloc(0);
    ASSERT_TRUE(ptr == NULL);
#ifdef HITLS_BSL_SAL_MEM
    ptr = BSL_SAL_Malloc(1);
    ASSERT_TRUE(ptr != NULL);
    BSL_SAL_FREE(ptr);
#endif

    ptr = BSL_SAL_Calloc(0xFFFFFFFF, 0xFFFFFFFF);
    ASSERT_TRUE(ptr == NULL);

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(0, NULL) == BSL_SAL_ERR_BAD_PARAM);

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL) == BSL_SUCCESS);

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free) == BSL_SUCCESS);

    ptr = BSL_SAL_Malloc(0);
    ASSERT_TRUE(ptr != NULL);

    BSL_SAL_FREE(ptr);
    ASSERT_TRUE(ptr == NULL);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_REG_THREAD_API_TC001
 * @title Register thread-related functions.
 * @precon nan
 * @brief
 *    1. Call BSL_SAL_CallBack_Ctrl to transfer an exception parameter. Expected result 1 is obtained.
 *    2. Call BSL_SAL_CallBack_Ctrl to transfer an normal parameter. Expected result 2 is obtained.
 *    3. Call BSL_SAL_ThreadLockNew to transfer an exception parameter. Expected result 3 is obtained.
 *    4. Call BSL_SAL_ThreadReadLock to transfer an exception parameter. Expected result 4 is obtained.
 *    5. Call BSL_SAL_ThreadWriteLock to transfer an exception parameter. Expected result 5 is obtained.
 *    6. Call BSL_SAL_ThreadUnlock to transfer an exception parameter. Expected result 6 is obtained.
 *    7. Call BSL_SAL_ThreadLockFree to transfer an exception parameter. Expected result 7 is obtained.
 * @expect
 *    1. Failed to register the callback, return BSL_SAL_ERR_BAD_PARAM
 *    2. Registration callback succeeded, return BSL_SUCCESS.
 *    9. Failed to create the new lock, return BSL_SAL_ERR_BAD_PARAM
 *    10. Failed to create the read lock, return BSL_SAL_ERR_BAD_PARAM
 *    11. Failed to create the write lock, return BSL_SAL_ERR_BAD_PARAM
 *    12. Failed to unlock, return BSL_SAL_ERR_BAD_PARAM
 *    13. No return value
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_REG_THREAD_API_TC001(void)
{
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(0, NULL) == BSL_SAL_ERR_BAD_PARAM);

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(0, NULL) == BSL_SAL_ERR_BAD_PARAM);

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_NEW_CB_FUNC, pthreadRWLockNew) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_FREE_CB_FUNC, pthreadRWLockFree) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC, pthreadRWLockReadLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, pthreadRWLockWriteLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC, pthreadRWLockUnlock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, pthreadGetId) == BSL_SUCCESS);

    // Cannot create a lock handle because the pointer of the pointer is NULL.
    ASSERT_TRUE(BSL_SAL_ThreadLockNew(NULL) == BSL_SAL_ERR_BAD_PARAM);
    ASSERT_TRUE(BSL_SAL_ThreadReadLock(NULL) == BSL_SAL_ERR_BAD_PARAM);
    ASSERT_TRUE(BSL_SAL_ThreadWriteLock(NULL) == BSL_SAL_ERR_BAD_PARAM);
    ASSERT_TRUE(BSL_SAL_ThreadUnlock(NULL) == BSL_SAL_ERR_BAD_PARAM);
    BSL_SAL_ThreadLockFree(NULL);
EXIT:
    return;
}
/* END_CASE */

#ifdef HITLS_BSL_SAL_PID
static int32_t MockGetPid(void)
{
    return -1;
}
#endif
/**
 * @test SDV_BSL_SAL_GETPID_FUNC_TC001
 * @title Testing BSL_SAL_GetPid Under Different Configurations
 * @precon nan
 * @brief
 *    1. Call BSL_SAL_CallBack_Ctrl with invalid parameters. Expected result 1 is obtained.
 *    2. Call BSL_SAL_GetPid with default callback configuration. Expected result 2 is obtained.
 *    3. Call BSL_SAL_GetPid after setting default callback function. Expected result 3 is obtained.
 *    4. Call BSL_SAL_GetPid after setting mock callback function. Expected result 4 is obtained.
 * @expect
 *    1. Failed to register callback, returns BSL_SAL_ERR_BAD_PARAM
 *    2. Returns actual process ID on Linux, otherwise returns BSL_SUCCESS
 *    3. Returns actual process ID on Linux, otherwise returns BSL_SUCCESS
 *    4. Returns mock value (-1)
 */
/* BEGIN_CASE */
    void SDV_BSL_SAL_GETPID_FUNC_TC001(void)
{
#ifdef HITLS_BSL_SAL_PID
    int32_t pid;
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(0, NULL) == BSL_SAL_ERR_BAD_PARAM);

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_PID_GET_ID_CB_FUNC, NULL) == BSL_SUCCESS);
    pid = BSL_SAL_GetPid();
#ifdef HITLS_BSL_SAL_LINUX
    ASSERT_EQ(pid, getProcessId());
#else
    ASSERT_EQ(pid, 0);
#endif

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_PID_GET_ID_CB_FUNC, BSL_SAL_GetPid) == BSL_SUCCESS);
    pid = BSL_SAL_GetPid();
#ifdef HITLS_BSL_SAL_LINUX
    ASSERT_EQ(pid, getProcessId());
#else
    ASSERT_EQ(pid, 0);
#endif

    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_PID_GET_ID_CB_FUNC, MockGetPid) == BSL_SUCCESS);
    pid = BSL_SAL_GetPid();
    ASSERT_EQ(pid, -1);
EXIT:
#else
    SKIP_TEST();
#endif
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_MEM_API_TC001
 * @title Test the memory application function when the memory registration callback function is not invoked.
 * @precon nan
 * @brief
 *    1. Call BSL_SAL_Malloc to allocate 100-byte space. Expected result 1 is obtained.
 *    2. Call BSL_SAL_ClearFree to free 100-byte space. Expected result 2 is obtained.
 * @expect
 *    1. Memory application succeeded.
 *    2. The memory is released successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_MEM_API_TC001(void)
{
#ifndef HITLS_BSL_SAL_MEM
    SKIP_TEST();
#else
    // 1
    void *obj = BSL_SAL_Malloc(100);
    ASSERT_TRUE(obj != NULL);

    memset_s(obj, 100, 0x1, 100);

    BSL_SAL_ClearFree(obj, 100);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_MEM_API_TC001
 * @title Test the memory application function when the memory registration callback function is not invoked.
 * @precon nan
 * @brief
 *    1. Call BSL_SAL_Malloc to allocate 1-byte space. Expected result 1 is obtained.
 *    2. Call BSL_SAL_Calloc to allocate 1000-byte space. Expected result 2 is obtained.
 * @expect
 *    1. Memory application succeeded.
 *    2. Memory application succeeded.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_MEM_API_TC002(void)
{
#ifndef HITLS_BSL_SAL_MEM
    SKIP_TEST();
#else
    // 1
    void *obj = BSL_SAL_Malloc(1);
    ASSERT_TRUE(obj != NULL);
    BSL_SAL_FREE(obj);

    uint8_t objZero3[1000] = {0};
    uint8_t *obj3 = (uint8_t *)BSL_SAL_Calloc(1000, sizeof(uint8_t));
    ASSERT_TRUE(obj3 != NULL);
    ASSERT_TRUE(memcmp(objZero3, obj3, 1000) == 0);
    BSL_SAL_FREE(obj3);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_DUMP_API_TC001
 * @title Test the function of the dump interface when the memory-related callback is not registered.
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_Dump with the source memory address set to NULL. Expected result 1 is obtained.
 *    2. Call BSL_SAL_Dump to set the total memory size to 0. Expected result 2 is obtained.
 *    3. Call BSL_SAL_Dump interface to transfer normal parameters. Expected result 3 is obtained.
 * @expect
 *    1. Failed to duplicate the memory space. Return NULL.
 *    2. Failed to duplicate the memory space. Return NULL.
 *    3. Succeeded in duplicate the memory space.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_DUMP_API_TC001(void)
{
#ifndef HITLS_BSL_SAL_MEM
    SKIP_TEST();
#else
    uint32_t memLen = 1024U;
    void *testPtr = NULL;
    void *srcPtr = BSL_SAL_Malloc(memLen);
    ASSERT_TRUE(srcPtr != NULL);

    // 1
    ASSERT_TRUE(BSL_SAL_Dump(NULL, memLen) == NULL);

    // 2
    ASSERT_TRUE(BSL_SAL_Dump(srcPtr, 0) == NULL);

    // 3
    testPtr = BSL_SAL_Dump(srcPtr, memLen);
    ASSERT_TRUE(testPtr != NULL);

    ASSERT_TRUE(memcmp(testPtr, srcPtr, memLen) == 0);
EXIT:
    BSL_SAL_FREE(srcPtr);
    BSL_SAL_FREE(testPtr);
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_REALLOC_API_TC001
 * @title Test functions related to reallocation when the memory-related callback is not registered.
 * @precon  nan
 * @brief
 *    1. The size of the extended memory is smaller than the original size. Expected result 1 is obtained.
 *    2. The size of the extended memory is smaller than the original size. Expected result 2 is obtained.
 * @expect
 *    1. Success. The extended memory address is returned.
 *    2. Success. The extended memory address is returned. No ASAN alarm is generated for realloc memory read/write.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_REALLOC_API_TC001(void)
{
#ifndef HITLS_BSL_SAL_MEM
    SKIP_TEST();
#else
    uint32_t originSize = 2000u;
    uint32_t biggerSize = 3000u;
    uint32_t smallerSize = 1000u;
    void *obj = BSL_SAL_Malloc(originSize);
    ASSERT_TRUE(obj != NULL);

    // 1
    void *obj2 = BSL_SAL_Realloc(obj, smallerSize, originSize);

    // 2
    uint8_t *obj3 = (uint8_t *)BSL_SAL_Realloc(obj2, biggerSize, smallerSize);
    ASSERT_TRUE(obj3 != NULL);
    ASSERT_TRUE(memset_s(obj3, biggerSize, 1, biggerSize) == EOK);
    ASSERT_TRUE(obj3[biggerSize - 1] == 1);

    // The realloc releases the obj. Therefore, the obj does not need to be released.
    // The value of realloc size to 0 is an implementation definition. Therefore, the test is not performed.
EXIT:
    BSL_SAL_FREE(obj3);
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_THREAD_CREATE_FUNC_TC001
 * @title Creating and Closing Threads test
 * @precon  nan
 * @brief
 *    1. Unregistered thread-related callback and create a thread lock. Expected result 1 is obtained.
 *    2. Call BSL_SAL_ThreadCreate to transfer abnormal parameters. Expected result 2 is obtained.
 *    3. Call BSL_SAL_ThreadCreate to transfer normal parameters. Expected result 3 is obtained.
 *    4. Call BSL_SAL_ThreadClose to transfer normal parameters. Expected result 4 is obtained.
 *    5. Call BSL_SAL_ThreadClose to transfer abnormal parameters. Expected result 5 is obtained.
 *    6. Release the lock. Expected result 6 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_SAL_ERR_BAD_PARAM
 *    3. BSL_SUCCESS
 *    4. The thread is closed successfully.
 *    5. No return value
 *    6. Lock released successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_THREAD_CREATE_FUNC_TC001(void)
{
#ifndef HITLS_BSL_SAL_THREAD
    SKIP_TEST();
#else
    BSL_SAL_ThreadLockHandle lock = NULL;
    ASSERT_TRUE(BSL_SAL_ThreadLockNew(&lock) == BSL_SUCCESS);
    BSL_SAL_ThreadId thread = NULL;
    int32_t ret = BSL_SAL_ThreadCreate(&thread, NULL, NULL);
    ASSERT_TRUE(ret == BSL_SAL_ERR_BAD_PARAM);
    ret = BSL_SAL_ThreadCreate(NULL, TEST_Read, NULL);
    ASSERT_TRUE(ret == BSL_SAL_ERR_BAD_PARAM);
    ret = BSL_SAL_ThreadCreate(&thread, TEST_Read, lock);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    BSL_SAL_ThreadClose(thread);
    BSL_SAL_ThreadClose(NULL);
    BSL_SAL_ThreadLockFree(lock);
EXIT:
    return;
#endif
}
/* END_CASE */

static void TestRunOnce(void)
{
    return;
}
/**
 * @test SDV_BSL_SAL_THREAD_API_TC001
 * @title Creating and Disabling Condition Variable Test
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_ThreadRunOnce to transfer abnormal parameters. Expected result 1 is obtained.
 *    2. Call BSL_SAL_ThreadRunOnce to transfer normal parameters. Expected result 2 is obtained.
 * @expect
 *    1. BSL_SAL_ERR_BAD_PARAM
 *    2. BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_THREAD_API_TC001(void)
{
    BSL_SAL_OnceControl isErrInit = BSL_SAL_ONCE_INIT;
    ASSERT_EQ(BSL_SAL_ThreadRunOnce(NULL, TestRunOnce), BSL_SAL_ERR_BAD_PARAM);
    ASSERT_EQ(BSL_SAL_ThreadRunOnce(&isErrInit, NULL), BSL_SAL_ERR_BAD_PARAM);
    ASSERT_EQ(BSL_SAL_ThreadRunOnce(&isErrInit, TestRunOnce), BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_CONDVAR_CREATE_FUNC_TC001
 * @title Creating and Disabling Condition Variable Test
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_CreateCondVar to transfer abnormal parameters. Expected result 1 is obtained.
 *    2. Call BSL_SAL_CreateCondVar to transfer normal parameters. Expected result 2 is obtained.
 *    3. Call BSL_SAL_CondSignal to transfer abnormal parameters. Expected result 3 is obtained.
 *    4. Call BSL_SAL_CondSignal to transfer normal parameters. Expected result 4 is obtained.
 *    5. Call BSL_SAL_DeleteCondVar to transfer abnormal parameters. Expected result 5 is obtained.
 *    6. Call BSL_SAL_DeleteCondVar to transfer normal parameters. Expected result 6 is obtained.
 *    7. Call BSL_SAL_DeleteCondVar to delete the deleted condVar. Expected result 7 is obtained.
 * @expect
 *    1. BSL_SAL_ERR_BAD_PARAM
 *    2. BSL_SUCCESS
 *    3. BSL_SAL_ERR_BAD_PARAM
 *    4. BSL_SUCCESS
 *    5. BSL_SAL_ERR_BAD_PARAM
 *    6. BSL_SUCCESS
 *    7. BSL_SAL_ERR_UNKNOWN
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_CONDVAR_CREATE_FUNC_TC001(void)
{
#ifndef HITLS_BSL_SAL_THREAD
    SKIP_TEST();
#else
    BSL_SAL_CondVar condVar = NULL;
    int32_t ret = BSL_SAL_CreateCondVar(NULL);
    ASSERT_TRUE(ret == BSL_SAL_ERR_BAD_PARAM);
    ret = BSL_SAL_CreateCondVar(&condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ret = BSL_SAL_CondSignal(NULL);
    ASSERT_TRUE(ret == BSL_SAL_ERR_BAD_PARAM);
    ret = BSL_SAL_CondSignal(condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ret = BSL_SAL_DeleteCondVar(NULL);
    ASSERT_TRUE(ret == BSL_SAL_ERR_BAD_PARAM);
    ret = BSL_SAL_DeleteCondVar(condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_CONDVAR_WAIT_API_TC001
 * @title Creating and Disabling Condition Variable Test
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_CreateCondVar to create a condition variable. Expected result 1 is obtained.
 *    2. Unregistered thread-related callback and create a thread lock. Expected result 2 is obtained.
 *    3. Call BSL_SAL_CondTimedwaitMs to transfer abnormal parameters. Expected result 3 is obtained.
 *    4. Call BSL_SAL_CondTimedwaitMs to transfer normal parameters. Expected result 4 is obtained.
 *    5. Release the lock. Expected result 5 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_SUCCESS
 *    3. BSL_SAL_ERR_BAD_PARAM
 *    4. BSL_SUCCESS
 *    5. Lock released successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_CONDVAR_WAIT_API_TC001(void)
{
#ifndef HITLS_BSL_SAL_THREAD
    SKIP_TEST();
#else
    BSL_SAL_ThreadLockHandle lock = NULL;
    ASSERT_TRUE(BSL_SAL_ThreadLockNew(&lock) == BSL_SUCCESS);

    BSL_SAL_CondVar condVar = NULL;
    int32_t ret = BSL_SAL_CreateCondVar(&condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    ret = BSL_SAL_CondTimedwaitMs(NULL, condVar, 10);
    ASSERT_TRUE(ret == BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_CondTimedwaitMs(lock, condVar, 1);
    ASSERT_TRUE(ret == BSL_SAL_ERR_UNKNOWN);
    ret = BSL_SAL_DeleteCondVar(condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    BSL_SAL_ThreadLockFree(lock);
EXIT:
    return;
#endif
}
/* END_CASE */

#ifdef HITLS_BSL_SAL_THREAD
static BSL_SAL_CondVar g_condVar = NULL;
static pthread_mutex_t g_lock;

static void *ThreadTest(void *arg)
{
    (void)arg;
    int32_t ret1 = BSL_SAL_CondTimedwaitMs(&g_lock, g_condVar, 10000000);
    ASSERT_TRUE(ret1 == BSL_SUCCESS);
EXIT:
    return NULL;
}
#endif

/**
 * @test SDV_BSL_SAL_CONDVAR_WAIT_FUNC_TC001
 * @title Creating and Disabling Condition Variable Test
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_CreateCondVar to create a condition variable. Expected result 1 is obtained.
 *    2. Call BSL_SAL_ThreadCreate to create the timedwait thread. Expected result 2 is obtained.
 *    3. Call BSL_SAL_CondSignal to transfer normal parameters. Expected result 3 is obtained.
 *    4. Call BSL_SAL_DeleteCondVar to transfer normal parameters. Expected result 4 is obtained.
 *    5. Release the lock. Expected result 5 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_SUCCESS
 *    3. BSL_SUCCESS
 *    4. BSL_SUCCESS
 *    5. Lock released successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_CONDVAR_WAIT_FUNC_TC001(void)
{
#ifndef HITLS_BSL_SAL_THREAD
    SKIP_TEST();
#else
    int32_t ret = BSL_SAL_CreateCondVar(&g_condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    pthread_mutex_init(&g_lock, NULL);

    BSL_SAL_ThreadId thread = NULL;
    ret = BSL_SAL_ThreadCreate(&thread, ThreadTest, NULL);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    sleep(1); // Wait one seconds to send the signal
    pthread_mutex_lock(&g_lock);
    ret = BSL_SAL_CondSignal(g_condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    pthread_mutex_unlock(&g_lock);

    BSL_SAL_ThreadClose(thread);
    ret = BSL_SAL_DeleteCondVar(g_condVar);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    pthread_mutex_destroy(&g_lock);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_STR_API_TC001
 * @title Test on the function of inputting abnormal parameters for character string processing of the BSL module
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_StrcaseCmp to transfer abnormal parameters. Expected result 1 is obtained.
 *    2. Call BSL_SAL_Memchr to transfer abnormal parameters. Expected result 2 is obtained.
 *    3. Call BSL_SAL_Atoi to transfer abnormal parameters. Expected result 3 is obtained.
 *    4. Call BSL_SAL_Strnlen to transfer abnormal parameters. Expected result 4 is obtained.
 * @expect
 *    1. BSL_NULL_INPUT
 *    2. NULL
 *    3. 0
 *    4. 0
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_STR_API_TC001(void)
{
#ifndef HITLS_BSL_SAL_STR
    SKIP_TEST();
#else
    char *str1 = "aaastr1";
    char *str2 = "aaastr2";
    ASSERT_TRUE(BSL_SAL_StrcaseCmp(str1, NULL) == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_SAL_StrcaseCmp(NULL, str2) == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_SAL_Memchr(NULL, 's', 10) == NULL);
    ASSERT_TRUE(BSL_SAL_Atoi(NULL) == 0);
    ASSERT_TRUE(BSL_SAL_Strnlen(NULL, 0) == 0);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_STR_FUNC_TC001
 * @title Character string processing function of the BSL module
 * @precon  nan
 * @brief
 *    1. Call BSL_SAL_StrcaseCmp to transfer normal parameters. Expected result 1 is obtained.
 *    2. Call BSL_SAL_Memchr to transfer normal parameters. Expected result 2 is obtained.
 *    3. Call BSL_SAL_Atoi to transfer normal parameters. Expected result 3 is obtained.
 *    4. Call BSL_SAL_Strnlen to transfer normal parameters. Expected result 4 is obtained.
 * @expect
 *    1. String comparison succeeded.
 *    2. Searching for the corresponding character succeeded.
 *    3. Succeeded in converting a character string to a number.
 *    4. Obtaining the length of the given string succeeded.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_STR_FUNC_TC001(void)
{
#ifndef HITLS_BSL_SAL_STR
    SKIP_TEST();
#else
    char *str1 = "aaastr1";
    char *str2 = "aaastr2";
    char *str3 = "   aaastr3";
    ASSERT_TRUE(BSL_SAL_StrcaseCmp(str1, str1) == 0);
    ASSERT_TRUE(BSL_SAL_StrcaseCmp(str1, str2) == -1);
    ASSERT_TRUE(BSL_SAL_StrcaseCmp(str2, str1) == 1);

    ASSERT_TRUE(BSL_SAL_Memchr(str1, 's', strlen(str1)) != NULL);
    ASSERT_TRUE(BSL_SAL_Memchr(str1, '1', 5) == NULL);
    ASSERT_TRUE(BSL_SAL_Memchr(str1, '1', strlen(str1)) != NULL);
    ASSERT_TRUE(BSL_SAL_Memchr(str1, 'b', strlen(str1)) == NULL);
    ASSERT_TRUE(BSL_SAL_Memchr(str3, ' ', strlen(str3)) != NULL);

    ASSERT_TRUE(BSL_SAL_Atoi("-100") == -100);
    ASSERT_TRUE(BSL_SAL_Atoi("123") == 123);
    ASSERT_TRUE(BSL_SAL_Atoi("123.456") == 123);
    ASSERT_TRUE(BSL_SAL_Atoi("  123   ") == 123);
    ASSERT_TRUE(BSL_SAL_Atoi("000123") == 123);
    ASSERT_TRUE(BSL_SAL_Atoi(" 1 23") == 1);
    ASSERT_TRUE(BSL_SAL_Atoi("\n1 23") == 1);
    ASSERT_TRUE(BSL_SAL_Atoi("1\n23") == 1);
    ASSERT_TRUE(BSL_SAL_Atoi("0\n23") == 0);

    ASSERT_TRUE(BSL_SAL_Strnlen(str1, strlen(str1)) == 7);
    ASSERT_TRUE(BSL_SAL_Strnlen(str1, 100) == 7);
    ASSERT_TRUE(BSL_SAL_Strnlen(str1, 3) == 3);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_THREAD_DEFAULT_FUNC_TC001
 * @title Default Thread Related Functions
 * @precon  nan
 * @brief
 *    1. Unregistered thread-related callback and create a thread lock. Expected result 1 is obtained.
 *    2. Create two read threads and two write threads, read and write concurrent threads,
 *       and obtain IDs from the threads. Expected result 2 is obtained.
 *    3. Obtain the process ID and compare it with the subthread ID. Expected result 3 is obtained.
 *    4. Obtain the subprocess ID and compare it with the current process ID. Expected result 4 is obtained.
 *    5. Release the lock. Expected result 5 is obtained.
 * @expect
 *    1. Thread lock created successfully.
 *    2. The read thread and write thread are successfully created.
 *    3. The process ID and subthread ID are different.
 *    4. The current subprocess ID is the same as the current process ID.
 *    5. Lock released successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_THREAD_DEFAULT_FUNC_TC001(void)
{
#ifndef HITLS_BSL_SAL_THREAD
    SKIP_TEST();
#else
    g_threadDefaultWrite001 = 0;
    g_threadDefaultRead001 = 0;
    g_threadDefaultId001 = 0;

    // 1
    BSL_SAL_ThreadLockHandle lock = NULL;
    ASSERT_TRUE(BSL_SAL_ThreadLockNew(&lock) == BSL_SUCCESS);

    // 2
    BSL_SAL_ThreadId pid[TEST_WRITE_PID_CNT];
    BSL_SAL_ThreadId pid2[TEST_READ_PID_CNT];
    size_t i = 0;
    size_t m = 0;
    for (i = 0u; i < TEST_WRITE_PID_CNT; i++) {
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&pid[i], TEST_Write, (void *)lock) == BSL_SUCCESS);
    }
    for (m = 0u; m < TEST_READ_PID_CNT; m++) {
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&pid2[m], TEST_Read, (void *)lock) == BSL_SUCCESS);
    }
    for (size_t j = 0; j < i; j++) {
        BSL_SAL_ThreadClose(pid[j]);
    }
    for (size_t n = 0; n < m; n++) {
        BSL_SAL_ThreadClose(pid2[n]);
    }
    ASSERT_EQ(g_threadDefaultWrite001, TEST_READ_PID_CNT * TEST_THREAD_DEFAULT_TC001_WRITE_CNT);
    // Concurrent reads. The read result is uncertain and does not determine whether to perform the read operation.

    // 3
    uint64_t mainId = BSL_SAL_ThreadGetId();
    ASSERT_TRUE(mainId != g_threadDefaultId001);

    // 4
    uint64_t childId = 0;
    pid_t pidFork = fork();
    if (pidFork == 0) {
        // The child process
        childId = BSL_SAL_ThreadGetId();
    } else {
        // The parent process
        goto EXIT;
    }
    // The default implementation uses pthread_self. Therefore, the IDs of the parent and child processes are the same.
    ASSERT_EQ(childId, mainId);
EXIT:
    // 5
    BSL_SAL_ThreadLockFree(lock);
    g_threadDefaultWrite001 = 0;
    g_threadDefaultRead001 = 0;
    g_threadDefaultId001 = 0;
#endif
}
/* END_CASE */

/**
 * @test   SDV_BSL_SAL_CALLBACK_CTRL_FUNC_TC001
 * @title  test BSL_SAL_CallBack_Ctrl functions
 * @precon nan
 * @brief
 *    1.Call BSL_SAL_CallBack_Ctrl registering file Callback Function, Expected result 1 is obtained.
 *    2.Call BSL_SAL_CallBack_Ctrl registering time Callback Function, Expected result 1 is obtained.
 *    3.Call BSL_SAL_CallBack_Ctrl registering net Callback Function, Expected result 1 is obtained.
 *    4.Call BSL_SAL_CallBack_Ctrl registering invalid Callback Function, Expected result 2 is obtained.
 *    5.Call BSL_SAL_SockGetLastSocketError obtaining the last socket error, Expected result 3 is obtained.
 * @expect
 *    1. BSL_SUCCESS
 *    2. BSL_SAL_ERR_NET_IOCTL
 *    3. Succeeded in obtaining the last socket error.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_CALLBACK_CTRL_FUNC_TC001(void)
{
#if defined(HITLS_BSL_SAL_FILE) || defined(HITLS_BSL_SAL_TIME) || defined(HITLS_BSL_SAL_NET)
#ifdef HITLS_BSL_SAL_FILE
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_FILE_OPEN_CB_FUNC, NULL), BSL_SUCCESS);
#endif
#ifdef HITLS_BSL_SAL_TIME
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_TIME_GET_UTC_TIME_CB_FUNC, NULL), BSL_SUCCESS);
#endif
#ifdef HITLS_BSL_SAL_NET
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_NET_WRITE_CB_FUNC, NULL), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_Ioctlsocket(0, 0, NULL), BSL_SAL_ERR_NET_IOCTL);
#endif
EXIT:
    return;
#endif
}
/* END_CASE */
