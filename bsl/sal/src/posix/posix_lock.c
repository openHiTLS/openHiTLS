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

#include <pthread.h>
#include <unistd.h>
#include "hitls_build.h"
#include "bsl_errno.h"
#include "bsl_sal.h"

#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)) && defined(HITLS_BSL_SAL_LOCK)
// Used for DEFAULT lock implementation
typedef struct {
    pthread_rwlock_t rwlock;
} BslOsalRWLock;

int32_t SAL_RwLockNew(BSL_SAL_ThreadLockHandle *lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    BslOsalRWLock *newLock = (BslOsalRWLock *)BSL_SAL_Calloc(1, sizeof(BslOsalRWLock));
    if (newLock == NULL) {
        return BSL_MALLOC_FAIL;
    }

    if (pthread_rwlock_init(&newLock->rwlock, (const pthread_rwlockattr_t *)NULL) != 0) {
        BSL_SAL_FREE(newLock);
        return BSL_SAL_ERR_UNKNOWN;
    }
    *lock = newLock;
    return BSL_SUCCESS;
}

int32_t SAL_RwReadLock(BSL_SAL_ThreadLockHandle rwLock)
{
    BslOsalRWLock *lock = (BslOsalRWLock *)rwLock;
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_rdlock(&lock->rwlock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

int32_t SAL_RwWriteLock(BSL_SAL_ThreadLockHandle rwLock)
{
    BslOsalRWLock *lock = (BslOsalRWLock *)rwLock;
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_wrlock(&lock->rwlock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

int32_t SAL_RwUnlock(BSL_SAL_ThreadLockHandle rwLock)
{
    BslOsalRWLock *lock = (BslOsalRWLock *)rwLock;
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }

    if (pthread_rwlock_unlock(&lock->rwlock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

void SAL_RwLockFree(BSL_SAL_ThreadLockHandle rwLock)
{
    BslOsalRWLock *lock = (BslOsalRWLock *)rwLock;
    if (lock != NULL) {
        (void)pthread_rwlock_destroy(&(lock->rwlock));
        BSL_SAL_FREE(lock);
    }
}
#endif

#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)) && defined(HITLS_BSL_SAL_THREAD)
uint64_t SAL_GetThreadId(void)
{
    // By default, gettid is not used to obtain the global tid corresponding to the thread
    // because other thread functions use the pthread library.
    // Use pthread_self to obtain the PID used by pthread_create in this process.
    // However, the pids of the parent and child processes may be the same.
    return (uint64_t)pthread_self();
}

/**
 * @brief Thread-safe one-time initialization wrapper
 *
 * Directly wraps pthread_once for posix system
 */
int32_t SAL_PthreadRunOnce(BSL_SAL_OnceControl *onceControl, BSL_SAL_ThreadInitRoutine initFunc)
{
    if (onceControl == NULL || initFunc == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }

    if (pthread_once(onceControl, initFunc) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }

    return BSL_SUCCESS;
}

int32_t BSL_SAL_ThreadCreate(BSL_SAL_ThreadId *thread, void *(*startFunc)(void *), void *arg)
{
    if (thread == NULL || startFunc == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    int32_t ret = pthread_create((pthread_t *)thread, NULL, startFunc, arg);
    if (ret != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

void BSL_SAL_ThreadClose(BSL_SAL_ThreadId thread)
{
    if (thread == NULL) {
        return;
    }
    (void)pthread_join((pthread_t)(uintptr_t)thread, NULL);
}

int32_t BSL_SAL_CreateCondVar(BSL_SAL_CondVar *condVar)
{
    if (condVar == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    pthread_cond_t *cond = (pthread_cond_t *)BSL_SAL_Malloc(sizeof(pthread_cond_t));
    if (cond == NULL) {
        return BSL_MALLOC_FAIL;
    }
    if (pthread_cond_init(cond, NULL) != 0) {
        BSL_SAL_FREE(cond);
        return BSL_SAL_ERR_UNKNOWN;
    }
    *condVar = cond;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_CondSignal(BSL_SAL_CondVar condVar)
{
    if (condVar == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_cond_signal(condVar) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

#define SAL_SECS_IN_NS 1000000000  // 1s = 1000000000ns
#define SAL_SECS_IN_MS 1000        // 1s = 1000ms
#define SAL_MS_IN_NS 1000000       // 1ms = 1000000ns

int32_t BSL_SAL_CondTimedwaitMs(BSL_SAL_Mutex condMutex, BSL_SAL_CondVar condVar, int32_t timeout)
{
    struct timespec stm = {0};
    struct timespec etm = {0};
    long int endNs;  // nanosecond
    long int endSecs;  // second
    if (condMutex == NULL || condVar == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    pthread_mutex_lock(condMutex);

    clock_gettime(CLOCK_REALTIME, &stm);
    endSecs = stm.tv_sec + timeout / SAL_SECS_IN_MS;
    endNs = stm.tv_nsec + (timeout % SAL_SECS_IN_MS) * SAL_MS_IN_NS;
    endSecs += endNs / SAL_SECS_IN_NS;
    endNs %= SAL_SECS_IN_NS;
    etm.tv_sec = endSecs;
    etm.tv_nsec = endNs;

    int32_t ret = pthread_cond_timedwait(condVar, condMutex, &etm);
    pthread_mutex_unlock(condMutex);
    if (ret != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

int32_t BSL_SAL_DeleteCondVar(BSL_SAL_CondVar condVar)
{
    if (condVar == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    int32_t ret = pthread_cond_destroy((pthread_cond_t *)condVar);
    BSL_SAL_FREE(condVar);
    if (ret != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}
#endif

#if defined(HITLS_BSL_SAL_LINUX) && defined(HITLS_BSL_SAL_PID)
int32_t SAL_GetPid(void)
{
    return (int32_t)getpid();
}
#endif
