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

#ifndef SAL_LOCKIMPL_H
#define SAL_LOCKIMPL_H

#include <stdint.h>
#include "hitls_build.h"
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct ThreadCallback {
    /**
     * @ingroup bsl_sal
     * @brief Create a thread lock.
     *
     * Create a thread lock.
     *
     * @param lock [IN/OUT] Lock handle
     * @retval #BSL_SUCCESS, created successfully.
     * @retval #BSL_MALLOC_FAIL, memory space is insufficient and thread lock space cannot be applied for.
     * @retval #BSL_SAL_ERR_UNKNOWN, thread lock initialization failed.
     * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
     */
    int32_t (*pfThreadLockNew)(BSL_SAL_ThreadLockHandle *lock);

    /**
     * @ingroup bsl_sal
     * @brief Release the thread lock.
     *
     * Release the thread lock. Ensure that the lock can be released when other threads obtain the lock.
     *
     * @param lock [IN] Lock handle
     */
    void (*pfThreadLockFree)(BSL_SAL_ThreadLockHandle lock);

    /**
     * @ingroup bsl_sal
     * @brief Lock the read operation.
     *
     * Lock the read operation.
     *
     * @param lock [IN] Lock handle
     * @retval #BSL_SUCCESS, succeeded.
     * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
     * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
     */
    int32_t (*pfThreadReadLock)(BSL_SAL_ThreadLockHandle lock);

    /**
     * @ingroup bsl_sal
     * @brief Lock the write operation.
     *
     * Lock the write operation.
     *
     * @param lock [IN] Lock handle
     * @retval #BSL_SUCCESS, succeeded.
     * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
     * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
     */
    int32_t (*pfThreadWriteLock)(BSL_SAL_ThreadLockHandle lock);

    /**
     * @ingroup bsl_sal
     * @brief Unlock
     *
     * Unlock
     *
     * @param lock [IN] Lock handle
     * @retval #BSL_SUCCESS, succeeded.
     * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
     * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
     */
    int32_t (*pfThreadUnlock)(BSL_SAL_ThreadLockHandle lock);

    /**
     * @ingroup bsl_sal
     * @brief Obtain the thread ID.
     *
     * Obtain the thread ID.
     *
     * @retval Thread ID
     */
    uint64_t (*pfThreadGetId)(void);
} BSL_SAL_ThreadCallback;

typedef struct {
    BslThreadRunOnce pfThreadRunOnce;
    BslThreadCreate pfThreadCreate;
    BslThreadClose pfThreadClose;
    BslCreateCondVar pfCreateCondVar;
    BslCondSignal pfCondSignal;
    BslCondTimedwaitMs pfCondTimedwaitMs;
    BslDeleteCondVar pfDeleteCondVar;
} BSL_SAL_ThreadCondCallback;

typedef struct PiDCallback {
    /**
     * @ingroup bsl_sal
     * @brief Obtain the process ID.
     *
     * Obtain the process ID.
     *
     * @retval Process ID
     */
    int32_t (*pfGetId)(void);
} BSL_SAL_PiDCallback;

#ifdef HITLS_BSL_SAL_PID
int32_t SAL_PiDCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);
#endif

#if defined(HITLS_BSL_SAL_LOCK) || defined(HITLS_BSL_SAL_THREAD)

#ifdef HITLS_BSL_SAL_LOCK
int32_t SAL_RwLockNew(BSL_SAL_ThreadLockHandle *lock);

int32_t SAL_RwReadLock(BSL_SAL_ThreadLockHandle rwLock);

int32_t SAL_RwWriteLock(BSL_SAL_ThreadLockHandle rwLock);

int32_t SAL_RwUnlock(BSL_SAL_ThreadLockHandle rwLock);

void SAL_RwLockFree(BSL_SAL_ThreadLockHandle rwLock);
#endif

#ifdef HITLS_BSL_SAL_PID
int32_t SAL_GetPid(void);
#endif

#ifdef HITLS_BSL_SAL_THREAD
uint64_t SAL_GetThreadId(void);

int32_t SAL_PthreadRunOnce(uint32_t *onceControl, BSL_SAL_ThreadInitRoutine initFunc);

int32_t SAL_ThreadCreate(BSL_SAL_ThreadId *thread, void *(*startFunc)(void *), void *arg);

void SAL_ThreadClose(BSL_SAL_ThreadId thread);

int32_t SAL_CreateCondVar(BSL_SAL_CondVar *condVar);

int32_t SAL_CondSignal(BSL_SAL_CondVar condVar);

int32_t SAL_CondTimedwaitMs(BSL_SAL_Mutex condMutex, BSL_SAL_CondVar condVar, int32_t timeout);

int32_t SAL_DeleteCondVar(BSL_SAL_CondVar condVar);

#endif

#endif /* #if defined(HITLS_BSL_SAL_LOCK) || defined(HITLS_BSL_SAL_THREAD) */

int32_t SAL_ThreadCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // SAL_LOCKIMPL_H
