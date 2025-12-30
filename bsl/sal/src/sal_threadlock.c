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

#include <stddef.h>
#include "hitls_build.h"

#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_errno.h"
#include "sal_lockimpl.h"
#include "bsl_sal.h"

// OnceControl status values for non-threaded fallback implementation
typedef enum {
    ONCE_STATUS_NOT_INITIALIZED = 0,  // Not initialized yet
    ONCE_STATUS_INITIALIZING    = 1,  // Currently initializing
    ONCE_STATUS_DONE            = 2   // Initialization complete
} OnceStatus;

static BSL_SAL_ThreadCallback g_threadCallback = {NULL, NULL, NULL, NULL, NULL, NULL};
static BSL_SAL_ThreadCondCallback g_threadCondCallback = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
#ifdef HITLS_BSL_SAL_PID
static BSL_SAL_PidCallback g_pidCallback = {0};
#endif

int32_t BSL_SAL_ThreadLockNew(BSL_SAL_ThreadLockHandle *lock)
{
    if ((g_threadCallback.pfThreadLockNew != NULL) && (g_threadCallback.pfThreadLockNew != BSL_SAL_ThreadLockNew)) {
        return g_threadCallback.pfThreadLockNew(lock);
    }
#if defined(HITLS_BSL_SAL_LOCK) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_RwLockNew(lock);
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadReadLock(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadReadLock != NULL) && (g_threadCallback.pfThreadReadLock != BSL_SAL_ThreadReadLock)) {
        return g_threadCallback.pfThreadReadLock(lock);
    }
#if defined(HITLS_BSL_SAL_LOCK) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_RwReadLock(lock);
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadWriteLock(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadWriteLock != NULL) &&
        (g_threadCallback.pfThreadWriteLock != BSL_SAL_ThreadWriteLock)) {
        return g_threadCallback.pfThreadWriteLock(lock);
    }
#if defined(HITLS_BSL_SAL_LOCK) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_RwWriteLock(lock);
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadUnlock(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadUnlock != NULL) && (g_threadCallback.pfThreadUnlock != BSL_SAL_ThreadUnlock)) {
        return g_threadCallback.pfThreadUnlock(lock);
    }
#if defined(HITLS_BSL_SAL_LOCK) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_RwUnlock(lock);
#else
    return BSL_SUCCESS;
#endif
}

void BSL_SAL_ThreadLockFree(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadLockFree != NULL) && (g_threadCallback.pfThreadLockFree != BSL_SAL_ThreadLockFree)) {
        g_threadCallback.pfThreadLockFree(lock);
        return;
    }
#if defined(HITLS_BSL_SAL_LOCK) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    SAL_RwLockFree(lock);
#endif
}

uint64_t BSL_SAL_ThreadGetId(void)
{
    if ((g_threadCallback.pfThreadGetId != NULL) && (g_threadCallback.pfThreadGetId != BSL_SAL_ThreadGetId)) {
        return g_threadCallback.pfThreadGetId();
    }
#if defined(HITLS_BSL_SAL_THREAD) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_GetThreadId();
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadRunOnce(BSL_SAL_OnceControl *onceControl, BSL_SAL_ThreadInitRoutine initFunc)
{
    if ((g_threadCondCallback.pfThreadRunOnce != NULL) &&
        (g_threadCondCallback.pfThreadRunOnce != BSL_SAL_ThreadRunOnce)) {
        return g_threadCondCallback.pfThreadRunOnce(onceControl, initFunc);
    }
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    return SAL_PthreadRunOnce(onceControl, initFunc);
#else
    // Fallback for no threading support
    if (onceControl->status == ONCE_STATUS_DONE) {
        return BSL_SUCCESS;  // Already initialized before
    }
    if (onceControl->status == ONCE_STATUS_NOT_INITIALIZED) {
        onceControl->status = ONCE_STATUS_INITIALIZING;
        initFunc();
        onceControl->status = ONCE_STATUS_DONE;
    }
    return BSL_SUCCESS;
#endif
}

#ifdef HITLS_BSL_SAL_THREAD
int32_t BSL_SAL_ThreadCreate(BSL_SAL_ThreadId *thread, void *(*startFunc)(void *), void *arg)
{
    if ((g_threadCondCallback.pfThreadCreate != NULL) &&
        (g_threadCondCallback.pfThreadCreate != BSL_SAL_ThreadCreate)) {
        return g_threadCondCallback.pfThreadCreate(thread, startFunc, arg);
    }
#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_ThreadCreate(thread, startFunc, arg);
#else
    return BSL_SAL_THREAD_LOCK_NO_REG_FUNC;
#endif
}

void BSL_SAL_ThreadClose(BSL_SAL_ThreadId thread)
{
    if ((g_threadCondCallback.pfThreadClose != NULL) && (g_threadCondCallback.pfThreadClose != BSL_SAL_ThreadClose)) {
        g_threadCondCallback.pfThreadClose(thread);
    }

#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    SAL_ThreadClose(thread);
#endif
}

int32_t BSL_SAL_CreateCondVar(BSL_SAL_CondVar *condVar)
{
    if ((g_threadCondCallback.pfCreateCondVar != NULL) &&
        (g_threadCondCallback.pfCreateCondVar != BSL_SAL_CreateCondVar)) {
        return g_threadCondCallback.pfCreateCondVar(condVar);
    }

#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_CreateCondVar(condVar);
#else
    return BSL_SAL_THREAD_LOCK_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_CondSignal(BSL_SAL_CondVar condVar)
{
    if ((g_threadCondCallback.pfCondSignal != NULL) && (g_threadCondCallback.pfCondSignal != BSL_SAL_CondSignal)) {
        return g_threadCondCallback.pfCondSignal(condVar);
    }

#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_CondSignal(condVar);
#else
    return BSL_SAL_THREAD_LOCK_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_CondTimedwaitMs(BSL_SAL_Mutex condMutex, BSL_SAL_CondVar condVar, int32_t timeout)
{
    if ((g_threadCondCallback.pfCondTimedwaitMs != NULL) && (g_threadCondCallback.pfCondTimedwaitMs !=
        BSL_SAL_CondTimedwaitMs)) {
        return g_threadCondCallback.pfCondTimedwaitMs(condMutex, condVar, timeout);
    }

#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_CondTimedwaitMs(condMutex, condVar, timeout);
#else
    return BSL_SAL_THREAD_LOCK_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_DeleteCondVar(BSL_SAL_CondVar condVar)
{
    if ((g_threadCondCallback.pfDeleteCondVar != NULL) &&
        (g_threadCondCallback.pfDeleteCondVar != BSL_SAL_DeleteCondVar)) {
        return g_threadCondCallback.pfDeleteCondVar(condVar);
    }

#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_DeleteCondVar(condVar);
#else
    return BSL_SAL_THREAD_LOCK_NO_REG_FUNC;
#endif
}
#endif

int32_t SAL_ThreadCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    uint32_t offset = 0;
    if (type >= BSL_SAL_THREAD_LOCK_NEW_CB_FUNC && type <= BSL_SAL_THREAD_GET_ID_CB_FUNC) {
        offset = (uint32_t)(type - BSL_SAL_THREAD_LOCK_NEW_CB_FUNC);
        ((void **)&g_threadCallback)[offset] = funcCb;
        return BSL_SUCCESS;
    }
    if (type >= BSL_SAL_THREAD_RUN_ONCE_CB_FUNC && type <= BSL_SAL_THREAD_CONDVAR_DELETE_CB_FUNC) {
        offset = (uint32_t)(type - BSL_SAL_THREAD_RUN_ONCE_CB_FUNC);
        ((void **)&g_threadCondCallback)[offset] = funcCb;
        return BSL_SUCCESS;
    }
    return BSL_SAL_THREAD_LOCK_NO_REG_FUNC;
}

#ifdef HITLS_BSL_SAL_PID
int32_t SAL_PidCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type != BSL_SAL_PID_GET_ID_CB_FUNC) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    g_pidCallback.pfGetId = (int32_t (*)(void))funcCb;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_GetPid(void)
{
    if ((g_pidCallback.pfGetId != NULL) && (g_pidCallback.pfGetId != BSL_SAL_GetPid)) {
        return g_pidCallback.pfGetId();
    }
#if defined (HITLS_BSL_SAL_PID) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_GetPid();
#else
    return 0;
#endif
}

#endif