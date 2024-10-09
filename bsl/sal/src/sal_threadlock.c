/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stddef.h>
#include <pthread.h>

#include "hitls_build.h"

#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_errno.h"
#include "sal_lockimpl.h"
#include "bsl_sal.h"

static BSL_SAL_ThreadCallback g_threadCallback = {0};

int32_t BSL_SAL_ThreadLockNew(BSL_SAL_ThreadLockHandle *lock)
{
    if ((g_threadCallback.pfThreadLockNew != NULL) && (g_threadCallback.pfThreadLockNew != BSL_SAL_ThreadLockNew)) {
        return g_threadCallback.pfThreadLockNew(lock);
    }
#ifdef HITLS_BSL_SAL_LOCK
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
#ifdef HITLS_BSL_SAL_LOCK
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
#ifdef HITLS_BSL_SAL_LOCK
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
#ifdef HITLS_BSL_SAL_LOCK
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
#ifdef HITLS_BSL_SAL_LOCK
    SAL_RwLockFree(lock);
#endif
}

uint64_t BSL_SAL_ThreadGetId(void)
{
    if ((g_threadCallback.pfThreadGetId != NULL) && (g_threadCallback.pfThreadGetId != BSL_SAL_ThreadGetId)) {
        return g_threadCallback.pfThreadGetId();
    }
#ifdef HITLS_BSL_SAL_THREAD
    return SAL_GetPid();
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadRunOnce(uint32_t *onceControl, BSL_SAL_ThreadInitRoutine initFunc)
{
    if (onceControl == NULL || initFunc == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
#ifdef HITLS_BSL_SAL_THREAD
    return SAL_PthreadRunOnce(onceControl, initFunc);
#else
    if (*onceControl == 1) {
        return BSL_SUCCESS;
    }
    initFunc();
    *onceControl = 1;
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_RegThreadCallback(BSL_SAL_ThreadCallback *cb)
{
    if ((cb == NULL) || (cb->pfThreadLockNew == NULL) || (cb->pfThreadLockFree == NULL) ||
        (cb->pfThreadReadLock == NULL) || (cb->pfThreadWriteLock == NULL) ||
        (cb->pfThreadUnlock == NULL) || (cb->pfThreadGetId == NULL)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05012, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid params", 0, 0, 0, 0);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    g_threadCallback.pfThreadLockNew = cb->pfThreadLockNew;
    g_threadCallback.pfThreadLockFree = cb->pfThreadLockFree;
    g_threadCallback.pfThreadReadLock = cb->pfThreadReadLock;
    g_threadCallback.pfThreadWriteLock = cb->pfThreadWriteLock;
    g_threadCallback.pfThreadUnlock = cb->pfThreadUnlock;
    g_threadCallback.pfThreadGetId = cb->pfThreadGetId;
    return BSL_SUCCESS;
}
