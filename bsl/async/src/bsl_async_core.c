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

#include "hitls_build.h"

#ifdef HITLS_BSL_ASYNC

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "bsl_binlog_id.h"
#include "bsl_err_internal.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_async.h"
#include "bsl_async_internal.h"

/* The process lock protects key publication, lookup and retirement. Task and
 * notify objects remain confined to their owning execution domain. */
static BSL_SAL_ThreadLocalKey g_execCtxKey;
static bool g_execCtxKeyCreated = false;
static uint32_t g_liveExecCtxCount = 0;
static BSL_SAL_ThreadLockHandle g_asyncProcLock = NULL;
BSL_SAL_DECLARE_THREAD_ONCE(g_asyncProcOnce);

static void AsyncProcLockInit(void)
{
    if (BSL_SAL_ThreadLockNew(&g_asyncProcLock) != BSL_SUCCESS) {
        g_asyncProcLock = NULL;
    }
}

static int32_t AsyncProcLockReady(void)
{
    int32_t ret = BSL_SAL_ThreadRunOnce(&g_asyncProcOnce, AsyncProcLockInit);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    return g_asyncProcLock == NULL ? BSL_SAL_ERR_NO_MEMORY : BSL_SUCCESS;
}

static int32_t AsyncProcLock(void)
{
    int32_t ret = AsyncProcLockReady();
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    return BSL_SAL_ThreadWriteLock(g_asyncProcLock);
}

static void AsyncProcUnlock(void)
{
    (void)BSL_SAL_ThreadUnlock(g_asyncProcLock);
}

/* Live counter is maintained under the lock; when it drops to zero the key is
 * deleted so the thread local slot is returned. Callers hold
 * the lock. */
static void AsyncProcLiveDown(void)
{
    if (g_liveExecCtxCount > 0) {
        g_liveExecCtxCount--;
    }
    if (g_liveExecCtxCount == 0 && g_execCtxKeyCreated) {
        (void)BSL_SAL_ThreadLocalKeyDelete(g_execCtxKey);
        g_execCtxKeyCreated = false;
    }
}

static BSL_ASYNC_ExecCtx *GetExecCtx(void)
{
    BSL_ASYNC_ExecCtx *ctx = NULL;
    if (AsyncProcLockReady() != BSL_SUCCESS || BSL_SAL_ThreadReadLock(g_asyncProcLock) != BSL_SUCCESS) {
        return NULL;
    }
    if (g_execCtxKeyCreated) {
        ctx = BSL_SAL_ThreadLocalGet(g_execCtxKey);
    }
    AsyncProcUnlock();
    return ctx;
}

static void BSL_ASYNC_TaskEntryLoop(void *arg)
{
    BSL_ASYNC_Task *task = (BSL_ASYNC_Task *)arg;
    BSL_ASYNC_ExecCtx *ctx = task->ownerExecCtx;

    while (true) {
        task->ret = task->entry(task->argsCopy);
        task->state = BSL_ASYNC_TASK_STATE_STOPPING;
        while (BSL_SAL_CoroutineSwitch(task->coroutine, ctx->hostCtx) != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05157, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
                        "task completion switch failed", 0, 0, 0, 0);
            /* Completion must reach the host without re-running the entry. */
        }
        /* Resumed only after this physical task is bound to a new logical
         * task. */
    }
}

static int32_t PoolTaskNew(BSL_ASYNC_ExecCtx *ctx, BSL_ASYNC_Task **out)
{
    BSL_ASYNC_Task *task = BSL_SAL_Calloc(1, sizeof(BSL_ASYNC_Task));
    if (task == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = BSL_SAL_CoroutineCreate(&task->coroutine, ctx->taskStackSize, BSL_ASYNC_TaskEntryLoop, task);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(task);
        return ret;
    }
    task->state = BSL_ASYNC_TASK_STATE_IDLE;
    task->ownerExecCtx = ctx;
    ctx->pool->currTasks++;
    *out = task;
    return BSL_SUCCESS;
}

/* Only handles the physical task; outstanding_count is untouched.
 * Returns BSL_ASYNC_NO_JOB when the pool is full; any other non-success code
 * is the failure already pushed by PoolTaskNew. */
static int32_t PoolTaskAlloc(BSL_ASYNC_ExecCtx *ctx, BSL_ASYNC_Task **out)
{
    BSL_ASYNC_Task *task = ctx->pool->freeList;
    if (task != NULL) {
        ctx->pool->freeList = task->nextFree;
        task->nextFree = NULL;
        *out = task;
        return BSL_SUCCESS;
    }
    /* maxTasks == 0 means no pool limit. */
    if (ctx->pool->maxTasks != 0 && ctx->pool->currTasks >= ctx->pool->maxTasks) {
        return BSL_ASYNC_NO_JOB;
    }
    int32_t ret = PoolTaskNew(ctx, &task);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    *out = task;
    return BSL_SUCCESS;
}

/* Reset to IDLE and push back to the free list; the coroutine survives for
 * the next logical task. */
static void PoolTaskRecycle(BSL_ASYNC_Task *task)
{
    BSL_ASYNC_Pool *pool = task->ownerExecCtx->pool;
    task->state = BSL_ASYNC_TASK_STATE_IDLE;
    task->notifyCtx = NULL;
    task->entry = NULL;
    BSL_SAL_FREE(task->argsCopy);
    task->ret = 0;
    task->nextFree = pool->freeList;
    pool->freeList = task;
    if (pool->outstandingCount > 0) {
        pool->outstandingCount--;
    }
}

/* Destroy one idle task from the free-list head. Idle tasks always carry a
 * NULL argsCopy (PoolTaskRecycle releases it), the free is defensive. */
static void PoolTaskRelease(BSL_ASYNC_ExecCtx *ctx)
{
    BSL_ASYNC_Task *task = ctx->pool->freeList;

    ctx->pool->freeList = task->nextFree;
    BSL_SAL_FREE(task->argsCopy);
    BSL_SAL_CoroutineDestroy(task->coroutine);
    BSL_SAL_FREE(task);
    ctx->pool->currTasks--;
}

/* Resize the physical population to initialTasks. Shrinking releases idle
 * tasks beyond the target: outstanding tasks are never on the free list and
 * the caller's outstanding-count check guarantees enough idle tasks, so a
 * bound task is never destroyed. Growing pre-creates the deficit; on
 * failure only the tasks this call created are destroyed (they sit on the
 * free-list head) and currTasks is restored - the error is the one
 * PoolTaskNew already pushed. */
static int32_t PoolResize(BSL_ASYNC_ExecCtx *ctx, uint32_t initialTasks)
{
    BSL_ASYNC_Task *task = NULL;
    uint32_t added = 0;
    int32_t ret;

    while (ctx->pool->currTasks > initialTasks) {
        PoolTaskRelease(ctx);
    }
    while (ctx->pool->currTasks < initialTasks) {
        ret = PoolTaskNew(ctx, &task);
        if (ret != BSL_SUCCESS) {
            while (added > 0) {
                PoolTaskRelease(ctx);
                added--;
            }
            return ret;
        }
        task->nextFree = ctx->pool->freeList;
        ctx->pool->freeList = task;
        added++;
    }
    return BSL_SUCCESS;
}

/* Destroy the domain's idle tasks (the freeList), the host context, the pool
 * and the context itself. Outstanding tasks are not reclaimed: with the
 * caller of a paused task gone by definition, releasing its live coroutine
 * stack would be premature, so the task is abandoned with a diagnostic and
 * its memory stays allocated .
 * Thread-private: no lock needed for the objects; the live counter is
 * handled by the caller. Returns whether the domain was actually destroyed:
 * on a task stack nothing is released and the domain is kept as is
 * - the running task's stack and the host context are under the
 * caller's feet, and the control flow returns there when the task finishes. */
static bool ExecCtxDestroy(BSL_ASYNC_ExecCtx *ctx)
{
    if (ctx == NULL) {
        return true;
    }
    if (ctx->currentTask != NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05150, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                              "BSL_ASYNC_CleanupThread called on a task stack; cleanup skipped, domain kept", 0, 0, 0,
                              0);
        return false;
    }
    if (ctx->pool != NULL) {
        if (ctx->pool->outstandingCount != 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05151, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                                  "execution domain released with %u outstanding task(s); abandoned, not reclaimed",
                                  ctx->pool->outstandingCount, 0, 0, 0);
        }
        while (ctx->pool->freeList != NULL) {
            PoolTaskRelease(ctx);
        }
        BSL_SAL_FREE(ctx->pool);
    }
    BSL_SAL_CoroutineDestroy(ctx->hostCtx);
    ctx->hostCtx = NULL;
    /* This domain's live reservation prevents key retirement. */
    (void)BSL_SAL_ThreadLocalSet(g_execCtxKey, NULL);
    BSL_SAL_FREE(ctx);
    return true;
}

/* Thread-exit cleanup registered with the thread local key: same semantics
 * as BSL_ASYNC_CleanupThread. */
static void ExecCtxThreadExit(void *arg)
{
    BSL_ASYNC_ExecCtx *ctx = (BSL_ASYNC_ExecCtx *)arg;

    if (ctx == NULL) {
        return;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05154, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                          "thread exit with an active execution domain; cleaning up", 0, 0, 0, 0);
    if (!ExecCtxDestroy(ctx)) {
        /* Thread exiting on a task stack: the domain leaks with a diagnostic;
         * its reservation is not released either, so the key
         * stays valid for the remaining domains. */
        return;
    }
    if (AsyncProcLock() == BSL_SUCCESS) {
        AsyncProcLiveDown();
        AsyncProcUnlock();
    }
}

/* -------------------------------------------------------------------------- */
/* public API: capability and execution domain management */

bool BSL_ASYNC_IsSupported(void)
{
    /* Zero side effects: the build switch is compile-time and the backend
     * probe allocates nothing and switches nothing. */
    return BSL_SAL_CoroutineIsSupported();
}

int32_t BSL_ASYNC_InitThread(uint32_t maxTasks, uint32_t initialTasks, uint32_t stackSize)
{
    BSL_ASYNC_ExecCtx *ctx = NULL;
    int32_t ret;

    /* maxTasks == 0 means no pool limit. */
    if (initialTasks > maxTasks) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    ctx = GetExecCtx();
    if (ctx != NULL) {
        if (ctx->currentTask != NULL) {
            BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_STATE_CONFLICT);
            return BSL_ASYNC_ERR_STATE_CONFLICT;
        }
        /* Re-initialization resizes the pool in place: the execution domain
         * (host context, resolved stack size, thread local slot, live
         * reservation) and every outstanding task survive, so paused handles
         * stay resumable. The pool limit is committed only after the
         * resize succeeded. */
        if ((stackSize == 0 ? BSL_ASYNC_DEFAULT_STACK_SIZE : stackSize) != ctx->taskStackSize) {
            BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_STATE_CONFLICT);
            return BSL_ASYNC_ERR_STATE_CONFLICT;
        }
        if (initialTasks < ctx->pool->outstandingCount) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05153, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                                  "pool scale-down rejected: %u outstanding task(s) exceed the requested %u",
                                  ctx->pool->outstandingCount, initialTasks, 0, 0);
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_INVALID_ARG;
        }
        ret = PoolResize(ctx, initialTasks);
        if (ret != BSL_SUCCESS) {
            /* PoolResize restored the pool and pushed the error. */
            return ret;
        }
        ctx->pool->maxTasks = maxTasks;
        return BSL_SUCCESS;
    }

    /* First initialization on this thread: create the process key once
     * and count the new live domain. */
    ret = AsyncProcLock();
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_NO_MEMORY);
        return BSL_SAL_ERR_NO_MEMORY;
    }
    if (!g_execCtxKeyCreated) {
        ret = BSL_SAL_ThreadLocalKeyCreate(&g_execCtxKey, ExecCtxThreadExit);
        if (ret != BSL_SUCCESS) {
            AsyncProcUnlock();
            return ret;
        }
        g_execCtxKeyCreated = true;
    }
    g_liveExecCtxCount++;
    AsyncProcUnlock();

    ctx = BSL_SAL_Calloc(1, sizeof(BSL_ASYNC_ExecCtx));
    if (ctx == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ctx->pool = BSL_SAL_Calloc(1, sizeof(BSL_ASYNC_Pool));
    if (ctx->pool == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ctx->pool->maxTasks = maxTasks;
    ctx->taskStackSize = (stackSize == 0) ? BSL_ASYNC_DEFAULT_STACK_SIZE : stackSize;
    ret = BSL_SAL_CoroutineInitCurrent(&ctx->hostCtx);
    if (ret != BSL_SUCCESS) {
        goto ERR;
    }
    /* Pre-created tasks are idle only: curr_tasks grows, no outstanding
     * task is produced. */
    ret = PoolResize(ctx, initialTasks);
    if (ret != BSL_SUCCESS) {
        goto ERR;
    }
    ret = BSL_SAL_ThreadLocalSet(g_execCtxKey, ctx);
    if (ret != BSL_SUCCESS) {
        goto ERR;
    }
    return BSL_SUCCESS;

ERR:
    /* First initialization failed: the reservation and the partially built
     * domain are released together. */
    (void) ExecCtxDestroy(ctx);
    if (AsyncProcLock() == BSL_SUCCESS) {
        AsyncProcLiveDown();
        AsyncProcUnlock();
    }
    return ret;
}

void BSL_ASYNC_CleanupThread(void)
{
    ExecCtxThreadExit(GetExecCtx());
}

/* -------------------------------------------------------------------------- */
/* public API: task scheduling */

int32_t BSL_ASYNC_StartTask(BSL_ASYNC_Task **task, int32_t *ret, const BSL_ASYNC_TaskParam *param)
{
    BSL_ASYNC_ExecCtx *ctx = NULL;
    BSL_ASYNC_Task *cur = NULL;
    int32_t retCode;

    if (task == NULL || ret == NULL) {
        /* The caller's handle, when present, stays untouched. */
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_ASYNC_ERR;
    }
    /* Resume input: the owner pointer comparison is the only check for the
     * domain; param is neither read nor validated. */
    if (*task != NULL) {
        ctx = GetExecCtx();
        if (ctx == NULL || (*task)->ownerExecCtx != ctx) {
            return BSL_ASYNC_WRONG_EXEC_CTX;
        }
        cur = *task;
    }
    /* State dispatch loop: every coroutine switch lands here with the task
     * in a transient state it set before switching back; collapse it and
     * deliver the scheduling result, or resume a paused task. PAUSE still
     * escapes to the caller - the loop never waits for the completion event. */
    while (true) {
        if (cur != NULL) {
            switch (cur->state) {
                case BSL_ASYNC_TASK_STATE_STOPPING:
                    /* The entry returned: deliver the result, release the
                     * argument copy and recycle the physical task; the handle
                     * is invalidated. The copy is discarded, not written
                     * back - outputs leave through pointers embedded in the
                     * buffer or through the return value. */
                    ctx->currentTask = NULL;
                    *ret = cur->ret;
                    if (ctx->blockedPauseDepth != 0) {
                        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05152, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                                              "task finished with block-pause depth %u; clearing before recycle",
                                              ctx->blockedPauseDepth, 0, 0, 0);
                        ctx->blockedPauseDepth = 0;
                    }
                    PoolTaskRecycle(cur);
                    *task = NULL;
                    return BSL_ASYNC_FINISH;
                case BSL_ASYNC_TASK_STATE_PAUSING:
                    /* Collapse the transient state; the handle stays with the
                     * caller for a later resume. Nothing is copied
                     * out: the entry keeps running on its own copy after the
                     * resume, the caller's buffer is untouched. */
                    ctx->currentTask = NULL;
                    *task = cur;
                    cur->state = BSL_ASYNC_TASK_STATE_PAUSED;
                    return BSL_ASYNC_PAUSE;
                case BSL_ASYNC_TASK_STATE_PAUSED:
                    if (ctx->currentTask != NULL) {
                        BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_STATE_CONFLICT);
                        return BSL_ASYNC_ERR;
                    }
                    ctx->currentTask = cur;
                    cur->state = BSL_ASYNC_TASK_STATE_RUNNING;
                    retCode = BSL_SAL_CoroutineSwitch(ctx->hostCtx, cur->coroutine);
                    if (retCode != BSL_SUCCESS) {
                        /* Not switched: the handle stays with the caller. */
                        ctx->currentTask = NULL;
                        cur->state = BSL_ASYNC_TASK_STATE_PAUSED;
                        return BSL_ASYNC_ERR;
                    }
                    continue; /* Dispatch on the state set before the switch back. */
                default:
                    /* IDLE or RUNNING: a stale or in-flight handle. */
                    BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_STATE_CONFLICT);
                    return BSL_ASYNC_ERR;
            }
        }

        /* First start. */
        ctx = GetExecCtx();
        if (ctx != NULL && ctx->currentTask != NULL) {
            BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_STATE_CONFLICT);
            return BSL_ASYNC_ERR;
        }
        if (param == NULL || param->func == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
            return BSL_ASYNC_ERR;
        }
        /* Argument contract: a non-NULL buffer must declare its size, a
         * NULL buffer none (the one-way snapshot semantics of the TaskParam,
         * see include/bsl/bsl_async.h). Checked before the allocation: an
         * invalid param creates no task. */
        if ((param->args == NULL && param->argsSize != 0) || (param->args != NULL && param->argsSize == 0)) {
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_ASYNC_ERR;
        }
        /* Capability probe precedes the implicit default initialization: on a
         * no-backend build nothing is created. */
        if (!BSL_ASYNC_IsSupported()) {
            return BSL_ASYNC_UNSUPPORTED;
        }
        if (ctx == NULL) {
            /* Defaults: no pool limit, no pre-created tasks. */
            retCode = BSL_ASYNC_InitThread(0, 0, 0);
            if (retCode != BSL_SUCCESS) {
                /* InitThread already pushed its reason. */
                return BSL_ASYNC_ERR;
            }
            ctx = GetExecCtx();
            if (ctx == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR_NOT_INITIALIZED);
                return BSL_ASYNC_ERR;
            }
        }
        retCode = PoolTaskAlloc(ctx, &cur);
        if (retCode == BSL_ASYNC_NO_JOB) {
            return BSL_ASYNC_NO_JOB;
        }
        if (retCode != BSL_SUCCESS) {
            /* PoolTaskNew already recorded the allocation or backend failure. */
            return BSL_ASYNC_ERR;
        }
        /* Counted from here: the argument-copy failure path below recycles
         * through PoolTaskRecycle, which decrements the counter. */
        ctx->pool->outstandingCount++;
        if (param->argsSize != 0) {
            cur->argsCopy = BSL_SAL_Dump(param->args, param->argsSize);
            if (cur->argsCopy == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                PoolTaskRecycle(cur);
                *task = NULL;
                return BSL_ASYNC_ERR;
            }
        }
        /* Bind the logical task. */
        cur->notifyCtx = param->notifyCtx;
        cur->entry = param->func;
        cur->ret = 0;
        cur->state = BSL_ASYNC_TASK_STATE_RUNNING;
        *task = cur;
        ctx->currentTask = cur;
        retCode = BSL_SAL_CoroutineSwitch(ctx->hostCtx, cur->coroutine);
        if (retCode != BSL_SUCCESS) {
            /* Never entered: collapse safely and report the handle as gone. */
            ctx->currentTask = NULL;
            PoolTaskRecycle(cur);
            *task = NULL;
            return BSL_ASYNC_ERR;
        }
        /* Loop: dispatch on the state the task set before switching back. */
    }
}

BSL_ASYNC_Task *BSL_ASYNC_GetCurrentTask(void)
{
    BSL_ASYNC_ExecCtx *ctx = GetExecCtx();
    return (ctx == NULL) ? NULL : ctx->currentTask;
}

BSL_ASYNC_NotifyCtx *BSL_ASYNC_TaskGetNotifyCtx(const BSL_ASYNC_Task *task)
{
    if (task == NULL) {
        return NULL;
    }
    return task->notifyCtx;
}

/* -------------------------------------------------------------------------- */
/* public API: pause control */

int32_t BSL_ASYNC_PauseTask(void)
{
    BSL_ASYNC_ExecCtx *ctx = GetExecCtx();
    BSL_ASYNC_Task *task = NULL;
    int32_t ret;

    if (ctx == NULL || ctx->currentTask == NULL || ctx->blockedPauseDepth > 0) {
        return BSL_SUCCESS;
    }
    task = ctx->currentTask;
    task->state = BSL_ASYNC_TASK_STATE_PAUSING;
    ret = BSL_SAL_CoroutineSwitch(task->coroutine, ctx->hostCtx);
    if (ret != BSL_SUCCESS) {
        /* Not switched: the current context keeps running. */
        task->state = BSL_ASYNC_TASK_STATE_RUNNING;
        return ret;
    }
    /* Resume point: consume the previous change window before returning to
     * the business chain. */
    if (task->notifyCtx != NULL) {
        BSL_ASYNC_NotifyCtxConsumeChanges(task->notifyCtx);
    }
    return BSL_SUCCESS;
}

void BSL_ASYNC_BlockPause(void)
{
    BSL_ASYNC_ExecCtx *ctx = GetExecCtx();
    if (ctx == NULL || ctx->currentTask == NULL) {
        /* Host side misuse is a no-op, the counter stays. */
        return;
    }
    ctx->blockedPauseDepth++;
}

void BSL_ASYNC_UnblockPause(void)
{
    BSL_ASYNC_ExecCtx *ctx = GetExecCtx();
    if (ctx == NULL || ctx->currentTask == NULL) {
        return;
    }
    if (ctx->blockedPauseDepth > 0) {
        ctx->blockedPauseDepth--;
    }
}

#endif // HITLS_BSL_ASYNC
