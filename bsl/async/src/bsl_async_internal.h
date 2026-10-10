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

#ifndef BSL_ASYNC_INTERNAL_H
#define BSL_ASYNC_INTERNAL_H

#include "hitls_build.h"

#include <stddef.h>
#include <stdint.h>
#include "bsl_async.h"
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
 * Internal objects of the bsl async core (not part of the public contract; the struct members express the logical
 * capabilities, not a frozen layout).
 */

/** Expected task coroutine stack size in bytes, used when BSL_ASYNC_InitThread
 * receives stackSize == 0. The actual size, alignment, guard pages and release
 * remain owned by the SAL coroutine backend. */
#define BSL_ASYNC_DEFAULT_STACK_SIZE (32 * 1024)

/** Task state machine (the only authoritative definition). */
typedef enum {
    BSL_ASYNC_TASK_STATE_IDLE = 0, /**< physical task free in the pool */
    BSL_ASYNC_TASK_STATE_RUNNING, /**< business chain executing or resumed */
    BSL_ASYNC_TASK_STATE_PAUSING, /**< pause decided, switch back in flight */
    BSL_ASYNC_TASK_STATE_PAUSED, /**< parked, caller holds the handle */
    BSL_ASYNC_TASK_STATE_STOPPING, /**< entry returned, delivery in flight */
} BSL_ASYNC_TaskState;

typedef struct BSL_ASYNC_TaskStruct BSL_ASYNC_Task;
typedef struct BSL_ASYNC_ExecCtxStruct BSL_ASYNC_ExecCtx;
typedef struct BSL_ASYNC_PoolStruct BSL_ASYNC_Pool;

/** Per-domain physical task pool. */
struct BSL_ASYNC_PoolStruct {
    uint32_t maxTasks; /**< pool limit from BSL_ASYNC_InitThread */
    uint32_t currTasks; /**< created physical tasks, idle included */
    uint32_t outstandingCount; /**< bound logical tasks, not yet recycled;
                                       the floor a pool resize may not go below */
    BSL_ASYNC_Task *freeList; /**< idle tasks for O(1) allocation, resize-time
                                      release and destroy-time reclamation;
                                      outstanding tasks are not tracked and are
                                      abandoned at destroy */
};

/** Execution domain: one per initialized thread, stored in
 * thread local storage; no state field, currentTask derives the stack. */
struct BSL_ASYNC_ExecCtxStruct {
    BSL_ASYNC_Coroutine *hostCtx; /**< saved host call stack context */
    BSL_ASYNC_Task *currentTask; /**< task holding the execution right */
    uint32_t blockedPauseDepth; /**< pause shielding counter */
    BSL_ASYNC_Pool *pool;
    uint32_t taskStackSize; /**< resolved stack size for this domain */
};

/** Physical task. */
struct BSL_ASYNC_TaskStruct {
    BSL_ASYNC_TaskState state;
    BSL_ASYNC_Func entry;
    void *argsCopy; /**< task-owned snapshot of the caller's argument buffer:
                     * the entry runs on it; one-way, never written back */
    int32_t ret; /**< business return value */
    BSL_ASYNC_NotifyCtx *notifyCtx; /**< borrowed notify context or NULL */
    BSL_ASYNC_Coroutine *coroutine; /**< resumable backend context */
    BSL_ASYNC_ExecCtx *ownerExecCtx; /**< domain allowed to resume this task */
    BSL_ASYNC_Task *nextFree; /**< freeList linkage */
};

/** Notify context (the source registration part lands with M4). */
/** Notify source state machine (the only authoritative definition: a key with no node is the no-entry state, not a state). */
typedef enum {
    BSL_ASYNC_SOURCE_STATE_PENDING_ADD = 0, /**< registered, waiting for the app's waiter */
    BSL_ASYNC_SOURCE_STATE_REGISTERED, /**< visible in the app's waiter */
    BSL_ASYNC_SOURCE_STATE_PENDING_DEL, /**< logically deleted, waiting for reclamation */
} BSL_ASYNC_SourceState;

/** One notify source registration; linkage belongs to the
 * BslList that carries it, the node itself has no next pointer. */
typedef struct BSL_ASYNC_NotifyNodeStruct {
    const void *key; /**< stable caller identity */
    BSL_ASYNC_NotifyHandle handle; /**< opaque platform wait object */
    void *userData; /**< implementation-private data */
    BSL_ASYNC_SourceState state;
    BSL_ASYNC_NotifySourceCleanup cleanup;
} BSL_ASYNC_NotifyNode;

/** Notify context. */
struct BSL_ASYNC_NotifyCtxStruct {
    BSL_ASYNC_NotifyCallback callback;
    void *callbackArg;
    int32_t submitStatus; /**< UNSUPPORTED / ERR / OK / EAGAIN */
    BslList *sourceList; /**< every registration node */
    uint32_t pendingAddCount; /**< current change window: additions */
    uint32_t pendingDelCount; /**< current change window: deletions */
};

/**
 * Resume-point consumption: consume the previous change window
 * and reset the submit status. Contains no fallible step; a NULL ctx is
 * skipped by the caller. Implemented in bsl_async_notify.c.
 */
void BSL_ASYNC_NotifyCtxConsumeChanges(BSL_ASYNC_NotifyCtx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif
