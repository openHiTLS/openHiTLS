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

/**
 * @defgroup bsl_async
 * @ingroup bsl
 * @brief Generic asynchronous task framework
 */

#ifndef BSL_ASYNC_H
#define BSL_ASYNC_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_async
 * @brief   Asynchronous task handle, opaque to callers
 */
typedef struct BSL_ASYNC_TaskStruct BSL_ASYNC_Task;

/**
 * @ingroup bsl_async
 * @brief   Notify context handle, opaque to callers
 */
typedef struct BSL_ASYNC_NotifyCtxStruct BSL_ASYNC_NotifyCtx;

/**
 * @ingroup bsl_async
 * @brief   Platform wait object value (eventfd, Windows Event, etc.)
 *
 * The value is owned by the crypto implementation; the framework never
 * creates, waits on, signals or closes it.
 */
typedef uintptr_t BSL_ASYNC_NotifyHandle;

/**
 * @ingroup bsl_async
 * @brief   Report whether a resumable execution context backend is available
 *
 * @retval  true   The transparent async path is usable.
 * @retval  false  The backend is absent; BSL_ASYNC_StartTask returns BSL_ASYNC_UNSUPPORTED.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * The probe has no side effect: no resource is allocated and no context is switched.
 */
bool BSL_ASYNC_IsSupported(void);

/**
 * @ingroup bsl_async
 * @brief   Establish the execution domain and the task pool of the current thread
 *
 * @param maxTasks [IN] Task pool limit; 0 means no limit (the pool grows on demand and never reports full).
 * @param initialTasks [IN] Number of tasks to pre-create; 0 pre-creates none; must not exceed maxTasks
 *         (therefore it must also be 0 when maxTasks is 0). On a re-entering call the pool is resized
 *         to this count: idle tasks beyond it are released, and a value below the outstanding
 *         (bound, not yet finished) task count is rejected.
 * @param stackSize [IN] Expected task coroutine stack size in bytes for this execution domain;
 *         0 uses the framework default; a non-zero value is used as given, the framework
 *         sets no lower or upper bound (out-of-range values are rejected by the SAL backend).
 *         Effective only on the first initialization of the thread.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_INVALID_ARG Invalid task counts, a rejected scale-down (initialTasks below the
 *         outstanding task count), or a stack size rejected while pre-creating tasks.
 * @retval #BSL_ASYNC_ERR_STATE_CONFLICT Called on a task stack, no coroutine backend is built,
 *         or a re-entering stackSize resolves to a value different from the domain's.
 * @retval #BSL_MALLOC_FAIL Allocation of the execution domain, pool, task or coroutine wrapper failed.
 * @retval #BSL_SAL_ERR_NO_MEMORY Process lock, thread local storage or platform coroutine creation failed.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Time-consuming (pre-creates coroutines when initialTasks is not 0).
 * Must be called on the host call stack. Calling this function again on a thread that
 * already has an execution domain is legal and resizes the pool in place: the execution
 * domain itself (host context, resolved stack size, thread local reservation) and every
 * outstanding task survive, so paused handles stay resumable across the call. The pool
 * limit is replaced with maxTasks and the task population is adjusted to initialTasks:
 * a scale-down releases the idle tasks beyond the target, while a target below the
 * outstanding task count is rejected with BSL_INVALID_ARG (outstanding tasks are never
 * destroyed here, so a re-entry with initialTasks == 0 requires that no task is
 * outstanding).
 * With initialTasks == 0, stack size validation is deferred until a task is created.
 * Creation failure releases partially built resources and returns the original error
 * without pushing it again; a failed re-entry leaves the previous pool untouched.
 */
int32_t BSL_ASYNC_InitThread(uint32_t maxTasks, uint32_t initialTasks, uint32_t stackSize);

/**
 * @ingroup bsl_async
 * @brief   Release the execution domain of the current thread
 *
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * Must be called on the host call stack. An uninitialized domain is a no-op.
 * Complete outstanding tasks before cleanup. Otherwise they are abandoned with
 * a diagnostic: their coroutine stacks and argument copies remain allocated,
 * and they cannot be resumed. This function has no return value.

 */
void BSL_ASYNC_CleanupThread(void);

/**
 * @ingroup bsl_async
 * @brief   Scheduling result of BSL_ASYNC_StartTask
 *
 * Macro constants with consecutive values starting from 1; 0 is not a legal
 * scheduling result, so a zero-initialized variable is never misread as one.
 */
#define BSL_ASYNC_PAUSE          1
#define BSL_ASYNC_FINISH         2
#define BSL_ASYNC_NO_JOB         3
#define BSL_ASYNC_WRONG_EXEC_CTX 4
#define BSL_ASYNC_UNSUPPORTED    5
#define BSL_ASYNC_ERR            6

/**
 * @ingroup bsl_async
 * @brief   Business entry of a logical task, executed on the task stack
 */
typedef int32_t (*BSL_ASYNC_Func)(void *args);

/**
 * @ingroup bsl_async
 * @brief   Aggregated input of BSL_ASYNC_StartTask for a first start
 */
typedef struct {
    BSL_ASYNC_NotifyCtx *notifyCtx; /**< Notify context of the logical task; NULL when unused. */
    BSL_ASYNC_Func func; /**< Business entry, mandatory on a first start. */
    void *args; /**< Argument buffer; argsSize bytes are copied once into task-owned
                                          storage at the first start and the entry runs on that copy
                                          (one-way snapshot, never written back). Inline (non-pointer)
                                          fields therefore flow caller-to-task only; communicate
                                          results through pointers embedded in the buffer, the task
                                          return value, or shared external state. Indirect references
                                          are copied as pointer values and remain the caller's
                                          responsibility. */
    uint32_t argsSize; /**< Size of the argument buffer in bytes; must be 0 when args is NULL. */
} BSL_ASYNC_TaskParam;

/**
 * @ingroup bsl_async
 * @brief   Start or resume a pausable asynchronous task
 *
 * @param task [IN/OUT] NULL means a first start; non-NULL resumes the paused task.
 * @param ret [OUT] Business return value, defined only when BSL_ASYNC_FINISH is returned.
 * @param param [IN] Aggregated input for a first start; not read and not validated when
 *        resuming (NULL or a reused param are both accepted). On a first start with a
 *        non-NULL args, argsSize must be non-zero: the buffer is copied once before the entry
 *        runs and never written back, so outputs must flow through pointers embedded in the
 *        buffer, the task return value, or shared external state (args NULL with argsSize 0 is
 *        the no-argument form; any other combination is rejected with BSL_INVALID_ARG).
 *
 * @retval #BSL_ASYNC_FINISH The logical task finished, *ret was delivered and *task was reset to NULL.
 * @retval #BSL_ASYNC_PAUSE The task is paused and *task refers to it.
 * @retval #BSL_ASYNC_NO_JOB The pool is full; *task stays NULL.
 * @retval #BSL_ASYNC_WRONG_EXEC_CTX Non-destructive rejection; the task belongs to its owner domain.
 * @retval #BSL_ASYNC_UNSUPPORTED No backend is available; *task stays NULL.
 * @retval #BSL_ASYNC_ERR Failure; the reason is on the BSL error stack.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Depends on the business entry.
 * Must be called on the host call stack of the execution domain owning the task.
 */
int32_t BSL_ASYNC_StartTask(BSL_ASYNC_Task **task, int32_t *ret, const BSL_ASYNC_TaskParam *param);

/**
 * @ingroup bsl_async
 * @brief   Get the currently running task
 *
 * @retval  Non-NULL  The task currently holding the execution right.
 * @retval  NULL      The caller is on the host call stack (or the domain is not initialized).
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
BSL_ASYNC_Task *BSL_ASYNC_GetCurrentTask(void);

/**
 * @ingroup bsl_async
 * @brief   Get the notify context bound to a task
 *
 * @param task [IN] Task handle, usually obtained through BSL_ASYNC_GetCurrentTask.
 *
 * @retval  Non-NULL  Borrowed pointer to the bound notify context.
 * @retval  NULL      The task is NULL or no notify context is bound.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * The returned pointer is borrowed and must not be freed or kept beyond the logical task.
 */
BSL_ASYNC_NotifyCtx *BSL_ASYNC_TaskGetNotifyCtx(const BSL_ASYNC_Task *task);

/**
 * @ingroup bsl_async
 * @brief   Pause the current task and switch back to the host call stack
 *
 * @retval #BSL_SUCCESS The task was paused and later resumed at this call site.
 * @retval #BSL_ASYNC_ERR_NOT_INITIALIZED No execution domain is initialized.
 * @retval #BSL_ASYNC_ERR_STATE_CONFLICT Called on the host call stack.
 * @retval #BSL_ASYNC_ERR_COROUTINE_SWITCH The platform context switch failed.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * Can only be called inside a task; becomes a successful no-op while pause is blocked.
 * A failed switch keeps the current task running, preserves notification changes and
 * submit status, and returns the SAL error without pushing it again.
 */
int32_t BSL_ASYNC_PauseTask(void);

/**
 * @ingroup bsl_async
 * @brief   Forbid pausing the current task (nestable)
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * Must be paired with BSL_ASYNC_UnblockPause inside a task; a call on the
 * host call stack changes nothing.
 */
void BSL_ASYNC_BlockPause(void);

/**
 * @ingroup bsl_async
 * @brief   Undo one level of BSL_ASYNC_BlockPause
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * The depth stays at 0 when it is already 0; a call on the host call stack
 * changes nothing.
 */
void BSL_ASYNC_UnblockPause(void);

/**
 * @ingroup bsl_async
 * @brief   Create a notify context
 *
 * @retval  Non-NULL  The created context.
 * @retval  NULL      Allocation failed.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
BSL_ASYNC_NotifyCtx *BSL_ASYNC_NotifyCtxNew(void);

/**
 * @ingroup bsl_async
 * @brief   Release a notify context
 *
 * @param ctx [IN] Context to release; NULL is a safe no-op.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * The caller must guarantee that no task, crypto implementation or completion
 * callback still uses the context; violation is undefined behavior.
 */
void BSL_ASYNC_NotifyCtxFree(BSL_ASYNC_NotifyCtx *ctx);

/**
 * @ingroup bsl_async
 * @brief   Wakeup callback installed by the application
 *
 * The callback only posts a "resumable" event; it must be short, non-blocking,
 * and must not resume the task by itself.
 */
typedef int32_t (*BSL_ASYNC_NotifyCallback)(void *callbackArg);

/**
 * @ingroup bsl_async
 * @brief   Install the wakeup callback of a notify context
 *
 * @param ctx [IN] Notify context.
 * @param callback [IN] Callback to install; NULL clears it.
 * @param callbackArg [IN] Argument passed through to the callback.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT ctx is NULL.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * The framework does not track outstanding tasks (a notify context can be bound by
 * several tasks), so replacing or clearing the callback while a task may still use
 * it is a caller guarantee, not a framework check.
 */
int32_t BSL_ASYNC_NotifyCtxSetCallback(BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyCallback callback, void *callbackArg);

/**
 * @ingroup bsl_async
 * @brief   Query the wakeup callback of a notify context
 *
 * @param ctx [IN] Notify context.
 * @param callback [OUT] Current callback.
 * @param callbackArg [OUT] Current callback argument.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT A mandatory parameter is NULL.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
int32_t BSL_ASYNC_NotifyCtxGetCallback(const BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyCallback *callback,
                                       void **callbackArg);

/**
 * @ingroup bsl_async
 * @brief   Submit status published by a crypto implementation before pausing
 *
 * Macro constants: 0 means the callback path is not used for the request and
 * is the default value.
 */
#define BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED 0
#define BSL_ASYNC_NOTIFY_STATUS_ERR         1
#define BSL_ASYNC_NOTIFY_STATUS_OK          2
#define BSL_ASYNC_NOTIFY_STATUS_EAGAIN      3

/**
 * @ingroup bsl_async
 * @brief   Publish the submit status of the current request
 *
 * @param ctx [IN] Notify context.
 * @param status [IN] Status to publish; one of the BSL_ASYNC_NOTIFY_STATUS_* values.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT ctx is NULL.
 * @retval #BSL_INVALID_ARG status is not a defined value.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * Called by a crypto implementation on the task stack, after submitting the
 * request and before pausing.
 */
int32_t BSL_ASYNC_NotifyCtxSetStatus(BSL_ASYNC_NotifyCtx *ctx, int32_t status);

/**
 * @ingroup bsl_async
 * @brief   Query the submit status of a notify context
 *
 * @param ctx [IN] Notify context.
 * @param status [OUT] Current status; one of the BSL_ASYNC_NOTIFY_STATUS_* values.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT A mandatory parameter is NULL.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
int32_t BSL_ASYNC_NotifyCtxGetStatus(const BSL_ASYNC_NotifyCtx *ctx, int32_t *status);

/**
 * @ingroup bsl_async
 * @brief   Cleanup callback of a notify source, invoked when the node is reclaimed
 */
typedef void (*BSL_ASYNC_NotifySourceCleanup)(BSL_ASYNC_NotifyCtx *ctx, const void *key, BSL_ASYNC_NotifyHandle handle,
                                              void *userData);

/**
 * @ingroup bsl_async
 * @brief   Register a notify source
 *
 * @param ctx [IN] Notify context.
 * @param key [IN] Stable pointer identifying the source.
 * @param handle [IN] Platform wait object value.
 * @param userData [IN] Private data of the crypto implementation; NULL is allowed.
 * @param cleanup [IN] Cleanup callback invoked when the node is reclaimed; NULL is allowed.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT ctx or key is NULL.
 * @retval #BSL_MALLOC_FAIL Node allocation failed.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * Every call registers a new node: an existing key is neither updated nor deduplicated, so
 * repeated registrations under one key coexist until cleared or reclaimed, and queries and
 * clears resolve to the newest registration. To reuse a registered source, query it with
 * BSL_ASYNC_NotifyCtxGetNotifySource first and only register when it is absent.
 */
int32_t BSL_ASYNC_NotifyCtxSetNotifySource(BSL_ASYNC_NotifyCtx *ctx, const void *key, BSL_ASYNC_NotifyHandle handle,
                                           void *userData, BSL_ASYNC_NotifySourceCleanup cleanup);

/**
 * @ingroup bsl_async
 * @brief   Query a registered notify source
 *
 * @param ctx [IN] Notify context.
 * @param key [IN] Stable pointer identifying the source.
 * @param handle [OUT] Current wait object value; NULL skips it.
 * @param userData [OUT] Current private data; NULL skips it.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT ctx, key or handle is NULL.
 * @retval #BSL_ASYNC_ERR_NOT_FOUND No entry is registered under key.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * When a key holds several registrations, the most recent one is returned.
 */
int32_t BSL_ASYNC_NotifyCtxGetNotifySource(const BSL_ASYNC_NotifyCtx *ctx, const void *key,
                                           BSL_ASYNC_NotifyHandle *handle, void **userData);

/**
 * @ingroup bsl_async
 * @brief   Output list of notify handles, supporting the two-phase query
 */
typedef struct {
    BSL_ASYNC_NotifyHandle *handles; /**< Caller-provided array; NULL only counts the required number. */
    uint32_t capacity; /**< Capacity of the array. */
    uint32_t numHandles; /**< Output: actual number, or the required number on overflow. */
} BSL_ASYNC_NotifyHandleList;

/**
 * @ingroup bsl_async
 * @brief   List all notify sources of a notify context
 *
 * @param ctx [IN] Notify context.
 * @param list [OUT] Output list; handles == NULL only counts the required number.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT A mandatory parameter is NULL.
 * @retval #BSL_ASYNC_ERR_CAPACITY_EXCEEDED capacity is smaller than the required number;
 *         numHandles carries the required number and no array is written.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * Handles are listed from the most recently registered source to the oldest.
 */
int32_t BSL_ASYNC_NotifyCtxGetAllNotifySources(const BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyHandleList *list);

/**
 * @ingroup bsl_async
 * @brief   Logically delete a notify source
 *
 * @param ctx [IN] Notify context.
 * @param key [IN] Stable pointer identifying the source.
 *
 * @retval #BSL_SUCCESS success (idempotent for a deleting key).
 * @retval #BSL_NULL_INPUT ctx or key is NULL.
 * @retval #BSL_ASYNC_ERR_NOT_FOUND No entry is registered under key.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * When a key holds several registrations, the most recent one is cleared and the
 * older nodes remain registered. The handle itself is not released; the application
 * deregisters it from its waiter before resuming the task.
 */
int32_t BSL_ASYNC_NotifyCtxClearNotifySource(BSL_ASYNC_NotifyCtx *ctx, const void *key);

/**
 * @ingroup bsl_async
 * @brief   Read the current change window of a notify context
 *
 * @param ctx [IN] Notify context.
 * @param addList [OUT] List receiving added handles; handles == NULL only counts.
 * @param delList [OUT] List receiving removed handles; handles == NULL only counts.
 *
 * @retval #BSL_SUCCESS success.
 * @retval #BSL_NULL_INPUT A mandatory parameter is NULL.
 * @retval #BSL_ASYNC_ERR_CAPACITY_EXCEEDED A list capacity is insufficient;
 *         numHandles of both lists carries the required number and no array is written.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 * Only reads the change; the framework consumes it at the resume point. Both sets are
 * listed from the most recently registered source to the oldest. Passing handles == NULL
 * for both lists reports only the required numbers.
 */
int32_t BSL_ASYNC_NotifyCtxGetChangedNotifySources(const BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyHandleList *addList,
                                                   BSL_ASYNC_NotifyHandleList *delList);

#ifdef __cplusplus
}
#endif

#endif // BSL_ASYNC_H
