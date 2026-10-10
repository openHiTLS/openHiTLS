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

/*
 * Shared base of every bsl async SDV suite group.
 * It is spliced into the generated per-group source through the
 * INCLUDE_BASE directive, so it must only contain includes, macros and
 * non-static fixtures: static helpers would trip -Wunused-function in groups
 * that do not use them, and group-specific fixtures live in the group files.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_async.h"

/*
 * Runtime coroutine backend availability: cases that need a
 * resumable-context backend call this and SKIP_TEST() when the build selected
 * none; the no-backend build variant exercises the declaration-of-unsupport
 * cases instead.
 */
#define ASYNC_BACKEND_READY() (BSL_SAL_CoroutineIsSupported())

/* Fixed business return values used across the job fixtures. */
#define JOB_SYNC_RET   0x1234
#define JOB_FAIL_RET   0x0BAD
#define JOB_EAGAIN_RET 0x600D

/*
 * Fault-injection allocator: counts every BSL allocation
 * and fails the allocation whose ordinal (counted from the last arm) equals
 * g_injectFailAt. Registered as the BSL_SAL_MEM_MALLOC/BSL_SAL_MEM_FREE pair
 * while armed; -1 arms counting only.
 */
int32_t g_injectFailAt = -1;
uint32_t g_allocCount = 0;

void *InjectMalloc(uint32_t len)
{
    g_allocCount++;
    if (g_injectFailAt >= 0 && (int32_t)g_allocCount == g_injectFailAt + 1) {
        return NULL;
    }
    return malloc((size_t)len);
}

void InjectFree(void *ptr)
{
    free(ptr);
}

void InjectArm(int32_t failAt)
{
    g_allocCount = 0;
    g_injectFailAt = failAt;
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, InjectMalloc);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, InjectFree);
}

void InjectDisarm(void)
{
    g_injectFailAt = -1;
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, NULL);
}

/* -------------------------------------------------------------------------- */
/* business entry fixtures */

/* Shared-state wrapper: the TaskParam snapshot copies the pointer value only
 * (one-way), so every fixture that must exchange data with its host across a
 * scheduling boundary receives this wrapper and dereferences it, instead of
 * relying on inline fields of the snapshot itself (those flow caller-to-task
 * only and are never copied back). */
typedef struct {
    void *shared;
} ArgRef;

/* jobSync: no async call at all, returns a fixed value (UC3). */
int32_t jobSync(void *args)
{
    (void)args;
    return JOB_SYNC_RET;
}

/* jobPauseOnce: one pause, then a fixed value. */
int32_t jobPauseOnce(void *args)
{
    (void)args;
    (void)BSL_ASYNC_PauseTask();
    return JOB_SYNC_RET;
}

/* jobCopyWitness: proves the one-way snapshot. Round 1 mutates the copy and
 * pauses; the caller then overwrites its own buffer; round 2 reports the
 * copy's state through the return value, which must still be the task's own
 * mutation, never the caller's mid-pause write. The caller's buffer in turn
 * is never written back. */
typedef struct {
    uint32_t rounds; /* mutated by the task on its copy; by the test on the caller buffer */
} JobCopyArgs;

int32_t jobCopyWitness(void *args)
{
    JobCopyArgs *a = (JobCopyArgs *)args;
    if (a->rounds == 0) {
        a->rounds = 1;
        (void)BSL_ASYNC_PauseTask();
    }
    return (int32_t)a->rounds;
}

/* jobPauseN: 'rounds' pause rounds; snapshots the counter before each pause
 * and the submit status after each resume (TC19/TC64). */
typedef struct {
    uint32_t rounds;
    uint32_t counter;
    uint32_t pauseLog[16];
    int32_t statusLog[16];
    uint32_t logCount;
} JobPauseNArgs;

int32_t jobPauseN(void *args)
{
    JobPauseNArgs *a = (JobPauseNArgs *)((ArgRef *)args)->shared;
    BSL_ASYNC_Task *self = BSL_ASYNC_GetCurrentTask();
    BSL_ASYNC_NotifyCtx *ctx = BSL_ASYNC_TaskGetNotifyCtx(self);
    int32_t status = 0;

    while (a->counter < a->rounds) {
        a->counter++;
        if (a->logCount < 16) {
            a->pauseLog[a->logCount] = a->counter;
        }
        if (ctx != NULL) {
            (void)BSL_ASYNC_NotifyCtxSetStatus(ctx, BSL_ASYNC_NOTIFY_STATUS_OK);
        }
        (void)BSL_ASYNC_PauseTask();
        if (ctx != NULL && a->logCount < 16) {
            (void)BSL_ASYNC_NotifyCtxGetStatus(ctx, &status);
            a->statusLog[a->logCount] = status;
        }
        a->logCount++;
    }
    return (int32_t)a->counter;
}

/* jobRecordSelf: records the current task and its notify context. */
typedef struct {
    BSL_ASYNC_Task *taskSeen;
    BSL_ASYNC_NotifyCtx *ctxSeen;
} JobRecordSelfArgs;

/* Global sink of the last jobRecordSelf run: lets the zero-allocation
 * reuse case run without an argument buffer (no TaskParam copy-in). */
BSL_ASYNC_Task *g_recordTaskSeen = NULL;
BSL_ASYNC_NotifyCtx *g_recordCtxSeen = NULL;

int32_t jobRecordSelf(void *args)
{
    BSL_ASYNC_Task *self = BSL_ASYNC_GetCurrentTask();
    g_recordTaskSeen = self;
    g_recordCtxSeen = BSL_ASYNC_TaskGetNotifyCtx(self);
    if (args != NULL) {
        JobRecordSelfArgs *a = (JobRecordSelfArgs *)((ArgRef *)args)->shared;
        a->taskSeen = self;
        a->ctxSeen = g_recordCtxSeen;
    }
    return JOB_SYNC_RET;
}

/* jobBlockPause: pause inside the shielded region must not switch (TC20). */
typedef struct {
    int32_t pauseRet;
    int flagInside;
    int flagAfter;
} JobBlockPauseArgs;

int32_t jobBlockPause(void *args)
{
    JobBlockPauseArgs *a = (JobBlockPauseArgs *)((ArgRef *)args)->shared;
    BSL_ASYNC_BlockPause();
    a->pauseRet = BSL_ASYNC_PauseTask();
    a->flagInside = 1;
    BSL_ASYNC_UnblockPause();
    (void)BSL_ASYNC_PauseTask();
    a->flagAfter = 1;
    return JOB_SYNC_RET;
}

/* jobBlockNoUnblock: leaves the depth non-zero on finish (TC22). */
int32_t jobBlockNoUnblock(void *args)
{
    (void)args;
    BSL_ASYNC_BlockPause();
    return JOB_SYNC_RET;
}

/* jobNestedBlock: nested shields, all released, then one real pause (TC21). */
typedef struct {
    uint32_t depth;
} JobNestedBlockArgs;

int32_t jobNestedBlock(void *args)
{
    JobNestedBlockArgs *a = (JobNestedBlockArgs *)((ArgRef *)args)->shared;
    uint32_t i;
    for (i = 0; i < a->depth; i++) {
        BSL_ASYNC_BlockPause();
    }
    (void)BSL_ASYNC_PauseTask(); /* shielded: success without a switch */
    for (i = 0; i < a->depth; i++) {
        BSL_ASYNC_UnblockPause();
    }
    (void)BSL_ASYNC_PauseTask();
    return JOB_SYNC_RET;
}

/* jobUnblockAtZero: unblock at depth zero must not underflow (TC21). */
typedef struct {
    int flagBeforeFinalPause;
} JobUnblockAtZeroArgs;

int32_t jobUnblockAtZero(void *args)
{
    JobUnblockAtZeroArgs *a = (JobUnblockAtZeroArgs *)((ArgRef *)args)->shared;
    BSL_ASYNC_UnblockPause(); /* depth 0: no-op */
    BSL_ASYNC_BlockPause();
    (void)BSL_ASYNC_PauseTask(); /* shielded: must not pause here */
    BSL_ASYNC_UnblockPause();
    a->flagBeforeFinalPause = 1;
    (void)BSL_ASYNC_PauseTask();
    return JOB_SYNC_RET;
}

/* jobMisuse: framework-detected misuse from inside a task (TC3/TC10). The
 * trailing CleanupThread must be a no-op on a task stack; the
 * follow-up host-side job proves the domain survived it. */
typedef struct {
    int32_t rets[2]; /* [0] InitThread, [1] StartTask */
} JobMisuseArgs;

int32_t jobMisuse(void *args)
{
    JobMisuseArgs *a = (JobMisuseArgs *)((ArgRef *)args)->shared;
    BSL_ASYNC_Task *inner = NULL;
    int32_t innerRet = 0;
    BSL_ASYNC_TaskParam param = {0};
    param.func = jobSync;
    param.args = NULL;
    a->rets[0] = BSL_ASYNC_InitThread(2, 0, 0);
    a->rets[1] = BSL_ASYNC_StartTask(&inner, &innerRet, &param);
    BSL_ASYNC_CleanupThread();
    return JOB_SYNC_RET;
}

/* jobWithCtx: optional status publish, N pause rounds, status log after each
 * resume (TC13; TC25/TC28 extend it through the M4 fixtures). */
typedef struct {
    int32_t setStatus; /* 0 = do not publish */
    uint32_t rounds; /* pause rounds before returning */
    int32_t statusLog[16];
    uint32_t logCount;
    int32_t statusAfterResume;
    int32_t setStatusRet; /* return code of the first SetStatus (TC028) */
} JobWithCtxArgs;

int32_t jobWithCtx(void *args)
{
    JobWithCtxArgs *a = (JobWithCtxArgs *)((ArgRef *)args)->shared;
    BSL_ASYNC_Task *self = BSL_ASYNC_GetCurrentTask();
    BSL_ASYNC_NotifyCtx *ctx = BSL_ASYNC_TaskGetNotifyCtx(self);
    int32_t status = 0;
    uint32_t round;

    if (ctx == NULL) {
        return -1;
    }
    for (round = 0; round < a->rounds; round++) {
        if (a->setStatus != 0) {
            if (round == 0) {
                a->setStatusRet = BSL_ASYNC_NotifyCtxSetStatus(ctx, a->setStatus);
            } else {
                (void)BSL_ASYNC_NotifyCtxSetStatus(ctx, a->setStatus);
            }
        }
        (void)BSL_ASYNC_PauseTask();
        if (a->logCount < 16) {
            (void)BSL_ASYNC_NotifyCtxGetStatus(ctx, &status);
            a->statusLog[a->logCount] = status;
        }
        a->logCount++;
    }
    if (a->logCount > 0) {
        a->statusAfterResume = a->statusLog[a->logCount - 1];
    }
    return JOB_SYNC_RET;
}

/* -------------------------------------------------------------------------- */
/* generic notify source job engine: one op sequence
 * drives every source-related case; SET/CLEAR record their return codes
 * parallel to the op array, PAUSE splits the rounds the host drives. */

typedef enum {
    SRC_OP_NOP = 0,
    SRC_OP_SET, /* register values[i] on the bound context */
    SRC_OP_CLEAR, /* clear values[i].key */
    SRC_OP_PAUSE, /* pause round boundary */
    SRC_OP_SNAPSHOT, /* record the all-source count and the submit status */
} SrcOpKind;

typedef struct {
    const void *key;
    BSL_ASYNC_NotifyHandle handle;
    void *userData;
    BSL_ASYNC_NotifySourceCleanup cleanup;
} SrcValue;

typedef struct {
    SrcOpKind ops[48];
    SrcValue values[48];
    uint32_t opCount;
    int32_t rets[48]; /* return code of each op (parallel to ops) */
    uint32_t allCount; /* SNAPSHOT: two-phase all-source count */
    int32_t lastStatus; /* SNAPSHOT: submit status */
    uint32_t snapCount;
} SrcJobArgs;

int32_t jobSources(void *args)
{
    SrcJobArgs *a = (SrcJobArgs *)((ArgRef *)args)->shared;
    BSL_ASYNC_Task *self = BSL_ASYNC_GetCurrentTask();
    BSL_ASYNC_NotifyCtx *ctx = BSL_ASYNC_TaskGetNotifyCtx(self);
    BSL_ASYNC_NotifyHandleList list = {NULL, 0, 0};
    uint32_t i;

    if (ctx == NULL) {
        return -1;
    }
    for (i = 0; i < a->opCount; i++) {
        switch (a->ops[i]) {
            case SRC_OP_SET:
                a->rets[i] = BSL_ASYNC_NotifyCtxSetNotifySource(ctx, a->values[i].key, a->values[i].handle,
                                                                a->values[i].userData, a->values[i].cleanup);
                break;
            case SRC_OP_CLEAR:
                a->rets[i] = BSL_ASYNC_NotifyCtxClearNotifySource(ctx, a->values[i].key);
                break;
            case SRC_OP_PAUSE:
                a->rets[i] = BSL_ASYNC_PauseTask();
                break;
            case SRC_OP_SNAPSHOT:
                list.handles = NULL;
                list.capacity = 0;
                a->rets[i] = BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &list);
                a->allCount = list.numHandles;
                a->lastStatus = 0;
                (void)BSL_ASYNC_NotifyCtxGetStatus(ctx, &a->lastStatus);
                a->snapCount++;
                break;
            default:
                a->rets[i] = 0;
                break;
        }
    }
    return 0;
}

/* Two-phase changed-sources read: first count both lists, then fetch into
 * the given buffers; returns the BSL code of the fetching call. */
int32_t AsyncReadChanges(BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_NotifyHandle *addBuf, uint32_t addCap, uint32_t *addCount,
                         BSL_ASYNC_NotifyHandle *delBuf, uint32_t delCap, uint32_t *delCount)
{
    BSL_ASYNC_NotifyHandleList addList = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandleList delList = {NULL, 0, 0};
    int32_t ret;

    ret = BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &addList, &delList);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    *addCount = addList.numHandles;
    *delCount = delList.numHandles;
    addList.handles = addBuf;
    addList.capacity = addCap;
    delList.handles = delBuf;
    delList.capacity = delCap;
    return BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &addList, &delList);
}

/* -------------------------------------------------------------------------- */
/* application post layer and mock crypto implementation */

/* Fixed device result the mock implementation delivers (business value). */
#define MOCK_DEVICE_RET 0xD00D

/* Resume-ready queue: the same handle is merged only once. */
#define READY_CAP 16
typedef struct {
    BSL_ASYNC_Task *items[READY_CAP];
    uint32_t count;
} ReadyQueue;

ReadyQueue g_ready = {{NULL}, 0};

void AppPost(BSL_ASYNC_Task *task)
{
    uint32_t i;
    for (i = 0; i < g_ready.count; i++) {
        if (g_ready.items[i] == task) {
            return; /* idempotent merge: repeated deliveries collapse */
        }
    }
    if (g_ready.count < READY_CAP) {
        g_ready.items[g_ready.count++] = task;
    }
}

BSL_ASYNC_Task *AppPop(void)
{
    BSL_ASYNC_Task *t = NULL;
    uint32_t i;
    if (g_ready.count == 0) {
        return NULL;
    }
    t = g_ready.items[0];
    for (i = 1; i < g_ready.count; i++) {
        g_ready.items[i - 1] = g_ready.items[i];
    }
    g_ready.count--;
    return t;
}

/* Delivery callback argument: task is backfilled either by the host
 * after the pause (method 1) or by the task before an early completion
 * (method 2); ret is the delivery status the callback reports. */
typedef struct {
    BSL_ASYNC_Task *task;
    int32_t ret;
} MockArg;

int32_t mockCb(void *arg)
{
    MockArg *a = (MockArg *)arg;
    if (a->ret != BSL_SUCCESS) {
        return a->ret; /* failed delivery: nothing is enqueued */
    }
    AppPost(a->task);
    return a->ret;
}

/* Wait object of one mock request. The members are plain descriptors so the
 * type stays portable; only the functions below are platform-specific. */
typedef struct {
    int readFd; /* the BSL_ASYNC_NotifyHandle: eventfd or pipe read end */
    int writeFd; /* pipe write end; -1 for eventfd */
} MockWait;

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/* POSIX waiter primitives, defined at the end of this file. */
int MockWaitOpen(MockWait *w);
void MockWaitClose(MockWait *w);
BSL_ASYNC_NotifyHandle MockWaitHandle(const MockWait *w);
void MockWaitSignal(MockWait *w);
void MockWaitConsume(MockWait *w);
#endif

/* One mock crypto request. */
typedef struct {
    BSL_ASYNC_NotifyCtx *ctx; /* the request's notify context */
    BSL_ASYNC_NotifyCallback cb; /* cached by the task via GetCallback */
    void *cbArg;
    int32_t publishStatus; /* OK / EAGAIN / ERR / UNSUPPORTED */
    MockWait wait; /* notify-node path wait object */
    const void *key; /* notify-node registration identity */
    int32_t deviceResult; /* delivered after the resume */
    int completeBeforePause; /* completion fired before the pause returns */
} MockReq;

int32_t mockSubmit(BSL_ASYNC_Task **task, int32_t *ret, BSL_ASYNC_NotifyCtx *ctx, BSL_ASYNC_Func function, MockReq *req)
{
    /* The request block is shared through the snapshot pointer: the entry's
     * writes (cached callback, result) and the host's writes (handle
     * backfill) meet in the same block. */
    ArgRef reqRef = {req};
    BSL_ASYNC_TaskParam param = {0};
    param.notifyCtx = ctx;
    param.func = function;
    param.args = &reqRef;
    param.argsSize = sizeof(reqRef);
    return BSL_ASYNC_StartTask(task, ret, &param);
}

int32_t mockReadResult(MockReq *r)
{
    return r->deviceResult;
}

void mockOnComplete(MockReq *r)
{
    if (r->cb != NULL) { /* notify-callback path */
        (void)r->cb(r->cbArg);
        return;
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    MockWaitSignal(&r->wait); /* notify-node path */
#endif
}

/* UC4: cache the callback, publish the status, pause, deliver the result. */
int32_t mockJob(void *args)
{
    MockReq *r = (MockReq *)((ArgRef *)args)->shared;
    BSL_ASYNC_Task *self = BSL_ASYNC_GetCurrentTask();

    if (self == NULL) {
        return -1;
    }
    if (BSL_ASYNC_TaskGetNotifyCtx(self) != r->ctx) {
        return -2;
    }
    if (BSL_ASYNC_NotifyCtxGetCallback(r->ctx, &r->cb, &r->cbArg) != BSL_SUCCESS) {
        return -3;
    }
    if (BSL_ASYNC_NotifyCtxSetStatus(r->ctx, r->publishStatus) != BSL_SUCCESS) {
        return -4;
    }
    if (r->completeBeforePause && r->cbArg != NULL) {
        /* Early completion: backfill the handle the callback needs before
         * the delivery fires. */
        ((MockArg *)r->cbArg)->task = self;
        mockOnComplete(r);
    }
    (void)BSL_ASYNC_PauseTask();
    return mockReadResult(r);
}

/* UC7 / UC8 branch A: publish EAGAIN or ERR, pause, then advance without
 * any external event (the retry policy is the implementation's own). */
int32_t jobEagainOrErr(void *args)
{
    MockReq *r = (MockReq *)((ArgRef *)args)->shared;

    if (BSL_ASYNC_NotifyCtxSetStatus(r->ctx, r->publishStatus) != BSL_SUCCESS) {
        return -1;
    }
    (void)BSL_ASYNC_PauseTask();
    if (r->publishStatus == BSL_ASYNC_NOTIFY_STATUS_EAGAIN) {
        r->deviceResult = JOB_EAGAIN_RET;
    }
    return r->deviceResult;
}

/* UC8 branch B: the request was submitted (OK) but the device failed; the
 * business error is delivered after the resume. */
int32_t jobFailAfterPause(void *args)
{
    MockReq *r = (MockReq *)((ArgRef *)args)->shared;

    (void)BSL_ASYNC_NotifyCtxSetStatus(r->ctx, BSL_ASYNC_NOTIFY_STATUS_OK);
    (void)BSL_ASYNC_PauseTask();
    return JOB_FAIL_RET;
}

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
#include <fcntl.h>
#include <unistd.h>
#if defined(HITLS_BSL_SAL_LINUX)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#else
#include <poll.h>
#endif

/* Wait object of one mock request: eventfd on Linux, a self-pipe on other
 * POSIX systems. */
int MockWaitOpen(MockWait *w)
{
#if defined(HITLS_BSL_SAL_LINUX)
    int fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    w->readFd = fd;
    w->writeFd = -1;
#else
    int fds[2];
    if (pipe(fds) != 0) {
        return -1;
    }
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    w->readFd = fds[0];
    w->writeFd = fds[1];
#endif
    return 0;
}

/* Idempotent: the node cleanup and the case teardown may both close it. */
void MockWaitClose(MockWait *w)
{
    if (w->readFd >= 0) {
        close(w->readFd);
        w->readFd = -1;
    }
    if (w->writeFd >= 0) {
        close(w->writeFd);
        w->writeFd = -1;
    }
}

BSL_ASYNC_NotifyHandle MockWaitHandle(const MockWait *w)
{
    return (BSL_ASYNC_NotifyHandle)(uintptr_t)w->readFd;
}

void MockWaitSignal(MockWait *w)
{
    uint64_t one = 1;
#if defined(HITLS_BSL_SAL_LINUX)
    (void)write(w->readFd, &one, sizeof(one));
#else
    (void)write(w->writeFd, &one, sizeof(one));
#endif
}

void MockWaitConsume(MockWait *w)
{
    uint64_t v;
    (void)read(w->readFd, &v, sizeof(v));
}

/* Application-side waiter registration set: the handles actually
 * registered in the waiter, maintained from the change window. epfd is
 * only used where epoll exists. */
#define WAIT_SET_CAP 8
typedef struct {
    BSL_ASYNC_NotifyHandle items[WAIT_SET_CAP];
    uint32_t count;
    int epfd;
} WaitSet;

WaitSet g_waitSet = {{0}, 0, -1};

int AppWaitInit(void)
{
    g_waitSet.count = 0;
    g_waitSet.epfd = -1;
#if defined(HITLS_BSL_SAL_LINUX)
    g_waitSet.epfd = epoll_create1(0);
    if (g_waitSet.epfd < 0) {
        return -1;
    }
#endif
    return 0;
}

void AppWaitDeinit(void)
{
#if defined(HITLS_BSL_SAL_LINUX)
    if (g_waitSet.epfd >= 0) {
        close(g_waitSet.epfd);
        g_waitSet.epfd = -1;
    }
#endif
    g_waitSet.count = 0;
}

int AppWaitAdd(BSL_ASYNC_NotifyHandle h)
{
#if defined(HITLS_BSL_SAL_LINUX)
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = (int)h;
    if (g_waitSet.epfd < 0 || epoll_ctl(g_waitSet.epfd, EPOLL_CTL_ADD, (int)h, &ev) != 0) {
        return -1;
    }
#endif
    if (g_waitSet.count >= WAIT_SET_CAP) {
        return -1;
    }
    g_waitSet.items[g_waitSet.count++] = h;
    return 0;
}

int AppWaitRemove(BSL_ASYNC_NotifyHandle h)
{
    uint32_t i;
    int found = 0;
    for (i = 0; i < g_waitSet.count; i++) {
        if (found) {
            g_waitSet.items[i - 1] = g_waitSet.items[i];
        } else if (g_waitSet.items[i] == h) {
            found = 1;
        }
    }
    if (found) {
        g_waitSet.count--;
    }
#if defined(HITLS_BSL_SAL_LINUX)
    if (g_waitSet.epfd >= 0) {
        (void)epoll_ctl(g_waitSet.epfd, EPOLL_CTL_DEL, (int)h, NULL);
    }
#endif
    return found ? 0 : -1;
}

int AppWaitContains(BSL_ASYNC_NotifyHandle h)
{
    uint32_t i;
    for (i = 0; i < g_waitSet.count; i++) {
        if (g_waitSet.items[i] == h) {
            return 1;
        }
    }
    return 0;
}

/* Wait until one registered handle is ready: returns the ready handle, or
 * 0 on timeout / when nothing is registered. */
BSL_ASYNC_NotifyHandle AppWaitWait(int timeoutMs)
{
#if defined(HITLS_BSL_SAL_LINUX)
    struct epoll_event ev = {0};
    if (g_waitSet.count == 0 || g_waitSet.epfd < 0) {
        return 0;
    }
    if (epoll_wait(g_waitSet.epfd, &ev, 1, timeoutMs) != 1) {
        return 0;
    }
    return (BSL_ASYNC_NotifyHandle)ev.data.fd;
#else
    struct pollfd fds[WAIT_SET_CAP];
    uint32_t i;
    if (g_waitSet.count == 0) {
        return 0;
    }
    for (i = 0; i < g_waitSet.count; i++) {
        fds[i].fd = (int)g_waitSet.items[i];
        fds[i].events = POLLIN;
        fds[i].revents = 0;
    }
    if (poll(fds, g_waitSet.count, timeoutMs) < 1) {
        return 0;
    }
    for (i = 0; i < g_waitSet.count; i++) {
        if (fds[i].revents & POLLIN) {
            return g_waitSet.items[i];
        }
    }
    return 0;
#endif
}

/* Node reclaim callback: records the call and releases the wait
 * object owned by the request; the idempotent close tolerates the case
 * teardown repeating it. */
uint32_t g_mockCleanupCount = 0;
BSL_ASYNC_NotifyHandle g_mockCleanupHandle = 0;

void mockCleanup(BSL_ASYNC_NotifyCtx *ctx, const void *key, BSL_ASYNC_NotifyHandle handle, void *userData)
{
    (void)ctx;
    (void)key;
    g_mockCleanupCount++;
    g_mockCleanupHandle = handle;
    MockWaitClose(&((MockReq *)userData)->wait);
}

/* UC5 / UC9: register the event source, publish UNSUPPORTED, pause; on the
 * resume consume the completion, clear the source, pause once more for the
 * application's unregister, then deliver the device result. */
int32_t mockJobSource(void *args)
{
    MockReq *r = (MockReq *)((ArgRef *)args)->shared;

    if (BSL_ASYNC_NotifyCtxSetNotifySource(r->ctx, r->key, MockWaitHandle(&r->wait), r, mockCleanup) != BSL_SUCCESS) {
        return -1;
    }
    if (BSL_ASYNC_NotifyCtxSetStatus(r->ctx, BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED) != BSL_SUCCESS) {
        return -2;
    }
    (void)BSL_ASYNC_PauseTask(); /* first pause: wait for the device */
    MockWaitConsume(&r->wait);
    if (BSL_ASYNC_NotifyCtxClearNotifySource(r->ctx, r->key) != BSL_SUCCESS) {
        return -3;
    }
    (void)BSL_ASYNC_PauseTask(); /* second pause: wait for the unregister */
    return mockReadResult(r);
}
#endif /* HITLS_BSL_SAL_LINUX || HITLS_BSL_SAL_DARWIN */
