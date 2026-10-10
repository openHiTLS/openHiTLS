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

/* INCLUDE_BASE test_suite_sdv_async */

/* BEGIN_HEADER */
/* macOS exposes <ucontext.h> only with _XOPEN_SOURCE; the late define is
 * scoped the same way as bsl/sal/src/posix/posix_coroutine.c and the test
 * build already carries -Wno-deprecated-declarations. */
#if defined(__APPLE__) && defined(__MACH__) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
/* Pin the interposed wrapper to the plain "mmap" symbol: with
 * _FILE_OFFSET_BITS=64, newer glibc redirects mmap to mmap64 through an asm
 * label on its declaration, which renames the stub wrapper generated below
 * and silently breaks the interposition (the library keeps calling plain
 * mmap). macOS is unaffected (no mmap64 redirect) and its SDK declaration
 * already carries __DARWIN_ALIAS, which an explicit asm label would
 * conflict with. */
#if !defined(__APPLE__)
extern void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) __asm__("mmap");
#endif
#include <sys/mman.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
#include "stub_utils.h"

STUB_DEFINE_RET2(int32_t, BSL_SAL_ThreadRunOnce, BSL_SAL_OnceControl *, BSL_SAL_ThreadInitRoutine);

typedef void (*KeyCleanup)(void *);
STUB_DEFINE_RET2(int, pthread_key_create, pthread_key_t *, KeyCleanup);
STUB_DEFINE_RET1(int, pthread_key_delete, pthread_key_t);
/* pthread_setspecific is written out instead of STUB_DEFINE_RET2: glibc 2.39
 * declares it with __attr_access_none(2), and combined with GCC 13's
 * -Wmaybe-uninitialized that falsely flags the parameter passed through to
 * the indirect calls. Copying the parameter first keeps the same wrapper
 * behavior without the false positive. */
typedef int (*real_pthread_setspecific_func_t)(pthread_key_t, const void *);
typedef struct {
    const char *stub_target_symbol;
    int (*stub_impl)(pthread_key_t, const void *);
    real_pthread_setspecific_func_t real_impl;
} pthread_setspecific_Stub;
pthread_setspecific_Stub pthread_setspecific_stub = {
    .stub_target_symbol = "pthread_setspecific",
    .stub_impl = NULL,
};
static real_pthread_setspecific_func_t get_real_pthread_setspecific(void)
{
    if (pthread_setspecific_stub.real_impl == NULL) {
        pthread_setspecific_stub.real_impl = (real_pthread_setspecific_func_t)dlsym(RTLD_NEXT, "pthread_setspecific");
    }
    return pthread_setspecific_stub.real_impl;
}
void pthread_setspecific_restore(void)
{
    pthread_setspecific_stub.stub_impl = NULL;
}
int pthread_setspecific(pthread_key_t arg0, const void *arg1)
{
    const void *value = arg1;
    if (pthread_setspecific_stub.stub_impl != NULL) {
        return pthread_setspecific_stub.stub_impl(arg0, value);
    }
    real_pthread_setspecific_func_t real_func = get_real_pthread_setspecific();
    if (real_func != NULL) {
        return real_func(arg0, value);
    }
    int default_ret = {0};
    return default_ret;
}
STUB_DEFINE_RET2(int, swapcontext, ucontext_t *, const ucontext_t *);
STUB_DEFINE_RET6(void *, mmap, void *, size_t, int, int, int, off_t);
STUB_DEFINE_RET2(int, munmap, void *, size_t);

#define CHECK_REGRESS(expr)                                               \
    do {                                                                  \
        if (!(expr)) {                                                    \
            fprintf(stderr, "Regression line %d: %s\n", __LINE__, #expr); \
            return 1;                                                     \
        }                                                                 \
    } while (0)

static int g_failSwitch;
static int g_failSetAt;
static int g_entryCalls;
static int g_deleteCalls;
static int g_liveMaps;
static int g_cleanupCalls;

static int FailSwitch(ucontext_t *from, const ucontext_t *to)
{
    if (g_failSwitch > 0) {
        g_failSwitch--;
        errno = EFAULT;
        return -1;
    }
    return get_real_swapcontext()(from, to);
}

static int FailKeyCreate(pthread_key_t *key, KeyCleanup cleanup)
{
    (void)key;
    (void)cleanup;
    return EAGAIN;
}

static int CountKeyDelete(pthread_key_t key)
{
    int ret = get_real_pthread_key_delete()(key);
    if (ret == 0) {
        g_deleteCalls++;
    }
    return ret;
}

static int FailSetSpecific(pthread_key_t key, const void *value)
{
    if (--g_failSetAt == 0) {
        STUB_RESTORE(pthread_setspecific);
        return ENOMEM;
    }
    return get_real_pthread_setspecific()(key, value);
}

static void *CountMap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    void *map = get_real_mmap()(addr, len, prot, flags, fd, offset);
    if (map != MAP_FAILED) {
        g_liveMaps++;
    }
    return map;
}

static void *FailMap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    (void)addr;
    (void)len;
    (void)prot;
    (void)flags;
    (void)fd;
    (void)offset;
    errno = ENOMEM;
    return MAP_FAILED;
}

static int CountUnmap(void *addr, size_t len)
{
    int ret = get_real_munmap()(addr, len);
    if (ret == 0) {
        g_liveMaps--;
    }
    return ret;
}

static int32_t FinishWithSwitchFailure(void *arg)
{
    (void)arg;
    if (++g_entryCalls == 1) {
        g_failSwitch = 2;
    }
    return JOB_SYNC_RET;
}

static int CheckFinish(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t result = -1;
    BSL_ASYNC_TaskParam param = {NULL, FinishWithSwitchFailure, NULL, 0};
    STUB_REPLACE(swapcontext, FailSwitch);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_FINISH);
    CHECK_REGRESS(task == NULL && result == JOB_SYNC_RET && g_entryCalls == 1);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_FINISH);
    CHECK_REGRESS(g_entryCalls == 2);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static int CheckPrivateKey(void)
{
    pthread_key_t foreign;
    int marker = 0;
    CHECK_REGRESS(pthread_key_create(&foreign, NULL) == 0);
    CHECK_REGRESS(pthread_setspecific(foreign, &marker) == 0);
    BSL_ERR_ClearError();
    STUB_REPLACE(pthread_key_create, FailKeyCreate);
    /* The execution-domain key is the only pthread key the core owns
     * (backends keep no private TLS slot). */
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SAL_ERR_NO_MEMORY);
    CHECK_REGRESS(pthread_getspecific(foreign) == &marker);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SAL_ERR_NO_MEMORY);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    STUB_RESTORE(pthread_key_create);
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 1, 0) == BSL_SUCCESS);
    CHECK_REGRESS(pthread_getspecific(foreign) == &marker);
    BSL_ASYNC_CleanupThread();
    CHECK_REGRESS(pthread_getspecific(foreign) == &marker);
    CHECK_REGRESS(pthread_key_delete(foreign) == 0);
    return 0;
}

static void CleanupSource(BSL_ASYNC_NotifyCtx *ctx, const void *key, BSL_ASYNC_NotifyHandle handle, void *data)
{
    (void)ctx;
    (void)key;
    (void)handle;
    (void)data;
    g_cleanupCalls++;
}

static int CheckClear(void)
{
    BSL_ASYNC_NotifyCtx *ctx = BSL_ASYNC_NotifyCtxNew();
    BSL_ASYNC_Task *task = NULL;
    SrcJobArgs args = {0};
    ArgRef argsRef = {&args};
    BSL_ASYNC_TaskParam param = {ctx, jobSources, &argsRef, sizeof(argsRef)};
    BSL_ASYNC_NotifyHandle handle = 99;
    BSL_ASYNC_NotifyHandle deleted = 0;
    BSL_ASYNC_NotifyHandleList add = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandleList del = {&deleted, 1, 0};
    int32_t result = -1;
    int key;
    CHECK_REGRESS(ctx != NULL);
    args.opCount = 8;
    args.ops[0] = SRC_OP_SET;
    args.values[0] = (SrcValue){&key, 11, NULL, CleanupSource};
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2] = (SrcValue){&key, 22, NULL, CleanupSource};
    args.ops[3] = SRC_OP_CLEAR;
    args.values[3].key = &key;
    args.ops[4] = SRC_OP_CLEAR;
    args.values[4].key = &key;
    args.ops[5] = SRC_OP_PAUSE;
    args.ops[6] = SRC_OP_SNAPSHOT;
    args.ops[7] = SRC_OP_PAUSE;
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_PAUSE);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, NULL) == BSL_ASYNC_PAUSE);
    CHECK_REGRESS(args.rets[2] == 0 && args.rets[3] == 0 && args.rets[4] == 0);
    CHECK_REGRESS(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key, &handle, NULL) == BSL_ASYNC_ERR_NOT_FOUND);
    CHECK_REGRESS(handle == 99 && g_cleanupCalls == 1);
    CHECK_REGRESS(BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &add, &del) == BSL_SUCCESS);
    CHECK_REGRESS(add.numHandles == 0 && del.numHandles == 1 && deleted == 11);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, NULL) == BSL_ASYNC_PAUSE);
    CHECK_REGRESS(g_cleanupCalls == 2 && args.allCount == 0);
    CHECK_REGRESS(BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &add, &del) == BSL_SUCCESS);
    CHECK_REGRESS(add.numHandles == 0 && del.numHandles == 0);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, NULL) == BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    CHECK_REGRESS(g_cleanupCalls == 2);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static int32_t ResumeInsideTask(void *arg)
{
    BSL_ASYNC_Task **other = arg;
    BSL_ASYNC_Task *savedOther = *other;
    BSL_ASYNC_Task *self = BSL_ASYNC_GetCurrentTask();
    int32_t result = 99;
    CHECK_REGRESS(BSL_ASYNC_StartTask(other, &result, NULL) == BSL_ASYNC_ERR);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_ASYNC_ERR_STATE_CONFLICT);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    CHECK_REGRESS(result == 99 && *other == savedOther && BSL_ASYNC_GetCurrentTask() == self);
    CHECK_REGRESS(BSL_ASYNC_PauseTask() == BSL_SUCCESS);
    return JOB_SYNC_RET;
}

static int CheckNestedResume(void)
{
    BSL_ASYNC_Task *first = NULL;
    BSL_ASYNC_Task *second = NULL;
    int32_t result = -1;
    BSL_ASYNC_TaskParam param = {NULL, jobPauseOnce, NULL, 0};
    CHECK_REGRESS(BSL_ASYNC_StartTask(&first, &result, &param) == BSL_ASYNC_PAUSE);
    param.func = ResumeInsideTask;
    param.args = &first;
    param.argsSize = sizeof(first);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&second, &result, &param) == BSL_ASYNC_PAUSE);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&first, &result, NULL) == BSL_ASYNC_FINISH);
    CHECK_REGRESS(result == JOB_SYNC_RET);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&second, &result, NULL) == BSL_ASYNC_FINISH);
    CHECK_REGRESS(result == JOB_SYNC_RET);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static void *ExitWithTask(void *arg)
{
    int32_t result = BSL_ASYNC_InitThread(1, 1, 0);
    if (result == BSL_SUCCESS && arg != NULL) {
        BSL_ASYNC_Task *task = NULL;
        BSL_ASYNC_TaskParam param = {NULL, jobPauseOnce, NULL, 0};
        result = BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_PAUSE ? BSL_SUCCESS : BSL_INVALID_ARG;
    }
    return (void *)(intptr_t)result;
}

static int CheckExit(int paused)
{
    pthread_key_t occupied;
    pthread_t worker;
    void *result = NULL;
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
    CHECK_REGRESS(pthread_key_create(&occupied, NULL) == 0);
    STUB_REPLACE(mmap, CountMap);
    STUB_REPLACE(munmap, CountUnmap);
    CHECK_REGRESS(pthread_create(&worker, NULL, ExitWithTask, paused ? &worker : NULL) == 0);
    CHECK_REGRESS(pthread_join(worker, &result) == 0 && result == NULL);
    /* The paused variant leaves one outstanding task: it is abandoned at
     * thread exit (not reclaimed), so its coroutine stack stays
     * mapped; the non-paused variant destroys its idle task. */
    CHECK_REGRESS(g_liveMaps == (paused ? 1 : 0));
    CHECK_REGRESS(pthread_key_delete(occupied) == 0);
    return 0;
}

static BSL_SAL_OnceControl *g_failedOnceControl;

static int32_t FailAsyncOnce(BSL_SAL_OnceControl *control, BSL_SAL_ThreadInitRoutine init)
{
    if (g_failedOnceControl == NULL) {
        g_failedOnceControl = control;
    }
    if (control == g_failedOnceControl) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return get_real_BSL_SAL_ThreadRunOnce()(control, init);
}

static int CheckOnceFailure(void)
{
    int32_t retryExpected = ASYNC_BACKEND_READY() ? BSL_SUCCESS : BSL_ASYNC_ERR_STATE_CONFLICT;
    CHECK_REGRESS(BSL_ASYNC_InitThread(0, 1, 0) == BSL_INVALID_ARG);
    BSL_ERR_ClearError();
    STUB_REPLACE(BSL_SAL_ThreadRunOnce, FailAsyncOnce);
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SAL_ERR_NO_MEMORY);
    STUB_RESTORE(BSL_SAL_ThreadRunOnce);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SAL_ERR_NO_MEMORY);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    /* Without a backend the retry still cannot establish a domain: the host
     * context is a backend object. */
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == retryExpected);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static int CheckLockFailure(void)
{
    CHECK_REGRESS(BSL_ASYNC_InitThread(0, 1, 0) == BSL_INVALID_ARG);
    BSL_ERR_ClearError();
    InjectArm(0);
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SAL_ERR_NO_MEMORY);
    InjectDisarm();
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SAL_ERR_NO_MEMORY);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    InjectArm(-1);
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SAL_ERR_NO_MEMORY);
    CHECK_REGRESS(g_allocCount == 0);
    InjectDisarm();
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SAL_ERR_NO_MEMORY);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    CHECK_REGRESS(BSL_ASYNC_GetCurrentTask() == NULL);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static int CheckReinit(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t result = 99;
    BSL_ASYNC_TaskParam param = {NULL, jobSync, NULL, 0};
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SUCCESS);
    STUB_REPLACE(pthread_key_delete, CountKeyDelete);
    STUB_REPLACE(mmap, CountMap);
    STUB_REPLACE(munmap, CountUnmap);
    /* Scale up in place: the key is never retired, the slot never rebound. */
    CHECK_REGRESS(BSL_ASYNC_InitThread(2, 2, 0) == BSL_SUCCESS);
    CHECK_REGRESS(g_deleteCalls == 0 && g_liveMaps == 2);
    BSL_ERR_ClearError();
    InjectArm(2);
    /* A mid-way failed scale-up rolls the pool back and keeps the domain:
     * the key survives together with the thread's reservation. */
    CHECK_REGRESS(BSL_ASYNC_InitThread(4, 4, 0) == BSL_MALLOC_FAIL);
    InjectDisarm();
    CHECK_REGRESS(g_deleteCalls == 0 && g_liveMaps == 2);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_MALLOC_FAIL);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    /* The restored pool still schedules with its previous limit. */
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_FINISH);
    CHECK_REGRESS(result == JOB_SYNC_RET);
    CHECK_REGRESS(BSL_ASYNC_InitThread(4, 4, 0) == BSL_SUCCESS);
    CHECK_REGRESS(g_liveMaps == 4);
    /* Scale down: the idle surplus is released back to the backend. */
    CHECK_REGRESS(BSL_ASYNC_InitThread(2, 2, 0) == BSL_SUCCESS);
    CHECK_REGRESS(g_liveMaps == 2);
    STUB_RESTORE(mmap);
    STUB_RESTORE(munmap);
    BSL_ASYNC_CleanupThread();
    CHECK_REGRESS(g_deleteCalls == 1);
    return 0;
}

static int CheckTaskAllocation(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t result = 99;
    BSL_ASYNC_TaskParam param = {NULL, jobSync, NULL, 0};
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SUCCESS);
    InjectArm(0);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_ERR);
    InjectDisarm();
    CHECK_REGRESS(task == NULL && result == 99);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_MALLOC_FAIL);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static int CheckInitError(int mode)
{
    int32_t expected = mode == 0 ? BSL_INVALID_ARG : BSL_SAL_ERR_NO_MEMORY;
    if (mode == 1) {
        STUB_REPLACE(pthread_key_create, FailKeyCreate);
    } else if (mode == 2) {
        STUB_REPLACE(mmap, FailMap);
    } else if (mode == 3) {
        g_failSetAt = 1;
        STUB_REPLACE(pthread_setspecific, FailSetSpecific);
    }
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 1, mode == 0 ? 1 : 0) == expected);
    STUB_RESTORE(pthread_key_create);
    STUB_RESTORE(mmap);
    STUB_RESTORE(pthread_setspecific);
    CHECK_REGRESS(BSL_ERR_GetLastError() == expected);
    CHECK_REGRESS(BSL_ERR_GetLastError() == BSL_SUCCESS);
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 1, 0) == BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static int g_setSpecificCalls;

static int CountSetSpecific(pthread_key_t key, const void *value)
{
    g_setSpecificCalls++;
    return get_real_pthread_setspecific()(key, value);
}

/* Re-entry resizes the pool without touching the thread local slot: neither
 * the clear nor the rebind of a rebuild happens, so a failure between them
 * cannot drop the domain. The first-initialization binding failure stays
 * covered by CheckInitError(3). */
static int CheckReinitKeepsSlot(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t result = 99;
    BSL_ASYNC_TaskParam param = {NULL, jobSync, NULL, 0};
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 0, 0) == BSL_SUCCESS);
    g_setSpecificCalls = 0;
    STUB_REPLACE(pthread_setspecific, CountSetSpecific);
    CHECK_REGRESS(BSL_ASYNC_InitThread(1, 1, 0) == BSL_SUCCESS);
    CHECK_REGRESS(g_setSpecificCalls == 0);
    STUB_RESTORE(pthread_setspecific);
    /* The domain kept alive by the untouched slot still schedules. */
    CHECK_REGRESS(BSL_ASYNC_StartTask(&task, &result, &param) == BSL_ASYNC_FINISH);
    CHECK_REGRESS(result == JOB_SYNC_RET);
    BSL_ASYNC_CleanupThread();
    return 0;
}

static void *ConcurrentInit(void *arg)
{
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        if (BSL_ASYNC_InitThread(1, 0, 0) != BSL_SUCCESS || BSL_ASYNC_GetCurrentTask() != NULL) {
            return (void *)(uintptr_t)1;
        }
        BSL_ASYNC_CleanupThread();
        if (BSL_ASYNC_GetCurrentTask() != NULL) {
            return (void *)(uintptr_t)2;
        }
    }
    return NULL;
}

static int CheckConcurrent(void)
{
    pthread_t workers[4];
    void *result;
    for (int i = 0; i < 4; i++) {
        CHECK_REGRESS(pthread_create(&workers[i], NULL, ConcurrentInit, NULL) == 0);
    }
    for (int i = 0; i < 4; i++) {
        CHECK_REGRESS(pthread_join(workers[i], &result) == 0 && result == NULL);
    }
    return 0;
}
/* END_HEADER */

/**
 * @test SDV_BSL_ASYNC_REGRESS_FUNC_TC001
 * @precon POSIX coroutine backend
 * @brief Inject scheduling and initialization failures in fresh child processes;
 *        verify retry, ownership, error-stack and resource reclamation contracts.
 * @expect Each scenario preserves outputs on failure and releases its resources.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_REGRESS_FUNC_TC001(int scenario)
{
    pid_t child;
    int status = 0;
    int result = 1;
    /* Scenarios 8 (process-lock allocation failure) and 17 (run-once
     * failure) exercise failure paths that exist without a backend; every
     * other scenario needs a working execution domain. */
    if (!ASYNC_BACKEND_READY() && scenario != 8 && scenario != 17) {
        SKIP_TEST();
    }
    /* Resolve interposed libc symbols before concurrent calls. */
    (void)get_real_BSL_SAL_ThreadRunOnce();
    (void)get_real_pthread_key_create();
    (void)get_real_pthread_key_delete();
    (void)get_real_pthread_setspecific();
    (void)get_real_swapcontext();
    (void)get_real_mmap();
    (void)get_real_munmap();
    child = fork();
    if (child == 0) {
        BSL_ERR_ClearError();
        switch (scenario) {
            case 1:
                result = CheckFinish();
                break;
            case 2:
                result = CheckPrivateKey();
                break;
            case 3:
                result = CheckConcurrent();
                break;
            case 5:
                result = CheckClear();
                break;
            case 6:
                result = CheckNestedResume();
                break;
            case 7:
                result = CheckExit(0);
                break;
            case 8:
                result = CheckLockFailure();
                break;
            case 9:
                result = CheckReinit();
                break;
            case 10:
                result = CheckTaskAllocation();
                break;
            case 11:
                result = CheckInitError(0);
                break;
            case 12:
                result = CheckInitError(1);
                break;
            case 13:
                result = CheckInitError(2);
                break;
            case 14:
                result = CheckInitError(3);
                break;
            case 15:
                result = CheckExit(1);
                break;
            case 16:
                result = CheckReinitKeepsSlot();
                break;
            case 17:
                result = CheckOnceFailure();
                break;
            default:
                break;
        }
        _exit(result);
    }
    ASSERT_TRUE(child > 0);
    ASSERT_TRUE(waitpid(child, &status, 0) == child);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0);
EXIT:
    return;
}
/* END_CASE */
