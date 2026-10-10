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
#include "bsl_async.h"
#include "bsl_errno.h"

#define NTf_H1 ((BSL_ASYNC_NotifyHandle)0x11)
#define NTf_H2 ((BSL_ASYNC_NotifyHandle)0x22)
#define NTf_H3 ((BSL_ASYNC_NotifyHandle)0x33)
#define NTf_H4 ((BSL_ASYNC_NotifyHandle)0x44)
#define NTf_HS ((BSL_ASYNC_NotifyHandle)0x77)

/* Counting cleanup callback: records key and handle of every invocation. */
static uint32_t g_cleanupCount = 0;
static const void *g_cleanupKeys[16] = {0};
static BSL_ASYNC_NotifyHandle g_cleanupHandles[16] = {0};

static void countCleanup(BSL_ASYNC_NotifyCtx *ctx, const void *key, BSL_ASYNC_NotifyHandle handle, void *userData)
{
    (void)ctx;
    (void)userData;
    if (g_cleanupCount < 16) {
        g_cleanupKeys[g_cleanupCount] = key;
        g_cleanupHandles[g_cleanupCount] = handle;
    }
    g_cleanupCount++;
}

/* Zero-arg stub callbacks for the set/get round trips. */
static int32_t cb1(void *arg)
{
    (void)arg;
    return BSL_SUCCESS;
}

static int32_t cb2(void *arg)
{
    (void)arg;
    return BSL_SUCCESS;
}

/* Publishes the configured submit status once and returns without pausing
 * (TC028 step 4: the out-of-range write is rejected, the task still finishes). */
static int32_t jobSetStatusNoPause(void *args)
{
    JobWithCtxArgs *a = (JobWithCtxArgs *)((ArgRef *)args)->shared;
    BSL_ASYNC_Task *self = BSL_ASYNC_GetCurrentTask();
    BSL_ASYNC_NotifyCtx *ctx = BSL_ASYNC_TaskGetNotifyCtx(self);
    if (ctx == NULL) {
        return -1;
    }
    a->setStatusRet = BSL_ASYNC_NotifyCtxSetStatus(ctx, a->setStatus);
    return JOB_SYNC_RET;
}
/* END_HEADER */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC023
 * @title  BSL_ASYNC_NotifyCtxNew initial values and preconditions
 * @precon nan
 * @brief
 *    1. Create a context on a thread without an execution domain: the
 *       initial submit status is UNSUPPORTED, no callback is set and the
 *       all-source count is zero.
 * @expect
 *    1. Non-NULL context; status UNSUPPORTED; callback and arg NULL;
 *       numHandles == 0.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC023(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_NotifyCallback cb = NULL;
    void *cbArg = NULL;
    int32_t status = 0;
    BSL_ASYNC_NotifyHandleList list = {NULL, 0, 0};

    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetCallback(ctx, &cb, &cbArg), BSL_SUCCESS);
    ASSERT_TRUE(cb == NULL);
    ASSERT_TRUE(cbArg == NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &list), BSL_SUCCESS);
    ASSERT_EQ(list.numHandles, 0);
    BSL_ASYNC_NotifyCtxFree(ctx);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC024
 * @title  BSL_ASYNC_NotifyCtxNew allocation failure
 * @precon nan
 * @brief
 *    1. With the next allocation forced to fail the creation returns NULL
 *       with BSL_MALLOC_FAIL on the error stack; a retry succeeds.
 * @expect
 *    1. NULL with the reason on the stack; non-NULL after the retry.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC024(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;

    InjectArm(0);
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx == NULL);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_MALLOC_FAIL);
    InjectDisarm();
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    BSL_ASYNC_NotifyCtxFree(ctx);
EXIT:
    InjectDisarm();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC025
 * @title  BSL_ASYNC_NotifyCtxFree runs every node cleanup exactly once
 * @precon nan
 * @brief
 *    1. Register three sources in one task round, let them become
 *       REGISTERED at the resume point, finish the task and free the
 *       context: each key's cleanup runs exactly once; Free(NULL) is safe.
 * @expect
 *    1. Three cleanups, one per key, each with the registered handle;
 *       Free(NULL) neither crashes nor touches the error stack.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC025(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    int k1 = 0;
    int k2 = 0;
    int k3 = 0;
    uint32_t cleanupBefore = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &k1;
    args.values[0].handle = NTf_H1;
    args.values[0].cleanup = countCleanup;
    args.ops[1] = SRC_OP_SET;
    args.values[1].key = &k2;
    args.values[1].handle = NTf_H2;
    args.values[1].cleanup = countCleanup;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &k3;
    args.values[2].handle = NTf_H3;
    args.values[2].cleanup = countCleanup;
    args.ops[3] = SRC_OP_PAUSE;
    args.opCount = 4;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    cleanupBefore = g_cleanupCount;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    ASSERT_EQ(g_cleanupCount - cleanupBefore, 3);
    /* Nodes are reclaimed in list order (newest registration first). */
    ASSERT_TRUE(g_cleanupKeys[cleanupBefore + 0] == (const void *)&k3);
    ASSERT_EQ(g_cleanupHandles[cleanupBefore + 0], NTf_H3);
    ASSERT_TRUE(g_cleanupKeys[cleanupBefore + 1] == (const void *)&k2);
    ASSERT_EQ(g_cleanupHandles[cleanupBefore + 1], NTf_H2);
    ASSERT_TRUE(g_cleanupKeys[cleanupBefore + 2] == (const void *)&k1);
    ASSERT_EQ(g_cleanupHandles[cleanupBefore + 2], NTf_H1);
    BSL_ASYNC_NotifyCtxFree(NULL);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC026
 * @title  BSL_ASYNC_NotifyCallback set, query and clear
 * @precon nan
 * @brief
 *    1. Install, query, clear and query again; clearing drops the argument
 *       with the callback; the NULL-input matrix is rejected.
 * @expect
 *    1. cb1/&a1 round trip; after clearing both read NULL; the three NULL
 *       variants return BSL_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC026(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_NotifyCallback cb = NULL;
    void *cbArg = NULL;
    int a1 = 0;
    int a2 = 0;

    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(ctx, cb1, &a1), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetCallback(ctx, &cb, &cbArg), BSL_SUCCESS);
    ASSERT_TRUE(cb == cb1);
    ASSERT_TRUE(cbArg == &a1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(ctx, NULL, &a2), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetCallback(ctx, &cb, &cbArg), BSL_SUCCESS);
    ASSERT_TRUE(cb == NULL);
    ASSERT_TRUE(cbArg == NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetCallback(NULL, &cb, &cbArg), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetCallback(ctx, NULL, &cbArg), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetCallback(ctx, &cb, NULL), BSL_NULL_INPUT);
    BSL_ASYNC_NotifyCtxFree(ctx);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC027
 * @title  SetCallback validates only its input, not outstanding tasks
 * @precon nan
 * @brief
 *    1. While a task bound to the context is paused, replacing the callback
 * succeeds (the timing is a caller guarantee) and
 *       the new pair reads back; the paused task still resumes.
 * @expect
 *    1. BSL_SUCCESS for the replacement; cb2/&a2 read back; the resume
 *       returns BSL_ASYNC_FINISH; SetCallback(NULL,...) fails with
 *       BSL_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC027(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyCallback cb = NULL;
    void *cbArg = NULL;
    int32_t ret = 0;
    int a1 = 0;
    int a2 = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(ctx, cb1, &a1), BSL_SUCCESS);
    param.notifyCtx = ctx;
    param.func = jobPauseOnce;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(ctx, cb2, &a2), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetCallback(ctx, &cb, &cbArg), BSL_SUCCESS);
    ASSERT_TRUE(cb == cb2);
    ASSERT_TRUE(cbArg == &a2);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(NULL, cb2, &a2), BSL_NULL_INPUT);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC028
 * @title  Submit status write and read
 * @precon nan
 * @brief
 *    1. Every legal status value round trips through Set/Get; an
 *       out-of-range value is rejected with BSL_INVALID_ARG and the
 *       previous value survives.
 * @expect
 *    1. Four legal values read back; setStatusRet == BSL_INVALID_ARG for
 *       0x7F with the old value intact.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC028(int statusToSet)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    int32_t status = 0;
    int32_t preStatus = 0;
    JobWithCtxArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.setStatus = statusToSet;
    args.rounds = 1;
    param.notifyCtx = ctx;
    param.func = jobWithCtx;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, statusToSet);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    /* Design step 4: re-read the post-resume value, then a task writes the
     * out-of-range 0x7F: rejected, the previous value survives and the task
     * finishes without pausing. */
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    preStatus = status;
    args.setStatus = 0x7F;
    args.setStatusRet = 0;
    param.func = jobSetStatusNoPause;
    task = NULL;
    ret = -1;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);
    ASSERT_EQ(args.setStatusRet, BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, preStatus);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetStatus(NULL, BSL_ASYNC_NOTIFY_STATUS_OK), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(NULL, &status), BSL_NULL_INPUT);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC029
 * @title  SetNotifySource registers a new source
 * @precon nan
 * @brief
 *    1. A first registration lands in the addition set, is queryable by key
 *       and the NULL-input matrix is rejected.
 * @expect
 *    1. Set returns BSL_SUCCESS; the change window counts 1 addition and 0
 *       deletions with handle1 in the addition set; Get returns handle1;
 *       Set with a NULL ctx or key returns BSL_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC029(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.opCount = 2;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[0], BSL_SUCCESS);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetNotifySource(NULL, &key1, NTf_H1, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetNotifySource(ctx, NULL, NTf_H1, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC030
 * @title  Repeated registration appends one node per call
 * @precon nan
 * @brief
 *    1. Register the same triple, then the same key with a new handle, all
 *       inside one round: every call succeeds and appends a node, the
 *       addition set lists each registration newest first with no
 *       deletion, and a single clear removes only the newest registration.
 * @expect
 *    1. Three BSL_SUCCESS returns; add == {handle2, handle1, handle1},
 *       del empty, all-source count 3; after one clear the count is 2 and
 *       Get returns handle1.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC030(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_SET;
    args.values[1].key = &key1;
    args.values[1].handle = NTf_H1;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &key1;
    args.values[2].handle = NTf_H2;
    args.ops[3] = SRC_OP_PAUSE;
    args.opCount = 4;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[0], BSL_SUCCESS);
    ASSERT_EQ(args.rets[1], BSL_SUCCESS);
    ASSERT_EQ(args.rets[2], BSL_SUCCESS);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 3);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H2);
    ASSERT_EQ(addBuf[1], NTf_H1);
    ASSERT_EQ(addBuf[2], NTf_H1);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 3);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H2);
    /* One clear removes the newest registration only. */
    ASSERT_EQ(BSL_ASYNC_NotifyCtxClearNotifySource(ctx, &key1), BSL_SUCCESS);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 2);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC031
 * @title  A repeated registration after the resume point coexists
 * @precon nan
 * @brief
 *    1. After the first registration became REGISTERED at the resume point,
 *       registering a new handle appends a second node without deleting
 *       the first: the change window reports add {handle2} and no
 *       deletion, both handles stay in the all-source list and the key
 *       resolves to the new handle.
 * @expect
 *    1. Two pauses; add == {handle2}, del empty, all-source count 2; Get
 *       returns handle2; the final resume finishes the task.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC031(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &key1;
    args.values[2].handle = NTf_H2;
    args.ops[3] = SRC_OP_PAUSE;
    args.opCount = 4;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(addBuf[0], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H2);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 2);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H2);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC032
 * @title  Attribute changes append registrations
 * @precon nan
 * @brief
 *    1. A REGISTERED node whose handle stays but userData changes appends
 *       a node carrying the same handle; two more handle changes within
 *       one round append two nodes: the addition set lists the new values
 *       newest first with no deletion and the key resolves to the last
 *       value.
 * @expect
 *    1. Round 2: add {handle1} and no deletion, the key resolves to
 *       handle1 with the new data, all-source count 2; round 3: add
 *       {handle3, handle2}, no deletion, all-source count 4.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC032(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    void *dataOut = NULL;
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    int d1 = 1;
    int d2 = 2;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.values[0].userData = &d1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &key1;
    args.values[2].handle = NTf_H1;
    args.values[2].userData = &d2;
    args.ops[3] = SRC_OP_PAUSE;
    args.ops[4] = SRC_OP_SET;
    args.values[4].key = &key1;
    args.values[4].handle = NTf_H2;
    args.values[4].userData = &d2;
    args.ops[5] = SRC_OP_SET;
    args.values[5].key = &key1;
    args.values[5].handle = NTf_H3;
    args.values[5].userData = &d2;
    args.ops[6] = SRC_OP_PAUSE;
    args.opCount = 7;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, &dataOut), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    ASSERT_TRUE(dataOut == &d2);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 2);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 2);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H3);
    ASSERT_EQ(addBuf[1], NTf_H2);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 4);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, &dataOut), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H3);
    ASSERT_TRUE(dataOut == &d2);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC033
 * @title  Re-registering a deleting key appends a node; no limit
 * @precon nan
 * @brief
 *    1. Clearing a REGISTERED key and immediately registering it again
 *       succeeds: the window reports add {h2} / del {h1}; after the resume
 *       point consumed the deletion, registering the same triple again
 *       appends a second node for the key. Registering 40 distinct keys on
 *       a fresh context all succeed and enumerate as 40.
 * @expect
 *    1. clearThenSetRet and setAfterResetRet == BSL_SUCCESS; the window
 *       matches add {h2} / del {h1}; after the task finishes the key holds
 *       two nodes; 40 registrations succeed with numHandles == 40.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC033(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[8] = {0};
    BSL_ASYNC_NotifyHandle delBuf[8] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    int keys[40] = {0};
    uint32_t i;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_CLEAR;
    args.values[2].key = &key1;
    args.ops[3] = SRC_OP_SET;
    args.values[3].key = &key1;
    args.values[3].handle = NTf_H2;
    args.ops[4] = SRC_OP_PAUSE;
    args.ops[5] = SRC_OP_SET;
    args.values[5].key = &key1;
    args.values[5].handle = NTf_H2;
    args.opCount = 6;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[2], BSL_SUCCESS);
    ASSERT_EQ(args.rets[3], BSL_SUCCESS);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(addBuf[0], NTf_H2);
    ASSERT_EQ(delBuf[0], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(args.rets[5], BSL_SUCCESS);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 2);
    BSL_ASYNC_NotifyCtxFree(ctx);

    /* No limit on the number of registrations (40 > the historical 32). */
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    param.notifyCtx = ctx;
    for (i = 0; i < 40; i++) {
        args.ops[i] = SRC_OP_SET;
        args.values[i].key = &keys[i];
        args.values[i].handle = (BSL_ASYNC_NotifyHandle)(0x100 + i);
    }
    args.ops[40] = SRC_OP_PAUSE;
    args.opCount = 41;
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    for (i = 0; i < 40; i++) {
        ASSERT_EQ(args.rets[i], BSL_SUCCESS);
    }
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 40);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC034
 * @title  A failing node allocation rolls back
 * @precon nan
 * @brief
 *    1. With the next allocation forced to fail, registering a third source
 *       returns BSL_MALLOC_FAIL, neither the existing registrations nor the
 *       change window are affected and the domain keeps working.
 * @expect
 *    1. setSourceRet == BSL_MALLOC_FAIL; all-source count stays 2; the
 *       addition set does not contain the third handle; the resume and the
 *       following rounds finish.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC034(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[8] = {0};
    BSL_ASYNC_NotifyHandle delBuf[8] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    int key2 = 0;
    int key3 = 0;
    uint32_t i;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &key2;
    args.values[2].handle = NTf_H2;
    args.ops[3] = SRC_OP_PAUSE;
    args.opCount = 4;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    /* Both registrations are REGISTERED now; the third round injects.
     * Skip one allocation: the TaskParam copy-in of this start allocates
     * first, the notify-source node is the second allocation after arming. */
    InjectArm(1);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key3;
    args.values[0].handle = NTf_H3;
    args.ops[1] = SRC_OP_PAUSE;
    args.opCount = 2;
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    InjectDisarm();
    ASSERT_EQ(args.rets[0], BSL_MALLOC_FAIL);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 2);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    for (i = 0; i < addN; i++) {
        ASSERT_TRUE(addBuf[i] != NTf_H3);
    }
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC035
 * @title  GetNotifySource query semantics
 * @precon nan
 * @brief
 *    1. A REGISTERED node resolves with handle and userData; a deleting key
 *       and an unknown key report BSL_ASYNC_ERR_NOT_FOUND; the NULL-input
 *       matrix is rejected.
 * @expect
 *    1. Registered: BSL_SUCCESS with handle1 and &d1; deleting and unknown:
 *       BSL_ASYNC_ERR_NOT_FOUND; the three NULL variants:
 *       BSL_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC035(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle handleOut = 0;
    void *dataOut = NULL;
    int32_t ret = 0;
    int key1 = 0;
    int key2 = 0;
    int key3 = 0;
    int d1 = 1;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.values[0].userData = &d1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &key2;
    args.values[2].handle = NTf_H2;
    args.ops[3] = SRC_OP_PAUSE;
    args.ops[4] = SRC_OP_CLEAR;
    args.values[4].key = &key2;
    args.ops[5] = SRC_OP_PAUSE;
    args.opCount = 6;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, &dataOut), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    ASSERT_TRUE(dataOut == &d1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key3, &handleOut, NULL), BSL_ASYNC_ERR_NOT_FOUND);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key2, &handleOut, NULL), BSL_ASYNC_ERR_NOT_FOUND);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(NULL, &key1, &handleOut, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, NULL, &handleOut, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, NULL, NULL), BSL_NULL_INPUT);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC036
 * @title  GetAllNotifySources two-phase query
 * @precon nan
 * @brief
 *    1. Count with handles == NULL (a PENDING_DEL node is not counted),
 *       fetch with exact capacity, then reject with capacity-1: the
 *       required count is reported and the buffer is left untouched; the
 *       NULL-input matrix is rejected. Handles are listed newest first.
 * @expect
 *    1. Count 3; fetch writes the three registered handles newest first;
 *       the capacity-1 call returns BSL_ASYNC_ERR_CAPACITY_EXCEEDED with
 *       numHandles 3 and the sentinel buffer intact.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC036(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandleList list = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle buf[4] = {0};
    int32_t ret = 0;
    int keys[4] = {0};
    uint32_t i;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    for (i = 0; i < 4; i++) {
        args.ops[i * 2] = SRC_OP_SET;
        args.values[i * 2].key = &keys[i];
        args.values[i * 2].handle = NTf_H1 + i;
        args.ops[i * 2 + 1] = SRC_OP_PAUSE;
    }
    args.ops[8] = SRC_OP_CLEAR;
    args.values[8].key = &keys[3];
    args.ops[9] = SRC_OP_PAUSE;
    args.opCount = 10;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Rounds: four registrations, then the clear of the fourth key. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    list.handles = NULL;
    list.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &list), BSL_SUCCESS);
    ASSERT_EQ(list.numHandles, 3);
    list.handles = buf;
    list.capacity = 3;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &list), BSL_SUCCESS);
    ASSERT_EQ(list.numHandles, 3);
    /* Newest registration first: keys[2], keys[1], keys[0]. */
    for (i = 0; i < 3; i++) {
        ASSERT_EQ(buf[i], NTf_H1 + 2 - i);
    }
    buf[0] = (BSL_ASYNC_NotifyHandle)0x5A5A;
    buf[1] = (BSL_ASYNC_NotifyHandle)0x5A5A;
    buf[2] = (BSL_ASYNC_NotifyHandle)0x5A5A;
    list.capacity = 2;
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &list), BSL_ASYNC_ERR_CAPACITY_EXCEEDED);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_ASYNC_ERR_CAPACITY_EXCEEDED);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    ASSERT_EQ(list.numHandles, 3);
    ASSERT_EQ(buf[0], (BSL_ASYNC_NotifyHandle)0x5A5A);
    ASSERT_EQ(buf[1], (BSL_ASYNC_NotifyHandle)0x5A5A);
    ASSERT_EQ(buf[2], (BSL_ASYNC_NotifyHandle)0x5A5A);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(NULL, &list), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, NULL), BSL_NULL_INPUT);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC037
 * @title  ClearNotifySource on a pending addition and on misses
 * @precon nan
 * @brief
 *    1. A registration cleared inside the same round never enters the
 *       change window; clearing an unknown key reports
 *       BSL_ASYNC_ERR_NOT_FOUND; the NULL-input matrix is rejected.
 * @expect
 *    1. Both in-round calls return BSL_SUCCESS with both windows empty and
 *       a zero all-source count; the unknown key and NULL variants return
 *       BSL_ASYNC_ERR_NOT_FOUND / BSL_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC037(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    int key9 = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_CLEAR;
    args.values[1].key = &key1;
    args.ops[2] = SRC_OP_PAUSE;
    args.opCount = 3;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[0], BSL_SUCCESS);
    ASSERT_EQ(args.rets[1], BSL_SUCCESS);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 0);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 0);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxClearNotifySource(ctx, &key9), BSL_ASYNC_ERR_NOT_FOUND);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxClearNotifySource(NULL, &key1), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxClearNotifySource(ctx, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC038
 * @title  ClearNotifySource removes one registration per call, newest first
 * @precon nan
 * @brief
 *    1. Key A holds one registration and key B two: clearing key A twice
 *       succeeds idempotently, while the two clears of key B remove its
 *       newest and then its older node; the deletion set lists all three
 *       handles newest first and the resume point consumes them.
 * @expect
 *    1. Four BSL_SUCCESS returns; add count 0, del count 3 in the order
 *       {h3, h2, h1}; after the consumption Get reports
 *       BSL_ASYNC_ERR_NOT_FOUND for both keys and both windows are empty.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC038(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[8] = {0};
    BSL_ASYNC_NotifyHandle delBuf[8] = {0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int keyA = 0;
    int keyB = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &keyA;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &keyB;
    args.values[2].handle = NTf_H2;
    args.ops[3] = SRC_OP_PAUSE;
    args.ops[4] = SRC_OP_SET;
    args.values[4].key = &keyB;
    args.values[4].handle = NTf_H3;
    args.ops[5] = SRC_OP_PAUSE;
    args.ops[6] = SRC_OP_CLEAR;
    args.values[6].key = &keyA;
    args.ops[7] = SRC_OP_CLEAR;
    args.values[7].key = &keyA;
    args.ops[8] = SRC_OP_CLEAR;
    args.values[8].key = &keyB;
    args.ops[9] = SRC_OP_CLEAR;
    args.values[9].key = &keyB;
    args.ops[10] = SRC_OP_PAUSE;
    args.ops[11] = SRC_OP_PAUSE;
    args.opCount = 12;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[6], BSL_SUCCESS);
    ASSERT_EQ(args.rets[7], BSL_SUCCESS);
    ASSERT_EQ(args.rets[8], BSL_SUCCESS);
    ASSERT_EQ(args.rets[9], BSL_SUCCESS);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 3);
    ASSERT_EQ(delBuf[0], NTf_H3);
    ASSERT_EQ(delBuf[1], NTf_H2);
    ASSERT_EQ(delBuf[2], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &keyA, &handleOut, NULL), BSL_ASYNC_ERR_NOT_FOUND);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &keyB, &handleOut, NULL), BSL_ASYNC_ERR_NOT_FOUND);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC039
 * @title  Change window counts and set contents
 * @precon nan
 * @brief
 *    1. Drive keys into the different states (two pending additions, one
 *       deleting, one registered untouched and one registered then
 *       re-registered) and check that the window reports exactly the
 *       additions and the deletion, and never the untouched registered
 *       handles.
 * @expect
 *    1. add == {h_add, h4}, del == {h_del}; h_keep in neither set; the
 *       all-source count is 4 (the re-registered key holds two nodes).
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC039(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[8] = {0};
    BSL_ASYNC_NotifyHandle delBuf[8] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int kAdd = 0;
    int k1 = 0;
    int kDel = 0;
    int kKeep = 0;
    uint32_t i;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &k1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_SET;
    args.values[1].key = &kDel;
    args.values[1].handle = NTf_H2;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &kKeep;
    args.values[2].handle = NTf_H3;
    args.ops[3] = SRC_OP_PAUSE;
    args.ops[4] = SRC_OP_SET;
    args.values[4].key = &k1;
    args.values[4].handle = NTf_H4;
    args.ops[5] = SRC_OP_CLEAR;
    args.values[5].key = &kDel;
    args.ops[6] = SRC_OP_SET;
    args.values[6].key = &kAdd;
    args.values[6].handle = NTf_HS;
    args.ops[7] = SRC_OP_PAUSE;
    args.opCount = 8;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 2);
    ASSERT_EQ(delN, 1);
    ASSERT_TRUE((addBuf[0] == NTf_HS && addBuf[1] == NTf_H4) || (addBuf[0] == NTf_H4 && addBuf[1] == NTf_HS));
    ASSERT_EQ(delBuf[0], NTf_H2);
    for (i = 0; i < addN; i++) {
        ASSERT_TRUE(addBuf[i] != NTf_H3);
    }
    for (i = 0; i < delN; i++) {
        ASSERT_TRUE(delBuf[i] != NTf_H3);
    }
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 4);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC040
 * @title  Change window capacity rejection and read-only semantics
 * @precon nan
 * @brief
 *    1. With two additions and two deletions in the window (two keys
 *       cleared, two keys registered): an undersized addition list fails
 *       with BSL_ASYNC_ERR_CAPACITY_EXCEEDED, reports both counts and
 *       writes nothing; after enlarging, two consecutive reads return
 *       identical sets; the NULL-input matrix is rejected.
 * @expect
 *    1. EXCEEDED with counts 2/2 and sentinel buffers; two identical
 *       successful reads; the three NULL variants return BSL_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC040(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandleList addList = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandleList delList = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandle addFirst[4] = {0};
    int32_t ret = 0;
    int k1 = 0;
    int k2 = 0;
    int k3 = 0;
    int k4 = 0;
    uint32_t i;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &k1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_SET;
    args.values[1].key = &k2;
    args.values[1].handle = NTf_H2;
    args.ops[2] = SRC_OP_PAUSE;
    args.ops[3] = SRC_OP_CLEAR;
    args.values[3].key = &k1;
    args.ops[4] = SRC_OP_CLEAR;
    args.values[4].key = &k2;
    args.ops[5] = SRC_OP_SET;
    args.values[5].key = &k3;
    args.values[5].handle = NTf_H3;
    args.ops[6] = SRC_OP_SET;
    args.values[6].key = &k4;
    args.values[6].handle = NTf_H4;
    args.ops[7] = SRC_OP_PAUSE;
    args.opCount = 8;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    addBuf[0] = (BSL_ASYNC_NotifyHandle)0x5A5A;
    addBuf[1] = (BSL_ASYNC_NotifyHandle)0x5A5A;
    delBuf[0] = (BSL_ASYNC_NotifyHandle)0x5A5A;
    delBuf[1] = (BSL_ASYNC_NotifyHandle)0x5A5A;
    addList.handles = addBuf;
    addList.capacity = 1;
    delList.handles = delBuf;
    delList.capacity = 4;
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &addList, &delList), BSL_ASYNC_ERR_CAPACITY_EXCEEDED);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_ASYNC_ERR_CAPACITY_EXCEEDED);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    ASSERT_EQ(addList.numHandles, 2);
    ASSERT_EQ(delList.numHandles, 2);
    ASSERT_EQ(addBuf[0], (BSL_ASYNC_NotifyHandle)0x5A5A);
    ASSERT_EQ(delBuf[0], (BSL_ASYNC_NotifyHandle)0x5A5A);
    addList.capacity = 4;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &addList, &delList), BSL_SUCCESS);
    for (i = 0; i < 2; i++) {
        addFirst[i] = addBuf[i];
    }
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &addList, &delList), BSL_SUCCESS);
    for (i = 0; i < 2; i++) {
        ASSERT_EQ(addBuf[i], addFirst[i]);
    }
    /* Newest first: additions {handle4, handle3}, deletions {handle2, handle1}. */
    ASSERT_EQ(addBuf[0], NTf_H4);
    ASSERT_EQ(addBuf[1], NTf_H3);
    ASSERT_EQ(delBuf[0], NTf_H2);
    ASSERT_EQ(delBuf[1], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetChangedNotifySources(NULL, &addList, &delList), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, NULL, &delList), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetChangedNotifySources(ctx, &addList, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC041
 * @title  Multiple keys evolve independently in one round
 * @precon nan
 * @brief
 *    1. In one round: re-register key A with a new handle (its first node
 *       stays registered), clear key B and register key C: the window
 *       reports add {h2, hc} and del {hb}, the all-source count excludes B,
 *       and the single-key queries resolve accordingly.
 * @expect
 *    1. add {h2, hc}; del {hb}; count 3 (key A holds two nodes); A -> h2,
 *       C -> hc, B -> NOT_FOUND.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC041(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[8] = {0};
    BSL_ASYNC_NotifyHandle delBuf[8] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int kA = 0;
    int kB = 0;
    int kC = 0;
    uint32_t i;
    int h2Seen = 0;
    int hcSeen = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &kA;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &kB;
    args.values[2].handle = NTf_H2;
    args.ops[3] = SRC_OP_PAUSE;
    args.ops[4] = SRC_OP_SET;
    args.values[4].key = &kA;
    args.values[4].handle = NTf_H3;
    args.ops[5] = SRC_OP_CLEAR;
    args.values[5].key = &kB;
    args.ops[6] = SRC_OP_SET;
    args.values[6].key = &kC;
    args.values[6].handle = NTf_H4;
    args.ops[7] = SRC_OP_PAUSE;
    args.opCount = 8;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[4], BSL_SUCCESS);
    ASSERT_EQ(args.rets[5], BSL_SUCCESS);
    ASSERT_EQ(args.rets[6], BSL_SUCCESS);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 2);
    ASSERT_EQ(delN, 1);
    for (i = 0; i < addN; i++) {
        h2Seen += (addBuf[i] == NTf_H3);
        hcSeen += (addBuf[i] == NTf_H4);
    }
    ASSERT_EQ(h2Seen, 1);
    ASSERT_EQ(hcSeen, 1);
    ASSERT_EQ(delBuf[0], NTf_H2);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 3);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &kA, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H3);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &kC, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H4);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &kB, &handleOut, NULL), BSL_ASYNC_ERR_NOT_FOUND);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC042
 * @title  Two keys may register the same handle value
 * @precon nan
 * @brief
 *    1. Two keys register the same handle: the addition set reports it
 *       twice and the all-source count is 2; after both become REGISTERED,
 *       clearing only the first key leaves the second untouched.
 * @expect
 *    1. add count 2 with both elements hSame; count 2; the deletion set
 *       after clearing key1 is {hSame} and key2 still resolves to hSame.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC042(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[8] = {0};
    BSL_ASYNC_NotifyHandle delBuf[8] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int k1 = 0;
    int k2 = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &k1;
    args.values[0].handle = NTf_HS;
    args.ops[1] = SRC_OP_SET;
    args.values[1].key = &k2;
    args.values[1].handle = NTf_HS;
    args.ops[2] = SRC_OP_PAUSE;
    args.ops[3] = SRC_OP_CLEAR;
    args.values[3].key = &k1;
    args.ops[4] = SRC_OP_PAUSE;
    args.opCount = 5;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[0], BSL_SUCCESS);
    ASSERT_EQ(args.rets[1], BSL_SUCCESS);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 2);
    ASSERT_EQ(addBuf[0], NTf_HS);
    ASSERT_EQ(addBuf[1], NTf_HS);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 2);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 8, &addN, delBuf, 8, &delN), BSL_SUCCESS);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(delBuf[0], NTf_HS);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &k2, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_HS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC043
 * @title  The same key accumulates registrations over consecutive rounds
 * @precon nan
 * @brief
 *    1. A registered key is registered three more times with new handles:
 *       every window reports the new value as the only addition with no
 *       deletion, the all-source count grows by one per round and the key
 *       resolves to the latest value.
 * @expect
 *    1. Windows {h2}/-, {h3}/-, {h4}/-; the all-source count is 2, 3, 4;
 *       Get returns h4.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC043(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    BSL_ASYNC_NotifyHandle handleOut = 0;
    BSL_ASYNC_NotifyHandle expectAdd[3] = {NTf_H2, NTf_H3, NTf_H4};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    int round;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_SET;
    args.values[2].key = &key1;
    args.values[2].handle = NTf_H2;
    args.ops[3] = SRC_OP_PAUSE;
    args.ops[4] = SRC_OP_SET;
    args.values[4].key = &key1;
    args.values[4].handle = NTf_H3;
    args.ops[5] = SRC_OP_PAUSE;
    args.ops[6] = SRC_OP_SET;
    args.values[6].key = &key1;
    args.values[6].handle = NTf_H4;
    args.ops[7] = SRC_OP_PAUSE;
    args.opCount = 8;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    for (round = 0; round < 3; round++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
        ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
        ASSERT_EQ(addN, 1);
        ASSERT_EQ(delN, 0);
        ASSERT_EQ(addBuf[0], expectAdd[round]);
        all.handles = NULL;
        all.capacity = 0;
        ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
        ASSERT_EQ(all.numHandles, (uint32_t)(round + 2));
    }
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H4);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_NOTIFY_FUNC_TC044
 * @title  A source registered with NULL userData
 * @precon nan
 * @brief
 *    1. Register with userData == NULL and a cleanup callback: the query
 *       succeeds with a NULL userData, and freeing the context runs the
 *       cleanup exactly once with the registered key and handle.
 * @expect
 *    1. Set returns BSL_SUCCESS; queries succeed with dataOut == NULL;
 *       cleanup count 1 with key == &key1 and handle == handle1.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NOTIFY_FUNC_TC044(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle handleOut = 0;
    void *dataOut = NULL;
    int32_t ret = 0;
    int key1 = 0;
    uint32_t cleanupBefore = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.values[0].userData = NULL;
    args.values[0].cleanup = countCleanup;
    args.ops[1] = SRC_OP_PAUSE;
    args.opCount = 2;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    cleanupBefore = g_cleanupCount;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.rets[0], BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, &dataOut), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    ASSERT_TRUE(dataOut == NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    ASSERT_EQ(g_cleanupCount - cleanupBefore, 1);
    ASSERT_TRUE(g_cleanupKeys[cleanupBefore] == (const void *)&key1);
    ASSERT_EQ(g_cleanupHandles[cleanupBefore], NTf_H1);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */
