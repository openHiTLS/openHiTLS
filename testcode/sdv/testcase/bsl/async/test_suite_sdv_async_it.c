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
/* END_HEADER */

/**
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC060
 * @title  Execution domain lifecycle loop
 * @precon nan
 * @brief
 *    1. Initialize, drive 20 mixed rounds (alternating pausing and
 *       synchronous jobs, each pausing job resumed through its own handle),
 *       clean up, re-initialize with the same pool parameters and run two
 *       more jobs: no state may leak across the cycles.
 * @expect
 *    1. Every pausing round yields PAUSE then FINISH, every synchronous
 *       round yields FINISH; both initializations return BSL_SUCCESS and
 *       the business results are identical across the cycles.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC060(int maxTasks, int initialTasks)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    int32_t firstRet = 0;
    int i;
    BSL_ASYNC_TaskParam pauseParam = {0};
    BSL_ASYNC_TaskParam syncParam = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    pauseParam.func = jobPauseOnce;
    syncParam.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_InitThread((uint32_t)maxTasks, (uint32_t)initialTasks, 0), BSL_SUCCESS);
    for (i = 0; i < 20; i++) {
        task = NULL;
        if (i % 2 == 0) {
            ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &pauseParam), BSL_ASYNC_PAUSE);
            ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
        } else {
            ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &syncParam), BSL_ASYNC_FINISH);
            firstRet = ret;
        }
    }
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread((uint32_t)maxTasks, (uint32_t)initialTasks, 0), BSL_SUCCESS);
    for (i = 0; i < 2; i++) {
        task = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &syncParam), BSL_ASYNC_FINISH);
        ASSERT_EQ(ret, firstRet);
    }
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC061
 * @title  Task pool reuse under pressure and the NO_JOB limit
 * @precon nan
 * @brief
 *    1. 500 synchronous jobs on a pre-created pool of 4: all finish and no
 *       allocation happens after the first round.
 *    2. Four pausing jobs fill the pool, the fifth is rejected with NO_JOB;
 *       resuming one frees its slot for the fifth, then everything is
 *       resumed to completion.
 * @expect
 *    1. 500 times BSL_ASYNC_FINISH; allocation delta after round 1 is 0.
 *    2. Four times PAUSE, then NO_JOB with a NULL handle, PAUSE for the
 *       reused slot and FINISH for all five resumes.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC061(void)
{
    BSL_ASYNC_Task *tasks[5] = {0};
    int32_t ret = 0;
    uint32_t base = 0;
    int i;
    BSL_ASYNC_TaskParam syncParam = {0};
    BSL_ASYNC_TaskParam pauseParam = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    syncParam.func = jobSync;
    pauseParam.func = jobPauseOnce;
    InjectArm(-1);
    ASSERT_EQ(BSL_ASYNC_InitThread(4, 4, 0), BSL_SUCCESS);
    for (i = 0; i < 500; i++) {
        tasks[0] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[0], &ret, &syncParam), BSL_ASYNC_FINISH);
        if (i == 0) {
            base = g_allocCount;
        }
    }
    ASSERT_EQ(g_allocCount - base, 0);
    InjectDisarm();

    for (i = 0; i < 4; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    tasks[4] = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[4], &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    ASSERT_TRUE(tasks[4] == NULL);
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[0], &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[4], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    for (i = 1; i < 4; i++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, NULL), BSL_ASYNC_FINISH);
    }
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[4], &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC062
 * @title  Notify node state machine across seven rounds
 * @precon nan
 * @brief
 *    1. Drive one key through register, idle, re-register, idle, clear of
 *    the newest node, clear of the older node and reclaim: every round's
 *    change window matches the expected state transition and the
 *    application-side wait set bookkeeping ends empty.
 * @expect
 *    1. Windows: add {h1}/-, then empty, then add {h2}/-, then empty, then
 *       -/del {h2} with Get resolving to h1, then -/del {h1} with Get
 *       flipping to NOT_FOUND, then both empty with a zero all-source
 *       count.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC062(void)
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
    /* Round map: 1 register h1, 2 idle, 3 register h2 (both coexist), 4
     * idle, 5 clear the newest, 6 clear the older, 7 return; every round
     * ends with a pause except the last. */
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_PAUSE;
    args.ops[3] = SRC_OP_SET;
    args.values[3].key = &key1;
    args.values[3].handle = NTf_H2;
    args.ops[4] = SRC_OP_PAUSE;
    args.ops[5] = SRC_OP_PAUSE;
    args.ops[6] = SRC_OP_CLEAR;
    args.values[6].key = &key1;
    args.ops[7] = SRC_OP_PAUSE;
    args.ops[8] = SRC_OP_CLEAR;
    args.values[8].key = &key1;
    args.ops[9] = SRC_OP_PAUSE;
    args.opCount = 10;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Round 1: PENDING_ADD. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H1);
    /* Round 2: REGISTERED, no changes. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    /* Round 3: add h2, h1 stays registered. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H2);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H2);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 2);
    /* Round 4: both REGISTERED, no changes. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 0);
    /* Round 5: clear the newest, the older node stays. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(delBuf[0], NTf_H2);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_SUCCESS);
    ASSERT_EQ(handleOut, NTf_H1);
    /* Round 6: clear the older node too. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(delBuf[0], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetNotifySource(ctx, &key1, &handleOut, NULL), BSL_ASYNC_ERR_NOT_FOUND);
    /* Round 7: reclaimed, everything empty. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 0);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 0);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC063
 * @title  Change window lifetime around the resume point
 * @precon nan
 * @brief
 *    1. Two sources registered in one round: two consecutive reads report
 *       the identical window (read-only), the resume point consumes it and
 *       the task-side snapshot taken right after the resume observes both
 *       sources still present with the submit status at its initial value.
 * @expect
 *    1. Two identical reads with add {h1, h2}; after the resume the task
 *       snapshot counts 2 sources and status UNSUPPORTED; the next window
 *       is empty.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC063(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle addFirst[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;
    int key2 = 0;
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
    args.ops[1] = SRC_OP_SET;
    args.values[1].key = &key2;
    args.values[1].handle = NTf_H2;
    args.ops[2] = SRC_OP_PAUSE;
    /* Snapshot right after the resume point, then one more pause. */
    args.ops[3] = SRC_OP_SNAPSHOT;
    args.ops[4] = SRC_OP_PAUSE;
    args.opCount = 5;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 2);
    ASSERT_EQ(delN, 0);
    for (i = 0; i < addN; i++) {
        addFirst[i] = addBuf[i];
    }
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 2);
    for (i = 0; i < addN; i++) {
        ASSERT_EQ(addBuf[i], addFirst[i]);
    }
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.snapCount, 1);
    ASSERT_EQ(args.allCount, 2);
    ASSERT_EQ(args.lastStatus, BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
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
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC064
 * @title  Multiple tasks interleave without cross-talk
 * @precon nan
 * @brief
 *    1. Start three pausing tasks (1, 2 and 3 pause rounds) on one domain,
 *       then resume them in LIFO and FIFO orders: every task must keep its
 *       own state, log only its own counter sequence and finish exactly
 *       after its own number of rounds.
 * @expect
 *    1. Three PAUSE starts; the LIFO round yields PAUSE/PAUSE/FINISH and
 *       the FIFO round yields FINISH/PAUSE/FINISH; the counters end at
 *       1/2/3 and each log holds only its own sequence.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC064(void)
{
    BSL_ASYNC_Task *taskA = NULL;
    BSL_ASYNC_Task *taskB = NULL;
    BSL_ASYNC_Task *taskC = NULL;
    int32_t ret = 0;
    JobPauseNArgs argsA = {0};
    JobPauseNArgs argsB = {0};
    JobPauseNArgs argsC = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    argsA.rounds = 1;
    argsB.rounds = 2;
    argsC.rounds = 3;
    ASSERT_EQ(BSL_ASYNC_InitThread(3, 0, 0), BSL_SUCCESS);
    param.func = jobPauseN;
    ArgRef argsARef = {&argsA};
    param.args = &argsARef;
    param.argsSize = sizeof(argsARef);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskA, &ret, &param), BSL_ASYNC_PAUSE);
    ArgRef argsBRef = {&argsB};
    param.args = &argsBRef;
    param.argsSize = sizeof(argsBRef);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &ret, &param), BSL_ASYNC_PAUSE);
    ArgRef argsCRef = {&argsC};
    param.args = &argsCRef;
    param.argsSize = sizeof(argsCRef);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskC, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_TRUE(taskA != NULL && taskB != NULL && taskC != NULL);
    /* LIFO resume: C and B still have rounds left, A is done. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskC, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskA, &ret, NULL), BSL_ASYNC_FINISH);
    /* FIFO resume: B finishes, C needs its last round. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskC, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskC, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(argsA.counter, 1);
    ASSERT_EQ(argsB.counter, 2);
    ASSERT_EQ(argsC.counter, 3);
    ASSERT_EQ(argsA.logCount, 1);
    ASSERT_EQ(argsB.logCount, 2);
    ASSERT_EQ(argsC.logCount, 3);
    ASSERT_EQ(argsA.pauseLog[0], 1);
    ASSERT_EQ(argsB.pauseLog[0], 1);
    ASSERT_EQ(argsB.pauseLog[1], 2);
    ASSERT_EQ(argsC.pauseLog[0], 1);
    ASSERT_EQ(argsC.pauseLog[1], 2);
    ASSERT_EQ(argsC.pauseLog[2], 3);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC065
 * @title  Two tasks with independent notify contexts stay isolated
 * @precon nan
 * @brief
 *    1. Two concurrent requests hold two independent notify contexts: each
 *       registers its own source and pauses. Reading either context's
 *       change window and all-source count must reflect only its own
 *       registration, and finishing one task must not disturb the other's
 *       window.
 * @expect
 *    1. Both starts return PAUSE; the windows report add {hA} and add {hB}
 *       with one source each; after A finishes, ctxB's window and count
 *       are unchanged; B then finishes and both contexts free cleanly.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC065(void)
{
    BSL_ASYNC_NotifyCtx *ctxA = NULL;
    BSL_ASYNC_NotifyCtx *ctxB = NULL;
    BSL_ASYNC_Task *taskA = NULL;
    BSL_ASYNC_Task *taskB = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int keyA = 0;
    int keyB = 0;
    SrcJobArgs argsA = {0};
    SrcJobArgs argsB = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctxA = BSL_ASYNC_NotifyCtxNew();
    ctxB = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctxA != NULL && ctxB != NULL);
    argsA.ops[0] = SRC_OP_SET;
    argsA.values[0].key = &keyA;
    argsA.values[0].handle = NTf_H1;
    argsA.ops[1] = SRC_OP_PAUSE;
    argsA.opCount = 2;
    argsB.ops[0] = SRC_OP_SET;
    argsB.values[0].key = &keyB;
    argsB.values[0].handle = NTf_H2;
    argsB.ops[1] = SRC_OP_PAUSE;
    argsB.opCount = 2;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    param.func = jobSources;
    ArgRef argsARef = {&argsA};
    param.args = &argsARef;
    param.argsSize = sizeof(argsARef);
    param.notifyCtx = ctxA;
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskA, &ret, &param), BSL_ASYNC_PAUSE);
    ArgRef argsBRef = {&argsB};
    param.args = &argsBRef;
    param.argsSize = sizeof(argsBRef);
    param.notifyCtx = ctxB;
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &ret, &param), BSL_ASYNC_PAUSE);
    /* Each context sees only its own registration. */
    ASSERT_EQ(AsyncReadChanges(ctxA, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H1);
    ASSERT_EQ(AsyncReadChanges(ctxB, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], NTf_H2);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctxA, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 1);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctxB, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 1);
    /* Finishing A must not touch B's unconsumed window. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskA, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(AsyncReadChanges(ctxB, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(addBuf[0], NTf_H2);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctxB, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctxA);
    BSL_ASYNC_NotifyCtxFree(ctxB);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/**
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC066
 * @title  NotifyCallback and NotifyNode paths interleave on one domain
 * @precon nan
 * @brief
 *    1. One domain serves a callback-path request and a node-path request
 *       at the same time: the callback path publishes OK with no source
 *       registration, the node path registers its handle and publishes
 *       UNSUPPORTED; each completes through its own delivery mechanism and
 *       the submit statuses and change windows never mix.
 * @expect
 *    1. Both starts return PAUSE; statusA is OK, statusB is UNSUPPORTED;
 *       ctxA's window stays empty while ctxB's reports add {hB}; both
 *       resumes deliver FINISH and ctxB's window finally reports del {hB}
 *       with an empty registered set.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC066(void)
{
    BSL_ASYNC_NotifyCtx *ctxA = NULL;
    BSL_ASYNC_NotifyCtx *ctxB = NULL;
    BSL_ASYNC_Task *taskA = NULL;
    BSL_ASYNC_Task *taskB = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandle hB = 0;
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    MockReq reqA = {0};
    MockReq reqB = {0};
    MockArg cbArg = {0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int32_t status = 0;
    int keyB = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    g_ready.count = 0;
    ASSERT_EQ(AppWaitInit(), 0);
    ctxA = BSL_ASYNC_NotifyCtxNew();
    ctxB = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctxA != NULL && ctxB != NULL);
    cbArg.ret = BSL_SUCCESS;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(ctxA, mockCb, &cbArg), BSL_SUCCESS);
    ASSERT_EQ(MockWaitOpen(&reqB.wait), 0);
    hB = MockWaitHandle(&reqB.wait);
    reqA.ctx = ctxA;
    reqA.publishStatus = BSL_ASYNC_NOTIFY_STATUS_OK;
    reqA.deviceResult = MOCK_DEVICE_RET;
    reqB.ctx = ctxB;
    reqB.key = &keyB;
    reqB.deviceResult = MOCK_DEVICE_RET;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Callback-path request: the handle is backfilled after the pause. */
    ASSERT_EQ(mockSubmit(&taskA, &ret, ctxA, mockJob, &reqA), BSL_ASYNC_PAUSE);
    cbArg.task = taskA;
    /* Node-path request. */
    ASSERT_EQ(mockSubmit(&taskB, &ret, ctxB, mockJobSource, &reqB), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctxA, &status), BSL_SUCCESS);
    ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_OK);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctxB, &status), BSL_SUCCESS);
    ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED);
    /* The callback path produces no notify source. */
    ASSERT_EQ(AsyncReadChanges(ctxA, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(AsyncReadChanges(ctxB, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], hB);
    ASSERT_EQ(AppWaitAdd(hB), 0);
    /* Callback-path completion: AppPost then resume from the queue. */
    mockOnComplete(&reqA);
    ASSERT_EQ(g_ready.count, 1);
    ASSERT_TRUE(AppPop() == taskA);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskA, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, MOCK_DEVICE_RET);
    /* Node-path completion: signal, wait, resume, unregister. */
    mockOnComplete(&reqB);
    ASSERT_TRUE(AppWaitWait(1000) == hB);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctxB, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(delBuf[0], hB);
    ASSERT_EQ(AppWaitRemove(hB), 0);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, MOCK_DEVICE_RET);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctxB, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 0);
    ASSERT_EQ(AppWaitContains(hB), 0);
    BSL_ASYNC_NotifyCtxFree(ctxA);
    BSL_ASYNC_NotifyCtxFree(ctxB);
    BSL_ASYNC_CleanupThread();
    MockWaitClose(&reqB.wait);
    AppWaitDeinit();
EXIT:
    BSL_ASYNC_CleanupThread();
    MockWaitClose(&reqB.wait);
    AppWaitDeinit();
    return;
}
/* END_CASE */
#endif /* HITLS_BSL_SAL_LINUX || HITLS_BSL_SAL_DARWIN */

/**
 * @test   SDV_BSL_ASYNC_IT_FUNC_TC067
 * @title  One task registers and clears sources over many rounds
 * @precon nan
 * @brief
 *    1. A long-running task waits once per round, rotating to a new key and
 *       handle each time and clearing the previous key right after the
 *       resume: the previous round's node must be reclaimed at the resume
 *       point, so the registration never accumulates.
 * @expect
 *    1. Every round's all-source count is 1; the round-2 window reports
 * add {h2} and del {h1} (the previous key's clear, per the state
 *       machine); after the finish the count is 0 and the window reports
 *       del {h3} only.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_IT_FUNC_TC067(void)
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
    int key2 = 0;
    int key3 = 0;
    SrcJobArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    /* Round N: register {keyN, hN} and pause; after the resume clear keyN.
     * The clear of a registered key lands in the next round's window. */
    args.ops[0] = SRC_OP_SET;
    args.values[0].key = &key1;
    args.values[0].handle = NTf_H1;
    args.ops[1] = SRC_OP_PAUSE;
    args.ops[2] = SRC_OP_CLEAR;
    args.values[2].key = &key1;
    args.ops[3] = SRC_OP_SET;
    args.values[3].key = &key2;
    args.values[3].handle = NTf_H2;
    args.ops[4] = SRC_OP_PAUSE;
    args.ops[5] = SRC_OP_CLEAR;
    args.values[5].key = &key2;
    args.ops[6] = SRC_OP_SET;
    args.values[6].key = &key3;
    args.values[6].handle = ((BSL_ASYNC_NotifyHandle)0x33);
    args.ops[7] = SRC_OP_PAUSE;
    args.ops[8] = SRC_OP_CLEAR;
    args.values[8].key = &key3;
    args.opCount = 9;
    param.notifyCtx = ctx;
    param.func = jobSources;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Round 1: one source registered. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    /* Round 2: the previous node was reclaimed at the resume point, the
     * clear of key1 is visible as a deletion alongside the new add. */
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 1);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(addBuf[0], NTf_H2);
    ASSERT_EQ(delBuf[0], NTf_H1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    /* Round 3: still exactly one source. */
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    /* After the finish: nothing left, the last clear is the only change. */
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 0);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(delBuf[0], ((BSL_ASYNC_NotifyHandle)0x33));
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */
