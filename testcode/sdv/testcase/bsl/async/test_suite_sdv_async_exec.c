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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bsl_async.h"
#include "bsl_errno.h"
/* END_HEADER */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC001
 * @title  BSL_ASYNC_IsSupported capability query without side effects
 * @precon nan
 * @brief
 *    1. With the counting allocator armed, call IsSupported three times: the
 *       values must be identical and match the build expectation (true with
 *       a backend, false on the no-backend build) with zero allocations.
 *    2. Initialize after the probe, re-check the value and clean up.
 * @expect
 *    1. Three identical values matching the build; allocation delta is 0.
 *    2. InitThread succeeds with a backend and returns STATE_CONFLICT
 *       without one; the probe value is unchanged.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC001(void)
{
    int val = 0;
    uint32_t before = 0;

    InjectArm(-1);
    before = g_allocCount;
    val = BSL_ASYNC_IsSupported() ? 1 : 0;
    ASSERT_EQ(BSL_ASYNC_IsSupported(), val);
    ASSERT_EQ(BSL_ASYNC_IsSupported(), val);
    if (ASYNC_BACKEND_READY()) {
        ASSERT_EQ(val, 1);
    } else {
        ASSERT_EQ(val, 0);
    }
    ASSERT_EQ(g_allocCount - before, 0);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), val ? BSL_SUCCESS : BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(BSL_ASYNC_IsSupported(), val);
    BSL_ASYNC_CleanupThread();
    InjectDisarm();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC002
 * @title  BSL_ASYNC_InitThread parameter bounds and re-initialization
 * @precon nan
 * @brief
 *    1. initialTasks > maxTasks is rejected with BSL_INVALID_ARG and leaves
 *       the thread uninitialized, including the maxTasks == 0 (no limit) case.
 *    2. maxTasks == 0 means no limit: initialization succeeds and concurrent
 *       pausing jobs never hit BSL_ASYNC_NO_JOB.
 *    3. A non-zero stack size is accepted as given; repeated initialization
 *       with the same resolved stack size resizes the pool in place, after
 *       which scheduling works.
 * @expect
 *    1. BSL_INVALID_ARG for both invalid parameter sets.
 *    2. BSL_SUCCESS for the unlimited initialization; five times PAUSE and
 *       five times FINISH with no NO_JOB in between.
 *    3. BSL_SUCCESS for init, re-init and the custom stack size; a job runs
 *       to BSL_ASYNC_FINISH on the resized domain.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC002(void)
{
    BSL_ASYNC_Task *tasks[5] = {0};
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    int i;
    BSL_ASYNC_TaskParam param = {0};
    BSL_ASYNC_TaskParam pauseParam = {0};

    param.func = jobSync;
    pauseParam.func = jobPauseOnce;
    ASSERT_EQ(BSL_ASYNC_InitThread(0, 1, 0), BSL_INVALID_ARG);
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(1, 2, 0), BSL_INVALID_ARG);
    BSL_ASYNC_CleanupThread();
    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 64 * 1024), BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(0, 0, 0), BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(0, 0, 0), BSL_SUCCESS);
    for (i = 0; i < 5; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    for (i = 0; i < 5; i++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, NULL), BSL_ASYNC_FINISH);
    }
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC003
 * @title  BSL_ASYNC_InitThread and StartTask rejected on a task stack
 * @precon nan
 * @brief
 *    1. From inside a task, InitThread returns BSL_ASYNC_ERR_STATE_CONFLICT
 *       and StartTask returns BSL_ASYNC_ERR with STATE_CONFLICT on top of
 *       the error stack.
 *    2. jobMisuse also calls CleanupThread on the task stack: it must be a
 *       no-op there, so a normal job still finishes afterwards on the same
 *       domain and only the later host-side cleanup really releases it.
 * @expect
 *    1. rets[0] == BSL_ASYNC_ERR_STATE_CONFLICT; rets[1] == BSL_ASYNC_ERR
 *       with BSL_ERR_PeekLastError() == BSL_ASYNC_ERR_STATE_CONFLICT.
 *    2. The follow-up job returns BSL_ASYNC_FINISH on the same domain.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC003(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    JobMisuseArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};
    BSL_ASYNC_TaskParam syncParam = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    param.func = jobMisuse;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(args.rets[0], BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(args.rets[1], BSL_ASYNC_ERR);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_ASYNC_ERR_STATE_CONFLICT);
    syncParam.func = jobSync;
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &syncParam), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC004
 * @title  BSL_ASYNC_InitThread pre-created tasks stay idle
 * @precon nan
 * @brief
 *    1. Initialize with initialTasks == maxTasks: the pre-created tasks only
 *       occupy pool capacity (no outstanding task), the cleanup reclaims
 *       them and a second initialization with jobs works the same.
 * @expect
 *    1. BSL_SUCCESS both times; three consecutive jobs all reach
 *       BSL_ASYNC_FINISH with the business return value.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC004(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t rets[3] = {0};
    int i;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_InitThread(3, 3, 0), BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(3, 3, 0), BSL_SUCCESS);
    for (i = 0; i < 3; i++) {
        task = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&task, &rets[i], &param), BSL_ASYNC_FINISH);
        ASSERT_EQ(rets[i], JOB_SYNC_RET);
    }
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC005
 * @title  BSL_ASYNC_InitThread rolls back a mid-way allocation failure
 * @precon nan
 * @brief Fail domain, pool, host or task allocation, then retry initialization.
 * @expect The specified error is pushed once, no domain remains, and retry schedules a job.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC005(int failAtN, int expectedErr)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
    BSL_ERR_ClearError();
    InjectArm(failAtN - 1);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 2, 0), expectedErr);
    ASSERT_EQ(BSL_ERR_GetLastError(), expectedErr);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 2, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC006
 * @title  BSL_ASYNC_CleanupThread abandons an outstanding paused task
 * @precon nan
 * @brief
 *    1. Cleanup on an uninitialized thread is a no-op.
 *    2. With a paused task outstanding, cleanup records a diagnostic and
 * abandons it (not reclaimed); the stale handle then
 *       resumes to BSL_ASYNC_WRONG_EXEC_CTX without being modified, the
 *       thread can be re-initialized and a new job finishes.
 *    3. The abandoning sequence runs in a forked child: the deliberately
 *       leaked task must not surface as a LeakSanitizer report of the
 *       suite process, and the child's exit code carries the verdict.
 * @expect
 *    1. No error channel; the cleanup on the uninitialized thread is a no-op.
 *    2. BSL_ASYNC_PAUSE from the job; WRONG_EXEC_CTX with the handle
 *       preserved; BSL_SUCCESS re-init; BSL_ASYNC_FINISH for the new job.
 *    3. The child exits 0.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC006(void)
{
    pid_t child = -1;
    int status = 0;
    int isChild = 0;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_Task *stale = NULL;
    int32_t ret = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }

    child = fork();
    ASSERT_TRUE(child >= 0);
    if (child != 0) {
        /* Parent: the child's exit code is the verdict; no async object is
         * inherited here, so the abandoned task cannot leak into the suite
         * process (and its LeakSanitizer verdict). */
        ASSERT_TRUE(waitpid(child, &status, 0) == child);
        ASSERT_TRUE(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        return;
    }
    isChild = 1;

    /* Child: the original sequence. The abandoned task stays allocated by
     * design; _exit below skips the suite's leak check for it. */
    BSL_ASYNC_CleanupThread();
    param.func = jobPauseOnce;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    BSL_ASYNC_CleanupThread();
    stale = task;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_WRONG_EXEC_CTX);
    ASSERT_TRUE(task == stale);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    param.func = jobSync;
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    if (isChild != 0) {
        /* Only the forked child exits here; a parent-side assertion failure
         * must be reported through the framework, not terminate the suite. */
        _exit(g_testResult.result == TEST_RESULT_SUCCEED ? 0 : 1);
    }
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC007
 * @title  BSL_ASYNC_CleanupThread release and re-initialization cycle
 * @precon nan
 * @brief
 *    1. Walk init, job, cleanup, cleanup-again, re-init, job, cleanup: the
 *       second cycle must behave exactly like the first.
 * @expect
 *    1. Both jobs return BSL_ASYNC_FINISH with equal business results; the
 *       extra cleanup is a no-op.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC007(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret1 = 0;
    int32_t ret2 = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret1, &param), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret2, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret1, ret2);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC008
 * @title  BSL_ASYNC_StartTask first start completes synchronously
 * @precon nan
 * @brief
 *    1. Start a job that never pauses: the first StartTask already returns
 *       BSL_ASYNC_FINISH, delivers the business value and clears the handle.
 * @expect
 *    1. BSL_ASYNC_FINISH with ret == JOB_SYNC_RET and task == NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC008(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobSync;
    param.args = NULL;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC009
 * @title  BSL_ASYNC_StartTask parameter validation
 * @precon nan
 * @brief
 *    1. NULL task, NULL ret, NULL param and a NULL func are all rejected
 *       with BSL_ASYNC_ERR and BSL_NULL_INPUT on the error stack, and the
 *       sentinel handle is never modified.
 * @expect
 *    1. Four rejections, each with BSL_ERR_PeekLastError() ==
 *       BSL_NULL_INPUT; task keeps the sentinel value.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC009(void)
{
    BSL_ASYNC_Task *task = (BSL_ASYNC_Task *)0x5A5A;
    int32_t ret = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    /* Adapted from the test design: a non-NULL *task selects the resume
     * path, which by design neither reads nor validates param, so
     * the param/func validations are exercised in the first-start form
     * (*task == NULL) while the sentinel form covers the task-argument and
     * ret validations, whose checks precede the path split. */
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    param.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_StartTask(NULL, &ret, &param), BSL_ASYNC_ERR);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, NULL, &param), BSL_ASYNC_ERR);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_NULL_INPUT);
    ASSERT_TRUE(task == (BSL_ASYNC_Task *)0x5A5A);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_ERR);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_NULL_INPUT);
    ASSERT_TRUE(task == NULL);
    param.func = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_ERR);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_NULL_INPUT);
    ASSERT_TRUE(task == NULL);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC010
 * @title  BSL_ASYNC_StartTask default init, call environment and capability
 * @precon nan
 * @brief
 *    1. On a backend build: an uninitialized thread gets the implicit
 *       default initialization from StartTask and the job finishes; misuse
 *       from a task stack is rejected; a fresh init works afterwards.
 *    2. On the no-backend build: StartTask reports BSL_ASYNC_UNSUPPORTED
 *       before creating anything (no allocation, no domain).
 * @expect
 *    1. BSL_ASYNC_FINISH with the default initialization; rets[1] ==
 *       BSL_ASYNC_ERR with STATE_CONFLICT on the stack.
 *    2. BSL_ASYNC_UNSUPPORTED with the handle NULL and allocation delta 0.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC010(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    JobMisuseArgs args = {0};
    uint32_t before = 0;
    BSL_ASYNC_TaskParam param = {0};
    BSL_ASYNC_TaskParam misuseParam = {0};

    param.func = jobSync;
    if (!ASYNC_BACKEND_READY()) {
        InjectArm(-1);
        before = g_allocCount;
        ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_UNSUPPORTED);
        ASSERT_TRUE(task == NULL);
        ASSERT_EQ(g_allocCount - before, 0);
        BSL_ASYNC_CleanupThread();
        InjectDisarm();
        return;
    }
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    misuseParam.func = jobMisuse;
    ArgRef argsRef = {&args};
    misuseParam.args = &argsRef;
    misuseParam.argsSize = sizeof(argsRef);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &misuseParam), BSL_ASYNC_FINISH);
    ASSERT_EQ(args.rets[1], BSL_ASYNC_ERR);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_ASYNC_ERR_STATE_CONFLICT);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC011
 * @title  BSL_ASYNC_StartTask pool limit reports NO_JOB
 * @precon nan
 * @brief
 *    1. With maxTasks == 1: the first job pauses, the second is rejected
 *       with BSL_ASYNC_NO_JOB; after the first finishes, the slot is reused
 *       by the second request.
 * @expect
 *    1. PAUSE, NO_JOB with a NULL handle, FINISH on resume, then PAUSE and
 *       FINISH for the reused slot.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC011(void)
{
    BSL_ASYNC_Task *taskA = NULL;
    BSL_ASYNC_Task *taskB = NULL;
    int32_t retA = 0;
    int32_t retB = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobPauseOnce;
    ASSERT_EQ(BSL_ASYNC_InitThread(1, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskA, &retA, &param), BSL_ASYNC_PAUSE);
    ASSERT_TRUE(taskA != NULL);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &retB, &param), BSL_ASYNC_NO_JOB);
    ASSERT_TRUE(taskB == NULL);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskA, &retA, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(retA, JOB_SYNC_RET);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &retB, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskB, &retB, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC012
 * @title  BSL_ASYNC_START PAUSE result output contract
 * @precon nan
 * @brief
 *    1. On BSL_ASYNC_PAUSE the handle refers to the paused task and the ret
 *       output keeps its caller value; the resume delivers the business
 *       value and clears the handle.
 * @expect
 *    1. ret stays 0x5A5A across the pause; after the resume ret ==
 *       JOB_SYNC_RET and task == NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC012(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0x5A5A;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobPauseOnce;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_TRUE(task != NULL);
    ASSERT_EQ(ret, 0x5A5A);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC013
 * @title  BSL_ASYNC_StartTask resume
 * @precon nan
 * @brief
 *    1. The job publishes OK and pauses; the host reads OK; the resume
 *       returns BSL_ASYNC_FINISH.
 * @expect
 *    1. BSL_ASYNC_PAUSE; host status OK; BSL_ASYNC_FINISH.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC013(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    int32_t status = 0;
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    JobWithCtxArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.setStatus = BSL_ASYNC_NOTIFY_STATUS_OK;
    args.rounds = 1;
    param.notifyCtx = ctx;
    param.func = jobWithCtx;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_OK);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC014
 * @title  BSL_ASYNC_StartTask resume-time error keeps the handle
 * @precon nan
 * @brief
 *    1. Resuming a handle whose task is no longer paused (a finished and
 *       recycled task) fails with BSL_ASYNC_ERR and STATE_CONFLICT on the
 *       stack, keeps the handle value and leaves a genuinely paused task
 *       untouched.
 * @expect
 *    1. BSL_ASYNC_ERR with BSL_ERR_PeekLastError() ==
 *       BSL_ASYNC_ERR_STATE_CONFLICT; the stale handle is unchanged; the
 *       paused task still resumes to BSL_ASYNC_FINISH.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC014(void)
{
    BSL_ASYNC_Task *taskP = NULL;
    BSL_ASYNC_Task *stale = NULL;
    int32_t ret = 0;
    JobRecordSelfArgs recArgs = {0};
    BSL_ASYNC_TaskParam param = {0};
    BSL_ASYNC_TaskParam recParam = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobPauseOnce;
    recParam.func = jobRecordSelf;
    ArgRef recArgsRef = {&recArgs};
    recParam.args = &recArgsRef;
    recParam.argsSize = sizeof(recArgsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskP, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&stale, &ret, &recParam), BSL_ASYNC_FINISH);
    /* The FINISH invalidated the caller's slot; the recorded physical
     * pointer is now owned by the pool as an IDLE task. Resuming it must
     * fail on the state check without touching the handle. */
    stale = recArgs.taskSeen;
    ASSERT_EQ(BSL_ASYNC_StartTask(&stale, &ret, NULL), BSL_ASYNC_ERR);
    ASSERT_EQ(BSL_ERR_PeekLastError(), BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_TRUE(stale == recArgs.taskSeen);
    ASSERT_EQ(BSL_ASYNC_StartTask(&taskP, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_TRUE(taskP == NULL);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC015
 * @title  Physical tasks are reused after recycling
 * @precon nan
 * @brief
 *    1. Run 50 synchronous jobs on a single-task pool: every round observes
 *       the same physical task pointer and no allocation happens after the
 *       first round.
 * @expect
 *    1. 50 times BSL_ASYNC_FINISH; exactly one distinct task pointer; the
 *       allocation count does not grow after round 1.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC015(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    BSL_ASYNC_Task *seen[50] = {0};
    uint32_t distinct = 0;
    uint32_t afterFirst = 0;
    uint32_t base = 0;
    int i;
    int j;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    /* no argument buffer: the argument copy-in would allocate once per
     * round, but this case proves the POOL reuses the physical task with
     * zero allocation; jobRecordSelf reports through the global sink */
    param.func = jobRecordSelf;
    InjectArm(-1);
    ASSERT_EQ(BSL_ASYNC_InitThread(1, 1, 0), BSL_SUCCESS);
    for (i = 0; i < 50; i++) {
        g_recordTaskSeen = NULL;
        task = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
        seen[i] = g_recordTaskSeen;
        if (i == 0) {
            base = g_allocCount;
        }
    }
    afterFirst = g_allocCount;
    InjectDisarm();
    ASSERT_EQ(afterFirst - base, 0);
    for (i = 0; i < 50; i++) {
        int found = 0;
        for (j = 0; j < i; j++) {
            if (seen[j] == seen[i]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            distinct++;
        }
    }
    ASSERT_EQ(distinct, 1);
    BSL_ASYNC_CleanupThread();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC016
 * @title  BSL_ASYNC_GetCurrentTask in three environments
 * @precon nan
 * @brief
 *    1. On an uninitialized thread and on the host stack the result is NULL;
 *       inside a task it is non-NULL and TaskGetNotifyCtx returns the bound
 *       context.
 * @expect
 *    1. NULL, NULL, then a non-NULL task with ctxSeen equal to the bound
 *       context.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC016(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    JobRecordSelfArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    ASSERT_TRUE(BSL_ASYNC_GetCurrentTask() == NULL);
    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_TRUE(BSL_ASYNC_GetCurrentTask() == NULL);
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    param.notifyCtx = ctx;
    param.func = jobRecordSelf;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_TRUE(args.taskSeen != NULL);
    ASSERT_TRUE(args.ctxSeen == ctx);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC017
 * @title  BSL_ASYNC_TaskGetNotifyCtx binding and borrowing semantics
 * @precon nan
 * @brief
 *    1. A bound task reads back its context, an unbound task reads NULL, a
 *       NULL handle reads NULL and a finished (non-running) task reads NULL;
 *       the context object itself stays usable.
 * @expect
 *    1. ctxSeen == ctx for the bound case; NULL for the other three;
 *       NotifyCtxGetStatus still returns BSL_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC017(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    int32_t status = 0;
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    JobRecordSelfArgs bound = {0};
    JobRecordSelfArgs unbound = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    param.func = jobRecordSelf;
    param.notifyCtx = ctx;
    ArgRef boundRef = {&bound};
    param.args = &boundRef;
    param.argsSize = sizeof(boundRef);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_TRUE(bound.ctxSeen == ctx);
    param.notifyCtx = NULL;
    ArgRef unboundRef = {&unbound};
    param.args = &unboundRef;
    param.argsSize = sizeof(unboundRef);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_TRUE(unbound.ctxSeen == NULL);
    ASSERT_TRUE(BSL_ASYNC_TaskGetNotifyCtx(NULL) == NULL);
    ASSERT_TRUE(BSL_ASYNC_TaskGetNotifyCtx(bound.taskSeen) == NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC019
 * @title  Pause/resume loop with multi-round resume points
 * @precon nan
 * @brief
 *    1. A job pauses three times, publishing OK before every pause; each
 *       host read is OK; the fourth drive finishes the job.
 * @expect
 *    1. Three times BSL_ASYNC_PAUSE with host status OK; then
 *       BSL_ASYNC_FINISH; counter == 3.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC019(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    int32_t status = 0;
    int i;
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    JobPauseNArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    args.rounds = 3;
    param.notifyCtx = ctx;
    param.func = jobPauseN;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    for (i = 0; i < 3; i++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
        ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
        ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_OK);
    }
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(args.counter, 3);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC020
 * @title  Pause does not switch while the block count is non-zero
 * @precon nan
 * @brief
 *    1. The job pauses inside the shielded region (success, no switch), sets
 *       the inside flag, releases the shield and pauses for real; the host
 *       sees exactly one pause and the flags order the execution.
 * @expect
 *    1. BSL_ASYNC_PAUSE from the single real pause; pauseRet ==
 *       BSL_SUCCESS; flagInside set and flagAfter not set before the resume,
 *       set after it.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC020(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    JobBlockPauseArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobBlockPause;
    ArgRef argsRef = {&args};
    param.args = &argsRef;
    param.argsSize = sizeof(argsRef);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(args.pauseRet, BSL_SUCCESS);
    ASSERT_EQ(args.flagInside, 1);
    ASSERT_EQ(args.flagAfter, 0);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(args.flagAfter, 1);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC021
 * @title  BSL_ASYNC_BlockPause/UnblockPause counting semantics
 * @precon nan
 * @brief
 *    1. Nested shields of depth 1 and 3 each produce exactly one real
 *       pause; unblocking at depth zero is a no-op that does not underflow
 *       (the shielded pause stays a no-op and the final pause happens after
 *       the flag is set); host-side calls change nothing.
 * @expect
 *    1. Each variant pauses exactly once; flagBeforeFinalPause is set before
 *       the host sees the pause; a further nested-block job still pauses
 *       once after the host-side misuse.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC021(int depth)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    JobNestedBlockArgs nestArgs = {0};
    JobUnblockAtZeroArgs zeroArgs = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    nestArgs.depth = (uint32_t)depth;
    param.func = jobNestedBlock;
    ArgRef nestArgsRef = {&nestArgs};
    param.args = &nestArgsRef;
    param.argsSize = sizeof(nestArgsRef);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);

    param.func = jobUnblockAtZero;
    ArgRef zeroArgsRef = {&zeroArgs};
    param.args = &zeroArgsRef;
    param.argsSize = sizeof(zeroArgsRef);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(zeroArgs.flagBeforeFinalPause, 1);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);

    /* Host-side misuse: no-ops that must not pollute the counter. */
    BSL_ASYNC_BlockPause();
    BSL_ASYNC_UnblockPause();

    param.func = jobNestedBlock;
    param.args = &nestArgsRef;
    param.argsSize = sizeof(nestArgsRef);
    nestArgs.depth = 1;
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC022
 * @title  Unpaired block depth converges at task completion
 * @precon nan
 * @brief
 *    1. A job that blocks without unblocking still finishes; the depth is
 *       cleared by the convergence step, so the next task can pause again.
 * @expect
 *    1. BSL_ASYNC_FINISH for the unpaired job; BSL_ASYNC_PAUSE then
 *       BSL_ASYNC_FINISH for the follow-up job.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC022(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobBlockNoUnblock;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    param.func = jobPauseOnce;
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC023
 * @title  TaskParam argument snapshot is one-way
 * @precon nan
 * @brief
 *    1. Start jobCopyWitness with a raw argument buffer: the first start
 *       copies it, the entry sets rounds to 1 on its copy and pauses.
 *    2. While paused, overwrite the caller's buffer with a different value.
 *    3. Resume: the entry returns the copy's state and finishes.
 * @expect
 *    1. The entry reported its own copy (ret == 1), not the caller's
 *       mid-pause write (99): the entry runs on the first-start copy.
 *    2. The caller's buffer keeps the mid-pause 99: the copy is never
 *       written back at any scheduling boundary.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC023(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    JobCopyArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    param.func = jobCopyWitness;
    param.args = &args;
    param.argsSize = sizeof(args);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    /* the caller's write while paused must stay invisible to the task */
    args.rounds = 99;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    /* the entry reported its own copy: the mutation it made before pausing */
    ASSERT_EQ(ret, 1);
    /* no write-back: the caller's buffer keeps its mid-pause value */
    ASSERT_EQ(args.rounds, 99u);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC024
 * @title  TaskParam argument contract: args and argsSize must agree
 * @precon nan
 * @brief
 *    1. Start a job with a non-NULL args and argsSize 0.
 *    2. Start a job with args NULL and a non-zero argsSize.
 *    3. Start the no-argument form (args NULL, argsSize 0).
 * @expect
 *    1. Both mismatches return BSL_ASYNC_ERR with BSL_INVALID_ARG on the
 *       error stack; no task handle is created.
 *    2. The no-argument form finishes normally with the entry seeing NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC024(void)
{
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    JobCopyArgs args = {0};
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    param.func = jobSync;
    param.args = &args;
    param.argsSize = 0;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_ERR);
    ASSERT_TRUE(task == NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_INVALID_ARG);

    (void)memset(&param, 0, sizeof(param));
    param.func = jobSync;
    param.args = NULL;
    param.argsSize = sizeof(args);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_ERR);
    ASSERT_TRUE(task == NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_INVALID_ARG);

    (void)memset(&param, 0, sizeof(param));
    param.func = jobSync;
    task = NULL;
    ret = 0;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC025
 * @title  Re-initialization scales the pool up in place
 * @precon nan
 * @brief
 *    1. Re-entering InitThread with a larger initialTasks pre-creates the
 *       difference while an outstanding task exists: with allocation
 *       counting armed, the pre-created tasks serve new jobs without any
 *       allocation and the raised limit admits on-demand creation only.
 *    2. A paused handle issued before the re-entry stays resumable: the
 *       execution domain survives the pool resize untouched.
 * @expect
 *    1. Both re-entries return BSL_SUCCESS; the counting window shows zero
 *       allocations for the pre-created jobs and exactly one task creation
 *       when the pool grows beyond the pre-created count.
 *    2. The pre-re-entry handle resumes to BSL_ASYNC_FINISH with the
 *       business value after the scale-up.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC025(void)
{
    BSL_ASYNC_Task *tasks[6] = {0};
    BSL_ASYNC_Task *task = NULL;
    int32_t ret = 0;
    uint32_t base = 0;
    int i;
    BSL_ASYNC_TaskParam pauseParam = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    pauseParam.func = jobPauseOnce;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 2, 0), BSL_SUCCESS);
    /* One outstanding handle to carry across the resize. */
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &pauseParam), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_InitThread(4, 4, 0), BSL_SUCCESS);
    InjectArm(-1);
    base = g_allocCount;
    for (i = 0; i < 3; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    /* Three idle tasks were pre-created by the re-entry: no allocation. */
    ASSERT_EQ(g_allocCount - base, 0u);
    tasks[3] = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[3], &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    ASSERT_TRUE(tasks[3] == NULL);
    InjectDisarm();
    /* The pre-re-entry handle still belongs to the surviving domain. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    for (i = 0; i < 3; i++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, NULL), BSL_ASYNC_FINISH);
        ASSERT_EQ(ret, JOB_SYNC_RET);
    }
    /* Raising maxTasks alone adds no task and frees the limit. */
    InjectArm(-1);
    base = g_allocCount;
    ASSERT_EQ(BSL_ASYNC_InitThread(6, 4, 0), BSL_SUCCESS);
    for (i = 0; i < 4; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    /* Four recycled idle tasks served without allocation. */
    ASSERT_EQ(g_allocCount - base, 0u);
    for (i = 4; i < 6; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    /* Two on-demand creations, then the raised limit reports full. */
    ASSERT_EQ(g_allocCount - base, 4u);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    InjectDisarm();
    for (i = 0; i < 6; i++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, NULL), BSL_ASYNC_FINISH);
        ASSERT_EQ(ret, JOB_SYNC_RET);
    }
    BSL_ASYNC_CleanupThread();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_EXEC_FUNC_TC026
 * @title  Re-initialization resize, rejection and rollback semantics
 * @precon nan
 * @brief
 *    1. A scale-down with no outstanding task releases the idle tasks
 *       beyond the target without any allocation; the resized pool enforces
 *       the new population and limit.
 *    2. A scale-down below the outstanding count is rejected with
 *       BSL_INVALID_ARG and keeps the pool unchanged; shrinking exactly to
 *       the outstanding count succeeds and the paused handle stays
 *       resumable across it.
 *    3. A stack size resolving differently from the domain's is rejected
 *       with BSL_ASYNC_ERR_STATE_CONFLICT.
 *    4. A scale-up whose allocation fails mid-way rolls back to the previous
 *       pool: the old limit still applies and the retry succeeds.
 * @expect
 *    1. BSL_SUCCESS with a zero allocation delta; two jobs pause, the third
 *       reports BSL_ASYNC_NO_JOB.
 *    2. BSL_INVALID_ARG pushed exactly once; after the accepted shrink the
 *       next start reports BSL_ASYNC_NO_JOB and the carried handle resumes
 *       to BSL_ASYNC_FINISH.
 *    3. BSL_ASYNC_ERR_STATE_CONFLICT pushed exactly once.
 *    4. BSL_MALLOC_FAIL pushed exactly once, the old NO_JOB boundary holds,
 *       the retry returns BSL_SUCCESS and four jobs pause before the fifth
 *       reports BSL_ASYNC_NO_JOB.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_EXEC_FUNC_TC026(void)
{
    BSL_ASYNC_Task *tasks[4] = {0};
    BSL_ASYNC_Task *extra = NULL;
    int32_t ret = 0;
    uint32_t base = 0;
    int i;
    BSL_ASYNC_TaskParam pauseParam = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    pauseParam.func = jobPauseOnce;
    /* Scale-down with nothing outstanding: the idle surplus is released
     * without a single allocation and the new count and limit apply. */
    ASSERT_EQ(BSL_ASYNC_InitThread(4, 4, 0), BSL_SUCCESS);
    InjectArm(-1);
    base = g_allocCount;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 2, 0), BSL_SUCCESS);
    ASSERT_EQ(g_allocCount - base, 0u);
    InjectDisarm();
    for (i = 0; i < 2; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    extra = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&extra, &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    ASSERT_TRUE(extra == NULL);
    for (i = 0; i < 2; i++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, NULL), BSL_ASYNC_FINISH);
    }
    /* Scale-down below the outstanding count is rejected; shrinking exactly
     * to the outstanding count releases the idle surplus and the paused
     * handle survives the resize. */
    for (i = 0; i < 2; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_ASYNC_InitThread(1, 1, 0), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[0], &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(BSL_ASYNC_InitThread(1, 1, 0), BSL_SUCCESS);
    extra = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&extra, &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[1], &ret, NULL), BSL_ASYNC_FINISH);
    tasks[0] = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[0], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    extra = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&extra, &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[0], &ret, NULL), BSL_ASYNC_FINISH);
    /* A stack size resolving differently from the domain's is rejected. */
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_ASYNC_InitThread(4, 4, 64 * 1024), BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    /* Mid-way scale-up failure: the first new task is created, the second
     * allocation fails, the rollback restores the previous pool. */
    InjectArm(2);
    ASSERT_EQ(BSL_ASYNC_InitThread(4, 4, 0), BSL_MALLOC_FAIL);
    InjectDisarm();
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_MALLOC_FAIL);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    tasks[0] = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[0], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    extra = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&extra, &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[0], &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(BSL_ASYNC_InitThread(4, 4, 0), BSL_SUCCESS);
    for (i = 0; i < 4; i++) {
        tasks[i] = NULL;
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, &pauseParam), BSL_ASYNC_PAUSE);
    }
    extra = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&extra, &ret, &pauseParam), BSL_ASYNC_NO_JOB);
    ASSERT_TRUE(extra == NULL);
    for (i = 0; i < 4; i++) {
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &ret, NULL), BSL_ASYNC_FINISH);
        ASSERT_EQ(ret, JOB_SYNC_RET);
    }
    BSL_ASYNC_CleanupThread();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */
