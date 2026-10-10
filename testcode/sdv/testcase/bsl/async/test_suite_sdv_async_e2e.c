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
#include <string.h>
#include "bsl_async.h"
#include "bsl_base64.h"
#include "bsl_err.h"
#include "bsl_errno.h"

#define E2E_H1 ((BSL_ASYNC_NotifyHandle)0x11)

/* One round of existing synchronous operations (TC72/TC73): a succeeding
 * Base64 encode and a failing decode; records the return codes, the output
 * buffer and the error code pushed by the failure. */
static void SyncOpRound(int32_t *encRet, char *encOut, uint32_t encCap, int32_t *decRet, int32_t *decErr)
{
    static const uint8_t src[5] = {'h', 'e', 'l', 'l', 'o'};
    static const char badB64[] = "aG!sbG8=";
    uint8_t decOut[8] = {0};
    uint32_t len = encCap;

    BSL_ERR_ClearError();
    *encRet = BSL_BASE64_Encode(src, sizeof(src), encOut, &len);
    BSL_ERR_ClearError();
    len = sizeof(decOut);
    *decRet = BSL_BASE64_Decode(badB64, (uint32_t)strlen(badB64), decOut, &len);
    *decErr = BSL_ERR_GetLastError();
}
/* END_HEADER */

/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC068
 * @title  NotifyCallback path end-to-end closed loop
 * @precon nan
 * @brief
 *    1. Drive one request through the whole callback path: install the
 *       delivery callback, submit, pause, deliver, resume on the same
 *       domain and receive the device result.
 * @expect
 *    1. PAUSE on submit with status OK and the cached callback matching
 *       the installed one; one delivery enqueues exactly one handle; the
 *       resume returns FINISH with the device result and a NULL handle.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC068(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    MockReq req = {0};
    MockArg cbArg = {0};
    int32_t ret = 0;
    int32_t status = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    g_ready.count = 0;
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    cbArg.ret = BSL_SUCCESS;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(ctx, mockCb, &cbArg), BSL_SUCCESS);
    req.ctx = ctx;
    req.publishStatus = BSL_ASYNC_NOTIFY_STATUS_OK;
    req.deviceResult = MOCK_DEVICE_RET;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Submit: the handle does not exist while the callback is installed, it
     * is backfilled after the pause. */
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, mockJob, &req), BSL_ASYNC_PAUSE);
    cbArg.task = task;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_OK);
    ASSERT_TRUE(req.cb == mockCb);
    ASSERT_TRUE(req.cbArg == &cbArg);
    /* Device completion: the cached callback enqueues the handle. */
    mockOnComplete(&req);
    ASSERT_EQ(g_ready.count, 1);
    /* The host loop pops the handle and resumes on the same domain. */
    ASSERT_TRUE(AppPop() == task);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, MOCK_DEVICE_RET);
    ASSERT_TRUE(task == NULL);
    ASSERT_EQ(g_ready.count, 0);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC069
 * @title  EAGAIN and ERR submit statuses converge without events
 * @precon nan
 * @brief
 *    1. A device that cannot submit (EAGAIN) or fails submitting (ERR)
 *       still pauses; the application reads the status, resumes directly
 *       without waiting for any event and the request finishes.
 * @expect
 *    1. PAUSE on submit; the status reads back the published value; the
 *       direct resume returns FINISH.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC069(int statusToSet)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    MockReq req = {0};
    int32_t ret = 0;
    int32_t status = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    req.ctx = ctx;
    req.publishStatus = statusToSet;
    req.deviceResult = JOB_EAGAIN_RET;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, jobEagainOrErr, &req), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, statusToSet);
    /* No event is delivered and nothing is waited for: the direct resume
     * must advance the request. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_TRUE(task == NULL);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC070
 * @title  NotifyNode path end-to-end closed loop
 * @precon nan
 * @brief
 *    1. Drive one request through the whole notify-node path with a real
 *       platform wait object: register the source, maintain the
 *       application's waiter registration from the change window, deliver
 *       the completion through the wait object, resume twice and receive
 *       the device result; the completion must not get lost and the
 *       registration set must end empty.
 * @expect
 *    1. PAUSE on submit with add {handle} in the window; the waiter wakes
 *       on the delivered handle; the first resume returns PAUSE with del
 *       {handle}; the second returns FINISH with the device result; the
 *       all-source count and the registration set end at zero.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC070(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandle handle = 0;
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    MockReq req = {0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
    int key1 = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(AppWaitInit(), 0);
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(MockWaitOpen(&req.wait), 0);
    handle = MockWaitHandle(&req.wait);
    req.ctx = ctx;
    req.key = &key1;
    req.deviceResult = MOCK_DEVICE_RET;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Submit: the source registers before the first pause. */
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, mockJobSource, &req), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], handle);
    ASSERT_EQ(AppWaitAdd(handle), 0);
    ASSERT_EQ(AppWaitContains(handle), 1);
    /* Device completion: the wait object carries the notification. */
    mockOnComplete(&req);
    ASSERT_TRUE(AppWaitWait(1000) == handle);
    /* First resume: the task consumes the event and clears the source. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctx, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(delBuf[0], handle);
    ASSERT_EQ(AppWaitRemove(handle), 0);
    ASSERT_EQ(AppWaitContains(handle), 0);
    /* Second resume: the device result is delivered. */
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, MOCK_DEVICE_RET);
    ASSERT_TRUE(task == NULL);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctx, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 0);
    ASSERT_EQ(g_waitSet.count, 0);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
    MockWaitClose(&req.wait);
    AppWaitDeinit();
EXIT:
    BSL_ASYNC_CleanupThread();
    MockWaitClose(&req.wait);
    AppWaitDeinit();
    return;
}
/* END_CASE */
#endif /* HITLS_BSL_SAL_LINUX || HITLS_BSL_SAL_DARWIN */

/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC071
 * @title  NotifyCallback race and duplicate delivery
 * @precon nan
 * @brief
 *    1. Four delivery timings on the callback path: completion before the
 *       pause returns, completion right after it, three duplicate
 *       completions and a failed delivery followed by a retry; the
 *       application's idempotent merge must deliver each request exactly
 *       once.
 * @expect
 *    1. All four timings end with exactly one FINISH; the duplicate
 *       timing enqueues the handle once and resumes once; the failed
 *       delivery leaves the task paused with an untouched submit status
 *       and the retried delivery enqueues it.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC071(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    MockReq req = {0};
    MockArg cbArg = {0};
    int32_t ret = 0;
    int32_t status = 0;
    int resumes = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    g_ready.count = 0;
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    cbArg.ret = BSL_SUCCESS;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(ctx, mockCb, &cbArg), BSL_SUCCESS);
    req.ctx = ctx;
    req.publishStatus = BSL_ASYNC_NOTIFY_STATUS_OK;
    req.deviceResult = MOCK_DEVICE_RET;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);

    /* Timing 1: the completion fires before the pause returns, so the
     * task backfills its own handle. */
    req.completeBeforePause = 1;
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, mockJob, &req), BSL_ASYNC_PAUSE);
    ASSERT_EQ(g_ready.count, 1);
    ASSERT_TRUE(AppPop() == task);
    resumes++;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, MOCK_DEVICE_RET);

    /* Timing 2: the completion fires right after the pause. */
    req.completeBeforePause = 0;
    task = NULL;
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, mockJob, &req), BSL_ASYNC_PAUSE);
    cbArg.task = task;
    mockOnComplete(&req);
    ASSERT_EQ(g_ready.count, 1);
    ASSERT_TRUE(AppPop() == task);
    resumes++;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);

    /* Timing 3: three duplicate completions collapse into one entry. */
    task = NULL;
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, mockJob, &req), BSL_ASYNC_PAUSE);
    cbArg.task = task;
    mockOnComplete(&req);
    mockOnComplete(&req);
    mockOnComplete(&req);
    ASSERT_EQ(g_ready.count, 1);
    ASSERT_TRUE(AppPop() == task);
    resumes++;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(g_ready.count, 0);

    /* Timing 4: the delivery fails, the task stays paused with its submit
     * status untouched; the retry delivers and the resume finishes. */
    task = NULL;
    cbArg.ret = 1;
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, mockJob, &req), BSL_ASYNC_PAUSE);
    cbArg.task = task;
    mockOnComplete(&req);
    ASSERT_EQ(g_ready.count, 0);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_OK);
    cbArg.ret = BSL_SUCCESS;
    mockOnComplete(&req);
    ASSERT_EQ(g_ready.count, 1);
    ASSERT_TRUE(AppPop() == task);
    resumes++;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(resumes, 4);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC072
 * @title  Synchronous path behavior unchanged without async devices
 * @precon nan
 * @brief
 *    1. Run one round of existing synchronous operations (one succeeding
 *       and one failing Base64 call) on an uninitialized thread, then the
 *       same round on the host stack of an initialized execution domain:
 *       return codes, output buffers and error codes must be identical.
 * @expect
 *    1. GetCurrentTask returns NULL in both environments; both rounds
 *       report the same encode result and output, the same decode failure
 *       and the same pushed error code.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC072(void)
{
    int32_t encRet1 = 0;
    int32_t decRet1 = 0;
    int32_t decErr1 = 0;
    int32_t encRet2 = 0;
    int32_t decRet2 = 0;
    int32_t decErr2 = 0;
    char encOut1[16] = {0};
    char encOut2[16] = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    /* Round 1: the thread is not initialized. */
    ASSERT_TRUE(BSL_ASYNC_GetCurrentTask() == NULL);
    SyncOpRound(&encRet1, encOut1, sizeof(encOut1), &decRet1, &decErr1);
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Round 2: the same calls on the host stack of a live domain. */
    ASSERT_TRUE(BSL_ASYNC_GetCurrentTask() == NULL);
    SyncOpRound(&encRet2, encOut2, sizeof(encOut2), &decRet2, &decErr2);
    ASSERT_EQ(encRet1, encRet2);
    ASSERT_EQ(memcmp(encOut1, encOut2, sizeof(encOut1)), 0);
    ASSERT_EQ(decRet1, decRet2);
    ASSERT_EQ(decErr1, decErr2);
    ASSERT_EQ(encRet1, BSL_SUCCESS);
    ASSERT_NE(decRet1, BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
    ASSERT_TRUE(BSL_ASYNC_GetCurrentTask() == NULL);
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC073
 * @title  Capability declaration without a resumable-context backend
 * @precon nan
 * @brief
 *    1. On a build without any resumable-context backend the whole
 *       framework degrades: both probes report unsupported, the execution
 * domain cannot be established (the host context is a backend object), task startup is rejected before any
 *       allocation and synchronous operations keep working.
 * @expect
 *    1. IsSupported is false and the SAL probe returns 0; InitThread
 *       returns BSL_ASYNC_ERR_STATE_CONFLICT; StartTask returns
 *       BSL_ASYNC_UNSUPPORTED with the handle NULL and a zero allocation
 *       delta; the synchronous operation matches its baseline.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC073(void)
{
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_TaskParam param = {0};
    int32_t ret = 0;
    int32_t encRet = 0;
    int32_t decRet = 0;
    int32_t decErr = 0;
    char encOut[16] = {0};
    uint32_t before = 0;

    if (ASYNC_BACKEND_READY()) {
        /* The no-backend build variant runs this case; on a backend build
         * the declaration-of-support cases cover the opposite direction. */
        SKIP_TEST();
    }
    ASSERT_TRUE(BSL_ASYNC_IsSupported() == false);
    ASSERT_TRUE(!BSL_SAL_CoroutineIsSupported());
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_ASYNC_ERR_STATE_CONFLICT);
    InjectArm(-1);
    before = g_allocCount;
    param.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_UNSUPPORTED);
    ASSERT_TRUE(task == NULL);
    ASSERT_EQ(g_allocCount - before, 0);
    InjectDisarm();
    SyncOpRound(&encRet, encOut, sizeof(encOut), &decRet, &decErr);
    ASSERT_EQ(encRet, BSL_SUCCESS);
    ASSERT_NE(decRet, BSL_SUCCESS);
    BSL_ASYNC_CleanupThread();
EXIT:
    InjectDisarm();
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC074
 * @title  Error recovery within one execution domain
 * @precon nan
 * @brief
 *    1. A submitted request (branch B: status OK) fails on the device:
 *       the business error is delivered after the resume as a normal
 *       FINISH, and later requests on the same domain are unaffected.
 * @expect
 *    1. PAUSE with status OK; the resume returns FINISH (not
 *       BSL_ASYNC_ERR) with ret 0x0BAD and a NULL handle; two follow-up
 *       synchronous jobs both finish normally.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC074(void)
{
    BSL_ASYNC_NotifyCtx *ctx = NULL;
    BSL_ASYNC_Task *task = NULL;
    MockReq req = {0};
    int32_t ret = 0;
    int32_t status = 0;
    BSL_ASYNC_TaskParam syncParam = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ctx = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(ctx != NULL);
    req.ctx = ctx;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(mockSubmit(&task, &ret, ctx, jobFailAfterPause, &req), BSL_ASYNC_PAUSE);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetStatus(ctx, &status), BSL_SUCCESS);
    ASSERT_EQ(status, BSL_ASYNC_NOTIFY_STATUS_OK);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_FAIL_RET);
    ASSERT_TRUE(task == NULL);
    /* The error did not spill over to later requests. */
    syncParam.func = jobSync;
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &syncParam), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    task = NULL;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &syncParam), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    BSL_ASYNC_NotifyCtxFree(ctx);
    BSL_ASYNC_CleanupThread();
EXIT:
    BSL_ASYNC_CleanupThread();
    return;
}
/* END_CASE */

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/**
 * @test   SDV_BSL_ASYNC_E2E_FUNC_TC075
 * @title  Both completion paths close the loop in one process
 * @precon nan
 * @brief
 *    1. One process first serves a callback-path request, then a
 *       notify-node-path request, on the same execution domain and task
 *       pool: no state may leak between the two paths.
 * @expect
 *    1. The callback path yields PAUSE then FINISH; the node context's
 *       window is empty in between; the node path yields PAUSE, PAUSE
 *       then FINISH with the window carrying add {handle} and then del
 *       {handle}; the final all-source count is zero.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_E2E_FUNC_TC075(void)
{
    BSL_ASYNC_NotifyCtx *ctxA = NULL;
    BSL_ASYNC_NotifyCtx *ctxB = NULL;
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_NotifyHandle addBuf[4] = {0};
    BSL_ASYNC_NotifyHandle delBuf[4] = {0};
    BSL_ASYNC_NotifyHandle handle = 0;
    BSL_ASYNC_NotifyHandleList all = {NULL, 0, 0};
    MockReq reqA = {0};
    MockReq reqB = {0};
    MockArg cbArg = {0};
    uint32_t addN = 0;
    uint32_t delN = 0;
    int32_t ret = 0;
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
    handle = MockWaitHandle(&reqB.wait);
    reqA.ctx = ctxA;
    reqA.publishStatus = BSL_ASYNC_NOTIFY_STATUS_OK;
    reqA.deviceResult = MOCK_DEVICE_RET;
    reqB.ctx = ctxB;
    reqB.key = &keyB;
    reqB.deviceResult = MOCK_DEVICE_RET;
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    /* Callback path first. */
    ASSERT_EQ(mockSubmit(&task, &ret, ctxA, mockJob, &reqA), BSL_ASYNC_PAUSE);
    cbArg.task = task;
    mockOnComplete(&reqA);
    ASSERT_TRUE(AppPop() == task);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, MOCK_DEVICE_RET);
    /* Nothing leaked into the node context between the two paths. */
    ASSERT_EQ(AsyncReadChanges(ctxB, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 0);
    /* Node path on the same domain and pool. */
    ASSERT_EQ(mockSubmit(&task, &ret, ctxB, mockJobSource, &reqB), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctxB, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 1);
    ASSERT_EQ(delN, 0);
    ASSERT_EQ(addBuf[0], handle);
    ASSERT_EQ(AppWaitAdd(handle), 0);
    mockOnComplete(&reqB);
    ASSERT_TRUE(AppWaitWait(1000) == handle);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_PAUSE);
    ASSERT_EQ(AsyncReadChanges(ctxB, addBuf, 4, &addN, delBuf, 4, &delN), BSL_SUCCESS);
    ASSERT_EQ(addN, 0);
    ASSERT_EQ(delN, 1);
    ASSERT_EQ(delBuf[0], handle);
    ASSERT_EQ(AppWaitRemove(handle), 0);
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, MOCK_DEVICE_RET);
    all.handles = NULL;
    all.capacity = 0;
    ASSERT_EQ(BSL_ASYNC_NotifyCtxGetAllNotifySources(ctxB, &all), BSL_SUCCESS);
    ASSERT_EQ(all.numHandles, 0);
    ASSERT_EQ(g_waitSet.count, 0);
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
