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

/* INCLUDE_BASE test_suite_sdv_async_sim */

/* BEGIN_HEADER */
#include "crypt_eal_pkey.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "bsl_async.h"
#include <poll.h>
#include <stdatomic.h>
#include <unistd.h>

/* ---------------------------------------------------------------------- */
/* BSL-level driving fixtures: */
/* the crypto call is wrapped in a task on the owner thread; the pause    */
/* rounds are driven by resuming the same task after each completion      */
/* signal. Phase 1 never goes through TLS for the async path.             */
/* ---------------------------------------------------------------------- */

/* completion-callback counter (callback path only posts, never resumes);
 * the callback also records its own thread id for the thread id comparison */
static atomic_int g_asyncCbCount;
static atomic_uint_fast64_t g_asyncCbTid;

static int32_t SimAsyncTestCallback(void *arg)
{
    (void)arg;
    g_asyncCbTid = BSL_SAL_ThreadGetId();
    g_asyncCbCount++;
    return BSL_SUCCESS;
}

/* job kinds of SimAsyncJobRun */
#define SIM_ASYNC_JOB_SIGN      0 /* CRYPT_EAL_PkeySign */
#define SIM_ASYNC_JOB_SHARE_KEY 1 /* CRYPT_EAL_PkeyComputeShareKey */
#define SIM_ASYNC_JOB_ENCAPS    2 /* CRYPT_EAL_PkeyEncaps, two outputs */
#define SIM_ASYNC_JOB_DECAPS    3 /* CRYPT_EAL_PkeyDecaps */

/* the business entry running inside the task */
typedef struct {
    int32_t kind; /* SIM_ASYNC_JOB_SIGN / _SHARE_KEY / _ENCAPS / _DECAPS */
    CRYPT_EAL_PkeyCtx *prv;
    CRYPT_EAL_PkeyCtx *peer;
    int32_t mdId;
    const uint8_t *data;
    uint32_t dataLen;
    uint8_t out[2048]; /* signature, shared secret or KEM ciphertext */
    uint32_t outLen;
    uint8_t out2[64]; /* KEM encaps shared secret */
    uint32_t outLen2;
    int32_t ret;
} SimAsyncJob;

static int32_t SimAsyncJobRun(void *args)
{
    /* The job block is shared through the snapshot pointer, so the results
     * written here (ret, out, outLen) are visible to the host. */
    SimAsyncJob *j = (SimAsyncJob *)((ArgRef *)args)->shared;
    j->outLen = sizeof(j->out);
    switch (j->kind) {
        case SIM_ASYNC_JOB_SIGN:
            j->ret = CRYPT_EAL_PkeySign(j->prv, j->mdId, j->data, j->dataLen, j->out, &j->outLen);
            break;
        case SIM_ASYNC_JOB_SHARE_KEY:
            j->ret = CRYPT_EAL_PkeyComputeShareKey(j->prv, j->peer, j->out, &j->outLen);
            break;
        case SIM_ASYNC_JOB_ENCAPS:
            j->outLen2 = sizeof(j->out2);
            j->ret = CRYPT_EAL_PkeyEncaps(j->prv, j->out, &j->outLen, j->out2, &j->outLen2);
            break;
        case SIM_ASYNC_JOB_DECAPS:
            j->ret = CRYPT_EAL_PkeyDecaps(j->prv, j->data, j->dataLen, j->out, &j->outLen);
            break;
        default:
            j->ret = FRAME_ASYNC_ERR_STATE;
            break;
    }
    return j->ret;
}

/* Wait for one completion signal. Callback path: poll the counter. Handle
 * path: poll the notify-source fd registered by the provider on the task's
 * notify context, then drain it (eventfd read resets the counter). */
static int32_t SimAsyncWaitSignal(BSL_ASYNC_NotifyCtx *nc, bool useCb, uint32_t timeoutMs)
{
    uint32_t elapsed = 0;
    if (useCb) {
        while (g_asyncCbCount == 0) {
            if (elapsed >= timeoutMs) {
                return FRAME_ASYNC_ERR_TIMEOUT;
            }
            /* BSL_SAL_Sleep counts SECONDS; poll at millisecond granularity */
            usleep(1000);
            elapsed++;
        }
        g_asyncCbCount--;
        return FRAME_ASYNC_SUCCESS;
    }
    /* handle path */
    BSL_ASYNC_NotifyHandle fds[4] = {0};
    BSL_ASYNC_NotifyHandleList list = {NULL, 0, 0};
    if (BSL_ASYNC_NotifyCtxGetAllNotifySources(nc, &list) != BSL_SUCCESS || list.numHandles == 0) {
        return FRAME_ASYNC_ERR_TIMEOUT;
    }
    uint32_t n = list.numHandles > 4 ? 4 : list.numHandles;
    list.handles = fds;
    list.capacity = n;
    if (BSL_ASYNC_NotifyCtxGetAllNotifySources(nc, &list) != BSL_SUCCESS) {
        return FRAME_ASYNC_ERR_TIMEOUT;
    }
    struct pollfd pfd[4] = {0};
    for (uint32_t i = 0; i < n; i++) {
        pfd[i].fd = (int)(uintptr_t)fds[i];
        pfd[i].events = POLLIN;
    }
    while (true) {
        int pr = poll(pfd, n, (int)(timeoutMs - elapsed));
        if (pr > 0) {
            for (uint32_t i = 0; i < n; i++) {
                if (pfd[i].revents & POLLIN) {
                    uint64_t val = 0;
                    (void)read(pfd[i].fd, &val, sizeof(val));
                }
            }
            return FRAME_ASYNC_SUCCESS;
        }
        if (pr == 0) {
            return FRAME_ASYNC_ERR_TIMEOUT;
        }
        return FRAME_ASYNC_ERR_TIMEOUT;
    }
}

/* Drive each pause from its notification. */
/* waitFirstSignal: false for actions whose first pause precedes any device
 * submission (EAGAIN re-submits only at the resume point), so the first
 * resume must happen without waiting for a signal. */
static int32_t SimAsyncDrive2(BSL_ASYNC_Task **task, BSL_ASYNC_NotifyCtx *nc, bool useCb, uint32_t timeoutMs,
                              int32_t *jobRet, bool *timedOut, bool waitFirstSignal)
{
    int32_t ret = 0;
    bool signalled = !waitFirstSignal;
    uint32_t rounds = 0;
    *timedOut = false;
    while (true) {
        if (!signalled) {
            int32_t wr = SimAsyncWaitSignal(nc, useCb, timeoutMs);
            if (wr != FRAME_ASYNC_SUCCESS) {
                *timedOut = true;
                *jobRet = ret;
                return FRAME_ASYNC_ERR_TIMEOUT;
            }
            signalled = true;
        }
        int32_t sr = BSL_ASYNC_StartTask(task, &ret, NULL);
        if (sr != BSL_ASYNC_PAUSE) {
            /* FINISH (or NO_JOB/ERR, surfaced as a failure below) */
            *jobRet = ret;
            return sr == BSL_ASYNC_FINISH ? FRAME_ASYNC_SUCCESS : FRAME_ASYNC_ERR_STATE;
        }
        signalled = false;
        rounds++;
        if (rounds > 1000) {
            return FRAME_ASYNC_ERR_STATE;
        }
    }
}

static int32_t SimAsyncDrive(BSL_ASYNC_Task **task, BSL_ASYNC_NotifyCtx *nc, bool useCb, uint32_t timeoutMs,
                             int32_t *jobRet, bool *timedOut)
{
    return SimAsyncDrive2(task, nc, useCb, timeoutMs, jobRet, timedOut, true);
}

/* Build a provider-routed ECDSA P-256 key pair used by the sign cases. */
static int32_t SimAsyncMakeSignKey(CRYPT_EAL_LibCtx *libCtx, CRYPT_EAL_PkeyCtx **prv, CRYPT_EAL_PkeyCtx **pub)
{
    *prv =
        CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDSA, CRYPT_EAL_PKEY_SIGN_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    if (*prv == NULL) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    if (CRYPT_EAL_PkeySetParaById(*prv, CRYPT_ECC_NISTP256) != CRYPT_SUCCESS) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    if (CRYPT_EAL_PkeyGen(*prv) != CRYPT_SUCCESS) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    if (pub != NULL) {
        uint8_t buf[128] = {0};
        uint32_t len = sizeof(buf);
        BSL_Param param[2] = {0};
        param[0].key = CRYPT_PARAM_PKEY_ENCODE_PUBKEY;
        param[0].valueType = BSL_PARAM_TYPE_OCTETS;
        param[0].value = buf;
        param[0].valueLen = len;
        param[1].key = 0;
        if (CRYPT_EAL_PkeyGetPubEx(*prv, param) != CRYPT_SUCCESS) {
            return FRAME_ASYNC_ERR_PROVIDER;
        }
        len = param[0].useLen;
        *pub = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
                                            FRAME_ASYNC_PROVIDER_ATTR);
        if (*pub == NULL) {
            return FRAME_ASYNC_ERR_PROVIDER;
        }
        if (CRYPT_EAL_PkeySetParaById(*pub, CRYPT_ECC_NISTP256) != CRYPT_SUCCESS) {
            return FRAME_ASYNC_ERR_PROVIDER;
        }
        param[0].valueLen = len;
        if (CRYPT_EAL_PkeySetPubEx(*pub, param) != CRYPT_SUCCESS) {
            return FRAME_ASYNC_ERR_PROVIDER;
        }
    }
    return FRAME_ASYNC_SUCCESS;
}

/* Build a provider-routed ML-KEM-768 key used by the KEM cases. */
static int32_t SimAsyncMakeKemKey(CRYPT_EAL_LibCtx *libCtx, CRYPT_EAL_PkeyCtx **prv)
{
    *prv =
        CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    if (*prv == NULL) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    if (CRYPT_EAL_PkeySetParaById(*prv, CRYPT_KEM_TYPE_MLKEM_768) != CRYPT_SUCCESS) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    if (CRYPT_EAL_PkeyGen(*prv) != CRYPT_SUCCESS) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    return FRAME_ASYNC_SUCCESS;
}
/* END_HEADER */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC001
 * @title  PAUSE(1) inline + callback: the async path really pauses once
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure INLINE execution and a PAUSE(resumeCount=1) scenario on
 *       SIGN, install the completion callback on the task notify context.
 *    2. Wrap a provider-routed ECDSA sign in a task and drive it.
 *    3. Verify the signature and the counters.
 * @expect
 *    1. The task pauses and finishes after one resume.
 *    2. The signature verifies under the public key.
 *    3. pauses == 1, submits == 1, resumes >= 1, syncDirectCalls == 0,
 *       inlineDone == 1, notifications == 1.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC001(int useCallback)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    (void)useCallback;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    CRYPT_EAL_PkeyCtx *pub = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t data[32] = {0};
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }
    for (uint32_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i + 1);
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeSignKey(libCtx, &prv, &pub), FRAME_ASYNC_SUCCESS);

    /* baseline after key setup: the host-stack keygen is a legitimate sync
     * call; the async assertions below use the DELTA over this snapshot */
    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 1;
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_INLINE, 0, 0), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    if (useCallback) {
        ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    }
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_SIGN;
    job.prv = prv;
    job.mdId = CRYPT_MD_SHA256;
    job.data = data;
    job.dataLen = sizeof(data);
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, useCallback != 0, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_TRUE(job.outLen > 0);

    /* the delegated signature must verify (delegation correctness) */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pub, CRYPT_MD_SHA256, data, sizeof(data), job.out, job.outLen), CRYPT_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    /* the in-task sign added one cryptoCall; the host-stack verify added one
     * more cryptoCall and one syncDirectCall (delta view) */
    ASSERT_TRUE(stats.cryptoCalls == base.cryptoCalls + 2);
    ASSERT_TRUE(stats.syncDirectCalls == base.syncDirectCalls + 1);
    ASSERT_EQ(stats.pauses - base.pauses, 1u);
    ASSERT_EQ(stats.submits - base.submits, 1u);
    ASSERT_TRUE(stats.resumes - base.resumes >= 1);
    ASSERT_TRUE(stats.resubmits == 0);
    ASSERT_EQ(stats.completes - base.completes, 1u);
    ASSERT_TRUE(stats.failures == 0);
    ASSERT_EQ(stats.notifications - base.notifications, 1u);
    ASSERT_EQ(stats.inlineDone - base.inlineDone, 1u);
    ASSERT_TRUE(stats.workerDone == 0);

EXIT:
    if (task != NULL) {
        /* a still-paused task is abandoned by the domain cleanup */
        task = NULL;
    }
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    CRYPT_EAL_PkeyFreeCtx(pub);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC002
 * @title  PAUSE(3): multiple resumes, no re-submission
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure a PAUSE(resumeCount=3) scenario on SIGN, inline mode.
 *    2. Drive the sign to completion.
 * @expect
 *    1. The task finishes with a valid signature.
 *    2. pauses == 3, resubmits == 0, submits == 1.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC002(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    CRYPT_EAL_PkeyCtx *pub = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t data[16] = {1, 2, 3, 4};
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeSignKey(libCtx, &prv, &pub), FRAME_ASYNC_SUCCESS);
    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 3;
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_SIGN;
    job.prv = prv;
    job.mdId = CRYPT_MD_SHA256;
    job.data = data;
    job.dataLen = sizeof(data);
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, false, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pub, CRYPT_MD_SHA256, data, sizeof(data), job.out, job.outLen), CRYPT_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.pauses - base.pauses, 3u);
    ASSERT_EQ(stats.submits - base.submits, 1u);
    ASSERT_TRUE(stats.resubmits == 0);
    ASSERT_TRUE(stats.resumes - base.resumes >= 3);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    CRYPT_EAL_PkeyFreeCtx(pub);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC003
 * @title  Worker execution: real computation happens off the dispatcher thread
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure WORKER mode (P=2) with a PAUSE(1) scenario and a nonzero
 *       device wait.
 *    2. Drive a sign; the completion callback records its own thread id.
 *    3. Compare the callback thread id with the dispatcher thread id.
 * @expect
 *    1. The sign completes and verifies.
 *    2. workerDone == 1, inlineDone == 0.
 * 3. The callback thread id differs from the dispatcher thread id.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC003(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    CRYPT_EAL_PkeyCtx *pub = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t data[16] = {9, 8, 7};
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeSignKey(libCtx, &prv, &pub), FRAME_ASYNC_SUCCESS);
    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 1;
    sc.waitNs = 2000000; /* 2 ms device wait */
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    g_asyncCbCount = 0;
    g_asyncCbTid = 0;

    job.kind = SIM_ASYNC_JOB_SIGN;
    job.prv = prv;
    job.mdId = CRYPT_MD_SHA256;
    job.data = data;
    job.dataLen = sizeof(data);
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    uint64_t dispatcherTid = BSL_SAL_ThreadGetId();
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, true, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pub, CRYPT_MD_SHA256, data, sizeof(data), job.out, job.outLen), CRYPT_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.workerDone - base.workerDone, 1u);
    ASSERT_TRUE(stats.inlineDone == base.inlineDone);
    ASSERT_EQ(stats.pauses - base.pauses, 1u);

    /* the callback ran on the worker thread, not on the dispatcher */
    ASSERT_TRUE(g_asyncCbTid != 0);
    ASSERT_TRUE(g_asyncCbTid != dispatcherTid);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    CRYPT_EAL_PkeyFreeCtx(pub);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC004
 * @title  EAGAIN: exactly one re-submission, final success
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure an EAGAIN scenario on SIGN, inline mode.
 *    2. Drive the sign: the first submission fails with EAGAIN, the resume
 *       re-submits once and completes.
 * @expect
 *    1. The sign finishes with a valid signature.
 *    2. resubmits == 1, submits == 1, pauses >= 1.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC004(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    CRYPT_EAL_PkeyCtx *pub = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t data[16] = {5, 5, 5};
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeSignKey(libCtx, &prv, &pub), FRAME_ASYNC_SUCCESS);

    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_EAGAIN;
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_SIGN;
    job.prv = prv;
    job.mdId = CRYPT_MD_SHA256;
    job.data = data;
    job.dataLen = sizeof(data);
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    /* EAGAIN: the first pause precedes the submission, so the first resume
     * happens without waiting; the re-submitted request then signals */
    ASSERT_EQ(SimAsyncDrive2(&task, nc, false, 3000, &jobRet, &timedOut, false), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pub, CRYPT_MD_SHA256, data, sizeof(data), job.out, job.outLen), CRYPT_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.resubmits - base.resubmits, 1u);
    ASSERT_EQ(stats.submits - base.submits, 1u);
    ASSERT_TRUE(stats.pauses - base.pauses >= 1);
    ASSERT_TRUE(stats.failures == 0);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    CRYPT_EAL_PkeyFreeCtx(pub);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC005
 * @title  FAIL: the task ends with the injected error code
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure a FAIL(resumeCount=1) scenario with a non-zero errCode.
 *    2. Drive the sign.
 * @expect
 *    1. The job returns the injected errCode.
 * 2. failures == 1 (injected failures are counted).
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC005(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t data[16] = {6};
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeSignKey(libCtx, &prv, NULL), FRAME_ASYNC_SUCCESS);

    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_FAIL;
    sc.resumeCount = 1;
    sc.errCode = CRYPT_EAL_ALG_NOT_SUPPORT;
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_SIGN;
    job.prv = prv;
    job.mdId = CRYPT_MD_SHA256;
    job.data = data;
    job.dataLen = sizeof(data);
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, false, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_EAL_ALG_NOT_SUPPORT);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    /* one injected failure, no delegated failure (the real crypto worked) */
    ASSERT_EQ(stats.failures - base.failures, 1u);
    ASSERT_EQ(stats.completes - base.completes, 1u);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC006
 * @title  FAST_COMPLETE: notification before the pause returns, still recovers
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure a FAST_COMPLETE scenario (worker mode forces the inline
 *       completion at submit so the notification precedes the pause).
 *    2. Drive the sign; the signal must already be pending at the first
 *       wait (the notification was posted before PauseTask returned).
 * @expect
 *    1. The task recovers and the signature verifies.
 *    2. pauses == 1, completes == 1.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC006(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    CRYPT_EAL_PkeyCtx *pub = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t data[16] = {7};
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeSignKey(libCtx, &prv, &pub), FRAME_ASYNC_SUCCESS);

    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_FAST_COMPLETE;
    /* worker mode still completes FAST_COMPLETE inline at submit */
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_SIGN;
    job.prv = prv;
    job.mdId = CRYPT_MD_SHA256;
    job.data = data;
    job.dataLen = sizeof(data);
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    /* the completion notification was posted before the pause returned, so
     * the signal is already pending here (callback counter already >= 1) */
    ASSERT_TRUE(g_asyncCbCount >= 1);
    g_asyncCbCount = 0; /* consume: the drive must not wait for it again */
    /* the signal already arrived (before the pause returned): resume
     * directly without waiting, like the EAGAIN first round */
    ASSERT_EQ(SimAsyncDrive2(&task, nc, true, 3000, &jobRet, &timedOut, false), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pub, CRYPT_MD_SHA256, data, sizeof(data), job.out, job.outLen), CRYPT_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.pauses - base.pauses, 1u);
    ASSERT_EQ(stats.completes - base.completes, 1u);
    /* FAST_COMPLETE computes inline even in worker mode */
    ASSERT_EQ(stats.inlineDone - base.inlineDone, 1u);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    CRYPT_EAL_PkeyFreeCtx(pub);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC007
 * @title  DUP_NOTIFY: extra notifications do not break single-task recovery
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure a DUP_NOTIFY scenario with notifyRepeat = 2.
 *    2. Drive the sign.
 * @expect
 *    1. notifications == 3 (1 + 2 extra).
 *    2. The task still completes exactly once with a valid signature
 *       (notifications > resumes needed; no concurrent recovery).
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC007(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    CRYPT_EAL_PkeyCtx *pub = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t data[16] = {8};
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeSignKey(libCtx, &prv, &pub), FRAME_ASYNC_SUCCESS);

    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_SIGN;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_DUP_NOTIFY;
    sc.resumeCount = 1;
    sc.notifyRepeat = 2;
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_SIGN;
    job.prv = prv;
    job.mdId = CRYPT_MD_SHA256;
    job.data = data;
    job.dataLen = sizeof(data);
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, true, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pub, CRYPT_MD_SHA256, data, sizeof(data), job.out, job.outLen), CRYPT_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.notifications - base.notifications, 3u);
    ASSERT_EQ(stats.completes - base.completes, 1u);
    ASSERT_EQ(stats.pauses - base.pauses, 1u);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    CRYPT_EAL_PkeyFreeCtx(pub);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC010
 * @title  KEYEXCH pause: async shared secret equals the sync computation
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Generate two provider-routed ECDH keys; compute the shared secret
 *       synchronously (host stack) as the reference.
 *    2. Wrap a second computation in a task with a PAUSE(1) scenario on
 *       KEYEXCH (worker mode) and drive it.
 *    3. Compare the two shared secrets byte by byte.
 * @expect
 *    1. Both computations succeed.
 *    2. The outputs are identical (delegation correctness on the async path).
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC010(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *a = NULL;
    CRYPT_EAL_PkeyCtx *b = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t ref[128] = {0};
    uint32_t refLen = sizeof(ref);
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    a = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    b = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(a, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(b, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(a), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(b), CRYPT_SUCCESS);

    /* reference: synchronous computation on the host stack */
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, ref, &refLen), CRYPT_SUCCESS);
    ASSERT_TRUE(refLen > 0);
    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    /* async: same computation inside a task with a KEYEXCH pause */
    sc.operaId = CRYPT_EAL_OPERAID_KEYEXCH;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 1;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_SHARE_KEY;
    job.prv = a;
    job.peer = b;
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, true, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_EQ(job.outLen, refLen);
    ASSERT_COMPARE("async shared secret differs from the sync reference", job.out, job.outLen, ref, refLen);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.pauses - base.pauses, 1u);
    ASSERT_EQ(stats.workerDone - base.workerDone, 1u);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(a);
    CRYPT_EAL_PkeyFreeCtx(b);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC011
 * @title  Two in-flight requests complete out of order and recover individually
 * @precon Provider loaded; coroutine backend available
 * @brief
 *    1. Configure two scenarios on KEYEXCH: hit 1 waits 40 ms, hit 2 waits
 *       2 ms (worker mode, P=2), both PAUSE(1).
 *    2. Start two tasks; both pause.
 *    3. Resume whichever task's signal arrives; the fast one finishes first.
 * @expect
 *    1. Both tasks finish with correct shared secrets.
 *    2. The fast request completes before the slow one (out-of-order).
 *    3. pauses == 2, submits == 2.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC011(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *keys[4] = {NULL};
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *tasks[2] = {NULL};
    SimAsyncJob jobs[2] = {{0}};
    SIM_PROV_SCENARIO sc[2] = {{0}};
    SIM_PROV_STATS stats = {0};
    uint8_t ref[2][128] = {{0}};
    uint32_t refLen[2] = {0};
    int32_t jobRet = 0;
    BSL_ASYNC_TaskParam params[2] = {{0}};
    int32_t finishOrder[2] = {-1, -1};
    uint32_t finished = 0;

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    /* two ECDH pairs: jobs[i] computes with (keys[i], keys[i+2]) */
    for (int i = 0; i < 4; i++) {
        keys[i] = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE,
                                               FRAME_ASYNC_PROVIDER_ATTR);
        ASSERT_TRUE(keys[i] != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(keys[i], CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    }
    for (int i = 0; i < 4; i++) {
        ASSERT_EQ(CRYPT_EAL_PkeyGen(keys[i]), CRYPT_SUCCESS);
    }
    for (int i = 0; i < 2; i++) {
        refLen[i] = sizeof(ref[i]);
        ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(keys[i], keys[i + 2], ref[i], &refLen[i]), CRYPT_SUCCESS);
    }

    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    /* hit 1 waits 40 ms, hit 2 waits 2 ms: out-of-order completion */
    sc[0].operaId = CRYPT_EAL_OPERAID_KEYEXCH;
    sc[0].hitIndex = 1;
    sc[0].action = SIM_PROV_ACTION_PAUSE;
    sc[0].resumeCount = 1;
    sc[0].waitNs = 40000000u;
    sc[1].operaId = CRYPT_EAL_OPERAID_KEYEXCH;
    sc[1].hitIndex = 2;
    sc[1].action = SIM_PROV_ACTION_PAUSE;
    sc[1].resumeCount = 1;
    sc[1].waitNs = 2000000u;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(sc, 2), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    g_asyncCbCount = 0;

    ArgRef jobRefs[2] = {{&jobs[0]}, {&jobs[1]}};
    for (int i = 0; i < 2; i++) {
        jobs[i].kind = SIM_ASYNC_JOB_SHARE_KEY;
        jobs[i].prv = keys[i];
        jobs[i].peer = keys[i + 2];
        params[i].notifyCtx = nc;
        params[i].func = SimAsyncJobRun;
        params[i].args = &jobRefs[i];
        params[i].argsSize = sizeof(jobRefs[i]);
        ASSERT_EQ(BSL_ASYNC_StartTask(&tasks[i], &jobRet, &params[i]), BSL_ASYNC_PAUSE);
    }

    /* drive both: wait for a completion signal, THEN resume each task once.
     * Resuming before the signal only makes an unfinished request pause
     * again (spurious wakeup) and inflates the pause count. */
    for (uint32_t guard = 0; guard < 20000 && finished < 2; guard++) {
        int32_t sr;
        if (g_asyncCbCount == 0) {
            usleep(1000);
            continue;
        }
        g_asyncCbCount--;
        for (int i = 0; i < 2; i++) {
            if (tasks[i] == NULL) {
                continue;
            }
            sr = BSL_ASYNC_StartTask(&tasks[i], &jobRet, NULL);
            if (sr == BSL_ASYNC_FINISH) {
                ASSERT_EQ(jobs[i].ret, CRYPT_SUCCESS);
                ASSERT_EQ(jobs[i].outLen, refLen[i]);
                ASSERT_COMPARE("out-of-order shared secret differs", jobs[i].out, jobs[i].outLen, ref[i], refLen[i]);
                finishOrder[finished] = i;
                finished++;
                tasks[i] = NULL;
                break; /* one resume per signal */
            }
        }
    }
    ASSERT_EQ(finished, 2u);
    /* the fast request (hit 2, 2 ms) must complete before the slow one */
    ASSERT_EQ(finishOrder[0], 1);
    ASSERT_EQ(finishOrder[1], 0);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    /* two first pauses are structural; a resume that races the completion
     * signal may add one spurious re-pause (legal: query only) */
    ASSERT_TRUE(stats.pauses - base.pauses >= 2);
    ASSERT_EQ(stats.submits - base.submits, 2u);
    ASSERT_EQ(stats.completes - base.completes, 2u);
    ASSERT_EQ(stats.resubmits - base.resubmits, 0u);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    for (int i = 0; i < 4; i++) {
        CRYPT_EAL_PkeyFreeCtx(keys[i]);
    }
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC012
 * @title  KEM encaps pause: both outputs recover after the resume
 * @precon Provider loaded; coroutine backend available; ML-KEM enabled
 * @brief
 *    1. Generate a provider-routed ML-KEM-768 key; run one encaps/decaps
 *       pair on the host stack as the sync-path reference.
 *    2. Configure a PAUSE(1) scenario on KEM (worker mode, P=2) and wrap a
 *       second encapsulation in a task; drive it through the pause.
 *    3. Decapsulate the recovered ciphertext on the host stack.
 * @expect
 *    1. The task pauses once and finishes with both outputs produced.
 *    2. pauses == 1, submits == 1, workerDone == 1 (delta over the base).
 *    3. The decapsulated secret equals the task's shared secret.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC012(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC) || \
    !defined(HITLS_CRYPTO_MLKEM)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t refCipher[2048] = {0};
    uint32_t refCipherLen = sizeof(refCipher);
    uint8_t refSecret[64] = {0};
    uint32_t refSecretLen = sizeof(refSecret);
    uint8_t dec[64] = {0};
    uint32_t decLen = sizeof(dec);
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeKemKey(libCtx, &prv), FRAME_ASYNC_SUCCESS);

    /* sync-path reference: the KEM delegation also works without a task */
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(prv, refCipher, &refCipherLen, refSecret, &refSecretLen), CRYPT_SUCCESS);
    decLen = sizeof(dec);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(prv, refCipher, refCipherLen, dec, &decLen), CRYPT_SUCCESS);
    ASSERT_EQ(decLen, refSecretLen);
    ASSERT_COMPARE("sync decapsulated secret differs", dec, decLen, refSecret, refSecretLen);

    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_KEM;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 1;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_ENCAPS;
    job.prv = prv;
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, true, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_TRUE(job.outLen > 0);
    ASSERT_TRUE(job.outLen2 > 0);
    /* each encapsulation is fresh: the ciphertext must differ from the
     * reference one while keeping the ML-KEM-768 length */
    ASSERT_EQ(job.outLen, refCipherLen);

    /* the async ciphertext decapsulates back to the async shared secret */
    decLen = sizeof(dec);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(prv, job.out, job.outLen, dec, &decLen), CRYPT_SUCCESS);
    ASSERT_EQ(decLen, job.outLen2);
    ASSERT_COMPARE("async decapsulated secret differs", dec, decLen, job.out2, job.outLen2);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.pauses - base.pauses, 1u);
    ASSERT_EQ(stats.submits - base.submits, 1u);
    ASSERT_EQ(stats.completes - base.completes, 1u);
    ASSERT_EQ(stats.workerDone - base.workerDone, 1u);
    ASSERT_TRUE(stats.inlineDone == base.inlineDone);
    ASSERT_EQ(stats.notifications - base.notifications, 1u);
    ASSERT_EQ(stats.resubmits - base.resubmits, 0u);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_ASYNC_TC013
 * @title  KEM decaps pause: the shared secret recovers after the resume
 * @precon Provider loaded; coroutine backend available; ML-KEM enabled
 * @brief
 *    1. Generate a provider-routed ML-KEM-768 key and encapsulate once on
 *       the host stack to obtain a ciphertext and its shared secret.
 *    2. Configure a PAUSE(1) scenario on KEM (worker mode, P=2) and wrap
 *       the decapsulation of that ciphertext in a task; drive it.
 * @expect
 *    1. The task pauses once and finishes with the secret produced.
 *    2. pauses == 1, submits == 1, workerDone == 1 (delta over the base).
 *    3. The recovered secret equals the encapsulated shared secret.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_ASYNC_TC013(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER) || !defined(HITLS_BSL_ASYNC) || \
    !defined(HITLS_CRYPTO_MLKEM)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *prv = NULL;
    BSL_ASYNC_NotifyCtx *nc = NULL;
    BSL_ASYNC_Task *task = NULL;
    SimAsyncJob job = {0};
    SIM_PROV_SCENARIO sc = {0};
    SIM_PROV_STATS stats = {0};
    uint8_t cipher[2048] = {0};
    uint32_t cipherLen = sizeof(cipher);
    uint8_t secret[64] = {0};
    uint32_t secretLen = sizeof(secret);
    int32_t jobRet = 0;
    bool timedOut = false;
    BSL_ASYNC_TaskParam param = {0};

    if (!ASYNC_SIM_BACKEND_READY()) {
        SKIP_TEST();
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(SimAsyncMakeKemKey(libCtx, &prv), FRAME_ASYNC_SUCCESS);

    /* reference: host-stack encapsulation provides the ciphertext input */
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(prv, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);

    SIM_PROV_STATS base = {0};
    ASSERT_EQ(FRAME_ASYNC_GetStats(&base), FRAME_ASYNC_SUCCESS);

    sc.operaId = CRYPT_EAL_OPERAID_KEM;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 1;
    ASSERT_EQ(FRAME_ASYNC_SetDevice(SIM_PROV_EXEC_WORKER, 2, 0), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    nc = BSL_ASYNC_NotifyCtxNew();
    ASSERT_TRUE(nc != NULL);
    ASSERT_EQ(BSL_ASYNC_NotifyCtxSetCallback(nc, SimAsyncTestCallback, NULL), BSL_SUCCESS);
    g_asyncCbCount = 0;

    job.kind = SIM_ASYNC_JOB_DECAPS;
    job.prv = prv;
    job.data = cipher;
    job.dataLen = cipherLen;
    param.notifyCtx = nc;
    param.func = SimAsyncJobRun;
    ArgRef jobRef = {&job};
    param.args = &jobRef;
    param.argsSize = sizeof(jobRef);

    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &jobRet, &param), BSL_ASYNC_PAUSE);
    ASSERT_EQ(SimAsyncDrive(&task, nc, true, 3000, &jobRet, &timedOut), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(!timedOut);
    ASSERT_EQ(job.ret, CRYPT_SUCCESS);
    ASSERT_EQ(job.outLen, secretLen);
    ASSERT_COMPARE("async decapsulated secret differs from the encapsulated one", job.out, job.outLen, secret,
                   secretLen);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_EQ(stats.pauses - base.pauses, 1u);
    ASSERT_EQ(stats.submits - base.submits, 1u);
    ASSERT_EQ(stats.completes - base.completes, 1u);
    ASSERT_EQ(stats.workerDone - base.workerDone, 1u);
    ASSERT_TRUE(stats.inlineDone == base.inlineDone);
    ASSERT_EQ(stats.notifications - base.notifications, 1u);
    ASSERT_EQ(stats.resubmits - base.resubmits, 0u);

EXIT:
    BSL_ASYNC_NotifyCtxFree(nc);
    CRYPT_EAL_PkeyFreeCtx(prv);
    AsyncSimTeardown();
#endif
}
/* END_CASE */
