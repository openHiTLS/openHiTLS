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

/* Simulation provider: crypto-callback orchestration (sync direct path and
 * async submit/pause/notify/resume path) */

#include "sim_prov_internal.h"
#include <sched.h>

#ifdef HITLS_CRYPTO_PROVIDER

#ifdef HITLS_BSL_ASYNC
static int32_t SimPrepareNotify(SimEngine *e, SimOpCtx *op, BSL_ASYNC_Task *task)
{
    BSL_ASYNC_NotifyCtx *nc = BSL_ASYNC_TaskGetNotifyCtx(task);
    if (nc == NULL) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = BSL_ASYNC_NotifyCtxGetCallback(nc, &op->cb, &op->cbArg);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    op->useCallback = op->cb != NULL;
    ret = BSL_ASYNC_NotifyCtxSetStatus(nc, op->useCallback ? BSL_ASYNC_NOTIFY_STATUS_OK :
                                                             BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED);
    if (ret != BSL_SUCCESS || op->useCallback) {
        return ret;
    }
    if (!e->notifyFdOpen) {
        if (SimNotifyFdCreate(&e->notifyFd) != SIM_PROV_SUCCESS) {
            return CRYPT_MEM_ALLOC_FAIL;
        }
        e->notifyFdOpen = true;
    }
    return BSL_ASYNC_NotifyCtxSetNotifySource(nc, e, (BSL_ASYNC_NotifyHandle)(uintptr_t)e->notifyFd.fd, NULL, NULL);
}

static void SimClearNotify(SimEngine *e, SimOpCtx *op, BSL_ASYNC_Task *task)
{
    if (op->useCallback) {
        return;
    }
    BSL_ASYNC_NotifyCtx *nc = BSL_ASYNC_TaskGetNotifyCtx(task);
    if (nc == NULL) {
        return;
    }
    (void)BSL_ASYNC_NotifyCtxClearNotifySource(nc, (const void *)e);
}
#endif /* HITLS_BSL_ASYNC */

int32_t SimCryptoEntry(SimOpCtx *op)
{
    SimEngine *e = SimEngineGet();
    if (e == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    BSL_SAL_ThreadWriteLock(e->lock);
    e->stats.cryptoCalls++;
    BSL_SAL_ThreadUnlock(e->lock);

#ifdef HITLS_BSL_ASYNC
    BSL_ASYNC_Task *task = BSL_ASYNC_GetCurrentTask();
    if (task == NULL)
#endif
    {
        /* Sync path: direct delegation, no scenario table, no counting beyond
         * cryptoCalls/syncDirectCalls (clean baseline). */
        int32_t ret = SimRunOperation(op);
        BSL_SAL_ThreadWriteLock(e->lock);
        e->stats.syncDirectCalls++;
        BSL_SAL_ThreadUnlock(e->lock);
        return ret;
    }

#ifdef HITLS_BSL_ASYNC
    /* Async path: scenario match -> notify prepare (register BEFORE submit, order is not exchangeable) -> submit -> pause. */
    BSL_SAL_ThreadWriteLock(e->lock);
    SimScenarioMatch(e, op->operaId, &op->scenario);
    uint32_t action = op->scenario.action;
    BSL_SAL_ThreadUnlock(e->lock);

    if (action == SIM_PROV_ACTION_COMPLETE) {
        /* No pause: run in place and return like a sync call, but through the
         * device layer so accounting stays uniform. */
        SimDeviceSubmit(e, op);
        return op->ret;
    }

    op->pauseRemain =
        (action == SIM_PROV_ACTION_PAUSE || action == SIM_PROV_ACTION_FAIL) ? op->scenario.resumeCount : 1;
    int32_t ret = SimPrepareNotify(e, op, task);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    op->notifyReg = true;

    /* Submit (unless the action defers it), then pause. When the task is
     * resumed, BSL_ASYNC_PauseTask returns and execution falls into the
     * collection loop below - the resume point IS this same stack frame. */
    if (action == SIM_PROV_ACTION_EAGAIN) {
        /* First submission "fails" with EAGAIN: publish the status, pause once,
         * and re-submit only at the resume point (the only legal re-submit). */
        BSL_ASYNC_NotifyCtx *nc = BSL_ASYNC_TaskGetNotifyCtx(task);
        if (nc != NULL) {
            (void)BSL_ASYNC_NotifyCtxSetStatus(nc, BSL_ASYNC_NOTIFY_STATUS_EAGAIN);
        }
    } else if (action == SIM_PROV_ACTION_NEVER) {
        /* Submit nothing; the request stays outstanding forever. */
    } else {
        int32_t sret = SimDeviceSubmit(e, op);
        if (sret != CRYPT_SUCCESS) {
            SimClearNotify(e, op, task);
            return sret;
        }
        BSL_SAL_ThreadWriteLock(e->lock);
        e->stats.submits++;
        BSL_SAL_ThreadUnlock(e->lock);
    }

    BSL_SAL_ThreadWriteLock(e->lock);
    e->stats.pauses++;
    e->outstanding++;
    BSL_SAL_ThreadUnlock(e->lock);

    int32_t pret = BSL_ASYNC_PauseTask();
    /* ---- resume point: the task is running again on the same thread ---- */

    if (pret != BSL_SUCCESS) {
        while (op->submitted && !SimDeviceIsDone(e, op)) {
            sched_yield();
        }
        SimClearNotify(e, op, task);
        BSL_SAL_ThreadWriteLock(e->lock);
        if (e->outstanding > 0) {
            e->outstanding--;
        }
        BSL_SAL_ThreadUnlock(e->lock);
        return pret;
    }

    /* Resume loop: query completion; re-submit only for EAGAIN; pause again
     * while rounds remain or the result is not ready. */
    while (true) {
        BSL_SAL_ThreadWriteLock(e->lock);
        e->stats.resumes++;
        BSL_SAL_ThreadUnlock(e->lock);

        if (action == SIM_PROV_ACTION_EAGAIN && !op->submitted) {
            BSL_ASYNC_NotifyCtx *nc = BSL_ASYNC_TaskGetNotifyCtx(task);
            (void)BSL_ASYNC_NotifyCtxSetStatus(nc, op->useCallback ? BSL_ASYNC_NOTIFY_STATUS_OK :
                                                                     BSL_ASYNC_NOTIFY_STATUS_UNSUPPORTED);
            int32_t sret = SimDeviceSubmit(e, op);
            if (sret != CRYPT_SUCCESS) {
                SimClearNotify(e, op, task);
                BSL_SAL_ThreadWriteLock(e->lock);
                if (e->outstanding > 0) {
                    e->outstanding--;
                }
                BSL_SAL_ThreadUnlock(e->lock);
                return sret;
            }
            BSL_SAL_ThreadWriteLock(e->lock);
            e->stats.resubmits++;
            e->stats.submits++;
            BSL_SAL_ThreadUnlock(e->lock);
        }

        if (!SimDeviceIsDone(e, op)) {
            /* not finished (or NEVER): query only, never submit again */
            BSL_SAL_ThreadWriteLock(e->lock);
            e->stats.pauses++;
            BSL_SAL_ThreadUnlock(e->lock);
            pret = BSL_ASYNC_PauseTask();
            if (pret != BSL_SUCCESS) {
                break;
            }
            continue;
        }

        if (op->pauseRemain > 0 && action != SIM_PROV_ACTION_EAGAIN) {
            op->pauseRemain--;
            if (op->pauseRemain > 0) {
                /* completed but pause rounds not exhausted: pause again */
                BSL_SAL_ThreadWriteLock(e->lock);
                e->stats.pauses++;
                SimDeviceNotifyLocked(e, op);
                BSL_SAL_ThreadUnlock(e->lock);
                pret = BSL_ASYNC_PauseTask();
                if (pret != BSL_SUCCESS) {
                    break;
                }
                continue;
            }
        }
        break;
    }

    while (op->submitted && !SimDeviceIsDone(e, op)) {
        sched_yield();
    }
    SimClearNotify(e, op, task);
    BSL_SAL_ThreadWriteLock(e->lock);
    if (e->outstanding > 0) {
        e->outstanding--;
    }
    if (pret != BSL_SUCCESS) {
        BSL_SAL_ThreadUnlock(e->lock);
        return pret;
    }
    if (action == SIM_PROV_ACTION_FAIL) {
        /* injected failure (failures counts injected ones too);
         * the delegated computation itself succeeded and its result is
         * discarded in favour of the scenario error code */
        e->stats.failures++;
        BSL_SAL_ThreadUnlock(e->lock);
        return op->scenario.errCode;
    }
    BSL_SAL_ThreadUnlock(e->lock);
    return op->ret;
#endif
}

#endif /* HITLS_CRYPTO_PROVIDER */
