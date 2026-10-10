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

/* Simulation provider: device layer (request queue + worker threads) */

#include "sim_prov_internal.h"
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#endif

#ifdef HITLS_CRYPTO_PROVIDER

struct SimDevice {
    SimEngine *engine;
    BSL_SAL_Mutex queueMutex;
    BSL_SAL_CondVar queueCond;
    SimOpCtx *queueHead;
    SimOpCtx *queueTail;
    BSL_SAL_ThreadId *threads;
    uint32_t threadCount;
    int32_t *workerCpus;
    bool stop;
};

static void SimWaitNs(uint64_t waitNs)
{
    if (waitNs == 0 || waitNs == SIM_PROV_WAIT_INHERIT) {
        return;
    }
    struct timespec ts = {(time_t)(waitNs / 1000000000u), (long)(waitNs % 1000000000u)};
    (void)nanosleep(&ts, NULL);
}

/* Queue + stop flag are guarded by the dedicated queue mutex so the engine
 * rwlock is never held across a condvar wait or a thread join. */
static void SimQueueLock(SimDevice *e)
{
    (void)pthread_mutex_lock((pthread_mutex_t *)e->queueMutex);
}

static void SimQueueUnlock(SimDevice *e)
{
    (void)pthread_mutex_unlock((pthread_mutex_t *)e->queueMutex);
}

static void SimQueuePush(SimDevice *e, SimOpCtx *op)
{
    op->next = NULL;
    if (e->queueTail == NULL) {
        e->queueHead = op;
    } else {
        e->queueTail->next = op;
    }
    e->queueTail = op;
}

static SimOpCtx *SimQueuePop(SimDevice *e)
{
    SimOpCtx *op = e->queueHead;
    if (op == NULL) {
        return NULL;
    }
    e->queueHead = op->next;
    if (e->queueHead == NULL) {
        e->queueTail = NULL;
    }
    op->next = NULL;
    return op;
}

/* Worker requests compute on the caller's key objects directly: the caller
 * keeps them exclusive to the request for the whole pause window (see the
 * SimOpCtx contract in sim_prov_internal.h). */

static void *SimWorkerLoop(void *arg)
{
    SimDevice *e = arg;
    while (true) {
        SimQueueLock(e);
        if (e->stop) {
            SimQueueUnlock(e);
            break;
        }
        SimOpCtx *op = SimQueuePop(e);
        SimQueueUnlock(e);
        if (op == NULL) {
            /* The SAL condvar pairs with the raw queue mutex; its timed wait
             * covers the (otherwise lost) signal between unlock and wait. */
            (void)BSL_SAL_CondTimedwaitMs(e->queueMutex, e->queueCond, 10);
            continue;
        }
        SimDeviceComplete(e->engine, op, true);
    }
    return NULL;
}

static uint32_t SimDefaultWorkers(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n <= 0) {
        return 4;
    }
    return (uint32_t)n;
}

static void SimDeviceFree(SimDevice *device)
{
    if (device == NULL) {
        return;
    }
    SimQueueLock(device);
    device->stop = true;
    SimQueueUnlock(device);
    /* Best-effort wake-all at teardown: the SAL condvar offers no broadcast,
     * so one signal per thread; a worker that misses its signal observes stop
     * on its next timed-wait timeout. */
    for (uint32_t i = 0; i < device->threadCount; i++) {
        (void)BSL_SAL_CondSignal(device->queueCond);
    }
    for (uint32_t i = 0; i < device->threadCount; i++) {
        BSL_SAL_ThreadClose(device->threads[i]);
    }
    BSL_SAL_Free(device->threads);
    BSL_SAL_Free(device->workerCpus);
    if (device->queueCond != NULL) {
        (void)BSL_SAL_DeleteCondVar(device->queueCond);
    }
    pthread_mutex_destroy((pthread_mutex_t *)device->queueMutex);
    BSL_SAL_Free(device->queueMutex);
    BSL_SAL_Free(device);
}

static int32_t SimCreateWorker(SimDevice *device, int32_t cpu)
{
#ifdef __linux__
    cpu_set_t saved;
    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_getaffinity(0, sizeof(saved), &saved) != 0 || sched_setaffinity(0, sizeof(set), &set) != 0) {
            return SIM_PROV_ERR_STATE;
        }
    }
#endif
    int32_t ret = BSL_SAL_ThreadCreate(&device->threads[device->threadCount], SimWorkerLoop, device);
    if (ret == BSL_SUCCESS) {
        device->threadCount++;
    }
#ifdef __linux__
    if (cpu >= 0 && sched_setaffinity(0, sizeof(saved), &saved) != 0) {
        return SIM_PROV_ERR_STATE;
    }
#else
    (void)cpu;
#endif
    return ret == BSL_SUCCESS ? SIM_PROV_SUCCESS : SIM_PROV_ERR_MEMORY;
}

static bool SimWorkerCpusValid(const int32_t *cpus, uint32_t cpuCount, uint32_t want)
{
    if (cpuCount == 0) {
        return cpus == NULL;
    }
#ifdef __linux__
    if (cpus == NULL || cpuCount != want) {
        return false;
    }
    for (uint32_t i = 0; i < cpuCount; i++) {
        if (cpus[i] < 0 || cpus[i] >= CPU_SETSIZE) {
            return false;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (cpus[i] == cpus[j]) {
                return false;
            }
        }
    }
    return true;
#else
    (void)cpus;
    (void)want;
    return false;
#endif
}

static bool SimDeviceMatches(const SimDevice *device, uint32_t want, const int32_t *cpus)
{
    if (device == NULL) {
        return want == 0;
    }
    if (device->threadCount != want || (device->workerCpus == NULL) != (cpus == NULL)) {
        return false;
    }
    for (uint32_t i = 0; cpus != NULL && i < want; i++) {
        if (device->workerCpus[i] != cpus[i]) {
            return false;
        }
    }
    return true;
}

int32_t SimDeviceEnsure(SimEngine *e, uint32_t execMode, uint32_t workers, const int32_t *cpus, uint32_t cpuCount)
{
    uint32_t want = execMode == SIM_PROV_EXEC_WORKER ? (workers == 0 ? SimDefaultWorkers() : workers) : 0;
    if (!SimWorkerCpusValid(cpus, cpuCount, want)) {
        return SIM_PROV_ERR_ARG;
    }
    if (SimDeviceMatches(e->device, want, cpus)) {
        return CRYPT_SUCCESS;
    }
    SimDevice *device = NULL;
    if (want != 0) {
        device = BSL_SAL_Calloc(1, sizeof(*device));
        if (device == NULL) {
            return SIM_PROV_ERR_MEMORY;
        }
        pthread_mutex_t *mutex = BSL_SAL_Calloc(1, sizeof(*mutex));
        if (mutex == NULL || pthread_mutex_init(mutex, NULL) != 0) {
            BSL_SAL_Free(mutex);
            BSL_SAL_Free(device);
            return SIM_PROV_ERR_MEMORY;
        }
        device->queueMutex = mutex;
        device->engine = e;
        device->threads = BSL_SAL_Calloc(want, sizeof(*device->threads));
        if (device->threads == NULL || BSL_SAL_CreateCondVar(&device->queueCond) != BSL_SUCCESS) {
            SimDeviceFree(device);
            return SIM_PROV_ERR_MEMORY;
        }
        if (cpuCount != 0) {
            device->workerCpus = BSL_SAL_Calloc(cpuCount, sizeof(*cpus));
            if (device->workerCpus == NULL) {
                SimDeviceFree(device);
                return SIM_PROV_ERR_MEMORY;
            }
            for (uint32_t i = 0; i < cpuCount; i++) {
                device->workerCpus[i] = cpus[i];
            }
        }
        for (uint32_t i = 0; i < want; i++) {
            int32_t ret = SimCreateWorker(device, cpus == NULL ? -1 : cpus[i]);
            if (ret != SIM_PROV_SUCCESS) {
                SimDeviceFree(device);
                return ret;
            }
        }
    }
    SimDeviceFree(e->device);
    e->device = device;
    return CRYPT_SUCCESS;
}

void SimDeviceStop(SimEngine *e)
{
    SimDeviceFree(e->device);
    e->device = NULL;
}

/* SimDeviceSubmit never fails while the harness is consistent: the worker path
 * is only reached after SimDeviceEnsure built the pool, and submitters quiesce
 * before SimDeviceStop tears it down. A failure here therefore signals a
 * harness/configuration defect - not a scenario outcome - so it prints the full
 * context on stderr to make the root cause directly locatable instead of
 * surfacing as a bare error code far from the submit point. */
static int32_t SimSubmitFail(SimEngine *e, const SimOpCtx *op, const char *reason)
{
    (void)fprintf(stderr,
                  "[async_sim_provider][ANOMALY] SimDeviceSubmit failed (unreachable in a normal test run): %s "
                  "(execMode=%u, device=%p, opKind=%d, operaId=%d, submitted=%d)\n",
                  reason, (unsigned)e->execMode, (const void *)e->device, (int)op->kind, op->operaId,
                  (int)op->submitted);
    return CRYPT_MEM_ALLOC_FAIL;
}

int32_t SimDeviceSubmit(SimEngine *e, SimOpCtx *op)
{
    /* Ops whose result is required at the call boundary complete inline at the
     * submit point regardless of the configured execution mode:
     *  - COMPLETE returns its result directly to the caller;
     *  - FAST_COMPLETE must post the notification before the pause returns;
     *  - GEN mutates the caller's key object and would be pointless on a copy.
     * PAUSE/FAIL/EAGAIN/DUP_NOTIFY results are collected after the resume, so
     * those go through the worker queue when worker mode is configured. */
    if (e->execMode == SIM_PROV_EXEC_INLINE || op->kind == SIM_OP_KIND_GEN ||
        op->scenario.action == SIM_PROV_ACTION_COMPLETE || op->scenario.action == SIM_PROV_ACTION_FAST_COMPLETE) {
        op->submitted = true;
        SimDeviceComplete(e, op, false);
        return CRYPT_SUCCESS;
    }

    SimDevice *device = e->device;
    if (device == NULL) {
        /* Cannot happen on a correct run: worker mode implies SimDeviceEnsure
         * created the pool before the first submit. */
        return SimSubmitFail(e, op, "worker-mode submit without a device pool (SimDeviceEnsure not applied?)");
    }
    SimQueueLock(device);
    if (device->stop) {
        SimQueueUnlock(device);
        /* Cannot happen on a correct run: stop is set only by SimDeviceStop,
         * which the caller invokes after all submitters have quiesced. */
        return SimSubmitFail(e, op, "submit after SimDeviceStop (teardown race)");
    }
    op->submitted = true;
    SimQueuePush(device, op);
    SimQueueUnlock(device);
    /* One node per submit, so one signal hands it to one worker; condvar
     * signals do not queue, and extra wakeups only pop an empty queue. Any
     * signal lost in the unlock/wait window is covered by the worker's timed
     * wait. */
    (void)BSL_SAL_CondSignal(device->queueCond);
    return CRYPT_SUCCESS;
}

/* Runs on a worker thread (or inline on the submitter). Performs the wait,
 * delegates the real computation and posts the completion notification. */
void SimDeviceComplete(SimEngine *e, SimOpCtx *op, bool onWorker)
{
    uint64_t waitNs = op->scenario.waitNs == SIM_PROV_WAIT_INHERIT ? e->waitNs : op->scenario.waitNs;
    SimWaitNs(waitNs);

    op->ret = SimRunOperation(op);

    bool failed = op->ret != CRYPT_SUCCESS;

    /* A resumed task can reclaim op after observing done. Keep notification
     * delivery inside the publication lock; callbacks may only post events. */
    BSL_SAL_ThreadWriteLock(e->lock);
    op->done = true;
    e->stats.completes++;
    if (failed) {
        e->stats.failures++;
    }
    if (onWorker) {
        e->stats.workerDone++;
    } else {
        e->stats.inlineDone++;
    }
    SimDeviceNotifyLocked(e, op);
    BSL_SAL_ThreadUnlock(e->lock);
}

bool SimDeviceIsDone(SimEngine *e, const SimOpCtx *op)
{
    BSL_SAL_ThreadReadLock(e->lock);
    bool done = op->done;
    BSL_SAL_ThreadUnlock(e->lock);
    return done;
}

void SimDeviceNotifyLocked(SimEngine *e, const SimOpCtx *op)
{
    if (!op->notifyReg) {
        return;
    }
    uint64_t repeat = 1;
    if (op->scenario.action == SIM_PROV_ACTION_DUP_NOTIFY) {
        repeat += op->scenario.notifyRepeat;
    }
    for (uint64_t i = 0; i < repeat; i++) {
        if (op->useCallback && op->cb != NULL) {
            (void)op->cb(op->cbArg);
            e->stats.notifications++;
        } else if (e->notifyFdOpen) {
            SimNotifyFdSignal(&e->notifyFd);
            e->stats.notifications++;
        } else {
            /* No notify channel (OFF build sync fallback): nothing to post. */
        }
    }
}

#endif /* HITLS_CRYPTO_PROVIDER */
