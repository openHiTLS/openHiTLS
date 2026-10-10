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

/* Simulation provider: single-command control plane and engine singleton */

#include "sim_prov_internal.h"
#include <string.h>

#ifdef HITLS_CRYPTO_PROVIDER

SimEngine *g_simEngine = NULL;

SimEngine *SimEngineGet(void)
{
    if (g_simEngine == NULL) {
        SimEngine *e = BSL_SAL_Calloc(1, sizeof(SimEngine));
        if (e == NULL) {
            return NULL;
        }
        if (BSL_SAL_ThreadLockNew(&e->lock) != BSL_SUCCESS) {
            BSL_SAL_Free(e);
            return NULL;
        }
        e->execMode = SIM_PROV_EXEC_INLINE;
        e->workers = 0;
        e->waitNs = 0;
        e->notifyFd.fd = -1;
        e->notifyFd.write = -1;
        g_simEngine = e;
    }
    return g_simEngine;
}

void SimEngineFree(void)
{
    SimEngine *e = g_simEngine;
    if (e == NULL) {
        return;
    }
    SimDeviceStop(e);
    if (e->scenarios != NULL) {
        BSL_SAL_Free(e->scenarios);
    }
    if (e->disarmed != NULL) {
        BSL_SAL_Free(e->disarmed);
    }
    if (e->notifyFdOpen) {
        SimNotifyFdDestroy(&e->notifyFd);
        e->notifyFdOpen = false;
    }
    if (e->lock != NULL) {
        BSL_SAL_ThreadLockFree(e->lock);
    }
    BSL_SAL_Free(e);
    g_simEngine = NULL;
}

/* Minimum struct bytes for each op: SET reads through scenarioCount, GET/RESET
 * read the whole struct including the stats they fill. */
static uint32_t SimProvMinSize(uint32_t op)
{
    switch (op) {
        case SIM_PROV_OP_SET:
            return SIM_PROV_REQ_SET_MIN_SIZE;
        case SIM_PROV_OP_GET:
        case SIM_PROV_OP_RESET:
            return SIM_PROV_REQ_GET_MIN_SIZE;
        default:
            return SIM_PROV_REQ_GET_MIN_SIZE;
    }
}

static bool SimProvExecModeValid(uint32_t mode)
{
    return mode == SIM_PROV_EXEC_INLINE || mode == SIM_PROV_EXEC_WORKER;
}

static int32_t SimProvApplySet(SimEngine *e, SIM_PROV_CTRL_REQ *req, uint32_t valLen)
{
    const int32_t *cpus = NULL;
    uint32_t cpuCount = 0;
    if (valLen >= offsetof(SIM_PROV_CTRL_REQ, workerCpuCount) + sizeof(req->workerCpuCount)) {
        cpus = req->workerCpus;
        cpuCount = req->workerCpuCount;
    }
    if ((cpus == NULL) != (cpuCount == 0) || (cpuCount != 0 && req->execMode != SIM_PROV_EXEC_WORKER)) {
        return SIM_PROV_ERR_ARG;
    }
    SIM_PROV_SCENARIO *copy = NULL;
    bool *disarmed = NULL;

    if (!SimProvExecModeValid(req->execMode)) {
        return SIM_PROV_ERR_ARG;
    }
    if (req->scenarios == NULL && req->scenarioCount != 0) {
        return SIM_PROV_ERR_ARG;
    }
    if (req->scenarioCount != 0) {
        for (uint32_t i = 0; i < req->scenarioCount; i++) {
            const SIM_PROV_SCENARIO *s = &req->scenarios[i];
            if (s->reserved != 0 || s->once > 1 || s->operaId > CRYPT_EAL_OPERAID_SELFTEST ||
                s->action < SIM_PROV_ACTION_COMPLETE || s->action > SIM_PROV_ACTION_NEVER) {
                return SIM_PROV_ERR_ARG;
            }
            if (s->action == SIM_PROV_ACTION_FAIL && s->errCode == 0) {
                return SIM_PROV_ERR_ARG;
            }
        }
        copy = BSL_SAL_Calloc(req->scenarioCount, sizeof(SIM_PROV_SCENARIO));
        disarmed = BSL_SAL_Calloc(req->scenarioCount, sizeof(bool));
        if (copy == NULL || disarmed == NULL) {
            BSL_SAL_FREE(copy);
            BSL_SAL_FREE(disarmed);
            return SIM_PROV_ERR_MEMORY;
        }
        for (uint32_t i = 0; i < req->scenarioCount; i++) {
            copy[i] = req->scenarios[i];
        }
    }

    BSL_SAL_ThreadWriteLock(e->lock);
    if (e->outstanding != 0) {
        BSL_SAL_ThreadUnlock(e->lock);
        BSL_SAL_FREE(copy);
        BSL_SAL_FREE(disarmed);
        return SIM_PROV_ERR_STATE;
    }
    BSL_SAL_ThreadUnlock(e->lock);
    int32_t ret = SimDeviceEnsure(e, req->execMode, req->workers, cpus, cpuCount);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(copy);
        BSL_SAL_FREE(disarmed);
        return ret;
    }
    BSL_SAL_ThreadWriteLock(e->lock);
    e->execMode = req->execMode;
    e->workers = req->workers;
    e->waitNs = req->waitNs;
    BSL_SAL_FREE(e->scenarios);
    BSL_SAL_FREE(e->disarmed);
    e->scenarios = copy;
    e->disarmed = disarmed;
    e->scenarioCount = req->scenarioCount;
    /* per-operaId hit counters follow the new table */
    for (uint32_t i = 0; i < 16; i++) {
        e->hits[i] = 0;
    }
    BSL_SAL_ThreadUnlock(e->lock);

    return SIM_PROV_SUCCESS;
}

static void SimProvFillStats(SimEngine *e, SIM_PROV_CTRL_REQ *req, uint32_t valLen)
{
    req->execMode = e->execMode;
    req->workers = e->workers;
    req->waitNs = e->waitNs;
    req->scenarios = e->scenarios;
    req->scenarioCount = e->scenarioCount;
    req->stats = e->stats;
    if (valLen >= offsetof(SIM_PROV_CTRL_REQ, outstanding) + sizeof(req->outstanding)) {
        req->outstanding = e->outstanding;
    }
}

static int32_t SimProvApplyCtrl(SimEngine *e, SIM_PROV_CTRL_REQ *req, uint32_t valLen)
{
    switch (req->op) {
        case SIM_PROV_OP_SET:
            return SimProvApplySet(e, req, valLen);
        case SIM_PROV_OP_GET:
            BSL_SAL_ThreadReadLock(e->lock);
            SimProvFillStats(e, req, valLen);
            BSL_SAL_ThreadUnlock(e->lock);
            return SIM_PROV_SUCCESS;
        case SIM_PROV_OP_RESET:
            BSL_SAL_ThreadWriteLock(e->lock);
            if (e->outstanding != 0) {
                BSL_SAL_ThreadUnlock(e->lock);
                return SIM_PROV_ERR_STATE;
            }
            SIM_PROV_STATS previous = e->stats;
            e->execMode = SIM_PROV_EXEC_INLINE;
            e->workers = 0;
            e->waitNs = 0;
            BSL_SAL_FREE(e->scenarios);
            BSL_SAL_FREE(e->disarmed);
            e->scenarioCount = 0;
            for (uint32_t i = 0; i < 16; i++) {
                e->hits[i] = 0;
            }
            BSL_SAL_CleanseData(&e->stats, sizeof(e->stats));
            SimProvFillStats(e, req, valLen);
            req->stats = previous;
            BSL_SAL_ThreadUnlock(e->lock);
            (void)SimDeviceEnsure(e, SIM_PROV_EXEC_INLINE, 0, NULL, 0);
            return SIM_PROV_SUCCESS;
        default:
            return SIM_PROV_ERR_OP;
    }
}

int32_t SimProvCtrl(void *provCtx, int32_t cmd, void *val, uint32_t valLen)
{
    (void)provCtx;
    if (cmd != SIM_PROV_CTRL_CMD) {
        return SIM_PROV_ERR_OP;
    }
    if (val == NULL || valLen < offsetof(SIM_PROV_CTRL_REQ, result) + sizeof(uint32_t)) {
        return SIM_PROV_ERR_SIZE;
    }
    SIM_PROV_CTRL_REQ *req = (SIM_PROV_CTRL_REQ *)val;
    if (req->op != SIM_PROV_OP_SET && req->op != SIM_PROV_OP_GET && req->op != SIM_PROV_OP_RESET) {
        req->result = (uint32_t)SIM_PROV_ERR_OP;
        return SIM_PROV_ERR_OP;
    }
    if (valLen < SimProvMinSize(req->op)) {
        req->result = (uint32_t)SIM_PROV_ERR_SIZE;
        return SIM_PROV_ERR_SIZE;
    }
    SimEngine *e = SimEngineGet();
    if (e == NULL) {
        req->result = (uint32_t)SIM_PROV_ERR_MEMORY;
        return SIM_PROV_ERR_MEMORY;
    }
    int32_t ret = SimProvApplyCtrl(e, req, valLen);
    req->result = (uint32_t)ret;
    return ret;
}

void SimProvFree(void *provCtx)
{
    (void)provCtx;
    SimEngineFree();
}

#endif /* HITLS_CRYPTO_PROVIDER */
