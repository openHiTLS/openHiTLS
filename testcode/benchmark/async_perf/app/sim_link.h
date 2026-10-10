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

#ifndef SIM_LINK_H
#define SIM_LINK_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include "async_perf_opt.h"
#include "hitls.h"
#include "hitls_config.h"

typedef struct PerfEndpoint {
    HITLS_Ctx *ctx;
    int fd;
    int32_t ret;
    uint8_t byte;
    uint32_t ioLen;
    atomic_bool posted;
    uint32_t phase;
    struct PerfBatch *batch;
    struct PerfEndpoint *notifyNext;
    struct PerfEndpoint *waitNext;
} PerfEndpoint;

typedef struct PerfBatch {
    PerfEndpoint *servers;
    HITLS_Config *serverCfg;
    uint32_t n;
    uint32_t doneServers;
    uint64_t startNs;
    uint64_t doneNs;
    PerfForm form;
    int listener;
    int wakeFds[2];
    pthread_mutex_t notifyMutex;
    bool notifyMutexInit;
    PerfEndpoint *notified;
} PerfBatch;

#define PERF_TIMEOUT_MS 30000

int PerfListen(uint16_t port);
int32_t PerfBatchCreate(HITLS_Config *serverCfg, uint32_t n, PerfForm form, int listener, PerfBatch *batch);
void PerfBatchDestroy(PerfBatch *batch);
bool PerfAsyncSupported(void);
int32_t PerfRunServer(PerfBatch *batch);

#endif /* SIM_LINK_H */
