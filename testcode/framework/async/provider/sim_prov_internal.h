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

#ifndef SIM_PROV_INTERNAL_H
#define SIM_PROV_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "hitls_build.h"
#include "sim_prov_ctrl.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_implprovider.h"
#include "crypt_errno.h"

#ifdef HITLS_BSL_ASYNC
#include "bsl_async.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Default provider attribute */
#define SIM_PROV_ATTR "provider=async_sim_async"

/* ---------------- notify fd abstraction (D2) ---------------- */

typedef struct {
    int fd; /* eventfd on Linux, pipe read end elsewhere; -1 when closed */
    int write; /* write end on pipe platforms, unused elsewhere */
} SimNotifyFd;

int32_t SimNotifyFdCreate(SimNotifyFd *nfd);
void SimNotifyFdDestroy(SimNotifyFd *nfd);
void SimNotifyFdSignal(const SimNotifyFd *nfd);

/* ---------------- operation context ---------------- */

/* Execution role of one crypto operation */
typedef enum {
    SIM_OP_KIND_SIGN = 1,
    SIM_OP_KIND_VERIFY = 2,
    SIM_OP_KIND_EXCH = 3,
    SIM_OP_KIND_GEN = 4,
    SIM_OP_KIND_DECODE = 5,
    SIM_OP_KIND_KEM_ENC = 6,
    SIM_OP_KIND_KEM_DEC = 7,
} SimOpKind;

/* Snapshot of the scenario that matched one operation */
typedef struct {
    uint32_t action;
    uint32_t resumeCount;
    uint32_t notifyRepeat;
    uint64_t waitNs;
    int32_t errCode;
} SimScenarioSnap;

/*
 * One in-flight crypto operation. The dispatcher thread creates it, the device
 * layer (inline or worker) fills the result, the dispatcher collects it after
 * each resume. Lifetime spans the pause window, therefore all inputs referenced
 * by the delegated computation must stay valid for that window: the EAL layer
 * above us guarantees this for the sync call parameters because the whole call
 * stack is suspended by BSL_ASYNC_PauseTask.
 *
 * The delegated computation runs on `pkey`/`peer` directly, with no key copy.
 * The caller therefore owns one contract for the whole pause window: the key
 * objects it hands us must stay exclusively ours until the callback returns -
 * not aliased into another in-flight request or task, and not mutated
 * concurrently (the TLS sign path, for example, sets RSA PSS/MD parameters on
 * the key in place right before the call).
 */
typedef struct SimOpCtx {
    /* identity */
    SimOpKind kind;
    int32_t operaId; /* CRYPT_EAL_OPERAID_* used for scenario matching */

    /* delegated computation inputs */
    CRYPT_EAL_PkeyCtx *pkey; /* provider-side key context (ours) */
    const CRYPT_EAL_PkeyCtx *peer; /* verify/exch peer key (borrowed) */
    int32_t mdId;
    const uint8_t *data;
    uint32_t dataLen;
    uint8_t *out; /* output buffer (borrowed from the sync API caller) */
    uint32_t outCap; /* capacity of out */
    uint32_t outLen; /* produced length */
    uint8_t *out2; /* second output buffer (KEM encaps shared secret, borrowed) */
    uint32_t outCap2; /* capacity of out2 */
    uint32_t outLen2; /* produced length of out2 */
    int32_t ret; /* delegated return code */
    int32_t decodeFormat;
    int32_t decodeType;
    const uint8_t *password;
    uint32_t passwordLen;
    CRYPT_EAL_PkeyCtx *decoded;

    /* async orchestration */
    SimScenarioSnap scenario;
    uint32_t pauseRemain;
    bool done; /* device finished (result valid) */
    bool submitted; /* entered the device queue at least once */
    bool notifyReg; /* callback cached or fd registered */
    bool useCallback; /* completion-callback path selected */
    int32_t (*cb)(void *arg); /* cached completion callback */
    void *cbArg;

    /* device linkage */
    struct SimOpCtx *next; /* intrusive queue node */
} SimOpCtx;

/* ---------------- engine ---------------- */

typedef struct SimDevice SimDevice;

typedef struct {
    /* control plane config (written by SET, read by GET) */
    uint32_t execMode;
    uint32_t workers;
    uint64_t waitNs;

    /* scenario table (deep copy) */
    SIM_PROV_SCENARIO *scenarios;
    uint32_t scenarioCount;
    bool *disarmed; /* once-flag per scenario entry */

    /* per-operaId hit counters for scenario matching */
    uint64_t hits[16]; /* indexed by CRYPT_EAL_OPERAID_* (max 12) */

    /* stats */
    SIM_PROV_STATS stats;

    /* device layer */
    BSL_SAL_ThreadLockHandle lock;
    SimDevice *device;
    uint32_t outstanding; /* requests in the device or paused */

    /* notify handle path (single shared source, engine address is the key) */
    SimNotifyFd notifyFd;
    bool notifyFdOpen;
} SimEngine;

/* Global engine singleton: one simulation provider instance per process */
extern SimEngine *g_simEngine;

SimEngine *SimEngineGet(void);
void SimEngineFree(void);

/* Scenario matching: bumps the per-operaId counter, scans in array order,
 * first match wins; returns the snapshot and disarms the entry when once=1. */
void SimScenarioMatch(SimEngine *e, uint32_t operaId, SimScenarioSnap *snap);

int32_t SimRunOperation(SimOpCtx *op);

/* Orchestration (sim_prov_crypto.c) */
int32_t SimCryptoEntry(SimOpCtx *op);

/* Device layer (sim_prov_device.c) */
int32_t SimDeviceEnsure(SimEngine *e, uint32_t execMode, uint32_t workers, const int32_t *cpus, uint32_t cpuCount);
void SimDeviceStop(SimEngine *e);
int32_t SimDeviceSubmit(SimEngine *e, SimOpCtx *op);
void SimDeviceComplete(SimEngine *e, SimOpCtx *op, bool onWorker);
bool SimDeviceIsDone(SimEngine *e, const SimOpCtx *op);
void SimDeviceNotifyLocked(SimEngine *e, const SimOpCtx *op);

/* Provider callbacks (sim_prov_init.c) */
int32_t SimProvQuery(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos);
extern const CRYPT_EAL_AlgInfo g_simDecoderAlgs[];

#ifdef __cplusplus
}
#endif

#endif /* SIM_PROV_INTERNAL_H */
