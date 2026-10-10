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

/**
 * @defgroup sim_prov_ctrl
 * @ingroup testcode
 * @brief Control-plane contract shared by the async simulation crypto provider and its consumers
 */

#ifndef SIM_PROV_CTRL_H
#define SIM_PROV_CTRL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Smallest prefix of SIM_PROV_CTRL_REQ the provider reads for SET (through scenarioCount) */
#define SIM_PROV_REQ_SET_MIN_SIZE ((uint32_t)offsetof(SIM_PROV_CTRL_REQ, stats))
/** Smallest prefix the provider reads for GET/RESET (through the stats field, result included) */
#define SIM_PROV_REQ_GET_MIN_SIZE ((uint32_t)offsetof(SIM_PROV_CTRL_REQ, outstanding))

/**
 * @ingroup sim_prov_ctrl
 * @brief The single control command of the simulation provider ('S','I','M',1)
 *
 * Must avoid CRYPT_PROVIDER_GET_USER_CTX (=1), which the EAL intercepts
 * without forwarding to the provider.
 */
#define SIM_PROV_CTRL_CMD 0x53494D01

/** Result codes of the control command; the provider never pushes them onto the BSL error stack */
#define SIM_PROV_SUCCESS    0
#define SIM_PROV_ERR_SIZE   1
#define SIM_PROV_ERR_OP     2
#define SIM_PROV_ERR_ARG    3
#define SIM_PROV_ERR_STATE  4
#define SIM_PROV_ERR_MEMORY 5

/** Operation selector of SIM_PROV_CTRL_REQ */
typedef enum {
    SIM_PROV_OP_SET = 1,
    SIM_PROV_OP_GET = 2,
    SIM_PROV_OP_RESET = 3,
} SIM_PROV_OP;

/** Execution mode: where the real crypto computation happens */
typedef enum {
    SIM_PROV_EXEC_INLINE = 1,
    SIM_PROV_EXEC_WORKER = 2,
} SIM_PROV_EXEC_MODE;

/** Scenario action set (async path only; the sync path never consults the table) */
typedef enum {
    SIM_PROV_ACTION_COMPLETE = 1,
    SIM_PROV_ACTION_PAUSE = 2,
    SIM_PROV_ACTION_FAIL = 3,
    SIM_PROV_ACTION_EAGAIN = 4,
    SIM_PROV_ACTION_FAST_COMPLETE = 5,
    SIM_PROV_ACTION_DUP_NOTIFY = 6,
    SIM_PROV_ACTION_NEVER = 7,
} SIM_PROV_ACTION;

/** Matches any crypto operation id */
#define SIM_PROV_OPERA_ANY 0u
/** Scenario-level wait time inheriting the device base wait time */
#define SIM_PROV_WAIT_INHERIT UINT64_MAX

/**
 * @ingroup sim_prov_ctrl
 * @brief One exception-injection rule of the scenario table
 */
typedef struct {
    uint32_t operaId; /* CRYPT_EAL_OPERAID_* or SIM_PROV_OPERA_ANY */
    uint32_t hitIndex; /* 1-based hit ordinal of that operaId; 0 = every hit */
    uint32_t action; /* SIM_PROV_ACTION_* */
    uint32_t resumeCount; /* pauses before completion; 0 = action default (1) */
    uint32_t notifyRepeat; /* extra notify posts; DUP_NOTIFY only */
    uint32_t once; /* 1 = entry disarms after one hit */
    uint64_t waitNs; /* SIM_PROV_WAIT_INHERIT = inherit device base */
    int32_t errCode; /* FAIL action return code, must be non-zero */
    uint32_t reserved; /* must be 0 */
} SIM_PROV_SCENARIO;

/**
 * @ingroup sim_prov_ctrl
 * @brief Provider observation counters
 */
typedef struct {
    uint64_t cryptoCalls; /* crypto callback invocations, sync included */
    uint64_t syncDirectCalls; /* sync-path direct delegations */
    uint64_t submits; /* requests successfully submitted to the device */
    uint64_t resubmits; /* re-submissions after EAGAIN */
    uint64_t pauses; /* BSL_ASYNC_PauseTask invocations */
    uint64_t resumes; /* re-entries into the provider after resume */
    uint64_t completes; /* completed requests */
    uint64_t failures; /* injected or delegated failures */
    uint64_t notifications; /* posted notifications */
    uint64_t inlineDone; /* requests completed in place */
    uint64_t workerDone; /* requests completed on worker threads */
} SIM_PROV_STATS;

/**
 * @ingroup sim_prov_ctrl
 * @brief The extensible single-command structure
 *
 * New fields may only be appended at the tail; the caller passes its own
 * sizeof(SIM_PROV_CTRL_REQ) as valLen, which bounds the prefix the provider
 * may access.
 */
typedef struct {
    uint32_t op; /* [IN]  SIM_PROV_OP_* */
    uint32_t result; /* [OUT] SIM_PROV_SUCCESS or SIM_PROV_ERR_* */
    uint32_t execMode; /* [IN]  SIM_PROV_EXEC_* (SET) */
    uint32_t workers; /* [IN]  worker threads; 0 = default (CPU count) (SET) */
    uint64_t waitNs; /* [IN]  device base wait time in ns (SET) */
    const SIM_PROV_SCENARIO *scenarios; /* [IN]  scenario array (SET) */
    uint32_t scenarioCount; /* [IN]  scenario array length (SET) */
    SIM_PROV_STATS stats; /* [OUT] filled by GET/RESET */
    uint32_t outstanding; /* [OUT] requests not yet collected; optional GET/RESET tail */
    const int32_t *workerCpus; /* optional SET tail: one logical CPU per worker */
    uint32_t workerCpuCount; /* 0 keeps the inherited affinity */
} SIM_PROV_CTRL_REQ;

#ifdef __cplusplus
}
#endif

#endif /* SIM_PROV_CTRL_H */
