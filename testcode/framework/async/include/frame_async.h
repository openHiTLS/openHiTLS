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
 * @defgroup frame_async
 * @ingroup testcode
 * @brief Test-framework side of the async simulation provider: lifecycle, control,
 * observation and link driving helpers
 */

#ifndef FRAME_ASYNC_H
#define FRAME_ASYNC_H

#include "sim_prov_ctrl.h"
#include "crypt_eal_provider.h"
#include <stdatomic.h>

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
#include "hitls.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FRAME_ASYNC_SUCCESS        0
#define FRAME_ASYNC_ERR_NOT_LOADED 1
#define FRAME_ASYNC_ERR_STATE      2
#define FRAME_ASYNC_ERR_TIMEOUT    3
#define FRAME_ASYNC_ERR_PROVIDER   4
#define FRAME_ASYNC_ERR_PROTOCOL   5

#define FRAME_ASYNC_PROVIDER_NAME "async_sim_provider"
#define FRAME_ASYNC_PROVIDER_ATTR "provider=async_sim_async"

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
/**
 * @ingroup frame_async
 * @brief One registered connection of the async driving group
 *
 * The frame records the last protocol API and its parameters so a resume
 * replays them unchanged (HITLS rejects a mismatching resume with HITLS_ASYNC_ERR_OPERATION_BUSY).
 */
typedef enum {
    FRAME_ASYNC_OP_NONE = 0,
    FRAME_ASYNC_OP_CONNECT,
    FRAME_ASYNC_OP_ACCEPT,
    FRAME_ASYNC_OP_READ,
} FRAME_ASYNC_OP;

typedef struct FrameAsyncLink {
    struct FRAME_LinkObj_ *linkObj;
    struct FrameAsyncLink *peer; /* the other end of the memory UIO pair */
    HITLS_Ctx *ctx; /* cached FRAME_GetTlsCtx(linkObj) */
    /* last protocol API and parameters */
    FRAME_ASYNC_OP lastOp; /* pending API to replay on resume */
    uint8_t *readBuf; /* READ buffer address */
    uint32_t readSize;
    uint32_t *readLenOut;
    int32_t lastRet; /* most recent direct return of the protocol API */
    bool done; /* handshake finished on this end */
    /* callback-path completion flag: FRAME_ASYNC_OnDone posts it from worker
     * threads, the pump drains it on the owner thread */
    atomic_int cbPosted;
    /* handshake-drive drain read: after this side's handshake call returns
     * SUCCESS while the peer still sends, the frame keeps reading (the
     * trailing NewSessionTicket is consumed by Read); keeps the pull model
     * converging until the peer finishes */
    uint8_t drainBuf[512];
    uint32_t drainLen;
    bool draining;
} FRAME_ASYNC_Link;

/**
 * @ingroup frame_async
 * @brief Frame-supplied completion callback for the callback path
 *
 * Installs with HITLS_SetAsyncCallback(ctx, FRAME_ASYNC_OnDone, link). It
 * only posts the link into the pump's completion set (a callback never resumes the task); FRAME_ASYNC_Pump drains
 * the set on the owner
 * thread. Tests that want the notify-handle path install no callback at all.
 *
 * @param ctx [IN] Connection the completion belongs to (unused)
 * @param arg [IN] The FRAME_ASYNC_Link handle of that connection
 * @retval HITLS_SUCCESS always
 */
int32_t FRAME_ASYNC_OnDone(HITLS_Ctx *ctx, void *arg);
#endif /* HITLS_TLS_FEATURE_MODE_ASYNC */

/* ---------------- lifecycle ---------------- */

int32_t FRAME_ASYNC_InitThread(uint32_t maxTasks, uint32_t initialTasks);

int32_t FRAME_ASYNC_CleanupThread(void);

int32_t FRAME_ASYNC_LoadProvider(const char *loadPath);

int32_t FRAME_ASYNC_UnloadProvider(void);

/* Borrowed library context with the default + simulation providers loaded;
 * lets tests route CRYPT_EAL_Provider* calls through the simulation provider. */
CRYPT_EAL_LibCtx *FRAME_ASYNC_GetLibCtx(void);

/* ---------------- control ---------------- */

/**
 * @ingroup frame_async
 * @brief Replace the scenario table of the simulation engine
 *
 * The device fields of the frame-side configuration are preserved. NULL with
 * count 0 clears the table.
 *
 * @param scenarios [IN] Scenario array; may be NULL only when count is 0
 * @param count [IN] Number of entries
 * @retval FRAME_ASYNC_SUCCESS success
 * @retval FRAME_ASYNC_ERR_NOT_LOADED provider not loaded
 * @retval FRAME_ASYNC_ERR_PROVIDER provider rejected the request
 * @retval FRAME_ASYNC_ERR_STATE non-owner thread
 */
int32_t FRAME_ASYNC_SetScenario(const SIM_PROV_SCENARIO *scenarios, uint32_t count);

/**
 * @ingroup frame_async
 * @brief Set the execution mode and device parameters of the simulation engine
 *
 * The scenario table of the frame-side configuration is preserved. A full SET
 * resets the scenario hit counters and is rejected while a request is
 * outstanding.
 *
 * @param execMode [IN] SIM_PROV_EXEC_INLINE or SIM_PROV_EXEC_WORKER
 * @param workers [IN] Worker threads; 0 selects the default count
 * @param waitNs [IN] Base device wait in nanoseconds; 0 does not wait
 * @retval FRAME_ASYNC_SUCCESS success
 * @retval FRAME_ASYNC_ERR_NOT_LOADED provider not loaded
 * @retval FRAME_ASYNC_ERR_PROVIDER provider rejected the request
 * @retval FRAME_ASYNC_ERR_STATE non-owner thread
 */
int32_t FRAME_ASYNC_SetDevice(uint32_t execMode, uint32_t workers, uint64_t waitNs);

/* ---------------- observation ---------------- */

int32_t FRAME_ASYNC_GetStats(SIM_PROV_STATS *stats);

/* Any-thread snapshot; UINT32_MAX means the provider query failed. */
uint32_t FRAME_ASYNC_GetOutstanding(void);

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
/* ---------------- driving group ---------------- */

/**
 * @ingroup frame_async
 * @brief Register a connection pair member for the frame driving group
 *
 * @param linkObj [IN] Connection created by FRAME_CreateLink
 * @param out [OUT] Registration handle
 * @retval FRAME_ASYNC_SUCCESS success
 * @retval FRAME_ASYNC_ERR_STATE non-owner thread or duplicate registration
 */
int32_t FRAME_ASYNC_AttachLink(struct FRAME_LinkObj_ *linkObj, FRAME_ASYNC_Link **out);

/**
 * @ingroup frame_async
 * @brief Unregister a connection from the driving group
 *
 * @param link [IN] Registration handle
 * @retval FRAME_ASYNC_SUCCESS success
 * @retval FRAME_ASYNC_ERR_STATE the connection still has an outstanding task
 */
int32_t FRAME_ASYNC_DetachLink(FRAME_ASYNC_Link *link);

/**
 * @ingroup frame_async
 * @brief Advance the event loop once: drain completions, wait, resume
 *
 * @param timeoutMs [IN] Upper bound of this round's wait; 0 does not block
 * @retval FRAME_ASYNC_SUCCESS at least one connection progressed
 * @retval FRAME_ASYNC_ERR_TIMEOUT nothing progressed within timeoutMs
 * @retval FRAME_ASYNC_ERR_STATE non-owner thread
 */
int32_t FRAME_ASYNC_Pump(uint32_t timeoutMs);

/**
 * @ingroup frame_async
 * @brief Drive a client/server pair to both sides established
 *
 * @param client [IN] Client registration handle
 * @param server [IN] Server registration handle
 * @param timeoutMs [IN] Handshake deadline before bounded cleanup
 * @retval FRAME_ASYNC_SUCCESS both sides established
 * @retval FRAME_ASYNC_ERR_TIMEOUT not established within timeoutMs
 * @retval FRAME_ASYNC_ERR_PROTOCOL a fatal protocol error occurred
 * @retval FRAME_ASYNC_ERR_STATE driver failure or pending tasks could not be drained
 */
int32_t FRAME_ASYNC_Handshake(FRAME_ASYNC_Link *client, FRAME_ASYNC_Link *server, uint32_t timeoutMs);
#endif /* HITLS_TLS_FEATURE_MODE_ASYNC */

#ifdef __cplusplus
}
#endif

#endif /* FRAME_ASYNC_H */
