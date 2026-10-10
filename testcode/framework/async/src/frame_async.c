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

/* Test-framework side of the simulation provider: lifecycle, control and
 * observation. The frame keeps a full config copy so dimension-wise setters
 * merge into one whole-struct SET. */

#include "frame_async.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_async.h"
#include "crypt_eal_provider.h"
#include "crypt_errno.h"
#include "hitls_error.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#ifndef HITLS_ASYNC_SIM_PROVIDER_DIR
#define HITLS_ASYNC_SIM_PROVIDER_DIR "testcode/output/async_sim_provider"
#endif

typedef struct {
    int loaded;
    int inited;
    uint64_t ownerTid;
    CRYPT_EAL_LibCtx *libCtx;
    CRYPT_EAL_ProvMgrCtx *mgrCtx;
    SIM_PROV_CTRL_REQ req; /* current full config */
    SIM_PROV_SCENARIO *scenarios; /* frame-owned copy of the scenario array */
    uint32_t scenarioCount;
} FrameAsyncState;

static FrameAsyncState g_state = {0};
/* The provider lifecycle and control path exists only when the library was
 * built with HITLS_CRYPTO_PROVIDER; without it the frame stays linkable and
 * reports the provider as permanently unavailable. */
#ifdef HITLS_CRYPTO_PROVIDER
static pthread_mutex_t g_observationLock = PTHREAD_MUTEX_INITIALIZER;
#endif

static int32_t FrameAsyncQuery(SIM_PROV_CTRL_REQ *req)
{
#ifdef HITLS_CRYPTO_PROVIDER
    pthread_mutex_lock(&g_observationLock);
    int32_t ret = FRAME_ASYNC_ERR_NOT_LOADED;
    if (g_state.loaded) {
        ret = CRYPT_EAL_ProviderCtrl(g_state.mgrCtx, SIM_PROV_CTRL_CMD, req, sizeof(*req)) == SIM_PROV_SUCCESS ?
                  FRAME_ASYNC_SUCCESS :
                  FRAME_ASYNC_ERR_PROVIDER;
    }
    pthread_mutex_unlock(&g_observationLock);
    return ret;
#else
    (void)req;
    return FRAME_ASYNC_ERR_NOT_LOADED;
#endif
}

#ifdef HITLS_CRYPTO_PROVIDER
static void FrameAsyncCacheConfig(const SIM_PROV_CTRL_REQ *req, SIM_PROV_SCENARIO *scenarios)
{
    BSL_SAL_FREE(g_state.scenarios);
    g_state.scenarios = scenarios;
    g_state.scenarioCount = req == NULL ? 0 : req->scenarioCount;
    g_state.req = (SIM_PROV_CTRL_REQ){.execMode = req == NULL ? SIM_PROV_EXEC_INLINE : req->execMode,
                                      .workers = req == NULL ? 0 : req->workers,
                                      .waitNs = req == NULL ? 0 : req->waitNs};
}
#endif

static bool FrameAsyncIsOwner(void)
{
    return g_state.ownerTid == BSL_SAL_ThreadGetId();
}

static bool FrameAsyncIsIdle(void)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (!g_state.loaded) {
        return true;
    }
    SIM_PROV_CTRL_REQ req = {.op = SIM_PROV_OP_GET};
    return CRYPT_EAL_ProviderCtrl(g_state.mgrCtx, SIM_PROV_CTRL_CMD, &req, sizeof(req)) == SIM_PROV_SUCCESS &&
           req.outstanding == 0;
#else
    return true; /* nothing can be loaded without the provider framework */
#endif
}

int32_t FRAME_ASYNC_InitThread(uint32_t maxTasks, uint32_t initialTasks)
{
    if (g_state.inited || (g_state.loaded && !FrameAsyncIsOwner())) {
        return FRAME_ASYNC_ERR_STATE;
    }
    g_state.ownerTid = BSL_SAL_ThreadGetId();
    int32_t ret = BSL_ASYNC_InitThread(maxTasks, initialTasks, 0);
    if (ret != BSL_SUCCESS) {
        if (!g_state.loaded) {
            g_state.ownerTid = 0;
        }
        return ret;
    }
    g_state.inited = 1;
    return FRAME_ASYNC_SUCCESS;
}

int32_t FRAME_ASYNC_CleanupThread(void)
{
    if (!g_state.inited) {
        return FRAME_ASYNC_SUCCESS;
    }
    if (!FrameAsyncIsOwner() || BSL_ASYNC_GetCurrentTask() != NULL || !FrameAsyncIsIdle()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    BSL_ASYNC_CleanupThread();
    g_state.inited = 0;
    if (!g_state.loaded) {
        g_state.ownerTid = 0;
    }
    return FRAME_ASYNC_SUCCESS;
}

int32_t FRAME_ASYNC_LoadProvider(const char *loadPath)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (g_state.loaded) {
        return FRAME_ASYNC_ERR_STATE;
    }
    if (!g_state.inited) {
        return FRAME_ASYNC_ERR_STATE;
    }
    if (!FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }

    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    if (libCtx == NULL) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    const char *path = loadPath;
    if (path == NULL) {
        path = getenv("HITLS_ASYNC_SIM_PROVIDER_PATH");
        if (path == NULL || path[0] == '\0') {
            path = HITLS_ASYNC_SIM_PROVIDER_DIR;
        }
    }
    int32_t ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, path);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(libCtx);
        return ret;
    }
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_LIBSO, FRAME_ASYNC_PROVIDER_NAME, NULL, &mgrCtx);
    if (ret != CRYPT_SUCCESS || mgrCtx == NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
        /* EAL failures pass through; a NULL mgrCtx with a
         * success code has no code to pass through */
        return ret != CRYPT_SUCCESS ? ret : FRAME_ASYNC_ERR_PROVIDER;
    }
    /* Decoder candidates follow provider load order. */
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(libCtx);
        return ret;
    }

    pthread_mutex_lock(&g_observationLock);
    g_state.libCtx = libCtx;
    g_state.mgrCtx = mgrCtx;
    g_state.loaded = 1;
    pthread_mutex_unlock(&g_observationLock);
    FrameAsyncCacheConfig(NULL, NULL);
    return FRAME_ASYNC_SUCCESS;
#else
    (void)loadPath;
    return FRAME_ASYNC_ERR_PROVIDER;
#endif
}

int32_t FRAME_ASYNC_UnloadProvider(void)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (!g_state.loaded) {
        return FRAME_ASYNC_ERR_NOT_LOADED;
    }
    if (!FrameAsyncIsOwner() || BSL_ASYNC_GetCurrentTask() != NULL || !FrameAsyncIsIdle()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    pthread_mutex_lock(&g_observationLock);
    if (CRYPT_EAL_ProviderUnload(g_state.libCtx, BSL_SAL_LIB_FMT_LIBSO, FRAME_ASYNC_PROVIDER_NAME) != CRYPT_SUCCESS) {
        pthread_mutex_unlock(&g_observationLock);
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    CRYPT_EAL_LibCtxFree(g_state.libCtx);
    g_state.libCtx = NULL;
    g_state.mgrCtx = NULL;
    g_state.loaded = 0;
    pthread_mutex_unlock(&g_observationLock);
    if (!g_state.inited) {
        g_state.ownerTid = 0;
    }
    FrameAsyncCacheConfig(NULL, NULL);
    return FRAME_ASYNC_SUCCESS;
#else
    return FRAME_ASYNC_ERR_NOT_LOADED;
#endif
}

CRYPT_EAL_LibCtx *FRAME_ASYNC_GetLibCtx(void)
{
    if (!g_state.loaded) {
        return NULL;
    }
    return g_state.libCtx;
}

/* Raw SET passthrough shared by the public setters. The frame-owned scenario
 * copy is published only after the provider accepted the request.
 * Not exported: FRAME_ASYNC_SetScenario / FRAME_ASYNC_SetDevice are the
 * supported entry points. */
static int32_t FrameAsyncSetConfig(SIM_PROV_CTRL_REQ *req)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (!g_state.loaded) {
        return FRAME_ASYNC_ERR_NOT_LOADED;
    }
    if (!FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    if (req == NULL) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    SIM_PROV_SCENARIO *copy = NULL;
    if (req->op == SIM_PROV_OP_SET && req->scenarioCount != 0 && req->scenarios != NULL) {
        copy = BSL_SAL_Calloc(req->scenarioCount, sizeof(*copy));
        if (copy == NULL) {
            return FRAME_ASYNC_ERR_PROVIDER;
        }
        memcpy(copy, req->scenarios, req->scenarioCount * sizeof(*copy));
    }
    int32_t ret = CRYPT_EAL_ProviderCtrl(g_state.mgrCtx, SIM_PROV_CTRL_CMD, req, sizeof(*req));
    if (ret != SIM_PROV_SUCCESS) {
        BSL_SAL_Free(copy);
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    if (req->op == SIM_PROV_OP_SET) {
        FrameAsyncCacheConfig(req, copy);
    }
    return FRAME_ASYNC_SUCCESS;
#else
    (void)req;
    return FRAME_ASYNC_ERR_NOT_LOADED;
#endif
}

int32_t FRAME_ASYNC_SetScenario(const SIM_PROV_SCENARIO *scenarios, uint32_t count)
{
    if (!g_state.loaded) {
        return FRAME_ASYNC_ERR_NOT_LOADED;
    }
    if (!FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    SIM_PROV_CTRL_REQ req = g_state.req;
    req.op = SIM_PROV_OP_SET;
    req.scenarios = scenarios;
    req.scenarioCount = count;
    return FrameAsyncSetConfig(&req);
}

int32_t FRAME_ASYNC_SetDevice(uint32_t execMode, uint32_t workers, uint64_t waitNs)
{
    if (!g_state.loaded) {
        return FRAME_ASYNC_ERR_NOT_LOADED;
    }
    if (!FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    SIM_PROV_CTRL_REQ req = {.op = SIM_PROV_OP_SET,
                             .execMode = execMode,
                             .workers = workers,
                             .waitNs = waitNs,
                             .scenarios = g_state.scenarios,
                             .scenarioCount = g_state.scenarioCount};
    return FrameAsyncSetConfig(&req);
}

int32_t FRAME_ASYNC_GetStats(SIM_PROV_STATS *stats)
{
    if (stats == NULL) {
        return FRAME_ASYNC_ERR_STATE;
    }
    SIM_PROV_CTRL_REQ req = {.op = SIM_PROV_OP_GET};
    int32_t ret = FrameAsyncQuery(&req);
    if (ret == FRAME_ASYNC_SUCCESS) {
        *stats = req.stats;
    }
    return ret;
}

uint32_t FRAME_ASYNC_GetOutstanding(void)
{
    SIM_PROV_CTRL_REQ req = {.op = SIM_PROV_OP_GET};
    int32_t ret = FrameAsyncQuery(&req);
    if (ret == FRAME_ASYNC_ERR_NOT_LOADED) {
        return 0;
    }
    return ret == FRAME_ASYNC_SUCCESS ? req.outstanding : UINT32_MAX;
}

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC

/* ---------------- driving group ----------------
 *
 * Phase-2 interfaces: connection registration, the pump event loop and the
 * handshake driver. All resumes happen on the owner thread and replay the
 * recorded protocol API with its original parameters; the protocol layer
 * rejects a mismatching resume with HITLS_ASYNC_ERR_OPERATION_BUSY.
 *
 * The two FRAME_* helpers are forward-declared on purpose: frame_tls.h drags
 * the whole TLS internal header tree into the include path. The symbols
 * resolve at the final link against tls_frame, which every SDV suite links.
 *
 * TLS_CONNECTED (handshake-done value of HITLS_GetHandShakeState) lives in
 * the internal tls.h - the SDV test framework's established convention. */

struct FRAME_LinkObj_;
int32_t FRAME_TrasferMsgBetweenLink(struct FRAME_LinkObj_ *linkA, struct FRAME_LinkObj_ *linkB);
HITLS_Ctx *FRAME_GetTlsCtx(const struct FRAME_LinkObj_ *linkObj);

#include "tls.h"
#include <poll.h>
#include <stdatomic.h>

/* Growable registration table: the frame doubles as a scalability driver, so
 * the slot count is not capped by a compile-time constant; the table doubles
 * on demand and the practical limit is host memory (a table grow or link
 * allocation failure surfaces as FRAME_ASYNC_ERR_PROVIDER). Only the owner
 * thread touches the table, so reallocating it is safe; completion flags live
 * inside each link, so worker-thread callbacks never dereference the table. */
static FRAME_ASYNC_Link **g_links = NULL;
static uint32_t g_linkCap = 0; /* allocated slots; free slots hold NULL */

/* Pump wait-set scratch, sized 4 handles per table slot (a connection reports
 * at most 4 notify sources, the per-link buffer in FrameAsyncCollectHandles);
 * rebuilt from scratch every round, so growth never has to preserve it. */
static BSL_ASYNC_NotifyHandle *g_waitHandles = NULL;
static struct pollfd *g_waitPfds = NULL;

static uint64_t FrameAsyncNowMs(void)
{
    struct timespec ts = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Double the registration table. Returns false only on allocation failure or
 * counter overflow, leaving the old table fully intact. */
static bool FrameAsyncGrowTable(void)
{
    uint32_t newCap = g_linkCap == 0 ? 16 : g_linkCap * 2;
    if (newCap < g_linkCap || newCap > UINT32_MAX / 4u) {
        return false;
    }
    FRAME_ASYNC_Link **links = BSL_SAL_Calloc(newCap, sizeof(*links));
    if (links == NULL) {
        return false;
    }
    if (g_linkCap > 0) {
        memcpy(links, g_links, g_linkCap * sizeof(*links));
    }
    BSL_ASYNC_NotifyHandle *handles = BSL_SAL_Calloc(newCap * 4u, sizeof(*handles));
    struct pollfd *pfds = BSL_SAL_Calloc(newCap * 4u, sizeof(*pfds));
    if (handles == NULL || pfds == NULL) {
        BSL_SAL_FREE(handles);
        BSL_SAL_FREE(pfds);
        BSL_SAL_FREE(links);
        return false;
    }
    BSL_SAL_FREE(g_links);
    BSL_SAL_FREE(g_waitHandles);
    BSL_SAL_FREE(g_waitPfds);
    g_links = links;
    g_waitHandles = handles;
    g_waitPfds = pfds;
    g_linkCap = newCap;
    return true;
}

int32_t FRAME_ASYNC_OnDone(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    FRAME_ASYNC_Link *link = (FRAME_ASYNC_Link *)arg;
    if (link != NULL) {
        /* callback-path completion flag: the callback only posts; the pump
         * drains the flag on the owner thread. Posted from worker threads,
         * hence the atomic on a link-owned (stable-address) field. */
        atomic_store(&link->cbPosted, 1);
    }
    return HITLS_SUCCESS;
}

static bool FrameAsyncIsLinkFatal(const FRAME_ASYNC_Link *link)
{
    /* WANT_* codes are recoverable; anything else surfaced by HITLS_GetError
     * is a fatal protocol error (no code folding). */
    int32_t err = HITLS_GetError(link->ctx, link->lastRet);
    return err != HITLS_WANT_READ && err != HITLS_WANT_WRITE && err != HITLS_WANT_ASYNC &&
           err != HITLS_WANT_ASYNC_JOB && err != HITLS_WANT_CLIENT_HELLO_CB && err != HITLS_WANT_X509_LOOKUP &&
           err != HITLS_SUCCESS;
}

/* Replay the recorded protocol API with its original parameters. */
static void FrameAsyncReinvoke(FRAME_ASYNC_Link *link)
{
    int32_t ret = HITLS_SUCCESS;
    switch (link->lastOp) {
        case FRAME_ASYNC_OP_CONNECT:
            ret = HITLS_Connect(link->ctx);
            break;
        case FRAME_ASYNC_OP_ACCEPT:
            ret = HITLS_Accept(link->ctx);
            break;
        case FRAME_ASYNC_OP_READ:
            ret = HITLS_Read(link->ctx, link->readBuf, link->readSize, link->readLenOut);
            break;
        default:
            return;
    }
    link->lastRet = ret;
}

/* Rebuild the wait set from the CURRENT sources of every paused link.
 *
 * The design's incremental maintenance (GetChanged + add/del)
 * breaks on the shared engine notify object: the provider registers ONE
 * eventfd under one key, but each connection has its own notify context, so
 * one connection's deletion window can drop the handle another paused
 * connection still needs. Rebuilding from GetAll is O(links * handles) over
 * the whole table and is self-healing. */
static bool FrameAsyncCollectHandles(BSL_ASYNC_NotifyHandle *handles, uint32_t cap, uint32_t *count)
{
    *count = 0;
    for (uint32_t i = 0; i < g_linkCap; i++) {
        FRAME_ASYNC_Link *link = g_links[i];
        if (link == NULL || link->done) {
            continue;
        }
        BSL_ASYNC_NotifyHandle buf[4];
        BSL_ASYNC_NotifyHandleList list = {buf, 4, 0};
        int32_t ret = HITLS_GetAllAsyncNotifyHandles(link->ctx, &list);
        if (ret == HITLS_ASYNC_ERR_NOT_PAUSED) {
            continue; /* not paused: nothing to wait for */
        }
        if (ret != HITLS_SUCCESS) {
            return false;
        }
        for (uint32_t h = 0; h < list.numHandles && *count < cap; h++) {
            bool known = false;
            for (uint32_t k = 0; k < *count; k++) {
                if (handles[k] == buf[h]) {
                    known = true;
                    break;
                }
            }
            if (!known) {
                handles[(*count)++] = buf[h];
            }
        }
    }
    return true;
}

int32_t FRAME_ASYNC_Pump(uint32_t timeoutMs)
{
    if (!FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }

    /* drive phase 1: IO links are always drivable - the memory UIO transfer
     * is instantaneous and may unblock the peer's pending write */
    uint32_t progressed = 0;
    bool anyPaused = false;
    bool fatal = false;
    for (uint32_t i = 0; i < g_linkCap; i++) {
        FRAME_ASYNC_Link *link = g_links[i];
        if (link == NULL || link->done) {
            continue;
        }
        int32_t err = HITLS_GetError(link->ctx, link->lastRet);
        if (err == HITLS_WANT_READ) {
            /* pull from the peer: this link drained its receive buffer (the
             * record layer found nothing), so the transfer cannot drop the
             * peer's pending record (a drop would desync the record
             * sequence and break later MAC checks) */
            if (link->peer != NULL) {
                (void)FRAME_TrasferMsgBetweenLink(link->peer->linkObj, link->linkObj);
            }
            FrameAsyncReinvoke(link);
            progressed++;
        } else if (err == HITLS_WANT_WRITE || err == HITLS_WANT_ASYNC_JOB) {
            /* our send blob waits for the peer to pull it (the peer's
             * WANT_READ round does the transfer); just retry the write */
            FrameAsyncReinvoke(link);
            progressed++;
        } else if (err == HITLS_SUCCESS && link->peer != NULL && !link->peer->done) {
            /* our handshake call finished but the peer still sends its
             * trailing flight: keep reading on this side so the pull model
             * keeps draining the peer (the NewSessionTicket is a
             * post-handshake message consumed by Read) */
            if (!link->draining) {
                link->draining = true;
                link->drainLen = 0;
                link->readBuf = link->drainBuf;
                link->readSize = sizeof(link->drainBuf);
                link->readLenOut = &link->drainLen;
                link->lastOp = FRAME_ASYNC_OP_READ;
            }
            FrameAsyncReinvoke(link);
            progressed++;
        } else if (err == HITLS_WANT_ASYNC) {
            int32_t status;
            if (HITLS_GetAsyncStatus(link->ctx, &status) != HITLS_SUCCESS) {
                return FRAME_ASYNC_ERR_STATE;
            }
            if (status == BSL_ASYNC_NOTIFY_STATUS_EAGAIN || status == BSL_ASYNC_NOTIFY_STATUS_ERR) {
                FrameAsyncReinvoke(link);
                progressed++;
            }
        }
        err = HITLS_GetError(link->ctx, link->lastRet);
        anyPaused = anyPaused || err == HITLS_WANT_ASYNC || err == HITLS_WANT_ASYNC_JOB;
        /* a fatal link is reported at the end of the round: the round still
         * drives the surviving paused links so a quiescing caller can drain
         * them before freeing */
        fatal = fatal || FrameAsyncIsLinkFatal(link);
    }

    /* drive phase 2: wait for a completion signal of the paused links
     * (both paths), then resume them in the same pump round */
    bool cbPosted = false;
    for (uint32_t i = 0; i < g_linkCap; i++) {
        FRAME_ASYNC_Link *link = g_links[i];
        if (link != NULL && atomic_exchange(&link->cbPosted, 0) != 0) {
            cbPosted = true;
        }
    }
    bool signal = cbPosted;
    if (!signal && anyPaused) {
        uint32_t count = 0;
        if (!FrameAsyncCollectHandles(g_waitHandles, g_linkCap * 4u, &count)) {
            return FRAME_ASYNC_ERR_STATE;
        }
        if (count > 0) {
            /* handle path: wait for the shared eventfd */
            struct pollfd *pfds = g_waitPfds;
            for (uint32_t i = 0; i < count; i++) {
                pfds[i].fd = (int)(uintptr_t)g_waitHandles[i];
                pfds[i].events = POLLIN;
                pfds[i].revents = 0;
            }
            int pr = poll(pfds, count, (int)timeoutMs);
            if (pr < 0) {
                return FRAME_ASYNC_ERR_STATE;
            }
            if (pr > 0) {
                /* consume the signal: the eventfd read resets the counter;
                 * a level-triggered poll would otherwise fire again */
                for (uint32_t i = 0; i < count; i++) {
                    if (pfds[i].revents & POLLIN) {
                        uint64_t val = 0;
                        (void)read(pfds[i].fd, &val, sizeof(val));
                    }
                }
                signal = true;
            }
        } else if (timeoutMs > 0) {
            /* pure callback setup whose completion has not arrived yet */
            uint64_t deadline = FrameAsyncNowMs() + timeoutMs;
            while (true) {
                for (uint32_t i = 0; i < g_linkCap; i++) {
                    FRAME_ASYNC_Link *link = g_links[i];
                    if (link != NULL && atomic_exchange(&link->cbPosted, 0) != 0) {
                        signal = true;
                        break;
                    }
                }
                if (signal || FrameAsyncNowMs() >= deadline) {
                    break;
                }
                usleep(1000);
            }
        }
    }

    /* drive phase 3: resume the paused links whose signal arrived (a
     * spurious resume of an unfinished request is legal - it pauses again,
     * query only, never re-submit). WANT_ASYNC_JOB started no task: retry. */
    if (signal) {
        for (uint32_t i = 0; i < g_linkCap; i++) {
            FRAME_ASYNC_Link *link = g_links[i];
            if (link == NULL || link->done) {
                continue;
            }
            int32_t err = HITLS_GetError(link->ctx, link->lastRet);
            if (err == HITLS_WANT_ASYNC || err == HITLS_WANT_ASYNC_JOB) {
                FrameAsyncReinvoke(link);
                progressed++;
                fatal = fatal || FrameAsyncIsLinkFatal(link);
            }
        }
    }
    if (fatal) {
        return FRAME_ASYNC_ERR_PROTOCOL;
    }
    return progressed > 0 ? FRAME_ASYNC_SUCCESS : FRAME_ASYNC_ERR_TIMEOUT;
}

int32_t FRAME_ASYNC_AttachLink(struct FRAME_LinkObj_ *linkObj, FRAME_ASYNC_Link **out)
{
    if (out == NULL) {
        return FRAME_ASYNC_ERR_STATE;
    }
    *out = NULL;
    if (!g_state.loaded || !FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    if (linkObj == NULL) {
        return FRAME_ASYNC_ERR_STATE;
    }
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(linkObj);
    if (ctx == NULL) {
        return FRAME_ASYNC_ERR_STATE;
    }
    for (uint32_t i = 0; i < g_linkCap; i++) {
        if (g_links[i] != NULL && g_links[i]->linkObj == linkObj) {
            return FRAME_ASYNC_ERR_STATE; /* duplicate registration */
        }
    }
    uint32_t slot = g_linkCap;
    for (uint32_t i = 0; i < g_linkCap; i++) {
        if (g_links[i] == NULL) {
            slot = i;
            break;
        }
    }
    if (slot == g_linkCap && !FrameAsyncGrowTable()) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    FRAME_ASYNC_Link *link = BSL_SAL_Calloc(1, sizeof(*link));
    if (link == NULL) {
        return FRAME_ASYNC_ERR_PROVIDER;
    }
    link->linkObj = linkObj;
    link->ctx = ctx;
    atomic_store(&link->cbPosted, 0);
    g_links[slot] = link;
    *out = link;
    return FRAME_ASYNC_SUCCESS;
}

int32_t FRAME_ASYNC_DetachLink(FRAME_ASYNC_Link *link)
{
    if (link == NULL || !FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    /* a still-paused task keeps notify handles registered; detaching then
     * would lose the completion signal */
    BSL_ASYNC_NotifyHandleList list = {NULL, 0, 0};
    int32_t ret = HITLS_GetAllAsyncNotifyHandles(link->ctx, &list);
    if (ret != HITLS_ASYNC_ERR_NOT_PAUSED) {
        return FRAME_ASYNC_ERR_STATE; /* paused (or query failed) */
    }
    for (uint32_t i = 0; i < g_linkCap; i++) {
        if (g_links[i] == link) {
            g_links[i] = NULL;
            if (link->peer != NULL) {
                link->peer->peer = NULL;
            }
            BSL_SAL_Free(link);
            return FRAME_ASYNC_SUCCESS;
        }
    }
    return FRAME_ASYNC_ERR_STATE;
}

/* True when no registered link still has a paused task. */
static bool FrameAsyncLinksQuiesced(void)
{
    for (uint32_t i = 0; i < g_linkCap; i++) {
        FRAME_ASYNC_Link *link = g_links[i];
        if (link == NULL) {
            continue;
        }
        BSL_ASYNC_NotifyHandleList list = {NULL, 0, 0};
        if (HITLS_GetAllAsyncNotifyHandles(link->ctx, &list) != HITLS_ASYNC_ERR_NOT_PAUSED) {
            return false;
        }
    }
    return FRAME_ASYNC_GetOutstanding() == 0;
}

static int32_t FrameAsyncQuiesce(int32_t result)
{
    for (uint32_t i = 0; i < 50; i++) {
        if (FrameAsyncLinksQuiesced()) {
            return result;
        }
        (void)FRAME_ASYNC_Pump(100);
    }
    return FrameAsyncLinksQuiesced() ? result : FRAME_ASYNC_ERR_STATE;
}

int32_t FRAME_ASYNC_Handshake(FRAME_ASYNC_Link *client, FRAME_ASYNC_Link *server, uint32_t timeoutMs)
{
    if (!FrameAsyncIsOwner()) {
        return FRAME_ASYNC_ERR_STATE;
    }
    if (client == NULL || server == NULL || client == server) {
        return FRAME_ASYNC_ERR_STATE;
    }
    /* pair the two ends so WANT_IO can find the peer to drain */
    client->peer = server;
    server->peer = client;

    uint64_t deadline = FrameAsyncNowMs() + timeoutMs;
    /* start both ends */
    client->lastOp = FRAME_ASYNC_OP_CONNECT;
    FrameAsyncReinvoke(client);
    server->lastOp = FRAME_ASYNC_OP_ACCEPT;
    FrameAsyncReinvoke(server);
    if (FrameAsyncIsLinkFatal(client) || FrameAsyncIsLinkFatal(server)) {
        return FrameAsyncQuiesce(FRAME_ASYNC_ERR_PROTOCOL);
    }

    while (true) {
        uint32_t state = 0;
        bool clientDone = HITLS_GetHandShakeState(client->ctx, &state) == HITLS_SUCCESS && state == TLS_CONNECTED;
        bool serverDone = HITLS_GetHandShakeState(server->ctx, &state) == HITLS_SUCCESS && state == TLS_CONNECTED;
        if (clientDone && serverDone) {
            client->done = true;
            server->done = true;
            return FRAME_ASYNC_SUCCESS;
        }
        if (FrameAsyncNowMs() >= deadline) {
            return FrameAsyncQuiesce(FRAME_ASYNC_ERR_TIMEOUT);
        }
        int32_t ret = FRAME_ASYNC_Pump(100);
        if (ret != FRAME_ASYNC_SUCCESS && ret != FRAME_ASYNC_ERR_TIMEOUT) {
            return FrameAsyncQuiesce(ret);
        }
        if (ret == FRAME_ASYNC_ERR_TIMEOUT) {
            continue; /* pump made no progress; retry until the deadline */
        }
    }
}

#endif /* HITLS_TLS_FEATURE_MODE_ASYNC */
