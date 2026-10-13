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

#include "sim_link.h"
#include "hitls_async.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_err.h"
#include "bsl_async.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>

/* epoll data is a tag, not a pointer. Connection sockets use the index.
 * A connection's notify fd uses the same index with PERF_TAG_NOTIFY set. */
#define PERF_TAG_NOTIFY (1ull << 32)
#define PERF_TAG_LISTEN (1ull << 33)
#define PERF_TAG_WAKE   (1ull << 34)

static uint64_t PerfNowNs(void)
{
    struct timespec ts = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int PerfNonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ? -1 : 0;
}

int PerfListen(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int enabled = 1;
    struct sockaddr_in addr = {
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (fd < 0) {
        return -1;
    }
    if (PerfNonblocking(fd) != 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int32_t PerfEndSetup(PerfEndpoint *end, HITLS_Config *cfg, int fd)
{
    int enabled = 1;
    if (PerfNonblocking(fd) != 0 || setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) {
        close(fd);
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_Ctx *ctx = HITLS_New(cfg);
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    int32_t ret = HITLS_MEMALLOC_FAIL;
    if (ctx != NULL && uio != NULL) {
        int32_t socketFd = fd;
        ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(socketFd), &socketFd);
        if (ret == BSL_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);
            end->fd = fd;
            fd = -1;
            ret = HITLS_SetUio(ctx, uio);
        }
    }
    BSL_UIO_Free(uio);
    if (fd >= 0) {
        close(fd);
    }
    if (ret != HITLS_SUCCESS) {
        HITLS_Free(ctx);
        return ret;
    }
    end->ctx = ctx;
    return HITLS_SUCCESS;
}

bool PerfAsyncSupported(void)
{
#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
    return BSL_ASYNC_IsSupported();
#else
    return false;
#endif
}

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
static int32_t PerfWakeFd(int fd)
{
    uint8_t byte = 1;
    ssize_t ret;
    do {
        ret = write(fd, &byte, sizeof(byte));
    } while (ret < 0 && errno == EINTR);
    return ret >= 0 || errno == EAGAIN ? HITLS_SUCCESS : HITLS_INTERNAL_EXCEPTION;
}
#endif

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
static int32_t PerfOnDone(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    PerfEndpoint *end = arg;
    PerfBatch *batch = end->batch;
    pthread_mutex_lock(&batch->notifyMutex);
    if (!atomic_exchange(&end->posted, true)) {
        end->notifyNext = batch->notified;
        batch->notified = end;
    }
    pthread_mutex_unlock(&batch->notifyMutex);
    return PerfWakeFd(batch->wakeFds[1]);
}
#endif

int32_t PerfBatchCreate(HITLS_Config *serverCfg, uint32_t n, PerfForm form, int listener, PerfBatch *batch)
{
    (void)memset(batch, 0, sizeof(*batch));
    batch->form = form;
    batch->listener = listener;
    batch->serverCfg = serverCfg;
    batch->epollFd = -1;
    batch->wakeFds[0] = batch->wakeFds[1] = -1;
    if (form != PERF_FORM_SYNC && !PerfAsyncSupported()) {
        return HITLS_ASYNC_ERR_UNSUPPORTED;
    }
    if (n == 0 || n > INT_MAX - 3) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    batch->servers = calloc(n, sizeof(*batch->servers));
    if (form == PERF_FORM_ON_CB) {
        if (pthread_mutex_init(&batch->notifyMutex, NULL) != 0) {
            PerfBatchDestroy(batch);
            return HITLS_INTERNAL_EXCEPTION;
        }
        batch->notifyMutexInit = true;
    }
    if (batch->servers == NULL) {
        PerfBatchDestroy(batch);
        return HITLS_MEMALLOC_FAIL;
    }
    batch->n = n;
    if (form == PERF_FORM_ON_CB && (pipe(batch->wakeFds) != 0 || PerfNonblocking(batch->wakeFds[0]) != 0 ||
                                    PerfNonblocking(batch->wakeFds[1]) != 0)) {
        PerfBatchDestroy(batch);
        return HITLS_INTERNAL_EXCEPTION;
    }
    for (uint32_t i = 0; i < n; i++) {
        atomic_init(&batch->servers[i].posted, false);
        batch->servers[i].notifyFd = -1;
        batch->servers[i].batch = batch;
    }
    return HITLS_SUCCESS;
}

static bool PerfIsPaused(const PerfEndpoint *end)
{
    return end->ret == HITLS_ASYNC_ERR_PAUSED;
}

static void PerfDrainTasks(PerfBatch *batch)
{
    uint64_t deadline = PerfNowNs() + 5000000000ull;
    for (;;) {
        bool pending = false;
        for (uint32_t i = 0; i < batch->n; i++) {
            PerfEndpoint *end = &batch->servers[i];
            if (PerfIsPaused(end)) {
                end->ret = HITLS_Accept(end->ctx);
                pending = pending || PerfIsPaused(end);
            }
        }
        if (!pending) {
            return;
        }
        if (PerfNowNs() >= deadline) {
            /* Paused stacks and worker callbacks still own the batch memory. */
            fprintf(stderr, "async tasks did not drain; terminating without freeing live contexts\n");
            fflush(NULL);
            _Exit(2);
        }
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
}

void PerfBatchDestroy(PerfBatch *batch)
{
    if (batch == NULL) {
        return;
    }
    PerfDrainTasks(batch);
    for (uint32_t i = 0; i < batch->n; i++) {
        HITLS_Free(batch->servers[i].ctx);
    }
    free(batch->servers);
    batch->servers = NULL;
    batch->n = 0;
    bool closeWake = batch->notifyMutexInit;
    if (batch->notifyMutexInit) {
        pthread_mutex_destroy(&batch->notifyMutex);
        batch->notifyMutexInit = false;
    }
    batch->notified = NULL;
    if (closeWake) {
        for (unsigned i = 0; i < 2; i++) {
            if (batch->wakeFds[i] >= 0) {
                close(batch->wakeFds[i]);
                batch->wakeFds[i] = -1;
            }
        }
    }
}

static bool PerfWantIo(const PerfEndpoint *end)
{
    int32_t err = HITLS_GetError(end->ctx, end->ret);
    return err == HITLS_WANT_READ || err == HITLS_WANT_WRITE;
}

static void PerfDrainFd(int fd)
{
    uint64_t signal;
    while (read(fd, &signal, sizeof(signal)) > 0) {
    }
}

static int32_t PerfEpollAdd(PerfBatch *batch, int fd, uint32_t events, uint64_t tag)
{
    struct epoll_event event = {.events = events, .data.u64 = tag};
    return epoll_ctl(batch->epollFd, EPOLL_CTL_ADD, fd, &event) == 0 ? HITLS_SUCCESS : HITLS_INTERNAL_EXCEPTION;
}

static int32_t PerfEpollDel(PerfBatch *batch, int fd)
{
    return epoll_ctl(batch->epollFd, EPOLL_CTL_DEL, fd, NULL) == 0 ? HITLS_SUCCESS : HITLS_INTERNAL_EXCEPTION;
}

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
/* One connection waits on one fd. A finished operation clears its registration, so the next
 * pause reports that deletion together with the new operation's fd. Further pauses of the
 * same operation find an empty change window. */
static int32_t PerfWatchNotify(PerfBatch *batch, PerfEndpoint *end)
{
    BSL_ASYNC_NotifyHandle added[2];
    BSL_ASYNC_NotifyHandle removed[2];
    BSL_ASYNC_NotifyHandleList addList = {added, 2, 0};
    BSL_ASYNC_NotifyHandleList delList = {removed, 2, 0};
    if (HITLS_GetChangedAsyncNotifyHandles(end->ctx, &addList, &delList) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    for (uint32_t i = 0; i < delList.numHandles; i++) {
        if (end->notifyFd < 0 || removed[i] != (BSL_ASYNC_NotifyHandle)end->notifyFd) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        if (PerfEpollDel(batch, end->notifyFd) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        end->notifyFd = -1;
    }
    uint32_t index = (uint32_t)(end - batch->servers);
    for (uint32_t i = 0; i < addList.numHandles; i++) {
        if (end->notifyFd >= 0 || added[i] > (BSL_ASYNC_NotifyHandle)INT_MAX) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        int fd = (int)added[i];
        if (PerfEpollAdd(batch, fd, EPOLLIN, (uint64_t)index | PERF_TAG_NOTIFY) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        end->notifyFd = fd;
    }
    return end->notifyFd >= 0 ? HITLS_SUCCESS : HITLS_INTERNAL_EXCEPTION;
}
#endif

static int32_t PerfDrive(PerfBatch *batch, PerfEndpoint *end)
{
    end->ret = HITLS_Accept(end->ctx);
    if (end->ret == HITLS_SUCCESS) {
        end->done = true;
        batch->doneServers++;
        batch->doneNs = PerfNowNs();
        if (end->notifyFd >= 0) {
            if (PerfEpollDel(batch, end->notifyFd) != HITLS_SUCCESS) {
                return HITLS_INTERNAL_EXCEPTION;
            }
            end->notifyFd = -1;
        }
        return HITLS_SUCCESS;
    }
    if (end->ret == HITLS_ASYNC_ERR_PAUSED) {
#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
        if (batch->form == PERF_FORM_ON_FD) {
            return PerfWatchNotify(batch, end);
        }
        if (batch->form == PERF_FORM_ON_CB) {
            return HITLS_SUCCESS;
        }
#endif
        return HITLS_INTERNAL_EXCEPTION;
    }
    if (PerfWantIo(end)) {
        return HITLS_SUCCESS;
    }
    fprintf(stderr, "server TLS failed: ret=0x%x bsl=0x%x\n", end->ret, BSL_ERR_GetLastError());
    return HITLS_INTERNAL_EXCEPTION;
}

static int32_t PerfOnAccept(PerfBatch *batch)
{
    while (batch->accepted < batch->n) {
        int fd = accept(batch->listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno == EAGAIN || errno == EWOULDBLOCK ? HITLS_SUCCESS : HITLS_INTERNAL_EXCEPTION;
        }
        if (batch->startNs == 0) {
            batch->startNs = PerfNowNs();
            batch->doneNs = batch->startNs;
        }
        uint32_t index = batch->accepted;
        PerfEndpoint *end = &batch->servers[index];
        batch->accepted++;
        uint32_t inflight = batch->accepted - batch->doneServers;
        if (inflight > batch->peakInflight) {
            batch->peakInflight = inflight;
        }
        int32_t ret = PerfEndSetup(end, batch->serverCfg, fd);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        /* WANT_READ/WANT_WRITE means the kernel buffer is empty or full, so edge trigger is safe. */
        if (PerfEpollAdd(batch, end->fd, EPOLLIN | EPOLLOUT | EPOLLET, index) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
        if (batch->form == PERF_FORM_ON_CB && HITLS_SetAsyncCallback(end->ctx, PerfOnDone, end) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
#endif
        if (PerfDrive(batch, end) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
    }
    return PerfEpollDel(batch, batch->listener);
}

static int32_t PerfOnNotify(PerfBatch *batch, uint32_t index)
{
    PerfEndpoint *end = &batch->servers[index];
    if (end->notifyFd < 0) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    PerfDrainFd(end->notifyFd);
    if (!end->done && PerfIsPaused(end)) {
        return PerfDrive(batch, end);
    }
    return HITLS_SUCCESS;
}

static int32_t PerfOnWake(PerfBatch *batch)
{
    PerfDrainFd(batch->wakeFds[0]);
    pthread_mutex_lock(&batch->notifyMutex);
    PerfEndpoint *end = batch->notified;
    batch->notified = NULL;
    pthread_mutex_unlock(&batch->notifyMutex);
    while (end != NULL) {
        PerfEndpoint *next = end->notifyNext;
        atomic_store(&end->posted, false);
        if (PerfIsPaused(end) && PerfDrive(batch, end) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        end = next;
    }
    return HITLS_SUCCESS;
}

static int32_t PerfOnSocket(PerfBatch *batch, uint32_t index)
{
    PerfEndpoint *end = &batch->servers[index];
    if (end->done || PerfIsPaused(end)) {
        return HITLS_SUCCESS;
    }
    return PerfDrive(batch, end);
}

static int32_t PerfDispatch(PerfBatch *batch, const struct epoll_event *event)
{
    uint64_t tag = event->data.u64;
    bool hangup = (event->events & (EPOLLERR | EPOLLHUP)) != 0;
    if (tag == PERF_TAG_LISTEN || tag == PERF_TAG_WAKE) {
        if (hangup) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        return tag == PERF_TAG_LISTEN ? PerfOnAccept(batch) : PerfOnWake(batch);
    }
    uint32_t index = (uint32_t)tag;
    if (index >= batch->n) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    /* A finished connection is only kept open until the batch ends, so its peer closing does not matter. */
    if (batch->servers[index].done) {
        return HITLS_SUCCESS;
    }
    if (hangup) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    if ((tag & PERF_TAG_NOTIFY) != 0) {
        return PerfOnNotify(batch, index);
    }
    return PerfOnSocket(batch, index);
}

int32_t PerfRunServer(PerfBatch *batch)
{
    uint64_t deadline = PerfNowNs() + (uint64_t)PERF_TIMEOUT_MS * 1000000ull;
    batch->epollFd = epoll_create1(EPOLL_CLOEXEC);
    int32_t ret = HITLS_INTERNAL_EXCEPTION;
    if (batch->epollFd >= 0 && PerfEpollAdd(batch, batch->listener, EPOLLIN, PERF_TAG_LISTEN) == HITLS_SUCCESS &&
        (batch->form != PERF_FORM_ON_CB ||
         PerfEpollAdd(batch, batch->wakeFds[0], EPOLLIN, PERF_TAG_WAKE) == HITLS_SUCCESS)) {
        puts("LISTENING");
        fflush(stdout);
        bool failed = false;
        while (!failed && batch->doneServers < batch->n) {
            uint64_t now = PerfNowNs();
            if (now >= deadline) {
                break;
            }
            uint64_t remaining = (deadline - now + 999999ull) / 1000000ull;
            struct epoll_event events[64];
            int count = epoll_wait(batch->epollFd, events, (int)(sizeof(events) / sizeof(events[0])),
                                   remaining > INT_MAX ? INT_MAX : (int)remaining);
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                failed = true;
                break;
            }
            for (int i = 0; i < count; i++) {
                if (batch->doneServers == batch->n) {
                    break;
                }
                if (PerfDispatch(batch, &events[i]) != HITLS_SUCCESS) {
                    failed = true;
                    break;
                }
            }
        }
        if (!failed && batch->doneServers == batch->n) {
            ret = HITLS_SUCCESS;
        }
    }
    if (batch->epollFd >= 0) {
        close(batch->epollFd);
        batch->epollFd = -1;
    }
    return ret;
}
