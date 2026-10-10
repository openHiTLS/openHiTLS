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

enum { PERF_HANDSHAKE, PERF_READ, PERF_WRITE, PERF_DONE };

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
        batch->servers[i].batch = batch;
    }
    return HITLS_SUCCESS;
}

static bool PerfIsPaused(const PerfEndpoint *end)
{
    return end->ret == HITLS_ASYNC_ERR_PAUSED;
}

static int32_t PerfStep(PerfEndpoint *end);

static void PerfDrainTasks(PerfBatch *batch)
{
    uint64_t deadline = PerfNowNs() + 5000000000ull;
    for (;;) {
        bool pending = false;
        for (uint32_t i = 0; i < batch->n; i++) {
            PerfEndpoint *end = &batch->servers[i];
            if (PerfIsPaused(end)) {
                (void)PerfStep(end);
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

static int32_t PerfStep(PerfEndpoint *end)
{
    switch (end->phase) {
        case PERF_HANDSHAKE:
            end->ret = HITLS_Accept(end->ctx);
            break;
        case PERF_READ:
            end->ret = HITLS_Read(end->ctx, &end->byte, 1, &end->ioLen);
            break;
        case PERF_WRITE:
            end->ret = HITLS_Write(end->ctx, &end->byte, 1, &end->ioLen);
            break;
        default:
            return HITLS_INTERNAL_EXCEPTION;
    }
    if (end->ret == HITLS_SUCCESS) {
        if (end->phase != PERF_HANDSHAKE && end->ioLen != 1) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        end->phase++;
        return HITLS_SUCCESS;
    }
    if (PerfWantIo(end) || PerfIsPaused(end)) {
        return HITLS_SUCCESS;
    }
    fprintf(stderr, "server TLS failed: ret=0x%x bsl=0x%x\n", end->ret, BSL_ERR_GetLastError());
    return HITLS_INTERNAL_EXCEPTION;
}

static int32_t PerfAccept(PerfBatch *batch, uint32_t *accepted)
{
    while (*accepted < batch->n) {
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
        PerfEndpoint *end = &batch->servers[(*accepted)++];
        int32_t ret = PerfEndSetup(end, batch->serverCfg, fd);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        end->phase = PERF_HANDSHAKE;
#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
        if (batch->form == PERF_FORM_ON_CB && HITLS_SetAsyncCallback(end->ctx, PerfOnDone, end) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
#endif
    }
    return HITLS_SUCCESS;
}

typedef enum {
    PERF_EVENT_LISTEN,
    PERF_EVENT_SOCKET,
    PERF_EVENT_ASYNC,
    PERF_EVENT_CALLBACK,
} PerfEventKind;

typedef struct PerfEpollWatch {
    int fd;
    PerfEventKind kind;
    bool added;
    bool armed;
    PerfEndpoint *end;
    PerfEndpoint *waiters;
} PerfEpollWatch;

typedef struct {
    PerfBatch *batch;
    int fd;
    PerfEpollWatch listener;
    PerfEpollWatch callback;
    PerfEpollWatch *sockets;
    PerfEpollWatch notify;
    uint32_t accepted;
    uint32_t echoed;
} PerfServerLoop;

static int32_t PerfEpollArm(PerfServerLoop *loop, PerfEpollWatch *watch, uint32_t events)
{
    struct epoll_event event = {.events = events | EPOLLONESHOT, .data.ptr = watch};
    if (epoll_ctl(loop->fd, watch->added ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, watch->fd, &event) != 0) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    watch->added = true;
    watch->armed = true;
    return HITLS_SUCCESS;
}

static int32_t PerfServerArm(PerfServerLoop *loop, PerfEndpoint *end)
{
    if (PerfIsPaused(end)) {
#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
        if (loop->batch->form == PERF_FORM_ON_CB) {
            return HITLS_SUCCESS;
        }
        BSL_ASYNC_NotifyHandle handle;
        BSL_ASYNC_NotifyHandleList list = {&handle, 1, 0};
        if (HITLS_GetAllAsyncNotifyHandles(end->ctx, &list) != HITLS_SUCCESS || list.numHandles != 1 ||
            handle > INT_MAX) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        PerfEpollWatch *watch = &loop->notify;
        if (watch->added && watch->fd != (int)handle) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        watch->fd = (int)handle;
        end->waitNext = watch->waiters;
        watch->waiters = end;
        return watch->armed ? HITLS_SUCCESS : PerfEpollArm(loop, watch, EPOLLIN);
#else
        return HITLS_INTERNAL_EXCEPTION;
#endif
    }
    PerfEpollWatch *watch = &loop->sockets[end - loop->batch->servers];
    watch->fd = end->fd;
    watch->kind = PERF_EVENT_SOCKET;
    watch->end = end;
    return PerfEpollArm(loop, watch, HITLS_GetError(end->ctx, end->ret) == HITLS_WANT_WRITE ? EPOLLOUT : EPOLLIN);
}

static int32_t PerfServerDrive(PerfServerLoop *loop, PerfEndpoint *end)
{
    while (end->phase != PERF_DONE) {
        uint32_t phase = end->phase;
        if (PerfStep(end) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        if (phase == end->phase) {
            return PerfServerArm(loop, end);
        }
        if (phase == PERF_HANDSHAKE) {
            loop->batch->doneNs = PerfNowNs();
            loop->batch->doneServers++;
            return HITLS_SUCCESS;
        }
        if (end->phase == PERF_DONE) {
            loop->echoed++;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t PerfServerAccept(PerfServerLoop *loop)
{
    uint32_t first = loop->accepted;
    if (PerfAccept(loop->batch, &loop->accepted) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    for (uint32_t i = first; i < loop->accepted; i++) {
        if (PerfServerDrive(loop, &loop->batch->servers[i]) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
    }
    if (loop->accepted == loop->batch->n) {
        return epoll_ctl(loop->fd, EPOLL_CTL_DEL, loop->listener.fd, NULL) == 0 ? HITLS_SUCCESS :
                                                                                  HITLS_INTERNAL_EXCEPTION;
    }
    return PerfEpollArm(loop, &loop->listener, EPOLLIN);
}

static int32_t PerfServerCallbacks(PerfServerLoop *loop)
{
    PerfBatch *batch = loop->batch;
    PerfDrainFd(batch->wakeFds[0]);
    pthread_mutex_lock(&batch->notifyMutex);
    PerfEndpoint *end = batch->notified;
    batch->notified = NULL;
    pthread_mutex_unlock(&batch->notifyMutex);
    while (end != NULL) {
        PerfEndpoint *next = end->notifyNext;
        atomic_store(&end->posted, false);
        if (PerfIsPaused(end) && PerfServerDrive(loop, end) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        end = next;
    }
    return PerfEpollArm(loop, &loop->callback, EPOLLIN);
}

static int32_t PerfServerNotify(PerfServerLoop *loop, PerfEpollWatch *watch)
{
    /* One provider fd can represent multiple paused connections. Detach before resuming. */
    PerfEndpoint *end = watch->waiters;
    watch->waiters = NULL;
    PerfDrainFd(watch->fd);
    while (end != NULL) {
        PerfEndpoint *next = end->waitNext;
        if (PerfServerDrive(loop, end) != HITLS_SUCCESS) {
            return HITLS_INTERNAL_EXCEPTION;
        }
        end = next;
    }
    return HITLS_SUCCESS;
}

static int32_t PerfServerEvent(PerfServerLoop *loop, PerfEpollWatch *watch)
{
    watch->armed = false;
    switch (watch->kind) {
        case PERF_EVENT_LISTEN:
            return PerfServerAccept(loop);
        case PERF_EVENT_SOCKET:
            return PerfServerDrive(loop, watch->end);
        case PERF_EVENT_ASYNC:
            return PerfServerNotify(loop, watch);
        case PERF_EVENT_CALLBACK:
            return PerfServerCallbacks(loop);
        default:
            return HITLS_INTERNAL_EXCEPTION;
    }
}

static int32_t PerfServerEvents(PerfServerLoop *loop, uint64_t deadline)
{
    bool echoStarted = false;
    for (;;) {
        if (!echoStarted && loop->batch->doneServers == loop->batch->n) {
            echoStarted = true;
            deadline = PerfNowNs() + (uint64_t)PERF_TIMEOUT_MS * 1000000ull;
            for (uint32_t i = 0; i < loop->batch->n; i++) {
                if (PerfServerDrive(loop, &loop->batch->servers[i]) != HITLS_SUCCESS) {
                    return HITLS_INTERNAL_EXCEPTION;
                }
            }
        }
        if (loop->echoed == loop->batch->n) {
            return HITLS_SUCCESS;
        }
        uint64_t now = PerfNowNs();
        if (now >= deadline) {
            break;
        }
        uint64_t remaining = (deadline - now + 999999ull) / 1000000ull;
        struct epoll_event events[64];
        int count = epoll_wait(loop->fd, events, sizeof(events) / sizeof(events[0]),
                               remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return HITLS_INTERNAL_EXCEPTION;
        }
        for (int i = 0; i < count; i++) {
            if ((events[i].events & (EPOLLERR | EPOLLHUP)) ||
                PerfServerEvent(loop, events[i].data.ptr) != HITLS_SUCCESS) {
                return HITLS_INTERNAL_EXCEPTION;
            }
        }
    }
    return HITLS_INTERNAL_EXCEPTION;
}

int32_t PerfRunServer(PerfBatch *batch)
{
    uint64_t deadline = PerfNowNs() + (uint64_t)PERF_TIMEOUT_MS * 1000000ull;
    PerfServerLoop loop = {.batch = batch,
                           .fd = epoll_create1(EPOLL_CLOEXEC),
                           .listener = {.fd = batch->listener, .kind = PERF_EVENT_LISTEN},
                           .callback = {.fd = batch->wakeFds[0], .kind = PERF_EVENT_CALLBACK},
                           .notify = {.fd = -1, .kind = PERF_EVENT_ASYNC}};
    int32_t ret = HITLS_INTERNAL_EXCEPTION;
    loop.sockets = calloc(batch->n, sizeof(*loop.sockets));
    if (loop.fd >= 0 && loop.sockets != NULL && PerfEpollArm(&loop, &loop.listener, EPOLLIN) == HITLS_SUCCESS &&
        (batch->form != PERF_FORM_ON_CB || PerfEpollArm(&loop, &loop.callback, EPOLLIN) == HITLS_SUCCESS)) {
        puts("LISTENING");
        fflush(stdout);
        ret = PerfServerEvents(&loop, deadline);
    }
    if (loop.fd >= 0) {
        close(loop.fd);
    }
    free(loop.sockets);
    return ret;
}
