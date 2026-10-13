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

#include "hitls_build.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_err.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <pthread.h>

typedef struct {
    uint16_t port;
    bool tls12;
} ClientArgs;

static bool ClientWantIo(HITLS_Ctx *ctx, int32_t ret)
{
    int32_t error = HITLS_GetError(ctx, ret);
    return error == HITLS_WANT_READ || error == HITLS_WANT_WRITE;
}

static int ClientExchange(HITLS_Ctx *ctx)
{
    int32_t ret;
    uint8_t byte = 0;
    uint32_t len = 0;
    do {
        ret = HITLS_Connect(ctx);
    } while (ClientWantIo(ctx, ret));
    if (ret != HITLS_SUCCESS) {
        return -1;
    }
    /* TLS 1.3 session tickets are consumed here. The read then blocks until the server closes. */
    do {
        ret = HITLS_Read(ctx, &byte, 1, &len);
    } while (ClientWantIo(ctx, ret));
    (void)ret;
    return 0;
}

static void *ClientConnect(void *arg)
{
    const ClientArgs *args = arg;
    HITLS_Config *cfg = args->tls12 ? HITLS_CFG_NewTLS12Config() : HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int fd = -1;
    int32_t socketFd = -1;
    struct sockaddr_in addr = {
        .sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int enabled = 1;
    int ret = -1;
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    if (cfg == NULL || HITLS_CFG_SetGroups(cfg, &group, 1) != HITLS_SUCCESS ||
        HITLS_CFG_SetVerifyNoneSupport(cfg, true) != HITLS_SUCCESS) {
        goto EXIT;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET, .sin_port = htons(args->port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int enabled = 1;
    if (fd < 0 || setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        goto EXIT;
    }
    ctx = HITLS_New(cfg);
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    socketFd = fd;
    if (ctx == NULL || uio == NULL || BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(socketFd), &socketFd) != BSL_SUCCESS ||
        HITLS_SetUio(ctx, uio) != HITLS_SUCCESS) {
        goto EXIT;
    }
    ret = ClientExchange(ctx);
EXIT:
    if (ret != 0) {
        fprintf(stderr, "client failed: bsl=0x%x errno=%d\n", BSL_ERR_GetLastError(), errno);
    }
    BSL_UIO_Free(uio);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(cfg);
    if (fd >= 0) {
        close(fd);
    }
    BSL_ERR_RemoveErrorStack(false);
    if (ret != 0) {
        _Exit(1);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    char *end = NULL;
    errno = 0;
    unsigned long port = argc > 1 ? strtoul(argv[1], &end, 10) : 44330;
    if (argc > 4 || errno != 0 || port == 0 || port > UINT16_MAX || (argc > 1 && (end == argv[1] || *end != '\0')) ||
        (argc > 2 && strcmp(argv[2], "tls12") != 0 && strcmp(argv[2], "tls13") != 0)) {
        goto USAGE;
    }
    errno = 0;
    unsigned long count = argc > 3 ? strtoul(argv[3], &end, 10) : 1;
    if (errno != 0 || count == 0 || count > UINT32_MAX || (argc > 3 && (end == argv[3] || *end != '\0'))) {
        goto USAGE;
    }
    signal(SIGPIPE, SIG_IGN);
    alarm(30);
    pthread_t *threads = calloc(count, sizeof(*threads));
    if (threads == NULL) {
        return 1;
    }
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != CRYPT_SUCCESS) {
        free(threads);
        return 1;
    }
    ClientArgs args = {.port = (uint16_t)port, .tls12 = argc > 2 && strcmp(argv[2], "tls12") == 0};
    for (unsigned long i = 0; i < count; i++) {
        int ret = pthread_create(&threads[i], NULL, ClientConnect, &args);
        if (ret != 0) {
            fprintf(stderr, "client pthread_create failed: %s\n", strerror(ret));
            _Exit(1);
        }
    }
    for (unsigned long i = 0; i < count; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            _Exit(1);
        }
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    free(threads);
    return 0;
USAGE:
    fprintf(stderr, "usage: %s [port=44330] [tls12|tls13] [connections=1]\n", argv[0]);
    return 2;
}
