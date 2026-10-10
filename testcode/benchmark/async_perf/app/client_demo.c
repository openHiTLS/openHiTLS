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

static bool ClientWantIo(HITLS_Ctx *ctx, int32_t ret)
{
    int32_t error = HITLS_GetError(ctx, ret);
    return error == HITLS_WANT_READ || error == HITLS_WANT_WRITE;
}

static int ClientExchange(HITLS_Ctx *ctx)
{
    int32_t ret;
    do {
        ret = HITLS_Connect(ctx);
    } while (ClientWantIo(ctx, ret));
    if (ret != HITLS_SUCCESS) {
        return -1;
    }
    const uint8_t request = 42;
    uint8_t response = 0;
    uint32_t len = 0;
    do {
        ret = HITLS_Write(ctx, &request, 1, &len);
    } while (ClientWantIo(ctx, ret));
    if (ret != HITLS_SUCCESS || len != 1) {
        return -1;
    }
    do {
        ret = HITLS_Read(ctx, &response, 1, &len);
    } while (ClientWantIo(ctx, ret));
    return ret == HITLS_SUCCESS && len == 1 && response == request ? 0 : -1;
}

int main(int argc, char **argv)
{
    char *end = NULL;
    errno = 0;
    unsigned long port = argc > 1 ? strtoul(argv[1], &end, 10) : 44330;
    if (argc > 3 || errno != 0 || port == 0 || port > UINT16_MAX || (argc > 1 && (end == argv[1] || *end != '\0')) ||
        (argc > 2 && strcmp(argv[2], "tls12") != 0 && strcmp(argv[2], "tls13") != 0)) {
        fprintf(stderr, "usage: %s [port=44330] [tls12|tls13]\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    alarm(30);
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != CRYPT_SUCCESS) {
        return 1;
    }
    HITLS_Config *cfg =
        argc > 2 && strcmp(argv[2], "tls12") == 0 ? HITLS_CFG_NewTLS12Config() : HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int fd = -1;
    int ret = -1;
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    if (cfg == NULL || HITLS_CFG_SetGroups(cfg, &group, 1) != HITLS_SUCCESS ||
        HITLS_CFG_SetVerifyNoneSupport(cfg, true) != HITLS_SUCCESS) {
        goto EXIT;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int enabled = 1;
    if (fd < 0 || setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        goto EXIT;
    }
    ctx = HITLS_New(cfg);
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    int32_t socketFd = fd;
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
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret == 0 ? 0 : 1;
}
