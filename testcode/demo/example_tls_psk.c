/*
 * TLS PSK local client/server communication demo.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bsl_err.h"
#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
#include "hitls_error.h"
#include "hitls_psk.h"

#define TLS_PSK_BUFFER_SIZE 4096
#define TLS_PSK_CLIENT_MESSAGE "tls psk request"
#define TLS_PSK_SERVER_REPLY "tls psk response"
#define TLS_PSK_HINT "openhitls-psk"
#define TLS_PSK_IDENTITY "client-identity"

static const uint8_t TLS_PSK_KEY[] = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x11, 0x33, 0x55, 0x77, 0x99, 0xbb, 0xdd, 0xff
};

static int32_t TlsPskInitLibrary(void)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    return HITLS_SUCCESS;
}

static uint32_t TlsPskClientCallback(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen,
    uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;

    if (hint == NULL || strcmp((const char *)hint, TLS_PSK_HINT) != 0) {
        return 0;
    }
    if (identity == NULL || psk == NULL ||
        maxIdentityLen <= strlen(TLS_PSK_IDENTITY) || maxPskLen < sizeof(TLS_PSK_KEY)) {
        return 0;
    }
    memcpy(identity, TLS_PSK_IDENTITY, strlen(TLS_PSK_IDENTITY) + 1);
    memcpy(psk, TLS_PSK_KEY, sizeof(TLS_PSK_KEY));
    return sizeof(TLS_PSK_KEY);
}

static uint32_t TlsPskServerCallback(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;

    if (identity == NULL || strcmp((const char *)identity, TLS_PSK_IDENTITY) != 0) {
        return 0;
    }
    if (psk == NULL || maxPskLen < sizeof(TLS_PSK_KEY)) {
        return 0;
    }
    memcpy(psk, TLS_PSK_KEY, sizeof(TLS_PSK_KEY));
    return sizeof(TLS_PSK_KEY);
}

static int32_t TlsPskCreateListenSocket(uint16_t *port)
{
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    int32_t listenFd;
    int32_t opt = 1;

    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(listenFd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listenFd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(listenFd);
        return -1;
    }
    if (listen(listenFd, 1) != 0) {
        perror("listen");
        close(listenFd);
        return -1;
    }
    if (getsockname(listenFd, (struct sockaddr *)&addr, &addrLen) != 0) {
        perror("getsockname");
        close(listenFd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return listenFd;
}

static int32_t TlsPskConnectSocket(uint16_t port)
{
    struct sockaddr_in addr;
    int32_t fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

static int32_t TlsPskCreateServerConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    int32_t ret;
    const uint16_t cipherSuites[] = {HITLS_PSK_WITH_AES_128_CBC_SHA256};

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config(server) failed\n");
        return -1;
    }
    ret = HITLS_CFG_SetClientVerifySupport(config, false);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* Both peers must advertise the same PSK cipher suite or the handshake cannot enter PSK mode. */
    ret = HITLS_CFG_SetCipherSuites(config, cipherSuites, 1);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* The server hint is sent in the handshake so the client can choose the right identity/key pair. */
    ret = HITLS_CFG_SetPskIdentityHint(config, (const uint8_t *)TLS_PSK_HINT, (uint32_t)strlen(TLS_PSK_HINT));
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* The server callback is queried during handshake to map identity -> PSK bytes. */
    ret = HITLS_CFG_SetPskServerCallback(config, TlsPskServerCallback);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    *configOut = config;
    return HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    return ret;
}

static int32_t TlsPskCreateClientConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    int32_t ret;
    const uint16_t cipherSuites[] = {HITLS_PSK_WITH_AES_128_CBC_SHA256};

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config(client) failed\n");
        return -1;
    }
    /* The client also advertises the same PSK cipher suite so the server can choose it during handshake. */
    ret = HITLS_CFG_SetCipherSuites(config, cipherSuites, 1);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* The client callback is invoked during handshake to return identity and PSK bytes. */
    ret = HITLS_CFG_SetPskClientCallback(config, TlsPskClientCallback);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    *configOut = config;
    return HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    return ret;
}

static int32_t TlsPskRunServer(int32_t listenFd)
{
    uint8_t readBuf[TLS_PSK_BUFFER_SIZE] = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;

    ret = TlsPskInitLibrary();
    if (ret != HITLS_SUCCESS) {
        printf("server init failed: 0x%x\n", ret);
        return -1;
    }
    connFd = accept(listenFd, NULL, NULL);
    if (connFd < 0) {
        perror("accept");
        ret = -1;
        goto cleanup;
    }
    ret = TlsPskCreateServerConfig(&config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ctx = HITLS_New(config);
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (ctx == NULL || uio == NULL) {
        printf("server ctx/uio create failed\n");
        ret = -1;
        goto cleanup;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(connFd), &connFd);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* Accept consumes the configured cipher suite, hint, and server callback while building the PSK handshake. */
    ret = HITLS_Accept(ctx);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_Read(ctx, readBuf, sizeof(readBuf) - 1, &readLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    readBuf[readLen] = '\0';
    if (strcmp((char *)readBuf, TLS_PSK_CLIENT_MESSAGE) != 0) {
        printf("server received unexpected message: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_Write(ctx, (const uint8_t *)TLS_PSK_SERVER_REPLY, strlen(TLS_PSK_SERVER_REPLY), &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    printf("server completed PSK-authenticated TLS exchange\n");
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    if (connFd >= 0) {
        close(connFd);
    }
    BSL_UIO_Free(uio);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret == HITLS_SUCCESS ? 0 : -1;
}

static int32_t TlsPskRunClient(uint16_t port)
{
    uint8_t readBuf[TLS_PSK_BUFFER_SIZE] = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;

    ret = TlsPskInitLibrary();
    if (ret != HITLS_SUCCESS) {
        printf("client init failed: 0x%x\n", ret);
        return -1;
    }
    connFd = TlsPskConnectSocket(port);
    if (connFd < 0) {
        ret = -1;
        goto cleanup;
    }
    ret = TlsPskCreateClientConfig(&config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ctx = HITLS_New(config);
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (ctx == NULL || uio == NULL) {
        printf("client ctx/uio create failed\n");
        ret = -1;
        goto cleanup;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(connFd), &connFd);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* Connect consumes the PSK cipher suite list and client callback during the handshake. */
    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_Write(ctx, (const uint8_t *)TLS_PSK_CLIENT_MESSAGE, strlen(TLS_PSK_CLIENT_MESSAGE), &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_Read(ctx, readBuf, sizeof(readBuf) - 1, &readLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    readBuf[readLen] = '\0';
    if (strcmp((char *)readBuf, TLS_PSK_SERVER_REPLY) != 0) {
        printf("client received unexpected reply: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    printf("client established PSK-authenticated TLS connection\n");
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    if (connFd >= 0) {
        close(connFd);
    }
    BSL_UIO_Free(uio);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret == HITLS_SUCCESS ? 0 : -1;
}

int main(void)
{
    uint16_t port = 0;
    int32_t listenFd;
    pid_t pid;
    int32_t clientRet;
    int32_t waitStatus = 0;

    signal(SIGPIPE, SIG_IGN);
    printf("=== example_tls_psk ===\n");

    listenFd = TlsPskCreateListenSocket(&port);
    if (listenFd < 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        perror("fork");
        close(listenFd);
        return -1;
    }
    if (pid == 0) {
        int32_t serverRet = TlsPskRunServer(listenFd);

        close(listenFd);
        _exit(serverRet == 0 ? 0 : 1);
    }
    clientRet = TlsPskRunClient(port);
    close(listenFd);
    waitpid(pid, &waitStatus, 0);
    if (clientRet != 0 || !WIFEXITED(waitStatus) || WEXITSTATUS(waitStatus) != 0) {
        printf("example_tls_psk failed\n");
        return -1;
    }
    printf("example_tls_psk passed\n");
    return 0;
}
