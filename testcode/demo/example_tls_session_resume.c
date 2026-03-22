/*
 * TLS 1.2 session resumption demo.
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
#include "hitls_cert.h"
#include "hitls_cert_init.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
#include "hitls_session.h"

#define TLS_RESUME_CERTS_PATH "assets/tls_ecdsa_der/"
#define TLS_RESUME_BUFFER_SIZE 4096
#define TLS_RESUME_FIRST_MESSAGE "tls resume first request"
#define TLS_RESUME_SECOND_MESSAGE "tls resume second request"
#define TLS_RESUME_SERVER_REPLY "tls resume response"
#define TLS_RESUME_SESSION_ID_CTX "demo-session-id"

static int32_t TlsResumeInitLibrary(void)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    return HITLS_SUCCESS;
}

static int32_t TlsResumeVerifyCallback(int32_t isPreverifyOk, HITLS_CERT_StoreCtx *storeCtx)
{
    (void)storeCtx;
    return isPreverifyOk;
}

static int32_t TlsResumeCreateListenSocket(uint16_t *port)
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
    if (listen(listenFd, 2) != 0) {
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

static int32_t TlsResumeConnectSocket(uint16_t port)
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

static int32_t TlsResumeLoadVerifyStore(HITLS_Config *config)
{
    HITLS_CERT_X509 *rootCA = NULL;
    HITLS_CERT_X509 *intermediate = NULL;
    int32_t ret;

    rootCA = HITLS_CFG_ParseCert(config, (const uint8_t *)(TLS_RESUME_CERTS_PATH "ca.der"),
        strlen(TLS_RESUME_CERTS_PATH "ca.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    intermediate = HITLS_CFG_ParseCert(config, (const uint8_t *)(TLS_RESUME_CERTS_PATH "inter.der"),
        strlen(TLS_RESUME_CERTS_PATH "inter.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    if (rootCA == NULL || intermediate == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_CFG_AddCertToStore(config, intermediate, TLS_CERT_STORE_TYPE_DEFAULT, true);
    }

cleanup:
    if (rootCA != NULL) {
        HITLS_CFG_FreeCert(config, rootCA);
    }
    if (intermediate != NULL) {
        HITLS_CFG_FreeCert(config, intermediate);
    }
    return ret;
}

static int32_t TlsResumeCreateServerConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    int32_t ret;

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config(server) failed\n");
        return -1;
    }
    ret = HITLS_CFG_SetClientVerifySupport(config, false);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_SetSessionTicketSupport(config, false);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_SetSessionIdCtx(config, (const uint8_t *)TLS_RESUME_SESSION_ID_CTX,
        (uint32_t)strlen(TLS_RESUME_SESSION_ID_CTX));
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_LoadCertFile(config, TLS_RESUME_CERTS_PATH "server.der", TLS_PARSE_FORMAT_ASN1);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_LoadKeyFile(config, TLS_RESUME_CERTS_PATH "server.key.der", TLS_PARSE_FORMAT_ASN1);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_CheckPrivateKey(config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    *configOut = config;
    return HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    return ret;
}

static int32_t TlsResumeCreateClientConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    int32_t ret;

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config(client) failed\n");
        return -1;
    }
    ret = HITLS_CFG_SetVerifyCb(config, TlsResumeVerifyCallback);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = TlsResumeLoadVerifyStore(config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    *configOut = config;
    return HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    return ret;
}

static int32_t TlsResumeRunSingleServerConnection(HITLS_Config *config, int32_t listenFd, const char *expectedMessage)
{
    uint8_t readBuf[TLS_RESUME_BUFFER_SIZE] = {0};
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;

    connFd = accept(listenFd, NULL, NULL);
    if (connFd < 0) {
        perror("accept");
        return -1;
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
    ret = HITLS_Accept(ctx);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_Read(ctx, readBuf, sizeof(readBuf) - 1, &readLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    readBuf[readLen] = '\0';
    if (strcmp((char *)readBuf, expectedMessage) != 0) {
        printf("server received unexpected message: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_Write(ctx, (const uint8_t *)TLS_RESUME_SERVER_REPLY, strlen(TLS_RESUME_SERVER_REPLY), &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    if (connFd >= 0) {
        close(connFd);
    }
    BSL_UIO_Free(uio);
    return ret;
}

static int32_t TlsResumeRunServer(int32_t listenFd)
{
    HITLS_Config *config = NULL;
    int32_t ret;

    ret = TlsResumeInitLibrary();
    if (ret != HITLS_SUCCESS) {
        printf("server init failed: 0x%x\n", ret);
        return -1;
    }
    ret = TlsResumeCreateServerConfig(&config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = TlsResumeRunSingleServerConnection(config, listenFd, TLS_RESUME_FIRST_MESSAGE);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = TlsResumeRunSingleServerConnection(config, listenFd, TLS_RESUME_SECOND_MESSAGE);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    printf("server completed full handshake and resumed handshake\n");
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret == HITLS_SUCCESS ? 0 : -1;
}

static int32_t TlsResumeRunSingleClientConnection(HITLS_Config *config, uint16_t port, const char *message,
    HITLS_Session *sessionToUse, HITLS_Session **newSession, bool *isReusedOut)
{
    uint8_t readBuf[TLS_RESUME_BUFFER_SIZE] = {0};
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;
    bool isReused = false;

    connFd = TlsResumeConnectSocket(port);
    if (connFd < 0) {
        return -1;
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
    if (sessionToUse != NULL) {
        ret = HITLS_SetSession(ctx, sessionToUse);
        if (ret != HITLS_SUCCESS) {
            goto cleanup;
        }
    }
    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    if (isReusedOut != NULL) {
        ret = HITLS_IsSessionReused(ctx, &isReused);
        if (ret != HITLS_SUCCESS) {
            goto cleanup;
        }
        *isReusedOut = isReused;
    }
    if (newSession != NULL) {
        *newSession = HITLS_GetDupSession(ctx);
        if (*newSession == NULL) {
            ret = -1;
            goto cleanup;
        }
    }
    ret = HITLS_Write(ctx, (const uint8_t *)message, strlen(message), &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_Read(ctx, readBuf, sizeof(readBuf) - 1, &readLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    readBuf[readLen] = '\0';
    if (strcmp((char *)readBuf, TLS_RESUME_SERVER_REPLY) != 0) {
        printf("client received unexpected reply: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    if (connFd >= 0) {
        close(connFd);
    }
    BSL_UIO_Free(uio);
    return ret;
}

static int32_t TlsResumeRunClient(uint16_t port)
{
    HITLS_Config *config = NULL;
    HITLS_Session *session = NULL;
    bool isReused = false;
    int32_t ret;

    ret = TlsResumeInitLibrary();
    if (ret != HITLS_SUCCESS) {
        printf("client init failed: 0x%x\n", ret);
        return -1;
    }
    ret = TlsResumeCreateClientConfig(&config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = TlsResumeRunSingleClientConnection(config, port, TLS_RESUME_FIRST_MESSAGE, NULL, &session, &isReused);
    if (ret != HITLS_SUCCESS || isReused) {
        printf("first handshake should not be resumed\n");
        ret = -1;
        goto cleanup;
    }
    ret = TlsResumeRunSingleClientConnection(config, port, TLS_RESUME_SECOND_MESSAGE, session, NULL, &isReused);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    if (!isReused) {
        printf("second handshake did not reuse the session\n");
        ret = -1;
        goto cleanup;
    }
    printf("client resumed TLS session successfully on the second connection\n");
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_SESS_Free(session);
    HITLS_CFG_FreeConfig(config);
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
    printf("=== example_tls_session_resume ===\n");

    listenFd = TlsResumeCreateListenSocket(&port);
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
        int32_t serverRet = TlsResumeRunServer(listenFd);

        close(listenFd);
        _exit(serverRet == 0 ? 0 : 1);
    }
    clientRet = TlsResumeRunClient(port);
    close(listenFd);
    waitpid(pid, &waitStatus, 0);
    if (clientRet != 0 || !WIFEXITED(waitStatus) || WEXITSTATUS(waitStatus) != 0) {
        printf("example_tls_session_resume failed\n");
        return -1;
    }
    printf("example_tls_session_resume passed\n");
    return 0;
}
