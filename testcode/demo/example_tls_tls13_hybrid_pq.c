/*
 * TLS 1.3 hybrid post-quantum key exchange demo.
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

#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls.h"
#include "hitls_cert.h"
#include "hitls_cert_init.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
#include "hitls_session.h"

#define TLS13_HYBRID_CERTS_PATH "assets/tls_ecdsa_der/"
#define TLS13_HYBRID_BUFFER_SIZE 4096
#define TLS13_HYBRID_CLIENT_MESSAGE "tls13 hybrid pq request"
#define TLS13_HYBRID_SERVER_REPLY "tls13 hybrid pq response"

static const uint16_t TLS13_HYBRID_GROUPS[] = {
    HITLS_HYBRID_X25519_MLKEM768
};

static int32_t Tls13HybridInitLibrary(void)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    return HITLS_SUCCESS;
}

static int32_t Tls13HybridVerifyCallback(int32_t isPreverifyOk, HITLS_CERT_StoreCtx *storeCtx)
{
    (void)storeCtx;
    return isPreverifyOk;
}

static int32_t Tls13HybridCreateListenSocket(uint16_t *port)
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

static int32_t Tls13HybridConnectSocket(uint16_t port)
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

static int32_t Tls13HybridLoadVerifyStore(HITLS_Config *config)
{
    HITLS_CERT_X509 *rootCA = NULL;
    HITLS_CERT_X509 *intermediate = NULL;
    int32_t ret;

    rootCA = HITLS_CFG_ParseCert(config, (const uint8_t *)(TLS13_HYBRID_CERTS_PATH "ca.der"),
        strlen(TLS13_HYBRID_CERTS_PATH "ca.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    intermediate = HITLS_CFG_ParseCert(config, (const uint8_t *)(TLS13_HYBRID_CERTS_PATH "inter.der"),
        strlen(TLS13_HYBRID_CERTS_PATH "inter.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
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

static int32_t Tls13HybridApplyGroupConfig(HITLS_Config *config)
{
    return HITLS_CFG_SetGroups(config, TLS13_HYBRID_GROUPS,
        sizeof(TLS13_HYBRID_GROUPS) / sizeof(TLS13_HYBRID_GROUPS[0]));
}

static int32_t Tls13HybridCreateServerConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    int32_t ret;

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS13Config(server) failed\n");
        return -1;
    }
    ret = HITLS_CFG_SetClientVerifySupport(config, false);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* Restrict key exchange to a TLS 1.3 hybrid PQ group so the handshake uses hybrid ECDH + ML-KEM. */
    ret = Tls13HybridApplyGroupConfig(config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_LoadCertFile(config, TLS13_HYBRID_CERTS_PATH "server.der", TLS_PARSE_FORMAT_ASN1);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_LoadKeyFile(config, TLS13_HYBRID_CERTS_PATH "server.key.der", TLS_PARSE_FORMAT_ASN1);
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

static int32_t Tls13HybridCreateClientConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    int32_t ret;

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS13Config(client) failed\n");
        return -1;
    }
    /* The client advertises only the same hybrid group, so the server must negotiate that PQ path. */
    ret = Tls13HybridApplyGroupConfig(config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_SetVerifyCb(config, Tls13HybridVerifyCallback);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = Tls13HybridLoadVerifyStore(config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    *configOut = config;
    return HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    return ret;
}

static int32_t Tls13HybridRunServer(int32_t listenFd)
{
    uint8_t readBuf[TLS13_HYBRID_BUFFER_SIZE] = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint16_t negotiatedGroup = 0;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;

    ret = Tls13HybridInitLibrary();
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
    ret = Tls13HybridCreateServerConfig(&config);
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
    ret = HITLS_Accept(ctx);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_GetNegotiateGroup(ctx, &negotiatedGroup);
    if (ret != HITLS_SUCCESS || negotiatedGroup != HITLS_HYBRID_X25519_MLKEM768) {
        printf("server negotiated unexpected group: 0x%x\n", negotiatedGroup);
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_Read(ctx, readBuf, sizeof(readBuf) - 1, &readLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    readBuf[readLen] = '\0';
    if (strcmp((char *)readBuf, TLS13_HYBRID_CLIENT_MESSAGE) != 0) {
        printf("server received unexpected message: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_Write(ctx, (const uint8_t *)TLS13_HYBRID_SERVER_REPLY, strlen(TLS13_HYBRID_SERVER_REPLY), &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    printf("server completed TLS 1.3 handshake with hybrid group=0x%04x\n", negotiatedGroup);
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

static int32_t Tls13HybridRunClient(uint16_t port)
{
    uint8_t readBuf[TLS13_HYBRID_BUFFER_SIZE] = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_Session *session = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint16_t version = 0;
    uint16_t cipherSuite = 0;
    uint16_t negotiatedGroup = 0;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;

    ret = Tls13HybridInitLibrary();
    if (ret != HITLS_SUCCESS) {
        printf("client init failed: 0x%x\n", ret);
        return -1;
    }
    connFd = Tls13HybridConnectSocket(port);
    if (connFd < 0) {
        ret = -1;
        goto cleanup;
    }
    ret = Tls13HybridCreateClientConfig(&config);
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
    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_GetNegotiatedVersion(ctx, &version);
    if (ret != HITLS_SUCCESS || version != HITLS_VERSION_TLS13) {
        printf("client negotiated unexpected version: 0x%x\n", version);
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_GetNegotiateGroup(ctx, &negotiatedGroup);
    if (ret != HITLS_SUCCESS || negotiatedGroup != HITLS_HYBRID_X25519_MLKEM768) {
        printf("client negotiated unexpected group: 0x%x\n", negotiatedGroup);
        ret = -1;
        goto cleanup;
    }
    session = HITLS_GetDupSession(ctx);
    if (session == NULL || HITLS_SESS_GetCipherSuite(session, &cipherSuite) != HITLS_SUCCESS) {
        printf("client failed to query cipher suite\n");
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_Write(ctx, (const uint8_t *)TLS13_HYBRID_CLIENT_MESSAGE, strlen(TLS13_HYBRID_CLIENT_MESSAGE),
        &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_Read(ctx, readBuf, sizeof(readBuf) - 1, &readLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    readBuf[readLen] = '\0';
    if (strcmp((char *)readBuf, TLS13_HYBRID_SERVER_REPLY) != 0) {
        printf("client received unexpected reply: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    printf("client established TLS 1.3 hybrid PQ connection version=0x%04x cipher=0x%04x group=0x%04x\n",
        version, cipherSuite, negotiatedGroup);
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_SESS_Free(session);
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
    printf("=== example_tls_tls13_hybrid_pq ===\n");

    listenFd = Tls13HybridCreateListenSocket(&port);
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
        int32_t serverRet = Tls13HybridRunServer(listenFd);

        close(listenFd);
        _exit(serverRet == 0 ? 0 : 1);
    }
    clientRet = Tls13HybridRunClient(port);
    close(listenFd);
    waitpid(pid, &waitStatus, 0);
    if (clientRet != 0 || !WIFEXITED(waitStatus) || WEXITSTATUS(waitStatus) != 0) {
        printf("example_tls_tls13_hybrid_pq failed\n");
        return -1;
    }
    printf("example_tls_tls13_hybrid_pq passed\n");
    return 0;
}
