/*
 * TLS certificate-chain verification demo.
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

#define TLS_VERIFY_CERTS_PATH "assets/tls_ecdsa_der/"
#define TLS_VERIFY_BUFFER_SIZE 4096
#define TLS_VERIFY_CLIENT_MESSAGE "tls verify request"
#define TLS_VERIFY_SERVER_REPLY "tls verify response"

static int32_t TlsVerifyInitLibrary(void)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    return HITLS_SUCCESS;
}

static int32_t TlsVerifyCallback(int32_t isPreverifyOk, HITLS_CERT_StoreCtx *storeCtx)
{
    (void)storeCtx;
    return isPreverifyOk;
}

static int32_t TlsVerifyCreateListenSocket(uint16_t *port)
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

static int32_t TlsVerifyConnectSocket(uint16_t port)
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

static int32_t TlsVerifyLoadVerifyStore(HITLS_Config *config)
{
    HITLS_CERT_X509 *rootCA = NULL;
    HITLS_CERT_X509 *intermediate = NULL;
    int32_t ret;

    /* Add the CA and intermediate to the trust store so the peer certificate chain can be verified. */
    rootCA = HITLS_CFG_ParseCert(config, (const uint8_t *)(TLS_VERIFY_CERTS_PATH "ca.der"),
        strlen(TLS_VERIFY_CERTS_PATH "ca.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    intermediate = HITLS_CFG_ParseCert(config, (const uint8_t *)(TLS_VERIFY_CERTS_PATH "inter.der"),
        strlen(TLS_VERIFY_CERTS_PATH "inter.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
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

static int32_t TlsVerifyCreateServerConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    int32_t ret;

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config(server) failed\n");
        return -1;
    }
    /* The server only needs to present its own chain in this verification example. */
    ret = HITLS_CFG_SetClientVerifySupport(config, false);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    /* Load the certificate and key pair that the client will validate during handshake. */
    ret = HITLS_CFG_LoadCertFile(config, TLS_VERIFY_CERTS_PATH "server.der", TLS_PARSE_FORMAT_ASN1);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_LoadKeyFile(config, TLS_VERIFY_CERTS_PATH "server.key.der", TLS_PARSE_FORMAT_ASN1);
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

static int32_t TlsVerifyCreateClientConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    int32_t ret;

    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config(client) failed\n");
        return -1;
    }
    /* Register the verification callback so the handshake can report certificate-chain validation results. */
    ret = HITLS_CFG_SetVerifyCb(config, TlsVerifyCallback);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = TlsVerifyLoadVerifyStore(config);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    *configOut = config;
    return HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    return ret;
}

static int32_t TlsVerifyRunServer(int32_t listenFd)
{
    uint8_t readBuf[TLS_VERIFY_BUFFER_SIZE] = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;

    ret = TlsVerifyInitLibrary();
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
    ret = TlsVerifyCreateServerConfig(&config);
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
    /* Bind the accepted TCP socket before the server enters the handshake path. */
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
    if (strcmp((char *)readBuf, TLS_VERIFY_CLIENT_MESSAGE) != 0) {
        printf("server received unexpected message: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_Write(ctx, (const uint8_t *)TLS_VERIFY_SERVER_REPLY, strlen(TLS_VERIFY_SERVER_REPLY), &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    printf("server completed certificate-verified TLS handshake and application exchange\n");
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

static int32_t TlsVerifyRunClient(uint16_t port)
{
    uint8_t readBuf[TLS_VERIFY_BUFFER_SIZE] = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_Session *session = NULL;
    BSL_UIO *uio = NULL;
    int32_t connFd = -1;
    uint16_t version = 0;
    uint16_t cipherSuite = 0;
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    int32_t ret;

    ret = TlsVerifyInitLibrary();
    if (ret != HITLS_SUCCESS) {
        printf("client init failed: 0x%x\n", ret);
        return -1;
    }
    connFd = TlsVerifyConnectSocket(port);
    if (connFd < 0) {
        ret = -1;
        goto cleanup;
    }
    ret = TlsVerifyCreateClientConfig(&config);
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
    /* The transport object is attached once so both handshake and application data share the same socket. */
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
    /* Read back the negotiated result so the example checks both verification and final protocol state. */
    ret = HITLS_GetNegotiatedVersion(ctx, &version);
    if (ret != HITLS_SUCCESS || version != HITLS_VERSION_TLS12) {
        printf("client negotiated unexpected version: 0x%x\n", version);
        ret = -1;
        goto cleanup;
    }
    session = HITLS_GetDupSession(ctx);
    if (session == NULL || HITLS_SESS_GetCipherSuite(session, &cipherSuite) != HITLS_SUCCESS) {
        printf("client failed to query cipher suite\n");
        ret = -1;
        goto cleanup;
    }
    /* Finish with application data so the example proves a verified handshake also yields a usable channel. */
    ret = HITLS_Write(ctx, (const uint8_t *)TLS_VERIFY_CLIENT_MESSAGE, strlen(TLS_VERIFY_CLIENT_MESSAGE), &writeLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_Read(ctx, readBuf, sizeof(readBuf) - 1, &readLen);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    readBuf[readLen] = '\0';
    if (strcmp((char *)readBuf, TLS_VERIFY_SERVER_REPLY) != 0) {
        printf("client received unexpected reply: %s\n", readBuf);
        ret = -1;
        goto cleanup;
    }
    printf("client established verified TLS connection version=0x%04x cipher=0x%04x\n", version, cipherSuite);
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
    printf("=== example_tls_cert_verify ===\n");

    listenFd = TlsVerifyCreateListenSocket(&port);
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
        int32_t serverRet = TlsVerifyRunServer(listenFd);

        close(listenFd);
        _exit(serverRet == 0 ? 0 : 1);
    }
    clientRet = TlsVerifyRunClient(port);
    close(listenFd);
    waitpid(pid, &waitStatus, 0);
    if (clientRet != 0 || !WIFEXITED(waitStatus) || WEXITSTATUS(waitStatus) != 0) {
        printf("example_tls_cert_verify failed\n");
        return -1;
    }
    printf("example_tls_cert_verify passed\n");
    return 0;
}
