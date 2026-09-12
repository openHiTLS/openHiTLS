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

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bsl_sal.h"
#include "crypt_eal_init.h"
#include "hitls.h"
#include "hitls_cert.h"
#include "hitls_cert_init.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
#include "hitls_error.h"
#include "hitls_psk.h"
#include "tls.h"

#define RFC9973_DEMO_PORT     24443
#define RFC9973_DEMO_IDENTITY "Client_identity"
#define DEFAULT_CERT_FILE     "../../../testcode/testdata/tls/certificate/pem/ecdsa_sha256/server.pem"
#define DEFAULT_KEY_FILE      "../../../testcode/testdata/tls/certificate/pem/ecdsa_sha256/server.key.pem"
#define DEFAULT_CHAIN_FILE    "../../../testcode/testdata/tls/certificate/pem/ecdsa_sha256/inter.pem"
#define DEMO_REPLY            "openHiTLS RFC9973 server"
#define DEMO_MESSAGE_MAX_LEN  128u

/* Fixed example PSK; configure the same bytes on both peers. */
static const uint8_t g_rfc9973DemoPsk[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
                                           0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                           0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static uint32_t Rfc9973ServerPskCallback(HITLS_Ctx *ctx, const uint8_t *identity,
    uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;
    /* 1. Match the configured identity and check the output buffer capacity. */
    if (identity == NULL || strcmp((const char *)identity, RFC9973_DEMO_IDENTITY) != 0 ||
        maxPskLen < sizeof(g_rfc9973DemoPsk)) {
        return 0;
    }
    /* 2. Return the same example PSK as the client; zero above means the identity is unusable. */
    (void)memcpy(psk, g_rfc9973DemoPsk, sizeof(g_rfc9973DemoPsk));
    return sizeof(g_rfc9973DemoPsk);
}

static int32_t ConfigureServer(HITLS_Config *config, const char *certFile,
    const char *keyFile, const char *chainFile)
{
    /* 1. Enable mode 8, choose the SHA-256 suite, and install the external PSK callback. */
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    int32_t ret = HITLS_CFG_SetKeyExchMode(config, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    }
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_CFG_SetPskServerCallback(config, Rfc9973ServerPskCallback);
    }
    if (ret == HITLS_SUCCESS) {
        /* 2. Load the server certificate and private key; mode 8 still requires certificate authentication. */
        ret = HITLS_CFG_LoadCertFile(config, certFile, TLS_PARSE_FORMAT_PEM);
    }
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_CFG_LoadKeyFile(config, keyFile, TLS_PARSE_FORMAT_PEM);
    }
    if (ret != HITLS_SUCCESS || chainFile == NULL) {
        return ret;
    }

    /* 3. Add the optional intermediate certificate, transferring ownership only on success. */
    HITLS_CERT_X509 *chainCert = HITLS_CFG_ParseCert(config, (const uint8_t *)chainFile,
        (uint32_t)strlen(chainFile) + 1u, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_PEM);
    if (chainCert == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    ret = HITLS_CFG_AddChainCert(config, chainCert, false);
    if (ret != HITLS_SUCCESS) {
        (void)HITLS_CFG_FreeCert(config, chainCert);
    }
    return ret;
}

static int ListenTcp(uint16_t port)
{
    /* 1. Create a reusable IPv4 TCP listener. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int option = 1;
    struct sockaddr_in address = {0};
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) != 0) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return -1;
    }
    /* 2. Bind to loopback so this example accepts only local connections. */
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(fd, 1) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    uint16_t port = (uint16_t)(argc > 1 ? strtoul(argv[1], NULL, 10) : RFC9973_DEMO_PORT);
    const char *certFile = argc > 2 ? argv[2] : DEFAULT_CERT_FILE;
    const char *keyFile = argc > 3 ? argv[3] : DEFAULT_KEY_FILE;
    const char *chainFile = argc > 4 ? argv[4] : DEFAULT_CHAIN_FILE;
    int exitCode = EXIT_FAILURE;
    int listenFd = -1;
    int clientFd = -1;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;

    /* 1. Initialize crypto and certificate methods before creating the TLS configuration. */
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != HITLS_SUCCESS) {
        (void)fprintf(stderr, "failed to initialize crypto\n");
        return exitCode;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();

    /* 2. Configure credentials and establish the TCP transport. */
    config = HITLS_CFG_NewTLS13Config();
    if (config == NULL || ConfigureServer(config, certFile, keyFile, chainFile) != HITLS_SUCCESS) {
        (void)fprintf(stderr, "failed to configure RFC9973 server\n");
        goto EXIT;
    }
    listenFd = ListenTcp(port);
    if (listenFd < 0) {
        (void)fprintf(stderr, "failed to listen on 127.0.0.1:%u\n", port);
        goto EXIT;
    }
    (void)printf("waiting for one RFC9973 client on 127.0.0.1:%u\n", port);
    clientFd = accept(listenFd, NULL, NULL);
    if (clientFd < 0) {
        (void)fprintf(stderr, "accept failed\n");
        goto EXIT;
    }
    /* 3. Bind the connected socket to the TLS context and run the handshake. */
    ctx = HITLS_New(config);
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (ctx == NULL || uio == NULL ||
        BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(clientFd), &clientFd) != HITLS_SUCCESS ||
        HITLS_SetUio(ctx, uio) != HITLS_SUCCESS) {
        (void)fprintf(stderr, "failed to create TLS connection\n");
        goto EXIT;
    }
    int32_t ret = HITLS_Accept(ctx);
    if (ret != HITLS_SUCCESS) {
        (void)fprintf(stderr, "RFC9973 handshake failed: 0x%x\n", ret);
        goto EXIT;
    }

    /* 4. Verify that mode 8 was selected before exchanging application data. */
    uint32_t mode = ctx->negotiatedInfo.tls13BasicKeyExMode;
    if (mode != TLS13_CERT_AUTH_WITH_EXTERNAL_PSK) {
        (void)fprintf(stderr, "RFC9973 was not negotiated: mode=%u\n", mode);
        goto EXIT;
    }

    uint8_t message[DEMO_MESSAGE_MAX_LEN] = {0};
    uint32_t messageLen = 0;
    ret = HITLS_Read(ctx, message, sizeof(message) - 1u, &messageLen);
    if (ret != HITLS_SUCCESS) {
        (void)fprintf(stderr, "application read failed: 0x%x\n", ret);
        goto EXIT;
    }
    uint32_t written = 0;
    ret = HITLS_Write(ctx, (const uint8_t *)DEMO_REPLY, (uint32_t)strlen(DEMO_REPLY), &written);
    if (ret != HITLS_SUCCESS || written != strlen(DEMO_REPLY)) {
        (void)fprintf(stderr, "application write failed: 0x%x\n", ret);
        goto EXIT;
    }
    (void)printf("RFC9973 handshake and application data succeeded (mode=%u); peer sent: %.*s\n",
        mode, (int)messageLen, message);
    exitCode = EXIT_SUCCESS;

EXIT:
    /* 5. Release the TLS context, transport, configuration, and socket resources. */
    if (ctx != NULL) {
        (void)HITLS_Close(ctx);
    }
    HITLS_Free(ctx);
    BSL_UIO_Free(uio);
    HITLS_CFG_FreeConfig(config);
    if (clientFd >= 0) {
        (void)close(clientFd);
    }
    if (listenFd >= 0) {
        (void)close(listenFd);
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return exitCode;
}
