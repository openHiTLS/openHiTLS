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
#include "hitls_pki_cert.h"
#include "hitls_psk.h"
#include "tls.h"

#define RFC9973_DEMO_PORT     24443
#define RFC9973_DEMO_IDENTITY "Client_identity"
#define DEFAULT_CA_FILE       "../../../testcode/testdata/tls/certificate/pem/ecdsa_sha256/ca.pem"
#define DEMO_MESSAGE          "openHiTLS RFC9973 client"
#define DEMO_REPLY_MAX_LEN    128u

/* Fixed example PSK; configure the same bytes on both peers. */
static const uint8_t g_rfc9973DemoPsk[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
                                           0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                           0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static uint32_t Rfc9973ClientPskCallback(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity,
                                         uint32_t maxIdentityLen, uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;
    (void)hint;
    const uint32_t identityLen = (uint32_t)sizeof(RFC9973_DEMO_IDENTITY);
    /* 1. Check space for the NUL-terminated identity and the PSK. */
    if (maxIdentityLen < identityLen || maxPskLen < sizeof(g_rfc9973DemoPsk)) {
        return 0;
    }
    /* 2. Return the shared example identity and key through the legacy SHA-256 PSK callback. */
    (void)memcpy(identity, RFC9973_DEMO_IDENTITY, identityLen);
    (void)memcpy(psk, g_rfc9973DemoPsk, sizeof(g_rfc9973DemoPsk));
    return sizeof(g_rfc9973DemoPsk);
}

static int32_t ConfigureClient(HITLS_Config *config, const char *caFile, const char *certFile, const char *keyFile)
{
    /* 1. Enable mode 8 with its required psk_dhe_ke mode, choose SHA-256, and install the external PSK callback. */
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    int32_t ret = HITLS_CFG_SetKeyExchMode(config,
        TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    }
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_CFG_SetPskClientCallback(config, Rfc9973ClientPskCallback);
    }
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* 2. Add the CA used to verify the server certificate. */
    HITLS_X509_Cert *ca = NULL;
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caFile, &ca);
    if (ret == HITLS_SUCCESS) {
        ret = HITLS_CFG_AddCertToStore(config, ca, TLS_CERT_STORE_TYPE_DEFAULT, true);
    }
    HITLS_X509_CertFree(ca);
    /* 3. Optionally load the client certificate and private key for mutual authentication. */
    if (ret == HITLS_SUCCESS && certFile != NULL && keyFile != NULL) {
        ret = HITLS_CFG_LoadCertFile(config, certFile, TLS_PARSE_FORMAT_PEM);
        if (ret == HITLS_SUCCESS) {
            ret = HITLS_CFG_LoadKeyFile(config, keyFile, TLS_PARSE_FORMAT_PEM);
        }
    }
    return ret;
}

static int ConnectTcp(const char *host, uint16_t port)
{
    /* 1. Create an IPv4 TCP socket. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    /* 2. Parse the peer address and connect; close the socket on failure. */
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    uint16_t port = (uint16_t)(argc > 2 ? strtoul(argv[2], NULL, 10) : RFC9973_DEMO_PORT);
    const char *caFile = argc > 3 ? argv[3] : DEFAULT_CA_FILE;
    const char *certFile = argc > 4 ? argv[4] : NULL;
    const char *keyFile = argc > 5 ? argv[5] : NULL;
    int exitCode = EXIT_FAILURE;
    int fd = -1;
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
    if (config == NULL || ConfigureClient(config, caFile, certFile, keyFile) != HITLS_SUCCESS) {
        (void)fprintf(stderr, "failed to configure RFC9973 client\n");
        goto EXIT;
    }
    fd = ConnectTcp(host, port);
    if (fd < 0) {
        (void)fprintf(stderr, "failed to connect to %s:%u\n", host, port);
        goto EXIT;
    }
    /* 3. Bind the connected socket to the TLS context and run the handshake. */
    ctx = HITLS_New(config);
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (ctx == NULL || uio == NULL || BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd) != HITLS_SUCCESS ||
        HITLS_SetUio(ctx, uio) != HITLS_SUCCESS) {
        (void)fprintf(stderr, "failed to create TLS connection\n");
        goto EXIT;
    }
    int32_t ret = HITLS_Connect(ctx);
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

    uint32_t written = 0;
    ret = HITLS_Write(ctx, (const uint8_t *)DEMO_MESSAGE, (uint32_t)strlen(DEMO_MESSAGE), &written);
    if (ret != HITLS_SUCCESS || written != strlen(DEMO_MESSAGE)) {
        (void)fprintf(stderr, "application write failed: 0x%x\n", ret);
        goto EXIT;
    }
    uint8_t reply[DEMO_REPLY_MAX_LEN] = {0};
    uint32_t replyLen = 0;
    ret = HITLS_Read(ctx, reply, sizeof(reply) - 1u, &replyLen);
    if (ret != HITLS_SUCCESS) {
        (void)fprintf(stderr, "application read failed: 0x%x\n", ret);
        goto EXIT;
    }
    (void)printf("RFC9973 handshake and application data succeeded (mode=%u); peer replied: %.*s\n", mode,
                 (int)replyLen, reply);
    exitCode = EXIT_SUCCESS;

EXIT:
    /* 5. Release the TLS context, transport, configuration, and socket resources. */
    if (ctx != NULL) {
        (void)HITLS_Close(ctx);
    }
    HITLS_Free(ctx);
    BSL_UIO_Free(uio);
    HITLS_CFG_FreeConfig(config);
    if (fd >= 0) {
        (void)close(fd);
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return exitCode;
}
