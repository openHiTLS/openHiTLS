/*
 * Minimal TLS 1.3 server using RFC 9150 integrity-only suite TLS_SHA256_SHA256.
 * Listens on 127.0.0.1:12346. Build with the same flags as rfc9150_client.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_cert.h"
#include "hitls_crypt_init.h"
#include "hitls_pki_cert.h"
#include "crypt_errno.h"

#define CERTS_PATH "../../../testcode/testdata/tls/certificate/der/ecdsa_sha256/"
#define HTTP_BUF_MAXLEN (18 * 1024)

int main(void)
{
    int32_t exitValue = -1;
    int32_t ret;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int listenFd = -1;
    int connFd = -1;
    HITLS_X509_Cert *rootCA = NULL;
    HITLS_X509_Cert *subCA = NULL;

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init: %x\n", ret);
        return -1;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();

    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd == -1) {
        goto EXIT;
    }
    int option = 1;
    (void)setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12346);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listenFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
        printf("bind failed\n");
        goto EXIT;
    }
    if (listen(listenFd, 5) != 0) {
        goto EXIT;
    }

    struct sockaddr_in clientAddr;
    unsigned int len = sizeof(clientAddr);
    connFd = accept(listenFd, (struct sockaddr *)&clientAddr, &len);
    if (connFd < 0) {
        goto EXIT;
    }

    config = HITLS_CFG_NewTLS13Config();
    if (config == NULL) {
        goto EXIT;
    }
    ret = HITLS_CFG_SetClientVerifySupport(config, false);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

#ifndef HITLS_TLS_SUITE_TLS_SHA256_SHA256
    printf("Build openHiTLS with -DHITLS_TLS_SUITE_CIPHER_TLS13_INTEGRITY=ON.\n");
    goto EXIT;
#else
    {
        uint16_t suites[] = { HITLS_TLS_SHA256_SHA256 };
        ret = HITLS_CFG_SetCipherSuites(config, suites, sizeof(suites) / sizeof(suites[0]));
        if (ret != HITLS_SUCCESS) {
            printf("HITLS_CFG_SetCipherSuites failed: 0x%x\n", ret);
            goto EXIT;
        }
    }
#endif

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "ca.der", &rootCA);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "inter.der", &subCA);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_AddCertToStore(config, subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_LoadCertFile(config, CERTS_PATH "server.der", TLS_PARSE_FORMAT_ASN1);
    HITLS_CFG_LoadKeyFile(config, CERTS_PATH "server.key.der", TLS_PARSE_FORMAT_ASN1);

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        goto EXIT;
    }
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL) {
        goto EXIT;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(connFd), &connFd);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = HITLS_Accept(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Accept failed: 0x%x\n", ret);
        goto EXIT;
    }

    uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Read failed: 0x%x\n", ret);
        goto EXIT;
    }
    printf("from client (%u bytes): %s\n", readLen, readBuf);

    const uint8_t reply[] = "RFC9150 server OK\n";
    uint32_t wlen = 0;
    ret = HITLS_Write(ctx, reply, sizeof(reply), &wlen);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    exitValue = 0;

EXIT:
    if (ctx != NULL) {
        HITLS_Close(ctx);
        HITLS_Free(ctx);
    }
    HITLS_CFG_FreeConfig(config);
    if (connFd >= 0) {
        close(connFd);
    }
    if (listenFd >= 0) {
        close(listenFd);
    }
    HITLS_X509_CertFree(rootCA);
    HITLS_X509_CertFree(subCA);
    BSL_UIO_Free(uio);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return exitValue;
}
