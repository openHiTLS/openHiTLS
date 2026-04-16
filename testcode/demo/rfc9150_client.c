/*
 * Minimal TLS 1.3 client using RFC 9150 integrity-only suite TLS_SHA256_SHA256.
 * Build with testcode/demo (requires main library built with HITLS_TLS_SUITE_CIPHER_TLS13_INTEGRITY).
 *
 * Run: start rfc9150_server first, then ./rfc9150_client
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bsl_sal.h"
#include "crypt_eal_init.h"
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

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    int32_t exitValue = -1;
    int32_t ret;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int fd = -1;
    HITLS_X509_Cert *rootCA = NULL;
    HITLS_X509_Cert *subCA = NULL;

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init: %x\n", ret);
        return -1;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("socket failed\n");
        goto EXIT;
    }
    int option = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    struct sockaddr_in serverAddr;
    (void)memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12346);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
        printf("connect failed (is rfc9150_server listening on 12346?)\n");
        goto EXIT;
    }

    config = HITLS_CFG_NewTLS13Config();
    if (config == NULL) {
        printf("HITLS_CFG_NewTLS13Config failed\n");
        goto EXIT;
    }
    ret = HITLS_CFG_SetCheckKeyUsage(config, false);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

#ifndef HITLS_TLS_SUITE_TLS_SHA256_SHA256
    printf("Build openHiTLS with -DHITLS_TLS_SUITE_CIPHER_TLS13_INTEGRITY=ON (and full TLS deps).\n");
    goto EXIT;
#else
    {
        uint16_t suites[] = { HITLS_TLS_SHA256_SHA256 };
        ret = HITLS_CFG_SetCipherSuites(config, suites, sizeof(suites) / sizeof(suites[0]));
        if (ret != HITLS_SUCCESS) {
            printf("HITLS_CFG_SetCipherSuites failed: 0x%x (enable RFC 9150 suites in CMake)\n", ret);
            goto EXIT;
        }
    }
#endif

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "ca.der", &rootCA);
    if (ret != HITLS_SUCCESS) {
        printf("parse ca failed\n");
        goto EXIT;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "inter.der", &subCA);
    if (ret != HITLS_SUCCESS) {
        printf("parse inter failed\n");
        goto EXIT;
    }
    HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_AddCertToStore(config, subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        goto EXIT;
    }
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL) {
        goto EXIT;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Connect failed: 0x%x\n", ret);
        goto EXIT;
    }

    const uint8_t sndBuf[] = "RFC9150 client hello\n";
    uint32_t writeLen = 0;
    ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Write failed: 0x%x\n", ret);
        goto EXIT;
    }

    uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Read failed: 0x%x\n", ret);
        goto EXIT;
    }
    printf("from server (%u bytes): %s\n", readLen, readBuf);
    exitValue = 0;

EXIT:
    if (ctx != NULL) {
        HITLS_Close(ctx);
        HITLS_Free(ctx);
    }
    HITLS_CFG_FreeConfig(config);
    if (fd >= 0) {
        close(fd);
    }
    HITLS_X509_CertFree(rootCA);
    HITLS_X509_CertFree(subCA);
    BSL_UIO_Free(uio);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return exitValue;
}
