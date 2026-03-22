#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "crypt_eal_rand.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_cert.h"
#include "hitls_crypt_init.h"
#include "crypt_errno.h"
#include "bsl_log.h"

#define CERTS_PATH      "assets/tlcp_sm2/"
#define HTTP_BUF_MAXLEN (18 * 1024) /* 18KB */

static int32_t HiTLSInit()
{
    // Registration certificate, crypto callback
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init: error code is %x\n", ret);
        return -1;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    return 0;
}

int main(int32_t argc, char *argv[])
{
    int32_t exitValue = -1;
    int32_t ret = 0;
    int32_t port = 12345;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int fd = 0;

    (void)argc;
    (void)argv;

    if (HiTLSInit() != 0) {
        goto EXIT;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("Create socket failed.\n");
        goto EXIT;
    }
    int option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        close(fd);
        printf("setsockopt SO_REUSEADDR failed.\n");
        goto EXIT;
    }

    // Set the protocol and port number
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
        printf("connect failed.\n");
        goto EXIT;
    }

    config = HITLS_CFG_NewTLCPConfig();
    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config failed.\n");
        goto EXIT;
    }
    /* Load root certificate and intermediate certificate */
    {
        HITLS_CERT_X509 *rootCA = HITLS_CFG_ParseCert(config, (const uint8_t *)(CERTS_PATH "ca.der"),
            strlen(CERTS_PATH "ca.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
        HITLS_CERT_X509 *subCA = HITLS_CFG_ParseCert(config, (const uint8_t *)(CERTS_PATH "inter.der"),
            strlen(CERTS_PATH "inter.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
        if (rootCA == NULL || subCA == NULL) {
            printf("Parse verify certificates failed.\n");
            if (rootCA != NULL) {
                HITLS_CFG_FreeCert(config, rootCA);
            }
            if (subCA != NULL) {
                HITLS_CFG_FreeCert(config, subCA);
            }
            goto EXIT;
        }
        ret = HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
        if (ret == HITLS_SUCCESS) {
            ret = HITLS_CFG_AddCertToStore(config, subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
        }
        HITLS_CFG_FreeCert(config, rootCA);
        HITLS_CFG_FreeCert(config, subCA);
        if (ret != HITLS_SUCCESS) {
            printf("Add verify certificates to store failed.\n");
            goto EXIT;
        }
    }
    // Load signature certificate
    HITLS_CERT_X509 *signCert = NULL;
    HITLS_CERT_X509 *signPkey = NULL;
    signCert = HITLS_CFG_ParseCert(config, (const uint8_t *)(CERTS_PATH "sign.der"),
        strlen(CERTS_PATH "sign.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    if (signCert == NULL) {
        printf("Parse signCert failed.\n");
        goto EXIT;
    }
    signPkey = HITLS_CFG_ParseKey(config, (const uint8_t *)(CERTS_PATH "sign.key.der"),
        strlen(CERTS_PATH "sign.key.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    if (signPkey == NULL) {
        printf("Parse signPkey failed.\n");
        goto EXIT;
    }
    HITLS_CFG_SetTlcpCertificate(config, signCert, false, false);
    HITLS_CFG_SetTlcpPrivateKey(config, signPkey, false, false);

    // Load encryption certificate
    HITLS_CERT_X509 *encCert = NULL;
    HITLS_CERT_X509 *encPkey = NULL;
    encCert = HITLS_CFG_ParseCert(config, (const uint8_t *)(CERTS_PATH "enc.der"),
        strlen(CERTS_PATH "enc.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    if (encCert == NULL) {
        printf("Parse encCert failed.\n");
        goto EXIT;
    }
    encPkey = HITLS_CFG_ParseKey(config, (const uint8_t *)(CERTS_PATH "enc.key.der"),
        strlen(CERTS_PATH "enc.key.der"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    if (encPkey == NULL) {
        printf("Parse encPkey failed.\n");
        goto EXIT;
    }
    HITLS_CFG_SetTlcpCertificate(config, encCert, false, true);
    HITLS_CFG_SetTlcpPrivateKey(config, encPkey, false, true);

    /* Create a new openHiTLS ctx */
    ctx = HITLS_New(config);
    if (ctx == NULL) {
        printf("HITLS_New failed.\n");
        goto EXIT;
    }

    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL) {
        printf("BSL_UIO_New failed.\n");
        goto EXIT;
    }

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd);
    if (ret != HITLS_SUCCESS) {
        printf("BSL_UIO_SET_FD failed, fd = %u.\n", fd);
        goto EXIT;
    }

    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_SetUio failed. ret = 0x%x.\n", ret);
        goto EXIT;
    }

    /* To establish a TLS connection, users need to consider the return value based on the actual scenario */
    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Connect failed, ret = 0x%x.\n", ret);
        goto EXIT;
    }

    /* Sending messages to the other end, users need to consider the return value according to the actual scenario */
    const uint8_t sndBuf[] = "Hi, this is tlcp client\n";
    uint32_t writeLen = 0;
    ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Write error:error code:%d\n", ret);
        goto EXIT;
    }

    /* Read the message from the other end, and the user needs to consider the return value according to the actual
        scenario */
    uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Read failed, ret = 0x%x.\n", ret);
        goto EXIT;
    }

    printf("get from server size:%u :%s\n", readLen, readBuf);

    exitValue = 0;
EXIT:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    close(fd);
    BSL_UIO_Free(uio);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return exitValue;
}
