#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
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
#include "bsl_log.h"

#define CERTS_PATH      "../../../testcode/testdata/tls/certificate/der/sm2_with_userid/"
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
    int infd = 0;
    HITLS_X509_Cert *rootCA = NULL;
    HITLS_X509_Cert *subCA = NULL;
    HITLS_X509_Cert *serverCert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    if (HiTLSInit() != 0) {
        goto EXIT;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("Create socket failed.\n");
        return -1;
    }
    int option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        printf("setsockopt SO_REUSEADDR failed.\n");
        goto EXIT;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
        printf("bind failed.\n");
        goto EXIT;
    }
    if (listen(fd, 5) != 0) {
        printf("listen socket fail\n");
        goto EXIT;
    }

    struct sockaddr_in clientAddr;
    unsigned int len = sizeof(struct sockaddr_in);
    infd = accept(fd, (struct sockaddr *)&clientAddr, &len);
    if (infd < 0) {
        printf("accept failed.\n");
        goto EXIT;
    }

    config = HITLS_CFG_NewTLCPConfig();
    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config failed.\n");
        goto EXIT;
    }
    ret = HITLS_CFG_SetClientVerifySupport(config, false);  // disable peer verify
    if (ret != HITLS_SUCCESS) {
        printf("Disable peer verify faild.\n");
        goto EXIT;
    }

    /* Load root certificate and intermediate certificate */
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, CERTS_PATH "ca.crt", &rootCA);
    if (ret != HITLS_SUCCESS) {
        printf("Parse ca failed.\n");
        goto EXIT;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, CERTS_PATH "inter.crt", &subCA);
    if (ret != HITLS_SUCCESS) {
        printf("Parse subca failed.\n");
        goto EXIT;
    }
    HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_AddCertToStore(config, subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    // Load signature certificate
    HITLS_CERT_X509 *signCert = NULL;
    HITLS_CERT_X509 *signPkey = NULL;
    signCert = HITLS_CFG_ParseCert(config, CERTS_PATH "sign.crt",
        strlen(CERTS_PATH "sign.crt"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_PEM);
    if (signCert == NULL) {
        printf("Parse signCert failed.\n");
        goto EXIT;
    }
    signPkey = HITLS_CFG_ParseKey(config, CERTS_PATH "sign.key",
        strlen(CERTS_PATH "sign.key"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_PEM);
    if (signPkey == NULL) {
        printf("Parse signPkey failed.\n");
        goto EXIT;
    }
    HITLS_CFG_SetTlcpCertificate(config, signCert, TLS_PARSE_FORMAT_ASN1, false);
    HITLS_CFG_SetTlcpPrivateKey(config, signPkey, TLS_PARSE_FORMAT_ASN1, false);

    // Load encryption certificate
    HITLS_CERT_X509 *encCert = NULL;
    HITLS_CERT_X509 *encPkey = NULL;
    encCert = HITLS_CFG_ParseCert(config, CERTS_PATH "enc.crt",
        strlen(CERTS_PATH "enc.crt"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_PEM);
    if (encCert == NULL) {
        printf("Parse encCert failed.\n");
        goto EXIT;
    }
    encPkey = HITLS_CFG_ParseKey(config, CERTS_PATH "enc.key",
        strlen(CERTS_PATH "enc.key"), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_PEM);
    if (encPkey == NULL) {
        printf("Parse encPkey failed.\n");
        goto EXIT;
    }
    HITLS_CFG_SetTlcpCertificate(config, encCert, TLS_PARSE_FORMAT_ASN1, true);
    HITLS_CFG_SetTlcpPrivateKey(config, encPkey, TLS_PARSE_FORMAT_ASN1, true);

    /* Create a new openHiTLS ctx */
    ctx = HITLS_New(config);
    if (ctx == NULL) {
        printf("HITLS_New failed.\n");
        goto EXIT;
    }

    /* Users can implement methods as needed */
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL) {
        printf("BSL_UIO_New failed.\n");
        goto EXIT;
    }

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &infd);
    if (ret != HITLS_SUCCESS) {
        BSL_UIO_Free(uio);
        printf("BSL_UIO_SET_FD failed, fd = %u.\n", fd);
        goto EXIT;
    }

    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        BSL_UIO_Free(uio);
        printf("HITLS_SetUio failed. ret = 0x%x.\n", ret);
        goto EXIT;
    }

    /* To establish a TLS connection, users need to consider the return value based on the actual scenario */
    ret = HITLS_Accept(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Accept failed, ret = 0x%x.\n", ret);
        goto EXIT;
    }

    /* Sending messages to the other end, users need to consider the return value according to the actual scenario */
    uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Read failed, ret = 0x%x.\n", ret);
        goto EXIT;
    }
    printf("get from client size:%u :%s\n", readLen, readBuf);

    /* Read the message from the other end, and the user needs to consider the return value according to the actual
        scenario */
    const uint8_t sndBuf[] = "Hi, this is tlcp server\n";
    uint32_t writeLen = 0;
    ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Write error:error code:%d\n", ret);
        goto EXIT;
    }
    exitValue = 0;
EXIT:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    close(fd);
    close(infd);
    HITLS_X509_CertFree(rootCA);
    HITLS_X509_CertFree(subCA);
    HITLS_X509_CertFree(serverCert);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_UIO_Free(uio);
    return exitValue;
}