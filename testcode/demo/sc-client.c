/*
基于证书认证的DTLCP over sctp客户端
*/
#define HITLS_CRYPTO_EAL
#define HITLS_CRYPTO_CIPHER
#include <stdio.h> 
#include<string.h>
#include<unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h> 
#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <fcntl.h>
#include "bsl_sal.h" 
#include "bsl_err.h" 
#include "bsl_errno.h"
#include "bsl_log.h"
#include "hitls_error.h" 
#include "hitls_config.h" 
#include "hitls.h" 
#include "hitls_security.h"
#include "securec.h"
#include "hitls_pki_cert.h"
#include "hitls_cert.h"
#include "hitls_cert_init.h"

#include "hitls_crypt_init.h"

#include "crypt_eal_rand.h"
#include "crypt_eal_encode.h"
#define CERTS_PATH "../../testcode/testdata/tls/certificate/der/sm2_with_userid/"
#define HTTP_BUF_MAXLEN (18 * 1024) /* 18KB */

#define SUCCESS 0
#define ERROR (-1)

uint32_t ExampleClientCb(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen, uint8_t *psk,
    uint32_t maxPskLen)
{
    (void)ctx;
    (void)hint;
    int32_t ret;
    const char pskTrans[] = "psk data";
    uint32_t pskTransUsedLen = sizeof(pskTransUsedLen);
    if (memcpy_s(identity, maxIdentityLen, "hello", strlen("hello") + 1) != EOK) {
        return 0;
    }
    if (memcpy_s(psk, maxPskLen, pskTrans, pskTransUsedLen) != EOK) {
        return 0;
    }
    return pskTransUsedLen;
}

int main(int32_t argc, char *argv[])
{
    int32_t exitValue = -1;
    int32_t ret = 0;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int fd = 0;
    HITLS_X509_Cert *rootCA = NULL;
    HITLS_X509_Cert *subCA = NULL;

    /* 注册BSL内存能力、仅供参考 */
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, malloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);
    BSL_ERR_Init();

    HITLS_CertMethodInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    HITLS_CryptMethodInit();

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("Create socket failed.\n");
        return -1;
    }
    int option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        close(fd);
        printf("setsockopt SO_REUSEADDR failed.\n");
        return -1;
    }

    // Set the protocol and port number
    struct sockaddr_in serverAddr;
    (void)memset_s(&serverAddr, sizeof(serverAddr), 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
        printf("connect failed.\n");
        goto EXIT;
    }

    config = HITLS_CFG_NewTLCPConfig();//config = HITLS_CFG_NewTLS12Config();
    if (config == NULL) {
        printf("HITLS_CFG_NewTLCPConfig failed.\n");
        goto EXIT;
    }

    ret = HITLS_CFG_SetCheckKeyUsage(config, false); // disable cert keyusage check
    if (ret != HITLS_SUCCESS) {
        printf("Disable check KeyUsage failed.\n");
        goto EXIT;
    }

    uint16_t cipherSuite = HITLS_ECDHE_SM4_GCM_SM3;
	// 配置算法套
    if (HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1) != HITLS_SUCCESS) {
        printf("HITLS_CFG_SetCipherSuites err\n");
        return -1;
    }

    // ca and inter
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "ca.der", &rootCA);
    if (ret != HITLS_SUCCESS) {
        printf("Parse ca failed.\n");
        goto EXIT;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "inter.der", &subCA);
    if (ret != HITLS_SUCCESS) {
        printf("Parse subca failed.\n");
        goto EXIT;
    }
    HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_AddCertToStore(config, subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);

    // 从文件中加载加密证书和私钥
    HITLS_X509_Cert *signCert = NULL;
    HITLS_CERT_Key *signKey = NULL;
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "sign.der", &signCert);
    if (ret != HITLS_SUCCESS) {
        printf("Parse ca failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_ECC, 
    CERTS_PATH "sign.key.der", NULL, 0, (CRYPT_EAL_PkeyCtx **)&signKey);
    if (ret != HITLS_SUCCESS) {
        printf("Parse subca failed.\n");
        goto EXIT;
    }

    HITLS_X509_Cert *encCert = NULL;
    HITLS_CERT_Key *encKey = NULL;
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "enc.der", &encCert);
    if (ret != HITLS_SUCCESS) {
        printf("Parse ca failed.\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_ECC, CERTS_PATH "enc.key.der", 
        NULL, 0, (CRYPT_EAL_PkeyCtx **)&encKey);
    if (ret != HITLS_SUCCESS) {
        printf("Parse ca failed.\n");
        goto EXIT;
    }

    ret = HITLS_CFG_SetTlcpCertificate(config, signCert, false, false);
    printf("Set tlcp error=0x%x\n", ret);
    ret = HITLS_CFG_SetTlcpPrivateKey(config, signKey, false, false);
    printf("Set tlcp error=0x%x\n", ret);
    //设置添加国密加密证书和私钥
    ret = HITLS_CFG_SetTlcpCertificate(config, encCert, false, true);
    printf("Set tlcp error=0x%x\n", ret);
    ret = HITLS_CFG_SetTlcpPrivateKey(config, encKey, false, true);
    printf("Set tlcp error=0x%x\n", ret);
    /*ret = HITLS_CFG_SetVerifyNoneSupport(config, true);  // disable peer verify
    if (ret != HITLS_SUCCESS) {
        printf("Disable peer verify faild.\n");
        goto EXIT;
    }*/

    //uint8_t psk[] = "12121212121212";
    //memcpy_s(config->psk, 256, psk, sizeof(psk));
    //config->securitylevel = 0;
 

    /* 新建openHiTLS上下文 */
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

    /* 进行TLS连接、用户需按实际场景考虑返回值 */
    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Connect failed, ret = 0x%x.\n", ret);
        goto EXIT;
    }

    /* 向对端发送报文、用户需按实际场景考虑返回值 */
    const uint8_t sndBuf[] = "Hi, this is client\n";
    uint32_t writeLen = 0;
    ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Write error:error code:%d\n", ret);
        goto EXIT;
    }

    /* 读取对端报文、用户需按实际场景考虑返回值 */
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
    HITLS_X509_CertFree(rootCA);
    HITLS_X509_CertFree(subCA);
    BSL_UIO_Free(uio);
    return exitValue;
}