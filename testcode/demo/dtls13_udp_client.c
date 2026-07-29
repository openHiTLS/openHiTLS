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
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bsl_err.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls.h"
#include "hitls_dtls_cid.h"
#include "hitls_cert.h"
#include "hitls_cert_init.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
#include "hitls_error.h"
#include "hitls_pki_cert.h"

#define CERTS_PATH "../../../testcode/testdata/tls/certificate/der/ecdsa_sha256/"
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 12345
#define DEMO_BUF_SIZE 2048
#define KEYLOG_FILE "key.log"

static const char *LogLevelStr(uint32_t level)
{
    switch (level) {
        case BSL_LOG_LEVEL_SEC:
            return "SEC";
        case BSL_LOG_LEVEL_FATAL:
            return "FATAL";
        case BSL_LOG_LEVEL_ERR:
            return "ERR";
        case BSL_LOG_LEVEL_WARN:
            return "WARN";
        case BSL_LOG_LEVEL_INFO:
            return "INFO";
        case BSL_LOG_LEVEL_DEBUG:
            return "DEBUG";
        default:
            return "UNKNOWN";
    }
}

static void DemoBinLogFixLen(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    fprintf(stderr, "[BINLOG][%s][id=%u][type=0x%x] ", LogLevelStr(logLevel), logId, logType);
    if (format != NULL) {
        fprintf(stderr, (const char *)format, para1, para2, para3, para4);
    }
    fprintf(stderr, "\n");
}

static void DemoBinLogVarLen(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para)
{
    fprintf(stderr, "[BINLOG][%s][id=%u][type=0x%x] ", LogLevelStr(logLevel), logId, logType);
    if (format != NULL && para != NULL) {
        fprintf(stderr, (const char *)format, (const char *)para);
    } else if (format != NULL) {
        fprintf(stderr, "%s", (const char *)format);
    }
    fprintf(stderr, "\n");
}

static void DemoErrStackLog(uint64_t threadId, const char *file, uint32_t lineNo, int32_t errCode, bool mark)
{
    fprintf(stderr, "[ERRSTACK][tid=%llu][%s:%u][mark=%d] err=0x%x\n",
        (unsigned long long)threadId, (file != NULL) ? file : "", lineNo, mark ? 1 : 0, errCode);
}

static void RegisterDemoLog(void)
{
    BSL_LOG_BinLogFuncs funcs = {
        .fixLenFunc = DemoBinLogFixLen,
        .varLenFunc = DemoBinLogVarLen,
    };
    (void)BSL_LOG_RegBinLogFunc(&funcs);
    (void)BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG);
    BSL_ERR_RegErrStackLog(DemoErrStackLog);
}

static void DemoKeyLogCb(HITLS_Ctx *ctx, const char *line)
{
    (void)ctx;
    if (line == NULL) {
        return;
    }
    FILE *fp = fopen(KEYLOG_FILE, "a");
    if (fp == NULL) {
        fprintf(stderr, "open %s failed for key log\n", KEYLOG_FILE);
        return;
    }
    (void)fprintf(fp, "%s\n", line);
    (void)fclose(fp);
}

static int32_t HiTLSInit(void)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed, ret = 0x%x\n", ret);
        return ret;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    RegisterDemoLog();
    return HITLS_SUCCESS;
}

static int32_t LoadClientTrustStore(HITLS_Config *config, HITLS_X509_Cert **rootCA, HITLS_X509_Cert **subCA)
{
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "ca.der", rootCA);
    if (ret != HITLS_SUCCESS) {
        printf("Parse ca failed, ret = 0x%x\n", ret);
        return ret;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "inter.der", subCA);
    if (ret != HITLS_SUCCESS) {
        printf("Parse inter ca failed, ret = 0x%x\n", ret);
        return ret;
    }
    ret = HITLS_CFG_AddCertToStore(config, *rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    if (ret != HITLS_SUCCESS) {
        printf("Add root ca failed, ret = 0x%x\n", ret);
        return ret;
    }
    ret = HITLS_CFG_AddCertToStore(config, *subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    if (ret != HITLS_SUCCESS) {
        printf("Add inter ca failed, ret = 0x%x\n", ret);
    }
    return ret;
}

static int32_t SetupUdpUio(BSL_UIO **uio, int32_t fd, const struct sockaddr_in *peer)
{
    *uio = BSL_UIO_New(BSL_UIO_UdpMethod());
    if (*uio == NULL) {
        printf("BSL_UIO_New UDP failed.\n");
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret = BSL_UIO_Ctrl(*uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd);
    if (ret != HITLS_SUCCESS) {
        printf("BSL_UIO_SET_FD failed, ret = 0x%x\n", ret);
        return ret;
    }

    ret = BSL_UIO_Ctrl(*uio, BSL_UIO_SET_PEER_IP_ADDR, (int32_t)sizeof(*peer), (void *)peer);
    if (ret != HITLS_SUCCESS) {
        printf("BSL_UIO_SET_PEER_IP_ADDR failed, ret = 0x%x\n", ret);
    }
    return ret;
}

int main(int32_t argc, char *argv[])
{
    const char *host = (argc > 1) ? argv[1] : DEFAULT_HOST;
    uint16_t port = (argc > 2) ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;

    int32_t exitValue = -1;
    int32_t fd = -1;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    HITLS_X509_Cert *rootCA = NULL;
    HITLS_X509_Cert *subCA = NULL;

    if (HiTLSInit() != HITLS_SUCCESS) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("Create UDP socket failed.\n");
        goto EXIT;
    }

    struct sockaddr_in serverAddr;
    (void)memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &serverAddr.sin_addr) != 1) {
        printf("Invalid server address: %s\n", host);
        goto EXIT;
    }

    config = HITLS_CFG_NewDTLS13Config();
    if (config == NULL) {
        printf("HITLS_CFG_NewDTLS13Config failed.\n");
        goto EXIT;
    }

    int32_t ret = HITLS_CFG_SetCheckKeyUsage(config, false);
    if (ret != HITLS_SUCCESS) {
        printf("Disable check KeyUsage failed, ret = 0x%x\n", ret);
        goto EXIT;
    }
    ret = HITLS_CFG_SetKeyLogCb(config, DemoKeyLogCb);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_CFG_SetKeyLogCb failed, ret = 0x%x\n", ret);
        goto EXIT;
    }

    ret = LoadClientTrustStore(config, &rootCA, &subCA);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    /* Enable CID negotiation for E2E verification (config-level, before HITLS_New) */
    ret = HITLS_CFG_SetDtlsCidSupport(config, true);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_CFG_SetDtlsCidSupport failed, ret = 0x%x\n", ret);
        goto EXIT;
    }

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        printf("HITLS_New failed.\n");
        goto EXIT;
    }

    static const uint8_t clientCid[] = {0x01, 0x02, 0x03, 0x04};
    ret = HITLS_SetDtlsRecvCid(ctx, clientCid, sizeof(clientCid));
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_SetDtlsRecvCid failed, ret = 0x%x\n", ret);
        goto EXIT;
    }

    ret = SetupUdpUio(&uio, fd, &serverAddr);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_SetUio failed, ret = 0x%x\n", ret);
        goto EXIT;
    }

    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Connect failed, ret = 0x%x\n", ret);
        BSL_ERR_OutputErrorStack();
        goto EXIT;
    }
    printf("DTLS 1.3 UDP client connected to %s:%u\n", host, port);

    /* Report CID negotiation state */
    bool isCidNeg = false;
    HITLS_GetDtlsIsCidNegotiated(ctx, &isCidNeg);
    printf("CID negotiated: %s\n", isCidNeg ? "yes" : "no");
    if (isCidNeg) {
        HITLS_DtlsCidEntry sendEntries[4];
        uint8_t sendCount = 4;
        if (HITLS_GetDtlsSendCid(ctx, sendEntries, &sendCount) == HITLS_SUCCESS && sendCount > 0) {
            printf("Client send CID (len=%u): ", sendEntries[0].cidLen);
            for (uint8_t i = 0; i < sendEntries[0].cidLen; i++) {
                printf("%02x", sendEntries[0].cidVal[i]);
            }
            printf("\n");
        }
    }

    const uint8_t sndBuf[] = "Hi, this is DTLS 1.3 UDP client\n";
    uint32_t writeLen = 0;
    ret = HITLS_Write(ctx, sndBuf, (uint32_t)strlen((const char *)sndBuf), &writeLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Write failed, ret = 0x%x\n", ret);
        BSL_ERR_OutputErrorStack();
        goto EXIT;
    }

    uint8_t readBuf[DEMO_BUF_SIZE + 1] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(ctx, readBuf, DEMO_BUF_SIZE, &readLen);
    if (ret != HITLS_SUCCESS) {
        printf("HITLS_Read failed, ret = 0x%x\n", ret);
        BSL_ERR_OutputErrorStack();
        goto EXIT;
    }
    readBuf[readLen] = '\0';
    printf("get from server size:%u: %s\n", readLen, readBuf);

    exitValue = 0;

EXIT:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    HITLS_X509_CertFree(rootCA);
    HITLS_X509_CertFree(subCA);
    BSL_UIO_Free(uio);
    if (fd >= 0) {
        close(fd);
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return exitValue;
}
