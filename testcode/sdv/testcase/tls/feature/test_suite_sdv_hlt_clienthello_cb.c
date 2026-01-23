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

/* BEGIN_HEADER */

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "helper.h"
#include "hitls.h"
#include "frame_tls.h"
#include "hitls_type.h"
#include "rec_wrapper.h"
#include "hs_ctx.h"
#include "tls.h"
#include "hitls_config.h"
#include "alert.h"

#define READ_BUF_LEN_18K (18 * 1024)
/* END_HEADER */
static uint32_t g_uiPort = 16888;
static uint32_t retry_count = 0;

int32_t client_hello_test_renegotiation_callback(HITLS_Ctx *ctx, int32_t *alert, void *arg)
{
    (void)arg;
    uint8_t verifyData[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataSize = 0;
    HITLS_GetFinishVerifyData(ctx, verifyData, sizeof(verifyData), &verifyDataSize);
    if (verifyDataSize != 0) {
        *alert = ALERT_NO_RENEGOTIATION;
        return HITLS_CLIENT_HELLO_FAILED;
    }
    HITLS_GetPeerFinishVerifyData(ctx, verifyData, sizeof(verifyData), &verifyDataSize);
    if (verifyDataSize != 0) {
        *alert = ALERT_NO_RENEGOTIATION;
        return HITLS_CLIENT_HELLO_FAILED;
    }
    return HITLS_CLIENT_HELLO_SUCCESS;
}

int32_t client_hello_callback(HITLS_Ctx *ctx, int32_t *alert, void *arg)
{
    (void)ctx;
    uint32_t *num = arg;
    *alert = ALERT_INTERNAL_ERROR;
    if ((*num)++ == 0) {
        return HITLS_CLIENT_HELLO_RETRY;
    }
    return HITLS_CLIENT_HELLO_SUCCESS;
}

int32_t full_client_hello_callback(HITLS_Ctx *ctx, int32_t *alert, void *arg)
{
    uint16_t *cipher;
    uint16_t cipherLen;
    uint16_t *exts;
    uint8_t extLen;
    uint8_t *random;
    uint8_t randomLen;
    uint8_t *extBuff;
    uint32_t extBuffLen;
    uint32_t *num = arg;
    const uint16_t expected_ciphers[] = {0xc02c, 0x00ff};
    const uint16_t expected_extensions[] = {13, 10, 11, 23, 22};
    *alert = ALERT_INTERNAL_ERROR;
    if (*num == 0) {
        return HITLS_CLIENT_HELLO_RETRY;
    }
    if (*num == 1) {
        return HITLS_CLIENT_HELLO_FAILED;
    }
    /* Make sure we can defer processing and get called back. */
    ASSERT_TRUE(HITLS_ClientHelloGetRandom(ctx, &random, &randomLen) == HITLS_SUCCESS);

    ASSERT_TRUE(random != NULL);
    ASSERT_TRUE(randomLen == 32);

    ASSERT_TRUE(HITLS_ClientHelloGetCiphers(ctx, &cipher, &cipherLen) == HITLS_SUCCESS);

    ASSERT_TRUE(cipher != NULL);
    ASSERT_TRUE(cipherLen != 0);
    // Compare expected_ciphers and cipher
    ASSERT_TRUE(cipherLen == sizeof(expected_ciphers) / sizeof(expected_ciphers[0]));

    ASSERT_EQ(memcmp(cipher, expected_ciphers, cipherLen * sizeof(uint16_t)), 0);

    ASSERT_TRUE(HITLS_ClientHelloGetExtensionsPresent(ctx, &exts, &extLen) == HITLS_SUCCESS);
    ASSERT_TRUE(exts != NULL);
    ASSERT_TRUE(extLen != 0);
    // Compare expected_extensions and exts
    ASSERT_TRUE(extLen == sizeof(expected_extensions) / sizeof(expected_extensions[0]));

    for (uint16_t i = 0; i < extLen; ++i) {
        ASSERT_TRUE(exts[i] == expected_extensions[i]);
    }
    BSL_SAL_FREE(exts);
    ASSERT_TRUE(HITLS_ClientHelloGetExtension(ctx, 13, &extBuff, &extBuffLen) == HITLS_SUCCESS);
    ASSERT_TRUE(extBuff != NULL);
    ASSERT_TRUE(extBuffLen != 0);
    return HITLS_CLIENT_HELLO_SUCCESS;
EXIT:
    return HITLS_CLIENT_HELLO_FAILED;
}

/**
 * @test SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC01
 * @title  Client Hello Callback Function Test Case 1
 * @precon  nan
 * @brief   Server sets the client hello callback function, and the client hello callback function
 *          return HITLS_CLIENT_HELLO_FAILED.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The server returns HITLS_CALLBACK_CLIENT_HELLO_ERROR.
 */
/* BEGIN_CASE */
void SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC01(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);
    int32_t flag = 1;
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ;
    HLT_SetClientHelloCb(serverCtxConfig, full_client_hello_callback, &flag);
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");

    ASSERT_TRUE(clientCtxConfig != NULL);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_CALLBACK_CLIENT_HELLO_ERROR);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * @test SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC02
 * @title  Client Hello Callback Function Test Case 2
 * @precon  nan
 * @brief   Server sets the client hello callback function, and the client hello callback function
 *          return HITLS_CLIENT_HELLO_SUCCESS.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The server returns HITLS_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC02(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);
    int32_t flag = 2;
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_SetClientHelloCb(serverCtxConfig, full_client_hello_callback, &flag);
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * @test SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC03
 * @title  Client Hello Callback Function Test Case 3
 * @precon  nan
 * @brief   Server sets the client hello callback function, and the client hello callback function
 *          return HITLS_CLIENT_HELLO_RETRY. The client hello callback function is called twice,
 *          and the second time it returns HITLS_CLIENT_HELLO_SUCCESS.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The server returns HITLS_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC03(int version)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    if (version == TLS1_2 || version == TLS1_3) {
        remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    } else {
        remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, g_uiPort, true);
    }
    ASSERT_TRUE(remoteProcess != NULL);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ;
    HLT_SetClientHelloCb(serverCtxConfig, client_hello_callback, &retry_count);
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_SUCCESS);
    ASSERT_EQ(retry_count, 2);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
    retry_count = 0;
}
/* END_CASE */

/**
 * @test SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC04
 * @title  Client Hello Callback Function Test Case 4
 * @precon  nan
 * @brief   Server sets the client hello callback function, and the client hello callback function
 *          return HITLS_CLIENT_HELLO_SUCCESS.
 *          On renegotiation, the client hello callback returns HITLS_CLIENT_HELLO_FAILED.
 *          The server supports renegotiation, and the client does not support renegotiation.
 *          establish a TLS connection between the client and server, expect result 1.
 *          server starts renegotiation, and the client hello callback function returns HITLS_CLIENT_HELLO_FAILED.
 *          expect result 2.
 * @expect  1. The link establishment is successful.
 *          2. The server returns ALERT_NO_RENEGOTIATION.
 */
/* BEGIN_CASE */
void SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC04(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ;
    HLT_SetClientHelloCb(serverCtxConfig, client_hello_test_renegotiation_callback, &retry_count);
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetRenegotiationSupport(serverCtxConfig, true);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetRenegotiationSupport(clientCtxConfig, true);
    HLT_SetLegacyRenegotiateSupport(clientCtxConfig, true);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_EQ(HITLS_Renegotiate(serverRes->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverRes->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen),
              HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, READ_BUF_LEN_18K, &readLen),
              HITLS_CALLBACK_CLIENT_HELLO_ERROR);

    ALERT_Info info = {0};
    ALERT_GetInfo(serverRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_NO_RENEGOTIATION);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * @test SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC05
 * @title  Client Hello Callback Function Test Case 5
 * @precon  nan
 * @brief   Server sets the client hello callback function, and the client hello callback function return
 *          HITLS_CLIENT_HELLO_RETRY.
 *          The client hello callback function is called three times, and the third time it returns
 *          HITLS_CLIENT_HELLO_SUCCESS.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The server returns HITLS_SUCCESS.
 *          2. The client hello callback function is called three times.
 *          3. The retry_count is 3.
 */
/* BEGIN_CASE */
void SDV_TLS_CLIENT_HELLO_CALLBACK_FUNC_TC05(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_SetClientHelloCb(serverCtxConfig, client_hello_callback, &retry_count);
    HLT_SetGroups(serverCtxConfig, "HITLS_EC_GROUP_SECP256R1");
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_CURVE25519:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1");
    ASSERT_TRUE(clientCtxConfig != NULL);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_SUCCESS);
    ASSERT_EQ(retry_count, 3);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
    retry_count = 0;
}
/* END_CASE */
