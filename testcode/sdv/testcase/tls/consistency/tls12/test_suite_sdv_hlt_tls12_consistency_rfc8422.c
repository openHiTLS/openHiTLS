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
/* INCLUDE_BASE test_suite_tls12_consistency_rfc5246 */

#include <stdio.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "cert.h"
#include "securec.h"
#include "conn_init.h"
/* END_HEADER */

#define g_uiPort 12121
/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCY_ECDHE_ECDSA_FUNC_TC001
* @title    ECDHE_ECDSA requires an ECDSA certificate
* @precon nan
* @brief    Set the cipher suite to ECDHE_ECDSA and the certificate to ECDSA. The expected connection setup success is
*            expected.
* @expect   1. A success message is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_ECDHE_ECDSA_FUNC_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");
    HLT_SetClientVerifySupport(serverCtxConfig, true);

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    // Set the cipher suite to ECDHE_ECDSA and the certificate to ECDSA.
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1");
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCY_ECDHE_ECDSA_FUNC_TC002
* @title ECDHE_ECDSA requires an ECDSA certificate
* @precon nan
* @brief  Set the algorithm set to ECDHE_ECDSA and the certificate to the RSA certificate, Expected chain building
*          failure
* @expect 1. A failure message is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_ECDHE_ECDSA_FUNC_TC002(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(serverCtxConfig, true);

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    // Set the algorithm set to ECDHE_ECDSA and the certificate to the RSA certificate,
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1");
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCY_CURVE_AND_AUTH_FUNC_TC001
* @title    When the server selects the ECC cipher suite, the extension of the client must be considered for key
exchange and certificate.
* @precon nan
* @brief    1. Set the curve secp256r1 and secp384r1 on the client and server, set the certificate curve secp384r1 on
*            the server, and set the ECC cipher suite. It is expected that the certificate is loaded successfully.
*           Set serverkeyexchange to secp256r1, and the connection is set up successfully.
* @expect   1. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_CURVE_AND_AUTH_FUNC_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384");

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384");
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384");
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientCtxConfig, NULL);
    /* 1. Set the curve secp256r1 and secp384r1 on the client and server, set the certificate curve secp384r1 on
     *   the server, and set the ECC cipher suite. It is expected that the certificate is loaded successfully.
     *  Set serverkeyexchange to secp256r1 */
    int ret = HLT_TlsConnect(clientRes->ssl);
    ASSERT_TRUE(ret == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS12_RFC8422_CONSISTENCY_CURVE_AND_AUTH_FUNC_TC002
* @spec  -
* @title When the server selects the ECC cipher suite, both the key exchange and certificate must comply with the
*         extension of the client.
* @precon nan
* @brief  1. Set the curve secp256r1 on the client and server, set the certificate curve secp384r1, and set the ECC
*            cipher suite. The certificate is loaded successfully.
*          Set the serverkeyexchange parameter is set to secp256r1, the connection fails to be established.
* @expect 1. Connect establishment fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_CURVE_AND_AUTH_FUNC_TC002(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384");

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384");
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384");
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientCtxConfig, NULL);
    /* Set the curve secp256r1 on the client and server, set the certificate curve secp384r1, and set the ECC
     *  cipher suite. */
    int ret = HLT_TlsConnect(clientRes->ssl);
    ASSERT_TRUE(ret != 0);
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

static void Test_SetCipherSuites_With_Link(CipherInfo serverCipher, CipherInfo clientCipher, bool expectSuccess)
{
    int ret;
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *client_remote = NULL;
    HLT_Process *server_local = NULL;

    server_local = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(server_local != NULL);
    client_remote = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, false);
    ASSERT_TRUE(client_remote != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetCipherSuites(serverCtxConfig, serverCipher.cipher);
    HLT_SetGroups(serverCtxConfig, serverCipher.groups);
    HLT_SetSignature(serverCtxConfig, serverCipher.signAlg);
    TestSetCertPath(serverCtxConfig, serverCipher.signAlg);
    serverRes = HLT_ProcessTlsAccept(server_local, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetCipherSuites(clientCtxConfig, clientCipher.cipher);
    HLT_SetGroups(clientCtxConfig, clientCipher.groups);
    HLT_SetSignature(clientCtxConfig, clientCipher.signAlg);

    TestSetCertPath(clientCtxConfig, clientCipher.signAlg);

    clientRes = HLT_ProcessTlsConnect(client_remote, TLS1_2, clientCtxConfig, NULL);
    if (expectSuccess) {
        ASSERT_TRUE(clientRes != NULL);
    } else {
        ASSERT_TRUE(clientRes == NULL);
        goto EXIT;
    }
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    ASSERT_TRUE(HLT_ProcessTlsWrite(server_local, serverRes, (uint8_t *)"Hello", strlen("Hello")) == 0);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    ret = HLT_ProcessTlsRead(client_remote, clientRes, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(readLen == strlen("Hello"));
    ASSERT_TRUE(memcmp("Hello", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
}

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC001
* @title One configuration, the configuration algorithm suite at both ends is the same,
*        and the negotiation behavior is verified
* @precon nan
* @brief  1. Set the cipher suite to HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 at both ends.Expected result 1 is obtained.
* @expect 1. The negotiation is expected to succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC001()
{
    /* 1. Set the cipher suite to HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 at both ends. */
    CipherInfo clientCipher = {.cipher = "HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        .groups = "HITLS_EC_GROUP_SECP384R1",
        .signAlg = "CERT_SIG_SCHEME_RSA_PKCS1_SHA256",
        .cert = "rsa_sha256"};
    CipherInfo serverCipher = {.cipher = "HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        .groups = "HITLS_EC_GROUP_SECP384R1",
        .signAlg = "CERT_SIG_SCHEME_RSA_PKCS1_SHA256",
        .cert = "rsa_sha256"};
    Test_SetCipherSuites_With_Link(serverCipher, clientCipher, true);
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC002
* @title One configuration, the cipher suites configured at both ends are the same, and the negotiation behavior is
*          verified
* @precon nan
* @brief 1. Set the cipher suite to HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 at both ends.
*           Expected result 1 is obtained.
* @expect 1. The negotiation is expected to succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC002()
{
    CipherInfo clientCipher = {.cipher = "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        .groups = "HITLS_EC_GROUP_SECP256R1",
        .signAlg = "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
        .cert = "ecdsa_sha256"};
    CipherInfo serverCipher = {.cipher = "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        .groups = "HITLS_EC_GROUP_SECP256R1",
        .signAlg = "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
        .cert = "ecdsa_sha256"};
    Test_SetCipherSuites_With_Link(serverCipher, clientCipher, true);
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC003
* @title One configuration, the cipher suites configured at both ends are the same, and the negotiation behavior is
*        verified.
* @precon nan
* @brief  1. Set the cipher suite to HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA at both ends.Expected result 1 is obtained.
* @expect 1. The negotiation is expected to succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC003()
{
    // 1. Set the cipher suite to HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA at both ends.
    CipherInfo clientCipher = {.cipher = "HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        .groups = "HITLS_EC_GROUP_SECP256R1",
        .signAlg = "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
        .cert = "ecdsa_sha256"};
    CipherInfo serverCipher = {.cipher = "HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        .groups = "HITLS_EC_GROUP_SECP256R1",
        .signAlg = "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
        .cert = "ecdsa_sha256"};
    Test_SetCipherSuites_With_Link(serverCipher, clientCipher, true);
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC004
* @title  One configuration,the cipher suites configured at both ends are the same, and the negotiation behavior is
*         verified.
* @precon nan
* @brief  1. Set the cipher suite to HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA at both ends.Expected result 1 is obtained.
* @expect 1. The negotiation is expected to succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCY_SET_CIPHERSUITES_FUNC_TC004()
{
    // 1. Set the cipher suite to HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA at both ends.
    CipherInfo clientCipher = {.cipher = "HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        .groups = "HITLS_EC_GROUP_SECP256R1",
        .signAlg = "CERT_SIG_SCHEME_RSA_PKCS1_SHA256",
        .cert = "rsa_sha256"};
    CipherInfo serverCipher = {.cipher = "HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        .groups = "HITLS_EC_GROUP_SECP256R1",
        .signAlg = "CERT_SIG_SCHEME_RSA_PKCS1_SHA256",
        .cert = "rsa_sha256"};
    Test_SetCipherSuites_With_Link(serverCipher, clientCipher, true);
}
/* END_CASE */
static void MalformedClientHelloMsgCallback(void *msg, void *userData)
{
    //  2. Obtain the message, modify the field content, and send the message.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->pointFormats.exDataLen.data = 1;
    clientHello->pointFormats.exData.state = MISSING_FIELD;
EXIT:
    return;
}

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCYECDHE_ERR_POINT_FUNC_TC001
* @title    Set the ECC cipher suite.Before the server receives the client hello message, the extended value of the
*           point format is changed to 1. As a result, the negotiation on the server is expected to fail.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server.Expected result 1 is
*              obtained.
*           2. Obtain the message, modify the field content, and send the message.(Expected result 2)
*           3. Check the status of the tested end.Expected result 3 is obtained.
*           4. Check the status of the test end.Expected result 4 is obtained.
* @expect   1. A success message is returned.
*           2. A success message is returned .
*           3. The tested end returns an alert message, and the status is alerted.
*           4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
*              message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCYECDHE_ERR_POINT_FUNC_TC001(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;

    handle.frameCallBack = MalformedClientHelloMsgCallback;
    TestPara testPara = {0};
    testPara.port = g_uiPort;
    //  4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    //  3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedServerHelloMsgCallback(void *msg, void *userData)
{
    // 2. Obtain the message, modify the field content, and send the message.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;
    serverHello->pointFormats.exState = INITIAL_FIELD;
    serverHello->pointFormats.exType.state = INITIAL_FIELD;
    serverHello->pointFormats.exType.data = HS_EX_TYPE_POINT_FORMATS;
    uint8_t data[] = {0};
    FRAME_ModifyMsgArray8(data, sizeof(data), &serverHello->pointFormats.exData, &serverHello->pointFormats.exDataLen);
    serverHello->pointFormats.exLen.state = INITIAL_FIELD;
    serverHello->pointFormats.exLen.data = serverHello->pointFormats.exDataLen.data + sizeof(uint8_t);
    serverHello->pointFormats.exDataLen.data = 1;
    serverHello->pointFormats.exData.state = MISSING_FIELD;
EXIT:
    return;
}

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCYECDHE_ERR_POINT_FUNC_TC002
* @title    uses the ECC cipher suite.During connection setup, the serverhello message carries the point format and the
*           point format is set to 1. The connection setup fails.
* @precon nan
* @brief    1. The tested end functions as the server and the tested end functions as the client.Expected result 1 is
*              obtained.
*           2. Obtain the message, modify the field content, and send the message.(Expected result 2)
*           3. Check the status of the tested end.Expected result 3 is obtained.
*           4. Check the status of the test end.Expected result 4 is obtained.
* @expect   1. A success message is returned.
*           2. A success message is returned
*           3. The tested end returns an alert message, indicating that the status is alerted.
*           4. The status of the tested end is alerted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCYECDHE_ERR_POINT_FUNC_TC002(void)
{
    HLT_FrameHandle handle = {0};
    handle.userData = (void *)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    //  1. The tested end functions as the server and the tested end functions as the client.
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = MalformedServerHelloMsgCallback;
    TestPara testPara = {0};
    testPara.port = g_uiPort;
    testPara.emsMode = HITLS_EMS_MODE_FORCE;
    // 4. The status of the tested end is alerted.
    testPara.expectHsState = TRY_RECV_CLIENT_KEY_EXCHANGE;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ServerSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedNoCurveExternsionCallback(void *msg, void *userData)
{
    // 2. Modify the client to send a client hello message and remove the elliptic curve extension.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->supportedGroups.exState = MISSING_FIELD;
    clientHello->supportedGroups.exData.state = MISSING_FIELD;
    clientHello->supportedGroups.exDataLen.state = MISSING_FIELD;
    clientHello->supportedGroups.exLen.state = MISSING_FIELD;
    clientHello->supportedGroups.exType.state = MISSING_FIELD;
EXIT:
    return;
}

/** @
* @test SDV_TLS_TLS12_RFC8422_CONSISTENCYECDHE_ECDHE_LOSE_CURVE_FUNC_TC001
* @title: Configure the ECC cipher suite and remove the elliptic curve extension before the server receives the client
*        hello message.As a result,the connection establishment fails.
* @precon nan
* @brief     1. The server stops receiving client Hello messages.Expected result 1 is obtained
*            2. Modify the client to send a client hello message and remove the elliptic curve extension.Expected result
*                2 is obtained.
*            3. The server continues to establish a connection.(Expected result 3)
* @expect    1. Success
*            2. Success
*            3. A decryption failure message is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC8422_CONSISTENCYECDHE_ECDHE_LOSE_CURVE_FUNC_TC001(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The server stops receiving client Hello messages.
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedNoCurveExternsionCallback;
    TestPara testPara = {0};
    testPara.port = g_uiPort;
    testPara.emsMode = HITLS_EMS_MODE_FORCE;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. The server continues to establish a connection.
    testPara.expectDescription = ALERT_HANDSHAKE_FAILURE;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
