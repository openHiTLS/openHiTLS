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
/* INCLUDE_BASE test_suite_tls13_consistency_rfc8446 */

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
#include "rec_wrapper.h"
#include "cert.h"
#include "securec.h"
#include "process.h"
#include "conn_init.h"
#include "hitls_crypt_init.h"
#include "hitls_psk.h"
#include "common_func.h"
#include "alert.h"
#include "bsl_sal.h"
/* END_HEADER */
#define MAX_BUF 16384

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    HITLS_Config *s_config;
    HITLS_Config *c_config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
} ResumeTestInfo;

static int32_t DoHandshake(ResumeTestInfo *testInfo)
{
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);

    testInfo->client = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (testInfo->clientSession != NULL) {
        int32_t ret = HITLS_SetSession(testInfo->client->ssl, testInfo->clientSession);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
}
static void Test_PskGetCert(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    static uint8_t certBuf[MAX_BUF] = {0};
    static uint32_t bufLen = 0;
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    if (user != NULL) {  // cert message
        ASSERT_EQ(memcpy_s(certBuf, MAX_BUF, data, *len), EOK);
        bufLen = *len;
    } else {
        ASSERT_EQ(memcpy_s(data, bufSize, certBuf, bufLen), EOK);
        *len = bufLen;
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_CERT_FUNC_TC001
* @spec -
* When the @title psk session is resumed, the server sends the certificate message after sending the server hello
* message. The expected handshake fails.
* @precon nan
* @brief 2.2 Resumption and Pre-Shared Key line 7
* @expect 1. The expected handshake fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_CERT_FUNC_TC001()
{

    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();

    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, &wrapper, Test_PskGetCert};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);
    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    wrapper.ctrlState = TRY_SEND_FINISH;
    wrapper.userData = NULL;
    RegisterWrapper(wrapper);
    ASSERT_NE(DoHandshake(&testInfo), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC001
* @spec -
* @title Set the client and server to tls1.3. Set the cipher suites on the client and server to mismatch. As a result,
*           the expected connection establishment fails and a handshake_failure alert message is sent.
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation line 13
* @expect 1. Expected handshake failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC001()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    cipherSuite = HITLS_AES_256_GCM_SHA384;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_HANDSHAKE_FAILURE);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_PskGetCertReq(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    static uint8_t certBuf[READ_BUF_SIZE] = {0};
    static uint32_t bufLen = 0;
    (void)ctx;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    if (user != NULL) {  // cert message
        ASSERT_EQ(memcpy_s(certBuf, READ_BUF_SIZE, data, *len), EOK);
        bufLen = *len;
    } else {
        ASSERT_EQ(memcpy_s(data, bufSize, certBuf, bufLen), EOK);
        *len = bufLen;
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_CERTREQ_FUNC_TC001
* @spec -
* @title 1. Preset the PSK. After the server sends the encryption extension, construct the certficaterequest message and
*         observe the client behavior.
* @precon nan
* @brief 4.3.2. Certificate Request line 110
* @expect 1. The client sends an alert message and disconnects the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_CERTREQ_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.config->isSupportClientVerify = true;
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, &wrapper, Test_PskGetCertReq};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);
    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    wrapper.ctrlState = TRY_SEND_FINISH;
    wrapper.userData = NULL;
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC002
* @spec -
* @title Set the client and server to tls1.3. Set the group on the client and server to different values. If the
*         expected connection establishment fails, the handshake_failurealert message is sent.
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation line 13
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC002()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    HITLS_CFG_SetGroups(testInfo.config, &group, 1);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    group = HITLS_EC_GROUP_SECP384R1;
    HITLS_CFG_SetGroups(testInfo.config, &group, 1);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_HANDSHAKE_FAILURE);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC003
* @spec -
* @title Set the client server to tls1.3 and the server certificate does not match the signature algorithm specified by
*         the client. In this case, the connection establishment fails and a handshake_failure alert message is sent.
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation line 13
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC003()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t signature = CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256;
    HITLS_CFG_SetSignature(testInfo.config, &signature, 1);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    signature = CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384;
    HITLS_CFG_SetSignature(testInfo.config, &signature, 1);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_HANDSHAKE_FAILURE);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_ClientHelloMissKeyShare(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.keyshares.exState = MISSING_FIELD;
    frameMsg.body.hsMsg.body.clientHello.supportedGroups.exState = MISSING_FIELD;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    ASSERT_NE(parseLen, *len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC004
* @spec -
* @title Set the client server to tls1.3 and set the client psk mode to psk only. The provided psk server does not
*         support the psk. As a result, the connection fails to be established. Send handshake_failure alert
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation line 13
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC004()
{
    FRAME_Init();
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ClientHelloMissKeyShare};
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_HANDSHAKE_FAILURE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC005
* @spec -
* @title Set the client server to tls1.3 and set the psk mode of the client to psk only. No psk extension is provided.
 *        As a result, connection establishment fails. Send handshake_failure alert
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation line 13
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MISMATCH_FUNC_TC005()
{
    FRAME_Init();

    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ClientHelloMissKeyShare};
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_MISSING_EXTENSION);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_ErrorOrderPsk(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.extensionLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.length.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.pskModes.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    uint8_t pskMode[] = {0, 0x2d, 0, 2, 1, 1};  // psk with dhe mode
    ASSERT_NE(parseLen, *len);
    ASSERT_EQ(memcpy_s(&data[*len], bufSize - *len, &pskMode, sizeof(pskMode)), EOK);
    *len += sizeof(pskMode);
    ASSERT_EQ(parseLen, *len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC001
* @spec -
* @title Set the client server to tls1.3 and construct the clienthello pre_shared_key extension that is not the last.
*         The server is expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC001()
{
    FRAME_Init();
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ErrorOrderPsk};
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_RepeatClientHelloExtension(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FieldState *extensionState = GetDataAddress(&frameMsg, user);
    *extensionState = DUPLICATE_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    ASSERT_NE(parseLen, *len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void RepeatClientHelloExtension(void *memberAddress, bool isPsk)
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    if (isPsk) {
        uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
        HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
        HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_WITH_DHE);
        HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
        HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    }
    char serverName[] = "testServer";
    uint8_t alpn[6] = {4, '1', '2', '3', '4', 0};
    HITLS_CFG_SetServerName(testInfo.config, (uint8_t *)serverName, strlen(serverName));
    HITLS_CFG_SetAlpnProtos(testInfo.config, alpn, strlen((char *)alpn));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, memberAddress, Test_RepeatClientHelloExtension};
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC002
* @spec -
* @title The client server is tls1.3. Two signature algorithms are used to construct the clienthello. The server is
*         expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC002()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.signatureAlgorithms.exState, false);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC003
* @spec -
* @title The client server is tls1.3. Two supportedGroups are displayed in the clienthello. The server is expected to
*         return an alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC003()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.supportedGroups.exState, false);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC004
* @spec -
* @title The client server is tls1.3. Two pointFormats are displayed in the constructed clienthello. The server is
*         expected to return an alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC004()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.pointFormats.exState, false);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC005
* @spec -
* @title The client server is tls1.3. Two supportedVersion fields are displayed in the clienthello. The server is
         expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC005()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.supportedVersion.exState, false);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC006
* @spec -
* @title The client server is tls1.3. When two extendedMasterSecrets are displayed in the clienthello message, the
*        server is expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC006()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.extendedMasterSecret.exState, false);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC007
* @spec -
* @title The client server is tls1.3. Two pskModes are displayed in the clienthello. The server is expected to return an
*        alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC007()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.pskModes.exState, true);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC008
* @spec -
* @title The client server is tls1.3. Two keyshares are displayed when the clienthello is constructed. The server is
*         expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC008()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.keyshares.exState, false);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC009
* @spec -
* @title The client server is tls1.3. Two psks are displayed when the clienthello is constructed. The server is expected
*         to return an alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC009()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.psks.exState, true);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC010
* @spec -
* @title The client server is tls1.3. Two serverNames are displayed in the clienthello. The server is expected to return
*         alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC010()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.serverName.exState, false);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC011
* @spec -
* @title The client server is tls1.3. Two alpn extensions are displayed when the clienthello is constructed. The server is expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC011()
{
    RepeatClientHelloExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.alpn.exState, false);
}
/* END_CASE */

static void Test_RepeatServerHelloExtension(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    FieldState *extensionState = GetDataAddress(&frameMsg, user);
    *extensionState = DUPLICATE_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC012
* @spec -
* @title    The client server is tls1.3. Two supportedversion extensions are displayed when the serverhello is
*            constructed. The client is expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC012()
{

    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &((FRAME_Msg *)0)->body.hsMsg.body.serverHello.supportedVersion.exState,
        Test_RepeatServerHelloExtension};
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC013
* @spec -
* @title The client server is tls1.3. Two key_share extensions are displayed when the serverhello is constructed. The
*         client is expected to return alert.
* @precon nan
* @brief 4.2. Extensions line 40
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERR_HEELO_FUNC_TC013()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &((FRAME_Msg *)0)->body.hsMsg.body.serverHello.keyShare.exState,
        Test_RepeatServerHelloExtension};
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC002
* @spec -
* @title 1. Set the client to tls1.2 and the server to tls1.3. Initiate a connection establishment request. The expected
*           connection establishment is successful and the negotiated version is tls1.2.
* @precon nan
* @brief 4.2.1 Supported Versions line 42
* @expect 1. The expected connection setup is successful and the negotiated version is tls1.2.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC002()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.config = HITLS_CFG_NewTLS12Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint16_t version = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(testInfo.client->ssl, &version), HITLS_SUCCESS);
    ASSERT_EQ(version, HITLS_VERSION_TLS12);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_ErrLegacyVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.version.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.version.data = HITLS_VERSION_TLS13;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC003
* @spec -
* @title 1. Set the client to tls1.2 and server to tls1.3, initiate a connection establishment request, change the
*         version value in the client hello message to 0x0304, and expect the server to stop handshake.
* @precon nan
* @brief 4.2.1 Supported Versions line 42
* @expect 1. Expected connection establishment failure
@ */

/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC003()
{
    FRAME_Init();
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ErrLegacyVersion};
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.config = HITLS_CFG_NewTLS12Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl->negotiatedInfo.version == HITLS_VERSION_TLS12);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC004
* @spec -
* @title 1. Set the client to support TLS1.1 and TLS1.0 and the server to support TLS1.3. Initiate a connection
*          establishment request. The server is expected to negotiate TLS1.3.
* @precon nan
* @brief 4.2.1 Supported Versions line 43
* @expect 1. The expected connection setup is successful and the negotiated version is tls1.3.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC004()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint16_t version = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(testInfo.client->ssl, &version), HITLS_SUCCESS);
    ASSERT_EQ(version, HITLS_VERSION_TLS13);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_UnknownVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientHello.supportedVersion.exData.data);
    uint16_t version[] = { 0x01, 0x02, *(uint16_t *)user };
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exData.data =
        BSL_SAL_Calloc(sizeof(version) / sizeof(uint16_t), sizeof(uint16_t));
    ASSERT_EQ(memcpy_s(frameMsg.body.hsMsg.body.clientHello.supportedVersion.exData.data,
        sizeof(version), version, sizeof(version)), EOK);
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exData.size = sizeof(version) / sizeof(uint16_t);
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exData.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exDataLen.data = sizeof(version);
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exLen.data = sizeof(version) + sizeof(uint8_t);
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC005
* @spec -
* @title 1. Set the client server to tls1.3 and modify the supportedversion field in the client hello packet,
*            An invalid version number 0x0001,0x0002 is added before tils1.3. It is expected that the server can
*            negotiate the TLS1.3 version.
* @precon nan
* @brief 4.2.1 Supported Versions line 43
* @expect 1. The expected connection setup is successful and the negotiated version is tls1.3.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC005()
{
    FRAME_Init();
    uint16_t version = HITLS_VERSION_TLS13;
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, &version, Test_UnknownVersion};
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    version = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(testInfo.client->ssl, &version), HITLS_SUCCESS);
    ASSERT_EQ(version, HITLS_VERSION_TLS13);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC006
* @spec -
* @title 1. Configure the TLS1.2 client and TLS1.3 server, and construct the clienthello message that carries the
*            supportedversion extension. If the value is 0x0303 and 0x0302, the server negotiates TLS1.2 normally and
*            the handshake succeeds.
* @precon nan
* @brief 4.2.1 Supported Versions line 44
* @expect 1. The expected connection setup is successful and the negotiated version is tls1.2.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC006()
{
    FRAME_Init();
    uint16_t version = HITLS_VERSION_TLS12;
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &version,
        Test_UnknownVersion
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.config = HITLS_CFG_NewTLS12Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    version = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(testInfo.client->ssl, &version), HITLS_SUCCESS);
    ASSERT_EQ(version, HITLS_VERSION_TLS12);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_ServerVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    if (*(uint16_t *)user == 0) {
        ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.supportedVersion.exState, MISSING_FIELD);
    } else if (*(uint16_t *)user == HITLS_VERSION_TLS13) {
        ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.version.data, HITLS_VERSION_TLS12);
        ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.supportedVersion.data.data, HITLS_VERSION_TLS13);
    } else if (*(uint16_t *)user == HITLS_VERSION_TLS12) {
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.exState = INITIAL_FIELD;
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.exLen.state = INITIAL_FIELD;
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.exLen.data = 0;
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.exType.state = INITIAL_FIELD;
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.exType.data = HS_EX_TYPE_SUPPORTED_VERSIONS;
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.data.state = INITIAL_FIELD;
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.data.data = HITLS_VERSION_TLS12;
    } else {
        ASSERT_EQ(0, 1);
    }
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC007
* @spec  -
* @title 1. Set the client to TLS1.2 and server to TLS1.3. The earlier version of TLS1.2 is expected to be negotiated.
*            The server hello message sent does not carry the supportedversion extension.
* @precon nan
* @brief 4.2.1 Supported Versions line 45
* @expect 1. The expected connection setup is successful and the negotiated version is tls1.2.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC007()
{
    FRAME_Init();
    uint16_t version = 0;
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, &version, Test_ServerVersion};
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.config = HITLS_CFG_NewTLS12Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    version = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(testInfo.client->ssl, &version), HITLS_SUCCESS);
    ASSERT_EQ(version, HITLS_VERSION_TLS12);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_CHECK_SERVERHELLO_MASTER_SECRET_FUNC_TC001
 * @spec
 * The client does not support the extended master key and performs negotiation. After receiving the server hello
 * message with the extended master key, the client sends an alert message. Check whether the two parties enter the
 * alerted state, and the read and write operations fail.
 * @brief When an error is detected, the detecting party sends a message to its peer. Upon transmission or receipt of a
 * fatal alert message, both parties MUST immediately close the connection.
 * 6.2.0. Alert Protocol row 216
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CHECK_SERVERHELLO_MASTER_SECRET_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    HITLS_CFG_SetExtendedMasterSecretSupport(testInfo.c_config, true);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_ServerHelloSessionId(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    frameMsg.body.hsMsg.body.serverHello.sessionIdSize.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.serverHello.sessionIdSize.data = *len;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMESH_SESSIONId_LENGTHERR_FUNC_TC001
 * @spec
 * 1. Session recovery. If the client receives a ServerHello message whose session_id length exceeds the length of the
 * entire packet, the client sends a decode_error alarm and the session recovery fails.
 * @brief Peers which receive a message which cannot be parsed according to the syntax (e.g.,
 * have a length extending beyond the message boundary or contain an out-of-range length)
 * MUST terminate the connection with a "decode_error" alert.
 * 6. Alert Protocol row 209
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMESH_SESSIONId_LENGTHERR_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ServerHelloSessionId};
    testInfo.config = HITLS_CFG_NewTLS13Config();
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);
    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession), HITLS_SUCCESS);
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT), HITLS_PARSE_INVALID_MSG_LEN);

    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_DECODE_ERROR);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC008
* @spec -
* @title 1. Set the client to tls1.2 and server to tls1.3. Construct the serverhello message that carries the
            supportedversion extension. tls1.2 in the extension, the client is expected to abort the negotiation,
* @precon nan
* @brief 4.2.1 Supported Versions line 45
* @expect 1. The expected connection setup is successful and the negotiated version is tls1.3.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC008()
{
    FRAME_Init();
    uint16_t version = HITLS_VERSION_TLS12;
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, &version, Test_ServerVersion};
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS12Config();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC009
* @spec -
* @title Set the client server to tls1.3, set up a connection normally, and the serverhello message is expected to carry the
*        supportedversion extension. The value contains only 0x0304, and the value of legacy_version is 0x0303.
* @precon nan
* @brief 4.2.1 Supported Versions line 45
* @expect 1. The expected connection setup is successful and the negotiated version is tls1.3.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC009()
{
    FRAME_Init();
    uint16_t version = HITLS_VERSION_TLS13;
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &version,
        Test_ServerVersion
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    version = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(testInfo.client->ssl, &version), HITLS_SUCCESS);
    ASSERT_EQ(version, HITLS_VERSION_TLS13);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_ErrorServerVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    if (*(uint16_t *)user == 0) {
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.exState = MISSING_FIELD;
    } else if (*(uint16_t *)user == HITLS_VERSION_TLS13) {
        frameMsg.body.hsMsg.body.serverHello.version.data = HITLS_VERSION_TLS13;
    } else if (*(uint16_t *)user == HITLS_VERSION_TLS12) {
        frameMsg.body.hsMsg.body.serverHello.supportedVersion.data.data = HITLS_VERSION_TLS12;
    } else {
        ASSERT_EQ(0, 1);
    }
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void ErrorServerVersion(uint16_t version)
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &version,
        Test_ErrorServerVersion
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLSConfig();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    if (version == HITLS_VERSION_TLS12) {
        ALERT_Info alert = { 0 };
        ALERT_GetInfo(testInfo.client->ssl, &alert);
        ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
    }
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC0010
* @spec -
* @title 1. Set the client server to tls1.3, construct the legacy_version value of serverhello to 0x0304, and expect the
*           client to stop connection establishment.
* @precon nan
* @brief 4.2.1 Supported Versions line 45
* @expect 1. Expected connection establishment failure
@ */

/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC0010()
{
    ErrorServerVersion(HITLS_VERSION_TLS13);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC0011
* @spec -
* @title 1. Set the client server to tls1.3 and construct that the supportedversion parameter of the serverhello does
*            not exist. The client is expected to stop connection establishment.
* @precon nan
* @brief 4.2.1 Supported Versions line 45
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC0011()
{
    ErrorServerVersion(0);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC0012
* @spec -
* @title 1. Set the client server to tls1.3 and set the supportedversion value of the serverhello to tls1.2. Expect the
*            client to stop connection establishment. The client is expected to send the illegal_parameter alarm.
* @precon nan
* @brief 4.2.1 Supported Versions line 45/47
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SUPPORT_VERSION_FUNC_TC0012()
{
    ErrorServerVersion(HITLS_VERSION_TLS12);
}
/* END_CASE */

static void Test_AbsentGroup(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    (void)bufSize;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    uint32_t sz = frameMsg.body.hsMsg.body.clientHello.supportedGroups.exData.size;
    ASSERT_TRUE(sz > 1);

    frameMsg.body.hsMsg.body.clientHello.supportedGroups.exData.size = 1;
    frameMsg.body.hsMsg.body.clientHello.supportedGroups.exData.data[0] =
        frameMsg.body.hsMsg.body.clientHello.supportedGroups.exData.data[1];
    frameMsg.body.hsMsg.body.clientHello.supportedGroups.exDataLen.data = sizeof(uint16_t);
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC001
* @spec -
* @title 1. Initialize the client server to tls1.3, and construct that the keyshareentry.group in the sent client hello
*            message is not contained in the supported_group of the client. The server aborts the handshake and returns
*            the illegal_parameter alarm.
* @precon nan
* @brief 4.2.8 key share line 68
* @expect 1. Expected connection establishment failure
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC001()
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_AbsentGroup
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void HelloRetryRequest(WrapperFunc func)
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_HELLO_RETRY_REQUEST,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        func
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();

    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}

static void Test_HelloRetryRequest(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    (void)bufSize;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data = HITLS_EC_GROUP_SECP384R1;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC002
* @spec -
* @title 1. Initialize the client and server to tls1.3 and construct the scenario of sending hrr messages.
*            Construct the scenario where the selected_group in the hrr message is not in the group supported by the
*            client. Expect the client to terminate the handshake and return the illegal_parameter alarm.
* @precon nan
* @brief 4.2.8 key share line 69
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC002()
{
    HelloRetryRequest(Test_HelloRetryRequest);
}
/* END_CASE */

static void Test_HelloRetryRequestSameGroup(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    (void)bufSize;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data, HITLS_EC_GROUP_SECP256R1);
    frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data = HITLS_EC_GROUP_CURVE25519;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC003
* @spec -
* @title 1. Initialize the client server to tls1.3, construct the scenario of sending hrr messages, and construct the
*            group corresponding to the key_share key provided by the client. The client terminates the handshake and
*            returns the illegal_parameter alarm.
* @precon nan
* @brief 4.2.8 key share line 69
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC003()
{
    HelloRetryRequest(Test_HelloRetryRequestSameGroup);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC004
* @spec -
* @title 1. Initialize the client and server to tls1.3 and construct the scenario of sending hrr messages.
*            Construct the scenario where the key_share carried in the clienthello message sent again is not the
*            selected_group specified in the hrr message. The server is expected to terminate the handshake and return
*            the illegal_parameter alarm.
* @precon nan
* @brief 4.2.8 key share line 71
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_FUNC_TC004()
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_HELLO_RETRY_REQUEST,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_HelloRetryRequest
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_SUCCESS);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC001
* @spec -
* @title 1. The client initiates connection establishment by using the PSK encrypted by the unknown key.
*            Expected result: A non-PSK handshake is performed.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 96
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC001()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;
    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(testInfo.client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, false);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_InvalidSelectedIdentity(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    (void)bufSize;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.pskSelectedIdentity.exState, INITIAL_FIELD);
    frameMsg.body.hsMsg.body.serverHello.pskSelectedIdentity.data.data = 1;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC002
* @spec -
* @title 1. In the first handshake, the selected_identity of the server is not in the identity list provided by the
*            client, The client uses the illegal_parameter alarm to terminate the handshake. As a result, the first
*            connection fails to be established.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 100
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC002()
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_InvalidSelectedIdentity
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC003
* @spec  -
* @title 1. During session restoration, the selected_identity of the server is not in the identity list provided by the
*            client, The client uses the illegal_parameter alarm to terminate the handshake. As a result, the first
*            connection fails to be established.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 100
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC003()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);
    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession);
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_InvalidSelectedIdentity
    };
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_InvalidCipherSuites(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    (void)bufSize;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.pskSelectedIdentity.exState, INITIAL_FIELD);
    frameMsg.body.hsMsg.body.serverHello.cipherSuite.data = HITLS_AES_256_GCM_SHA384;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC004
* @spec -
* @title 1. In the first handshake, the hash algorithm in the cipher suite selected by the server does not match the
*           PSK. The client uses the (overwritten) illegal_parameter alarm to terminate the handshake. As a result, the
*           onnection fails to be established.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 100
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC004()
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_InvalidCipherSuites
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    HITLS_Connect(testInfo.client->ssl);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC005
* @spec -
* @title 1. Preset the PSK. When the client sends the client hello message, the client parses the extension item of the
*            client hello message so that the pre_share_key extension is not the last extension and continues to
*            establish the connection. Expected result: The server returns ALERT illegal_parameter and the handshake is
*           interrupted.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 100
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC005()
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_ErrorOrderPsk
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC006
* @spec -
* @title 1. During PSK-based session recovery, the client sends the client hello message, and parses the client hello
*            extension. Enable the pre_share_key extension not to establish a connection for the last extension. Expected
*            result: The server returns ALERT illegal_parameter and the handshake is interrupted.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 102
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC006()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);
    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession);
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_ErrorOrderPsk
    };
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_ServerErrorOrderPsk(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    frameMsg.body.hsMsg.body.serverHello.extensionLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.length.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.serverHello.supportedVersion.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    uint8_t supportedVersion[] = {0, 0x2b, 0, 2, 3, 4};
    ASSERT_NE(parseLen, *len);
    ASSERT_EQ(memcpy_s(&data[*len], bufSize - *len, &supportedVersion, sizeof(supportedVersion)), EOK);
    *len += sizeof(supportedVersion);
    ASSERT_EQ(parseLen, *len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC007
* @spec -
* @title 1. Preset the PSK. When the server sends the server hello message, the server parses the extension item of the
*            server hello message so that the pre_share_key extension is not the last extension and continues to
*            establish the connection. Expected result: The session is restored successfully.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 100
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC007()
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE_VERIFY,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_ServerErrorOrderPsk
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC008
* @spec -
* @title 1. During PSK-based session recovery, the server parses the extension items of the server hello message when
*           the server sends the server hello message, Make the pre_share_key extension not the last extension and
*           continue to establish the connection. Expected result: The session is restored successfully.
* @precon nan
* @brief 4.2.9 pre-shared key exchange line 102
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_FUNC_TC008()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession);
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_ServerErrorOrderPsk
    };
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */



static void Test_HrrMisClientHelloExtension(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    if (ctx->hsCtx->haveHrr) {
        uint32_t parseLen = 0;
        FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
        ASSERT_EQ(parseLen, *len);
        ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
        FieldState *extensionState = GetDataAddress(&frameMsg, user);
        *extensionState = MISSING_FIELD;
        memset_s(data, bufSize, 0, bufSize);
        FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void WithoutPskMisKeyExtension(void *memberAddress, bool isResume, bool isHrr)
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    if (isResume) {
        testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
        testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
        ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
        testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
        ASSERT_TRUE(testInfo.clientSession != NULL);
        FRAME_FreeLink(testInfo.client);
        testInfo.client = NULL;
        FRAME_FreeLink(testInfo.server);
        testInfo.server = NULL;
        testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
        HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession);
    } else {
        testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    }
    if (isHrr) {
        uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
        HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    }
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    WrapperFunc func = isHrr ? Test_HrrMisClientHelloExtension : Test_MisClientHelloExtension;
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        memberAddress,
        func
    };
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_MISSING_EXTENSION);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC001
* @spec -
* @title 1. When the first connection is established, the first ClientHello message received by the server does not
*            contain the pre_shared_key extension. If signature_algorithms, supported_groups, or key_share is missing,
*            the connection fails to be established and the server reports the missing_extension alarm.
* @precon nan
* @brief 9.2 Mandatory-to-Implement Extensions line 233
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC001()
{
    bool isResume = false;
    bool isHrr = false;
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.signatureAlgorithms.exState,
        isResume, isHrr);
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.supportedGroups.exState, isResume, isHrr);
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.keyshares.exState, isResume, isHrr);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC002
* @spec -
* @title 1. Certificate handshake in the hrr scenario, second ClientHello
*           If signature_algorithms, supported_groups, or key_share is missing, the connection fails to be established and the
*           server reports the missing_extension alarm.
* @precon nan
* @brief 9.2 Mandatory-to-Implement Extensions line 233
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC002()
{
    bool isResume = false;
    bool isHrr = true;
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.signatureAlgorithms.exState,
        isResume, isHrr);
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.supportedGroups.exState, isResume, isHrr);
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.keyshares.exState, isResume, isHrr);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC003
* @spec -
* @title 1. When the first connection is established, the first ClientHello message received by the server does not
*            contain supported_groups. But include key_share, and vice versa. The connection fails to be established and
*             theserver generates the missing_extension alarm.
* @precon nan
* @brief 9.2 Mandatory-to-Implement Extensions line 233
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC003()
{
    bool isResume = false;
    bool isHrr = false;
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.supportedGroups.exState, isResume, isHrr);
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.keyshares.exState, isResume, isHrr);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC004
* @spec -
* @title 1. The session is resumed. The first ClientHello message received by the server does not contain
*            supported_groups, But include key_share, and vice versa. The session fails to be restored, and the server
*            generates the missing_extension alarm.
* @precon nan
* @brief 9.2 Mandatory-to-Implement Extensions line 233
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC004()
{
    bool isResume = true;
    bool isHrr = false;
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.supportedGroups.exState, isResume, isHrr);
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.keyshares.exState, isResume, isHrr);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC005
* @spec -
* @title 1. In the hrr scenario, the certificate handshake second ClientHello does not contain supported_groups.
*            share is contained, the connection fails to be established and the server generates the
*           missing_extension alarm.
* @precon nan
* @brief 9.2 Mandatory-to-Implement Extensions line 233
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_EXTENSION_ASSOCIATION_FUNC_TC005()
{
    bool isResume = false;
    bool isHrr = true;
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.supportedGroups.exState, isResume, isHrr);
    WithoutPskMisKeyExtension(&((FRAME_Msg *)0)->body.hsMsg.body.clientHello.keyshares.exState, isResume, isHrr);
}
/* END_CASE */

static void Test_CertificateExtensionError001(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);
    FrameCertItem *certItem = frameMsg.body.hsMsg.body.certificate.certItem;

    // status_request Certificate Allowed Extensions. type(2) + len(2) + ctx(len)
    uint8_t certExtension[] = {0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00};
    uint32_t extensionLen = sizeof(certExtension);

    uint8_t *extensionData = BSL_SAL_Calloc(extensionLen, sizeof(uint8_t));
    ASSERT_TRUE(extensionData != NULL);
    ASSERT_EQ(memcpy_s(extensionData, extensionLen, certExtension, extensionLen), EOK);
    certItem->extension.state = ASSIGNED_FIELD;
    BSL_SAL_FREE(certItem->extension.data);
    certItem->extension.data = extensionData;
    certItem->extension.size = extensionLen;
    certItem->extensionLen.state = ASSIGNED_FIELD;
    certItem->extensionLen.data = extensionLen;
    *len += extensionLen;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CERT_EXTENSION_TC001
* @spec  -
* @title The test certificate message carries the extension of the response. However, due to the current feature not
*        being supported, requests will not be sent proactively. Expected to send illegal alerts and disconnect links.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the certificate message sent by the server to the client to include the status_request extension
*   3. Establish a connection and observe client behavior
* @expect
*   1. Initialization successful
*   2. Setup successful
*   3. The client returns alert ALERT_ILLEGAL_PARAMETER.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CERT_EXTENSION_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.config != NULL);
    testInfo.config->isSupportClientVerify = true;
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_CertificateExtensionError001};
    RegisterWrapper(wrapper);

    HITLS_CFG_SetCheckKeyUsage(testInfo.config, false);

    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_CertificateExtensionError002(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);
    FrameCertItem *certItem = frameMsg.body.hsMsg.body.certificate.certItem;

    // signature_algorithm Certificate-recognized but disallowed extensions. type(2) + len(2) + ctx(len)
    uint8_t certExtension[] = {0x00, 0x0d, 0x00, 0x04, 0x00, 0x00, 0x08, 0x09};
    uint32_t extensionLen = sizeof(certExtension);

    uint8_t *extensionData = BSL_SAL_Calloc(extensionLen, sizeof(uint8_t));
    ASSERT_TRUE(extensionData != NULL);
    ASSERT_EQ(memcpy_s(extensionData, extensionLen, certExtension, extensionLen), EOK);
    certItem->extension.state = ASSIGNED_FIELD;
    BSL_SAL_FREE(certItem->extension.data);
    certItem->extension.data = extensionData;
    certItem->extension.size = extensionLen;
    certItem->extensionLen.state = ASSIGNED_FIELD;
    certItem->extensionLen.data = extensionLen;
    *len += extensionLen;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CERT_EXTENSION_TC002
* @spec  -
* @title The test certificate message carries identifiable but not allowed extensions. Expected to send illegal
*       alerts and disconnect.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the certificate message sent by the server to the client to include the signature_algorithm extension
*   3. Establish a connection and observe client behavior
* @expect
*   1. Initialization successful
*   2. Setup successful
*   3. The client returns alert ALERT_ILLEGAL_PARAMETER.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CERT_EXTENSION_TC002()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.config != NULL);
    testInfo.config->isSupportClientVerify = true;
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_CertificateExtensionError002};
    RegisterWrapper(wrapper);

    HITLS_CFG_SetCheckKeyUsage(testInfo.config, false);

    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_CertificateExtensionError003(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);
    FrameCertItem *certItem = frameMsg.body.hsMsg.body.certificate.certItem;

    // Unrecognized Extensions. type(2) + len(2) + ctx(len)
    uint8_t certExtension[] = {0x00, 0x56, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00};
    uint32_t extensionLen = sizeof(certExtension);

    uint8_t *extensionData = BSL_SAL_Calloc(extensionLen, sizeof(uint8_t));
    ASSERT_TRUE(extensionData != NULL);
    ASSERT_EQ(memcpy_s(extensionData, extensionLen, certExtension, extensionLen), EOK);
    certItem->extension.state = ASSIGNED_FIELD;
    BSL_SAL_FREE(certItem->extension.data);
    certItem->extension.data = extensionData;
    certItem->extension.size = extensionLen;
    certItem->extensionLen.state = ASSIGNED_FIELD;
    certItem->extensionLen.data = extensionLen;
    *len += extensionLen;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CERT_EXTENSION_TC003
* @spec  -
* @title Test certificate message carrying unrecognized extensions. Expected to send illegal alerts and disconnect
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the certificate message sent by the server to the client to include the unrecognized extension
*   3. Establish a connection and observe client behavior
* @expect
*   1. Initialization successful
*   2. Setup successful
*   3. The client returns alert ALERT_ILLEGAL_PARAMETER.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CERT_EXTENSION_TC003()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.config != NULL);
    testInfo.config->isSupportClientVerify = true;
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_CertificateExtensionError003};
    RegisterWrapper(wrapper);

    HITLS_CFG_SetCheckKeyUsage(testInfo.config, false);

    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */
