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
#include "hs_extensions.h"
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

typedef enum {
    WITHOUT_PSK,
    PRE_CONFIG_PSK,
    SESSION_RESUME_PSK
} PskStatus;

static void Test_PskConnect(uint32_t serverMode, PskStatus pskStatus)
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE);
    if (pskStatus == SESSION_RESUME_PSK) {
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
    } else if (pskStatus == PRE_CONFIG_PSK) {
        uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
        HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
        HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
        HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
        testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    } else {
        testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    }
    HITLS_CFG_SetKeyExchMode(testInfo.config, serverMode);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(testInfo.client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, pskStatus == SESSION_RESUME_PSK);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC001
* @spec -
* @title 1. Set key_exchange_mode to 3 on the client and server to establish a connection for the first time.
*            The expected result indicates that the connection is successfully established.
* @precon nan
* @brief psk Supplement the test case line 269.
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC001()
{
    Test_PskConnect(TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE, WITHOUT_PSK);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC002
* @spec -
* @title 1. Set key_exchange_mode to 3 on the client and server to establish a connection for the first time.
*            The expected result indicates that the connection is successfully established.
* @precon nan
* @brief psk Supplement the test case line 269.
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC002()
{
    Test_PskConnect(TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE, PRE_CONFIG_PSK);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC003
* @spec -
* @title 1. Restore the session. Set key_exchange_mode to 3 on the client and server. The client carries key_share and
*            connection. The expected result indicates that the connection is successfully established.
* @precon nan
* @brief psk Supplement the test case line 269.
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC003()
{
    Test_PskConnect(TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE, SESSION_RESUME_PSK);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC004
* @spec -
* @title 1. Preset the PSK, set the key_exchange_mode of the client and server to 3 and set the key_exchange_mode of the
*            server to psk_only, and establish a connection. The expected result indicates that the connection is
*            successfully established.
* @precon nan
* @brief psk Supplement the test case line 269.
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC004()
{
    Test_PskConnect(TLS13_KE_MODE_PSK_ONLY, PRE_CONFIG_PSK);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC005
* @spec -
* @title 1. Restore the session. Set the key_exchange_mode of the client and server to 3. Set the key_share extended by
*            the client to establish a connection and enable the server to reject the PSK. Expected result:
*            The session fails and certificate authentication is rejected.
* @precon nan
* @brief psk Supplement the test case line 269.
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC005()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE);
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

    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.config = HITLS_CFG_NewTLS13Config();
    HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT), HITLS_SUCCESS);
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

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC006
* @spec -
* @title 1. Preset the PSK and set the key_exchange_mode on the client server to 3. The key_share extension on the
*           client is lost and a connection is established. Expected result: The server sends an alert message and
*           the connection is disconnected.
* @precon nan
* @brief psk Added the test case line 269.
* @expect 1. Expected connection establishment failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_MODES_FUNC_TC006()
{
    FRAME_Init();
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &((FRAME_Msg *)0)->body.hsMsg.body.clientHello.keyshares.exState,
        Test_MisClientHelloExtension
    };
    RegisterWrapper(wrapper);
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE);
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

/**
 * @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CERTICATE_VERIFY_FAIL_FUNC_TC001
 * @brief 6.3. Error Alerts row 216
 *    The client does not support extended master keys and performs negotiation. After receiving the server hello
 * message with the extended master keys, the client sends an alert message. Check whether the two parties enter the
 * alerted state, and the read and write operations fail.
 *
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CERTICATE_VERIFY_FAIL_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    HITLS_CFG_SetExtendedMasterSecretSupport(testInfo.c_config, false);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_Client_Mode(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    frameMsg.body.hsMsg.body.clientHello.pskModes.exData.state = ASSIGNED_FIELD;
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientHello.pskModes.exData.data);
    uint16_t version[] = { 0x03, };
    frameMsg.body.hsMsg.body.clientHello.pskModes.exData.data =
        BSL_SAL_Calloc(sizeof(version) / sizeof(uint8_t), sizeof(uint8_t));
    ASSERT_EQ(memcpy_s(frameMsg.body.hsMsg.body.clientHello.pskModes.exData.data,
        sizeof(version), version, sizeof(version)), EOK);
    frameMsg.body.hsMsg.body.clientHello.keyshares.exState = MISSING_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.state = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKMODEZERO_FUNC_TC001
* @spec  -
* @title Initialize the client and server to tls1.3. Construct a scenario where the psk is carried but key_share is not
*        carried. Construct a scenario where the psk_mode carried in the clienthello message is 3. It is expected
*        that the handshake fails.
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation line 11
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKMODEZERO_FUNC_TC001()
{
    FRAME_Init();

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Client_Mode
    };
    RegisterWrapper(wrapper);

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_MISSING_EXTENSION);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_Server_Keyshare(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    frameMsg.body.hsMsg.body.serverHello.keyShare.data.state = ASSIGNED_FIELD;

    frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data = *(uint64_t *)user;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC001
* @spec  -
* @title Initialize the client server to tls1.3 and construct the selected_group carried in the key_share extension in
*         the sent serverhello message. If the group is not the keyshareentry group carried in the client hello message
*         but the group provided in the client hello message, the connection fails to be established.
* @precon nan
* @brief 4.2.8. Key Share line 72
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC001()
{
    FRAME_Init();
    uint64_t groupreturn[] = {HITLS_EC_GROUP_SECP384R1, };

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &groupreturn,
        Test_Server_Keyshare
    };
    RegisterWrapper(wrapper);

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t group[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    HITLS_CFG_SetGroups(testInfo.config, group, 2);

    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_Server_Keyshare3(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_TRUE(frameMsg.body.hsMsg.body.serverHello.keyShare.exState == MISSING_FIELD);

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKKEYSHARE_FUNC_TC001
* @spec  -
* @title 1. Initialize the client and server to tls1.3 and construct a scenario where psk_ke is used. The expected
*            serverhello message sent does not carry the key_share extension.
* @precon nan
* @brief 4.2.8. Key Share line 73
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKKEYSHARE_FUNC_TC001()
{
    FRAME_Init();

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Server_Keyshare3
    };
    RegisterWrapper(wrapper);

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
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

static void Test_Server_Keyshare4(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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

    frameMsg.body.hsMsg.body.serverHello.keyShare.exState = INITIAL_FIELD;
    frameMsg.body.hsMsg.body.serverHello.keyShare.exLen.state = INITIAL_FIELD;
    frameMsg.body.hsMsg.body.serverHello.keyShare.data.state = INITIAL_FIELD;
    frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data = HITLS_EC_GROUP_CURVE25519;

    FRAME_ModifyMsgInteger(HS_EX_TYPE_KEY_SHARE, &frameMsg.body.hsMsg.body.serverHello.keyShare.exType);
    uint8_t uu[] = {0x3b, 0xb5, 0xe4, 0x3c, 0xf6, 0xc4, 0x70, 0x0f, 0x3c, 0x7f, 0x05, 0x0b, 0xd4, 0xfb, 0x24, 0x39,
    0xc8, 0xb6, 0x13, 0x50, 0xc6, 0xee, 0xde, 0x69, 0xc5, 0x09, 0xef, 0x2e, 0x21, 0x4d, 0xd8, 0x1e};
    FRAME_ModifyMsgArray8(uu, sizeof(uu), &frameMsg.body.hsMsg.body.serverHello.keyShare.data.keyExchange,
    &frameMsg.body.hsMsg.body.serverHello.keyShare.data.keyExchangeLen);

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKKEYSHARE_FUNC_TC002
* @spec  -
* @title 1. Initialize the client and server to tls1.3, construct the psk_ke scenario, and construct the sent
*            serverhello message carrying the key_share extension. It is expected that the connection fails to be
*            established.
* @precon nan
* @brief 4.2.8. Key Share line 73
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKKEYSHARE_FUNC_TC002()
{
    FRAME_Init();

    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_Server_Keyshare4};
    RegisterWrapper(wrapper);

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_HANDSHAKE_FAILURE);

    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC001
* @spec  -
* @title The supported_versions in the clientHello is extended to 0x0304 (TLS 1.3). If the server supports only 1.2, the
*         server returns a "protocol_version" warning and the handshake fails.
* @precon nan
* @brief Appendix D. Backward Compatibility line 247
* @expect
*   1. The setting is successful.
*   2. The setting is successful.
*   3. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = HITLS_CFG_NewTLS13Config();
    config_s = HITLS_CFG_NewTLS12Config();

    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->cipherSuites.data[0] = 0xC02F;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(serverTlsCtx->hsCtx->state, TRY_SEND_CERTIFICATE);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC004
* @spec -
* @title clientHello version is 0x0303 and the server supports only 1.3. The server returns "protocol_version" and the
*         handshake fails.
* @precon nan
* @brief Appendix D. Backward Compatibility line 247
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC004()
{
    FRAME_Init();

    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = HITLS_CFG_NewTLS12Config();
    config_s = HITLS_CFG_NewTLS13Config();

    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC005
* @spec  -
* @titleSet that the server supports only TLS 1.2 and the client supports TLS 1.3. ClientHello legacy_version contains
            0x0303 (TLS 1.2). The supported_versions field is extended to 0x0304 and 0x0303. The server responds with
            serverHello and ServerHello.version is 0x0303, The client agrees to use this version, and the handshake
            negotiation is successful.
* @precon nan
* @brief Appendix D. Backward Compatibility line 245
* @expect 1. The handshake negotiation is successful.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC005()
{
    FRAME_Init();

    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = HITLS_CFG_NewTLSConfig();
    config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config_c, TLS12_VERSION_BIT|TLS13_VERSION_BIT) == HITLS_SUCCESS);

    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC006
* @spec  -
* @title: The server supports only TLS 1.2, and the client supports TLS 1.3. ClientHello legacy_version contains 0x0303
*            (TLS 1.2). The supported_versions field is extended to 0x0304 and 0x0303. The server responds with
*            serverHello and ServerHello.version is 0x0303, The client agrees to use this version. The connection
*             establishment is interrupted, and the session is restored. The restoration is successful.
* @precon nan
* @brief Appendix D. Backward Compatibility line 245
* @expect 1. The handshake negotiation is successful.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC006()
{
    FRAME_Init();

    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = HITLS_CFG_NewTLSConfig();
    config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config_c, TLS12_VERSION_BIT|TLS13_VERSION_BIT) == HITLS_SUCCESS);

    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = NULL;
    clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

static void Test_SERVERHELLO_VERSION(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    frameMsg.body.hsMsg.body.serverHello.version.data = 0x0301;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC007
* @spec  -
* @titleSet that the server supports only TLS 1.2 and the client supports TLS 1.3. ClientHello legacy_version contains
*           0x0303 (TLS 1.2), and supported_versions is extended to 0x0304, 0x0303, and 0x0301: The server responds with
*           serverHello. The value of ServerHello.version is 0x0303. The client agrees to use this version. The
*           connection establishment is interrupted and the session is restored, Before the client receives the
*           ServerHello message, the session fails to be resumed after Server.version is changed to 0x0301.
* @precon nan
* @brief Appendix D. Backward Compatibility line 245
* @expect 1. Failed to restore the session.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC007()
{
    FRAME_Init();

    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = HITLS_CFG_NewTLSConfig();
    config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(HITLS_CFG_SetVersionSupport(config_c, TLS12_VERSION_BIT | TLS13_VERSION_BIT) ==
                HITLS_SUCCESS);

    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = NULL;
    clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_SERVERHELLO_VERSION};
    RegisterWrapper(wrapper);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */


/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKTICKETLIFETIME_FUNC_TC001
* @spec  -
* @title Set the life cycle of ticket_lifetime to 10s. After the first connection is established, send the session using the
*       ticket through the client to resume, The server processes the message 10 seconds after receiving the ticket. The
*       server determines that the ticket has expired and the session fails to be restored.
* @precon nan
* @brief 4.6.1. New Session Ticket Message line 164
* @expect 1. Expected handshake failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKTICKETLIFETIME_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetSessionTimeout(testInfo.config, 10);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;
    HITLS_CFG_FreeConfig(testInfo.config);

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();

    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, testInfo.clientSession), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    sleep(11);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, false);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_CERT_SIGNATURE_FUNC_TC001
* @spec  -
* @title    Certificate chain: ecdsa_secp256r1_sha256. If the signature algorithm is ecdsa_secp256r1_sha256, the certificate
*            and certificate chain are successfully verified.
* @precon nan
* @brief 9.1. Mandatory-to-Implement Cipher Suites line 229
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CERT_SIGNATURE_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256, CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    ASSERT_TRUE(HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t))== HITLS_SUCCESS);

    FRAME_CertInfo certInfo = {
        "rsa_sha/ca-3072.der:rsa_sha/inter-3072.der",
        NULL, NULL, NULL, NULL, NULL,};

    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Error stack exists
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_CERT_SIGNATURE_FUNC_TC002
* @spec  -
* @title  Certificate chain: ecdsa_secp256r1_sha256. If the signature algorithm is ecdsa_secp256r1_sha256, the
*         certificate and certificate chain are successfully verified.
* @precon nan
* @brief 9.1. Mandatory-to-Implement Cipher Suites line 229
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CERT_SIGNATURE_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256 };
    ASSERT_TRUE(HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t))== HITLS_SUCCESS);

    FRAME_CertInfo certInfo1 = {
        "rsa_pss_rsae/rsa_root.der:rsa_pss_rsae/rsa_intCa.der",
        NULL, NULL, NULL, NULL, NULL,};
    FRAME_CertInfo certInfo2 = {
        "rsa_pss_rsae/rsa_root.der:rsa_pss_rsae/rsa_intCa.der",
        "rsa_pss_rsae/rsa_intCa.der", "rsa_pss_rsae/rsa_dev.der", NULL, "rsa_pss_rsae/rsa_dev.key.der", NULL,};

    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo1);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo2);
    ASSERT_TRUE(server != NULL);

    // Error stack exists
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_CERT_SIGNATURE_FUNC_TC003
* @spec  -
* @title    Certificate chain: ecdsa_secp256r1_sha256. If the signature algorithm is ecdsa_secp256r1_sha256, the
*            certificate and certificate chain are successfully verified.
* @precon nan
* @brief 9.1. Mandatory-to-Implement Cipher Suites line 229
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CERT_SIGNATURE_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    ASSERT_TRUE(HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t))== HITLS_SUCCESS);

    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der:ecdsa/inter-nist521.der",
        NULL, NULL, NULL, NULL, NULL,};

    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RECVERSION_FUNC_TC001
* @spec  -
* @title    After the server negotiates the version number for the first time, the serverHello, Certificate, Server Key
*            Exchange, Certificate Request, Server Hello Done, Certificate, Certificate Key Exchange, The
*            legacy_record_version of all record messages, such as Certificate Verify, Change Cipher Spec, and Finished,
*            is the negotiated version.
* @precon nan
* @brief Appendix D. Backward Compatibility line 242
* @expect 1. The expected version number is the negotiated version.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECVERSION_FUNC_TC001(int flag, int type)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FrameUioUserData *ioUserData = NULL;

    config = HITLS_CFG_NewTLS12Config();
    HITLS_CFG_SetClientVerifySupport(config, true);

    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, flag, type) == HITLS_SUCCESS);

    if (flag == 1) {
        HITLS_Connect(client->ssl);
        ioUserData = BSL_UIO_GetUserData(client->io);
    } else {
        HITLS_Accept(server->ssl);
        ioUserData = BSL_UIO_GetUserData(server->io);
    }
    uint8_t *recvBuf = ioUserData->sndMsg.msg;
    uint32_t recvLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.recVersion.data, 0x0303);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RECVERSION_FUNC_TC002
* @spec  -
* @title    Renegotiation. After the server negotiates the version number, the serverHello, Certificate, Server Key
*            Exchange, Certificate Request, Server Hello Done, Certificate, Certificate Key Exchange, Certificate Verify,
*            Change Cipher Spec, Finished, and other record messages legacy_record_version indicates the renegotiation
            version.
* @precon nan
* @brief Appendix D. Backward Compatibility line 242
* @expect 1. The expected version number is the negotiated version.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECVERSION_FUNC_TC002(int flag, int type)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FrameUioUserData *ioUserData = NULL;

    config = HITLS_CFG_NewTLS12Config();
    HITLS_CFG_SetClientVerifySupport(config, true);

    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_SetRenegotiationSupport(server->ssl, true);
    HITLS_SetRenegotiationSupport(client->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, flag, type), HITLS_SUCCESS);

    if (flag == 1) {
        HITLS_Connect(client->ssl);
        ioUserData = BSL_UIO_GetUserData(client->io);
    } else {
        HITLS_Accept(server->ssl);
        ioUserData = BSL_UIO_GetUserData(server->io);
    }
    uint8_t *recvBuf = ioUserData->sndMsg.msg;
    uint32_t recvLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.recVersion.data, 0x0303);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
/** @
* @test  UT_TLS_TLS13_PARSE_CA_LIST_TC001
* @spec  -
* @title  The CA list is parsed correctly.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. stop the server in the TRY_RECV_CLIENT_HELLO
*            state. Expected result 1 is obtained.
*         2. Get the client hello message from the server. Expected result 2 is obtained.
*         3. Add the CA list to the client hello message. Expected result 3 is obtained.
*         4. Reconnect the client. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
*         2. The recvLen is not 0.
*         3. The CA list is packed correctly.
*         4. The client hello message is parsed correctly.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_PARSE_CA_LIST_TC001()
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FrameUioUserData *ioUserData = NULL;

    config = HITLS_CFG_NewTLS13Config();

    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ioUserData = BSL_UIO_GetUserData(server->io);

    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;

    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, recvBuf, recvLen, &frameMsg, &recvLen) == HITLS_SUCCESS);
    uint8_t caList[] = {0x00, 0x06, 0x00, 0x04, 0x4a, 0x4b, 0x4c, 0x4d};
    frameMsg.body.hsMsg.body.clientHello.caList.exState = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.caList.exType.data = HS_EX_TYPE_CERTIFICATE_AUTHORITIES;
    frameMsg.body.hsMsg.body.clientHello.caList.exType.state = ASSIGNED_FIELD;
    FRAME_ModifyMsgArray8(caList, sizeof(caList), &frameMsg.body.hsMsg.body.clientHello.caList.list,
        &frameMsg.body.hsMsg.body.clientHello.caList.listSize);
    frameMsg.body.hsMsg.body.clientHello.caList.exLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.caList.exLen.data = sizeof(caList) + sizeof(uint16_t);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_NE(FRAME_CreateConnection(server, client, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
