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

#include "rec_wrapper.h"
#include "alert.h"
#include "hitls_crypt_init.h"
#include "common_func.h"
#include "securec.h"
#include "hitls_error.h"
#include "hs.h"
#include "stub_replace.h"
#include "frame_tls.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_link.h"
#include "hlt.h"

#define UT_TIMEOUT 3
/* END_HEADER */

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
} HsTestInfo;
int32_t NewConfig(HsTestInfo *testInfo)
{
    switch (testInfo->version) {
        case HITLS_VERSION_DTLS12:
            testInfo->config = HITLS_CFG_NewDTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            testInfo->config = HITLS_CFG_NewTLS13Config();
            break;
        case HITLS_VERSION_TLS12:
            testInfo->config = HITLS_CFG_NewTLS12Config();
            break;
        default:
            break;
    }
    if (testInfo->config == NULL || testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    HITLS_CFG_SetClientVerifySupport(testInfo->config, true);
    HITLS_CFG_SetExtendedMasterSecretSupport(testInfo->config, true);
    HITLS_CFG_SetNoClientCertSupport(testInfo->config, true);
    HITLS_CFG_SetRenegotiationSupport(testInfo->config, true);
    HITLS_CFG_SetPskServerCallback(testInfo->config, (HITLS_PskServerCb)ExampleServerCb);
    return HITLS_SUCCESS;
}
static int32_t DoHandshake(HsTestInfo *testInfo)
{
    /* Construct a connection. */
    testInfo->client = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_OBSOLETE_RESERVED_FUNC_TC001
* @spec -
* @title Expired signature algorithm
* @precon nan
* @brief    1. Initialize the client server to tls1.3 and construct the scenario where the client uses all the
            obsolete_RESERVED signature algorithms in polling mode, Expected result: The connection fails to be
            established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_OBSOLETE_RESERVED_FUNC_TC001(int signAlg)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    HITLS_CFG_SetSignature(testInfo.config, (uint16_t *)&signAlg, 1);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_OBSOLETE_RESERVED_FUNC_TC002
* @spec - tls1.3 Expired group algorithm OBSOLETE_RESERVED test
* @title
* @precon nan
* @brief    1. Initialize the client and server to tls1.3 and construct the scenario where the client uses all the
            obsolete_RESERVED group algorithms in polling mode, Expected result: The connection fails to be established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_OBSOLETE_RESERVED_FUNC_TC002(int group)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    HITLS_CFG_SetGroups(testInfo.config, (uint16_t *)&group, 1);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_ServerHelloNoSupportedVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *user)
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
    frameMsg.body.hsMsg.body.serverHello.supportedVersion.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC001
* @spec -
* @title server hello really necessary extensions
* @precon nan
* @brief 1. If the server sends a HelloRetryRequest message without supported_versions, the connection fails to be
         established and the client generates an alarm.
         Expected result: The connection fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC001()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    RecWrapper wrapper = { TRY_SEND_HELLO_RETRY_REQUEST, REC_TYPE_HANDSHAKE, false, NULL,
        Test_ServerHelloNoSupportedVersion };
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC002
* @spec -
* @title server hello really necessary extension
* @precon nan
* @brief 1. In certificate authentication, the first connection is established. If the ServerHello message sent by the
        Server does not contain the signature_algorithms field, the connection fails to be established and the client generates
        an alarm.
        Expected result: The connection fails to be established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC002()
{

    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    RecWrapper wrapper = { TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ServerHelloNoSupportedVersion };
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_ResumeServerHelloNoSupportedVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *user)
{
    if (ctx->session == NULL) {
        return;
    }
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
    frameMsg.body.hsMsg.body.serverHello.supportedVersion.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_ResumeClientHelloNoSupportedVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *user)
{
    if (ctx->session == NULL) {
        return;
    }
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_ClientHelloNoSupportedVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC003
* @spec -
* @title server Hello message extension is missing.
* @precon nan
* @brief Certificate authentication, session recovery, the Server sends the ServerHello message without the
         signature_algorithms, the session recovery fails, and the client generates an alarm.
* Expected result: connect establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC003()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    RecWrapper wrapper = { TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL,
        Test_ResumeServerHelloNoSupportedVersion };
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    ClearWrapper();
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
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC004
* @spec -
* @title client hello is missing the necessary extension.
* @precon nan
* @brief  1. In certificate authentication, the first connection is established. If the clientHello message sent by the
*            client does not contain signature_algorithms, the connection fails to be established and the server
*            generates an alarm. Expected result: The connection fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC004()
{

    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ClientHelloNoSupportedVersion };
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC005
* @spec -
* @title client Hello packet extension is missing.
* @precon nan
* @brief Certificate authentication, session recovery. If the client sends a clientHello message without
*         signature_algorithms, the session recovery fails and the server generates an alarm. *Expected result: The
*        connection fails to be established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC005()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    HITLS_CFG_SetSessionTimeout(testInfo.config, UT_TIMEOUT);
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ResumeClientHelloNoSupportedVersion};
    RegisterWrapper(wrapper);
    /* First handshake */
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    ClearWrapper();
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
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

static void Test_ClientHello2NoSupportedVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *user)
{
    if (!ctx->hsCtx->haveHrr) {
        return;
    }
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC006
* @spec -
* @title client hello is missing the necessary extension.
* @precon nan
* @brief   1. After receiving the HelloRetryRequest message, the client sends the second ClientHello message. If the
*           client does not have the signature_algorithms message, the connection fails to be established and the server
*           generates an alarm. Expected result: The connection fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC006()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL,
        Test_ClientHello2NoSupportedVersion };
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_Client2HelloNoSupportedGroup(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *user)
{
    if (!ctx->hsCtx->haveHrr) {
        return;
    }
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.supportedGroups.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_ClientHelloNoSupportedGroup(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.supportedGroups.exState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC007
* @spec -
* @title client hello is missing the necessary extension.
* @precon nan
* @brief 1. During DHE key exchange, if the ClientHello does not contain "supported_groups", the connection fails to be
         established and the server generates an alarm. Expected result: The connection fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC007()
{
    FRAME_Init();
    HsTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ClientHelloNoSupportedGroup };
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_MISSING_EXTENSION);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC008
* @spec -
* @title client hello really necessary extension
* @precon nan
* @brief 1. After the client receives the HelloRetryRequest message, the client sends the second ClientHello message
            without the supported_groups field. In this case, the connection fails to be established and the server
            generates an alarm.
        Expected result: The connection fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NECESSARY_EXTENSION_FUNC_TC008()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_Client2HelloNoSupportedGroup };
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_MISSING_EXTENSION);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */