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
/* INCLUDE_BASE test_suite_sdv_frame_tlcp_consistency */
/* END_HEADER */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_RESUME_TC003
* @title Enable the session restoration function at both ends. If the session ID is obtained after the link is
         successfully established, a fatal alert is sent. The session ID fails to be used to restore the session.
* @precon  nan
* @brief   1. Use the default configuration items to configure the client and server.
*             Enable the session restoration function at both ends. Expected result 1.
*          2. Obtaine the session ID and a fatal alert is sent. The session ID fails to be used to restore the session.
*             Expected result 2.
* @expect  1. The initialization is successful.
*          2. Expected handshake failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_RESUME_TC003()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    HITLS_SetSession(client->ssl, clientSession);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_FINISH), HITLS_SUCCESS);
    client->ssl->method.sendAlert(client->ssl, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
    ASSERT_NE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    HITLS_SetSession(client->ssl, clientSession);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearWrapper();
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_RESUME_TC004
* @title Set the client and server support session recovery. After the first connection is established, the session ID
         is obtained. Create two connection. The client and server are the same as those in the last session. Use the
         same session ID to restore the session. If the session on one link fails, check whether the data communication
         on the other link is blocked. It is expected that the link is not blocked.
* @precon  nan
* @brief   1. Use the default configuration items to configure the client and server.
*             Enable the session restoration function at both ends. Expected result 1.
*          2. Use the default configuration items to configure two new client and server.
*             The client and server are the same as those in the last session. Expected result 1.
*          3. Use the obtained session ID to restore one session and send a alert. Expected result 2.
*          4. Use the obtained session ID to restore another session. Expected result 3.
* @expect  1. The initialization is successful.
*          2. Expected handshake failure.
*          3. Restore the session successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_RESUME_TC004()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_LinkObj *clientResume = NULL;
    FRAME_LinkObj *serverResume = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    HITLS_SetSession(client->ssl, clientSession);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_FINISH), HITLS_SUCCESS);

    clientResume = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    serverResume = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    HITLS_SetSession(clientResume->ssl, clientSession);
    ASSERT_EQ(FRAME_CreateConnection(clientResume, serverResume, false, TRY_SEND_FINISH), HITLS_SUCCESS);

    client->ssl->method.sendAlert(client->ssl, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
    ASSERT_NE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    ASSERT_EQ(FRAME_CreateConnection(clientResume, serverResume, false, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(clientResume->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(clientResume);
    FRAME_FreeLink(serverResume);
    ClearWrapper();
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_RESUME_TC005
* @title Set the client and server support session recovery. After the first connection is established, the session ID
*        is obtained. Apply for two links. The client and server are the same as those in the last session. Use the same
*        session ID to restore the session. If the session on one link times out, check whether the data communication
*        on the other link is blocked. If the data communication on the other link is not blocked, the data
*        communication on the other link is not blocked.
* @precon  nan
* @brief   1. Use the default configuration items to configure the client and server.
*             Enable the session restoration function at both ends. Expected result 1.
*          2. Use the default configuration items to configure two new client and server.
*             The client and server are the same as those in the last session. Expected result 1.
*          3. Use the obtained session ID to restore one session and sleep to cause a session to time out.
*             Expected result 2.
*          4. Use the obtained session ID to restore another session. Expected result 3.
* @expect  1. The initialization is successful.
*          2. Establish the connection but restore the session failed.
*          3. Establish the connection and restore the session successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_RESUME_TC005()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_LinkObj *clientResume = NULL;
    FRAME_LinkObj *serverResume = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    const uint64_t timeout = 5u;
    HITLS_CFG_SetSessionTimeout(config, timeout);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    // Error stack exists
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    HITLS_SetSession(client->ssl, clientSession);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_FINISH), HITLS_SUCCESS);

    clientResume = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    serverResume = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    HITLS_SetSession(clientResume->ssl, clientSession);
    sleep(timeout);
    ASSERT_EQ(FRAME_CreateConnection(clientResume, serverResume, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(clientResume->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, false);
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    FRAME_FreeLink(clientResume);
    FRAME_FreeLink(serverResume);
    ClearWrapper();
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_RESUME_TC006
* @title Enable the session recovery function at both ends. The link is successfully established. The setting of the
*        session_id expires. The session fails to be restored.
* @precon  nan
* @brief   1. Set the client and server support session recovery. Establishe the first connection. Expected result 1.
*          2. Set the session_id expired, restore the session. Expected result 2.
* @expect  1. The expected handshake is successful.
*          2. The session is not recovered.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_RESUME_TC006()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    const uint64_t timeout = 5u;
    HITLS_CFG_SetSessionTimeout(config, timeout);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    // Error stack exists
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    HITLS_SetSession(client->ssl, clientSession);
    sleep(timeout);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, false);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearWrapper();
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_RESUME_TC007
* @title When a link is established for the first time, the clienthello message on the client contains the session_id
*        field that is not empty and is in the connection state. If the session ID on the server is not found in the
*        cache, the first connection setup process is triggered.
* @precon  nan
* @brief   1. Create the TLCP links on the client and server again, set the obtained session as the session on the
*             client, and check whether the session is reused. Expected result 1.
* @expect  1. The expected handshake is successful, but the session is not recovered.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_RESUME_TC007()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    // Error stack exists
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    HITLS_SetSession(client->ssl, clientSession);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, false);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearWrapper();
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

STUB_DEFINE_RET5(int32_t, HITLS_X509_CheckSignature, void *, uint8_t *, uint32_t , const void *, const void *);

static int32_t STUB_HITLS_X509_CheckSignature_Fail(void *pubKey, uint8_t *rawData,
    uint32_t rawDataLen, const void *alg, const void *signature)
{
    (void)pubKey;
    (void)rawData;
    (void)rawDataLen;
    (void)alg;
    (void)signature;
    return -1;
}

/* @
* @test  UT_TLS_TLCP_CERT_VERIFY_FAIL_TC001
* @title TLCP certificate signature verification fails during handshake.
* @precon  nan
* @brief   1. Use the default configuration items to configure the client and server. Expected result 1.
*          2. Stub the HITLS_X509_CheckSignature function to return failure. Expected result 2.
*          3. Attempt to complete the handshake. Expected result 3.
* @expect  1. The initialization is successful.
*          2. The signature verification function is stubbed successfully.
*          3. The handshake fails due to certificate verification failure.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CERT_VERIFY_FAIL_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_CERTIFICATE), HITLS_SUCCESS);

    /* Stub the certificate signature verification function to return failure */
    STUB_REPLACE(HITLS_X509_CheckSignature, STUB_HITLS_X509_CheckSignature_Fail);

    /* Continue handshake, should fail due to certificate verification failure */
    ASSERT_NE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Restore the stub */
    STUB_RESTORE(HITLS_X509_CheckSignature);

EXIT:
    STUB_RESTORE(HITLS_X509_CheckSignature);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CKX_PUBKEY_LENGTH_ERR_TC001
* @title During the testing of the chain construction process, we aim to verify whether the sm2 decryption will reverse
*       when the length is less than 97, and whether it will trigger asan.
* @precon  nan
* @brief   1. Use the default configuration items to configure the client and server. Expected result 1.
*          2. Construct the clientkeyexchange message with the pubkey length to be less than 97. Expected result 2.
*          3. Attempt to complete the handshake. Expected result 3.
* @expect  1. The initialization is successful.
*          2. The stubbed successfully.
*          3. Length error, randomly generate pre-master secret key, the handshake failed due to decryption failure.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CKX_PUBKEY_LENGTH_ERR_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    uint16_t cipherSuite[] = {HITLS_ECC_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(config, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));

    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(client != NULL);
    uint8_t data[] = {0x3f, 0x30, 0x3d, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x20, 0x59, 0x98, 0x3c, 0x18, 0xf8,
                      0x09, 0xe2, 0x62, 0x92, 0x3c, 0x53, 0xae, 0xc2, 0x95, 0xd3, 0x03, 0x83, 0xb5, 0x4e, 0x39, 0xd6,
                      0x09, 0xd1, 0x60, 0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87, 0x66, 0x04, 0x13, 0x21, 0x88, 0x6c,
                      0xa9, 0x89, 0xca, 0x9c, 0x7d, 0x58, 0x08, 0x73, 0x07, 0xca, 0x93, 0x09, 0x2d, 0x65, 0x1e, 0xfa};
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.size = sizeof(data);
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.data);
    frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.data = BSL_SAL_Calloc(sizeof(data), 1);
    memcpy(frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.data, data, sizeof(data));
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_REC_BAD_RECORD_MAC);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
