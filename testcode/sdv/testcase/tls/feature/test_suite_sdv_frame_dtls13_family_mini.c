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
#include <stdint.h>
#include <string.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_session.h"
#include "tls.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "simulate_io.h"
#include "common_func.h"
/* END_HEADER */

#define DTLS13_MINI_READ_BUF_SIZE 2048u
#define DTLS13_MINI_RECORD_SIZE_LIMIT 5000u
#define DTLS13_MINI_LARGE_APP_DATA_LEN 6000u
#define DTLS13_MINI_MTU 16384u

static int32_t Dtls13MiniUseSingleKeyShareGroup(HITLS_Config *config)
{
    const uint16_t groups[] = {HITLS_EC_GROUP_CURVE25519};
    return HITLS_CFG_SetGroups(config, groups, sizeof(groups) / sizeof(groups[0]));
}

/* @
* @test SDV_HITLS_DTLS13_ONLY_BASE_CONNECT_TC001
* @spec -
* @title DTLS1.3-only mini build can complete a basic handshake and exchange app data.
* @precon nan
* @brief
* 1. Create DTLS1.3 client and server configs, and create UDP frame links.
* 2. Complete the handshake.
* 3. Send application data from the client to the server.
* @expect
* 1. Link setup succeeds.
* 2. Handshake succeeds.
* 3. The server reads the same application data.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_DTLS13_ONLY_BASE_CONNECT_TC001(void)
{
    FRAME_Init();

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t writeData[] = "DTLS1.3 mini app data";
    uint8_t readData[DTLS13_MINI_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_Write(client->ssl, writeData, sizeof(writeData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(writeData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readData, sizeof(readData), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(writeData));
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HITLS_DTLS13_ONLY_RECORD_SIZE_LIMIT_TC001
* @spec -
* @title DTLS1.3 uses TLS1.3-family record_size_limit plaintext accounting.
* @precon nan
* @brief
* 1. Create DTLS1.3 client and server configs, and set record_size_limit to 5000 on both sides.
* 2. Complete the handshake over UDP frame links.
* 3. Send 6000 bytes of application data from the client to the server.
* @expect
* 1. Link setup succeeds.
* 2. Handshake succeeds and record_size_limit is negotiated.
* 3. HITLS_Write reports 4999 bytes and the server reads the same 4999 bytes.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_DTLS13_ONLY_RECORD_SIZE_LIMIT_TC001(void)
{
    FRAME_Init();

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(clientConfig != NULL);
    HITLS_Config *serverConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(serverConfig != NULL);

    ASSERT_EQ(HITLS_CFG_SetRecordSizeLimit(clientConfig, DTLS13_MINI_RECORD_SIZE_LIMIT), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetRecordSizeLimit(serverConfig, DTLS13_MINI_RECORD_SIZE_LIMIT), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetMtu(client->ssl, DTLS13_MINI_MTU), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetMtu(server->ssl, DTLS13_MINI_MTU), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.recordSizeLimit, DTLS13_MINI_RECORD_SIZE_LIMIT);
    ASSERT_EQ(client->ssl->negotiatedInfo.peerRecordSizeLimit, DTLS13_MINI_RECORD_SIZE_LIMIT);

    uint8_t writeData[DTLS13_MINI_LARGE_APP_DATA_LEN] = {1};
    uint8_t readData[DTLS13_MINI_RECORD_SIZE_LIMIT] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_Write(client->ssl, writeData, sizeof(writeData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, DTLS13_MINI_RECORD_SIZE_LIMIT - 1u);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readData, sizeof(readData), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, writeLen);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HITLS_DTLS13_ONLY_SESSION_RESUME_TC001
* @spec -
* @title DTLS1.3-only mini build can resume a session with NewSessionTicket.
* @precon nan
* @brief
* 1. Establish a DTLS1.3 connection with one NewSessionTicket.
* 2. Set the ticket session on a new DTLS1.3 client.
* 3. Complete a resumed DTLS1.3 handshake and exchange application data.
* @expect
* 1. The first connection produces a ticket session.
* 2. The second connection is marked as reused on both endpoints.
* 3. The server reads the resumed-connection application data.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_DTLS13_ONLY_SESSION_RESUME_TC001(void)
{
    FRAME_Init();

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 1), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13MiniUseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);
    ASSERT_TRUE(HITLS_SESS_HasTicket(session) == true);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);
    isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(server->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

    uint8_t writeData[] = "DTLS1.3 resumed mini app data";
    uint8_t readData[DTLS13_MINI_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_Write(client->ssl, writeData, sizeof(writeData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(writeData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readData, sizeof(readData), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(writeData));
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/* @
* @test SDV_HITLS_DTLS13_ONLY_KEY_UPDATE_TC001
* @spec -
* @title DTLS1.3-only mini build can process a post-handshake KeyUpdate.
* @precon nan
* @brief
* 1. Establish a DTLS1.3 connection without automatic NewSessionTicket messages.
* 2. Let the client send a post-handshake KeyUpdate.
* 3. Let the server process the KeyUpdate, then exchange application data.
* @expect
* 1. KeyUpdate send succeeds.
* 2. The server consumes the post-handshake message without application data.
* 3. Application data after KeyUpdate is delivered successfully.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_DTLS13_ONLY_KEY_UPDATE_TC001(void)
{
    FRAME_Init();

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readData[DTLS13_MINI_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readData, sizeof(readData), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);

    uint8_t writeData[] = "DTLS1.3 app data after KeyUpdate";
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(client->ssl, writeData, sizeof(writeData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(writeData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    memset(readData, 0, sizeof(readData));
    readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readData, sizeof(readData), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(writeData));
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HITLS_DTLS13_ONLY_RENEGOTIATION_REJECT_TC001
* @spec -
* @title DTLS1.3-only mini build rejects renegotiation as a TLS1.3-family connection.
* @precon nan
* @brief
* 1. Establish a DTLS1.3 connection and enable renegotiation support in the config.
* 2. Invoke the renegotiation API on both endpoints.
* @expect
* 1. The handshake succeeds.
* 2. Renegotiation is rejected on both endpoints.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_DTLS13_ONLY_RENEGOTIATION_REJECT_TC001(void)
{
    FRAME_Init();

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetRenegotiationSupport(config, true), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    client->ssl->negotiatedInfo.isSecureRenegotiation = true;
    server->ssl->negotiatedInfo.isSecureRenegotiation = true;
    ASSERT_EQ(HITLS_Renegotiate(client->ssl), HITLS_CM_LINK_UNSUPPORT_SECURE_RENEGOTIATION);
    ASSERT_EQ(HITLS_Renegotiate(server->ssl), HITLS_CM_LINK_UNSUPPORT_SECURE_RENEGOTIATION);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
