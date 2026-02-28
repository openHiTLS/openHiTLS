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

#include "securec.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_type.h"
#include "hitls_error.h"
#include "hitls_session.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "alert.h"

/* END_HEADER */

static HITLS_Config *NewEmsConfigByVersion(uint16_t version)
{
    if (version == HITLS_VERSION_DTLS12) {
        return HITLS_CFG_NewDTLS12Config();
    }
    if (version == HITLS_VERSION_TLCP_DTLCP11) {
        return HITLS_CFG_NewTLCPConfig();
    }
    return HITLS_CFG_NewTLS12Config();
}

static FRAME_LinkObj *CreateEmsLinkByVersion(HITLS_Config *config, uint16_t version, bool isClient)
{
    if (version == HITLS_VERSION_TLCP_DTLCP11) {
        return FRAME_CreateTLCPLink(config, BSL_UIO_TCP, isClient);
    }
    if (version == HITLS_VERSION_DTLS12) {
        return FRAME_CreateLink(config, BSL_UIO_UDP);
    }
    return FRAME_CreateLink(config, BSL_UIO_TCP);
}

static void UI_TLS_EMS_MODE_TC001_ByVersion(uint16_t version,
    int clientMode, int serverMode, int expectEms);
static void UI_TLS_EMS_MODE_TC002_ByVersion(uint16_t version,
    int clientMode, int serverMode, int expectEms);
static void UI_TLS_EMS_MODE_RESUME_TC001_ByVersion(uint16_t version, int origClientMode,
    int resumeClientMode, int resumeServerMode, int expectResume, int expectEms);
static void UI_TLS_EMS_MODE_RESUME_TC002_ByVersion(uint16_t version, int origClientMode,
    int resumeClientMode, int resumeServerMode, int expectEms);
static void UI_TLS_EMS_MODE_RESUME_TC003_ByVersion(uint16_t version, int resumeServerMode);
static void UI_TLS_EMS_MODE_RESUME_TC004_ByVersion(uint16_t version);

/** @
* @test UI_TLS_EMS_MODE_TC001
* @title TLS1.2 EMS mode success combinations
* @precon nan
* @brief 1. Create client/server configs with EMS modes.
*        2. Create links and establish connection.
*        3. Verify negotiated EMS status.
* @expect 1. Connection succeeds.
*         2. Negotiated EMS status matches expected value.
@ */
/* BEGIN_CASE */
void UI_TLS_EMS_MODE_TC001(int clientMode, int serverMode, int expectEms)
{
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_TLCP_DTLCP11};
    uint32_t i;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        UI_TLS_EMS_MODE_TC001_ByVersion(versions[i], clientMode, serverMode, expectEms);
    }
}
/* END_CASE */

static void UI_TLS_EMS_MODE_TC001_ByVersion(uint16_t version,
    int clientMode, int serverMode, int expectEms)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    clientConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(serverConfig != NULL);

    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, clientMode), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, serverMode), HITLS_SUCCESS);

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isExtendedMasterSecret, (bool)expectEms);
    ASSERT_EQ(server->ssl->negotiatedInfo.isExtendedMasterSecret, (bool)expectEms);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    return;
}

/** @
* @test UI_TLS_EMS_MODE_TC002
* @title TLS1.2 EMS mode failure combinations
* @precon nan
* @brief 1. Create client/server configs with EMS modes.
*        2. Create links and establish connection.
* @expect 1. Connection fails.
@ */
/* BEGIN_CASE */
void UI_TLS_EMS_MODE_TC002(int clientMode, int serverMode, int expectEms)
{
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_TLCP_DTLCP11};
    uint32_t i;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        UI_TLS_EMS_MODE_TC002_ByVersion(versions[i], clientMode, serverMode, expectEms);
    }
}
/* END_CASE */

static void UI_TLS_EMS_MODE_TC002_ByVersion(uint16_t version,
    int clientMode, int serverMode, int expectEms)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    int32_t ret;

    (void)expectEms;

    FRAME_Init();

    clientConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(serverConfig != NULL);

    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, clientMode), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, serverMode), HITLS_SUCCESS);

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);

    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_NE(ret, HITLS_SUCCESS);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    return;
}

/*
 * EMS session resumption matrix (RFC 7627 5.3 + EMS mode policy)
 * -----------------------------------------------------------------------------------------------
 * | original session | abbreviated handshake | EMS mode (server) | expected behavior           |
 * | :-------------: | :-------------------: | :---------------: | :-------------------------- |
 * | true            | true                  | force / prefer    | resume success, EMS = true  |
 * | true            | true                  | forbid            | no resume, full HS, EMS=0   |
 * | true            | false                 | any               | abort handshake             |
 * | false           | true                  | force / prefer    | no resume, full HS, EMS=1   |
 * | false           | true                  | forbid            | no resume, full HS, EMS=0   |
 * | false           | false                 | force             | abort handshake             |
 * | false           | false                 | prefer / forbid   | resume success, EMS = false |
 *
 * Notes:
 * - "original session" EMS=true/false is driven by first-handshake client/server modes.
 * - "abbreviated handshake" EMS=true/false is driven by resume client mode.
 * - "no resume, full HS" means handshake succeeds but negotiatedInfo.isResume == false.
 */
/** @
* @test UI_TLS_EMS_MODE_RESUME_TC001
* @title TLS1.2 EMS session resumption success scenarios
* @precon nan
* @brief 1. First handshake with original EMS modes, save session.
*        2. Second handshake with resume EMS modes and set session.
*        3. Verify whether session is resumed and EMS status.
* @expect 1. Handshake succeeds.
*         2. Resume status and EMS status match expected values.
@ */
/* BEGIN_CASE */
void UI_TLS_EMS_MODE_RESUME_TC001(int origClientMode,
    int resumeClientMode, int resumeServerMode, int expectResume, int expectEms)
{
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_TLCP_DTLCP11};
    uint32_t i;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        UI_TLS_EMS_MODE_RESUME_TC001_ByVersion(versions[i], origClientMode,
            resumeClientMode, resumeServerMode, expectResume, expectEms);
    }
}
/* END_CASE */

static void UI_TLS_EMS_MODE_RESUME_TC001_ByVersion(uint16_t version, int origClientMode,
    int resumeClientMode, int resumeServerMode, int expectResume, int expectEms)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;

    FRAME_Init();

    clientConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, origClientMode), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, HITLS_EMS_MODE_PREFER), HITLS_SUCCESS);

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, resumeClientMode), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, resumeServerMode), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isResume, (bool)expectResume);
    ASSERT_EQ(server->ssl->negotiatedInfo.isResume, (bool)expectResume);
    ASSERT_EQ(client->ssl->negotiatedInfo.isExtendedMasterSecret, (bool)expectEms);
    ASSERT_EQ(server->ssl->negotiatedInfo.isExtendedMasterSecret, (bool)expectEms);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    HITLS_SESS_Free(session);
    return;
}

/** @
* @test UI_TLS_EMS_MODE_RESUME_TC002
* @title TLS1.2 EMS session resumption failure scenarios
* @precon nan
* @brief 1. First handshake with original EMS modes, save session.
*        2. Second handshake with resume EMS modes and set session.
* @expect 1. Handshake fails.
@ */
/* BEGIN_CASE */
void UI_TLS_EMS_MODE_RESUME_TC002(int origClientMode,
    int resumeClientMode, int resumeServerMode, int expectEms)
{
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_TLCP_DTLCP11};
    uint32_t i;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        UI_TLS_EMS_MODE_RESUME_TC002_ByVersion(versions[i], origClientMode,
            resumeClientMode, resumeServerMode, expectEms);
    }
}
/* END_CASE */

static void UI_TLS_EMS_MODE_RESUME_TC002_ByVersion(uint16_t version, int origClientMode,
    int resumeClientMode, int resumeServerMode, int expectEms)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    int32_t ret;

    (void)expectEms;

    FRAME_Init();

    clientConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, origClientMode), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, HITLS_EMS_MODE_PREFER), HITLS_SUCCESS);

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, resumeClientMode), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, resumeServerMode), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET);

EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    HITLS_SESS_Free(session);
    return;
}

/** @
* @test UI_TLS_EMS_MODE_RESUME_TC003
* @title TLS1.2 EMS resume abort when original session EMS=true but resume CH has no EMS
* @precon nan
* @brief 1. First handshake negotiates EMS.
*        2. Modify session EMS flag to false.
*        3. Resume handshake with client FORBID (no EMS) and given server mode.
* @expect 1. Handshake fails.
@ */
/* BEGIN_CASE */
void UI_TLS_EMS_MODE_RESUME_TC003(int resumeServerMode)
{
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_TLCP_DTLCP11};
    uint32_t i;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        UI_TLS_EMS_MODE_RESUME_TC003_ByVersion(versions[i], resumeServerMode);
    }
}
/* END_CASE */

/** @
* @test UI_TLS_EMS_MODE_RESUME_TC004
* @title TLS1.2 EMS resume disabled on client: no session resumption attempt
* @precon nan
* @brief 1. First handshake negotiates EMS and stores session.
*        2. Resume handshake with client EMS FORBID and set session.
*        3. Verify ClientHello has empty session_id (no resumption attempt).
* @expect 1. ClientHello session_id length is 0.
@ */
/* BEGIN_CASE */
void UI_TLS_EMS_MODE_RESUME_TC004(int dummy)
{
    uint16_t versions[] = {HITLS_VERSION_TLS12, HITLS_VERSION_DTLS12, HITLS_VERSION_TLCP_DTLCP11};
    uint32_t i;

    (void)dummy;

    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        UI_TLS_EMS_MODE_RESUME_TC004_ByVersion(versions[i]);
    }
}
/* END_CASE */

static void UI_TLS_EMS_MODE_RESUME_TC003_ByVersion(uint16_t version, int resumeServerMode)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    int32_t ret;

    FRAME_Init();

    clientConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, HITLS_EMS_MODE_PREFER), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, HITLS_EMS_MODE_PREFER), HITLS_SUCCESS);

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);
    ASSERT_EQ(HITLS_SESS_SetHaveExtMasterSecret(session, 0), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, HITLS_EMS_MODE_FORBID), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, resumeServerMode), HITLS_SUCCESS);

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET);

EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    HITLS_SESS_Free(session);
    return;
}

static void UI_TLS_EMS_MODE_RESUME_TC004_ByVersion(uint16_t version)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    int32_t ret;

    FRAME_Init();

    clientConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = NewEmsConfigByVersion(version);
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, HITLS_EMS_MODE_PREFER), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, HITLS_EMS_MODE_PREFER), HITLS_SUCCESS);

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, HITLS_EMS_MODE_FORBID), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, HITLS_EMS_MODE_PREFER), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = CreateEmsLinkByVersion(clientConfig, version, true);
    ASSERT_TRUE(client != NULL);
    server = CreateEmsLinkByVersion(serverConfig, version, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ret = FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Type frameType = {0};
    FRAME_Msg frameMsg = {0};
    uint32_t parseLen = 0;
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = (version == HITLS_VERSION_DTLS12) ? BSL_UIO_UDP : BSL_UIO_TCP;
    ASSERT_EQ(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientMsg->sessionIdSize.data, 0);
    FRAME_CleanMsg(&frameType, &frameMsg);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    HITLS_SESS_Free(session);
    return;
}
