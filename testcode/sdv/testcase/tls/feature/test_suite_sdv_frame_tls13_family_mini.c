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
#include "tls.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "common_func.h"
/* END_HEADER */

#define TLS13_MINI_READ_BUF_SIZE 2048u

/* @
* @test SDV_HITLS_TLS13_ONLY_BASE_CONNECT_TC001
* @spec -
* @title TLS1.3-only mini build can complete a basic handshake and exchange app data.
* @precon nan
* @brief
* 1. Create TLS1.3-only client and server configs, and create TCP frame links.
* 2. Complete the handshake and check the negotiated version on both endpoints.
* 3. Send application data from the client to the server, then from the server to the client.
* @expect
* 1. Link setup succeeds.
* 2. The handshake succeeds and TLS1.3 is negotiated on both endpoints.
* 3. Both directions of application data are delivered unchanged.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_TLS13_ONLY_BASE_CONNECT_TC001(void)
{
#if !defined(HITLS_TLS_PROTO_TLS13)
    SKIP_TEST();
    return;
#else
    FRAME_Init();

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientConfig != NULL);
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(serverConfig != NULL);

#if !defined(HITLS_TLS_PROTO_TLS12)
    /* The mini config compiles only the TLS1.3 protocol: any other version must be rejected. */
    ASSERT_TRUE(HITLS_CFG_SetVersion(clientConfig, HITLS_VERSION_TLS12, HITLS_VERSION_TLS12) != HITLS_SUCCESS);
#endif

    client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_TLS13);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_TLS13);

    uint8_t clientData[] = "TLS1.3 mini client data";
    uint8_t serverData[] = "TLS1.3 mini server data";
    uint8_t readData[TLS13_MINI_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_Write(client->ssl, clientData, sizeof(clientData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(clientData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readData, sizeof(readData), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(clientData));
    ASSERT_EQ(memcmp(clientData, readData, readLen), 0);

    memset(readData, 0, sizeof(readData));
    readLen = 0;
    writeLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, serverData, sizeof(serverData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(serverData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readData, sizeof(readData), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(serverData));
    ASSERT_EQ(memcmp(serverData, readData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */
