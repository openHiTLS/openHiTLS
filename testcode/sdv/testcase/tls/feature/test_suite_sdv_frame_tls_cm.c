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
#include <unistd.h>
#include <semaphore.h>
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "hitls.h"
#include "app_enc.h"
#include "bsl_errno.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "bsl_sal.h"
#include "bsl_uio.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include "hitls_error.h"
#include "tls.h"
#include "sal_net.h"
#include "bsl_base64.h"
#include "uio_base.h"
#include "bsl_buffer.h"
#include "sal_atomic.h"
#include "uio_abstraction.h"
#include <time.h>
#include "bsl_err_internal.h"
#include "simulate_io.h"
/* END_HEADER */

/* @
* @test  HITLS_clear_SDV_23_1_0_002
* @spec  -
* @title  TLS1.2 protocol, reset CTX, establish a new link, and use the same peer.
* @precon  nan
* @brief
1. Create a TLS1.2 link and suspend the link status to CM_STATE_TRANSPORTING. Expected result 1 is obtained.
2. Close the link, invoke the HITLS_clear API, and clear the CTX related to the link. (Expected result 2)
3. Use the config file to establish a new link. Expected result 3 is obtained.
4. Use the original session ID to restore the session. Expected result 4 is obtained.
* @expect
1. The current link status is CM_STATE_TRANSPORTING.
2. Clear the CTX configuration. Configure the following reserved items: isClient, rUio, uio, bUio, peerInfo, negotiatedInfo, and session.
3. The password and BIOS of the new link are the same.
4. The session is restored successfully.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_clear_SDV_23_1_0_002()
{
    FRAME_Init();
    HITLS_Config *config_resume = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    HITLS_CFG_SetQuietShutdown(config, true);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    // Obtain the client session for session recovery.
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    /* Disable the secure transmission link. Check that the status of the client secure link is CM_STATE_ CLOSED */
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);
    ASSERT_TRUE(clientTlsCtx->recCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == true);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_TRANSPORTING);
    ASSERT_EQ(clientTlsCtx->shutdownState, 3);
    ASSERT_TRUE(clientTlsCtx->userShutDown == true);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList != NULL);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, HITLS_VERSION_TLS12);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, HITLS_VERSION_TLS12);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session != NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS12_VERSION_BIT);

    ASSERT_TRUE(HITLS_Clear(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Clear(serverTlsCtx) == HITLS_SUCCESS);
    // Clear CTX-related items after the HITLS_Clear interface is called.
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->recCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 0);
    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    // The clientVersion is cleared.
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, 0);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, 0);

    // Reserve CTX-related items after the HITLS_Clear interface is called.
    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList == NULL);

    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session != NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS12_VERSION_BIT);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    config_resume = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_resume != NULL);
    HITLS_CFG_SetSignature(config_resume, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(config_resume);
    HITLS_SESS_Free(clientSession);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_clear_SDV_23_1_0_003
* @spec  -
* @title  When the TLS1.3 protocol is used, the CTX is reset, a new link is set up, and the peer is the same.
* @precon  nan
* @brief
1. Create a TLS1.3 link and suspend the link status to CM_STATE_TRANSPORTING. Expected result 1 is obtained.
2. Close the link, invoke the HITLS_clear API, and clear the CTX files related to the link. (Expected result 2)
3. Use the config file to establish a new link. Expected result 3 is obtained.
4. Use the original session ID to restore the session. Expected result 4 is obtained.
* @expect
1. Create a TLS1.3 link and suspend the link status to CM_STATE_ HANDSHAKING. Expected result 1 is obtained.
2. Close the link, invoke the HITLS_clear API, and clear the CTX files related to the link. (Expected result 2)
3. Use the config file to establish a new link. Expected result 3 is obtained.
4. Use the original session ID to restore the session. Expected result 4 is obtained.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_clear_SDV_23_1_0_003()
{
    FRAME_Init();
    HITLS_Config *config_resume = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetQuietShutdown(config, true);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    /* Disable the secure transmission link and query the client's secure link state. The status is CM_STATE_Closed. */
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);
    ASSERT_TRUE(clientTlsCtx->recCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == true);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 3);
    ASSERT_TRUE(clientTlsCtx->userShutDown == true);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList != NULL);
    // The negotiated version is tls1.2, which comes from legacy_version in clienhello.
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, HITLS_VERSION_TLS12);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, HITLS_VERSION_TLS13);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session!= NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS13_VERSION_BIT);

    ASSERT_TRUE(HITLS_Clear(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Clear(serverTlsCtx) == HITLS_SUCCESS);
    // Clear CTX-related items after the HITLS_Clear interface is called.
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->recCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 0);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, 0);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, 0);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList == NULL);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session != NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS13_VERSION_BIT);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    config_resume = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_resume != NULL);

    client = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(config_resume);
    HITLS_SESS_Free(clientSession);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_clear_SDV_23_1_0_005
* @spec  -
* @title  Reset the CTX and create a new link. The original link is not closed. The link is deleted from the session cache.
* @precon  nan
* @brief
1. Invoke the HITLS_Close interface. Before the closenotify response is received, invoke the HITLS_clear interface. Expected result 1 is obtained.
2. Use the original session ID to restore the session. Expected result 2 is obtained.
* @expect
1. The interface is invoked successfully.
2. Session restoration fails.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_clear_SDV_23_1_0_005()
{
    FRAME_Init();
    HITLS_Config *config_resume = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    HITLS_CFG_SetQuietShutdown(config, true);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_FINISH);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->sndMsg.len = 0;
    ioClientData->recMsg.len = 0;
    ioServerData->sndMsg.len = 0;
    ioServerData->recMsg.len = 0;

    HITLS_Session *serverSession = HITLS_GetDupSession(server->ssl);
    ASSERT_TRUE(serverSession != NULL);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(clientTlsCtx->recCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx !=NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 0);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList != NULL);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, HITLS_VERSION_TLS12);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session == NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS12_VERSION_BIT);

    ASSERT_TRUE(HITLS_Clear(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Clear(serverTlsCtx) == HITLS_SUCCESS);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->recCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 0);
    ASSERT_TRUE(clientTlsCtx->userShutDown == false);

    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, 0);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList == NULL);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session == NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS12_VERSION_BIT);

    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    config_resume = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_resume != NULL);
    HITLS_CFG_SetSignature(config_resume, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(server->ssl, serverSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(config_resume);
    HITLS_SESS_Free(serverSession);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_clear_SDV_23_1_0_004
* @spec  -
* @title  Reset the CTX and establish a new link. However, the original link is still in the open state and is deleted from the session cache.
* @precon  nan
* @brief
1. Invoke the HITLS_clear API without calling HITLS_Close. Expected result 1 is obtained.
2. Use the original session ID to restore the session. Expected result 2 is obtained.
* @expect
1. The interface is invoked successfully.
2. Session restoration fails.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_clear_SDV_23_1_0_004()
{
    FRAME_Init();
    HITLS_Config *config_resume = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    HITLS_CFG_SetQuietShutdown(config, true);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_KEY_EXCHANGE);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->sndMsg.len = 0;
    ioClientData->recMsg.len = 0;
    ioServerData->sndMsg.len = 0;
    ioServerData->recMsg.len = 0;

    HITLS_Session *serverSession = HITLS_GetDupSession(server->ssl);
    ASSERT_TRUE(serverSession == NULL);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(clientTlsCtx->recCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx !=NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_EQ(clientTlsCtx->preState, CM_STATE_IDLE);
    ASSERT_EQ(clientTlsCtx->shutdownState, 0);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList != NULL);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, HITLS_VERSION_TLS12);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session == NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS12_VERSION_BIT);

    ASSERT_TRUE(HITLS_Clear(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Clear(serverTlsCtx) == HITLS_SUCCESS);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->recCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 0);
    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, 0);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList == NULL);

    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session == NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS12_VERSION_BIT);

    // Reuse the original CTX to create a new link.
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    config_resume = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_resume != NULL);
    HITLS_CFG_SetSignature(config_resume, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(server->ssl, serverSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(config_resume);
    HITLS_SESS_Free(serverSession);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_clear_SDV_23_1_0_006
* @spec  -
* @title  Reset the CTX and establish a new link. The peer version of the new link is different from the original version.
* @precon  nan
* @brief
1. Start link establishment. Expected result 1 is obtained.
* @expect
1. Link establishment fails.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_clear_SDV_23_1_0_006()
{
    FRAME_Init();
    HITLS_Config *config_resume = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    HITLS_CFG_SetQuietShutdown(config, true);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);
    ASSERT_TRUE(clientTlsCtx->recCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx!=NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);

    ASSERT_TRUE(clientTlsCtx->userShutDown == true);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 3);
    ASSERT_TRUE(clientTlsCtx->userShutDown == true);

    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList != NULL);
    // Negotiated version is tls1.2, old version in clienthello
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, HITLS_VERSION_TLS12);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, HITLS_VERSION_TLS13);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session!= NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS13_VERSION_BIT);

    ASSERT_EQ(HITLS_Clear(NULL), HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_Clear(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Clear(serverTlsCtx) == HITLS_SUCCESS);
    // Clear CTX-related items after the HITLS_Clear interface is called.
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->recCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->alertCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->ccsCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->hsCtx ==NULL);
    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    ASSERT_TRUE(clientTlsCtx->userRenego == false);
    ASSERT_TRUE(clientTlsCtx->rwstate == HITLS_NOTHING);
    ASSERT_TRUE(clientTlsCtx->preState == CM_STATE_IDLE);
    ASSERT_TRUE(clientTlsCtx->shutdownState == 0);
    ASSERT_TRUE(clientTlsCtx->userShutDown == false);
    // clientVersion is cleared.
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.clientVersion, 0);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, 0);

    // After the HITLS_Clear interface is called, the CTX-related items are retained.
    ASSERT_TRUE(clientTlsCtx->isClient == true);
    ASSERT_TRUE(clientTlsCtx->rUio!= NULL);
    ASSERT_TRUE(clientTlsCtx->uio!= NULL);
    ASSERT_TRUE(clientTlsCtx->bUio== NULL);
    ASSERT_TRUE(clientTlsCtx->peerInfo.caList == NULL);
    ASSERT_TRUE(clientTlsCtx->clientAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->serverAppTrafficSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->resumptionMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->exporterMasterSecret != NULL);
    ASSERT_TRUE(clientTlsCtx->keyUpdateType == 255);
    ASSERT_TRUE(clientTlsCtx->isKeyUpdateRequest == false);
    ASSERT_TRUE(clientTlsCtx->haveClientPointFormats == false);

    ASSERT_TRUE(clientTlsCtx->session != NULL);
    ASSERT_EQ(clientTlsCtx->config.tlsConfig.version, TLS13_VERSION_BIT);

    HITLS_Config *config_server = HITLS_CFG_NewTLS12Config();
    FRAME_LinkObj *server1 = FRAME_CreateLink(config_server, BSL_UIO_TCP);
    ASSERT_TRUE(server1 != NULL);

    HITLS_Ctx *clientTlsCtx1 = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx1->state == CM_STATE_IDLE);
    /* The original CTX is reused to create a new link. Due to version inconsistency, the algorithm suite does not match, and the negotiation fails. */
    /* The client invokes the HITLS_Connect interface to complete the handshake process. The security link status is CM_STATE_TRANSPORTING. */
    ASSERT_EQ(FRAME_CreateConnection(client, server1, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
    ASSERT_TRUE(clientTlsCtx1->state == CM_STATE_HANDSHAKING);
    ASSERT_EQ(clientTlsCtx1->negotiatedInfo.clientVersion, HITLS_VERSION_TLS12);
    ASSERT_EQ(clientTlsCtx1->negotiatedInfo.version, 0);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    FRAME_FreeLink(server1);
    server1 = NULL;
    config_resume = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_resume != NULL);

    client = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_resume, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(config_server);
    HITLS_CFG_FreeConfig(config_resume);
    HITLS_SESS_Free(clientSession);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    FRAME_FreeLink(server1);
}
/* END_CASE */