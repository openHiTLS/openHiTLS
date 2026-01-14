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
#include "frame_link.h"
#include "hitls_type.h"
#include "rec_wrapper.h"
#include "hs_ctx.h"
#include "tls.h"
#include "bsl_list.h"
#include "hitls_config.h"
#include "alert.h"
#include "hitls_func.h"
/* END_HEADER */

static void CaListNodeInnerDestroy(void *data)
{
    HITLS_TrustedCANode *tmpData = (HITLS_TrustedCANode *)data;
    BSL_SAL_FREE(tmpData->data);
    BSL_SAL_FREE(tmpData);
    return;
}
/**
 * @test  UT_TLS_TLS13_RECV_CA_LIST_TC001
 * @brief 1. Use the default configuration items to configure the client and server, Expect result 1.
 *        2. Load the CA file into the configuration, Expect result 1.
 *        3. Set the CA list in the configuration, Expect result 1.
 *        4. Create the client and server links, Expect result 2.
 * @expect 1. HITLS_SUCCESS
 *         2. caList->count == 1
 */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_LoadCAFile_API_TC001(int version, char *certFile, char *userdata)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_TrustedCAList *caList = NULL;
    ASSERT_TRUE(HITLS_CFG_SetDefaultPasswordCbUserdata(tlsConfig, userdata) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetDefaultPasswordCbUserdata(tlsConfig) == userdata);
    ASSERT_TRUE(HITLS_CFG_ParseCAList(tlsConfig, certFile, (uint32_t)strlen(certFile), TLS_PARSE_TYPE_FILE,
                                      TLS_PARSE_FORMAT_ASN1, &caList) == HITLS_SUCCESS);
    ASSERT_TRUE(caList != NULL);
    ASSERT_TRUE(caList->count == 1);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    BSL_LIST_FREE(caList, CaListNodeInnerDestroy);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RECV_CA_LIST_TC001
* @spec  -
* @title  The CA list is parsed correctly.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server, Expect result 1.
*         2. Load the CA file into the configuration, Expect result 1.
*         3. Set the CA list in the configuration, Expect result 1.
*         4. Create the client and server links, Expect result 1.
*         5. Create the connection between the client and server, Expect result 2.
*         6. Get the peer CA list from the server, Expect result 1.
*         7. Verify that the peer CA list is not NULL and contains one CA, Expect result 3.
* @expect 1. HITLS_SUCCESS
*         2. link established successfully
*         3. peerList != NULL
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RECV_CA_LIST_TC001(char *certFile)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();

    ASSERT_TRUE(config != NULL);
    HITLS_TrustedCAList *caList = NULL;
    ASSERT_TRUE(HITLS_CFG_ParseCAList(config, certFile, (uint32_t)strlen(certFile), TLS_PARSE_TYPE_FILE,
                                      TLS_PARSE_FORMAT_ASN1, &caList) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetCAList(config, caList) == HITLS_SUCCESS);
    ASSERT_TRUE(caList != NULL);
    ASSERT_TRUE(caList->count == 1);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_TrustedCAList *peerList = HITLS_GetPeerCAList(server->ssl);
    ASSERT_TRUE(peerList != NULL);
    ASSERT_TRUE(peerList->count == 1);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS12_RECV_CA_LIST_TC001
* @spec  -
* @title  The CA list is parsed correctly.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server, Expect result 1.
*         2. Load the CA file into the configuration, Expect result 1.
*         3. Set the CA list in the configuration, Expect result 1.
*         4. set ClientVerifySupport, Expect result 1.
*         4. Create the client and server links, Expect result 1.
*         5. Create the connection between the client and server, Expect result 2.
*         6. Get the peer CA list from the server, Expect result 1.
*         7. Verify that the peer CA list is not NULL and contains one CA, Expect result 3.
* @expect 1. HITLS_SUCCESS
*         2. link established successfully
*         3. peerList != NULL
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RECV_CA_LIST_TC001(char *certFile)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();

    ASSERT_TRUE(config != NULL);
    HITLS_TrustedCAList *caList = NULL;
    ASSERT_TRUE(HITLS_CFG_ParseCAList(config, certFile, (uint32_t)strlen(certFile), TLS_PARSE_TYPE_FILE,
                                      TLS_PARSE_FORMAT_ASN1, &caList) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetCAList(config, caList) == HITLS_SUCCESS);
    HITLS_CFG_SetClientVerifySupport(config, true);
    ASSERT_TRUE(caList != NULL);
    ASSERT_TRUE(caList->count == 1);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    // Error stack is empty
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_TrustedCAList *peerList = HITLS_GetPeerCAList(client->ssl);
    ASSERT_TRUE(peerList != NULL);
    ASSERT_TRUE(peerList->count == 1);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */