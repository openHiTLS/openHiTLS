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
#include <string.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "hitls_security.h"
#include "common_func.h"
#include "frame_tls.h"
#include "frame_link.h"
/* END_HEADER */

/* Certificate chain (mixed_sig):
 *   Root CA:  self-signed RSA_PKCS1_SHA256
 *   Inter CA: signed by Root with RSA_PKCS1_SHA384  (differs from EE)
 *   EE cert:  signed by Inter with RSA_PKCS1_SHA256
 *
 * When the verifier's signAlgorithms only includes RSA_PKCS1_SHA256,
 * the intermediate CA's SHA384 sigalg is not in the list.
 */

/* @
* @test  SDV_HiTLS_CHAIN_SIG_ALG_SET_GET_API_TC001
* @title  Test HITLS_CFG_SetChainSigAlgCheck / HITLS_CFG_GetChainSigAlgCheck API.
* @precon  nan
* @brief  1. Call Set/Get with NULL config, expect HITLS_NULL_INPUT.
*         2. Create a TLS1.2 config, verify default is false.
*         3. Set to true, verify Get returns true.
*         4. Set back to false, verify Get returns false.
* @expect 1. HITLS_NULL_INPUT returned.
*         2. Default is false.
*         3. Set/Get succeed, value is true.
*         4. Set/Get succeed, value is false.
@ */
/* BEGIN_CASE */
void SDV_HiTLS_CHAIN_SIG_ALG_SET_GET_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    bool isCheck = true;

    ASSERT_EQ(HITLS_CFG_SetChainSigAlgCheck(config, true), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_GetChainSigAlgCheck(config, &isCheck), HITLS_NULL_INPUT);

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ASSERT_EQ(HITLS_CFG_GetChainSigAlgCheck(config, &isCheck), HITLS_SUCCESS);
    ASSERT_EQ(isCheck, false);

    ASSERT_EQ(HITLS_CFG_SetChainSigAlgCheck(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetChainSigAlgCheck(config, &isCheck), HITLS_SUCCESS);
    ASSERT_EQ(isCheck, true);

    ASSERT_EQ(HITLS_CFG_SetChainSigAlgCheck(config, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetChainSigAlgCheck(config, &isCheck), HITLS_SUCCESS);
    ASSERT_EQ(isCheck, false);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  SDV_HiTLS_CHAIN_SIG_ALG_SERVER_SEND_TC001
* @title  Server sends cert chain, client verifies chain sigalg.
* @precon  Server uses mixed_sig chain (EE SHA256, inter CA SHA384).
*         Client signAlgorithms only includes RSA_PKCS1_SHA256.
* @brief  1. Client enables chain sigalg check (isCheck=1), handshake fails
*            because inter CA SHA384 not in client's signAlgorithms.
*         2. Client disables chain sigalg check (isCheck=0), handshake succeeds.
* @expect 1. Handshake fails.
*         2. Handshake succeeds.
@ */
/* BEGIN_CASE */
void SDV_HiTLS_CHAIN_SIG_ALG_SERVER_SEND_TC001(int isCheck)
{
#if !(defined(HITLS_TLS_PROTO_TLS12) && defined(HITLS_BSL_UIO_TCP))
    SKIP_TEST();
#else
    FRAME_Init();

    FRAME_CertInfo certInfo = {
        .caFile = MIXED_SIG_CA_PATH,
        .chainFile = MIXED_SIG_CHAIN_PATH,
        .endEquipmentFile = MIXED_SIG_EE_PATH,
        .privKeyFile = MIXED_SIG_PRIV_PATH,
    };
    uint16_t sha256Only[] = { CERT_SIG_SCHEME_RSA_PKCS1_SHA256 };

    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    HITLS_CFG_SetSecurityCb(clientConfig, NULL);
    HITLS_CFG_SetSecurityCb(serverConfig, NULL);
    HITLS_CFG_SetSignature(clientConfig, sha256Only, sizeof(sha256Only) / sizeof(uint16_t));
    if (isCheck) {
        ASSERT_EQ(HITLS_CFG_SetChainSigAlgCheck(clientConfig, true), HITLS_SUCCESS);
    }

    client = FRAME_CreateLinkWithCert(clientConfig, BSL_UIO_TCP, &certInfo);
    server = FRAME_CreateLinkWithCert(serverConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL && server != NULL);

    if (isCheck) {
        ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    } else {
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    }

EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
#endif
}
/* END_CASE */

/* @
* @test  SDV_HiTLS_CHAIN_SIG_ALG_CLIENT_SEND_TC001
* @title  Client sends cert chain, server verifies chain sigalg (mutual auth).
* @precon  Client uses mixed_sig chain (EE SHA256, inter CA SHA384).
*         Server signAlgorithms only includes RSA_PKCS1_SHA256.
* @brief  1. Server enables chain sigalg check (isCheck=1), handshake fails
*            because client's inter CA SHA384 not in server's signAlgorithms.
*         2. Server disables chain sigalg check (isCheck=0), handshake succeeds.
* @expect 1. Handshake fails.
*         2. Handshake succeeds.
@ */
/* BEGIN_CASE */
void SDV_HiTLS_CHAIN_SIG_ALG_CLIENT_SEND_TC001(int isCheck)
{
#if !(defined(HITLS_TLS_PROTO_TLS12) && defined(HITLS_BSL_UIO_TCP))
    SKIP_TEST();
#else
    FRAME_Init();

    FRAME_CertInfo certInfo = {
        .caFile = MIXED_SIG_CA_PATH,
        .chainFile = MIXED_SIG_CHAIN_PATH,
        .endEquipmentFile = MIXED_SIG_EE_PATH,
        .privKeyFile = MIXED_SIG_PRIV_PATH,
    };
    uint16_t sha256Only[] = { CERT_SIG_SCHEME_RSA_PKCS1_SHA256 };

    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    HITLS_CFG_SetSecurityCb(clientConfig, NULL);
    HITLS_CFG_SetSecurityCb(serverConfig, NULL);
    HITLS_CFG_SetClientVerifySupport(serverConfig, true);
    HITLS_CFG_SetSignature(serverConfig, sha256Only, sizeof(sha256Only) / sizeof(uint16_t));
    if (isCheck) {
        ASSERT_EQ(HITLS_CFG_SetChainSigAlgCheck(serverConfig, true), HITLS_SUCCESS);
    }

    client = FRAME_CreateLinkWithCert(clientConfig, BSL_UIO_TCP, &certInfo);
    server = FRAME_CreateLinkWithCert(serverConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL && server != NULL);

    if (isCheck) {
        ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    } else {
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    }

EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
#endif
}
/* END_CASE */
