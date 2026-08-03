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
#include "hitls_type.h"
#include "common_func.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "record.h"
#include "rec_crypto.h"
/* END_HEADER */

#ifdef HITLS_TLS_PROTO_DATAGRAM
void DtlsPlainMsgGenerate(REC_TextInput *plainMsg, const TLS_Ctx *ctx,
    REC_Type recordType, const uint8_t *data, uint32_t plainLen, uint64_t epochSeq);
#endif

#define READ_BUF_SIZE 18432

/* @
* @test  SDV_HiTLS_ETM_DTLS12_RENEGOTIATE_MTE_TO_ETM_TC001
* @title DTLS1.2 CBC renegotiation from Mac-then-Encrypt to Encrypt-then-MAC should succeed.
* @precon nan
* @brief
*   1. Establish a DTLS1.2 CBC PSK connection with EncryptThenMac disabled.
*   2. Enable EncryptThenMac on both endpoints and start renegotiation.
*   3. Complete renegotiation and exchange one application data record.
* @expect
*   1. The first handshake succeeds without EncryptThenMac.
*   2. Renegotiation succeeds and EncryptThenMac is negotiated.
*   3. Application data is written and read successfully after renegotiation.
@ */
/* BEGIN_CASE */
void SDV_HiTLS_ETM_DTLS12_RENEGOTIATE_MTE_TO_ETM_TC001()
{
#if !(defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP) && \
    defined(HITLS_TLS_FEATURE_ETM) && defined(HITLS_TLS_FEATURE_RENEGOTIATION) && \
    defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA) && !defined(HITLS_TLS_FEATURE_PROVIDER))
    SKIP_TEST();
#else
    FRAME_Init();

    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    clientConfig = HITLS_CFG_NewDTLS12Config();
    serverConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(serverConfig != NULL);

    uint16_t cipherSuite = HITLS_PSK_WITH_AES_128_CBC_SHA;
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(clientConfig, &cipherSuite, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(serverConfig, &cipherSuite, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(clientConfig, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(serverConfig, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetRenegotiationSupport(clientConfig, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetRenegotiationSupport(serverConfig, true), HITLS_SUCCESS);
    HITLS_CFG_SetPskClientCallback(clientConfig, ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(serverConfig, ExampleServerCb);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    bool encryptThenMac = true;
    ASSERT_EQ(HITLS_GetEncryptThenMac(client->ssl, &encryptThenMac), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMac, false);
    ASSERT_EQ(HITLS_GetEncryptThenMac(server->ssl, &encryptThenMac), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMac, false);

    ASSERT_EQ(HITLS_SetEncryptThenMac(client->ssl, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetEncryptThenMac(server->ssl, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Renegotiate(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Renegotiate(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiation(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_GetEncryptThenMac(client->ssl, &encryptThenMac), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMac, true);
    ASSERT_EQ(HITLS_GetEncryptThenMac(server->ssl, &encryptThenMac), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMac, true);

    uint8_t msg[] = {0x01, 0x02, 0x03};
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(client->ssl, msg, sizeof(msg), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(msg));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(msg));
    ASSERT_EQ(memcmp(msg, readBuf, sizeof(msg)), 0);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */

/* @
* @test  SDV_HiTLS_ETM_DTLS12_RECORD_WRITE_STATE_TC001
* @title DTLS CBC record write should use the active write ETM state.
* @precon nan
* @brief
*   1. Establish a DTLS1.2 CBC PSK connection.
*   2. Simulate the renegotiation window where the next negotiated ETM value differs from the active write state.
*   3. Calculate ciphertext length through the active write state and encrypt one record.
* @expect
*   1. Encryption succeeds because length calculation and encryption use the same active write state.
@ */
/* BEGIN_CASE */
void SDV_HiTLS_ETM_DTLS12_RECORD_WRITE_STATE_TC001()
{
#if !(defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_TLS_PROTO_DATAGRAM) && defined(HITLS_BSL_UIO_UDP) && \
    defined(HITLS_TLS_FEATURE_ETM) && defined(HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA) && \
    !defined(HITLS_TLS_FEATURE_PROVIDER))
    SKIP_TEST();
#else
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);

    uint16_t cipherSuite = HITLS_PSK_WITH_AES_128_CBC_SHA;
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(tlsConfig, &cipherSuite, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(tlsConfig, true), HITLS_SUCCESS);
    HITLS_CFG_SetPskClientCallback(tlsConfig, ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(tlsConfig, ExampleServerCb);

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    RecConnState *state = client->ssl->recCtx->writeStates.currentState;
    client->ssl->negotiatedInfo.isEncryptThenMac = true;
    state->isEncryptThenMac = false;

    uint8_t msg[] = {0x01};
    uint64_t epochSeq = REC_EPOCHSEQ_CAL(RecConnGetEpoch(state), state->seq);
    REC_TextInput plainMsg = {0};
    DtlsPlainMsgGenerate(&plainMsg, client->ssl, REC_TYPE_APP, msg, sizeof(msg), epochSeq);

    uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(
        client->ssl, state->suiteInfo, sizeof(msg), false);
    uint8_t cipherText[128] = {0};
    ASSERT_EQ(RecConnEncrypt(client->ssl, state, &plainMsg, cipherText, ciphertextLen), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */
