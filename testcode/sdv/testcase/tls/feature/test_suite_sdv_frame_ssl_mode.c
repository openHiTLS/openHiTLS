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
#include "hlt.h"
#include "hitls_error.h"
#include "hitls_func.h"
#include "conn_init.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "alert.h"
#include "stub_utils.h"
#include "hs_common.h"
#include "change_cipher_spec.h"
#include "hs.h"
#include "simulate_io.h"
#include "rec_header.h"
#include "rec_wrapper.h"
#include "record.h"
#include "rec.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, APP_Read, TLS_Ctx *, uint8_t *, uint32_t, uint32_t *);

// Local helper function to replace app.c inclusion
static int32_t ReadAppData(TLS_Ctx *ctx, uint8_t *buf, uint32_t num, uint32_t *readLen)
{
    return REC_Read(ctx, REC_TYPE_APP, buf, readLen, num);
}


#define READ_BUF_SIZE 18432
#define MAX_DIGEST_SIZE 64UL /* The longest known is SHA512 */
uint32_t g_uiPort = 8890;
static uint32_t g_time = 0;
int32_t STUB_APP_Read(TLS_Ctx *ctx, uint8_t *buf, uint32_t num, uint32_t *readLen)
{
    int32_t ret;
    uint32_t readbytes;

    g_time++;
    if(g_time == 2) {
        return HITLS_REC_ERR_IO_EXCEPTION;
    }
    if (ctx == NULL || buf == NULL || num == 0) {
        return HITLS_APP_ERR_ZERO_READ_BUF_LEN;
    }
    // read data to the buffer in non-blocking mode
    do {
        ret =  ReadAppData(ctx, buf, num, &readbytes);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    } while (readbytes == 0); // do not exit the loop until data is read

    *readLen = readbytes;
    return HITLS_SUCCESS;
}

/** @
* @test UT_TLS_CM_SSL_MODE_AUTO_RETRY_TC001
* @title UT_TLS_CM_SSL_MODE_AUTO_RETRY_TC001
* @brief
*   1. Create connection. Expected result 1 is obtained.
*   2. Unset the auto retry mode, get keyupdate message. Expected result 2 is obtained.
* @expect
*   1. Successfully created connection.
*   2. After receive keyupdate message, the link will not try to read another app message
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SSL_MODE_AUTO_RETRY_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    config->isSupportRenegotiation = true;
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(config, true), HITLS_SUCCESS);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    uint16_t cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA256;
    int32_t ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Error stack exists
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint32_t len = 0;
    ASSERT_TRUE(HITLS_Write(client->ssl, (uint8_t *)"Hello World", strlen("Hello World"), &len) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ret = HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_NOT_REQUESTED);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_ClearModeSupport(server->ssl, HITLS_MODE_AUTO_RETRY) == HITLS_SUCCESS);
    g_time = 0;
    STUB_REPLACE(APP_Read, STUB_APP_Read);;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_RESTORE(APP_Read);
    g_time = 0;
}
/* END_CASE */

/** @
* @test UT_TLS_CM_SSL_MODE_AUTO_RETRY_TC002
* @title UT_TLS_CM_SSL_MODE_AUTO_RETRY_TC002
* @brief
*   1. Create connection. Expected result 1 is obtained.
*   2. Unset the auto retry mode, Send Hello request. Expected result 2 is obtained.
* @expect
*   1. Successfully created connection.
*   2. After receive Hello request and send no_renegotiation alert, the link will not try to read another app message
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SSL_MODE_AUTO_RETRY_TC002()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    config->isSupportRenegotiation = true;

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    uint16_t cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA256;
    int32_t ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Error stack exists
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint32_t len = 0;
    ASSERT_TRUE(HITLS_Write(client->ssl, (uint8_t *)"Hello World", strlen("Hello World"), &len) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_EQ(HITLS_SetRenegotiationSupport(client->ssl, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Renegotiate(server->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_ClearModeSupport(client->ssl, HITLS_MODE_AUTO_RETRY) == HITLS_SUCCESS);
    g_time = 0;
    STUB_REPLACE(APP_Read, STUB_APP_Read);;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_RESTORE(APP_Read);
    g_time = 0;
}
/* END_CASE */

/** @
* @test UT_TLS_CM_SSL_MODE_MOVE_BUFFER_TC001
* @title UT_TLS_CM_SSL_MODE_MOVE_BUFFER_TC001
* @brief
*   1. Create connection. Expected result 1 is obtained.
*   2. Set moving buffer mode, when io busy, using different buffer retry. Expected result 2 is obtained.
* @expect
*   1. Successfully created connection.
*   2. Retry success.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SSL_MODE_MOVE_BUFFER_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    config->isSupportRenegotiation = true;
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(config, true), HITLS_SUCCESS);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    uint16_t cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA256;
    int32_t ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Error stack exists
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_SetModeSupport(client->ssl, HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER) == HITLS_SUCCESS);

    uint8_t data[] = "hello world";
    uint8_t data2[] = "hello world";
    uint32_t len = 0;
    ASSERT_TRUE(HITLS_Write(client->ssl, data, sizeof(data), &len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Write(client->ssl, data, sizeof(data), &len) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Write(client->ssl, data2, sizeof(data2), &len), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_CM_SSL_MODE_MOVE_BUFFER_TC002
* @title UT_TLS_CM_SSL_MODE_MOVE_BUFFER_TC002
* @brief
*   1. Create connection. Expected result 1 is obtained.
*   2. Set moving buffer mode, when io busy, using shorter buffer retry. Expected result 2 is obtained.
* @expect
*   1. Successfully created connection.
*   2. Send alert. Before send alert, flush the out buffer first.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SSL_MODE_MOVE_BUFFER_TC002()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    config->isSupportRenegotiation = true;
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(config, true), HITLS_SUCCESS);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    uint16_t cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA256;
    int32_t ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_SetModeSupport(client->ssl, HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER) == HITLS_SUCCESS);

    uint8_t data[] = "hello world";
    uint32_t len = 0;
    ASSERT_TRUE(HITLS_Write(client->ssl, data, sizeof(data), &len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Write(client->ssl, data, sizeof(data), &len) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_TRUE(readLen == sizeof(data));
    ASSERT_TRUE(memcmp("hello world", readBuf, readLen) == 0);

    ASSERT_EQ(HITLS_Write(client->ssl, data, 1, &len), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTING);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

    ASSERT_EQ(HITLS_Write(client->ssl, data, 1, &len), HITLS_CM_LINK_FATAL_ALERTED);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(server->ssl->state, CM_STATE_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_CM_SSL_MODE_RELEASE_BUFFER_TC001
* @title UT_TLS_CM_SSL_MODE_RELEASE_BUFFER_TC001
* @brief
*   1. Set release buffer mode. Create connection. Expected result 1 is obtained.
* @expect
*   1. Successfully created connection.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SSL_MODE_RELEASE_BUFFER_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    config->isSupportRenegotiation = true;
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(config, true), HITLS_SUCCESS);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    uint16_t cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA256;
    int32_t ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_SetModeSupport(client->ssl, HITLS_MODE_RELEASE_BUFFERS) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_SetModeSupport(server->ssl, HITLS_MODE_RELEASE_BUFFERS) == HITLS_SUCCESS);
    // Error stack exists
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint32_t len = 0;
    ASSERT_TRUE(HITLS_Write(client->ssl, (uint8_t *)"Hello World", strlen("Hello World"), &len) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */