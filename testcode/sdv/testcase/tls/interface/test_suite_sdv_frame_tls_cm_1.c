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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>
#include <regex.h>
#include <pthread.h>
#include <unistd.h>
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
#include <sys/ioctl.h>
#include "securec.h"
#include "bsl_sal.h"
#include "sal_net.h"
#include "frame_tls.h"
#include "cert_callback.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "frame_io.h"
#include "uio_abstraction.h"
#include "tls.h"
#include "tls_config.h"
#include "logger.h"
#include "process.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "stub_replace.h"
#include "hitls_type.h"
#include "frame_link.h"
#include "session_type.h"
#include "common_func.h"
#include "hitls_func.h"
#include "hitls_cert_type.h"
#include "cert_mgr_ctx.h"
#include "parser_frame_msg.h"
#include "recv_process.h"
#include "simulate_io.h"
#include "rec_wrapper.h"
#include "cipher_suite.h"
#include "alert.h"
#include "conn_init.h"
#include "pack.h"
#include "send_process.h"
#include "cert.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "hs.h"
#include "hs_state_recv.h"
#include "app.h"
#include "record.h"
#include "rec_conn.h"
#include "session.h"
#include "frame_msg.h"
#include "pack_frame_msg.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "sctp_channel.h"
#include "hitls_crypt_init.h"
#include "hitls_session.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "hitls_crypt_reg.h"
#include "crypt_errno.h"
#include "bsl_list.h"
#include "hitls_cert.h"
#include "parse_extensions_client.c"
#include "parse_extensions_server.c"
#include "parse_server_hello.c"
#include "parse_client_hello.c"
/* END_HEADER */

static char *g_serverName = "testServer";
uint32_t g_uiPort = 18888;
#define DEFAULT_DESCRIPTION_LEN 128
#define TLS_DHE_PARAM_MAX_LEN 1024
#define GET_GROUPS_CNT (-1)
#define READ_BUF_SIZE (18 * 1024)
#define ALERT_BODY_LEN 2u

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *s_config;
    HITLS_Config *c_config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
    HITLS_TicketKeyCb serverKeyCb;
} ResumeTestInfo;

int32_t HITLS_RemoveCertAndKey(HITLS_Ctx *ctx);
HITLS_CRYPT_Key *cert_key = NULL;
HITLS_CRYPT_Key *DH_CB(HITLS_Ctx *ctx, int32_t isExport, uint32_t keyLen)
{
    (void)ctx;
    (void)isExport;
    (void)keyLen;
    return cert_key;
}

void *STUB_SAL_Calloc(uint32_t num, uint32_t size)
{
    (void)num;
    (void)size;
    return NULL;
}

void *STUB_SAL_Dump(const void *src, uint32_t size)
{
    (void)src;
    (void)size;
    return NULL;
}

FuncStubInfo g_TmpRpInfo = {0};

int32_t STUB_BSL_UIO_Read(BSL_UIO *uio, void *data, uint32_t len, uint32_t *readLen)
{
    (void)uio;
    (void)data;
    (void)len;
    (void)readLen;
    return 0;
}

static HITLS_Config *GetHitlsConfigViaVersion(int ver)
{
    switch (ver) {
        case HITLS_VERSION_TLS12:
            return HITLS_CFG_NewTLS12Config();
        case HITLS_VERSION_TLS13:
            return HITLS_CFG_NewTLS13Config();
        case HITLS_VERSION_DTLS12:
            return HITLS_CFG_NewDTLS12Config();
        default:
            return NULL;
    }
}

/** @
* @test  UT_TLS_CM_IS_DTLS_API_TC001
* @title Test HITLS_IsDtls
* @precon nan
* @brief HITLS_IsDtls
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer the non-empty TLS connection handle information and leave isDtls blank. Expected result 1.
* 3. Transfer the non-empty TLS connection handle information. The isDtls parameter is not empty. Expected result 2 is
*     obtained.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CM_IS_DTLS_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    uint8_t isDtls = 0;
    ASSERT_TRUE(HITLS_IsHandShakeDone(ctx, &isDtls) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_IsHandShakeDone(ctx, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_IsHandShakeDone(ctx, &isDtls) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_SET_CLEAR_CIPHERSUITES_API_TC001
* @title Test the HITLS_SetCipherSuites and HITLS_ClearTLS13CipherSuites interfaces.
* @precon nan
* @brief HITLS_SetCipherSuites
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer non-empty TLS connection handle information and leave cipherSuites empty. Expected result 1.
* 3. Transfer the non-empty TLS connection handle information. If cipherSuites is not empty and cipherSuitesSize is 0,
*   the expected result is 1.
* 4. Transfer the non-empty TLS connection handle information. Set cipherSuites to a value greater than
*   HITLS_CFG_MAX_SIZE. Expected result 2.
* 5. The input parameters are valid, and the SAL_CALLOC table is instrumented. Expected result 3.
* 6. Transfer the non-null TLS connection handle information, set cipherSuites to an invalid value, and set
*   cipherSuitesSize to a value smaller than HITLS_CFG_MAX_SIZE. Expected result 4 is displayed.
* 7. Transfer valid parameters. Expected result 5.
* HITLS_ClearTLS13CipherSuites
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer the non-empty TLS connection handle information. Expected result 5.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. Return HITLS_HITLS_CM_INVALID_LENGTH
* 3. Returns HITLS_MEMALLOC_FAIL
* 4. Return HITLS_HITLS_CM_NO_SUITABLE_CIPHER_SUITE
* 5. Returns HITLS_SUCCESS
@ */

/* BEGIN_CASE */
void UT_TLS_CM_SET_CLEAR_CIPHERSUITES_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    uint16_t cipherSuites[10] = {
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    };

    ASSERT_TRUE(HITLS_SetCipherSuites(ctx, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_ClearTLS13CipherSuites(ctx) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetCipherSuites(ctx, NULL, 0) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetCipherSuites(ctx, cipherSuites, 0) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetCipherSuites(ctx, cipherSuites, HITLS_CFG_MAX_SIZE + 1) == HITLS_CONFIG_INVALID_LENGTH);

    STUB_Init();
    FuncStubInfo tmpRpInfo;
    STUB_Replace(&tmpRpInfo, BSL_SAL_Calloc, STUB_SAL_Calloc);
    ASSERT_TRUE(
        HITLS_SetCipherSuites(ctx, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_MEMALLOC_FAIL);
    STUB_Reset(&tmpRpInfo);
    uint16_t cipherSuites2[10] = {0};
    cipherSuites2[0] = 0xFFFF;
    cipherSuites2[1] = 0xEFFF;
    ASSERT_TRUE(HITLS_SetCipherSuites(ctx, cipherSuites2, sizeof(cipherSuites2) / sizeof(uint16_t)) ==
                HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE);
    ASSERT_TRUE(HITLS_SetCipherSuites(ctx, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    if (tlsVersion == HITLS_VERSION_TLS13) {
        ASSERT_TRUE(HITLS_ClearTLS13CipherSuites(ctx) == HITLS_SUCCESS);
        ASSERT_TRUE(ctx->config.tlsConfig.tls13cipherSuitesSize == 0);
    }
EXIT:
    STUB_Reset(&tmpRpInfo);
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test     UT_TLS_CM_SET_GET_ENCRYPTHENMAC_FUNC_TC001
* @title HITLS_GetEncryptThenMac and HITLS_SetEncryptThenMac interface validation
* @precon nan
* @brief
* 1. After initialization, call the hitls_setencryptthenmac interface to set the value to true and call the
*   HITLS_GetEncryptThenMac interface to query the value. Expected result 1.
* 2. Set hitls_setencryptthenmac to true at both ends. After the connection is set up, invoke the HITLS_GetEncryptThenMac
*   interface to query the connection. Expected result 2.
* @expect
* 1. The return value is true.
* 2. The return value is true.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_ENCRYPTHENMAC_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);
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

    bool encryptThenMacType = 0;
    ASSERT_EQ(HITLS_GetEncryptThenMac(server->ssl, &encryptThenMacType), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMacType, 1);

    ASSERT_EQ(HITLS_GetEncryptThenMac(client->ssl, &encryptThenMacType), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMacType, 1);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_GetEncryptThenMac(server->ssl, &encryptThenMacType), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMacType, 1);
    ASSERT_EQ(HITLS_GetEncryptThenMac(client->ssl, &encryptThenMacType), HITLS_SUCCESS);
    ASSERT_EQ(encryptThenMacType, 1);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_SET_SERVERNAME_FUNC_TC001
* @title  HITLS_SetServerName invokes the interface to set the server name.
* @precon  nan
* @brief
*   1. Initialize the client and server. Expected result 1
*   2. After the initialization, set the servername and run the HITLS_GetServerName command to check the server name.
*   Expected result 2 is displayed
* @expect
*   1. Complete initialization
*   2. The returned result is consistent with the settings
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_SERVERNAME_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS12Config();

    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetServerName(client->ssl, (uint8_t *)g_serverName, (uint32_t)strlen(g_serverName)),
        HITLS_SUCCESS);
    client->ssl->isClient = true;
    const char *server_name = HITLS_GetServerName(client->ssl, HITLS_SNI_HOSTNAME_TYPE);
    ASSERT_TRUE(memcmp(server_name, (uint8_t *)g_serverName, strlen(g_serverName)) == 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_SET_GET_SESSION_TICKET_SUPPORT_API_TC001
* @title Test the HITLS_SetSessionTicketSupport and HITLS_GetSessionTicketSupport interfaces.
* @precon nan
* @brief HITLS_SetSessionTicketSupport
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer a non-empty TLS connection handle and set isEnable to an invalid value. Expected result 2.
* 3. Transfer the non-empty TLS connection handle information and set isEnable to a valid value. Expected result 3 is
*   obtained.
* HITLS_GetSessionTicketSupport
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Pass an empty getIsSupport pointer. Expected result 1.
* 3. Transfer the non-null TLS connection handle information and ensure that the getIsSupport pointer is not null.
*   Expected result 3.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned and ctx->config.tlsConfig.isSupportSessionTicket is true.
* 3. Returns HITLS_SUCCES and ctx->config.tlsConfig.isSupportSessionTicket is true or false.
@ */

/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_SESSION_TICKET_SUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool isSupport = false;
    bool getIsSupport = false;
    ASSERT_TRUE(HITLS_SetSessionTicketSupport(ctx, isSupport) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetSessionTicketSupport(ctx, &getIsSupport) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetSessionTicketSupport(ctx, NULL) == HITLS_NULL_INPUT);
    isSupport = true;
    ASSERT_TRUE(HITLS_SetSessionTicketSupport(ctx, isSupport) == HITLS_SUCCESS);
    isSupport = true;
    ASSERT_TRUE(HITLS_SetSessionTicketSupport(ctx, isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(ctx->config.tlsConfig.isSupportSessionTicket == true);
    isSupport = false;
    ASSERT_TRUE(HITLS_SetSessionTicketSupport(ctx, isSupport) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_GetSessionTicketSupport(ctx, &getIsSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(getIsSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_VERIFY_CLIENT_POST_HANDSHAKE_API_TC001
* @title  Invoke the HITLS_VerifyClientPostHandshake interface during connection establishment.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1.
*   2. Configure the client and server to support post-handshake extension. Expected result 3.
*   3. When a connection is established, the server is in the Try_RECV_CLIENT_HELLO state, and the
*       HITLS_VerifyClientPostHandshake interface is invoked.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The interface fails to be invoked.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_VERIFY_CLIENT_POST_HANDSHAKE_API_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Apply for and initialize the configuration file
    config = HITLS_CFG_NewTLS13Config();
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Configure the client and server to support post-handshake extension
    client->ssl->config.tlsConfig.isSupportPostHandshakeAuth = true;
    server->ssl->config.tlsConfig.isSupportPostHandshakeAuth = true;
    ASSERT_TRUE(client->ssl->config.tlsConfig.isSupportPostHandshakeAuth == true);
    ASSERT_TRUE(server->ssl->config.tlsConfig.isSupportPostHandshakeAuth == true);

    // he server is in the Try_RECV_CLIENT_HELLO state
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx->state == TRY_RECV_CLIENT_HELLO);

    // the HITLS_VerifyClientPostHandshake interface is invoked
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(client->ssl), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(server->ssl), HITLS_MSG_HANDLE_STATE_ILLEGAL);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_REMOVE_CERTANDKEY_API_TC001
* @title  Test the HITLS_RemoveCertAndKey interface.
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1.
*   2. Invoke the client HITLS_CFG_SetClientVerifySupport and  HITLS_CFG_SetNoClientCertSupport. Expected result 2.
*   3. Invoke the HITLS_RemoveCertAndKey,  Expected result 3.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. Return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_REMOVE_CERTANDKEY_API_TC001(void)
{
    FRAME_Init();
    int32_t ret;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);

    ret = HITLS_CFG_SetClientVerifySupport(config, true);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ret = HITLS_CFG_SetNoClientCertSupport(config, true);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ret = HITLS_RemoveCertAndKey(client->ssl);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = FRAME_CreateConnection(client, server, false, HS_STATE_BUTT);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static int32_t TestHITLS_PasswordCb(char *buf, int32_t bufLen, int32_t flag, void *userdata)
{
    (void)buf;
    (void)bufLen;
    (void)flag;
    (void)userdata;
    return 0;
}

/* @
* @test  UT_TLS_CM_SET_GET_DEFAULT_API_TC001
* @title  Test HITLS_SetDefaultPasswordCb/HITLS_GetDefaultPasswordCb interface
* @brief 1. Invoke the HITLS_SetDefaultPasswordCb interface.  Expected result 1.
*        2. Invoke the HITLS_SetDefaultPasswordCb interface. The value of ctx is not empty and the value of password is
*           not empty. Expected result 3.
*        3. Invoke the HITLS_GetDefaultPasswordCb interface and leave ctx blank. Expected result 2.
* @expect 1. Returns HITLS_NULL_INPUT
*        2. NULL is returned.
*        3. HITLS_SUCCESS is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_DEFAULT_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetDefaultPasswordCb(NULL, TestHITLS_PasswordCb) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetDefaultPasswordCb(ctx, TestHITLS_PasswordCb) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetDefaultPasswordCb(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetDefaultPasswordCb(ctx) == TestHITLS_PasswordCb);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_GET_SESSION_API_TC001
* @title  Test HITLS_SetSession/HITLS_GetSession interface
* @brief 1. If ctx is NULL, Invoke the HITLS_SetSession interface.Expected result 1.
*        2. Invoke the HITLS_SetSession interface.Expected result 2.
*        3. Invoke the HITLS_GetSession interface. Expected result 2.
* @expect 1. Returns HITLS_NULL_INPUT
*        2. returnes HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_SESSION_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_SetSession(NULL, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetSession(ctx, NULL) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetSession(ctx) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_PEERSIGNATURE_TYPE_API_TC001
* @title  Test HITLS_GetPeerSignatureType interface
* @brief 1. If ctx is NULL, Invoke the HITLS_GetPeerSignatureType interface. Expected result 2.
*        2. Invoke the HITLS_GetPeerSignatureType interface. Expected result 1.
* @expect 1. Returns HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE
*         2.Returns HITLS_NULL_INPUT
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_PEERSIGNATURE_TYPE_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    HITLS_SignAlgo sigType = {0};
    ASSERT_EQ(HITLS_GetPeerSignatureType(NULL, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetPeerSignatureType(ctx, &sigType), HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

static void Test_Fatal_Alert(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)bufSize;
    (void)user;
    (void)len;
    (void)data;
    uint8_t alertdata[2] = {0x02, 0x29};
    REC_Write(ctx, REC_TYPE_ALERT, alertdata, 2);
    return;
}


/** @
* @test     UT_TLS_CM_FATAL_ALERT_TC001
* @title    recv fatal alert brefore client hello need to close connection
* @precon   nan
* @brief    1. Initialize the client and server. Expected result 1
*           2. After the initialization, send a fetal alert to server, expect reslut 2.
* @expect   1. The initialization is successful.
*           2. The client close the connection
@ */
/* BEGIN_CASE */
void UT_TLS_CM_FATAL_ALERT_TC001(int version)
{
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Fatal_Alert
    };
    RegisterWrapper(wrapper);

    FRAME_Init();
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    /* Link initialization */
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(client->ssl->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(server->ssl->state, CM_STATE_ALERTED);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    /* Alert recv means the handshake state is in alerting state and no alert to be sent*/
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_NO_CERTIFICATE_RESERVED);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    return;
}
/* END_CASE */

/* @
* @test  UT_TLS_GET_GLOBALCONFIG_TC001
* @spec  -
* @title  test for HITLS_GetGlobalConfig
* @precon  nan
* @brief   HITLS_GetGlobalConfig
*          1. Transfer an empty TLS connection handle. Expected result 1 is obtained
*          2. Transfer non-empty TLS connection handle information. Expected result 2 is obtained
* @expect  1. return NULL
*          2. return globalConfig of TLS context
@ */
/* BEGIN_CASE */
void UT_TLS_GET_GLOBALCONFIG_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    ASSERT_TRUE(HITLS_GetGlobalConfig(ctx) == NULL);

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetGlobalConfig(ctx) != NULL);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_HITLS_PEEK_TC001
* @brief    1. Establish connection between server and client
            2. client sends a byte
            3. server calls HITLS_Peek twice
            4. server calls HITLS_Read to read one byte to make IO empty
            5. server calls HITLS_Peek
* @expect   1. Return HITLS_SUCCESS
            2. Return HITLS_SUCCESS
            3. Return HITLS_SUCCESS
            4. Return HITLS_SUCCESS
            5. Return HITLS_REC_NORMAL_RECV_BUF_EMPTY
@ */
/* BEGIN_CASE */
void UT_TLS_HITLS_PEEK_TC001(int tlsVersion)
{
    FRAME_Init();

    HITLS_Config *config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    uint8_t c2s[] = {0};
    uint32_t writeLen;
    ASSERT_TRUE(HITLS_Write(client->ssl, c2s, sizeof(c2s), &writeLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    uint8_t peekBuf[8] = {0};
    uint8_t peekBuf1[8] = {0};
    uint8_t peekBuf2[8] = {0};
    uint8_t readBuf[8] = {0};
    uint32_t peekLen = 0;
    uint32_t peekLen1 = 0;
    uint32_t peekLen2 = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Peek(server->ssl, peekBuf, sizeof(peekBuf), &peekLen), HITLS_SUCCESS);
    ASSERT_EQ(peekLen, sizeof(c2s));
    ASSERT_EQ(memcmp(peekBuf, c2s, peekLen), 0);
    ASSERT_EQ(HITLS_Peek(server->ssl, peekBuf1, sizeof(peekBuf1), &peekLen1), HITLS_SUCCESS);
    ASSERT_EQ(peekLen1, sizeof(c2s));
    ASSERT_EQ(memcmp(peekBuf1, c2s, peekLen1), 0);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(c2s));
    ASSERT_EQ(memcmp(readBuf, c2s, readLen), 0);
    ASSERT_EQ(HITLS_Peek(server->ssl, peekBuf2, sizeof(peekBuf2), &peekLen2), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(peekLen2, 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_SetTmpDhCb_TC001
* @spec  -
* @title  HITLS_SetTmpDhCb interface test. The config field is empty.
* @precon  nan
* @brief    1. If config is empty, expected result 1 occurs.
* @expect   1. HITLS_NULL_INPUT is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_SetTmpDhCb_TC001(void)
{
    // config is empty
    ASSERT_TRUE(HITLS_SetTmpDhCb(NULL, DH_CB) == HITLS_NULL_INPUT);
EXIT:
    ;
}
/* END_CASE */

/** @
* @test  UT_TLS_SET_VERSION_API_TC001
* @title Overwrite the input parameter of the HITLS_SetVersion interface.
* @precon nan
* @brief 1. Invoke the HITLS_SetVersion interface and leave ctx blank. Expected result 2 .
* 2. Invoke the HITLS_SetVersion interface. The ctx parameter is not empty. The minimum version number is
*   DTLS1.0, and the maximum version number is DTLS1.2. Expected result 2 .
* 3. Invoke the HITLS_SetVersion interface. The ctx parameter is not empty, the minimum version number is
*   DTLS1.2, and the maximum version number is DTLS1.2. Expected result 1 .
* 4. Invoke the HITLS_SetVersion interface, set ctx to a value, set the minimum version number to DTLS1.2, and
*   set the maximum version number to DTLS1.0. Expected result 2 .
* 5. Invoke the HITLS_SetVersion interface, set ctx to a value, set the minimum version number to DTLS1.2, and
*   set the maximum version number to TLS1.0. (Expected result 2)
* 6. Invoke the HITLS_SetVersion interface, set ctx to a value, set the minimum version number to DTLS1.2, and
*   set the maximum version number to TLS1.2. Expected result 2 .
* 7. Invoke the HITLS_SetVersion interface, set ctx to a value, set the minimum version number to TLS1.0, and set
*   the maximum version number to DTLS1.2. Expected result 2 .
* 8. Invoke the HITLS_SetVersion interface, set ctx to a value, set the minimum version number to TLS1.2, and set
*   the maximum version number to DTLS1.2. Expected result 2 .
* @expect 1. The interface returns a success response, HITLS_SUCCESS.
*         2. The interface returns an error code.
@ */
/* BEGIN_CASE */
void UT_TLS_SET_VERSION_API_TC001(void)
{
    HitlsInit();

    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    int32_t ret;
    ret = HITLS_SetVersion(NULL, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

    ret = HITLS_SetVersion(ctx, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_SetVersion(ctx, HITLS_VERSION_DTLS12, HITLS_VERSION_TLS12);
    ASSERT_TRUE(ret != HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_SET_ServerName_TC001
* @spec  -
* @title  HITLS_SetServerName invokes the interface to set the server name.
* @precon  nan
* @brief
1. Initialize the client and server. Expected result 1
2. After the initialization, set the servername and run the HITLS_GetServerName command to check the server name.
Expected result 2 is displayed
* @expect
1. Complete initialization
2. The returned result is consistent with the settings
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_SET_ServerName_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS12Config();

    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetServerName(client->ssl, (uint8_t *)g_serverName, (uint32_t)strlen((char *)g_serverName)), HITLS_SUCCESS);
    client->ssl->isClient = true;
    const char *server_name = HITLS_GetServerName(client->ssl, HITLS_SNI_HOSTNAME_TYPE);
    ASSERT_TRUE(memcmp(server_name, g_serverName, strlen(g_serverName)) == 0);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_REQUEST) == HITLS_SUCCESS);

    server_name = HS_GetServerName(server->ssl);
    ASSERT_TRUE(memcmp(server_name, g_serverName, strlen(g_serverName)) == 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test The interface is invoked in the Idle state. An exception is returned.
* @spec -
* @title UT_TLS_HITLS_READ_WRITE_TC001
* @precon nan
* @brief
1. When the connection is in the Idle state, call the hitls_read/hitls_write interface. Expected result 1 is obtained.
* @expect
1. The connection is not established.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_HITLS_READ_WRITE_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(client->ssl->state == CM_STATE_IDLE);
    ASSERT_TRUE(server->ssl->state == CM_STATE_IDLE);
    // 1.  When the link is in the Idle state, call the hitls_read/hitls_write interface.
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_TRUE(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen) == HITLS_CM_LINK_UNESTABLISHED);
    ASSERT_TRUE(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen) == HITLS_CM_LINK_UNESTABLISHED);

    // 1.  When the link is in the Idle state, call the hitls_read/hitls_write interface.
    uint8_t writeBuf[] = "abc";
    uint32_t writeLen = 4;
    uint32_t len = 0;
    ASSERT_TRUE(HITLS_Write(client->ssl, writeBuf, writeLen, &len) == HITLS_CM_LINK_UNESTABLISHED);
    ASSERT_TRUE(HITLS_Write(server->ssl, writeBuf, writeLen, &len) == HITLS_CM_LINK_UNESTABLISHED);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test test HITLS_Close in different cm state
* @spec -
* @title UT_TLS_HITLS_CLOSE_TC001
* @precon nan
* @brief    1. Initialize the client and server. Expected result 1
            2. Invoke HITLS_Connect to send the message. Expected result 2
            3. Invoke HITLS_Close and failed to send the message. Expected result 3
            4. Succeeded in invoking HITLS_Connect to resend the failed close_notify message. Expected result 4
            5. Invoke HITLS_Close to send the message. Expected result 5
* @expect   1. The connection is not established.
            2. The client status is CM_STATE_HANDSHAKING.
            3. The client status is CM_STATE_ALERTING.
            4. The client status is CM_STATE_ALERTED.
            5. The client status is CM_STATE_CLOSED.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_HITLS_CLOSE_TC001(int uioType)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = {0};
    FRAME_Msg sndframeMsg = {0};

    config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, uioType);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, uioType);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_REQUEST) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_CERTIFICATE_REQUEST);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->sndMsg.len = 1;
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_ALERTED);

    ioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Close(clientTlsCtx), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

EXIT:
    CleanRecordBody(&recvframeMsg);
    CleanRecordBody(&sndframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test test HITLS_Close in different cm state
* @spec -
* @title UT_TLS_HITLS_CLOSE_TC002
* @precon nan
* @brief    1. Initialize the client and server. Expected result 1
            2. Invoke HITLS_Close. Expected result 2
* @expect   1. The connection is not established.
            2. The client status is CM_STATE_CLOSED.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_HITLS_CLOSE_TC002(int uioType)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, uioType);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, uioType);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
int32_t ParseServerCookie(ParsePacket *pkt, ServerHelloMsg *msg);
/* @
* @test test ParseServerCookie and ParseClientCookie
* @spec -
* @title UT_TLS_PARSE_Cookie_TC001
* @precon nan
* @brief    1. Initialize the client. Expected result 1
            2. Assemble a message with zero length cookie, invoke ParseServerCookie. Expected result 2
            3. Assemble a message with zero length cookie, invoke ParseClientCookie. Expected result 2
* @expect   1. The connection is not established.
            2. The return value is HITLS_PARSE_INVALID_MSG_LEN.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_PARSE_Cookie_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    CONN_Init(client->ssl);
    ServerHelloMsg svrMsg = { 0 };
    ClientHelloMsg cliMsg = { 0 };
    uint8_t cookie[] = { 0x00 };
    uint32_t bufOffset = 0;
    ParsePacket pkt = {.ctx = client->ssl, .buf = cookie, .bufLen = sizeof(cookie), .bufOffset = &bufOffset};
    ASSERT_EQ(ParseServerCookie(&pkt, &svrMsg), HITLS_PARSE_INVALID_MSG_LEN);
    CleanServerHello(&svrMsg);
    ASSERT_EQ(ParseClientCookie(&pkt, &cliMsg), HITLS_PARSE_INVALID_MSG_LEN);
    CleanClientHello(&cliMsg);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
}
/* END_CASE */
