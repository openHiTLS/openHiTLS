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
#include "stub_utils.h"
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
#include "hitls.h"
#include "hitls_crypt_reg.h"
#include "crypt_errno.h"
#include "bsl_list.h"
#include "hitls_cert.h"
#include "hitls_cert_local.h"
#include "hitls_pki_cert.h"
#include "hitls_x509_local.h"
#include "parse_extensions_client.c"
#include "parse_extensions_server.c"
#include "parse_server_hello.c"
#include "parse_client_hello.c"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET2(void *, BSL_SAL_Calloc, uint32_t, uint32_t);
STUB_DEFINE_RET1(BslList *, BSL_LIST_New, int32_t);
STUB_DEFINE_RET1(const HITLS_Config *, HITLS_GetConfig, const HITLS_Ctx *);
STUB_DEFINE_RET2(void *, BSL_SAL_Dump, const void *, uint32_t);
STUB_DEFINE_RET3(int32_t, BSL_LIST_AddElement, BslList *, void *, BslListPosition);

static char *g_serverName = "testServer";
uint32_t g_uiPort = 18888;
#define DEFAULT_DESCRIPTION_LEN 128
#define TLS_DHE_PARAM_MAX_LEN 1024
#define GET_GROUPS_CNT (-1)
#define READ_BUF_SIZE (18 * 1024)
#define ALERT_BODY_LEN 2u
#define HITLS_MIN_RECORDSIZE_LIMIT 64
#define READ_BUF_LEN_18K 18432

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
    STUB_REPLACE(BSL_SAL_Calloc, STUB_SAL_Calloc);;
    ASSERT_TRUE(
        HITLS_SetCipherSuites(ctx, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_MEMALLOC_FAIL);
    STUB_RESTORE(BSL_SAL_Calloc);
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
    STUB_RESTORE(BSL_SAL_Calloc);
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

/* @
* @test SDV_HITLS_TLCP_PATCH_TC005_3
* @spec -
* @title    Establish a connection between tlcp client and tlsall server
* @precon nan
* @brief    1. Initialize tlsall client configuration. Expected result 1
            2. Initialize tlcp server configuration. Expected result 2
            3. The client uses server configuration to establish a connection. Expected result 3
            4. The server uses client configuration to establish a connection. Expected result 4
            5. Establish the connection. Expected result 5
* @expect   1. Initialization successfully.
            2. Initialization successfully.
            3. connection creation successfully.
            4. connection creation successfully.
            5. The connection is established.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_TLCP_PATCH_TC005_3()
{
    FRAME_Init();
    HITLS_Config *c_config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(s_config != NULL);

    HITLS_CFG_SetEndPoint(c_config, false);
    HITLS_CFG_SetEndPoint(s_config, true);
    FRAME_LinkObj *client = FRAME_CreateTLCPLink(c_config, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateTLCPLink(s_config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_SERVER_SKIP_DHE_SELECT_ECDHE_TC001
* @title  Test server skips DHE cipher suite when DH key generation fails
* @precon nan
* @brief
*   1. Configure server with DHE_ANON and ECDHE_ANON cipher suites, server preference enabled
*   2. Configure client to support both DHE and ECDHE cipher suites
*   3. Create a scenario where GetDhKey() returns NULL (no DH parameters configured)
*   4. Establish connection
* @expect
*   1. Connection establishment succeeds
*   2. Server skips DHE cipher suites
*   3. Server selects HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA instead
*   4. Final negotiated cipher suite is ECDHE-based
@ */
/* BEGIN_CASE */
void UT_TLS_SERVER_SKIP_DHE_SELECT_ECDHE_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Create TLS 1.2 config
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Configure server cipher suites: DHE first (preferred), then ECDHE
    uint16_t serverCipherSuites[] = {
        HITLS_DH_ANON_WITH_AES_128_GCM_SHA256,  // DHE cipher suite (should be skipped)
        HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA // ECDHE cipher suite (should be selected)
    };
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(config, serverCipherSuites,
        sizeof(serverCipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);

    // Create client and server links
    FRAME_CertInfo certInfo = {0, 0, 0, 0, 0, 0};
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    // Establish connection
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    // Verify connection established successfully
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    // Verify negotiated cipher suite is ECDHE (not DHE)
    ASSERT_TRUE(server->ssl->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(server->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite ==
        HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_TLS13_NO_KEY_EXCH_MATERIAL_TC001
* @title  Test TLS 1.3 handshake fails when no PSK or certificate is available
* @precon nan
* @brief
*   1. Create TLS 1.3 config without certificate and PSK. Expected result 1.
*   2. Client sends TLS 1.3 ClientHello. Expected result 2.
*   3. Server checks for available key exchange material. Expected result 3.
* @expect
*   1. Configuration created successfully.
*   2. ClientHello sent successfully.
*   3. Server returns HITLS_MSG_HANDLE_UNSUPPORT_VERSION and sends ALERT_HANDSHAKE_FAILURE.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_TLS13_NO_KEY_EXCH_MATERIAL_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Create TLS 1.3 config without certificate and PSK
    config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);

    // Create client and server links (no certificates configured)
    FRAME_CertInfo certInfo = {0, 0, 0, 0, 0, 0};
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    // Try to establish connection
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

    // Verify server state is ALERTED
    ASSERT_EQ(server->ssl->state, CM_STATE_ALERTED);

    // Verify alert was sent
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_HANDSHAKE_FAILURE);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_GET_SHARED_SIGALGS_API_TC001
* @title Test the HITLS_GetSharedSigAlgs interface parameter validation.
* @precon nan
* @brief HITLS_GetSharedSigAlgs
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer valid parameters with idx=-1 before handshake. Expected result 2.
* 3. Transfer valid parameters with idx=0 with NULL pointers before handshake. Expected result 3.
* @expect 1. Returns 0
* 2. Returns 0 
* 3. Returns 0
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_SHARED_SIGALGS_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    uint16_t signatureScheme;
    int32_t keyType;
    int32_t paraId;
    int32_t count;

    // Test NULL ctx
    count = HITLS_GetSharedSigAlgs(NULL, -1, NULL, NULL, NULL);
    ASSERT_TRUE(count == 0);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    // Test valid parameters (before handshake, should return 0 algorithms)
    count = HITLS_GetSharedSigAlgs(ctx, -1, NULL, NULL, NULL);
    ASSERT_TRUE(count == 0);

    // Test with valid index and NULL pointers (should return 0 before handshake)
    count = HITLS_GetSharedSigAlgs(ctx, 0, NULL, NULL, NULL);
    ASSERT_TRUE(count == 0);

    // Test with valid index and valid pointers (should return 0 before handshake)
    count = HITLS_GetSharedSigAlgs(ctx, 0, &signatureScheme, &keyType, &paraId);
    ASSERT_TRUE(count == 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_GET_SHARED_SIGALGS_FUNC_TC001
* @title Test HITLS_GetSharedSigAlgs before and after handshake.
* @precon nan
* @brief
* 1. Initialize the client and server. Expected result 1.
* 2. Before handshake, call HITLS_GetSharedSigAlgs on both sides. Expected result 2.
* 3. Complete handshake. Expected result 3.
* 4. After handshake, call HITLS_GetSharedSigAlgs on both sides. Expected result 4.
* @expect
* 1. Initialization successful
* 2. Returns 0 shared algorithms before handshake
* 3. Handshake completes successfully
* 4. Returns >= 0 shared algorithms after handshake (depends on peer extension)
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_SHARED_SIGALGS_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = GetHitlsConfigViaVersion(version);
    config_s = GetHitlsConfigViaVersion(version);

    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    // Set signature algorithms
    uint16_t signAlgs_c[] = {
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256,
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512,
        CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384
    };
    uint16_t signAlgs_s[] = {
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512,
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256
    };
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Before handshake, should return 0 algorithms
    int32_t clientCount = HITLS_GetSharedSigAlgs(client->ssl, -1, NULL, NULL, NULL);
    int32_t serverCount = HITLS_GetSharedSigAlgs(server->ssl, -1, NULL, NULL, NULL);
    ASSERT_EQ(clientCount, 0);
    ASSERT_EQ(serverCount, 0);

    // Complete handshake
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    // After handshake, check count (may be 0 if peer extension not received/stored)
    serverCount = HITLS_GetSharedSigAlgs(server->ssl, -1, NULL, NULL, NULL);

    // Just verify the function works (returns non-negative)
    ASSERT_TRUE(serverCount == 4);

    // If we have shared algorithms, verify we can retrieve them
    if (serverCount > 0) {
        for (int32_t i = 0; i < serverCount; i++) {
            uint16_t scheme;
            int32_t keyType, paraId;
            int32_t ret = HITLS_GetSharedSigAlgs(server->ssl, i, &scheme, &keyType, &paraId);
            ASSERT_EQ(ret, 4);
            ASSERT_EQ(scheme, signAlgs_c[i]);
        }
    }

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_GET_SHARED_SIGALGS_FUNC_TC002
* @title Test HITLS_GetSharedSigAlgs with out-of-bounds index.
* @precon nan
* @brief
* 1. Initialize the client. Expected result 1.
* 2. Query count before handshake (should be 0). Expected result 2.
* 3. Try to access index 0 when count is 0. Expected result 3.
* 4. Try to access negative index other than -1. Expected result 4.
* @expect
* 1. Initialization successful
* 2. Returns 0
* 3. Returns 0 or error
* 4. Returns 0 or error
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_SHARED_SIGALGS_FUNC_TC002(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;

    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    // Set signature algorithms
    uint16_t signAlgs[] = {
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA384,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA512,
        CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512
    };
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    // Get count (should be 0 before handshake)
    int32_t count = HITLS_GetSharedSigAlgs(ctx, -1, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);

    // Try to access index 0 when count is 0 (should return 0)
    uint16_t scheme;
    int32_t keyType, paraId;
    int32_t ret = HITLS_GetSharedSigAlgs(ctx, 0, &scheme, &keyType, &paraId);
    ASSERT_EQ(ret, 0);

    // Try negative index other than -1 (should return 0)
    ret = HITLS_GetSharedSigAlgs(ctx, -2, &scheme, &keyType, &paraId);
    ASSERT_EQ(ret, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  SDV_HITLS_LISTEN_API_TC001
* @spec  -
* @title  test for HITLS_Listen
* @precon  nan
* @brief   HITLS_Listen
*          1. Transfer an empty TLS connection handle. Expected result 1 is obtained
*          2. Transfer an empty TLS connection handle, an empty clientAddr. Expected result 1 is obtained
*          3. Transfer non-empty TLS connection handle, non-empty clientAddr. Expected result 2 is obtained
* @expect  1. return HITLS_NULL_INPUT
*          2. return HITLS_REC_NORMAL_RECV_BUF_EMPTY
@ */
/* BEGIN_CASE */
void SDV_HITLS_LISTEN_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewDTLS12Config();
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    BSL_SAL_SockAddr clientAddr = NULL;
    ASSERT_EQ(SAL_SockAddrNew(&clientAddr), BSL_SUCCESS);
    ASSERT_TRUE(HITLS_Listen(NULL, clientAddr) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_Listen(server->ssl, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_Listen(server->ssl, clientAddr) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Listen(server->ssl, clientAddr), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Listen(server->ssl, clientAddr), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    SAL_SockAddrFree(clientAddr);
}
/* END_CASE */

/* @
* @test  UT_CONFIG_SET_GROUP_LIST_TC002
* @spec  -
* @title  Testing the HITLS_CFG_SetGroupList and HITLS_SetGroupList interfaces
* @precon  nan
* @expect  1. return HITLS_CONFIG_UNSUPPORT_GROUP
@ */
/* BEGIN_CASE */
void UT_CONFIG_SET_GROUP_LIST_TC002()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    const char group[] = "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_";
    ASSERT_TRUE(HITLS_CFG_SetGroupList(config, group, sizeof(group)) ==  HITLS_CONFIG_UNSUPPORT_GROUP);
    ASSERT_EQ(HITLS_SetGroupList(ctx, group, sizeof(group)), HITLS_CONFIG_UNSUPPORT_GROUP);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  HITLS_TLS_SetGroupsList_SDV_23_1_0_001
* @spec  -
* @title  HTLS_CFG_SetGroupList interface test. A group is transferred.
* @precon  nan
* @brief    1. Transfer a correct group. Expected result 1 is obtained.
* @expect   1. Return HITLS_SUCCESS to obtain the correct group array.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_TLS_SetGroupsList_SDV_23_1_0_001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    // Transfer a correct group
    const char group[] = "HITLS_EC_GROUP_SECP256R1";
    ASSERT_TRUE(HITLS_CFG_SetGroupList(config, group, sizeof(group)) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_SetGroupList(ctx, group, sizeof(group)) ==  HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  HITLS_TLS_SetGroupsList_SDV_23_1_0_002
* @spec  -
* @title  HTLS_CFG_SetGroupList interface test. Multiple groups are transferred.
* @precon  nan
* @brief    1. Transfer multiple correct groups. Expected result 1 is obtained.
* @expect   1. Return HITLS_SUCCESS to obtain the correct group array.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_TLS_SetGroupsList_SDV_23_1_0_002()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    // Transfer multiple correct groups.
    const char group[] = "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1";
    ASSERT_TRUE(HITLS_CFG_SetGroupList(config, group, sizeof(group)) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_SetGroupList(ctx, group, sizeof(group)) ==  HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  HITLS_TLS_SetGroupsList_SDV_23_1_0_003
* @spec  -
* @title  HITLS_CFG_SetGroupList interface test. The input group contains incorrect enumerated values.
* @precon  nan
* @brief    1. Transfer multiple groups that contain incorrect enumerated values. Expected result 1 is obtained.
* @expect   1. An error is reported. HITLS_CONFIG_UNSUPPORT_GROUP is reported.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_TLS_SetGroupsList_SDV_23_1_0_003()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    // Transfer multiple groups that contain incorrect enumerated values
    const char group[] = "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1: \
                HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP256R1";

    ASSERT_TRUE(HITLS_CFG_SetGroupList(config, group, sizeof(group)) ==  HITLS_CONFIG_UNSUPPORT_GROUP);
    ASSERT_EQ(HITLS_SetGroupList(ctx, group, sizeof(group)), HITLS_CONFIG_UNSUPPORT_GROUP);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  HITLS_TLS_SetGroupsList_SDV_23_1_0_004
* @spec  -
* @title  HITLS_CFG_SetGroupList interface test. The input group contains incorrect enumerated values.
* @precon  nan
* @brief    1. Transfer multiple groups that contain incorrect enumerated values. Expected result 1 is obtained.
* @expect   1. An error is reported, and the HITLS_CONFIG_UNSUPPORT_GROUP is reported.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_TLS_SetGroupsList_SDV_23_1_0_004()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    // Transfer multiple groups that contain incorrect enumerated values.
    const char group[] = "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_";
    ASSERT_TRUE(HITLS_CFG_SetGroupList(config, group, sizeof(group)) ==  HITLS_CONFIG_UNSUPPORT_GROUP);
    ASSERT_EQ(HITLS_SetGroupList(ctx, group, sizeof(group)), HITLS_CONFIG_UNSUPPORT_GROUP);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  HITLS_TLS_SetGroupsList_SDV_23_1_0_005
* @spec  -
* @title  HITLS_CFG_SetGroupList interface test. The input groups are not separated by colons (:).
            The input groups are a long character string.
* @precon  nan
* @brief    1. Transfer multiple groups. Do not separate multiple groups with colons (:). Expected result 1 is obtained.
* @expect   1. An error is reported. HITLS_CONFIG_UNSUPPORT_GROUP is reported.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_TLS_SetGroupsList_SDV_23_1_0_005()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    // Transfer multiple groups. Do not separate multiple groups with colons (:).
    const char group[] = "HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1 \
                HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1HITLS_EC_GROUP_SECP256R1";

    ASSERT_TRUE(HITLS_CFG_SetGroupList(config, group, sizeof(group)) ==  HITLS_CONFIG_UNSUPPORT_GROUP);
    ASSERT_EQ(HITLS_SetGroupList(ctx, group, sizeof(group)), HITLS_CONFIG_UNSUPPORT_GROUP);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_CONFIG_SET_GROUP_LIST_TC001
* @spec  -
* @title  Testing the HITLS_CFG_SetGroupList interface
* @precon  nan
@ */
/* BEGIN_CASE */
void UT_CONFIG_SET_GROUP_LIST_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    switch (tlsVersion) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            break;
        default:
            config = NULL;
            break;
    }
    const char groupNamesError[] = "1:1";
    const char groupNames[] =
        "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1:HITLS_EC_GROUP_SECP521R1:HITLS_EC_GROUP_BRAINPOOLP256R1";

    ASSERT_EQ(HITLS_CFG_SetGroupList(config, groupNamesError, sizeof(groupNamesError)), HITLS_CONFIG_UNSUPPORT_GROUP);
    ASSERT_TRUE(HITLS_CFG_SetGroupList(config, groupNames, sizeof(groupNames)) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  SDV_HITLS_CM_GETCIPHERSUITES_API_TC001
* @spec  -
* @title  Testing the HITLS_GetCipherSuites interface
* @precon  nan
@ */

/* BEGIN_CASE */
void SDV_HITLS_CM_GETCIPHERSUITES_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    uint16_t data[1024] = {0};
    uint32_t dataLen = sizeof(data) / sizeof(uint16_t);
    uint32_t cipherSuiteSize = 0;
    ASSERT_TRUE(HITLS_GetCipherSuites(NULL, data, dataLen, &cipherSuiteSize) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetCipherSuites(ctx, data, dataLen, &cipherSuiteSize) == HITLS_SUCCESS);
    ASSERT_TRUE(data[0] == HITLS_AES_256_GCM_SHA384);
    ASSERT_TRUE(data[1] == HITLS_CHACHA20_POLY1305_SHA256);
    ASSERT_TRUE(data[2] == HITLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(cipherSuiteSize == 3);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_HITLS_CM_GET_CLIENT_CIPHER_SUITES_TC001
* @title  test for HITLS_GetClientCipherSuites
* @precon  nan
* @brief   1. Create TLS config. Expected result 1 is obtained
*          2. Get the client cipher suites. Expected result 1 is obtained
* @expect  1. Success
@ */
/* BEGIN_CASE */
void UT_HITLS_CM_GET_CLIENT_CIPHER_SUITES_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    uint16_t data[1024] = {0};
    uint32_t dataLen = sizeof(data) / sizeof(uint16_t);
    uint32_t cipherSuiteSize = 0;
    ASSERT_TRUE(HITLS_GetClientCipherSuites(ctx, data, dataLen, &cipherSuiteSize) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetClientCipherSuites(NULL, data, dataLen, &cipherSuiteSize) == HITLS_NULL_INPUT);

    ASSERT_EQ(data[0], HITLS_AES_256_GCM_SHA384);
    ASSERT_EQ(data[1], HITLS_CHACHA20_POLY1305_SHA256);
    ASSERT_EQ(data[2], HITLS_AES_128_GCM_SHA256);
    ASSERT_EQ(cipherSuiteSize, 3);
    HITLS_Ctx *ctx1 = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(HITLS_GetClientCipherSuites(ctx1, data, dataLen, &cipherSuiteSize) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

BslList *BSL_LIST_New_NULL(int32_t dataSize)
{
    (void)dataSize;
    return NULL;
}

const HITLS_Config *HITLS_GetConfig_FAIL(const HITLS_Ctx *ctx)
{
    (void)ctx;
    return NULL;
}

void *BSL_SAL_Dump_NULL(const void *src, uint32_t size)
{
    (void)src;
    (void)size;
    return NULL;
}

int32_t BSL_LIST_AddElement_FAIL(BslList *pList, void *pData, BslListPosition enPosition)
{
    (void)pList;
    (void)pData;
    (void)enPosition;
    return BSL_INVALID_ARG;
}

/* BEGIN_CASE */
void SDV_HITLS_GET_SUPPORTED_CIPHERS_001()
{
    HITLS_CryptMethodInit();
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    uint16_t cipherSuites[] = {HITLS_RSA_WITH_AES_128_CBC_SHA, HITLS_DHE_DSS_WITH_AES_128_CBC_SHA};
    HITLS_CFG_SetCipherSuites(config, cipherSuites, sizeof(cipherSuites)/sizeof(uint16_t));
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);

    ASSERT_TRUE(HITLS_GetSupportedCiphers(NULL) == NULL);
    STUB_REPLACE(BSL_LIST_New, BSL_LIST_New_NULL);
    ASSERT_TRUE(HITLS_GetSupportedCiphers(client->ssl) == NULL);
    STUB_RESTORE(BSL_LIST_New);
    STUB_REPLACE(HITLS_GetConfig, HITLS_GetConfig_FAIL);
    ASSERT_TRUE(HITLS_GetSupportedCiphers(client->ssl) == NULL);
    STUB_RESTORE(HITLS_GetConfig);
    STUB_REPLACE(BSL_SAL_Dump, BSL_SAL_Dump_NULL);
    ASSERT_TRUE(HITLS_GetSupportedCiphers(client->ssl) == NULL);
    STUB_RESTORE(BSL_SAL_Dump);
    STUB_REPLACE(BSL_LIST_AddElement, BSL_LIST_AddElement_FAIL);
    ASSERT_TRUE(HITLS_GetSupportedCiphers(client->ssl) == NULL);
    STUB_RESTORE(BSL_LIST_AddElement);

    HITLS_CIPHER_List *cipherList = HITLS_GetSupportedCiphers(client->ssl);
    ASSERT_TRUE(cipherList != NULL);
    BslListNode *tmp = BSL_LIST_FirstNode(cipherList);
    HITLS_Cipher *cipher = BSL_LIST_GetData(tmp);
    ASSERT_TRUE(cipher->cipherSuite == cipherSuites[0]);
    tmp = BSL_LIST_GetNextNode(cipherList, (const BslListNode *)BSL_LIST_FirstNode(cipherList));
    cipher = BSL_LIST_GetData(tmp);
    ASSERT_TRUE(cipher->cipherSuite == cipherSuites[1]);
    ASSERT_TRUE(BSL_LIST_COUNT(cipherList) == 2);
EXIT:
    BSL_LIST_FREE(cipherList, BSL_SAL_Free);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
}
/* END_CASE */

/* @
* @test  UT_INTERFACE_HITLS_ExportKeyingMaterial_TC002
* @spec  -
* @title  Testing the HITLS_ExportKeyingMaterial interface
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_INTERFACE_HITLS_ExportKeyingMaterial_TC002()
{
    HITLS_CryptMethodInit();
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint8_t out[20] = {0};
    size_t outLen = 20;
    const char *label = NULL;
    size_t labelLen = 0;
    const uint8_t *context = (uint8_t *)"12345";
    size_t contextLen = 5;
    int useContext = 1;
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen,
        label, labelLen, context, contextLen, useContext), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_CCA_EXPORT_KEY_MATERIAL_008
* @spec  -
* @title  Calling HITLS_ExportKeyingMaterial during the handshake process
* @precon  nan
* @brief  "1. Set the version number to tls1.2, and there is an expected result 1.
2. Keep the client/server status in the recv_finish state; expected result 2 occurs.
3. Invoke the HITLS_ExportKeyingMaterial interface, and expected result 3 is obtained.
* @expect  "1. Set successful
2. Set successful
3. return HITLS_MSG_HANDLE_STATE_ILLEGAL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_EXPORT_KEY_MATERIAL_008()
{
    HITLS_CryptMethodInit();
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);
    uint8_t out[20] = {0};
    size_t outLen = 20;
    const char *label = NULL;
    size_t labelLen = 0;
    const uint8_t *context = (uint8_t *)"12345";
    size_t contextLen = 5;
    int useContext = 1;
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen,
        label, labelLen, context, contextLen, useContext), HITLS_MSG_HANDLE_STATE_ILLEGAL);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_CCA_EXPORT_KEY_MATERIAL_001
* @spec  -
* @title  HITLS_ExportKeyingMaterial interface test
* @precon  nan
* @brief    1. If the ctx field is empty, expected result 1 is obtained.
            2. If the out field is empty, expected result 2 is obtained.
            3. The length of outLen is 0. Expected result 3 is obtained.
            4. The label field is empty, but the labelen field is not 0. (Expected result 4 is obtained.)
            5. If the length of labellen is 0, expected result 5 is obtained.
            6. If the context length is 0, expected result 6 is obtained.
            7. The value of useContext is 0, and the value of context is NULL.
            8. The context is NULL
            9. UseContext is set to another value.
* @expect   1. The interface returns the HITLS_INVALID_INPUT.
            2. The interface returns the HITLS_INVALID_INPUT message.
            3. The interface returns the HITLS_INVALID_INPUT message.
            4. The interface returns the HITLS_INVALID_INPUT.
            5. The interface returns HITLS_SUCCESS.
            6. The interface returns HITLS_SUCCESS.
            7. The interface returns HITLS_SUCCESS.
            8. The interface returns HITLS_SUCCESS.
            9. The interface returns HITLS_SUCCESS.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_EXPORT_KEY_MATERIAL_001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    uint8_t out[1000] = {0};
    size_t outLen = 1000;
    const char *label = "123456";
    size_t labelLen = strlen("123456");
    const uint8_t *context = (uint8_t *)"12345";
    size_t contextLen = 5;
    int useContext = 1;

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // The ctx field is empty
    ASSERT_EQ(HITLS_ExportKeyingMaterial(NULL, out, outLen, label, labelLen, context, contextLen, useContext),
        HITLS_INVALID_INPUT);

    // The out field is empty
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, NULL, outLen, label, labelLen, context, contextLen, useContext),
        HITLS_INVALID_INPUT);

    // The length of outLen is 0
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, 0, label, labelLen, context, contextLen, useContext),
        HITLS_INVALID_INPUT);

    // The label field is empty, but the labelen field is not 0
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen, NULL, labelLen, context, contextLen, useContext),
        HITLS_INVALID_INPUT);

    // The length of labellen is 0
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen, label, 0, context, contextLen, useContext),
        HITLS_SUCCESS);

    // The value of useContext is 0, and the value of context is NULL.
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen, label, labelLen, NULL, contextLen, 0),
        HITLS_SUCCESS);

    // The context is NULL
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen, label, labelLen, NULL, contextLen, useContext),
        HITLS_INVALID_INPUT);

    // The context length is 0
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen, label, labelLen, context, 0, useContext),
        HITLS_SUCCESS);

    // UseContext is set to another value.
    ASSERT_EQ(HITLS_ExportKeyingMaterial(client->ssl, out, outLen, label, labelLen, context, 0, 3), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static int32_t X509_CertSignatureCmp(HITLS_X509_Asn1AlgId *certOri, BSL_ASN1_BitString *signOri,
    HITLS_X509_Asn1AlgId *cert, BSL_ASN1_BitString *sign)
{
    if (certOri->algId != cert->algId) {
        return 1;
    }
    if (signOri->len != sign->len) {
        return 1;
    }
    return memcmp(signOri->buff, sign->buff, sign->len);
}

static int32_t X509_CertCmp(HITLS_X509_Cert *certOri, HITLS_X509_Cert *cert)
{
    if (certOri == cert) {
        return 0;
    }
    if (HITLS_X509_CmpNameNode(certOri->tbs.subjectName, cert->tbs.subjectName) != 0) {
        return 1;
    }
    if (certOri->tbs.tbsRawDataLen != cert->tbs.tbsRawDataLen) {
        return 1;
    }
    int32_t ret = memcmp(certOri->tbs.tbsRawData, cert->tbs.tbsRawData, cert->tbs.tbsRawDataLen);
    if (ret != 0) {
        return 1;
    }
    return X509_CertSignatureCmp(&certOri->tbs.signAlgId, &certOri->signature,
        &cert->tbs.signAlgId, &cert->signature);
}

uint32_t Compare_Certificates(FRAME_LinkObj *client, FRAME_LinkObj *server, bool isClientPeerCertNull,
    bool isServerPeerCertNull)
{
    HITLS_CERT_X509 *client_Cert = HITLS_GetCertificate(client->ssl);
    HITLS_CERT_X509 *server_Cert = HITLS_GetCertificate(server->ssl);

    HITLS_CERT_X509 *client_PeerCert = HITLS_GetPeerCertificate(client->ssl);
    HITLS_CERT_X509 *server_PeerCert = HITLS_GetPeerCertificate(server->ssl);
    HITLS_CERT_Chain *client_PeerChain = HITLS_GetPeerCertChain(client->ssl);
    HITLS_CERT_Chain *server_PeerChain = HITLS_GetPeerCertChain(server->ssl);

    HITLS_CERT_Chain *client_Chain = HITLS_CFG_GetChainCerts(&client->ssl->config.tlsConfig);
    HITLS_CERT_Chain *server_Chain = HITLS_CFG_GetChainCerts(&server->ssl->config.tlsConfig);

    HITLS_CERT_X509 *client_ChainCert = NULL;
    HITLS_CERT_X509 *server_PeerChainCert = NULL;
    HITLS_CERT_X509 *server_ChainCert = NULL;
    HITLS_CERT_X509 *client_PeerEECert = NULL;
    HITLS_CERT_X509 *client_PeerChainCert = NULL;

    if (!isClientPeerCertNull) {
        server_ChainCert = (HITLS_CERT_X509*)server_Chain->first->data; // server chain cert
        client_PeerEECert = (HITLS_CERT_X509*)client_PeerChain->first->data; // server ee cert
        client_PeerChainCert = (HITLS_CERT_X509*)client_PeerChain->last->data; // server chain cert
    }
    if (!isServerPeerCertNull) {
        client_ChainCert = (HITLS_CERT_X509*)client_Chain->first->data; // client chain cert
        server_PeerChainCert = (HITLS_CERT_X509*)server_PeerChain->first->data; // client chain cert
    }

    int client_result = 0;
    int server_result = 0;
    if (isClientPeerCertNull) {
        ASSERT_TRUE(client_PeerCert == NULL);
        ASSERT_TRUE(client_PeerChain == NULL);
        client_result = 1;
    } else {
        ASSERT_TRUE(client_PeerCert != NULL);
        if (X509_CertCmp(client_PeerCert, server_Cert) == 0 && X509_CertCmp(client_PeerEECert, server_Cert) == 0 &&
            X509_CertCmp(client_PeerChainCert, server_ChainCert) == 0) {
            client_result = 1;
        } else {
            client_result = 0;
        }
    }
    if (isServerPeerCertNull) {
        ASSERT_TRUE(server_PeerCert == NULL);
        ASSERT_TRUE(server_PeerChain == NULL);
        server_result = 1;
    } else {
        ASSERT_TRUE(server_PeerCert != NULL);
        if (X509_CertCmp(server_PeerCert, client_Cert) == 0 &&
            X509_CertCmp(server_PeerChainCert, client_ChainCert) == 0) {
            server_result = 1;
        } else {
            server_result = 0;
        }
    }

    HITLS_X509_CertFree(client_PeerCert);
    HITLS_X509_CertFree(server_PeerCert);

    if (client_result & server_result) {
        return HITLS_SUCCESS;
    } else {
        return 1;
    }
EXIT:
    return 1;
}

uint32_t Compare_ResumeCertificates(FRAME_LinkObj *client, FRAME_LinkObj *server)
{
    HITLS_CERT_X509 *client_Cert = HITLS_GetCertificate(client->ssl);
    HITLS_CERT_X509 *server_Cert = HITLS_GetCertificate(server->ssl);

    HITLS_CERT_X509 *client_PeerCert = HITLS_GetPeerCertificate(client->ssl);
    HITLS_CERT_X509 *server_PeerCert = HITLS_GetPeerCertificate(server->ssl);
    HITLS_CERT_Chain *client_PeerChain = HITLS_GetPeerCertChain(client->ssl);
    HITLS_CERT_Chain *server_PeerChain = HITLS_GetPeerCertChain(server->ssl);

    HITLS_CERT_Chain *server_Chain = HITLS_CFG_GetChainCerts(&server->ssl->config.tlsConfig);

    HITLS_CERT_X509 *server_ChainCert = NULL;
    HITLS_CERT_X509 *client_PeerEECert = NULL;
    HITLS_CERT_X509 *client_PeerChainCert = NULL;

    server_ChainCert = (HITLS_CERT_X509*)server_Chain->first->data; // server chain cert
    client_PeerEECert = (HITLS_CERT_X509*)client_PeerChain->first->data; // server ee cert
    client_PeerChainCert = (HITLS_CERT_X509*)client_PeerChain->last->data; // server chain cert

    int client_resulte = 0;
    int server_resulte = 0;
    ASSERT_TRUE(client_PeerCert != NULL);
    if ((X509_CertCmp(client_PeerCert, server_Cert) == 0) && (X509_CertCmp(client_PeerEECert, server_Cert) == 0) &&
        (X509_CertCmp(client_PeerChainCert, server_ChainCert) == 0)) {
        client_resulte = 1;
    } else {
        client_resulte = 0;
    }
    // After the session is resumed, the peer certificate chain of the server is empty, but the peer certificate is not
    // empty.
    ASSERT_TRUE(server_PeerChain == NULL);
    ASSERT_TRUE(server_PeerCert != NULL);
    if (X509_CertCmp(server_PeerCert, client_Cert) == 0) {
        server_resulte = 1;
    } else {
        server_resulte = 0;
    }

    HITLS_X509_CertFree(client_PeerCert);
    HITLS_X509_CertFree(server_PeerCert);

    if (client_resulte & server_resulte) {
        return HITLS_SUCCESS;
    } else {
        return 1;
    }
EXIT:
    return 1;
}

/* BEGIN_CASE */
void HITLS_TLS_KeepPeerCertFunc_OnceVerify_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetClientVerifySupport(config_s, true);
    HITLS_CFG_SetClientOnceVerifySupport(config_s, true);
    HITLS_CFG_SetRenegotiationSupport(config_s, true);
    HITLS_CFG_SetRenegotiationSupport(config_c, true);
    HITLS_CFG_SetKeepPeerCertificate(config_s, true);
    HITLS_CFG_SetKeepPeerCertificate(config_c, true);

    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_CERT_X509 *getCert_s1 = HITLS_GetPeerCertificate(server->ssl);
    HITLS_CERT_Chain *certChain_s1 = HITLS_GetPeerCertChain(server->ssl);
    ASSERT_TRUE(getCert_s1 != NULL);
    ASSERT_TRUE(certChain_s1 != NULL);
    HITLS_CFG_FreeCert(config_s, getCert_s1);

    ASSERT_EQ(HITLS_Renegotiate(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiation(client, server), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    HITLS_CERT_X509 *getCert_s = HITLS_GetPeerCertificate(server->ssl);
    HITLS_CERT_Chain *certChain_s = HITLS_GetPeerCertChain(server->ssl);
    ASSERT_TRUE(getCert_s == NULL);
    ASSERT_TRUE(certChain_s == NULL);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC001
* @spec -
* @title TLS12 caches the peer certificate by default.
* @precon nan
* @brief
* 1. Initialize the TLS12 client and server.
* 2. Establish a link. After the link is established, the HITLS_GetPeerCertificate and HITLS_GetPeerCertChain interfaces are
* invoked to check the peer certificate cached at both ends.
* @expect
* 1. Initialization succeeded.
* 2. The link is successfully established. The certificate cached on the client is the same as the certificate sent by the
*  server.The peer certificate cached on the server is NULL.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC001(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, true), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC002
* @spec -
* @title Enabling Peer Certificate Caching, Dual-End Authentication, and Empty Client Certificate, and Allowing the
*           Client to Send an Empty Certificate
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_SetKeepPeerCertificate interface to enable the function of caching the peer certificate and set
*    an empty certificate.
* 2. Enable two-way authentication on the server and allow the client to send an empty certificate.
* 3. Set up a link. After the link is set up, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check whether the
*    peer certificate cached on the server is NULL.
* @expect
* 1. Setting succeeded.
* 2. Setting succeeded.
* 3. The server cache certificate is empty.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC002(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetNoClientCertSupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) , HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, true) , HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC003
* @spec -
* @title TLS 12 enables dual-end authentication and peer certificate caching.
* @precon nan
* @brief
* 1. The client invokes the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer certificate caching function.
* 2. Establish a link. After the link is established, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check
*    whether the peer certificate cached at both ends is correct.
* @expect
* 1. Setting succeeded.
* 2. The link is successfully established. The cached certificate is the same as the certificate sent by the peer end.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC003(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC004
* @spec -
* @title TLS12 enables dual-end authentication and disables caching of the peer certificate.
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_SetKeepPeerCertificate interface to disable peer certificate caching and enable two-way authentication.
* 2. Establish a link. After the link is established, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check whether
*  the peer certificate cached at both ends is NULL.
* @expect
* 1. Setting succeeded.
* 2. Whether the Peer Certificate Cached at Both Ends Is NULL When Link Establishment Is Successful
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC004(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, false);
    HITLS_CFG_SetKeepPeerCertificate(s_config, false);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, true, true), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC005
* @spec -
* @title Enable dual-end authentication during renegotiation.
* @precon nan
* @brief
* 1. Disable the function of caching the peer certificate and set up a link when the client invokes the
*    HITLS_CFG_SetKeepPeerCertificate interface.
* 2. Enable dual-end authentication on the server and initiate renegotiation.
* 3. Establish a link. After the link is established, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check
*    whether the peer certificate cached at both ends is correct.
* @expect
* 1. Link setup success
* 2. The setting is successful and renegotiation is initiated.
* 3. The link is successfully established. The cached certificate is the same as the certificate sent by the peer end.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC005(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, false);
    HITLS_CFG_SetKeepPeerCertificate(s_config, false);
    HITLS_CFG_SetRenegotiationSupport(c_config, true);
    HITLS_CFG_SetRenegotiationSupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_SetKeepPeerCertificate(client->ssl, true);
    HITLS_SetKeepPeerCertificate(server->ssl, true);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC006
* @spec -
* @title Enable caching of the peer certificate and renegotiate a new certificate.
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_SetKeepPeerCertificate interface to enable the function of caching the peer certificate and
*    set up a link.
* 2. Set the algorithm suite to HITLS_RSA_WITH_AES_128_CCM on the client and initiate renegotiation.
* 3. After the renegotiation is complete, check whether the peer certificate cached on the client is an RSA certificate.
* @expect
* 1. Link setup success
* 2. The setting is successful and renegotiation is initiated.
* 3. The client caches the RSA certificate, which is the same as the certificate sent by the peer end during renegotiation.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC006(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_CERT_Store *verifyStore = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, false);
    HITLS_CFG_SetKeepPeerCertificate(s_config, false);
    HITLS_CFG_SetRenegotiationSupport(c_config, true);
    HITLS_CFG_SetRenegotiationSupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, true, true), HITLS_SUCCESS);

    char certChain2File[] = "../testdata/tls/certificate/der/ecdsa/inter-nist521.der";
    char certee2File[] = "../testdata/tls/certificate/der/ecdsa/end256-sha256.der";
    char privatekey2File[] = "../testdata/tls/certificate/der/ecdsa/end256-sha256.key.der";
    char caCertFile[] = "../testdata/tls/certificate/der/ecdsa/ca-nist521.der";

    HITLS_CERT_X509 *caCert = HITLS_CFG_ParseCert(c_config, (const uint8_t *)caCertFile,
        strlen(caCertFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certChain2 = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChain2File,
        strlen(certChain2File) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee2 = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certee2File,
        strlen(certee2File) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey2 = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekey2File,
        strlen(privatekey2File) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain2 != NULL);
    ASSERT_TRUE(certee2 != NULL);
    ASSERT_TRUE(privatekey2 != NULL);
    ASSERT_TRUE(caCert != NULL);

    verifyStore = SAL_CERT_StoreNew(s_config->certMgrCtx);
    ASSERT_TRUE(verifyStore != NULL);
    SAL_CERT_StoreCtrl(s_config, verifyStore, CERT_STORE_CTRL_ADD_CERT_LIST, caCert, NULL);
    
    ASSERT_EQ(HITLS_CFG_SetVerifyStore(&client->ssl->config.tlsConfig, verifyStore, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetVerifyStore(&server->ssl->config.tlsConfig, verifyStore, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(&client->ssl->config.tlsConfig, certee2, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(&client->ssl->config.tlsConfig, privatekey2, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(&client->ssl->config.tlsConfig, certChain2, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(&server->ssl->config.tlsConfig, certee2, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(&server->ssl->config.tlsConfig, privatekey2, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(&server->ssl->config.tlsConfig, certChain2, false), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_SetKeepPeerCertificate(client->ssl, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetKeepPeerCertificate(server->ssl, true), HITLS_SUCCESS);

    uint16_t cipher[] = {HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};
    ASSERT_EQ(HITLS_SetCipherSuites(client->ssl, cipher, sizeof(cipher)/sizeof(uint16_t)), HITLS_SUCCESS);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_SetSigalgsList(client->ssl, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC007
* @spec -
* @title Client Sending an Empty Certificate During Renegotiation
* @precon nan
* @brief
* 1. The client invokes the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer certificate caching function.
* 2. Configure an empty certificate on the client, configure the server to allow the client to send an empty certificate,
*    and initiate renegotiation.
* 3. Set up a link. After the link is set up, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check whether
*    the peer certificate cached on the server is NULL.
* @expect
* 1. Link setup success
* 2. The setting is successful and renegotiation is initiated.
* 3. The link is successfully established, and the certificate cached on the server is NULL.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC007(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetNoClientCertSupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);
    HITLS_CFG_SetRenegotiationSupport(c_config, true);
    HITLS_CFG_SetRenegotiationSupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);

    uint32_t keyType = client->ssl->config.tlsConfig.certMgrCtx->currentCertKeyType;
    ASSERT_TRUE(keyType != TLS_CERT_KEY_TYPE_UNKNOWN);
    CERT_Pair *currentCertPair =  NULL;
    CERT_MgrCtx *mgrCtx = client->ssl->config.tlsConfig.certMgrCtx;
    (void)BSL_HASH_At(mgrCtx->certPairs, (uintptr_t)mgrCtx->currentCertKeyType, (uintptr_t *)&currentCertPair);
    ASSERT_NE(currentCertPair, NULL);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    // The deep copy of the current certificate does use the reference counting mode. so isServerPeerCertNull is false.
    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC008
* @spec -
* @title Certificates are cached during the first link setup and are not cached during renegotiation.
* @precon nan
* @brief
* 1. The client invokes the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer certificate caching function.
* 2. Disable the caching of the peer certificate on the client and server and initiate renegotiation.
* 3. Establish a link. After the link is established, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check
*  whether the peer certificate cached at both ends is NULL.
* @expect
* 1. Link setup success
* 2. The setting is successful and renegotiation is initiated.
* 3. The link is successfully established, and the cached certificate is NULL.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC008(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);
    HITLS_CFG_SetRenegotiationSupport(c_config, true);
    HITLS_CFG_SetRenegotiationSupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);

    HITLS_SetKeepPeerCertificate(client->ssl, false);
    HITLS_SetKeepPeerCertificate(server->ssl, false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, true, true), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC009
* @spec -
* @title Enable caching of the peer certificate, verify the client only once, and perform renegotiation.
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer certificate cache function. Enable two-way
*    authentication.
* 2. Initiate renegotiation.
* 3. After the renegotiation is complete, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check whether the
*    peer certificate cached on the server is NULL
* @expect
* 1. Link setup success
* 2. Renegotiation initiated successfully.
* 3. The link is successfully established, and the cached certificate is NULL.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC009(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetClientOnceVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);
    HITLS_CFG_SetRenegotiationSupport(c_config, true);
    HITLS_CFG_SetRenegotiationSupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_Certificates(client, server, false, true), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC010
* @spec -
* @title Enabling Peer Certificate Caching and Resuming Sessions
* @precon nan
* @brief
* 1. The client invokes the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer certificate caching function.
* 2. Initiate session recovery.
* 3. After the session is restored, the HITLS_GetPeerCertificate and HITLS_GetPeerCertChain interfaces are invoked to check
*    the peer certificate cached at both ends.
* @expect
* 1. Link setup success
* 2. Session resumption initiated successfully.
* 3. The link is successfully established. The cached certificate is the peer certificate used during the first link establishment.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC010(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *Session = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(Session != NULL);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, Session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isResume, true);

    ASSERT_EQ(Compare_ResumeCertificates(client, server), HITLS_SUCCESS);
EXIT:
    HITLS_SESS_Free(Session);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC011
* @spec -
* @title Not enabled for the first time. Peer-end certificate caching is enabled for session recovery.
* @precon nan
* @brief
* 1. When the client and server invoke the HITLS_CFG_SetKeepPeerCertificate interface, the peer certificate caching
*    function is disabled.
* 2. Enable the function of caching the peer certificate on the client and server and initiate session recovery.
* 3. After session restoration is complete, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check whether the
*    peer certificate cached at both ends is NULL.
* @expect
* 1. Link setup success
* 2. Session resumption initiated successfully.
* 3. Whether the peer certificate in the dual-end cache is NULL
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC011(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *Session = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, false);
    HITLS_CFG_SetKeepPeerCertificate(s_config, false);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(Session != NULL);

    ASSERT_EQ(Compare_Certificates(client, server, true, true), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);
    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, Session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isResume, true);

    ASSERT_EQ(Compare_Certificates(client, server, true, true), HITLS_SUCCESS);
EXIT:
    HITLS_SESS_Free(Session);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC012
* @spec -
* @title Enabled for the First Time, Peer Certificate Cache Disabled for Session Restoration, Session Restoration
* @precon nan
* @brief
* 1. The client invokes the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer certificate caching function.
* 2. Disable the function of caching the peer certificate on the client and server and initiate session recovery.
* 3. After the session is restored, the HITLS_GetPeerCertificate and HITLS_GetPeerCertChain interfaces are invoked to check
*    the peer certificate cached at both ends.
* @expect
* 1. Link setup success
* 2. Session resumption initiated successfully.
* 3. The link is successfully established. The cached certificate is the peer certificate used for the first link establishment.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC012(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *Session = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(Session != NULL);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    HITLS_CFG_SetKeepPeerCertificate(c_config, false);
    HITLS_CFG_SetKeepPeerCertificate(s_config, false);
    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, Session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isResume, true);
    ASSERT_EQ(server->ssl->negotiatedInfo.isResume, true);

    ASSERT_EQ(Compare_ResumeCertificates(client, server), HITLS_SUCCESS);
EXIT:
    HITLS_SESS_Free(Session);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC013
* @spec -
* @title Enabled for the First Time, Peer Certificate Cache Disabled for Session Restoration, Session Restoration
* @precon nan
* @brief
* 1. The client invokes the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer certificate cache and
*    authentication after handshake.
* 2. Establish a link. After the link is established, invoke HITLS_GetPeerCertificate and HITLS_GetPeerCertChain to check
*    whether the peer certificate cached at both ends is correct. Expected result 2 is displayed.
* 3. Authentication after the server initiates a handshake
* 4. Check whether the peer certificate in the dual-end cache is correct.
* @expect
* 1. Setting succeeded.
* 2. The link is successfully established. The client caches the peer certificate, and the server cache is NULL.
* 3. Authentication completed after handshake.
* 4. Peer certificates can be cached on both the client and server.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC013(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);
    HITLS_CFG_SetPostHandshakeAuthSupport(c_config, true);
    HITLS_CFG_SetPostHandshakeAuthSupport(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(Compare_Certificates(client, server, false, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_VerifyClientPostHandshake(server->ssl) == HITLS_SUCCESS);

    uint8_t readbuff[READ_BUF_LEN_18K];
    uint32_t readLen = 0;

    // request
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    // certificate
    ASSERT_EQ(HITLS_Read(client->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_SEND_CERTIFICATE_VERIFY);
    ASSERT_EQ(HITLS_Read(server->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_RECV_CERTIFICATE_VERIFY);

    // verify
    ASSERT_EQ(HITLS_Read(client->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_SEND_FINISH);
    ASSERT_EQ(HITLS_Read(server->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_RECV_FINISH);

    // finish
    ASSERT_EQ(HITLS_Read(client->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(HITLS_Read(server->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_SEND_NEW_SESSION_TICKET);

    // new sessionticket
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_SEND_NEW_SESSION_TICKET);

    // new sessionticket
    ASSERT_EQ(HITLS_Read(server->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_KeepPeerCertificate_TC014
* @spec -
* @title Session Recovery After the Peer Certificate Caching Function Is Enabled for TLS13
* @precon nan
* @brief
* 1. Apply for a TLS13 client and server, invoke the HITLS_CFG_SetKeepPeerCertificate interface to enable the peer
*    certificate, and enable two-way authentication.
* 2. Initiate session recovery.
* 3. After the session is restored, the HITLS_GetPeerCertificate and HITLS_GetPeerCertChain interfaces are invoked to check
*    the peer certificate cached at both ends.
* @expect
* 1. Link setup success
* 2. Session resumption initiated successfully.
* 3. The link is successfully established. The cached certificate is the peer certificate used during the first link establishment.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_KeepPeerCertificate_TC014(void)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    HITLS_Config *c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_CertInfo certInfo = {RSA_SHA_CA_PATH, 0, 0, 0, 0, 0};
    char certChainFile[] = "../testdata/tls/certificate/der/rsa_sha/inter-3072.der";
    char certeeFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.der";
    char privatekeyFile[] = "../testdata/tls/certificate/der/rsa_sha/end-sha256.key.der";

    HITLS_CERT_X509 *certChain = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certChainFile,
        strlen(certChainFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *certee = HITLS_CFG_ParseCert(c_config, (const uint8_t *)certeeFile,
        strlen(certeeFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_Key *privatekey = HITLS_CFG_ParseKey(c_config, (const uint8_t *)privatekeyFile,
        strlen(privatekeyFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_TRUE(certee != NULL);
    ASSERT_TRUE(privatekey != NULL);

    HITLS_CFG_SetClientVerifySupport(s_config, true);
    HITLS_CFG_SetKeepPeerCertificate(c_config, true);
    HITLS_CFG_SetKeepPeerCertificate(s_config, true);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(c_config, certee, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(c_config, privatekey, true) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(c_config, certChain, true), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_SetCertificate(s_config, certee, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPrivateKey(s_config, privatekey, false) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_AddChainCert(s_config, certChain, false), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(Compare_Certificates(client, server, false, false), HITLS_SUCCESS);

    HITLS_Session *Session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(Session != NULL);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    client = FRAME_CreateLinkWithCert(c_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(s_config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, Session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(Compare_ResumeCertificates(client, server), HITLS_SUCCESS);
EXIT:
    HITLS_SESS_Free(Session);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_HITLS_CM_SETRECORDSIZELIMIT_API_TC001
* @spec  -
* @title  Testing the HITLS_SetRecordSizeLimit interface
* @precon  nan
@ */
/* BEGIN_CASE */
void SDV_HITLS_CM_SETRECORDSIZELIMIT_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetRecordSizeLimit(NULL, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_NULL_INPUT);

    ctx->state = CM_STATE_HANDSHAKING;
    ASSERT_TRUE(HITLS_SetRecordSizeLimit(ctx, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_CM_LINK_HANDSHAKING);
    ctx->state = CM_STATE_RENEGOTIATION;
    ASSERT_TRUE(HITLS_SetRecordSizeLimit(ctx, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_CM_LINK_HANDSHAKING);
    ctx->state = CM_STATE_ALERTING;
    ASSERT_TRUE(HITLS_SetRecordSizeLimit(ctx, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_CM_LINK_HANDSHAKING);
    ctx->state = CM_STATE_ALERTED;
    ASSERT_TRUE(HITLS_SetRecordSizeLimit(ctx, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_CM_LINK_HANDSHAKING);
    ctx->state = CM_STATE_CLOSED;
    ASSERT_TRUE(HITLS_SetRecordSizeLimit(ctx, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_CM_LINK_HANDSHAKING);

    ctx->state = CM_STATE_IDLE;
    ASSERT_TRUE(HITLS_SetRecordSizeLimit(ctx, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_SUCCESS);
    ctx->state = CM_STATE_TRANSPORTING;
    ASSERT_TRUE(HITLS_SetRecordSizeLimit(ctx, HITLS_MIN_RECORDSIZE_LIMIT) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  HITLS_UT_TLS_GET_RECORDSIZELIMIT_API_TC001
* @spec  -
* @title  Cover Abnormal Input Parameters of the HITLS_GetRecordSizeLimit Interface
* @precon  nan
* @brief  1.Invoke the HITLS_GetRecordSizeLimit interface. Ctx is NULL, recordSizeLimit is not NULL. Expected result 2.
*         2.Invoke the HITLS_GetRecordSizeLimit interface. Ctx is not NULL, recordSizeLimit is not NULL. Expected result 1.
* @expect  1.Return HITLS_SUCCESS
*          2.Return HITLS_NULL_INPUT
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_UT_TLS_GET_RECORDSIZELIMIT_API_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    uint16_t recordSizeLimit = 0;

    int32_t ret = HITLS_GetRecordSizeLimit(NULL, &recordSizeLimit);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_GetRecordSizeLimit(ctx, &recordSizeLimit);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  HITLS_UT_TLS_GET_RECORD_SIZE_LIMIT_TC001
 * @spec  -
 * @title  Cover Abnormal Input Parameters of the HITLS_CFG_GetRecordSizeLimit Interface
 * @precon  nan
 * @brief  1.Invoke the HITLS_CFG_GetRecordSizeLimit interface. Config is NULL, recordSize is not NULL. Expected result 2.
 *         2.Invoke the HITLS_CFG_GetRecordSizeLimit interface. Config is not NULL, recordSize is NULL. Expected result 2.
 *         3.Invoke the HITLS_CFG_GetRecordSizeLimit interface. Config is not NULL, recordSize is not NULL. Expected result 1.
 * @expect  1.Return HITLS_SUCCESS
 *          2.Return HITLS_NULL_INPUT
 * @prior  Level 1
 * @auto  TRUE
 **/
/* BEGIN_CASE */
void HITLS_UT_TLS_GET_RECORD_SIZE_LIMIT_TC001(void)
{
    HitlsInit();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t size = 0;
    int32_t ret = HITLS_CFG_GetRecordSizeLimit(NULL, &size);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_CFG_GetRecordSizeLimit(tlsConfig, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_CFG_GetRecordSizeLimit(tlsConfig, &size);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    return;
}
/* END_CASE */