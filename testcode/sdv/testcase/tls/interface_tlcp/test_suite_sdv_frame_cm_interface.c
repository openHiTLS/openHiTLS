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

#include <stdlib.h>
#include <unistd.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "bsl_uio.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_reg.h"
#include "hitls_config.h"
#include "tls_config.h"
#include "hitls.h"
#include "hs_common.h"
#include "hitls_func.h"
#include "tls.h"
#include "conn_init.h"
#include "crypt_errno.h"
#include "stub_utils.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "rec_wrapper.h"
#include "hlt_type.h"
#include "hlt.h"
#include "process.h"
#include "hitls_crypt_init.h"
#include "bsl_list.h"
#include "simulate_io.h"
#include "alert.h"
#include "crypt_default.h"
#include "stub_crypt.h"
#include "hitls_crypt.h"

#define READ_BUF_SIZE 18432
#define MAX_CERT_LIST 4294967295
#define MIN_CERT_LIST 0
#define DEFAULT_SECURITYLEVEL 0
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
// HS_ChangeState stub is defined in frame_connect.c (part of libtls_frame.a)
// Declare extern to use it
typedef int32_t (*real_HS_ChangeState_func_t)(TLS_Ctx *, uint32_t);
typedef struct HS_ChangeState_Stub {
    void *stub_handle;
    const char *stub_target_symbol;
    int32_t (*stub_impl)(TLS_Ctx *, uint32_t);
    real_HS_ChangeState_func_t stub_real_impl;
} HS_ChangeState_Stub;
extern HS_ChangeState_Stub HS_ChangeState_stub;
extern void HS_ChangeState_restore(void);


static HITLS_Config *GetHitlsConfigViaVersion(int ver)
{
    HITLS_Config *config;
    int32_t ret;
    switch (ver) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            ret = HITLS_CFG_SetCheckKeyUsage(config, false);
            if (ret != HITLS_SUCCESS) {
                return NULL;
            }
            return config;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            ret = HITLS_CFG_SetCheckKeyUsage(config, false);
            if (ret != HITLS_SUCCESS) {
                return NULL;
            }
            return config;
        case HITLS_VERSION_DTLS12:
            config = HITLS_CFG_NewDTLS12Config();
            ret = HITLS_CFG_SetCheckKeyUsage(config, false);
            if (ret != HITLS_SUCCESS) {
                return NULL;
            }
            return config;
        default:
            return NULL;
    }
}

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isSupportRenegotiation;
    bool isSupportSessionTicket;
    bool needStopBeforeRecvCCS;
} HandshakeTestInfo;

static uint8_t g_clientRandom[RANDOM_SIZE];
static uint8_t g_serverRandom[RANDOM_SIZE];

/* @
* @test  UT_TLS_CM_SET_GET_UIO_API_TC001
* @title  Test the HITLS_SetUio and HITLS_GetUio interfaces
* @precon  nan
* @brief   HITLS_SetUio
*          1. Input an empty connection context and a non-empty UIO. Expected result 1 is obtained
*          2. Input an empty connection context and an empty UIO. Expected result 1 is obtained
*          3. Input a non-empty connection context and an empty UIO. Expected result 1 is obtained
*          4. Input a non-empty connection context and a non-empty UIO. Expected result 2 is obtained
*          HITLS_GetUio
*          1. Input an empty connection context. Expected result 3 is obtained
*          2. Input a non-empty connection context. Expected result 4 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCESS
*          3. Return a null pointer
*          4. Return connection uio
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_UIO_API_TC001(int tlsVersion)
{
    HitlsInit();

    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_Ctx* ctx = HITLS_New(tlsConfig);
    BSL_UIO *uio = NULL;
    BSL_UIO *uio2;
    int32_t ret;

    uio = BSL_UIO_New(BSL_UIO_TcpMethod());

    ret = HITLS_SetUio(NULL, uio);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetUio(NULL, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetUio(ctx, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetUio(ctx, uio);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    uio2 = HITLS_GetUio(NULL);
    ASSERT_TRUE(uio2 == NULL);

    uio2 = HITLS_GetUio(ctx);
    ASSERT_TRUE(uio2 != NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    BSL_UIO_Free(uio);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_GET_READ_UIO_API_TC001
* @title  Test the HITLS_SetReadUio, HITLS_GetReadUio interfaces
* @precon  nan
* @brief   HITLS_SetReadUio
*          1. Input an empty connection context and a non-empty UIO. Expected result 1 is obtained
*          2. Input an empty connection context and an empty UIO. Expected result 1 is obtained
*          2. Input a non-empty connection context and an empty UIO. Expected result 1 is obtained
*          4. Input a non-empty connection context and a non-empty UIO. Expected result 2 is obtained
*          HITLS_GetReadUio
*          1. Input an empty connection context. Expected result 3 is obtained
*          2. Input a non-empty connection context. Expected result 4 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCESS
*          3. Return a null pointer
*          4. Return connection uio
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_READ_UIO_API_TC001(int tlsVersion)
{
    HitlsInit();

    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(tlsConfig != NULL)   ;

    HITLS_Ctx* ctx = HITLS_New(tlsConfig);
    BSL_UIO *uio = NULL;
    BSL_UIO *uio2  = NULL;
    int32_t ret;

    uio = BSL_UIO_New(BSL_UIO_TcpMethod());

    ret = HITLS_SetReadUio(NULL, uio);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetReadUio(NULL, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetReadUio(ctx, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetReadUio(ctx, uio);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    uio2 = HITLS_GetReadUio(NULL);
    ASSERT_TRUE(uio2 == NULL);

    uio2 = HITLS_GetReadUio(ctx);
    ASSERT_TRUE(uio2 != NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    BSL_UIO_Free(uio);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_ENDPOINT_FUNC_TC001
* @title  Invoke HITLS_SetEndPoint after initialization, check whether the state is handshaking
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1 is obtained
*          2. After initialization, call HITLS_SetEndPoint and check the state status. Expected result 2 is obtained
* @expect  1. Complete initialization
*          2. state is handshaking
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_ENDPOINT_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    uint32_t ret = HITLS_SetEndPoint(server->ssl, true);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->state, CM_STATE_IDLE);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  The HITLS_SetEndPoint function fails to be invoked during link establishment
* @title  UT_TLS_CM_SET_ENDPOINT_FUNC_TC002
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1 is obtained
*          2. Invoke HITLS_SetEndPoint during link establishment. Expected result 2 is obtained
* @expect  1. Complete initialization
*          2. Invoking failed
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_ENDPOINT_FUNC_TC002(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO) == HITLS_SUCCESS);
    uint32_t ret = HITLS_SetEndPoint(server->ssl, true);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_STATE_ILLEGAL);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test Obtains the maximum writable plaintext length after initialization
* @title  UT_TLS_CM_GET_MAXWRITESIZE_FUNC_TC001
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1 is obtained
*          2. Invoke HITLS_GetMaxWriteSize to obtain the maximum writable plaintext length.
*          Expected result 2 is obtained
* @expect  1. Complete initialization
*          2. Obtain the length successfully, the length is equal to REC_MAX_PLAIN_LENGTH
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_MAXWRITESIZE_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    uint32_t len = 0;
    uint32_t ret = CONN_Init(client->ssl);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_GetMaxWriteSize(client->ssl, &len);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(len, REC_MAX_PLAIN_LENGTH);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_GET_USR_DATA_TC001
* @title  test HITLS_SetUserData, HITLS_GetUserData interfaces
* @precon  nan
* @brief   HITLS_SetUserData
*          1. Input an empty connection context and a non-empty userData. Expected result 1 is obtained
*          2. Input an empty connection context and an empty userData. Expected result 1 is obtained
*          3. Input a non-empty connection context and an empty userData. Expected result 2 is obtained
*          4. Input a non-empty connection context and a non-empty userData. Expected result 2 is obtained
*          HITLS_GetUserData
*          1. Input an empty connection context. Expected result 4 is obtained
*          2. Input a non-empty connection context. Expected result 3 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCESS
*          3. Return userData
*          4. Return a null pointer
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_USR_DATA_API_TC001(int tlsVersion)
{
    HitlsInit();

    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(tlsConfig != NULL)   ;

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    int32_t ret;
    uint8_t userData[5] = {0};

    void *ret2 = HITLS_GetUserData(NULL);
    ASSERT_TRUE(ret2 == NULL);

    ret = HITLS_SetUserData(NULL, &userData);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetUserData(NULL, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetUserData(ctx, NULL);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_SetUserData(ctx, &userData);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_SetUserData(ctx, "userdata");
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret2 = HITLS_GetUserData(ctx);
    ASSERT_TRUE(strcmp(ret2, "userdata") == 0);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */


/* @
* @test  UT_TLS_CM_SET_GET_USR_DATA_TC001
* @title  test HITLS_SESS_SetUserData, HITLS_SESS_GetUserData interfaces
* @precon  nan
* @brief   HITLS_SESS_GetUserData
*          1. Input an empty connection context and a non-empty userData. Expected result 1 is obtained
*          2. Input an empty connection context and an empty userData. Expected result 1 is obtained
*          3. Input a non-empty connection context and an empty userData. Expected result 2 is obtained
*          4. Input a non-empty connection context and a non-empty userData. Expected result 2 is obtained
*          HITLS_SESS_GetUserData
*          1. Input an empty connection context. Expected result 4 is obtained
*          2. Input a non-empty connection context. Expected result 3 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCESS
*          3. Return userData
*          4. Return a null pointer
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SESSION_SET_GET_USR_DATA_API_TC001(void)
{
    HitlsInit();
    HITLS_Session *session = HITLS_SESS_New();
    int32_t ret;
    uint8_t userData[5] = {0};

    void *ret2 = HITLS_SESS_GetUserData(NULL);
    ASSERT_TRUE(ret2 == NULL);

    ret = HITLS_SESS_SetUserData(NULL, &userData);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SESS_SetUserData(NULL, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SESS_SetUserData(session, NULL);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_SESS_SetUserData(session, &userData);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_SESS_SetUserData(session, "userdata");
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret2 = HITLS_SESS_GetUserData(session);
    ASSERT_TRUE(strcmp(ret2, "userdata") == 0);
EXIT:
    HITLS_SESS_Free(session);
}
/* END_CASE */


/* @
* @test  HITLS_SetShutdownState Set HITLS_SENT_SHUTDOWN to 1 and do not send the close_notify message.
* @title  UT_TLS_CM_SET_SHUTDOWN_FUNC_TC001
* @precon nan
* @brief   1. Set HITLS_SENT_SHUTDOWN to 1 and invoke the Hitls_Close interface. Expected result 1 is obtained
* @expect  1. The interface is successfully invoked and the close_notify message is not sent
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SET_SHUTDOWN_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_SetShutdownState(client->ssl, 1) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Close(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_CLOSED);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint32_t readLen = ioUserData->recMsg.len;
    ASSERT_TRUE(readLen == 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_SHUTDOWN_FUNC_TC001
* @title  Use HITLS_GetShutdownState to obtain the configured value
* @precon nan
* @brief   1. Set HITLS_SENT_SHUTDOWN to 1 and invoke the HITLS_GetShutdownState interface. Expected result 1
*          2. Set HITLS_SENT_SHUTDOWN to 2 and invoke the HITLS_GetShutdownState interface. Expected result 2
*          3. Set HITLS_SENT_SHUTDOWN to 0 and invoke the HITLS_GetShutdownState interface. Expected result 3
* @expect  1. Obtain value 1
*          2. Obtain value 2
*          3. Obtain value 0.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_SHUTDOWN_FUNC_TC001(int version)
{
    int32_t ret;
    uint32_t mode;
    HitlsInit();
    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    CONN_Init(ctx);
    ASSERT_TRUE(ctx != NULL);

    for (uint32_t i = 0; i <= 2; i++) {
        ret = HITLS_SetShutdownState(ctx, i);
        ASSERT_TRUE(ret == HITLS_SUCCESS);
        ret = HITLS_GetShutdownState(ctx, &mode);
        ASSERT_TRUE(ret == HITLS_SUCCESS);
        ASSERT_TRUE(mode == i);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_NEGOTIATED_VERSION_FUNC_TC001
* @title  HITLS_GetNegotiatedVersion Interface in TLS1.2 Scenario and TLS1.3 Scenario
* @precon  nan
* @brief   1. Set the protocol version to TLS1.2 or TLS1.3. After initialization, invoke the HITLS_GetNegotiatedVersion
*          interface to obtain the negotiated version number. Expected result 1 is obtained
*          2. Set the protocol version to TLS1.2 or TLS1.3. After the connection is established, invoke the
*          HITLS_GetNegotiatedVersion interface to obtain the negotiated version number. Expected result 2 is obtained
* @expect  1. obtained value is 0
*          2. obtained value is tls1.2/tls1.3
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_NEGOTIATED_VERSION_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
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
    uint16_t negoVersion = HITLS_VERSION_TLCP_DTLCP11;
    ret = HITLS_GetNegotiatedVersion(client->ssl, &negoVersion);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(negoVersion, 0);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ret = HITLS_GetNegotiatedVersion(client->ssl, &negoVersion);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(negoVersion, version);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_GET_MAX_PROTO_VERSION_API_TC001
* @title  test HITLS_SetMaxProtoVersion, HITLS_GetMaxProtoVersion interfaces
* @precon  nan
* @brief   HITLS_SetMaxProtoVersion
*          1. Input an empty connection context. Expected result 1 is obtained
*          2. Input a non-empty connection context and version is too low. Expected result 2 is obtained
*          3. Input a non-empty connection context and normal version. Expected result 3 is obtained
*          HITLS_GetMaxProtoVersion
*          1. Input an empty connection context and a null pointer. Expected result 1 is obtained
*          2. Input an empty connection context and a non-empty pointer. Expected result 1 is obtained
*          3. Input a non-empty connection context and a non-empty pointer. Expected result 3 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_CONFIG_INVALID_VERSION
           3. Return HITLS_SUCCESS
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_MAX_PROTO_VERSION_API_TC001(int tlsVersion)
{
    HitlsInit();

    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    int32_t ret;
    uint16_t maxVersion = 0;

    ret = HITLS_SetMaxProtoVersion(NULL, HITLS_VERSION_TLS10);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetMaxProtoVersion(ctx, HITLS_VERSION_TLS10);
    ASSERT_TRUE(ret == HITLS_CONFIG_INVALID_VERSION);

    ret = HITLS_SetMaxProtoVersion(ctx, HITLS_VERSION_TLS13);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_GetMaxProtoVersion(NULL, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_GetMaxProtoVersion(NULL, &maxVersion);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_GetMaxProtoVersion(ctx, &maxVersion);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_GET_MIN_PROTO_VERSION_API_TC001
* @title  test HITLS_SetMinProtoVersion, HITLS_GetMinProtoVersion interfaces
* @precon  nan
* @brief   HITLS_SetMaxProtoVersion
*          1. Input an empty connection context. Expected result 1 is obtained
*          2. Input a non-empty connection context and version is too high. Expected result 2 is obtained
*          3. Input a non-empty connection context and normal version. Expected result 3 is obtained
*          HITLS_GetMinProtoVersion
*          1. Input an empty connection context and a null pointer. Expected result 1 is obtained
*          2. Input an empty connection context and a non-empty pointer. Expected result 1 is obtained
*          3. Input a non-empty connection context and a non-empty pointer. Expected result 3 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_CONFIG_INVALID_VERSION
*          3. Return HITLS_SUCCESS
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_MIN_PROTO_VERSION_API_TC001(int tlsVersion)
{
    HitlsInit();

    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(tlsConfig != NULL)   ;

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    int32_t ret;
    uint16_t minVersion = 0;

    ret = HITLS_SetMinProtoVersion(NULL, HITLS_VERSION_TLS12);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetMinProtoVersion(ctx, HITLS_VERSION_TLS13);
    ASSERT_TRUE(ret == HITLS_CONFIG_INVALID_VERSION);

    ret = HITLS_SetMinProtoVersion(ctx, HITLS_VERSION_TLS12);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_GetMinProtoVersion(NULL, NULL);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_GetMinProtoVersion(NULL, &minVersion);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_GetMinProtoVersion(ctx, &minVersion);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_IS_AEAD_FUNC_TC001
* @title  HITLS_IsAead Obtains whether to use the AEAD algorithm after negotiation
* @precon  TLS12, HITLS_RSA_with_AES_128_CBC_SHA256 (not AEAD), TLS13, HITLS_CHACHA20_POLY1305_SHA256 /
*          HITLS_AES_128_GCM_SHA256 (AEAD)
* @brief   1. Initialize the client and server and set the cipherSuite. Expected result 1
*          2. After connection is established, invoke HITLS_IsAead to check whether
*          the AEAD algorithm is negotiated. Expected result 2
* @expect  1. Initialization is complete.
*          2. Value of isAEAD
@ */
/* BEGIN_CASE */
void UT_TLS_CM_IS_AEAD_FUNC_TC001(int version, int ciphersuite)
{
    FRAME_Init();
    int ret;
    bool isAEAD = false;
    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    uint16_t cipherSuites[] = {(uint16_t)ciphersuite};

    HITLS_CFG_SetCipherSuites(config_c, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ret = HITLS_IsAead(client->ssl, &isAEAD);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isAEAD == (version == HITLS_VERSION_TLS13));

    ret = HITLS_IsAead(server->ssl, &isAEAD);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isAEAD == (version == HITLS_VERSION_TLS13));

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_IsHandShakeDone Check whether the handshake is complete during connection establishment
* @title  UT_TLS_CM_IS_HSDONE_FUNC_TC001
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1
*          2. During connection establishment, invoke HITLS_IsHandShakeDone to check whether the handshake is complete.
*          Expected result 2
* @expect  1. Initialization is complete
*          2. The interface returns 0 and the handshake is not done
@ */
/* BEGIN_CASE */
void UT_TLS_CM_IS_HSDONE_FUNC_TC001(int version, int state)
{
    FRAME_Init();
    int ret;
    uint8_t isDone;
    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_HandshakeState curState = (HITLS_HandshakeState)state;
    ret = FRAME_CreateConnection(client, server, true, curState);

    ret = HITLS_IsHandShakeDone(client->ssl, &isDone);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isDone == 0);

    ret = HITLS_IsHandShakeDone(server->ssl, &isDone);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    if (version == HITLS_VERSION_TLS12 && curState == TRY_RECV_FINISH) {
        ASSERT_TRUE(isDone == 1);
    } else {
        ASSERT_TRUE(isDone == 0);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_IsHandShakeDone Check whether the handshake is complete after connection establishment
* @title  UT_TLS_CM_IS_HSDONE_FUNC_TC002
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1
*          2. After the connection is established, invoke HITLS_IsHandShakeDone to check whether the handshake
*          is complete. Expected result 2
* @expect  1. Initialization is complete
*          2. The interface returns 1 and the handshake is done
@ */
/* BEGIN_CASE */
void UT_TLS_CM_IS_HSDONE_FUNC_TC002(int version)
{
    FRAME_Init();
    int ret;
    uint8_t isDone;
    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ret = HITLS_IsHandShakeDone(client->ssl, &isDone);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isDone == 1);

    ret = HITLS_IsHandShakeDone(server->ssl, &isDone);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isDone == 1);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_IS_SERVER_FUNC_TC001
* @title  HITLS_IsServer The client invokes the interface to determine whether the current server is the server
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1
*          2. The client invokes the HITLS_IsServer interface to determine whether the current client is a server.
*          Expected result 2
*          3. The server invokes the HITLS_IsServer interface to determine whether the current server is a server.
*          Expected result 3
* @expect  1. Initialization is complete
*          2. The interface returns false
*          3. The interface returns true
@ */
/* BEGIN_CASE */
void UT_TLS_CM_IS_SERVER_FUNC_TC001(int version)
{
    FRAME_Init();
    int ret;
    bool isServer;
    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ret = HITLS_IsServer(client->ssl, &isServer);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isServer == false);

    ret = HITLS_IsServer(server->ssl, &isServer);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isServer == true);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_READHASPENDING_FUNC_TC001
* @title  HITLS_ReadHasPending Interface test
* @precon  nan
* @brief   1. After initialization, invoke the hitls_readhaspending interface. Expected result 1 is obtained.
*          2. After the connection is established, the peer sends data and the local
*          invokes the hitls_readhaspending interface. Expected result 2 is obtained.
* @expect  1. Return 0
*          2. Return 1
@ */
/* BEGIN_CASE */
void UT_TLS_CM_READHASPENDING_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    bool isPending = false;
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(HITLS_ReadHasPending(client->ssl, &isPending) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_ReadHasPending(server->ssl, &isPending) == HITLS_SUCCESS);
    ASSERT_EQ(isPending, 0);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t data[] = "Hello World";
    uint32_t writeLen;
    ASSERT_TRUE(HITLS_Write(client->ssl, data, sizeof(data), &writeLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[5] = {0};
    uint32_t readLen = 0;
    ASSERT_TRUE(HITLS_Read(server->ssl, readBuf, 5, &readLen) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_ReadHasPending(server->ssl, &isPending) == HITLS_SUCCESS);
    ASSERT_EQ(isPending, 1);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_READPENDING_FUNC_TC001
* @title  HITLS_GetReadPendingBytes interfaces test
* @precon  nan
* @brief   1. After initialization, invoke the HITLS_GetReadPendingBytes interface to query data.
*          Expected result 1 is obtained.
*          2. Simulate a scenario where the peer end sends app data during renegotiation to generate app data cache,
*          and invoke HITLS_GetReadPendingBytes to obtain the cache value. Expected result 2 is obtained.
*          3. When the buffer length of the HITLS_Read read data is less than 16 KB, some data is left.
*          Invoke the HITLS_GetReadPendingBytes interface to query the data. Expected result 3 is obtained.
* @expect  1. The return value is 0.
*          2. Returns the size of the cached value.
*          3. Returns the size of the left value.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_READPENDING_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    config->isSupportRenegotiation = true;

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_GetReadPendingBytes(server->ssl) == 0);
    ASSERT_TRUE(HITLS_GetReadPendingBytes(client->ssl) == 0);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    uint8_t data[] = "Hello World";
    uint32_t writeLen;
    ASSERT_TRUE(HITLS_Write(server->ssl, data, sizeof(data), &writeLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_IO_BUSY);
    client->ssl->state = CM_STATE_ALERTING;
    ASSERT_TRUE(HITLS_GetReadPendingBytes(client->ssl) == sizeof("Hello World"));
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_GetPeerSignScheme Unidirectional authentication on the client
* @title  UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC001
* @precon  nan
* @brief   1. Configure unidirectional authentication. After the negotiation is complete,
*          call the interface to obtain the local signature hash algorithm. Expected result 1 is displayed.
*          2. Call the interface to obtain the peer signature hash algorithm. Expected result 2 is obtained.
* @expect  1. Return 0
*          2. Return 0
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    HITLS_CFG_SetClientVerifySupport(config, false);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    HITLS_SignHashAlgo peerSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    uint32_t ret = HITLS_GetPeerSignScheme(server->ssl, &peerSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(peerSignScheme, 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_GetPeerSignScheme Client two-way authentication Verification
* @title  UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC002
* @precon  nan
* @brief   1. Set two-way authentication. Before the client receives the certificate request, call the interface to
*          obtain the local signature hash algorithm. Expected result 1 is obtained.
*          2. After receiving the certificate request, the client invokes the interface to obtain the negotiated
8          signature hash algorithm. Expected result 2 is displayed.
* @expect  1. Return 0
*          2. The returned value is the negotiated algorithm
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC002(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    HITLS_CFG_SetClientVerifySupport(config, true);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_REQUEST) == HITLS_SUCCESS);
    HITLS_SignHashAlgo peerSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    //
    uint32_t ret = HITLS_GetPeerSignScheme(client->ssl, &peerSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    if (version == HITLS_VERSION_TLS13) {
        ASSERT_EQ(peerSignScheme, 0);
    } else {
        ASSERT_NE(peerSignScheme, 0);
    }

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    peerSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    ret = HITLS_GetPeerSignScheme(client->ssl, &peerSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_NE(peerSignScheme, 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC003
* @title  HITLS_GetPeerSignScheme Client Verification
* @precon  nan
* @brief   1. Before the client receives the serverkeyexchange message, call the interface to obtain the peer signature
*          hash algorithm. Expected result 1 is displayed.
*          2. After receiving the serverkeyexchange message, the client invokes the interface to obtain the signature
*          hash algorithm of the peer end. Expected result 2 is obtained.
* @expect  1. Return 0
*          2. The return value is the algorithm used by the server
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC003(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    HITLS_CFG_SetClientVerifySupport(config, true);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_SignHashAlgo peerSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    uint32_t ret = HITLS_GetPeerSignScheme(server->ssl, &peerSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(peerSignScheme, 0);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    peerSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    ret = HITLS_GetPeerSignScheme(client->ssl, &peerSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(peerSignScheme, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC004
* @title  HITLS_GetPeerSignScheme two-way authentication verification on the server
* @precon  nan
* @brief   1. Set two-way authentication. Before the server receives the certificate verify message,
*          call the API to obtain the peer signature hash algorithm. Expected result 1 is obtained.
*          2. After receiving the certificate verify message, the server invokes the API to obtain the signature hash
*          algorithm of the peer end. Expected result 2 is obtained.
* @expect  1. Return 0
*          2. The returned value is the algorithm used by the client
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_PEER_SIGN_SCHEME_FUNC_TC004(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    HITLS_CFG_SetClientVerifySupport(config, true);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    HITLS_SignHashAlgo peerSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    uint32_t ret = HITLS_GetPeerSignScheme(server->ssl, &peerSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(peerSignScheme, 0);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    peerSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    ret = HITLS_GetPeerSignScheme(server->ssl, &peerSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_NE(peerSignScheme, 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_LOCAL_SIGN_SCHEME_FUNC_TC001
* @title  HITLS_GetLocalSignScheme Server-side verification
* @precon  nan
* @brief   1. Before the server receives the client hello message, call the interface to obtain the negotiated signature
*          hash algorithm. Expected result 1 is displayed
*          2. After receiving the client hello message, the server invokes the interface to obtain the negotiated
*          signature hash algorithm. Expected result 2 is displayed
* @expect  1. Return 0
*          2. The return value is the algorithm used by the server
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_LOCAL_SIGN_SCHEME_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
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

    HITLS_SignHashAlgo localSignScheme = CERT_SIG_SCHEME_UNKNOWN;
    ret = HITLS_GetLocalSignScheme(server->ssl, &localSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(localSignScheme, 0);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ret = HITLS_GetLocalSignScheme(server->ssl, &localSignScheme);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    switch (version) {
        case HITLS_VERSION_TLS12:
            ASSERT_EQ(localSignScheme, CERT_SIG_SCHEME_RSA_PKCS1_SHA256);
            break;
        case HITLS_VERSION_TLS13:
            ASSERT_EQ(localSignScheme, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256);
            break;
        default:
            config = NULL;
            break;
    }
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_EC_GROUPS_FUNC_TC001
* @title  test HITLS_SetEcGroups interface
* @precon  nan
* @brief   1. Input an empty link context and a non-empty group. Normal groupsize. Expected result 1 is obtained
*          2. Input a non-empty link context, empty group, and normal groupsize. Expected result 1 is obtained.
*          3. Input a non-empty link context, a non-empty group, and groupsize 0. Expected result 1 is obtained
*          4. Transfer a non-empty link context, a non-empty group, and normal groupsize. Expected result 2 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_EC_GROUPS_FUNC_TC001(int tlsVersion)
{
    HitlsInit();
    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);

    int32_t ret;

    ret = HITLS_SetEcGroups(NULL, groups, groupsSize);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetEcGroups(ctx, NULL, groupsSize);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetEcGroups(ctx, groups, 0);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetEcGroups(ctx, groups, groupsSize);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_SIGAL_LIST_FUNC_TC001
* @title  test HITLS_SetSigalgsList interface
* @precon  nan
* @brief   1. Input an empty link context and a non-empty signAlg. Normal signAlgsSize. Expected result 1 is obtained
*          2. Input an non-empty link context and an empty signAlg. Normal signAlgsSize. Expected result 1 is obtained
*          2. Input a non-empty link context and a non-empty signAlg. 0 signAlgsSize. Expected result 1 is obtained
*          2. Input a non-empty link context and a non-empty signAlg. Normal signAlgsSize. Expected result 2 is obtained
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCESS
@*/
/* BEGIN_CASE */
void UT_TLS_CM_SET_SIGAL_LIST_FUNC_TC001(int tlsVersion)
{
    HitlsInit();

    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(tlsConfig != NULL)   ;

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    uint32_t signAlgsSize = sizeof(signAlgs) / sizeof(uint16_t);

    int32_t ret;

    ret = HITLS_SetSigalgsList(NULL, signAlgs, signAlgsSize);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetSigalgsList(ctx, NULL, signAlgsSize);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetSigalgsList(ctx, signAlgs, 0);
    ASSERT_TRUE(ret == HITLS_NULL_INPUT);

    ret = HITLS_SetSigalgsList(ctx, signAlgs, signAlgsSize);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SET_EC_POINT_FUNC_TC001
* @title  Set the normal dot format value.
* @precon  nan
* @brief   1. Set pointFormats to HITLS_POINT_FORMAT_UNCOMPRESSED and invoke the HITLS_CFG_SetEcPointFormats interface.
*          Expected result 1 is obtained.
*          2. Set pointFormats to HITLS_POINT_FORMAT_BUTT and invoke the HITLS_CFG_SetEcPointFormats interface.
*          Expected result 2
*          3. Use config to generate ctx, due to the result 3
*          4. Set pointFormats to HITLS_POINT_FORMAT_UNCOMPRESSED again and generate ctx again. Expected result 4 is
*          obtained. Set pointFormats to HITLS_POINT_FORMAT_UNCOMPRESSED and invoke the HITLS_SetEcPointFormats
*          interface. Expected result 2
* @expect   1. Interface return value, HITLS_SUCCESS
*           2. Interface return value: HITLS_SUCCESS
*           3. Failed to generate the file.
*           4. The file is generated successfully.
*           5. The setting is successful.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_EC_POINT_FUNC_TC001(int version)
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *Config = NULL;
    HITLS_Ctx *ctx = NULL;
    Config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(Config != NULL);
    const uint8_t pointFormats[] = {HITLS_POINT_FORMAT_UNCOMPRESSED};
    uint32_t pointFormatsSize = sizeof(pointFormats) / sizeof(uint8_t);
    ASSERT_TRUE(HITLS_CFG_SetEcPointFormats(Config, pointFormats, pointFormatsSize) == HITLS_SUCCESS);

    const uint8_t pointFormats2[] = {HITLS_POINT_FORMAT_BUTT};
    uint32_t pointFormatsSize2 = sizeof(pointFormats2) / sizeof(uint8_t);
    ASSERT_TRUE(HITLS_CFG_SetEcPointFormats(Config, pointFormats2, pointFormatsSize2) == HITLS_SUCCESS);
    ctx = HITLS_New(Config);
    if(version == TLS1_2){
        ASSERT_TRUE(ctx == NULL);
    }
    HITLS_Free(ctx);
    ASSERT_TRUE(HITLS_CFG_SetEcPointFormats(Config, pointFormats, pointFormatsSize) == HITLS_SUCCESS);
    ctx = HITLS_New(Config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_SetEcPointFormats(ctx, pointFormats, pointFormatsSize) == HITLS_SUCCESS);
    client = FRAME_CreateLink(Config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(Config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(Config);
    HITLS_Free(ctx);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_CONFIG_FUNC_TC001
* @title  After the initialization is complete, obtain the config file and check whether the configuration is consistent
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1 is obtained
*          2. After the initialization is complete, obtain hitlsConfig and check whether the main configurations are
*          consistent with the settings. Expected result 2 is obtained.
* @expect   1. Complete initialization
*           2. Consistent results
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_CONFIG_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    const HITLS_Config *cfgFromCtx = NULL;
    cfgFromCtx = HITLS_GetConfig(client->ssl);
    ASSERT_TRUE(cfgFromCtx != NULL);
    ASSERT_EQ(cfgFromCtx->signAlgorithmsSize, sizeof(signAlgs) / sizeof(uint16_t));
    ASSERT_TRUE(memcmp(cfgFromCtx->signAlgorithms, signAlgs, cfgFromCtx->signAlgorithmsSize) == 0);
    ASSERT_EQ(cfgFromCtx->isSupportRenegotiation, true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_CURRENT_CIPHER_FUNC_TC001
* @title  HITLS_GetCurrentCipher Obtain the negotiated cipher suite pointer after initialization and before negotiation
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1 is obtained
*          2. Before link establishment, call HITLS_GetCurrentCipher to obtain the negotiated cipher suite pointer.
*          Expected result 2 is returned.
* @expect   1. Complete initialization
*           2. Return NULL
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_CURRENT_CIPHER_FUNC_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    tlsConfig = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    CONN_Init(ctx);
    ASSERT_TRUE(ctx != NULL);

    const HITLS_Cipher *hitlsCipher = HITLS_GetCurrentCipher(ctx);
    ASSERT_EQ(hitlsCipher->cipherSuite, 0);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GET_RANDOM_FUNC_TC001
* @title  tls1.3 Obtain clientRandom and serverRandom
* @precon  nan
* @brief   1. establish connection
*          2. Obtain and compare clientRandom and serverRandom.
* @expect  1. Return success
*          2. The clientRandom stored on the server is the same as that sent by the client, and the serverRandom stored
8          on the client is the same as that sent by the server.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_RANDOM_FUNC_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Init();

    testInfo.config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.client = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.server = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.server != NULL);

    FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT);

    uint8_t clientRandom[RANDOM_SIZE];
    uint8_t serverRandom[RANDOM_SIZE];
    uint32_t randomSize = RANDOM_SIZE;

    ASSERT_TRUE(HITLS_GetHsRandom(testInfo.client->ssl, g_clientRandom, &randomSize, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetHsRandom(testInfo.server->ssl, clientRandom, &randomSize, true) == HITLS_SUCCESS);
    ASSERT_TRUE(randomSize == RANDOM_SIZE);
    ASSERT_TRUE(memcmp(g_clientRandom, clientRandom, RANDOM_SIZE) == 0);

    ASSERT_TRUE(HITLS_GetHsRandom(testInfo.server->ssl, g_serverRandom, &randomSize, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetHsRandom(testInfo.client->ssl, serverRandom, &randomSize, false) == HITLS_SUCCESS);
    ASSERT_TRUE(randomSize == RANDOM_SIZE);
    ASSERT_TRUE(memcmp(g_serverRandom, serverRandom, RANDOM_SIZE) == 0);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  HITLS_GetHandShakeState change state to alerting, obtain the state
* @title  UT_TLS_CM_GET_HANDSHAKE_STATE_FUNC_TC001
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1 is obtained
*          2. When an alerting message is generated during data transmission, invoke HITLS_GetHandShakeState to stop
*          sending the alerting message and obtain the current status. Expected result 2 is obtained
* @expect  1. Complete initialization
*          2. Return TLS_CONNECTED
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_HANDSHAKE_STATE_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
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
    client->ssl->method.sendAlert(client->ssl, ALERT_LEVEL_WARNING, ALERT_NO_CERTIFICATE_RESERVED);
    ret = ALERT_Flush(client->ssl);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    uint32_t state = 0;
    ret = HITLS_GetHandShakeState(client->ssl, &state);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(state, TLS_CONNECTED);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  HITLS_GetStateString Query the handshake status in sequence.
* @title  UT_TLS_CM_GET_STATE_STRING_FUNC_TC001
* @precon  nan
* @brief   1. Invoke the HITLS_GetStateString interface and transfer values 0-30 and 255 at a time. Expected result 1.
* @expect  1. The interface returns the corresponding handshake status.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_STATE_STRING_FUNC_TC001()
{
    const char goalStr[34][32] = {
        "idle",
        "connected",
        "send hello request",
        "send client hello",
        "send hello verify request",
        "send hello retry request",
        "send server hello",
        "send encrypted extensions",
        "send certificate",
        "send server key exchange",
        "send certificate request",
        "send server hello done",
        "send client key exchange",
        "send certificate verify",
        "send new session ticket",
        "send change cipher spec",
        "send end of early data",
        "send finished",
        "send keyupdate",
        "recv client hello",
        "recv hello verify request",
        "recv server hello",
        "recv encrypted extensions",
        "recv certificate",
        "recv server key exchange",
        "recv certificate request",
        "recv server hello done",
        "recv client key exchange",
        "recv certificate verify",
        "recv new session ticket",
        "recv end of early data",
        "recv finished",
        "recv keyupdate",
        "recv hello request",
    };
    int32_t ret;
    for (uint32_t i = 0; i <= 30; i++) {
        ret = strcmp(HITLS_GetStateString(i), goalStr[i]);
        ASSERT_TRUE(strcmp(HITLS_GetStateString(i), goalStr[i]) == 0);
    }
    ASSERT_TRUE(strcmp(HITLS_GetStateString(255), "unknown") == 0);
EXIT:
    return;
}
/* END_CASE */

/* @
* @test HITLS_IsHandShaking function point test
* @title  UT_TLS_CM_IS_HANDSHAKING_FUNC_TC001
* @precon  nan
* @brief   1. Initialize the client and server. Expected result 1.
*          2. Invoke the HITLS_IsHandShaking interface to check whether handshake is in progress. Expected result 2.
*          3. Initiate a connection establishment request and invoke the HITLS_IsHandShaking interface during connection establishment. (Expected result 3)
*          4. Invoke HITLS_IsHandShaking to complete connection establishment. Expected result 4.
*          5. Invoke the HITLS_Renegotiate interface to initiate renegotiation. (Expected result 5.)
*          6. Invoke the HITLS_IsHandShaking interface to check whether the handshake is in progress. (Expected result 6)
*          7. After the renegotiation is complete, invoke the HITLS_IsHandShaking interface to check whether handshake is in progress. Expected result 7.
*@expect   1. Initialization is complete.
*          2. The interface output parameter is 0.
*          3. The interface output parameter is 1.
*          4. The interface output parameter is 0.
*          5. The state changes to the renegotiation state.
*          6. The output parameter of the interface is 1.
*          7. The interface output parameter is 0.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_IS_HANDSHAKING_FUNC_TC001(int version)
{
    FRAME_Init();
    bool isHandShaking = false;
    HITLS_Config *tlsConfig = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportRenegotiation = true;
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(HITLS_IsHandShaking(clientTlsCtx, &isHandShaking) == HITLS_SUCCESS);
    ASSERT_TRUE(isHandShaking == false);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(HITLS_IsHandShaking(clientTlsCtx, &isHandShaking) == HITLS_SUCCESS);
    ASSERT_TRUE(isHandShaking == true);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(HITLS_IsHandShaking(clientTlsCtx, &isHandShaking) == HITLS_SUCCESS);
    ASSERT_TRUE(isHandShaking == false);

    if (version == HITLS_VERSION_TLS12) {
        ASSERT_EQ(HITLS_Renegotiate(clientTlsCtx), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Renegotiate(serverTlsCtx), HITLS_SUCCESS);
        ASSERT_TRUE(serverTlsCtx->state == CM_STATE_RENEGOTIATION);
        ASSERT_TRUE(clientTlsCtx->state == CM_STATE_RENEGOTIATION);
        ASSERT_TRUE(HITLS_IsHandShaking(clientTlsCtx, &isHandShaking) == HITLS_SUCCESS);
        ASSERT_TRUE(isHandShaking == true);

        ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
        ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
        ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);
        ASSERT_TRUE(HITLS_IsHandShaking(clientTlsCtx, &isHandShaking) == HITLS_SUCCESS);
        ASSERT_TRUE(isHandShaking == false);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test UT_TLS_CM_HITLS_IsBeforeHandShake_FUNC_TC001
 * @title HITLS_IsBeforeHandShake Check whether the handshake is not performed
 * @percon NA
 * @brief
 * 1. Initialize the client and server. Expected result 1
 * 2. Call HITLS_IsBeforeHandShake to check whether the handshake has not been performed. Expected result 2
 * 3. During transporting, call HITLS_IsBeforeHandShake to check whether the handshake has not been performed
 * Expected result 3
 * 4. Establish a connection and invoke the HITLS_IsBeforeHandShake interface to check whether the handshake
 * has not been performed.Expected result 4
 * @expect
 * 1. Initialization is complete
 * 2. isBefore will be 1
 * 3. isBefore will be 0
 * 4. isBefore will be 0
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_IsBeforeHandShake_FUNC_TC001(int version)
{
    FRAME_Init();
    int ret = 0;
    bool isBefore = false;
    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ret = HITLS_IsBeforeHandShake(client->ssl, &isBefore);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_IDLE);
    ASSERT_TRUE(isBefore == true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    ret = HITLS_IsBeforeHandShake(client->ssl, &isBefore);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(isBefore == false);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(isBefore == false);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test UT_TLS_CM_HITLS_GetClientVersion_FUNC_TC001
 * @title HITLS_GetClientVersion Obtains the client and server version numbers
 * after initialization and before negotiation.
 * @percon NA
 * @brief
 * 1. Initialize the client and server. Expected result 1
 * 2. Call HITLS_GetClientVersion to obtain the client and server version numbers. Expected result 2
 * @expect
 * 1. Completing the initialization
 * 2. The interface returns all 0s
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetClientVersion_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    uint16_t clientVersion = HITLS_VERSION_TLS12;
    ASSERT_TRUE(HITLS_GetClientVersion(client->ssl, &clientVersion) == HITLS_SUCCESS);
    uint16_t serverVersion = HITLS_VERSION_TLS12;
    ASSERT_TRUE(HITLS_GetClientVersion(server->ssl, &serverVersion) == HITLS_SUCCESS);
    ASSERT_EQ(clientVersion, 0);
    ASSERT_EQ(serverVersion, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test UT_TLS_CM_HITLS_IsClient_FUNC_TC001
 * @title Testing the HITLS_IsClient
 * @percon NA
 * @brief
 * 1. Enter an empty TLS connection handle. Expected result 1
 * 2. Enter a non-empty TLS connection handle and leave isClient empty. Expected result 1
 * 3. Enter a non-empty TLS connection handle and leave isClient not empty. Expected result 2
 * @expect
 * 1. Return HITLS_NULL_INPUT
 * 2. Return HITLS_SUCCESS
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_IsClient_FUNC_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool isClient = 0;
    ASSERT_TRUE(HITLS_IsClient(ctx, &isClient) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_IsClient(ctx, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_IsClient(ctx, &isClient) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
* @test HITLS_GetSharedGroup Obtain the first supported peer group when only one curve is matched on the client and
server.
* @title UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC001
* @precon nan
* @brief
* 1. Initialize the client and server. Expected result 1
* 2. Configure the client and server to support only one elliptic curve (the number of intersection groups is 1).
Expected result 2
* 3. Establish a connection and invoke the HITLS_GetSharedGroup interface to obtain the first supported peer group
(Expected result 3)
* @expect
* 1. Initialization is complete
* 2. The setting is successful
* 3. The interface returns the supported elliptic curve
@ */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC001(int version)
{
    FRAME_Init();
    int ret;
    uint16_t groupId;

    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    uint16_t groups_c[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    HITLS_CFG_SetGroups(config_c, groups_c, sizeof(groups_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));

    uint16_t groups_s[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP521R1};
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    HITLS_CFG_SetGroups(config_s, groups_s, sizeof(groups_s) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ret = HITLS_GetSharedGroup(server->ssl, 0, &groupId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(groupId == HITLS_EC_GROUP_SECP256R1);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test HITLS_GetSharedGroup Obtain the second supported peer group if only one matching curve exists on the client and
 * server.
 * @title UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC002
 * @precon nan
 * @brief
 * 1. Initialize the client and server. Expected result 1
 * 2. Configure only one elliptic curve supported by the client and server. Expected result 2
 * 3. Establish a connection and invoke the HITLS_GetSharedGroup interface to obtain the second supported peer group,
 * Expected result 3
 * @expect
 * 1. Initialization is complete
 * 2. The setting is successful
 * 3. The interface returns 0
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC002(int version)
{
    FRAME_Init();
    int ret;
    uint16_t groupId;

    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    uint16_t groups_c[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    HITLS_CFG_SetGroups(config_c, groups_c, sizeof(groups_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));

    uint16_t groups_s[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP521R1};
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    HITLS_CFG_SetGroups(config_s, groups_s, sizeof(groups_s) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ret = HITLS_GetSharedGroup(server->ssl, 2, &groupId);
    ASSERT_TRUE(ret == HITLS_INVALID_INPUT);
    ASSERT_TRUE(groupId == 0);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test HITLS_GetSharedGroup Obtain the second and third supported peer groups when the client and server have two
 * matching curves.
 * @title UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC003
 * @precon nan
 * @brief
 * 1. Initialize the client and server. Expected result 1
 * 2. Configure two elliptic curves supported by the client and server. Expected result 2
 * 3. Establish a connection. Invoke HITLS_GetSharedGroup to obtain the second supported peer group and the third
 * supported peer group, Expected result 3
 * @expect
 * 1. Initialization is complete
 * 2. The setting is successful
 * 3. The corresponding curve is returned for the first call and 0 is returned for the second call
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC003(int version)
{
    FRAME_Init();
    int ret;
    uint16_t groupId;

    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    uint16_t groups_c[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    HITLS_CFG_SetGroups(config_c, groups_c, sizeof(groups_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));

    uint16_t groups_s[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1, HITLS_EC_GROUP_SECP521R1};
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512};
    HITLS_CFG_SetGroups(config_s, groups_s, sizeof(groups_s) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ret = HITLS_GetSharedGroup(server->ssl, 1, &groupId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(groupId == HITLS_EC_GROUP_SECP384R1);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test HITLS_GetSharedGroup Obtain the first supported peer group when there is no matching curve on the client and
 * server
 * @title UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC004
 * @precon In the current framework, the TLS13 client and server do not have a matching curve. The TLS12 client and
 * server can successfully establish a connection. The TLS13 framework capability needs to be supplemented
 * @brief
 * 1. Initialize the client and server, Expected result 1
 * 2. Configure the client and server not to support the elliptic curve. Expected result 2
 * 3. Establish a connection. After the parameters are negotiated, invoke the HITLS_GetSharedGroup interface to obtain
 * the supported peer group. Expected result 3
 * @expect
 * 1. Initialization is complete
 * 2. The setting is successful
 * 3. The interface returns 0
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC004(int version)
{
    FRAME_Init();
    int ret;
    uint16_t groupId;
    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    uint16_t signWrtVersion =
        (version == HITLS_VERSION_TLS12) ? CERT_SIG_SCHEME_RSA_PKCS1_SHA256 : CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    uint16_t groups_c[] = {HITLS_EC_GROUP_SECP384R1};
    uint16_t signAlgs_c[] = {signWrtVersion, CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384};
    HITLS_CFG_SetGroups(config_c, groups_c, sizeof(groups_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));
    HITLS_CFG_SetDhAutoSupport(config_c, true);

    uint16_t groups_s[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP521R1};
    uint16_t signAlgs_s[] = {
        signWrtVersion, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512};
    HITLS_CFG_SetGroups(config_s, groups_s, sizeof(groups_s) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));
    HITLS_CFG_SetDhAutoSupport(config_s, true);

    FRAME_CertInfo certInfo = {
        "rsa_pss_sha256/rsa_pss_root.crt",
        "rsa_pss_sha256/rsa_pss_intCa.crt",
        "rsa_pss_sha256/rsa_pss_dev.crt",
        0,
        "rsa_pss_sha256/rsa_pss_dev.key",
        0,
    };

    client = (version == HITLS_VERSION_TLS12) ? FRAME_CreateLink(config_c, BSL_UIO_TCP)
                                              : FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = (version == HITLS_VERSION_TLS12) ? FRAME_CreateLink(config_s, BSL_UIO_TCP)
                                              : FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HITLS_GetSharedGroup(server->ssl, 1, &groupId);
    ASSERT_TRUE(ret == HITLS_INVALID_INPUT);
    ASSERT_TRUE(groupId == 0);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test HITLS_GetSharedGroup If the matched elliptic curve exists, obtain the (-1)th supported peer group.
 * @title UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC005
 * @precon nan
 * @brief
 * 1. Initialize the client and server. Expected result 1
 * 2. Configure two elliptic curves supported by the client and server. Expected result 2
 * 3. Establish a connection. Invoke HITLS_GetSharedGroup to obtain the (-1)th supported peer group. Expected result 3
 * @expect
 * 1. Initialization is complete
 * 2. The setting is successful
 * 3. The interface returns 2
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetSharedGroup_FUNC_TC005(int version)
{
    FRAME_Init();
    int ret;
    uint16_t groupId;

    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    uint16_t groups_c[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    HITLS_CFG_SetGroups(config_c, groups_c, sizeof(groups_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));

    uint16_t groups_s[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1, HITLS_EC_GROUP_SECP521R1};
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512};
    HITLS_CFG_SetGroups(config_s, groups_s, sizeof(groups_s) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ret = HITLS_GetSharedGroup(server->ssl, -1, &groupId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(groupId == 2);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test UT_TLS_CM_HITLS_SetVersionSupport_HITLS_GetVersionSupport_API_TC001
 * @title Test the HITLS_SetVersionSupport and HITLS_GetVersionSupport interfaces.
 * @precon nan
 * @brief
 * HITLS_SetVersionSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Input a non-empty TLS connection handle and set the version to an invalid value. Expected result 2
 * 3. Input a non-empty TLS connection handle and set the version to a valid value. Expected result 3
 * HITLS_GetVersionSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Input an empty version pointer. Expected result 1
 * 3. Input a non-empty TLS connection handle and ensure that the version pointer is not empty. Expected result 4
 * @expect
 * 1. Return HITLS_NULL_INPUT.
 * 2. Return HITLS_SUCCESS, and invalid values in ctx->config.tlsConfig are filtered out
 * 3. Return HITLS_SUCCESS is returned, and the value of ctx->config.tlsConfig is the expected value
 * 4. Return HITLS_SUCCESS is returned and the value of version is the same as that recorded in config
 */

/* BEGIN_CASE */
void UT_TLS_CM_HITLS_SetVersionSupport_HITLS_GetVersionSupport_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    uint32_t version = 0;

    ASSERT_TRUE(HITLS_SetVersionSupport(ctx, version) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetVersionSupport(ctx, &version) == HITLS_NULL_INPUT);
    config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetVersionSupport(ctx, NULL) == HITLS_NULL_INPUT);

    version = (TLS13_VERSION_BIT << 1) | TLS13_VERSION_BIT | TLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_SetVersionSupport(ctx, version) == HITLS_SUCCESS);
    ASSERT_TRUE(ctx->config.tlsConfig.minVersion == HITLS_VERSION_TLS12 &&
                ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13);
    version = TLS13_VERSION_BIT | TLS12_VERSION_BIT;
    ASSERT_TRUE(HITLS_SetVersionSupport(ctx, version) == HITLS_SUCCESS);
    ASSERT_TRUE(ctx->config.tlsConfig.minVersion == HITLS_VERSION_TLS12 &&
                ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13);
    uint32_t getversion = 0;
    ASSERT_TRUE(HITLS_GetVersionSupport(ctx, &getversion) == HITLS_SUCCESS);
    ASSERT_TRUE(getversion == ctx->config.tlsConfig.version);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
* @test  UT_TLS_CM_HITLS_SetQuietShutdown_HITLS_GetQuietShutdown_API_TC001
* @title  Test the HITLS_SetQuietShutdown and HITLS_GetQuietShutdown interfaces
* @precon  nan
* @brief
* HITLS_SetQuietShutdown
* 1. Input an empty TLS connection handle. Expected result 1
* 2. Input a non-empty TLS connection handle and set mode to an invalid value. Expected result 2
* 3. Input a non-empty TLS connection handle and set mode to a valid value. Expected result 3
* HITLS_GetQuietShutdown
* 1. Input an empty TLS connection handle. Expected result 1
* 2. Input an empty mode pointer. Expected result 1
* 3. Input a non-empty TLS connection handle and ensure that the mode pointer is not empty. Expected result 3
* @expect
* 1. Return HITLS_NULL_INPUT
* 2. Return HITLS_CONFIG_INVALID_SET
* 3. Return HITLS_SUCCES
*/

/* BEGIN_CASE */
void UT_TLS_CM_HITLS_SetQuietShutdown_HITLS_GetQuietShutdown_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    int32_t mode = 0;

    ASSERT_TRUE(HITLS_SetQuietShutdown(ctx, mode) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetQuietShutdown(ctx, &mode) == HITLS_NULL_INPUT);
    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetQuietShutdown(ctx, NULL) == HITLS_NULL_INPUT);
    mode = 1;
    ASSERT_TRUE(HITLS_SetQuietShutdown(ctx, mode) == HITLS_SUCCESS);
    mode = -1;
    ASSERT_TRUE(HITLS_SetQuietShutdown(ctx, mode) == HITLS_CONFIG_INVALID_SET);

    int32_t getMode = -1;
    ASSERT_TRUE(HITLS_GetQuietShutdown(ctx, &getMode) == HITLS_SUCCESS);
    ASSERT_TRUE(getMode == true);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */


/**
 * @test  UT_TLS_CM_HITLS_SetDhAutoSupport_API_TC001
 * @title  Test HITLS_SetDhAutoSupport
 * @precon  nan
 * @brief
 * HITLS_SetDhAutoSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Input a non-empty TLS connection handle and set support to an invalid value. Expected result 2
 * 3. Input a non-empty TLS connection handle and set support to a valid value. Expected result 3 is displayed.
 * @expect
 * 1. Return HITLS_NULL_INPUT
 * 2. Return HITLS_SUCCES, and isSupportDhAuto is ture
 * 3. Return HITLS_SUCCES, and isSupportDhAuto is ture or false
 */

/* BEGIN_CASE */
void UT_TLS_CM_HITLS_SetDhAutoSupport_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool support = -1;
    ASSERT_TRUE(HITLS_SetDhAutoSupport(ctx, support) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    support = true;
    ASSERT_TRUE(HITLS_SetDhAutoSupport(ctx, support) == HITLS_SUCCESS);
    support = -1;
    ASSERT_TRUE(HITLS_SetDhAutoSupport(ctx, support) == HITLS_SUCCESS);
    support = false;
    ASSERT_TRUE(HITLS_SetDhAutoSupport(ctx, support) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_TMPDH_TC001
 * @spec  -
 * @title  Test HITLS_SetTmpDh interface
 * @precon  nan
 * @brief
 * HITLS_SetTmpDh
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Input non-empty TLS connection handle information and leave dhPkey empty. Expected result 1
 * 3. Input the non-empty TLS connection handle information and ensure that dhPkey is not empty. Expected result 2
 * @expect
 * 1. Return HITLS_NULL_INPUT
 * 2. Return HITLS_SUCCES
 */

/* BEGIN_CASE */
void UT_TLS_CM_HITLS_SetTmpDh_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    HITLS_CRYPT_Key *dhPkey = HITLS_CRYPT_GenerateDhKeyBySecbits(LIBCTX_FROM_CONFIG(config),
        ATTRIBUTE_FROM_CONFIG(config), config, HITLS_SECURITY_LEVEL_THREE_SECBITS);
    ASSERT_TRUE(HITLS_SetTmpDh(ctx, dhPkey) == HITLS_NULL_INPUT);

    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetTmpDh(ctx, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_SetTmpDh(ctx, dhPkey) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test HITLS_GetPeerFinishVerifyData Obtaining Peer VerifyDATA After Link Establishment and Renegotiation Are Complete
 * @title  UT_TLS_CM_HITLS_GetPeerFinishVerifyData_FUNC_TC001
 * @precon  nan
 * @brief
 * 1. Initialize the client and server and obtain the verifyDATA. Expected result 1.
 * 2. Send a connection setup request. Expected result 2
 * 3. Call HITLS_GetPeerFinishVerifyData to obtain and store VerifyData. Expected result 3
 * 4. Perform renegotiation. Expected result 4
 * 5. Call HITLS_GetPeerFinishVerifyData to obtain VerifyData. Expected result 5
 * @expect
 * 1. Return HITLS_SUCCESS and the len of verifyDATA is 0
 * 2. The connection is established.
 * 3. Return HITLS_SUCCESS and the len of verifyDATA is not  0
 * 4. Renegotiation succeeded.
 * 5. Return HITLS_SUCCESS and the verifyDATA is different from result 1
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetPeerFinishVerifyData_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    uint8_t verifyDataNew[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataNewSize = 0;
    uint8_t verifyDataOld[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataOldSize = 0;

    uint32_t ret =
        HITLS_GetPeerFinishVerifyData(serverTlsCtx, verifyDataOld, sizeof(verifyDataOld), &verifyDataOldSize);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(verifyDataOldSize, 0);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ret = HITLS_GetPeerFinishVerifyData(serverTlsCtx, verifyDataOld, sizeof(verifyDataOld), &verifyDataOldSize);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_NE(verifyDataOldSize, 0);
    ASSERT_TRUE(memcmp(verifyDataNew, verifyDataOld, verifyDataOldSize) != 0);
    ASSERT_TRUE(memcpy_s(verifyDataOld, sizeof(verifyDataOld), verifyDataNew, verifyDataNewSize) == EOK);

    ASSERT_TRUE(HITLS_Renegotiate(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ret = HITLS_GetPeerFinishVerifyData(serverTlsCtx, verifyDataNew, sizeof(verifyDataNew), &verifyDataNewSize);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_EQ(verifyDataNewSize, verifyDataOldSize);
    ASSERT_TRUE(memcmp(verifyDataNew, verifyDataOld, verifyDataOldSize) != 0);
    ASSERT_TRUE(memcpy_s(verifyDataOld, sizeof(verifyDataOld), verifyDataNew, verifyDataNewSize) == EOK);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test HITLS_GetFinishVerifyData: Obtains the verification data before a connection is established
 * @title  UT_TLS_CM_HITLS_GetFinishVerifyData_FUNC_TC001
 * @precon  nan
 * @brief
 *1. Initialize the client and server. Expected result 1
 *2. Call HITLS_GetFinishVerifyData to obtain VerifyData. Expected result 2
 * @expect
 *1. Completing the initialization
 *2. The interface returns 0.
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetFinishVerifyData_FUNC_TC001(int version)
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
    uint8_t verifyDataNew[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataNewSize = 0;
    ASSERT_TRUE(HITLS_GetFinishVerifyData(server->ssl, verifyDataNew, sizeof(verifyDataNew), &verifyDataNewSize) ==
        HITLS_SUCCESS);
    ASSERT_EQ(verifyDataNewSize, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test HITLS_GetFinishVerifyData Obtain VerifyDATA after connection establishment
 * @title  UT_TLS_CM_HITLS_GetFinishVerifyData_FUNC_TC002
 * @precon  nan
 * @brief
 * 1. Initialize the client and server. Expected result 1
 * 2. Send a link setup request. Expected result 2
 * 3. Call HITLS_GetFinishVerifyData to obtain VerifyData. Expected result 3
 * @expect
 * 1. Completing the initialization
 * 2. The connection is established
 * 3. The value returned by the interface is not 0
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetFinishVerifyData_FUNC_TC002(int version)
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

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    uint8_t verifyDataNew[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataNewSize = 0;
    ASSERT_TRUE(HITLS_GetFinishVerifyData(server->ssl, verifyDataNew, sizeof(verifyDataNew), &verifyDataNewSize) ==
        HITLS_SUCCESS);
    ASSERT_NE(verifyDataNewSize, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test HITLS_GetFinishVerifyData Obtains VerifyDATA after link establishment and renegotiation.
* @title  UT_TLS_CM_HITLS_GetFinishVerifyData_FUNC_TC003
* @precon  nan
* @brief
* 1. Initialize the client and server. Expected result
* 2. Send a connection setup request. Expected result 2
* 3. Call HITLS_GetFinishVerifyData to obtain and store VerifyData. Expected result 3
* 4. Perform renegotiation. Expected result 4
* 5. Call HITLS_GetFinishVerifyData to obtain VerifyData. Expected result 5
* @expect
* 1. Complete the initialization
* 2. The link is established
* 3. The interface returns a value other than 0
* 4. Renegotiation succeeded
* 5. Inconsistent with the first link establishmen
*/
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetFinishVerifyData_FUNC_TC003(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
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
    uint8_t verifyDataNew[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataNewSize = 0;
    uint8_t verifyDataOld[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataOldSize = 0;

    ASSERT_TRUE(HITLS_GetFinishVerifyData(server->ssl, verifyDataOld, sizeof(verifyDataOld), &verifyDataOldSize) ==
        HITLS_SUCCESS);
    ASSERT_NE(verifyDataOldSize, 0);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(HITLS_Renegotiate(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_GetFinishVerifyData(serverTlsCtx, verifyDataNew, sizeof(verifyDataNew), &verifyDataNewSize) ==
        HITLS_SUCCESS);

    ASSERT_TRUE(verifyDataNewSize == verifyDataOldSize);
    ASSERT_TRUE(memcmp(verifyDataNew, verifyDataOld, verifyDataOldSize) != 0);
    ASSERT_TRUE(memcpy_s(verifyDataOld, sizeof(verifyDataOld), verifyDataNew, verifyDataNewSize) == EOK);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

int32_t SendHelloReq(HITLS_Ctx *ctx)
{
    uint8_t buf[HS_MSG_HEADER_SIZE] = {0u};
    size_t len = HS_MSG_HEADER_SIZE;

    return REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
}

/**
 * @test  UT_TLS_CM_HITLS_GetRenegotiationState_FUNC_TC001
 * @title  Verifying the HITLS_GetRenegotiationState Interface
 * @precon  nan
 * @brief
 * 1. After the client and server are initialized, initiate a connection establishment request. Expected result 1
 * 2. Call the HITLS_GetRenegotiationState interface to query the renegotiation status. Expected result 2
 * 3. The server invokes the hitls_renegotiate interface to initiate renegotiation and invokes the
 *  HITLS_GetRenegotiationState interface to query the renegotiation status on the server. Expected result 3
 * 4. After receiving the hello request, the client invokes the HITLS_GetRenegotiationState interface
 * to query the renegotiation status. Expected result 4
 * 5. After receiving the client hello message, the server invokes the HITLS_GetRenegotiationState interface to query
 * the renegotiation status. Expected result 5
 * 6. After the renegotiation is complete, call the HITLS_GetRenegotiationState interface to query the renegotiation
 * status on the client and server. Expected result 6
 * 7. The client invokes the hitls_renegotiate interface to initiate renegotiation and invokes the
 * HITLS_GetRenegotiationState interface to query the renegotiation status. Expected result 7
 * @expect
 * 1. The connection is successfully established
 * 2. The return value is false
 * 3. The return value is true
 * 4. The return value is true
 * 5. The return value is true
 * 6. The return value is flase
 * 7. The return value is true
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetRenegotiationState_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    bool isRenegotiation = true;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    client->ssl->config.tlsConfig.endpoint = HITLS_ENDPOINT_CLIENT;
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_SetRenegotiationSupport(server->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(client->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(server->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == true);

    ASSERT_TRUE(SendHelloReq(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(HITLS_GetRenegotiationState(server->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == true);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(server->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == true);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(server->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(server->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}

/* END_CASE */

/**
 * @test Verifying the HITLS_GetRwstate Interface
 * @title  UT_TLS_CM_HITLS_GetRwstate_FUNC_TC001
 * @precon  nan
 * @brief
 * 1. After the initialization, invoke the HITLS_GetRwstate interface to query data. Expected result 1
 * 2. When reading data, set ruio to null, construct a read exception, and call the HITLS_GetRwstate interface for
 * query. Expected result 2
 * 3. When writing data, set uio to null, construct a write exception, and call the HITLS_GetRwstate interface for
 * query. Expected result 3
 * @expect
 * 1. The returned status is nothing
 * 2. The returned status is reading
 * 3. The returned status is writing
 */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetRwstate_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t rwstate = HITLS_READING;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    uint32_t ret = HITLS_GetRwstate(client->ssl, &rwstate);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(rwstate, HITLS_NOTHING);

    void *tmpUio = client->ssl->rUio;
    client->ssl->rUio = NULL;
    BSL_UIO_Free(tmpUio);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ret = HITLS_GetRwstate(client->ssl, &rwstate);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(rwstate, HITLS_READING);

    tmpUio = client->ssl->uio;
    client->ssl->uio = NULL;
    BSL_UIO_Free(tmpUio);

    FRAME_TrasferMsgBetweenLink(client, server);
    HITLS_Accept(server->ssl);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    uint8_t writeBuf[100] = {0};
    uint32_t writeLen;
    ret = HITLS_Write(client->ssl, writeBuf, sizeof(writeBuf), &writeLen);
    ret = HITLS_GetRwstate(client->ssl, &rwstate);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(rwstate, HITLS_WRITING);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_GET_CLIENTVERIFYSUPPORT_API_TC001
 * @title  Test the HITLS_SetClientVerifySupport and HITLS_GetClientVerifySupport interfaces.
 * @precon  nan
 * @brief
 * HITLS_SetClientVerifySupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer non-empty TLS connection handle information and set support to an invalid value. Expected result 2
 * 3. Transfer the non-empty TLS connection handle information and set support to a valid value. Expected result 3
 * HITLS_GetClientVerifySupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer an empty isSupport pointer. Expected result 1
 * 3. Transfer the non-null TLS connection handle information and ensure that the isSupport pointer is not null.
 * Expected result 3
 * @expect
 * 1. HITLS_NULL_INPUT is returned
 * 2. Returns HITLS_SUCCES, isSupportClientVerify is true, and isSupportVerifyNone is false
 * 3. HITLS_SUCCES is returned, isSupportClientVerify is true or false, and isSupportVerifyNone and isSupportVerifyNone
 * are mutually exclusive, but can be false at the same time
 */
/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_CLIENTVERIFYSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_SetClientVerifySupport(ctx, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetClientVerifySupport(ctx, &isSupport) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetClientVerifySupport(ctx, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_SetClientVerifySupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isSupportVerifyNone == false);

    support = -1;
    ASSERT_TRUE(HITLS_SetClientVerifySupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetClientVerifySupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_SetClientVerifySupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetClientVerifySupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_GET_NOCLIENTCERTSUPPORT_API_TC001
 * @title  Test the HITLS_SetNoClientCertSupport and HITLS_GetClientVerifySupport interfaces
 * @precon  nan
 * @brief
 * HITLS_SetNoClientCertSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer non-empty TLS connection handle information and set support to an invalid value. Expected result 2
 * 3. Transfer the non-empty TLS connection handle information and set support to a valid value. Expected result 3
 * HITLS_GetNoClientCertSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer an empty isSupport pointer. Expected result 1
 * 3. Transfer the non-null TLS connection handle information and ensure that the isSupport pointer is not null
 * Expected result 3
 * @expect
 * 1. HITLS_NULL_INPUT is returned.
 * 2. HITLS_SUCCES is returned and isSupportNoClientCert is true
 * 3. Returns HITLS_SUCCES and isSupportNoClientCert is true or false
 */

/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_NOCLIENTCERTSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_SetNoClientCertSupport(ctx, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetNoClientCertSupport(ctx, &isSupport) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetNoClientCertSupport(ctx, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_SetNoClientCertSupport(ctx, support) == HITLS_SUCCESS);

    support = -1;
    ASSERT_TRUE(HITLS_SetNoClientCertSupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetNoClientCertSupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_SetNoClientCertSupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetNoClientCertSupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_GET_VERIFYNONESUPPORT_API_TC001
 * @title  Test the HITLS_SetVerifyNoneSupport and HITLS_GetVerifyNoneSupport interfaces
 * @precon  nan
 * @brief
 * HITLS_SetVerifyNoneSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer non-empty TLS connection handle information and set support to an invalid value. Expected result 2
 * 3. Transfer the non-empty TLS connection handle information and set support to a valid value. Expected result 3
 * HITLS_GetVerifyNoneSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer an empty isSupport pointer. Expected result 1
 * 3. Transfer the non-null TLS connection handle information and ensure that the isSupport pointer is not null
 * Expected result 3
 * @expect
 * 1. HITLS_NULL_INPUT is returned
 * 2. Returns HITLS_SUCCES, isSupportVerifyNone is true, and isSupportClientVerify is false
 * 3. HITLS_SUCCES is returned, isSupportVerifyNone is true or false, isSupportClientVerify and isSupportClientVerify
 * are mutually exclusive, but can be false at the same time
 */

/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_VERIFYNONESUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_SetVerifyNoneSupport(ctx, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetVerifyNoneSupport(ctx, &isSupport) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetVerifyNoneSupport(ctx, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_SetVerifyNoneSupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isSupportClientVerify == false);

    support = -1;
    ASSERT_TRUE(HITLS_SetVerifyNoneSupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetVerifyNoneSupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_SetVerifyNoneSupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetVerifyNoneSupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_GET_CLIENTONCEVERIFYSUPPORT_API_TC001
 * @title  Test the HITLS_SetClientOnceVerifySupport and HITLS_GetClientOnceVerifySupport interfaces.
 * @precon  nan
 * @brief
 * HITLS_SetClientOnceVerifySupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer non-empty TLS connection handle information and set support to an invalid value. Expected result 2
 * 3. Transfer the non-empty TLS connection handle information and set support to a valid value. Expected result 3
 * HITLS_GetClientOnceVerifySupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer an empty isSupport pointer. Expected result 1
 * 3. Transfer the non-null TLS connection handle information and ensure that the isSupport pointer is not null.
 * Expected result 3
 * @expect
 * 1. HITLS_NULL_INPUT is returned
 * 2. HITLS_SUCCES is returned and isSupportPostHandshakeAuth is true
 * 3. HITLS_SUCCES is returned and isSupportPostHandshakeAuth is true or false
 */

/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_CLIENTONCEVERIFYSUPPORT_API_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_SetClientOnceVerifySupport(ctx, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetClientOnceVerifySupport(ctx, &isSupport) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetClientOnceVerifySupport(ctx, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_SetClientOnceVerifySupport(ctx, support) == HITLS_SUCCESS);

    support = -1;
    ASSERT_TRUE(HITLS_SetClientOnceVerifySupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetClientOnceVerifySupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_SetClientOnceVerifySupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetClientOnceVerifySupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
* @test Verifying the HITLS_ClearRenegotiationNum Interface
* @title  UT_HITLS_CM_HITLS_ClearRenegotiationNum_FUNC_TC001
* @precon  nan
* @brief
* 1. After initialization, invoke the HITLS_ClearRenegotiationNum interface to query data. Expected result 1
* 2. After the link is set up, invoke the HITLS_ClearRenegotiationNum interface to query the link. Expected result 2
* 3. Initiate renegotiation. After the renegotiation is successful, invoke the HITLS_ClearRenegotiationNum interface to
check the values of the client and server. Expected result 3
* 4. Initiate another five renegotiations. After the negotiation is complete, invoke the HITLS_ClearRenegotiationNum
interface to query the values of the client and server. Expected result 4
* 5. Invoke the HITLS_ClearRenegotiationNum interface again to query the values on the client and server. Expected
result 5
* 6. The client initiates renegotiation. The server rejects the renegotiation. Invoke the HITLS_ClearRenegotiationNum
interface to query the values of the client and server. Expected result 6
* @expect
* 1. The value is 0
* 2. The value is 0
* 3. The value is 1
* 4. The value is 0
* 5. The value is 0
* 6. The value is 1 for the client and 0 for the server
*/
/* BEGIN_CASE */
void UT_HITLS_CM_HITLS_ClearRenegotiationNum_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);
    uint32_t renegotiationNum = 0;

    ASSERT_TRUE(HITLS_ClearRenegotiationNum(clientTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 0);
    ASSERT_TRUE(HITLS_ClearRenegotiationNum(serverTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 0);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_ClearRenegotiationNum(clientTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 0);
    ASSERT_TRUE(HITLS_ClearRenegotiationNum(serverTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 0);

    uint8_t verifyDataNew[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataNewSize = 0;
    uint8_t verifyDataOld[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataOldSize = 0;
    ASSERT_TRUE(HITLS_GetFinishVerifyData(serverTlsCtx, verifyDataOld, sizeof(verifyDataOld), &verifyDataOldSize) ==
        HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Renegotiate(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_GetFinishVerifyData(serverTlsCtx, verifyDataNew, sizeof(verifyDataNew), &verifyDataNewSize) ==
        HITLS_SUCCESS);

    ASSERT_TRUE(verifyDataNewSize == verifyDataOldSize);
    ASSERT_TRUE(memcmp(verifyDataNew, verifyDataOld, verifyDataOldSize) != 0);
    ASSERT_TRUE(memcpy_s(verifyDataOld, sizeof(verifyDataOld), verifyDataNew, verifyDataNewSize) == EOK);

    ASSERT_TRUE(HITLS_ClearRenegotiationNum(clientTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 1);
    ASSERT_TRUE(HITLS_ClearRenegotiationNum(serverTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 1);

    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(HITLS_Renegotiate(serverTlsCtx) == HITLS_SUCCESS);
        ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);
        ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
        ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
        ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);
        ASSERT_TRUE(HITLS_GetFinishVerifyData(serverTlsCtx, verifyDataNew, sizeof(verifyDataNew), &verifyDataNewSize) ==
            HITLS_SUCCESS);

        ASSERT_TRUE(verifyDataNewSize == verifyDataOldSize);
        ASSERT_TRUE(memcmp(verifyDataNew, verifyDataOld, verifyDataOldSize) != 0);
        ASSERT_TRUE(memcpy_s(verifyDataOld, sizeof(verifyDataOld), verifyDataNew, verifyDataNewSize) == EOK);
    }

    ASSERT_TRUE(HITLS_ClearRenegotiationNum(clientTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 5);
    ASSERT_TRUE(HITLS_ClearRenegotiationNum(serverTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 5);

    ASSERT_TRUE(HITLS_ClearRenegotiationNum(clientTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 0);
    ASSERT_TRUE(HITLS_ClearRenegotiationNum(serverTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 0);

    ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);

    serverTlsCtx->negotiatedInfo.isSecureRenegotiation = false;
    ASSERT_EQ(FRAME_CreateRenegotiation(client, server), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_GetFinishVerifyData(serverTlsCtx, verifyDataNew, sizeof(verifyDataNew), &verifyDataNewSize) ==
        HITLS_SUCCESS);

    ASSERT_TRUE(verifyDataNewSize == verifyDataOldSize);
    ASSERT_TRUE(memcmp(verifyDataNew, verifyDataOld, verifyDataOldSize) == 0);
    ASSERT_TRUE(memcpy_s(verifyDataOld, sizeof(verifyDataOld), verifyDataNew, verifyDataNewSize) == EOK);

    ASSERT_TRUE(HITLS_ClearRenegotiationNum(clientTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 1);
    ASSERT_TRUE(HITLS_ClearRenegotiationNum(serverTlsCtx, &renegotiationNum) == HITLS_SUCCESS);
    ASSERT_EQ(renegotiationNum, 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test HITLS_GetNegotiateGroup: EC cipher suite
 * @spec -
 * @title UT_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC001
 * @precon nan
 * @brief
 * 1. Configure the two ends to use the EC cipher suite. Before connection establishment is complete, invoke the
 * HITLS_GetNegotiateGroup interface to query the negotiated value. Expected result 1
 * 2. Configure the EC cipher suite to be used at both ends. After the connection is established, invoke the
 * HITLS_GetNegotiateGroup interface to query the negotiated value. Expected result 2
 * @expect
 * 1. The return value is 0
 * 2. The returned value is the negotiated value
 */
/* BEGIN_CASE */
void UT_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC001(int version)
{
    FRAME_Init();
    int ret;
    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    uint16_t groupId;
    uint16_t expectedGroupId = HITLS_EC_GROUP_SECP256R1;
    uint16_t groups_c[] = {expectedGroupId, HITLS_EC_GROUP_SECP384R1};
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384};
    HITLS_CFG_SetGroups(config_c, groups_c, sizeof(groups_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));

    uint16_t groups_s[] = {expectedGroupId, HITLS_EC_GROUP_SECP521R1};
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512};
    HITLS_CFG_SetGroups(config_s, groups_s, sizeof(groups_s) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    ret = HITLS_GetNegotiateGroup(client->ssl, &groupId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(groupId, 0);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ret = HITLS_GetNegotiateGroup(client->ssl, &groupId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(groupId, expectedGroupId);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test HITLS_GetNegotiateGroup interface uses the RSA cipher suite.
* @spec -
* @title UT_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC002
* @precon nan
* @brief
* 1. Set the RSA cipher suite to be used at both ends. After the connection is established, invoke the
HITLS_GetNegotiateGroup interface to query the negotiated value. Expected result 1
* @expect
* 1. The return value of tls12 is 0. The prerequisite is that the cipher suite does not contain the (EC)DHE. The cipher
suite involved in key exchange must have the same group. tls13 is the negotiated group. The current framework supports
only ECDHE. Therefore, the connection can be successfully established only when the same EC group exists, The default
common curve is HITLS_EC_GROUP_CURVE25519.
*/
/* BEGIN_CASE */
void UT_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC002(int version)
{
    FRAME_Init();
    int ret;
    HITLS_Config *config_c = GetHitlsConfigViaVersion(version);
    HITLS_Config *config_s = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    if (version == HITLS_VERSION_TLS12) {
        ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(config_c, true), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(config_s, true), HITLS_SUCCESS);
        uint16_t cipherSuite = HITLS_RSA_WITH_AES_256_CBC_SHA;
        ASSERT_EQ(HITLS_CFG_SetCipherSuites(config_c, &cipherSuite, 1), HITLS_SUCCESS);
    }
    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint16_t groupId;
    uint16_t expectedGroupId = (version == HITLS_VERSION_TLS12) ? 0 : HITLS_EC_GROUP_CURVE25519;
    ret = HITLS_GetNegotiateGroup(server->ssl, &groupId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(groupId, expectedGroupId);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_GET_CIPHERSERVERPREFERENCE_FUNC_TC001
 * @title  Test the HITLS_SetCipherServerPreference and HITLS_GetCipherServerPreference interfaces
 * @precon  nan
 * @brief
 * HITLS_SetCipherServerPreference
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer a non-empty TLS connection handle and set isSupport to an invalid value. Expected result 2
 * 3. Transfer a non-empty TLS connection handle and set isSupport to a valid value. Expected result 3
 * HITLS_GetCipherServerPreference
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer an empty isSupport pointer. Expected result 1
 * 3. Transfer the non-null TLS connection handle information and ensure that the isSupport pointer is not null.
 * Expected result 3
 * @expect
 * 1. HITLS_NULL_INPUT is returned
 * 2. HITLS_SUCCES is returned and isSupportServerPreference is true
 * 3. Returns HITLS_SUCCES and isSupportServerPreference is true or false
 */

/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_CIPHERSERVERPREFERENCE_FUNC_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool isSupport = false;
    bool getIsSupport = false;
    ASSERT_TRUE(HITLS_SetCipherServerPreference(ctx, isSupport) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetCipherServerPreference(ctx, &getIsSupport) == HITLS_NULL_INPUT);
    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetCipherServerPreference(ctx, NULL) == HITLS_NULL_INPUT);
    isSupport = true;
    ASSERT_TRUE(HITLS_SetCipherServerPreference(ctx, isSupport) == HITLS_SUCCESS);
    isSupport = -1;
    ASSERT_TRUE(HITLS_SetCipherServerPreference(ctx, isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isSupportServerPreference = true);
    isSupport = false;
    ASSERT_TRUE(HITLS_SetCipherServerPreference(ctx, isSupport) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_GetCipherServerPreference(ctx, &getIsSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(getIsSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_GET_RENEGOTIATIONSUPPORT_FUNC_TC001
 * @title  Test the HITLS_SetRenegotiationSupport and HITLS_GetRenegotiationSupport interfaces.
 * @precon  nan
 * @brief
 * HITLS_SetRenegotiationSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer non-empty TLS connection handle information and set support to an invalid value. Expected result 2
 * 3. Transfer the non-empty TLS connection handle information and set support to a valid value. Expected result 3
 * HITLS_GetRenegotiationSupport
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer an empty isSupport pointer. Expected result 1
 * 3. Transfer the non-null TLS connection handle information and ensure that the isSupport pointer is not null.
 * Expected result 3
 * @expect
 * 1. HITLS_NULL_INPUT is returned
 * 2. HITLS_SUCCES is returned and isSupportRenegotiation is true
 * 3. HITLS_SUCCES is returned and isSupportRenegotiation is true or false
 */

/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_RENEGOTIATIONSUPPORT_FUNC_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool support = -1;
    bool isSupport = -1;
    ASSERT_TRUE(HITLS_SetRenegotiationSupport(ctx, support) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetRenegotiationSupport(ctx, &isSupport) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetRenegotiationSupport(ctx, NULL) == HITLS_NULL_INPUT);

    support = true;
    ASSERT_TRUE(HITLS_SetRenegotiationSupport(ctx, support) == HITLS_SUCCESS);

    support = -1;
    ASSERT_TRUE(HITLS_SetRenegotiationSupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationSupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == true);

    support = false;
    ASSERT_TRUE(HITLS_SetRenegotiationSupport(ctx, support) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationSupport(ctx, &isSupport) == HITLS_SUCCESS);
    ASSERT_TRUE(isSupport == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
 * @test  UT_HITLS_CM_SET_GET_FLIGHTTRANSMITSWITCH_FUNC_TC001
 * @title  Test the HITLS_SetFlightTransmitSwitch and HITLS_GetFlightTransmitSwitch interfaces
 * @precon  nan
 * @brief
 * HITLS_SetFlightTransmitSwitch
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Transfer a non-empty TLS connection handle and set isEnable to an invalid value. Expected result 2
 * 3. Transfer a non-empty TLS connection handle and set isEnable to a valid value. Expected result 3
 * GetFlightTransmitSwitch
 * 1. Input an empty TLS connection handle. Expected result 1
 * 2. Pass an empty getIsEnable pointer. Expected result 1
 * 3. Transfer the non-null TLS connection handle information and ensure that the getIsEnable pointer is not null.
 * Expected result 3
 * @expect
 * 1. HITLS_NULL_INPUT is returned
 * 2. HITLS_SUCCES is returned and ctx->config.tlsConfig.isFlightTransmitEnable is true
 * 3. Returns HITLS_SUCCES and ctx->config.tlsConfig.isFlightTransmitEnable is true or false
 */

/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_FLIGHTTRANSMITSWITCH_FUNC_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool isEnable = false;
    bool getIsEnable = false;
    ASSERT_TRUE(HITLS_SetFlightTransmitSwitch(ctx, isEnable) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetFlightTransmitSwitch(ctx, &getIsEnable) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetFlightTransmitSwitch(ctx, NULL) == HITLS_NULL_INPUT);
    isEnable = 1;
    ASSERT_TRUE(HITLS_SetFlightTransmitSwitch(ctx, isEnable) == HITLS_SUCCESS);
    isEnable = -1;
    ASSERT_TRUE(HITLS_SetFlightTransmitSwitch(ctx, isEnable) == HITLS_SUCCESS);
    ASSERT_TRUE(ctx->config.tlsConfig.isFlightTransmitEnable = true);
    isEnable = 0;
    ASSERT_TRUE(HITLS_SetFlightTransmitSwitch(ctx, isEnable) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_GetFlightTransmitSwitch(ctx, &getIsEnable) == HITLS_SUCCESS);
    ASSERT_TRUE(getIsEnable == false);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/**
* @test UT_HITLS_CM_SET_GET_SetMaxCertList_FUNC_TC001
* @title HTLS_CFG_SetMaxCertList, HITLS_CFG_GetMaxCertList, HITLS_SetMaxCertList, and HITLS_GetMaxCertList APIs
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx
* 2. Set the certificate chain length config to null and invoke the HITLS_CFG_SetMaxCertList interface
* 3. Invoke the HITLS_CFG_GetMaxCertList interface and check the output parameter value
* 4. Set the maximum length of the certificate chain by calling the HITLS_CFG_SetMaxCertList interface
* 5. Invoke the HITLS_CFG_GetMaxCertList interface and check the output parameter value
* 6. Set the minimum certificate chain length by calling the HITLS_CFG_SetMaxCertList interface
* 7. Invoke the HITLS_CFG_GetMaxCertList interface and check the output parameter value
* 8. Use the HITLS_SetMaxCertList and HITLS_GetMaxCertList interfaces to repeat the preceding test
* @expect
* 1. Initialization succeeds
* 2. HITLS_NULL_INPUT is returned
* 3. HITLS_NULL_INPUT is returned
* 4. The interface returns HITLS_SUCCESS
* 5. The value of MaxCertList returned by the interface is 2 ^ 32 - 1
* 6. The interface returns the HITLS_SUCCESS
* 7. The value of MaxCertList returned by the interface is 0
* 8. Same as above

*/
/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_SetMaxCertList_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig;
    HITLS_Ctx *ctx = NULL;
    tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    uint32_t maxSize;
    // The config parameter is empty.
    ASSERT_TRUE(HITLS_CFG_SetMaxCertList(NULL, MAX_CERT_LIST) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetMaxCertList(NULL, &maxSize) == HITLS_NULL_INPUT);
    // Set the maximum value to 2 ^ 32 - 1.
    ASSERT_TRUE(HITLS_CFG_SetMaxCertList(tlsConfig, MAX_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxCertList(tlsConfig, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MAX_CERT_LIST);
    // Set the minimum value to 0.
    ASSERT_TRUE(HITLS_CFG_SetMaxCertList(tlsConfig, MIN_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxCertList(tlsConfig, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MIN_CERT_LIST);
    // The config parameter is empty.
    ASSERT_TRUE(HITLS_SetMaxCertList(NULL, MAX_CERT_LIST) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetMaxCertList(NULL, &maxSize) == HITLS_NULL_INPUT);
    // Set the maximum value to 2 ^ 32 - 1.
    ASSERT_TRUE(HITLS_SetMaxCertList(ctx, MAX_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetMaxCertList(ctx, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MAX_CERT_LIST);
    // Set the minimum value to 0.
    ASSERT_TRUE(HITLS_SetMaxCertList(ctx, MIN_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetMaxCertList(ctx, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MIN_CERT_LIST);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */
void ExampleInfoCallback(const HITLS_Ctx *ctx, int32_t eventType, int32_t value)
{
    (void)ctx;
    (void)eventType;
    (void)value;
}

uint64_t Test_RecordPaddingCb(HITLS_Ctx *ctx, int32_t type, uint64_t length, void *arg)
{
    (void)ctx;
    (void)type;
    (void)length;
    (void)arg;
    return HITLS_SUCCESS;
}

/* @
* @test  UT_TLS_CM_InfoCb_API_TC001
* @title  InfoCb Interface Parameter Test
* @precon  nan
* @brief
1. Use the HITLS_GetInfoCb without HITLS_CFG_SetInfoCb. Expected result 1 is obtained.
2. Use the HITLS_SetInfoCb interface to set callback. Expected result 2
3. Use the HITLS_GetInfoCb . Expected result 3
4. Use the HITLS_GetInfoCb with the parameter is NULL . Expected result 4
* @expect
1. Return the NULL.
2. Return the HITLS_SUCCESS
3. Return value is not NULL.
4. Return the NULL.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_InfoCb_API_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx != NULL);
    HITLS_InfoCb infoCallBack = HITLS_GetInfoCb(clientTlsCtx);
    ASSERT_TRUE(infoCallBack == NULL);
    int32_t ret = HITLS_SetInfoCb(clientTlsCtx, ExampleInfoCallback);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    infoCallBack = HITLS_GetInfoCb(clientTlsCtx);
    ASSERT_TRUE(infoCallBack != NULL);
    infoCallBack = HITLS_GetInfoCb(NULL);
    ASSERT_TRUE(infoCallBack == NULL);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
}
/* END_CASE */

#define MSG_CB_PRINT_LEN 500

void msg_callback(int32_t writePoint, int32_t tlsVersion, int32_t contentType, const void *msg,
                    uint32_t msgLen, HITLS_Ctx *ctx, void *arg)
{
   (void)writePoint;
   (void)tlsVersion;
   (void)contentType;
   (void)msg;
   (void)msgLen;
   (void)ctx;
   (void)arg;
}

/* @
* @test  UT_TLS_CM_SetMsgCb_API_TC001
* @title  HITLS_SetMsgCb Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
2. Use the HITLS_SetMsgCb interface to set callback. (Expected result 2)
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetMsgCb_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_SetMsgCb(NULL, msg_callback), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetMsgCb(ctx, msg_callback), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_GetError_API_TC001
* @title  HITLS_GetError Interface Parameter Test
* @precon  nan
* @brief  1. Set ctx to NULL. Expected result 1 is obtained.
2.Invoke the HITLS_GetError interface and send the return value. The expected result 2 is obtained
* @expect  1. Return the HITLS_ERR_SYSCALL message.
2. Link error codes are returned
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GetError_API_TC001(void)
{
    FRAME_Init();
    HITLS_Ctx *ctx = NULL;
    HITLS_Config *config = NULL;
    config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_GetError(NULL, HITLS_SUCCESS) == HITLS_ERR_SYSCALL);
    ASSERT_TRUE(HITLS_GetError(ctx, HITLS_SUCCESS) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SetAlpnProtos_API_TC001
* @title  HITLS_SetAlpnProtos Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
* @expect
1. Return the HITLS_NULL_INPUT message.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetAlpnProtos_API_TC001()
{
    HitlsInit();
    uint8_t * alpnProtosname = (uint8_t *)"vpn|http";
    uint32_t alpnProtosnameLen = sizeof(alpnProtosname);
    ASSERT_TRUE(HITLS_SetAlpnProtos(NULL, alpnProtosname, alpnProtosnameLen) == HITLS_NULL_INPUT);
EXIT:
    return;
}
/* END_CASE */

uint32_t SetPskClientCallback(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen,
    uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;
    (void)hint;
    (void)identity;
    (void)maxIdentityLen;
    (void)psk;
    (void)maxPskLen;
    return HITLS_SUCCESS;
}

/* @
* @test  UT_TLS_CM_SetPskClientCallback_API_TC001
* @title  HITLS_SetPskClientCallback Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
2. Use the HITLS_SetPskClientCallback interface to set callback. Expected result 2
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetPskClientCallback_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_SetPskClientCallback(NULL, SetPskClientCallback), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetPskClientCallback(ctx, SetPskClientCallback), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

static uint32_t SetPskServerCallback(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;
    (void)identity;
    (void)psk;
    (void)maxPskLen;
    return HITLS_SUCCESS;
}

/* @
* @test  UT_TLS_CM_SetPskServerCallback_API_TC001
* @title  HITLS_SetPskServerCallback Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
2. Use the HITLS_SetPskServerCallback interface to set callback. Expected result 2
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetPskServerCallback_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_SetPskServerCallback(NULL, SetPskServerCallback), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetPskServerCallback(ctx, SetPskServerCallback), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

static int32_t SetPskUsePsksessionCallback(HITLS_Ctx *ctx, uint32_t hashAlgo, const uint8_t **id,
    uint32_t *idLen, HITLS_Session **session)
{
    (void)ctx;
    (void)hashAlgo;
    (void)id;
    (void)idLen;
    (void)session;
    return HITLS_SUCCESS;
}

/* @
* @test  UT_TLS_CM_SetPskUseSessionCallback_API_TC001
* @title  HITLS_SetPskUseSessionCallback Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
2. Use the HITLS_SetPskUseSessionCallback interface to set callback. Expected result 2
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetPskUseSessionCallback_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_SetPskUseSessionCallback(NULL, SetPskUsePsksessionCallback), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetPskUseSessionCallback(ctx, SetPskUsePsksessionCallback), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

int32_t SetPskFindSessionCallback(HITLS_Ctx *ctx, const uint8_t *identity, uint32_t identityLen,
    HITLS_Session **session)
{
    (void)ctx;
    (void)identity;
    (void)identityLen;
    (void)session;
    return HITLS_SUCCESS;
}

/* @
* @test  UT_TLS_CM_SetPskFindSessionCallback_API_TC001
* @title  HITLS_SetPskFindSessionCallback Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
2. Use the HITLS_SetPskFindSessionCallback interface to set callback. Expected result 2
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetPskFindSessionCallback_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_SetPskFindSessionCallback(NULL, SetPskFindSessionCallback), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetPskFindSessionCallback(ctx, SetPskFindSessionCallback), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SetNeedCheckPmsVersion_API_TC001
* @title  HITLS_SetNeedCheckPmsVersion Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
2. Use the HITLS_SetNeedCheckPmsVersion interface to set parameter true. Expected result 2
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetNeedCheckPmsVersion_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = NULL;
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_SetNeedCheckPmsVersion(NULL, true), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetNeedCheckPmsVersion(ctx, true), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_SetPskIdentityHint_API_TC001
* @title  HITLS_SetPskIdentityHint Interface Parameter Test
* @precon  nan
* @brief
1. Set ctx to NULL. Expected result 1 is obtained.
2. Use the HITLS_SetPskIdentityHint interface to set parameter. Expected result 2
* @expect
1. Return the HITLS_NULL_INPUT message.
2. Return the HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetPskIdentityHint_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    uint8_t * identityH = (uint8_t *)"123456";
    uint32_t identityHintLen = strlen((char *)identityH);
    ASSERT_TRUE(HITLS_SetPskIdentityHint(ctx, identityH, identityHintLen) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    return;
}
/* END_CASE */

/* @
* @test UT_TLS_CM_SETTICKETNUMS_API_TC001
* @title HITLS_SetTicketNums interface test
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Invoke the HITLS_SetTicketNums interface and set the input parameter of the HITLS_Ctx to NULL.
* 3. Invoke the HITLS_SetTicketNums interface and set the input parameter of the ticketNums to 0.
* 4. Invoke the HITLS_SetTicketNums interface and set normal ticketNums.
* @expect
* 1. Initialization succeeded.
* 2. The interface returns HITLS_NULL_INPUT.
* 3. The interface returns HITLS_SUCCESS.
* 4. The interface returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SETTICKETNUMS_API_TC001()
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HITLS_SetTicketNums(NULL, 0), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetTicketNums(ctx, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetTicketNums(ctx, 3), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetTicketNums(ctx, 100), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_CM_GETTICKETNUMS_API_TC001
* @title HITLS_GetTicketNums interface test
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Invoke the HITLS_GetRecordPaddingCb interface and set the input parameter of the HITLS_Ctx to NULL.
* 3. Invoke the HITLS_GetRecordPaddingCb interface to get the default ticketNums.
* 4. Invoke the HITLS_GetRecordPaddingCb interface and set normal ticketNums.
* 5. Invoke the HITLS_GetRecordPaddingCb interface to get the ticketNums
* @expect
* 1. Initialization succeeded.
* 2. The interface returns ticketNums is 2.
* 3. The interface returns HITLS_NULL_INPUT.
* 4. The interface returns HITLS_SUCCESS.
* 5. Consistent with the configured ticketNums.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GETTICKETNUMS_API_TC001()
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    const int defaultNum = 2;
    int TicketNum = 3;
    ASSERT_EQ(HITLS_GetTicketNums(NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetTicketNums(ctx), defaultNum);
    ASSERT_EQ(HITLS_SetTicketNums(ctx, TicketNum), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetTicketNums(ctx), TicketNum);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_CM_SETRECORDPADDINGCB_API_TC001
* @title HITLS_SetRecordPaddingCb interface test
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Invoke the HITLS_SetRecordPaddingCb interface and set the input parameter of the HITLS_Ctx to NULL.
* 3. Invoke the HITLS_SetRecordPaddingCb interface and set the input parameter of the callback to NULL.
* 4. Invoke the HITLS_SetRecordPaddingCb interface and set normal callback.
* @expect
* 1. Initialization succeeded.
* 2. The interface returns HITLS_NULL_INPUT.
* 3. The interface returns HITLS_SUCCESS.
* 4. The interface returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SETRECORDPADDINGCB_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HITLS_SetRecordPaddingCb(NULL, 0), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetRecordPaddingCb(ctx, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetRecordPaddingCb(ctx, Test_RecordPaddingCb), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_CM_GETRECORDPADDINGCB_API_TC001
* @title HITLS_GetRecordPaddingCb interface test
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Invoke the HITLS_GetRecordPaddingCb interface to get the default callback.
* 3. Invoke the HITLS_GetRecordPaddingCb interface and set the input parameter of the HITLS_Ctx to NULL.
* 4. Invoke the HITLS_GetRecordPaddingCb interface and set normal callback.
* 5. Invoke the HITLS_GetRecordPaddingCb interface to get the callback
* @expect
* 1. Initialization succeeded.
* 2. The interface returns NULL.
* 3. The interface returns HITLS_NULL_INPUT.
* 4. The interface returns HITLS_SUCCESS.
* 5. Consistent with the configured callback.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GETRECORDPADDINGCB_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HITLS_GetRecordPaddingCb(ctx), NULL);
    ASSERT_EQ(HITLS_GetRecordPaddingCb(NULL), NULL);

    ASSERT_TRUE(HITLS_SetRecordPaddingCb(ctx, Test_RecordPaddingCb) ==  HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRecordPaddingCb(ctx) == Test_RecordPaddingCb);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_CM_SETRECORDPADDINGCBARG_API_TC001
* @title HITLS_SetRecordPaddingCbArg interface test
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Invoke the HITLS_SetRecordPaddingCbArg interface and set the input parameter of the HITLS_Ctx to NULL.
* 3. Invoke the HITLS_SetRecordPaddingCbArg interface and set the input parameter of the RecordPaddingArg to NULL.
* 4. Invoke the HITLS_SetRecordPaddingCbArg interface and set normal recordPaddingArg.
* @expect
* 1. Initialization succeeded.
* 2. The interface returns HITLS_NULL_INPUT.
* 3. The interface returns HITLS_SUCCESS.
* 4. The interface returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SETRECORDPADDINGCBARG_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    uint32_t arg = 1;

    ASSERT_EQ(HITLS_SetRecordPaddingCbArg(NULL, &arg), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetRecordPaddingCbArg(ctx, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetRecordPaddingCbArg(ctx, &arg), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_CM_GETRECORDPADDINGCBARG_API_TC001
* @title HITLS_GetRecordPaddingCbArg interface test
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Invoke the HITLS_GetRecordPaddingCbArg interface to get the default recordPaddingArg.
* 3. Invoke the HITLS_GetRecordPaddingCbArg interface and set the input parameter of the HITLS_Ctx to NULL.
* 4. Invoke the HITLS_GetRecordPaddingCbArg interface and set normal recordPaddingArg.
* 5. Invoke the HITLS_GetRecordPaddingCbArg interface to get the recordPaddingArg.
* @expect
* 1. Initialization succeeded.
* 2. The interface returns NULL.
* 3. The interface returns HITLS_NULL_INPUT.
* 4. The interface returns HITLS_SUCCESS.
* 5. Consistent with the configured recordPaddingArg.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GETRECORDPADDINGCBARG_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    int arg = 1;

    ASSERT_EQ(HITLS_GetRecordPaddingCbArg(ctx), NULL);
    ASSERT_EQ(HITLS_GetRecordPaddingCbArg(NULL), NULL);

    ASSERT_EQ(HITLS_SetRecordPaddingCbArg(ctx, &arg), HITLS_SUCCESS);
    ASSERT_EQ(*(int*)HITLS_GetRecordPaddingCbArg(ctx) , arg);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_CM_SETCLOSECHECKKEYUSAGE_API_TC001
* @title HITLS_SetCheckKeyUsage interface test
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Invoke the HITLS_SetCheckKeyUsage interface and set the input parameter of the HITLS_Ctx to NULL.
* 3. Invoke the HITLS_SetCheckKeyUsage interface and set the input parameter of the isClose to true.
* 4. Invoke the HITLS_SetCheckKeyUsage interface and set the input parameter of the isClose to false.
* @expect
* 1. Initialization succeeded.
* 2. The interface returns HITLS_NULL_INPUT.
* 3. The interface returns HITLS_SUCCESS.
* 4. The interface returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SETCLOSECHECKKEYUSAGE_API_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HITLS_SetCheckKeyUsage(NULL, true), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetCheckKeyUsage(ctx, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetCheckKeyUsage(ctx, false), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

static int32_t STUB_ChangeState(TLS_Ctx *ctx, uint32_t nextState)
{
    int32_t ret = HITLS_SUCCESS;
    if (HS_STATE_BUTT == nextState) {
        if (true == ctx->isClient) {
            ctx->hsCtx->hsMsg = NULL;
            ret = HITLS_REC_NORMAL_RECV_BUF_EMPTY;
        }
    }

    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    hsCtx->state = nextState;
    return ret;
}

static bool StateCompare(FRAME_LinkObj *link, HITLS_HandshakeState state)
{
    if ((link->ssl->hsCtx != NULL) && (link->ssl->hsCtx->state == state)) {
        if (state != TRY_RECV_FINISH) {
            return true;
        }
    }
    return false;
}

/** @
* @test  UT_TLS_CM_HITLS_DOHANDSHAKE_API_TC001
* @title  HITLS_DoHandShake Interface Test
* @precon  nan
* @brief  1、Invoke the HITLS_DoHandShake to create tls connect. The expected result 1 is obtained
* @expect  1、connect success
@ */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_DOHANDSHAKE_API_TC001()
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
    int32_t clientRet;
    int32_t serverRet;
    int32_t ret;
    uint32_t count = 0;
    STUB_REPLACE(HS_ChangeState, STUB_ChangeState);;
    HITLS_SetEndPoint(client->ssl, true);
    do {
        if (StateCompare(client, HS_STATE_BUTT)) {
            ret = HITLS_SUCCESS;
            break;
        }
        clientRet = HITLS_DoHandShake(client->ssl);
        if (clientRet != HITLS_SUCCESS) {
            ret = clientRet;
            if ((clientRet != HITLS_REC_NORMAL_IO_BUSY) && (clientRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }
        ret = FRAME_TrasferMsgBetweenLink(client, server);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        if (StateCompare(server, HS_STATE_BUTT)) {
            ret = HITLS_SUCCESS;
            break;
        }
        serverRet = HITLS_DoHandShake(server->ssl);
        if (serverRet != HITLS_SUCCESS) {
            ret = serverRet;
            if ((serverRet != HITLS_REC_NORMAL_IO_BUSY) && (serverRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }
        ret = FRAME_TrasferMsgBetweenLink(server, client);
        if (ret != HITLS_SUCCESS) {
            break;
        }
        if (clientRet == HITLS_SUCCESS && serverRet == HITLS_SUCCESS) {
            ret = HITLS_SUCCESS;
            break;
        }
        count++;
        ret = HITLS_INTERNAL_EXCEPTION;
    } while (count < 40);
    ASSERT_EQ(ret, HITLS_SUCCESS);
EXIT:
    STUB_RESTORE(HS_ChangeState);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/** @
* @test  UT_TLS_CM_SECURITY_SECURITYLEVEL_API_TC001
* @title  HITLS_GetSecurityLevel and HITLS_CFG_GetSecurityLevel Interface Test
* @precon  nan
* @brief  HITLS_GetSecurityLevel
1、Invoke HITLS_GetSecurityLevel to obtain the default security level. The expected result 1 is obtained
2、Check the obtained security level. The expected result 2 is obtained
HITLS_CFG_GetSecurityLevel
3、Invoke HITLS_CFG_GetSecurityLevel to obtain the default security level. The expected result 1 is obtained
4、Check the obtained security level. The expected result 2 is obtained
* @expect  1、return HITLS_SUCCESS
2、The security level is 1
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SECURITY_SECURITYLEVEL_API_TC001()
{
    HitlsInit();
    HITLS_Ctx *ctx = NULL;
    HITLS_Config *Config;
    int32_t level;
    Config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(Config != NULL);
    ctx = HITLS_New(Config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetSecurityLevel(ctx, &level) == HITLS_SUCCESS);
    ASSERT_TRUE(level == 1);
    ASSERT_TRUE(HITLS_CFG_GetSecurityLevel(Config, &level) == HITLS_SUCCESS);
    ASSERT_TRUE(level == 1);
EXIT:
    HITLS_CFG_FreeConfig(Config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_SECURITY_SECURITYLEVEL_API_TC002
* @title  HITLS_SetSecurityLevel and HITLS_CFG_SetSecurityLevel Interface Parameter Test
* @precon  nan
* @brief  HITLS_SetSecurityLevel
1、Invoke the HITLS_SetSecurityLevel to configure the security level.The expected result 1 is obtained
2、Invoke HITLS_GetSecurityLevel to obtain the default security level. The expected result 2 is obtained
3、Check the obtained security level. The expected result 3 is obtained
HITLS_CFG_SetSecurityLevel
4、Invoke the HITLS_CFG_SetSecurityLevel to configure the security level.The expected result 1 is obtained
5、Invoke HITLS_GetSecurityLevel to obtain the default security level. The expected result 2 is obtained
6、Check the obtained security level. The expected result 3 is obtained
* @expect  1、return HITLS_SUCCESS
2、return HITLS_SUCCESS
3、The security level is equal to the configured security level.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SECURITY_SECURITYLEVEL_API_TC002()
{
    HitlsInit();
    HITLS_Ctx *ctx = NULL;
    HITLS_Config *Config;
    int32_t level;
    Config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(Config != NULL);
    ctx = HITLS_New(Config);
    ASSERT_TRUE(ctx != NULL);

    for(int32_t i = 0; i <= 5; i++){
        ASSERT_TRUE(HITLS_SetSecurityLevel(ctx, i) == HITLS_SUCCESS);
        ASSERT_TRUE(HITLS_GetSecurityLevel(ctx, &level) == HITLS_SUCCESS);
        ASSERT_TRUE(level == i);
        ASSERT_TRUE(HITLS_CFG_SetSecurityLevel(Config, i) == HITLS_SUCCESS);
        ASSERT_TRUE(HITLS_CFG_GetSecurityLevel(Config, &level) == HITLS_SUCCESS);
        ASSERT_TRUE(level == i);
    }
EXIT:
    HITLS_CFG_FreeConfig(Config);
    HITLS_Free(ctx);
}
/* END_CASE */

int32_t TEST_HITLS_SecurityCb(const HITLS_Ctx *ctx, const HITLS_Config *config, int32_t option,
    int32_t bits, int32_t id, void *other, void *exData)
{
    (void)ctx;
    (void)config;
    (void)option;
    (void)bits;
    (void)id;
    (void)other;
    (void)exData;
    return HITLS_SUCCESS;
}

/** @
* @test  UT_TLS_CM_SECURITY_SECURITYCB_API_TC001
* @title  HITLS_SetSecurityCb HITLS_SetSecurityExData HITLS_GetSecurityCb and HITLS_GetSecurityExData Interface Test
* @precon  nan
* @brief  1、Invoke the HITLS_SetSecurityCb interface and set the first parameter to NULL.
The expected result 1 is obtained
2、Invoke the HITLS_SetSecurityCb interface and transfer the first parameter to a normal parameter.
The expected result 2 is obtained
3、Invoke the HITLS_SetSecurityExData interface and set the first parameter to NULL. The expected result 3 is obtained
4、Invoke the HITLS_SetSecurityExData interface and transfer the first parameter to a normal parameter.
The expected result 4 is obtained
5、Invoke the HITLS_GetSecurityCb interface and set the parameter to NULL. The expected result 5 is obtained
6、Invoke the HITLS_GetSecurityCb interface and transfer the parameter to a normal parameter.
The expected result 5 is obtained
7、Invoke the HITLS_GetSecurityExData interface and set the parameter to NULL. The expected result 7 is obtained
8、Invoke the HITLS_GetSecurityExData interface and transfer the parameter to a normal parameter.
The expected result 8 is obtained
* @expect  1、return HITLS_NULL_INPUT
2、 return HITLS_SUCCESS
3、 return HITLS_NULL_INPUT
4、 return HITLS_SUCCESS
5、 return NULL
6、 The returned value is equal to the configured value TEST_HITLS_SecurityCb.
7、 return NULL
8、 The returned value is equal to the configured value securityExData.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SECURITY_SECURITYCB_API_TC001()
{
    HitlsInit();
    HITLS_Ctx *ctx = NULL;
    HITLS_Config *Config;
    Config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(Config != NULL);
    ctx = HITLS_New(Config);
    int32_t userdata = 0;
    void *securityExData = &userdata;
    ASSERT_EQ(HITLS_SetSecurityCb(NULL, TEST_HITLS_SecurityCb), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetSecurityCb(ctx, TEST_HITLS_SecurityCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetSecurityExData(NULL, securityExData), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetSecurityExData(ctx, securityExData), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_GetSecurityCb(NULL), NULL);
    ASSERT_EQ(HITLS_GetSecurityCb(ctx), TEST_HITLS_SecurityCb);
    ASSERT_EQ(HITLS_GetSecurityExData(NULL), NULL);
    ASSERT_EQ(HITLS_GetSecurityExData(ctx), securityExData);
EXIT:
    HITLS_CFG_FreeConfig(Config);
    HITLS_Free(ctx);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_SECURITY_SECURITYCB_API_TC002
* @title  HITLS_CFG_SetSecurityCb HITLS_CFG_SetSecurityExData HITLS_CFG_GetSecurityCb and
HITLS_CFG_GetSecurityExData Interface Test
* @precon  nan
* @brief  1、Invoke the HITLS_CFG_SetSecurityCb interface and set the first parameter to NULL.
The expected result 1 is obtained
2、Invoke the HITLS_CFG_SetSecurityCb interface and transfer the first parameter to a normal parameter.
The expected result 2 is obtained
3、Invoke the HITLS_CFG_SetSecurityExData interface and set the first parameter to NULL.
The expected result 3 is obtained
4、Invoke the HITLS_CFG_SetSecurityExData interface and transfer the first parameter to a normal parameter.
The expected result 4 is obtained
5、Invoke the HITLS_CFG_GetSecurityCb interface and set the parameter to NULL. The expected result 5 is obtained
6、Invoke the HITLS_CFG_GetSecurityCb interface and transfer the parameter to a normal parameter.
The expected result 5 is obtained
7、Invoke the HITLS_CFG_GetSecurityExData interface and set the parameter to NULL. The expected result 7 is obtained
8、Invoke the HITLS_CFG_GetSecurityExData interface and transfer the parameter to a normal parameter.
The expected result 8 is obtained
* @expect  1、return HITLS_NULL_INPUT
2、 return HITLS_SUCCESS
3、 return HITLS_NULL_INPUT
4、 return HITLS_SUCCESS
5、 return NULL
6、 The returned value is equal to the configured value TEST_HITLS_SecurityCb.
7、 return NULL
8、 The returned value is equal to the configured value securityExData.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SECURITY_SECURITYCB_API_TC002()
{
    HitlsInit();
    HITLS_Config *Config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(Config != NULL);
    int32_t userdata = 0;
    void *securityExData = &userdata;
    ASSERT_EQ(HITLS_CFG_SetSecurityCb(NULL, TEST_HITLS_SecurityCb), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetSecurityCb(Config, TEST_HITLS_SecurityCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSecurityExData(NULL, securityExData), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetSecurityExData(Config, securityExData), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_GetSecurityCb(NULL), NULL);
    ASSERT_EQ(HITLS_CFG_GetSecurityCb(Config), TEST_HITLS_SecurityCb);
    ASSERT_EQ(HITLS_CFG_GetSecurityExData(NULL), NULL);
    ASSERT_EQ(HITLS_CFG_GetSecurityExData(Config), securityExData);
EXIT:
    HITLS_CFG_FreeConfig(Config);
}
/* END_CASE */

/* @
* @test  UT_TLS_CM_IS_DTLS_API_TC001
* @title Test HITLS_IsDtls
* @precon nan
* @brief HITLS_IsDtls
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer the non-empty TLS connection handle information and leave isDtls blank. Expected result 1.
* 3. Transfer the non-empty TLS connection handle information. The isDtls parameter is not empty. Expected result 2.
* @expect
* 1. Returns HITLS_NULL_INPUT
* 2. Returns HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_TLS_CM_IS_DTLS_API_TC001(int tlsVersion)
{
    HitlsInit();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool isDtls = false;
    ASSERT_TRUE(HITLS_IsDtls(ctx, &isDtls) == HITLS_NULL_INPUT);

    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_IsDtls(ctx, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_IsDtls(ctx, &isDtls) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */


/*@
* @test UT_TLS_CM_GET_SELECTEDALPNPROTO_API_TC001
*
* @title   test HITLS_GetSelectedAlpnProto interface
* @brief
*          1. Construct the CTX configuration. Expected result 1.
*          2. Construct the CTX connection handle. Expected result 1.
*          3. tls connection handle is NULL, Invoke the HITLS_GetSelectedAlpnProto interface. Expected result 2.
*          4. proto is NULL ,invoke the HITLS_CFG_SetSessionIdCtx interface.Expected result 2.
*          5. protoLen is NULL, Invoke the HITLS_GetSessionTicketKey interface.Expected result 2
* @expect  1. Return not NULL.
*          2. Return not HITLS_NULL_INPUT.
@ */

/* BEGIN_CASE */
void UT_TLS_CM_GET_SELECTEDALPNPROTO_API_TC001()
{
    HitlsInit();
    HITLS_Config *tlsConfig;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    uint8_t * alpnProtosname = (uint8_t *)"vpn|http";
    uint32_t alpnProtosnameLen = sizeof(alpnProtosname);
    ASSERT_TRUE(HITLS_GetSelectedAlpnProto(NULL, &alpnProtosname, &alpnProtosnameLen) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetSelectedAlpnProto(ctx, NULL, &alpnProtosnameLen), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetSelectedAlpnProto(ctx, &alpnProtosname, NULL), HITLS_NULL_INPUT);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    return;
}
/* END_CASE */

#define DATA_MAX_LEN 1024
/*@
* @test UT_TLS_CM_GET_SET_SESSIONTICKETKEY_API_TC001
*
* @title  test HITLS_SetSessionTicketKey/HITLS_GetSessionTicketKey interface
* @brief   1. Construct the CTX connection handle. Expected result 1.
*          2. tls connection handle is NULL, Invoke the HITLS_SetSessionTicketKey interface. Expected result 2.
*          3. tls connection handle is NULL, Invoke the HITLS_GetSessionTicketKey interface.Expected  result 2.
* @expect  1. Return not NULL.
*          2. Return HITLS_NULL_INPUT.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_SET_SESSIONTICKETKEY_API_TC001(int version)
{
    FRAME_Init();
    uint8_t key[] = "748ab9f3dc1a23";
    HITLS_Config *config = GetHitlsConfigViaVersion(version);

    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    uint8_t getKey[DATA_MAX_LEN] = {0};
    uint32_t getKeySize = DATA_MAX_LEN;
    uint32_t outSize = 0;
    uint32_t ticketKeyRandLen = HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_KEY_SIZE + HITLS_TICKET_KEY_SIZE;
    ASSERT_TRUE(HITLS_SetSessionTicketKey(NULL, key, ticketKeyRandLen) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetSessionTicketKey(NULL, getKey, getKeySize, &outSize) == HITLS_NULL_INPUT);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test UT_TLS_CM_SET_SESSIONIDCTX_API_TC001
*
* @title  test HITLS_CFG_SetSessionIdCtx interface
* @precon  nan
* @brief   1. Construct the CTX connection handle. Expected result 1.
*          2. config is NULL, Invoke the HITLS_CFG_SetSessionIdCtx interface. Expected result 4.
*          3. invoke the HITLS_CFG_SetSessionIdCtx interface.Expected result 2.
*          4. tls connection handle is NULL, Invoke the HITLS_SetSessionIdCtx interface.Expected
*             result 4.
*          5. Invoke the HITLS_SetSessionIdCtx interface. Expected result 2.
* @expect  1. Return not NULL.
*          2. Return not HITLS_NULL_INPUT.
*          3. Return NULL.
*          4. Return HITLS_NULL_INPUT.
@ */

/* BEGIN_CASE */
void UT_TLS_CM_SET_SESSIONIDCTX_API_TC001(int version)
{
    FRAME_Init();
    char *key = "748ab9f3dc1a23";
    HITLS_Config *config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    uint32_t keyLen = strlen(key);
    ASSERT_TRUE(HITLS_CFG_SetSessionIdCtx(NULL, (const uint8_t *)key, keyLen)== HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetSessionIdCtx(config, (const uint8_t *)key, keyLen)!= HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetSessionIdCtx(NULL, (const uint8_t *)key, keyLen)== HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetSessionIdCtx(ctx, (const uint8_t *)key, keyLen)!= HITLS_NULL_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test   UT_TLS_CM_HITLS_GetCertificate_API_TC001
* @title  Cover the input parameter of the HITLS_GetCertificate interface.
* @precon nan
* @brief  1. Invoke the HITLS_GetCertificate interface and leave ctx blank. Expected result 1.
*         2. Invoke the HITLS_GetPeerCertificate interface and leave ctx blank. Expected result 1.
*         3. Invoke the HITLS_GetPeerCertificate interface. The value of ctx is not empty and the value of ctx->session
*            is empty. Expected result 1.
*         4. Invoke the HITLS_GetPeerCertChain interface and leave ctx blank. Expected result 1.
*         5. Invoke the HITLS_GetPeerCertChain interface. The value of ctx is not empty and the value of ctx->session is
*            empty. Expected result 1.
* @expect 1.Return NULL
@ */
/* BEGIN_CASE */
void UT_TLS_CM_HITLS_GetCertificate_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_GetCertificate(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetPeerCertificate(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetPeerCertChain(NULL) == NULL);
    ctx->session = NULL;
    ASSERT_TRUE(HITLS_GetPeerCertificate(ctx) == NULL);
    ASSERT_TRUE(HITLS_GetPeerCertChain(ctx) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test   UT_HITLS_CM_HITLS_Set_and_Get_ErrorCode_API_TC001
* @spec  -
* @title  Cover the input parameter of HITLS_SetChainStore and HITLS_GetChainStore interface
* @precon nan
* @brief  1. Invoke the HITLS_GetErrorCode interface and leave ctx blank. Expected result 1.
          2. Invoke the HITLS_GetErrorCode interface with ctx not empty. Expected result 3.
          3. Invoke the HITLS_SetErrorCode interface and leave ctx blank. Expected result 1.
          4. Invoke the HITLS_SetErrorCode interface. The value of ctx is not empty. Expected result 2.
* @expect 1. Return HITLS_NULL_INPUT
          2. Return HITLS_SUCCESS
          3. Return errorCode
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_HITLS_CM_HITLS_Set_and_Get_ErrorCode_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    uint32_t errorCode = 0;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    HITLS_SetErrorCode(ctx, errorCode);
    ASSERT_TRUE(HITLS_GetErrorCode(NULL) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetErrorCode(ctx), errorCode);
    ASSERT_TRUE(HITLS_SetErrorCode(ctx, errorCode) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_SetErrorCode(NULL, errorCode) == HITLS_NULL_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */
/* @
* @test   UT_HITLS_CM_SET_GET_ENCRYPTTHENMAC_TC001
* @title  Test the HITLS_SetEncryptThenMac and HITLS_GetEncryptThenMac interfaces.
* @precon nan
* @brief  HITLS_SetEncryptThenMac
*         1. Transfer an empty TLS connection handle. Expected result 1.
*         2. Transfer a non-empty TLS connection handle and set encryptThenMacType to an invalid value. Expected result 2.
*         3. Transfer a non-empty TLS connection handle and set encryptThenMacType to a valid value. Expected result 3.
*         HITLS_GetEncryptThenMac
*         1. Transfer an empty TLS connection handle. Expected result 1.
*         2. Transfer an empty encryptThenMacType pointer. Expected result 1.
*         3. Transfer the non-null TLS connection handle information and ensure that the encryptThenMacType pointer is not null. Expected result 3.
* @expect 1. Return HITLS_NULL_INPUT
*         2. Return HITLS_SUCCES and isEncryptThenMac is True
*         3. Return HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_HITLS_CM_SET_GET_ENCRYPTTHENMAC_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool encryptThenMacType = false;

    ASSERT_TRUE(HITLS_SetEncryptThenMac(ctx, encryptThenMacType) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetEncryptThenMac(ctx, &encryptThenMacType) == HITLS_NULL_INPUT);
    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetEncryptThenMac(ctx, NULL) == HITLS_NULL_INPUT);
    encryptThenMacType = true;
    ASSERT_TRUE(HITLS_SetEncryptThenMac(ctx, encryptThenMacType) == HITLS_SUCCESS);
    encryptThenMacType = true;
    ASSERT_TRUE(HITLS_SetEncryptThenMac(ctx, encryptThenMacType) == HITLS_SUCCESS);
    ASSERT_TRUE(config->isEncryptThenMac == true);

    bool getencryptThenMacType = false;
    ASSERT_TRUE(HITLS_GetEncryptThenMac(ctx, &getencryptThenMacType) == HITLS_SUCCESS);
    ASSERT_TRUE(getencryptThenMacType == true);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test   UT_HITLS_CM_HITLS_GetPostHandshakeAuthSupport_TC001
* @title  Test the HITLS_GetPostHandshakeAuthSupport interfaces.
* @precon nan
* @brief  1. Transfer an empty TLS connection handle. Expected result 1.
*         2. Transfer a non-empty TLS connection handle and set isSupport to to NULL. Expected result 1.
*         3. Transfer a non-empty TLS connection handle and set isSupport to a valid value. Expected result 2.
* @expect 1. Return HITLS_NULL_INPUT
*         2. Return HITLS_SUCCES
@ */

/* BEGIN_CASE */
void UT_HITLS_CM_HITLS_GetPostHandshakeAuthSupport_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    uint32_t isSupport = 0;

    ASSERT_TRUE(HITLS_GetPostHandshakeAuthSupport(NULL, NULL) == HITLS_NULL_INPUT);
    config = GetHitlsConfigViaVersion(tlsVersion);
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetEncryptThenMac(ctx, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetEncryptThenMac(ctx, isSupport) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */

static void test_msg_callback(int32_t writePoint, int32_t tlsVersion, int32_t contentType,
                              const void *msg, uint32_t msgLen, HITLS_Ctx *ctx, void *arg)
{
    (void)writePoint;
    (void)contentType;
    (void)ctx;
    (void)arg;
    ASSERT_TRUE(msg != NULL);
    bool isValid = false;
    /* Check if tlsVersion is valid */
    if (tlsVersion == HITLS_VERSION_SSL30 ||
        tlsVersion == HITLS_VERSION_TLS10 ||
        tlsVersion == HITLS_VERSION_TLS11 ||
        tlsVersion == HITLS_VERSION_TLS12 ||
        tlsVersion == HITLS_VERSION_TLS13 ||
        tlsVersion == HITLS_VERSION_DTLS12 ||
        tlsVersion == HITLS_VERSION_TLCP_DTLCP11 ||
        tlsVersion == 0) { /* 0 is valid for record headers before version negotiation */
        isValid = true;
    }
    ASSERT_TRUE(isValid);
    ASSERT_TRUE(msgLen > 0);
EXIT:
    return;
}

/* @
* @test   UT_TLS_CM_SetMsgCb_FUNC_TC001
* @title  Test HITLS_SetMsgCb callback function to verify tlsVersion and msgLen parameters
* @precon nan
* @brief
*         1. Set up TLS client and server configurations.
*         2. Set message callback using HITLS_SetMsgCb. (Expected result 1)
*         3. Establish TLS handshake connection. (Expected result 2)
*         4. Verify callback was invoked with valid parameters. (Expected result 3)
* @expect
*         1. HITLS_SetMsgCb returns HITLS_SUCCESS
*         2. Handshake completes successfully
*         3. Callback receives valid tlsVersion and non-zero msgLen
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SetMsgCb_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    /* Create TLS12 configurations */
    clientConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(serverConfig != NULL);

    /* Set message callback on config */
    ASSERT_EQ(HITLS_CFG_SetMsgCb(clientConfig, test_msg_callback), HITLS_SUCCESS);

    /* Create client and server */
    client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* Establish connection to trigger callback */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */