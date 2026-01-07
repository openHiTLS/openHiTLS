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

#include "hitls_error.h"
#include "tls.h"
#include "change_cipher_spec.h"
#include "frame_tls.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_link.h"
#include "frame_io.h"
#include "frame_msg.h"
#include "simulate_io.h"
#include "stub_replace.h"
#include "hs.h"
#include "alert.h"
#include "bsl_sal.h"
#include "securec.h"
#include "app.h"
#include "hs_kx.h"
#include "hs_msg.h"
#include "rec.h"
#include "conn_init.h"
#include "parse.h"
#include "hs_common.h"
#include "common_func.h"
#include "hlt.h"
#include "process.h"
#include "hitls_crypt_init.h"
#include "rec_wrapper.h"

#define REC_TLS_RECORD_HEADER_LEN 5
#define ALERT_BODY_LEN 2u
#define READ_BUF_SIZE 18432
#define ERROR_VERSION_BIT 0x00000000U
#define READ_BUF_LEN_18K (18 * 1024)
#define BUF_SIZE_DTO_TEST (18 * 1024)
#define ROOT_DER "%s/ca.der:%s/inter.der"
#define INTCA_DER "%s/inter.der"
#define SERVER_DER "%s/server.der"
#define SERVER_KEY_DER "%s/server.key.der"
#define CLIENT_DER "%s/client.der"
#define CLIENT_KEY_DER "%s/client.key.der"
static char *g_serverName = "testServer";
uint32_t g_uiPort = 18890;
/* END_HEADER */

int32_t RecParseInnerPlaintext(TLS_Ctx *ctx, uint8_t *text, uint32_t *textLen, uint8_t *recType);
int32_t STUB_RecParseInnerPlaintext(TLS_Ctx *ctx, uint8_t *text, uint32_t *textLen, uint8_t *recType)
{
    (void)ctx;
    (void)text;
    (void)textLen;
    *recType = (uint8_t)REC_TYPE_APP;

    return HITLS_SUCCESS;
}

void SetFrameType(FRAME_Type *frametype, uint16_t versionType, REC_Type recordType, HS_MsgType handshakeType,
    HITLS_KeyExchAlgo keyExType)
{
    frametype->versionType = versionType;
    frametype->recordType = recordType;
    frametype->handshakeType = handshakeType;
    frametype->keyExType = keyExType;
    frametype->transportType = BSL_UIO_TCP;
}

void TestSetCertPath(HLT_Ctx_Config *ctxConfig, char *SignatureType)
{
    if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA1", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA1")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA256")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, RSA_SHA256_PRIV_PATH3, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA384", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA384")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA384_EE_PATH, RSA_SHA384_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA512", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA512")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA512_EE_PATH, RSA_SHA512_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA256_EE_PATH,
            ECDSA_SHA256_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA384_EE_PATH,
            ECDSA_SHA384_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA512_EE_PATH,
            ECDSA_SHA512_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_ECDSA_SHA1", strlen("CERT_SIG_SCHEME_ECDSA_SHA1")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA1_CA_PATH,
            ECDSA_SHA1_CHAIN_PATH,
            ECDSA_SHA1_EE_PATH,
            ECDSA_SHA1_PRIV_PATH,
            "NULL",
            "NULL");
    }
}

static int SetCertPath(HLT_Ctx_Config *ctxConfig, const char *certStr, bool isServer)
{
    char caCertPath[50];
    char chainCertPath[30];
    char eeCertPath[30];
    char privKeyPath[30];

    int32_t ret = sprintf_s(caCertPath, sizeof(caCertPath), ROOT_DER, certStr, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(chainCertPath, sizeof(chainCertPath), INTCA_DER, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(eeCertPath, sizeof(eeCertPath), isServer ? SERVER_DER : CLIENT_DER, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(privKeyPath, sizeof(privKeyPath), isServer ? SERVER_KEY_DER : CLIENT_KEY_DER, certStr);
    ASSERT_TRUE(ret > 0);
    HLT_SetCaCertPath(ctxConfig, (char *)caCertPath);
    HLT_SetChainCertPath(ctxConfig, (char *)chainCertPath);
    HLT_SetEeCertPath(ctxConfig, (char *)eeCertPath);
    HLT_SetPrivKeyPath(ctxConfig, (char *)privKeyPath);
    return 0;
EXIT:
    return -1;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVE_RENEGOTIATION_REQUEST_FUNC_TC001
* @spec Because TLS 1.3 forbids renegotiation, if a server has negotiated
*       TLS 1.3 and receives a ClientHello at any other time, it MUST
*       terminate the connection with an "unexpected_message" alert.
* @title Initialize the client server to tls1.3. After the connection is established, the client sends a client hello message.
*        The expected server sends an alarm after receiving the message and disconnects the connection.
* @precon nan
* @brief 4.1.1. ryptographic Negotiation row15
*               Initialize the client server to tls1.3. After the connection is established, the client sends a client hello
*                message.
*               The expected server sends an alarm after receiving the message and disconnects the connection.
* @expect 1. The server sends an alarm and the connection is disconnected.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVE_RENEGOTIATION_REQUEST_FUNC_TC001()
{
    FRAME_Init();
    /*  Initialize the client server to tls1.3. */
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportRenegotiation = true;

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    /* After the connection is established, the client sends a client hello message. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);

    FrameMsg recMsg = {0};
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg + REC_TLS_RECORD_HEADER_LEN,
    ioServerData->recMsg.len - REC_TLS_RECORD_HEADER_LEN) == EOK);
    recMsg.len = ioServerData->recMsg.len - 5;

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(serverTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS13);
    ASSERT_TRUE(clientTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS13);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(REC_Write(clientTlsCtx, REC_TYPE_HANDSHAKE, recMsg.msg, recMsg.len), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


static void Test_ModifyClientHello(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->supportedVersion.exState = MISSING_FIELD;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_DOWN_GRADE_FUNC_TC001
* @spec random: 32 bytes generated by a secure random number generator. See
*       Appendix C for additional information. The last 8 bytes MUST be
*       overwritten as described below if negotiating TLS 1.2 or TLS 1.1,
*       but the remaining bytes MUST be random. This structure is
*       generated by the server and MUST be generated independently of the ClientHello.random.
* @title Initialize the client and server to tls1.3. Delete the supportversion extension when sending clienthello
*       messages.
*       After receiving the message, the server negotiates with the TLS1.2 and returns the serverhello after the random
*        number is overwrritened.
*       After receiving the serverhello message, the client checks the random number and sends the
        ALERT_ELLEGAL_PARAMETER alarm.
* @precon nan
* @brief 4.1.3. Server Hello row24
*       Initialize the client server to tls1.3 and delete the supportversion extension when sending client hello
*        messages.
*       After receiving the message, the server negotiates TLS1.2 and returns the serverhello after the random number is
*        overwrritened.
*       After receiving the serverhello message, the client checks the random number and sends the
ALERT_LOCKGAL_PARAMETER a       larm.
* @expect 1. The client sends the ALERT_AIRGAL_PARAMETER alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_DOWN_GRADE_FUNC_TC001()
{
    FRAME_Init();
    /* Initialize the client and server to tls1.3. Delete the supportversion extension when sending clienthello
     * messages. */
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    };
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(tlsConfig, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_CFG_SetVersionSupport(tlsConfig, 0x00000030U);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyClientHello};
    RegisterWrapper(wrapper);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    /* After receiving the message, the server negotiates with the TLS1.2 and returns the serverhello after the random
     *  number is overwrritened. */
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    /* After receiving the serverhello message, the client checks the random number and sends the
     *   ALERT_ELLEGAL_PARAMETER alarm. */
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC001
* @spec Protocol messages MUST be sent in the order defined in Section 4.4.1
*       and shown in the diagrams in Section 2. A peer which receives a
*       handshake message in an unexpected order MUST abort the handshake
*       with an "unexpected_message" alert.
* @title    Client. The certificate is received after the clienthello message is sent.
* @precon nan
* @brief    4.Handshake Protocol row9
*           Client, receiving the certificate after sending the clienthello message.
* @expect 1. Return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = false;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);
    FRAME_LinkObj *client2 = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server2 = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client2 != NULL);
    ASSERT_TRUE(server2 != NULL);
    HITLS_Ctx *clientTlsCtx2 = FRAME_GetTlsCtx(client2);
    HITLS_Ctx *serverTlsCtx2 = FRAME_GetTlsCtx(server2);
    ASSERT_TRUE(FRAME_CreateConnection(client2, server2, true, TRY_RECV_CERTIFICATE_REQUEST) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx2->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx2->state == CM_STATE_HANDSHAKING);
    char *buffer = BSL_SAL_Calloc(1u, MAX_RECORD_LENTH);
    FrameUioUserData *ioUserData2 = BSL_UIO_GetUserData(client2->io);
    uint8_t *recvBuf2 = ioUserData2->recMsg.msg;
    uint32_t recvLen2 = ioUserData2->recMsg.len;
    memcpy_s(buffer, MAX_RECORD_LENTH, recvBuf2, recvLen2);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, buffer, recvLen2), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    FRAME_FreeLink(client2);
    FRAME_FreeLink(server2);
    BSL_SAL_FREE(buffer);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC002
* @spec Protocol messages MUST be sent in the order defined in Section 4.4.1
*       and shown in the diagrams in Section 2. A peer which receives a
*       handshake message in an unexpected order MUST abort the handshake
*       with an "unexpected_message" alert.
* @title Client, unidirectional authentication, certificateverify received after receiving the serverhello message
* @precon nan
* @brief 4.Handshake Protocol row9
*           Client, unidirectional authentication, certificateverify received after receiving the server hello message
* @expect   1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC002()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = false;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);
    client->ssl->hsCtx->state = TRY_RECV_ENCRYPTED_EXTENSIONS;
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC003
* @spec Protocol messages MUST be sent in the order defined in Section 4.4.1
*       and shown in the diagrams in Section 2. A peer which receives a
*       handshake message in an unexpected order MUST abort the handshake
*       with an "unexpected_message" alert.
* @title Client, two-way authentication, certificate received after receiving the serverhello message
* @precon nan
* @brief 4.Handshake Protocol row9
*        Client, two-way authentication, certificate received after receiving the serverhello message
* @expect 1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    client->ssl->hsCtx->state = TRY_RECV_ENCRYPTED_EXTENSIONS;

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC004
* @spec Protocol messages MUST be sent in the order defined in Section 4.4.1
*       and shown in the diagrams in Section 2. A peer which receives a
*       handshake message in an unexpected order MUST abort the handshake
*       with an "unexpected_message" alert.
* @title Client, two-way authentication, receiving certificateverify after receiving certificaterequest
* @precon nan
* @brief     4.Handshake Protocol row9
*           Client, two-way authentication, receiving certificateverify after receiving certificaterequest
* @expect   1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
@ */
 /* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC004()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    client->ssl->hsCtx->state = TRY_RECV_CERTIFICATE;

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC005
* @spec Protocol messages MUST be sent in the order defined in Section 4.4.1
*       and shown in the diagrams in Section 2. A peer which receives a
*       handshake message in an unexpected order MUST abort the handshake
*       with an "unexpected_message" alert.
* @title    Client, unidirectional authentication. After receiving the certificate, the client receives the finished message.
* @precon nan
* @brief    4.Handshake Protocol row9
*           Client, unidirectional authentication. After receiving the certificate, the client receives the finished message.
* @expect   1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC005()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = false;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    client->ssl->hsCtx->state = TRY_RECV_CERTIFICATE_VERIFY;

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC006
* @spec Protocol messages MUST be sent in the order defined in Section 4.4.1
*       and shown in the diagrams in Section 2. A peer which receives a
*       handshake message in an unexpected order MUST abort the handshake
*       with an "unexpected_message" alert.
* @title    Client, unidirectional authentication, receiving appdata after receiving certificateverify
* @precon   nan
* @brief    4.Handshake Protocol row9
*           Client, unidirectional authentication, receiving appdata after receiving certificateverify
* @expect   1. Return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC006()
{
    FRAME_Init();

    STUB_Init();
    FuncStubInfo tmpRpInfo = { 0 };

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = false;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    STUB_Replace(&tmpRpInfo, RecParseInnerPlaintext, STUB_RecParseInnerPlaintext);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_Reset(&tmpRpInfo);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC007
* @spec Protocol messages MUST be sent in the order defined in Section 4.4.1
*       and shown in the diagrams in Section 2. A peer which receives a
*       handshake message in an unexpected order MUST abort the handshake
*       with an "unexpected_message" alert.
* @title     Client, unidirectional authentication, certificateverify received after receiving encryptedextensions
* @precon nan
* @brief 4.Handshake Protocol row9
*           Client, unidirectional authentication, certificateverify received after receiving encryptedextensions
* @expect 1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC007()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = false;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    client->ssl->hsCtx->state = TRY_RECV_CERTIFICATE_REQUEST;

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC008
* @spec     Protocol messages MUST be sent in the order defined in Section 4.4.1
*           and shown in the diagrams in Section 2. A peer which receives a
*           handshake message in an unexpected order MUST abort the handshake
*           with an "unexpected_message" alert.
* @title    The server receives the certificate message in idle state.
* @precon   nan
* @brief    4.Handshake Protocol row9
*           The server receives a certificate message in idle state.
* @expect   1. Return HITLS_CM_LINK_UNESTABLICED
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC008()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FRAME_LinkObj *client2 = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server2 = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client2 != NULL);
    ASSERT_TRUE(server2 != NULL);
    HITLS_Ctx *clientTlsCtx2 = FRAME_GetTlsCtx(client2);
    HITLS_Ctx *serverTlsCtx2 = FRAME_GetTlsCtx(server2);

    ASSERT_TRUE(FRAME_CreateConnection(client2, server2, false, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx2->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx2->state == CM_STATE_HANDSHAKING);

    char *buffer = BSL_SAL_Calloc(1u, MAX_RECORD_LENTH);
    FrameUioUserData *ioUserData2 = BSL_UIO_GetUserData(server2->io);
    uint8_t *recvBuf2 = ioUserData2->recMsg.msg;
    uint32_t recvLen2 = ioUserData2->recMsg.len;
    memcpy_s(buffer, MAX_RECORD_LENTH, recvBuf2, recvLen2);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, buffer, recvLen2), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_UNESTABLISHED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    FRAME_FreeLink(client2);
    FRAME_FreeLink(server2);
    BSL_SAL_FREE(buffer);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC009
* @spec     Protocol messages MUST be sent in the order defined in Section 4.4.1
*           and shown in the diagrams in Section 2. A peer which receives a
*           handshake message in an unexpected order MUST abort the handshake
*           with an "unexpected_message" alert.
* @title    The server uses unidirectional authentication. The certificate message is received after the client hello message is received.
* @precon nan
* @brief    4.Handshake Protocol row9
*           Server, unidirectional authentication, certificate message received after receiving client hello messages.
* @expect   1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC009()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    server->ssl->hsCtx->state = TRY_RECV_FINISH;

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC010
* @spec     Protocol messages MUST be sent in the order defined in Section 4.4.1
*           and shown in the diagrams in Section 2. A peer which receives a
*           handshake message in an unexpected order MUST abort the handshake
*           with an "unexpected_message" alert.
* @title    server, unidirectional authentication, receiving the app message after receiving the client hello message
* @precon nan
* @brief    4.Handshake Protocol row9
*           Server, unidirectional authentication, receiving the app message after receiving the client hello message
* @expect 1. Return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC010()
{
    FRAME_Init();

    STUB_Init();
    FuncStubInfo tmpRpInfo = { 0 };

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = false;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    STUB_Replace(&tmpRpInfo, RecParseInnerPlaintext, STUB_RecParseInnerPlaintext);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_Reset(&tmpRpInfo);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC011
* @spec     Protocol messages MUST be sent in the order defined in Section 4.4.1
*           and shown in the diagrams in Section 2. A peer which receives a
*           handshake message in an unexpected order MUST abort the handshake
*           with an "unexpected_message" alert.
* @title    server, two-way authentication, certificateverify message received after client hello is received
* @precon nan
* @brief    4.Handshake Protocol row9
*           The server, two-way authentication, receives the certificateverify message after receiving the client hello
*           message.
* @expect   1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE

@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC011()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    server->ssl->hsCtx->state = TRY_RECV_CERTIFICATE;

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC012
* @spec     Protocol messages MUST be sent in the order defined in Section 4.4.1
*           and shown in the diagrams in Section 2. A peer which receives a
*           handshake message in an unexpected order MUST abort the handshake
*           with an "unexpected_message" alert.
* @title    server, two-way authentication, receiving the finish message after receiving the certificate message
* @precon   nan
* @brief    4.Handshake Protocol row9
*           The server, two-way authentication, receives the finish message after receiving the certificate message.
* @expect   1. Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC012()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = false;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    server->ssl->hsCtx->state = TRY_RECV_CERTIFICATE_VERIFY;

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC013
* @spec  Protocol messages MUST be sent in the order defined in Section 4.4.1
*        and shown in the diagrams in Section 2.  A peer which receives a
*        handshake message in an unexpected order MUST abort the handshake
*        with an "unexpected_message" alert.
* @title server, two-way authentication, receiving the app message after receiving the certificateverify message
* @precon nan
* @brief 4.Handshake Protocol row9
*        The server, two-way authentication, receives the app message after receiving the certificateverify message.
* @expect 1. Return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_FUNC_TC013()
{
    FRAME_Init();

    STUB_Init();
    FuncStubInfo tmpRpInfo = { 0 };

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    STUB_Replace(&tmpRpInfo, RecParseInnerPlaintext, STUB_RecParseInnerPlaintext);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_Reset(&tmpRpInfo);
}
/* END_CASE */

static void Test_ModifyClientHelloNullKeyshare(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->keyshares.exLen.data = 2;
    clientMsg->keyshares.exKeyShareLen.data = 0;
    clientMsg->keyshares.exKeyShares.state = MISSING_FIELD;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NULL_KEYSHARE_FUNC_TC001
* @spec  If the server selects an (EC)DHE group and the client did not offer a
*       compatible "key_share" extension in the initial ClientHello, the
* server MUST respond with a HelloRetryRequest (Section 4.1.4) message.
* @title Construct the clienthello message sent by the client. The key_share extension is empty and the psk extension is
         not carried. The server is expected to send a hellorequest message.
* @precon nan
* @brief 4.Handshake Protocol row9
*       Construct the client hello message sent by the client. The key_share extension is empty and the psk extension is
        not carried. The server is expected to send a hellorequest message.
* @expect 1. The server sends hrr and waits for receiving the second client hello.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NULL_KEYSHARE_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_ModifyClientHelloNullKeyshare};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ClearWrapper();

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SECOND_GROUP_SUPPORT_FUNC_TC001
* @spec When a client first connects to a server, it is REQUIRED to send the
*       ClientHello as its first TLS message. The client will also send a
*       ClientHello when the server has responded to its ClientHello with a
*       HelloRetryRequest. In that case, the client MUST send the same
*       ClientHello without modification, except as follows:
* @title 1. Set the client server to tls1.3. Set the first group server not to support the client, but the second group
*         server to support the client,
*        The server is expected to send a helloretryrequest message. The client hello message is sent after the client
*        hello message is updated. The group in the keyshare of the client hello message is changed. The connection is
*        expected to be successfully set up.
* @precon nan
* @brief 4.1.2. Client Hello row14
*        1. Set the client server to tls1.3. Set the first group server to not support the client server, and set the
*         second group server to support the client server.
*        The server is expected to send a helloretryrequest message. The client hello message is sent after the client
*        hello message is updated. The group in the keyshare of the client hello message is changed. The connection is
*        expected to be successfully established.
* @expect 1. The server sends hrr and the connection is successfully established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SECOND_GROUP_SUPPORT_FUNC_TC001()
{
    FRAME_Init();
    /* Set the client server to tls1.3. Set the first group server not to support the client, but the second group
     *  server to support the client */
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);


    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SECOND_GROUP_SUPPORT_FUNC_TC002
* @spec When a client first connects to a server, it is REQUIRED to send the
*       ClientHello as its first TLS message. The client will also send a
*       ClientHello when the server has responded to its ClientHello with a
*       HelloRetryRequest. In that case, the client MUST send the same
*       ClientHello without modification, except as follows:
* @title 1. Set the client server to tls1.3. Set the first group server not to support the client, but the second group
*        server to support the client,
*       The server is expected to send a helloretryrequest message, construct the same client hello message sent by the
*        client, and the server is expected to reject connection establishment.
* @precon nan
* @brief 4.1.2. Client Hello row14
*       1. Set the client server to tls1.3. Set the first group server not to support the client, and the second group
*        server to support the client.
*       The server is expected to send a helloretryrequest message, construct the same client hello message sent by the
*        client, and the server is expected to reject connection establishment.
* @expect 1. Link establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SECOND_GROUP_SUPPORT_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    char *buffer = BSL_SAL_Calloc(1u, MAX_RECORD_LENTH);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    memcpy_s(buffer, MAX_RECORD_LENTH, recvBuf, recvLen);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, recvBuf, recvLen) == HITLS_SUCCESS);
    ioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_INVALID_PROTOCOL_VERSION);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    BSL_SAL_FREE(buffer);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SECOND_GROUP_SUPPORT_FUNC_TC003
* @spec     When a client first connects to a server, it is REQUIRED to send the
*           ClientHello as its first TLS message. The client will also send a
*           ClientHello when the server has responded to its ClientHello with a
*           HelloRetryRequest. In that case, the client MUST send the same
*           ClientHello without modification, except as follows:
* @titleSet the client server to tls1.3, and set the first group server not to support the client, and the second group
*            server to support the client,
*           The hash of the cipher suite on the server does not match the hash corresponding to the psk set on the
*            client. The server is expected to send a helloretryrequest message,
*           The client resends the client hello message and removes the psk extension.
* @precon nan
* @brief 4.1.2. Client Hello row14
*           Set the client server to tls1.3. Set the first group server not to support the client, but the second group
*            server to support the client,
*           The hash of the cipher suite on the server does not match the hash corresponding to the psk set on the
*           client. The server is expected to send a helloretryrequest message,
* The client resends the client hello message and removes the psk extension.
* @expect 1. The second clienthello does not contain the psk.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SECOND_GROUP_SUPPORT_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Session *Session = {0};
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    Session = HITLS_GetDupSession(client->ssl);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(HITLS_SetSession(client->ssl, Session) == HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(clientMsg->psks.exState == INITIAL_FIELD);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);

    ioUserData = BSL_UIO_GetUserData(client->io);
    recvBuf = ioUserData->recMsg.msg;
    recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->cipherSuite.data = HITLS_AES_128_GCM_SHA256;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ioUserData = BSL_UIO_GetUserData(server->io);
    recvBuf = ioUserData->recMsg.msg;
    recvLen = ioUserData->recMsg.len;

    parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(clientMsg->psks.exState == MISSING_FIELD);
    FRAME_CleanMsg(&frameType, &frameMsg);
EXIT:
    HITLS_SESS_Free(Session);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RENEGOTIATION_OLD_VERSION_FUNC_TC001
* @spec If a server established a TLS connection with a previous version of
*       TLS and receives a TLS 1.3 ClientHello in a renegotiation, it MUST
*       retain the previous protocol version. In particular, it MUST NOT
*       negotiate TLS 1.3.
* @title 1. On the server end of 1.3, after the connection between 1.2 and 1.2 is successfully established, initiate
        renegotiation and change the client version to 1.3. The supported version includes tls1.2. The expected version
        is tls1.2.
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation row16
*       1. On the 1.3 server, after the 1.2 connection is successfully established, initiate renegotiation and change the
        client version to 1.3. The supported version includes tls1.2. The tls1.2 version is expected to be negotiated.
* @expect 1. The TLS1.2 version is expected to be negotiated.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RENEGOTIATION_OLD_VERSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLS13Config();
    tlsConfig_s->isSupportClientVerify = true;
    tlsConfig_s->isSupportRenegotiation = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_s, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_s, 0x00000030U);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(tlsConfig_s, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_s != NULL);

    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLSConfig();
    HITLS_CFG_SetVersionSupport(tlsConfig_c, 0x00000010U);
    tlsConfig_c->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_c != NULL);
    tlsConfig_c->isSupportRenegotiation = true;

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(serverTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);
    ASSERT_TRUE(clientTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);

    HITLS_CFG_SetVersionSupport(&(clientTlsCtx->config.tlsConfig), 0x00000030U);
    ASSERT_EQ(HITLS_Renegotiate(clientTlsCtx), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_RENEGOTIATION);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_s);
    HITLS_CFG_FreeConfig(tlsConfig_c);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RENEGOTIATION_OLD_VERSION_FUNC_TC002
* @spec If a server established a TLS connection with a previous version of
*       TLS and receives a TLS 1.3 ClientHello in a renegotiation, it MUST
*       retain the previous protocol version. In particular, it MUST NOT
*       negotiate TLS 1.3.
* @title 1. On the server end of 1.2, after the connection is successfully established, the client version is changed to 1.3
*        and the minimum supported version is tls1.3. The renegotiation fails.
* @precon nan
* @brief 4.1.1. Cryptographic Negotiation row16
*       1. After the connection between the client and the client is set up successfully, the client version is changed
*        to 1.3 and the minimum supported version is tls1.3. The renegotiation fails.
* @expect 1. Expected renegotiation failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RENEGOTIATION_OLD_VERSION_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLS13Config();
    tlsConfig_s->isSupportClientVerify = true;
    tlsConfig_s->isSupportRenegotiation = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_s, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_s, 0x00000030U);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(tlsConfig_s, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_s != NULL);

    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLS12Config();
    tlsConfig_c->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_c != NULL);
    tlsConfig_c->isSupportRenegotiation = true;

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(serverTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);
    ASSERT_TRUE(clientTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);


    ASSERT_EQ(HITLS_Renegotiate(clientTlsCtx), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_RENEGOTIATION);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    HITLS_CFG_SetVersionSupport(&(clientTlsCtx->config.tlsConfig), 0x00000020U);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_s);
    HITLS_CFG_FreeConfig(tlsConfig_c);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_VERSION_FUNC_TC001
* @spec In TLS 1.3, the client indicates its version preferences in the
*       "supported_versions" extension (Section 4.2.1) and the
*       legacy_version field MUST be set to 0x0303, which is the version
*       number for TLS 1.2. TLS 1.3 ClientHellos are identified as having a legacy_version of 0x0303 and a
*        supported_versions extension
*       present with 0x0304 as the highest version indicated therein.
* @title    The client server is initialized to the tls1.3 version, and the legacy_version in the sent clienthello
*           message is changed to 0x0302. The server is expected to return an alert.
* @precon nan
* @brief 4.1.2. Client Hello row17
*       The client server is initialized to the tls1.3 version, and the legacy_version in the sent clienthello message
*       is changed to 0x0302. The server is expected to return an alert.
* @expect 1. The server sends an alert message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_VERSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    /* The client server is initialized to the tls1.3 version, and the legacy_version in the sent clienthello
     * message is changed to 0x0302 */
    clientMsg->version.data = 0x0302;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_VERSION_FUNC_TC002
* @spec In TLS 1.3, the client indicates its version preferences in the
*       "supported_versions" extension (Section 4.2.1) and the
*       legacy_version field MUST be set to 0x0303, which is the version
*       number for TLS 1.2. TLS 1.3 ClientHellos are identified as having a legacy_version of 0x0303 and a
*        supported_versions extension present with 0x0304 as the highest version indicated therein.
* @title    The client server is initialized to the tls1.3 version, and the legacy_version in the sent clienthello
*            message is changed to 0x0304. The server is expected to return an alert.
* @precon nan
* @brief 4.1.2. Client Hello row17
*       The client server is initialized to the tls1.3 version, and the legacy_version in the sent clienthello message
*        is changed to 0x0304. The server is expected to return an alert.
* @expect 1. The server sends an alert message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_VERSION_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    /* The client server is initialized to the tls1.3 version, and the legacy_version in the sent clienthello
     * message is changed to 0x0304. */
    clientMsg->version.data = 0x0304;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC001
* @spec     A client which has a cached session ID set by a pre-TLS 1.3 server SHOULD set this field to that value.
*           In compatibility mode (see Appendix D.4),this field MUST be non-empty, so a client not offering a
*           pre-TLS 1.3 session MUST generate a new 32-byte value. This value need not be random but SHOULD be
            unpredictable to avoid
*           implementations fixating on a specific value (also known as
*           ossification). Otherwise, it MUST be set as a zero-length vector
*           (i.e., a zero-valued single byte length field).
* @title    Set the client server to tls1.3 and check the legacy_session_id of the sent clienthello message. The value
            is a 32-byte value.
* @precon nan
* @brief 4.1.2. Client Hello row18
*           Set the client server to tls1.3 and check the legacy_session_id of the sent clienthello to a 32-byte value.
* @expect 1. Check the session ID.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    /* Set the client server to tls1.3 and check the legacy_session_id of the sent clienthello message. The value
     *  is a 32-byte value. */
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientMsg->sessionIdSize.data, 32);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ModifyClientHello_Sessionid_002(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->sessionIdSize.data = 0;
    clientMsg->sessionId.size = 0;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/* @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC002
* @spec     A client which has a cached session ID set by a pre-TLS 1.3 server SHOULD set this field to that value.
*           In compatibility mode (see Appendix D.4),this field MUST be non-empty, so a client not offering a
*           pre-TLS 1.3 session MUST generate a new 32-byte value. This value need not be random but SHOULD be
            unpredictable to avoid implementations fixating on a specific value (also known as
*            ossification). Otherwise, it MUST be set as a zero-length vector
*           (i.e., a zero-valued single byte length field).
* @title    Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message
            to a single byte 0. The expected connection establishment is successful.
* @precon nan
* @brief 4.1.2. Client Hello row18
*           Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message
            to a single byte 0. The expected connection establishment is successful.
* @expect   1. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    /* Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message
     *  to a single byte 0 */
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyClientHello_Sessionid_002};
    RegisterWrapper(wrapper);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    clientTlsCtx->hsCtx->sessionIdSize = 0;
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC003
* @spec  A client which has a cached session ID set by a pre-TLS 1.3 server SHOULD set this field to that value.
*        In compatibility mode (see Appendix D.4),this field MUST be non-empty, so a client not offering a
*        pre-TLS 1.3 session MUST generate a new 32-byte value.  This value need not be random but SHOULD be
*         unpredictable to avoid implementations fixating on a specific value (also known as
*        ossification).  Otherwise, it MUST be set as a zero-length vector
*        (i.e., a zero-valued single byte length field).
* @title Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
*         2-byte 0. The expected connection establishment failure
* @precon nan
* @brief 4.1.2. Client Hello row18
*       Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
*        two bytes 0. The expected connection establishment fails.
* @expect 1. Link establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->sessionIdSize.data = 0;
    /* Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
     *  2-byte 0. */
    clientMsg->sessionId.size = 2;
    clientMsg->sessionId.data[0] = 0x00;
    clientMsg->sessionId.data[1] = 0x00;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_PARSE_INVALID_MSG_LEN);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC004
* @spec A client which has a cached session ID set by a pre-TLS 1.3 server SHOULD set this field to that value.
*       In compatibility mode (see Appendix D.4),this field MUST be non-empty, so a client not offering a
*       pre-TLS 1.3 session MUST generate a new 32-byte value. This value need not be random but SHOULD be unpredictable
        to avoid implementations fixating on a specific value (also known as ossification). Otherwise, it MUST be set as
        a zero-length vector
*       (i.e., a zero-valued single byte length field).
* @title Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
         1 byte 1. The expected connection establishment fails.
* @precon nan
* @brief 4.1.2. Client Hello row18
*       Set the client server to tls1.3 and construct the value of legacy_session_id in the clienthello message to 1
        byte 1. The expected connection establishment fails.
* @expect 1. Connect establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC004()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    /* Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
     *  1 byte 1. */
    clientMsg->sessionIdSize.data = 1;
    clientMsg->sessionId.size = 1;
    clientMsg->sessionId.data[0] = 0x01;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_PARSE_INVALID_MSG_LEN);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ModifyClientHello_Sessionid_005(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->sessionIdSize.data = 26;
    clientMsg->sessionId.size = 26;
    const uint8_t sessionId_temp[26] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
    ASSERT_TRUE(memcpy_s(clientMsg->sessionId.data, sizeof(sessionId_temp) / sizeof(uint8_t),
    sessionId_temp, sizeof(sessionId_temp) / sizeof(uint8_t)) == 0);

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC005
* @spec     A client which has a cached session ID set by a pre-TLS 1.3 server SHOULD set this field to that value.
*       In compatibility mode (see Appendix D.4),this field MUST be non-empty, so a client not offering a
*       pre-TLS 1.3 session MUST generate a new 32-byte value. This value need not be random but SHOULD be unpredictable
        to avoid implementations fixating on a specific value (also known as ossification). Otherwise, it MUST be set as
        a zero-length vector (i.e., a zero-valued single byte length field).
* @title Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
        26 bytes 0. The expected connection is successfully established..
* @precon nan
* @brief 4.1.2. Client Hello row18
*       Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
        26 bytes 0. The expected link establishment success.
* @expect 1. Link establishment success.
* @expect 1. Link establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SESSION_ID_FUNC_TC005()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    /* Set the client server to tls1.3 and construct the value of legacy_session_id in the sent clienthello message to
     *  26 bytes 0. */
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyClientHello_Sessionid_005};
    RegisterWrapper(wrapper);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_CH_CIPHERSUITES_FUNC_TC001
* @spec  cipher_suites:  A list of the symmetric cipher options supported by
*        the client, specifically the record protection algorithm
*        (including secret key length) and a hash to be used with HKDF, in
*        descending order of client preference.  Values are defined in
*        Appendix B.4.  If the list contains cipher suites that the server
*        does not recognize, support, or wish to use, the server MUST
*        ignore those cipher suites and process the remaining ones as
*        usual. If the client is attempting a PSK key establishment, it SHOULD advertise at least one cipher suite
*        indicating a Hash associated with the PSK.
* @title clienthello The first three cipher suites are abnormal values, tls1.2 cipher suites, and tls1.3 cipher suites
*        that are not configured on the server, The fourth cipher suite is supported by the server. It is expected that
*        the server selects the fourth cipher suite to establish a connection.
* @precon nan
* @brief 4.1.2. Client Hello row19
*       The first three cipher suites of client hello are abnormal values, tls1.2 cipher suites, and tls1.3 cipher
*       suites that are not configured on the server,
*       The fourth cipher suite is supported by the server. It is expected that the server selects the fourth cipher
*        suite to establish a connection.
* @expect 1. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CH_CIPHERSUITES_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLS13Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    config_c->isSupportClientVerify = true;
    config_s->isSupportClientVerify = true;

    /* clienthello The first three cipher suites are abnormal values, tls1.2 cipher suites, and tls1.3 cipher suites
     *  that are not configured on the server, The fourth cipher suite is supported by the server.  */
    uint16_t cipherSuits_c[] = {
        0x0041, HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256, HITLS_CHACHA20_POLY1305_SHA256, HITLS_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(config_c, cipherSuits_c, sizeof(cipherSuits_c) / sizeof(uint16_t));
    uint16_t cipherSuits_s[] = {HITLS_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(config_s, cipherSuits_s, sizeof(cipherSuits_s) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_TRUE(server->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite == HITLS_AES_256_GCM_SHA384);


EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_CH_CIPHERSUITES_FUNC_TC002
* @spec  cipher_suites:  A list of the symmetric cipher options supported by
*        the client, specifically the record protection algorithm
*        (including secret key length) and a hash to be used with HKDF, in
*        descending order of client preference.  Values are defined in
*        Appendix B.4.  If the list contains cipher suites that the server
*        does not recognize, support, or wish to use, the server MUST
*        ignore those cipher suites and process the remaining ones as
*        usual. If the client is attempting a PSK key establishment, it SHOULD advertise at least one cipher suite
*        indicating a Hash associated with the PSK.
* @title  The hash of the configured psk does not match the specified cipher suite when tls1.3 is set on the client
*         server. The expected psk does not exist in the client hello.
* @precon nan
* @brief 4.1.2. Client Hello row19
*       When tls1.3 is set on the client and server, the hash of the psk does not match the specified cipher suite. It
*        is expected that the psk does not exist in the client hello.
* @expect 1. No psk is expected in the clienthello.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CH_CIPHERSUITES_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_CFG_SetPskServerCallback(tlsConfig, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(tlsConfig, (HITLS_PskClientCb)ExampleClientCb);
    /* The hash of the configured psk does not match the specified cipher suite when tls1.3 is set on the client
     *  server. */
    uint16_t cipherSuite = HITLS_AES_256_GCM_SHA384;
    HITLS_CFG_SetCipherSuites(tlsConfig, &cipherSuite, 1);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(clientMsg->psks.exState == MISSING_FIELD);


EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_COMPRESSION_METHOD_FUNC_TC001
* @spec     legacy_compression_methods: Versions of TLS before 1.3 supported
*           compression with the list of supported compression methods being
*           sent in this field. For every TLS 1.3 ClientHello, this vector
*           MUST contain exactly one byte, set to zero, which corresponds to
*           the "null" compression method in prior versions of TLS. If a
*           TLS 1.3 ClientHello is received with any other value in this
*           field, the server MUST abort the handshake with an
*           "illegal_parameter" alert. Note that TLS 1.3 servers might
*           receive TLS 1.2 or prior ClientHellos which contain other
*           compression methods and (if negotiating such a prior version) MUST follow the procedures for the appropriate
*            prior version of TLS.
* @title     Construct clienthello compression algorithm. The value is 0. The server is expected to return a decode
*            error alert.
* @precon nan
* @brief 4.1.2. Client Hello row20
*           Construct the clienthello compression algorithm with a two-byte value and the value 0. The server is
*            expected to return a decode error alert.
* @expect 1. Return the decode error alert.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_COMPRESSION_METHOD_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    /* Construct clienthello compression algorithm. The value is 0. */
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->compressionMethodsLen.data = 2;
    clientMsg->compressionMethods.data = realloc(clientMsg->compressionMethods.data, 2 * sizeof(uint8_t));
    clientMsg->compressionMethods.size = 2;
    clientMsg->compressionMethods.data[0] = 0x00;
    clientMsg->compressionMethods.data[1] = 0x00;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_INVALID_COMPRESSION_METHOD);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);


EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_COMPRESSION_METHOD_FUNC_TC002
* @spec     legacy_compression_methods: Versions of TLS before 1.3 supported
*           compression with the list of supported compression methods being
*           sent in this field. For every TLS 1.3 ClientHello, this vector
*           MUST contain exactly one byte, set to zero, which corresponds to
*           the "null" compression method in prior versions of TLS. If a
*           TLS 1.3 ClientHello is received with any other value in this
*           field, the server MUST abort the handshake with an
*           "illegal_parameter" alert. Note that TLS 1.3 servers might
*           receive TLS 1.2 or prior ClientHellos which contain other
*           compression methods and (if negotiating such a prior version) MUST follow the procedures for the appropriate
*            prior version of TLS.
* @title    Constructs clienthello compression algorithm. The value is 1, indicating that the server returns
*            illegal_parameter alert.
* @precon nan
* @brief 4.1.2. Client Hello row20
*           Construct the clienthello compression algorithm with a bit of one byte and the value is 1. The server is
*            expected to return illegal_parameter alert.
* @expect 1. Return ALERT_ELLEGAL_PARAMETER
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_COMPRESSION_METHOD_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    /*  Construct the clienthello compression algorithm with a bit of one byte and the value is 1. */
    clientMsg->compressionMethodsLen.data = 1;
    clientMsg->compressionMethods.size = 1;
    clientMsg->compressionMethods.data[0] = 0x01;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_INVALID_COMPRESSION_METHOD);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_COMPRESSION_METHOD_FUNC_TC003
* @spec     legacy_compression_methods: Versions of TLS before 1.3 supported
*           compression with the list of supported compression methods being
*           sent in this field. For every TLS 1.3 ClientHello, this vector
*           MUST contain exactly one byte, set to zero, which corresponds to
*           the "null" compression method in prior versions of TLS. If a
*           TLS 1.3 ClientHello is received with any other value in this
*           field, the server MUST abort the handshake with an
*           "illegal_parameter" alert. Note that TLS 1.3 servers might
*           receive TLS 1.2 or prior ClientHellos which contain other
*           compression methods and (if negotiating such a prior version) MUST follow the procedures for the appropriate
*            prior version of TLS.
* @title    Construct that the client version is TLS1.2 and the server version is TLS1.3. It is expected that the connection
*            can be set up normally.
* @precon nan
* @brief 4.1.2. Client Hello row20
*           Construct the scenario where the client version is TLS1.2 and the server version is TLS1.3 and the expected
*            connection establishment is normal.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_COMPRESSION_METHOD_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLS13Config();
    tlsConfig_s->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_s, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_s, 0x00000030U);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(tlsConfig_s, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_s != NULL);

    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLS12Config();
    tlsConfig_c->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_c != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(serverTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);
    ASSERT_TRUE(clientTlsCtx->negotiatedInfo.version == HITLS_VERSION_TLS12);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_s);
    HITLS_CFG_FreeConfig(tlsConfig_c);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNKNOWN_EXTENSION_FUNC_TC001
* @spec extensions: Clients request extended functionality from servers by
*       sending data in the extensions field. The actual "Extension"
*       format is defined in Section 4.2. In TLS 1.3, the use of certain extensions is mandatory, as functionality has
*        moved into extensions to preserve ClientHello compatibility with previous
*       versions of TLS. Servers MUST ignore unrecognized extensions
* @title Set the client server to tls1.3, construct a client hello message that carries the sni extension, and change
*        the sni extension type to 55 (unknown extension). It is expected that the server can establish a connection normally.
* @precon nan
* @brief 4.1.2. Client Hello row21
*       Set the client server to tls1.3, construct a client hello message that carries the SNI extension, and change the
*        SNI extension type to 55 (unknown extension). The server is expected to establish a connection normally.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNKNOWN_EXTENSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetServerName(tlsConfig, (uint8_t *)g_serverName, (uint32_t)strlen(g_serverName));
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = {0};

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    /** Set the client server to tls1.3, construct a client hello message that carries the sni extension, and change
     *  the sni extension type to 55 (unknown extension). */
    clientMsg->serverName.exType.data = 55;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(clientTlsCtx->hsCtx->state, TRY_RECV_ENCRYPTED_EXTENSIONS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC001
* @spec     TLS 1.3 servers will need to perform this check first and
*           only attempt to negotiate TLS 1.3 if the "supported_versions"
*           extension is present. If negotiating a version of TLS prior to 1.3,
*           a server MUST check that the message either contains no data after
*           legacy_compression_methods or that it contains a valid extensions
*           block with no data following. If not, then it MUST abort the
*           handshake with a "decode_error" alert.
* @title:   Set tls1.2 on the client and tls1.3 on the server. Construct the clienthello compression algorithm without
*            any extension. It is expected that the server can establish a connection.
* @precon nan
* @brief 4.1.2. Client Hello row22
*           Set TLS 1.2 on the client and TLS 1.3 on the server. Construct the clienthello compression algorithm without
*            any extension. It is expected that the server can establish a connection.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLSConfig();
    tlsConfig_s->isSupportExtendedMasterSecret = false;
    tlsConfig_s->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_s, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_s, 0x00000030U);
    HITLS_CFG_SetDhAutoSupport(tlsConfig_s, true);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    };
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(tlsConfig_s, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_s != NULL);
    /* Set tls1.2 on the client and tls1.3 on the server. Construct the clienthello compression algorithm without
     * any extension. */
    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLS12Config();
    tlsConfig_c->isSupportExtendedMasterSecret = false;
    tlsConfig_c->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_c != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->extensionState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_c);
    HITLS_CFG_FreeConfig(tlsConfig_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC002
* @spec     TLS 1.3 servers will need to perform this check first and
*           only attempt to negotiate TLS 1.3 if the "supported_versions"
*           extension is present. If negotiating a version of TLS prior to 1.3,
*           a server MUST check that the message either contains no data after
*           legacy_compression_methods or that it contains a valid extensions
*           block with no data following. If not, then it MUST abort the
*           handshake with a "decode_error" alert.
* @title:   Set the client TLS 1.2 and server TLS 1.3. Construct the clienthello compression algorithm and carry the
*            extension and 3-byte data after the extension. The expected connection establishment fails and the decode_error
*            alert is returned.
* @precon nan
* @brief 4.1.2. Client Hello row22
*           Set TLS 1.2 on the client and TLS 1.3 on the server. Construct the compression algorithm of the clienthello
*            message and carry the extension. After the extension, carry the 3-byte data. In this case, the connection
*            establishment fails and the decode_error alert is returned.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLSConfig();
    tlsConfig_s->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_s, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_s, 0x00000030U);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(tlsConfig_s, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_s != NULL);

    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLSConfig();
    HITLS_CFG_SetVersionSupport(tlsConfig_c, 0x00000010U);
    tlsConfig_c->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_c != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint32_t *recvLen = &ioUserData->recMsg.len;
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    ASSERT_TRUE(recvLen != 0);
    recvBuf[4] += 3;
    recvBuf[8] += 3;
    recvBuf[*recvLen] = 0x01;
    recvBuf[(*recvLen)+1] = 0x01;
    recvBuf[(*recvLen)+2] = 0x01;
    *recvLen += 3;

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_c);
    HITLS_CFG_FreeConfig(tlsConfig_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC003
* @spec  TLS 1.3 servers will need to perform this check first and
*        only attempt to negotiate TLS 1.3 if the "supported_versions"
*        extension is present.  If negotiating a version of TLS prior to 1.3,
*        a server MUST check that the message either contains no data after
*        legacy_compression_methods or that it contains a valid extensions
*        block with no data following.  If not, then it MUST abort the
*        handshake with a "decode_error" alert.
* @title:   Set the client TLS 1.2 and server TLS 1.3. Construct the clienthello compression algorithm and carry 3-byte
*            data without extension. Expected connection establishment failure and return decode_error alert.
* @precon nan
* @brief 4.1.2. Client Hello row22
*           Set TLS 1.2 on the client and TLS 1.3 on the server. Construct the compression algorithm of the clienthello
*            message without extension and carry 3-byte data. Expectedly, connection establishment fails and decode_error
*            alert is returned.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLS13Config();
    tlsConfig_s->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_s, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_s, 0x00000030U);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(tlsConfig_s, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_s != NULL);

    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLS12Config();
    tlsConfig_c->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_c != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->extensionState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    /* Set the client TLS 1.2 and server TLS 1.3. Construct the clienthello compression algorithm and carry 3-byte
     * data without extension. */
    sendBuf[4] += 3;
    sendBuf[8] += 3;
    sendBuf[sendLen] = 0x01;
    sendBuf[sendLen + 1] = 0x01;
    sendBuf[sendLen + 2] = 0x01;
    sendLen += 3;

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_c);
    HITLS_CFG_FreeConfig(tlsConfig_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC004
* @spec TLS 1.3 servers will need to perform this check first and
*       only attempt to negotiate TLS 1.3 if the "supported_versions"
*       extension is present. If negotiating a version of TLS prior to 1.3,
*       a server MUST check that the message either contains no data after
*       legacy_compression_methods or that it contains a valid extensions
*       block with no data following. If not, then it MUST abort the
*       handshake with a "decode_error" alert.
* @title 4. Set tls1.2 on the client and tls1.3 on the server. Construct the clienthello message that carries the SNI
*            extension. The SNI length is too large and does not match the content. As a result, the expected connection
*            establishment fails and a decode_error alert message is returned.
* @precon nan
* @brief 4.1.2. Client Hello row22
*           4. Set tls1.2 on the client and tls1.3 on the server. Construct a clienthello message that carries the SNI
*            extension. The SNI length is too large and does not match the content. As a result, the expected connection
*            establishment fails and a decode_error alert message is returned.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_DATA_AFTER_COMPRESSION_FUNC_TC004()
{
    FRAME_Init();

    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLS13Config();
    tlsConfig_s->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_s, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_s, 0x00000030U);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(tlsConfig_s, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_s != NULL);
    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLS12Config();
    HITLS_CFG_SetServerName(tlsConfig_c, (uint8_t *)g_serverName, (uint32_t)strlen(g_serverName));
    tlsConfig_c->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_c != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->serverName.exDataLen.data += 1;
    /* Set tls1.2 on the client and tls1.3 on the server. Construct the clienthello message that carries the SNI
     * extension. */
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_c);
    HITLS_CFG_FreeConfig(tlsConfig_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_LEGACY_VERSION_FUNC_TC001
* @spec legacy_version: In previous versions of TLS, this field was used for version negotiation and represented the
*        selected version number
*        for the connection. In TLS 1.3, the TLS server indicates
*       its version using the "supported_versions" extension
*       (Section 4.2.1), and the legacy_version field MUST be set to
*       0x0303, which is the version number for TLS 1.2. (See Appendix D
*       for details about backward compatibility.)
* @title    The client server is initialized to the tls1.3 version. The legacy_version in the sent serverhello message
*            is changed to 0x0304. The client is expected to return illegal_parameter alert.
* @precon nan
* @brief 4.1.3. Server Hello row23
*           The client and server are initialized to the tls1.3 version, and the legacy_version in the sent serverhello
*            message is changed to 0x0304. The client is expected to return illegal_parameter alert.
* @expect 1. The server sends an alert message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_LEGACY_VERSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    /* The client server is initialized to the tls1.3 version. The legacy_version in the sent serverhello message
     * is changed to 0x0304. */
    serverMsg->version.data = 0x0304;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_LEGACY_VERSION_FUNC_TC002
* @spec     legacy_version: In previous versions of TLS, this field was used for version negotiation and represented the
*            selected version number for the connection. In TLS 1.3, the TLS server indicates
*           its version using the "supported_versions" extension
*           (Section 4.2.1), and the legacy_version field MUST be set to
*           0x0303, which is the version number for TLS 1.2. (See Appendix D
*           for details about backward compatibility.)
* @title    The client server is initialized to the tls1.3 version, and the legacy_version in the sent serverhello
*            message is changed to 0x0302. The client is expected to return illegal_parameter alert.
* @precon nan
* @brief 4.1.3. Server Hello row23
*           The client and server are initialized to tls1.3 and the legacy_version in the sent serverhello message is
*            changed to 0x0302. The client is expected to return illegal_parameter alert.
* @expect 1. The server sends an alert message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_LEGACY_VERSION_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    /* The client server is initialized to the tls1.3 version, and the legacy_version in the sent serverhello
     * message is changed to 0x0302. */
    serverMsg->version.data = 0x0302;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_COMPRESSION_METHOD_FUNC_TC001
* @spec legacy_compression_method: A single byte which MUST have the
* value 0.
* @title    Construct serverhello compression algorithm. The value is 1, indicating that the server returns
*            illegal_parameter alert.
* @precon nan
* @brief 4.1.3. Server Hello row27
*           Construct the serverhello compression algorithm with a one-byte value. The server returns the
*            illegal_parameter alert message.
* @expect 1. The server sends an alert message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_COMPRESSION_METHOD_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    /* Construct serverhello compression algorithm. The value is 1 */
    serverMsg->compressionMethod.data = 0x01;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_PARSE_COMPRESSION_METHOD_ERR);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_EXTENSION_FUNC_TC001
* @spec extensions: A list of extensions. The ServerHello MUST only include
*       extensions which are required to establish the cryptographic
*       context and negotiate the protocol version. All TLS 1.3
*       ServerHello messages MUST contain the "supported_versions"
*       extension. Current ServerHello messages additionally contain
*       either the "pre_shared_key" extension or the "key_share"
*       extension, or both (when using a PSK with (EC)DHE key
*       establishment). Other extensions (see Section 4.2) are sent
*       separately in the EncryptedExtensions message.
* @title Initialize the client and server as tls1.3. Construct a serverhello message that carries the SNI extension. It
*        is expected that the connection fails to be established.
* @precon nan
* @brief 4.1.3. Server Hello row28
*           Initialize the client server to tls1.3 and construct a serverhello message that carries the SNI extension.
*            The expected connection establishment fails.
* @expect 1. The client sends an alert message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_EXTENSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->serverName.exState = INITIAL_FIELD;
    serverMsg->serverName.exType.state = INITIAL_FIELD;
    serverMsg->serverName.exLen.state = INITIAL_FIELD;
    serverMsg->serverName.exLen.data = 0x00;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNSUPPORTED_EXTENSION);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_EXTENSION_FUNC_TC002
* @spec extensions: A list of extensions. The ServerHello MUST only include
*       extensions which are required to establish the cryptographic
*       context and negotiate the protocol version. All TLS 1.3
*       ServerHello messages MUST contain the "supported_versions"
*       extension. Current ServerHello messages additionally contain
*       either the "pre_shared_key" extension or the "key_share"
*       extension, or both (when using a PSK with (EC)DHE key
*       establishment). Other extensions (see Section 4.2) are sent
*       separately in the EncryptedExtensions message.
* @title Initialize the client and server to tls1.3 and construct the serverhello message that does not carry the
*        supportedversion extension, client send illegal parameter after receive serverhello
* @precon nan
* @brief 4.1.3. Server Hello row28
*        Initialize the client server to tls1.3 and construct the serverhello message without the supportedversion
*        extension, client send illegal parameter because server send a tls13 ciphersuite without supportedversion
*        extension
* @expect 1. The client receives an alert response from the CCS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_EXTENSION_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportExtendedMasterSecret = false;
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    /* Initialize the client and server to tls1.3 and construct the serverhello message that does not carry the
     *  supportedversion extension */
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->supportedVersion.exState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_RANDOM_FUNC_TC001
* @spec For reasons of backward compatibility with middleboxes (see
*       Appendix D.4), the HelloRetryRequest message uses the same structure
*       as the ServerHello, but with Random set to the special value of the
*       SHA-256 of "HelloRetryRequest":
*
*       CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
*       C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
*
*       Upon receiving a message with type server_hello, implementations MUST first examine the Random value and,
*       if it matches this value, process it as described in Section 4.1.4).
* @title   The client and server are initialized to the TLS1.3 version and construct the scenario of sending hrr
*          messages. After receiving hrr messages,  The next packet sent by the client is expected to be a client hello
*          message, and the random value of the expected received hrr packet is the specified value.
* @precon nan
* @brief 4.1.3. Server Hello row29
*           The client and server are initialized to the TLS1.3 version, construct the scenario of sending hrr messages.
*            After receiving hrr messages,
*           The next packet sent by the client is expected to be a client hello packet, and the random value of the
*            expected received hrr packet is the specified value.
* @expect 1. Proofreading succeeded.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_RANDOM_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);


    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);


    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* The client and server are initialized to the TLS1.3 version and construct the scenario of sending hrr
     * messages. */
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    const uint8_t g_hrrRandom[HS_RANDOM_SIZE] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};
    ASSERT_TRUE(memcmp(serverMsg->randomValue.data, g_hrrRandom, sizeof(g_hrrRandom) / sizeof(uint8_t)) == 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test    UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_RANDOM_FUNC_TC002
* @spec    For reasons of backward compatibility with middleboxes (see
*          Appendix D.4), the HelloRetryRequest message uses the same structure
*          as the ServerHello, but with Random set to the special value of the
*          SHA-256 of "HelloRetryRequest":
*
*            CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
*            C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
*
*          Upon receiving a message with type server_hello, implementations MUST first examine the Random value and,
*           if it matches this value, process it as described in Section 4.1.4).
* @title    The client and server are initialized to the TLS1.3 version and construct the scenario of sending hrr
*            messages. After receiving hrr messages,
*           The next packet sent by the client is expected to be client hello, and the random value of the expected
*            received hrr is the specified value.
* @precon nan
* @brief 4.1.3. Server Hello row29
*           The client and server are initialized to the TLS1.3 version. The connection is established normally. The
*            client and server directly send the server hello packet without sending the hrr message. The random value of
*            the server hello packet is changed to the value specified by hrr,
*           The client is expected to send a client hello packet after receiving the packet.
* @expect 1. It is expected that the client sends a client hello packet after receiving the packet.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_RANDOM_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    const uint8_t g_hrrRandom[HS_RANDOM_SIZE] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};
    ASSERT_TRUE(memcpy_s(serverMsg->randomValue.data, sizeof(g_hrrRandom) / sizeof(uint8_t),
    g_hrrRandom, sizeof(g_hrrRandom) / sizeof(uint8_t)) == 0);
    serverMsg->keyShare.data.keyExchangeLen.state = MISSING_FIELD;
    serverMsg->keyShare.data.keyExchange.state = MISSING_FIELD;
    serverMsg->keyShare.data.group.data = HITLS_EC_GROUP_SECP521R1;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(clientTlsCtx->hsCtx->state, TRY_SEND_CLIENT_HELLO);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_DOWN_GRADE_RANDOM_FUNC_TC001
* @spec     TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
*           MUST check that the last 8 bytes are not equal to either of these values.
*           TLS 1.2 clients SHOULD also check that the last 8 bytes are not equal to the second value if the ServerHello
*            indicates TLS 1.1 or below.
*           If a match is found, the client MUST abort the handshake with an "illegal_parameter" alert.
*           Note: This is a change from [RFC5246], so in practice many TLS 1.2
*           clients and servers will not behave as specified above.
* @title    The client is tls1.3, and the server is tls1.2. Construct a scenario where the last eight random bytes of
*            the server hello packet received by the client are equal to the specified value. The expected result is that
*            the connection fails to be established and the client returns the illegal_parameter alarm.
* @precon nan
* @brief 4.1.3. Server Hello row31
*       When the client is tls1.3 and the server is tls1.2, construct the last eight random bytes of the server hello
*        packet received by the client equal to the specified value. In this case, the connection fails to be established
*        and the client returns the illegal_parameter alarm.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_DOWN_GRADE_RANDOM_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig_c = HITLS_CFG_NewTLS13Config();
    tlsConfig_c->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig_c, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig_c, 0x00000030U);
    uint16_t cipherSuites[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(tlsConfig_c, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(tlsConfig_c != NULL);

    HITLS_Config *tlsConfig_s = HITLS_CFG_NewTLS12Config();
    tlsConfig_s->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig_s != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);
     ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    /* The client is tls1.3, and the server is tls1.2. Construct a scenario where the last eight random bytes of
     * the server hello packet received by the client are equal to the specified value. */
    const uint8_t g_tls12Downgrade[HS_DOWNGRADE_RANDOM_SIZE] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01};
    ASSERT_TRUE(memcpy_s(serverMsg->randomValue.data + (HS_RANDOM_SIZE - HS_DOWNGRADE_RANDOM_SIZE), sizeof(g_tls12Downgrade) / sizeof(uint8_t),
    g_tls12Downgrade, sizeof(g_tls12Downgrade) / sizeof(uint8_t)) == 0);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig_s);
    HITLS_CFG_FreeConfig(tlsConfig_c);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ModifyServerHello(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->keyShare.exState = INITIAL_FIELD;
    serverMsg->keyShare.exType.state = INITIAL_FIELD;
    serverMsg->keyShare.exLen.state = INITIAL_FIELD;
    serverMsg->keyShare.exLen.data = 0x00;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_RENEGOTIATION_VERSION_FUNC_TC001
* @spec  A legacy TLS client performing renegotiation with TLS 1.2 or prior
*        and which receives a TLS 1.3 ServerHello during renegotiation MUST
*        abort the handshake with a "protocol_version" alert.  Note that
*        renegotiation is not possible when TLS 1.3 has been negotiated.
* @title Construct the TLS1.2 serverhello message received by the TLS1.3 serverhello message during renegotiation.
* @precon nan
* @brief 4.1.3. Server Hello row32
*           Construct the scenario where the TLS1.2 server hello message of the TLS1.3 version is received during
*            renegotiation.
* @expect 1. The client sends an alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_RENEGOTIATION_VERSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportRenegotiation = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_EQ(HITLS_Renegotiate(clientTlsCtx), HITLS_SUCCESS);
    /* Construct the TLS1.2 serverhello message received by the TLS1.3 serverhello message during renegotiation. */
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_ModifyServerHello};
    RegisterWrapper(wrapper);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_RENEGOTIATION);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNSUPPORTED_EXTENSION);


EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_FUNC_TC001
* @spec The server's extensions must contain "supported_versions".
*       Additionally, it SHOULD contain the minimal set of extensions
*       necessary for the client to generate a correct ClientHello pair. As
*       with the ServerHello, a HelloRetryRequest MUST NOT contain any
*       extensions that were not first offered by the client in its
*       ClientHello, with the exception of optionally the "cookie" (see
*       Section 4.2.2) extension.
* @title Initialize the client and server to tls1.3. Construct the scenario where the HRR message is sent and the HRR
*        message does not carry the supportedversion extension,
*       The client is expected to perform the 1.2 handshake process and the status is TRY_RECV_CERTIFICATIONATE.
* @precon nan
* @brief 4.1.4. Hello Retry Request row33
*       Initialize the client and server to tls1.3, construct the scenario where the HRR message is sent, and construct
*        the HRR message that does not carry the supportedversion extension,
*       The client is expected to perform the 1.2 handshake process and the status is TRY_RECV_CERTIFICATIONATE.
* @expect 1. The client is in the TRY_RECV_CERTIFICATIONATE state.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportExtendedMasterSecret = false;
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);


    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);


    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->supportedVersion.exState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(clientTlsCtx->hsCtx->state, TRY_RECV_CERTIFICATE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_FUNC_TC002
* @spec The server's extensions must contain "supported_versions".
*       Additionally, it SHOULD contain the minimal set of extensions
*        necessary for the client to generate a correct ClientHello pair. As
*       with the ServerHello, a HelloRetryRequest MUST NOT contain any
*       extensions that were not first offered by the client in its
*       ClientHello, with the exception of optionally the "cookie" (see
*       Section 4.2.2) extension.
* @title Initialize the client server to tls1.3, construct the scenario where the hrr message is sent, and construct the
*        hrr message carrying the sni extension. The client is expected to return the illegal_parameter alarm.
* @precon nan
* @brief 4.1.4. Hello Retry Request row33
*       Initialize the client server to tls1.3, construct the scenario where the hrr message is sent, and construct the
*        hrr message carrying the sni extension. The client is expected to return the illegal_parameter alarm.
* @expect 1. The client returns the illegal_parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->serverName.exState = INITIAL_FIELD;
    serverMsg->serverName.exType.state = INITIAL_FIELD;
    serverMsg->serverName.exLen.state = INITIAL_FIELD;
    serverMsg->serverName.exLen.data = 0x00;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_FUNC_TC003
* @spec The server's extensions must contain "supported_versions".
*       Additionally, it SHOULD contain the minimal set of extensions
*       necessary for the client to generate a correct ClientHello pair. As
*       with the ServerHello, a HelloRetryRequest MUST NOT contain any
*       extensions that were not first offered by the client in its
*       ClientHello, with the exception of optionally the "cookie" (see
*       Section 4.2.2) extension.
* @title Initialize the client and server to tls1.3, construct the scenario where the hrr message is sent and the hrr
*   message does not carry the key_share extension, and the client is expected to return the illegal_parameter alarm.
* @precon nan
* @brief 4.1.4. Hello Retry Request row33
* Initialize the client server to tls1.3, construct the scenario where the hrr message is sent, and construct the hrr
*   message that does not carry the key_share extension. The client is expected to return the illegal_parameter alarm.
* @expect 1. The client returns the illegal_parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);
    /* Initialize the client and server to tls1.3, construct the scenario where the hrr message is sent and the hrr
     * message does not carry the key_share extension */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->keyShare.exState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_MISSING_EXTENSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test    UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC001
* @spec    Upon receipt of a HelloRetryRequest, the client MUST check the
*          legacy_version, legacy_session_id_echo, cipher_suite, and
*          legacy_compression_method as specified in Section 4.1.3 and then
*          process the extensions, starting with determining the version using
*          "supported_versions".  Clients MUST abort the handshake with an
*          "illegal_parameter" alert if the HelloRetryRequest would not result
*          in any change in the ClientHello.  If a client receives a second
*           HelloRetryRequest in the same connection (i.e., where the ClientHello was itself in response to a
*            HelloRetryRequest),
*           it MUST abort the handshake with an "unexpected_message" alert.
*           Otherwise, the client MUST process all extensions in the HelloRetryRequest and send a second updated
*            ClientHello.
* @title    Initialize the client and server as tls1.3. Construct the scenario where two hrr messages are sent. The
*            client is expected to stop handshake and send unexpected_message alarms.
* @precon nan
* @brief 4.1.4. Hello Retry Request row34
*           Initialize the client and server as tls1.3, construct the scenario where two hrr messages are sent, and the
*            client is expected to stop handshake and send the unexpected_message alarm.
* @expect   1. The client sends the unexpected_message alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    /*  Initialize the client and server as tls1.3. Construct the scenario where two hrr messages are sent. */
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);


    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_SEND_CLIENT_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_SERVER_HELLO);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);


    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_ENCRYPTED_EXTENSIONS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    const uint8_t g_hrrRandom[HS_RANDOM_SIZE] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};
    ASSERT_TRUE(memcpy_s(serverMsg->randomValue.data, sizeof(g_hrrRandom) / sizeof(uint8_t),
    g_hrrRandom, sizeof(g_hrrRandom) / sizeof(uint8_t)) == 0);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_DUPLICATE_HELLO_RETYR_REQUEST);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC002
* @spec     Upon receipt of a HelloRetryRequest, the client MUST check the
*           legacy_version, legacy_session_id_echo, cipher_suite, and
*           legacy_compression_method as specified in Section 4.1.3 and then
*           process the extensions, starting with determining the version using
*           "supported_versions". Clients MUST abort the handshake with an
*           "illegal_parameter" alert if the HelloRetryRequest would not result
*           in any change in the ClientHello. If a client receives a second
*           HelloRetryRequest in the same connection (i.e., where the ClientHello was itself in response to a
*            HelloRetryRequest),
*           it MUST abort the handshake with an "unexpected_message" alert.
*           Otherwise, the client MUST process all extensions in the HelloRetryRequest and send a second updated
*            ClientHello.
* @title    The client server is initialized to the tls1.3 version, and the legacy_version in the hrr message is changed
*            to 0x0304. The client is expected to return illegal_parameter alert.
* @precon nan
* @brief 4.1.4. Hello Retry Request row34
*           The client and server are initialized to tls1.3 and the legacy_version in the hrr message is changed to
*            0x0304. The client is expected to return illegal_parameter alert.
* @expect 1. The client sends the unexpected_message alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->version.data = 0x0304;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC003
* @spec     Upon receipt of a HelloRetryRequest, the client MUST check the
*           legacy_version, legacy_session_id_echo, cipher_suite, and
*           legacy_compression_method as specified in Section 4.1.3 and then
*           process the extensions, starting with determining the version using
*           "supported_versions". Clients MUST abort the handshake with an
*           "illegal_parameter" alert if the HelloRetryRequest would not result
*           in any change in the ClientHello. If a client receives a second
*           HelloRetryRequest in the same connection (i.e., where the ClientHello was itself in response to a
*           HelloRetryRequest), it MUST abort the handshake with an "unexpected_message" alert.
*           Otherwise, the client MUST process all extensions in the HelloRetryRequest and send a second updated
*           ClientHello.
* @title    The client and server are initialized to tls1.3. Change the legacy_version in the hrr message to 0x0302. The
*            client is expected to return illegal_parameter alert.
* @precon nan
* @brief  4.1.4. Hello Retry Request row34
*           The client and server are initialized to tls1.3 and the legacy_version in the hrr message is changed to
*           0x0302. The client is expected to return illegal_parameter alert.
* @expect 1. The client sends the unexpected_message alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    /*  The client and server are initialized to tls1.3. Change the legacy_version in the hrr message to 0x0302. */
    serverMsg->version.data = 0x0302;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC004
* @spec     Upon receipt of a HelloRetryRequest, the client MUST check the
*           legacy_version, legacy_session_id_echo, cipher_suite, and
*           legacy_compression_method as specified in Section 4.1.3 and then
*           process the extensions, starting with determining the version using
*           "supported_versions". Clients MUST abort the handshake with an
*           "illegal_parameter" alert if the HelloRetryRequest would not result
*           in any change in the ClientHello. If a client receives a second
*           HelloRetryRequest in the same connection (i.e., where the ClientHello was itself in response to a
*            HelloRetryRequest),
*           it MUST abort the handshake with an "unexpected_message" alert.
*           Otherwise, the client MUST process all extensions in the HelloRetryRequest and send a second updated
*            ClientHello.
* @title    Initialize the client and server to TLS1.3. Construct the scenario where the session_id field in the hrr is
*            modified. The client is expected to send an illegal parameter alarm after receiving the modification.
* @precon nan
* @brief    4.1.4. Hello Retry Request row34
*           Initialize the client and server to TLS1.3 and construct the scenario where the hrr session_id field is
*            modified. The client is expected to send an illegal parameter alarm after receiving the modification.
* @expect 1. The client sends an illegal parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC004()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg parsedSH = {0};
    uint32_t parseLen = 0;
    FRAME_Type frameType = {0};
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &parsedSH, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *shMsg = &parsedSH.body.hsMsg.body.serverHello;
    memset_s((shMsg->sessionId.data), shMsg->sessionId.size, 1, shMsg->sessionId.size);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSH, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);

EXIT:
    FRAME_CleanMsg(&frameType, &parsedSH);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC005
* @spec Upon receipt of a HelloRetryRequest, the client MUST check the
*       legacy_version, legacy_session_id_echo, cipher_suite, and
*       legacy_compression_method as specified in Section 4.1.3 and then
*       process the extensions, starting with determining the version using
*        "supported_versions". Clients MUST abort the handshake with an
*       "illegal_parameter" alert if the HelloRetryRequest would not result
*       in any change in the ClientHello. If a client receives a second
*       HelloRetryRequest in the same connection (i.e., where the ClientHello was itself in response to a
*        HelloRetryRequest),
*        it MUST abort the handshake with an "unexpected_message" alert.
*       Otherwise, the client MUST process all extensions in the HelloRetryRequest and send a second updated
*        ClientHello.
* @title    The client server is initialized to the TLS1.3 version, and the value of cipher_suite in the hrr message is
*            changed to a value other than the value provided by the client. The client is expected to return
*            illegal_parameter alert.
* @precon nan
* @brief 4.1.4. Hello Retry Request row34
*           The client and server are initialized to the TLS1.3 version, and the value of cipher_suite in the hrr
*            message is changed to a value that is not provided by the client. The client is expected to return
*            illegal_parameter alert.
* @expect   1. The client sends an illegal parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC005()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);


    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg parsedSH = {0};
    uint32_t parseLen = 0;
    FRAME_Type frameType;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &parsedSH, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *shMsg = &parsedSH.body.hsMsg.body.serverHello;
    shMsg->cipherSuite.data = HITLS_AES_128_CCM_SHA256;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSH, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);

    FrameUioUserData *userData = BSL_UIO_GetUserData(client->io);
    uint8_t *alertBuf = userData->sndMsg.msg;
    uint32_t alertLen = userData->sndMsg.len;
    FRAME_Msg parsedAlert = {0};
    uint32_t parsedAlertLen = 0;
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(alertBuf, alertLen, &parsedAlert, &parsedAlertLen) == HITLS_SUCCESS);

    ASSERT_TRUE(parsedAlert.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&frameType, &parsedSH);
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC006
* @spec     Upon receipt of a HelloRetryRequest, the client MUST check the
*           legacy_version, legacy_session_id_echo, cipher_suite, and
*           legacy_compression_method as specified in Section 4.1.3 and then
*           process the extensions, starting with determining the version using
*           "supported_versions". Clients MUST abort the handshake with an
*           "illegal_parameter" alert if the HelloRetryRequest would not result
*           in any change in the ClientHello. If a client receives a second
*           HelloRetryRequest in the same connection (i.e., where the ClientHello was itself in response to a
*            HelloRetryRequest),
*           it MUST abort the handshake with an "unexpected_message" alert.
*           Otherwise, the client MUST process all extensions in the HelloRetryRequest and send a second updated
*            ClientHello.
* @title    Construct hrr compression algorithm. The value is 1. The server is expected to return illegal_parameter
*            alert.
* @precon nan
* @brief    4.1.4. Hello Retry Request row34
*           Construct the hrr compression algorithm byte and set the value to 1. The server is expected to return
*            illegal_parameter alert.
* @expect   1. The client sends an illegal parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FORMAT_FUNC_TC006()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->compressionMethod.data = 0x01;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_PARSE_COMPRESSION_METHOD_ERR);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_CONTENT_FUNC_TC001
* @spec The HelloRetryRequest extensions defined in this specification are:
*       - supported_versions (see Section 4.2.1)
*       - cookie (see Section 4.2.2)
*       - key_share (see Section 4.2.8)
*       A client which receives a cipher suite that was not offered MUST
*       abort the handshake. Servers MUST ensure that they negotiate the
*       same cipher suite when receiving a conformant updated ClientHello.
*       Upon receiving the ServerHello,
*       clients MUST check that the cipher suite supplied in the ServerHello is the same as that in the
*       HelloRetryRequest and otherwise abort the handshake with an "illegal_parameter" alert.
* @title    The client and server are initialized to the TLS1.3 version. In the scenario where the hrr message is sent,
*            the hrr cipher suite is changed to an algorithm that is not provided by the client. The expected connection
*            establishment fails and the illegal_parameter alarm is returned.
* @precon nan
* @brief    4.1.4. Hello Retry Request row35
*           The client and server are initialized to the TLS1.3 version, construct the scenario where the hrr message is
*            sent, and modify the hrr algorithm suite to an algorithm that is not provided by the client. In this case,
*            the expected connection establishment fails and the illegal_parameter alarm is returned.
* @expect 1. The client returns the illegal_parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_CONTENT_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->cipherSuite.data = HITLS_RSA_WITH_AES_128_CBC_SHA;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_CONTENT_FUNC_TC002
* @spec The HelloRetryRequest extensions defined in this specification are:
*       - supported_versions (see Section 4.2.1)
*       - cookie (see Section 4.2.2)
*       - key_share (see Section 4.2.8)
*       A client which receives a cipher suite that was not offered MUST
*       abort the handshake. Servers MUST ensure that they negotiate the
*       same cipher suite when receiving a conformant updated ClientHello.
*       Upon receiving the ServerHello,
*       clients MUST check that the cipher suite supplied in the ServerHello is the same as that in the
*       HelloRetryRequest and otherwise abort the handshake with an "illegal_parameter" alert.
* @title    2. Initialize the client and server to TLS1.3, construct the scenario where the hrr message is sent, and
*            change the algorithm suite for the client hello message to be sent again to the new algorithm suite. It is
*            expected that the connection fails to be established and the illegal_parameter alarm is returned.
* @precon nan
* @brief 4.1.4. Hello Retry Request row35
*           2. Initialize the client and server to TLS1.3, construct the scenario of sending hrr messages, and change
*            the cipher suite of the client hello message to be sent again to the new cipher suite. It is expected that
*            the connection fails to be established and the illegal_parameter alarm is returned.
* @expect 1. The server returns the illegal_parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_CONTENT_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);


    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_SEND_CLIENT_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    /* Initialize the client and server to TLS1.3, construct the scenario where the hrr message is sent, and
     * change the algorithm suite for the client hello message to be sent again to the new algorithm suite. */
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->cipherSuites.data[0] = HITLS_AES_128_GCM_SHA256;
    clientMsg->cipherSuites.data[1] = HITLS_AES_256_GCM_SHA384;
    clientMsg->cipherSuites.data[2] = HITLS_CHACHA20_POLY1305_SHA256;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    ioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_CONTENT_FUNC_TC003
* @spec The HelloRetryRequest extensions defined in this specification are:
*       - supported_versions (see Section 4.2.1)
*       - cookie (see Section 4.2.2)
*       - key_share (see Section 4.2.8)
*       A client which receives a cipher suite that was not offered MUST
*       abort the handshake. Servers MUST ensure that they negotiate the
*       same cipher suite when receiving a conformant updated ClientHello.
*       Upon receiving the ServerHello,
*       clients MUST check that the cipher suite supplied in the ServerHello is the same as that in the
*       HelloRetryRequest and otherwise abort the handshake with an "illegal_parameter" alert.
* @title    3. Initialize the client and server to TLS1.3. Construct the scenario where the HRR message is sent. Modify
*            the cipher suite in the serverhello message to be different from that in the HRR message. As a result, the
*            expected connection establishment fails and the illegal_parameter alarm is returned.
* @precon nan
* @brief    4.1.4. Hello Retry Request row35
*           3. The client and server are initialized to TLS1.3, construct the scenario where hrr is sent, modify the
*            cipher suite in serverhello and hrr to be different, and the expected connection setup fails and the
*            illegal_parameter alarm is returned.
* @expect 1. The client returns the illegal_parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_EXTENSION_CONTENT_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    CONN_Deinit(serverTlsCtx);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_SEND_CLIENT_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_SERVER_HELLO);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_ENCRYPTED_EXTENSIONS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->cipherSuite.data = HITLS_AES_128_GCM_SHA256;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE);

    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_SUPPORT_VERSION_FUNC_TC001
* @spec The value of selected_version in the HelloRetryRequest
*       "supported_versions" extension MUST be retained in the ServerHello,
*       and a client MUST abort the handshake with an "illegal_parameter"
*       alert if the value changes.
* @title    1. Initialize the client and server as tls1.3, construct a scenario where the supportedversion values
*            carried by serverhello and hrr are different,
*           The client is expected to return the illegal_parameter alarm.
* @precon nan
* @brief 4.1.4. Hello Retry Request row37
*       1. Initialize the client and server to tls1.3, construct the scenario where the supportedversion values carried
*        by serverhello and hrr are different,
*       The client is expected to return the illegal_parameter alarm.
* @expect 1. The client returns the illegal_parameter alarm.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_SUPPORT_VERSION_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetVersionSupport(&client->ssl->config.tlsConfig, 0x00000030U);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);
    /* 1. Initialize the client and server to tls1.3, construct the scenario where the supportedversion values carried
        by serverhello and hrr are different, */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);


    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_SEND_CLIENT_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_SERVER_HELLO);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_ENCRYPTED_EXTENSIONS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->supportedVersion.data.data = 0x0303;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);


EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* If the client curve is HITLS_EC_GROUP_CURVE25519 and the certificate is SECP256R1, the connection is successfully
 * established, indicating that the curve in tls1.3 is not associated with the certificate. */
/* BEGIN_CASE */
void SDV_TLS13_RFC8446_KeyShareGroup_TC003(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);
    HLT_SetTls13CipherSuites(serverCtxConfig, "HITLS_AES_128_GCM_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_CURVE25519");
    HLT_SetTls13CipherSuites(clientCtxConfig, "HITLS_AES_128_GCM_SHA256");

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_SUCCESS);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, clientRes->sslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, BUF_SIZE_DTO_TEST, 0, BUF_SIZE_DTO_TEST) == EOK);
    ASSERT_TRUE(HLT_TlsRead(serverRes->ssl, readBuf, BUF_SIZE_DTO_TEST, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_SUPPORT_VERSION_FUNC_TC001
* @title    During the TLS1.3 HRR handshaking, application messages can not be received
* @precon nan
* @brief
*       1. Initialize the client and server to tls1.3, construct the scenario where the supportedversion values carried
*       by serverhello and hrr are different, expect result 1.
*       2. Send a app data message the server, expect reslut 2.
* @expect 1. The client send secend client hello message.
8         2. The server send unexpected message alert.
@ */
/* BEGIN_CASE */
void UT_TLS13_RFC8446_HRR_APP_RECV_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLSConfig();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);
    /* 1. Initialize the client and server to tls1.3, construct the scenario where the supportedversion values carried
        by serverhello and hrr are different, */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_SEND_CLIENT_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    uint32_t sendLenapp = 7;
    uint8_t sendBufapp[7] = {0x17, 0x03, 0x03, 0x00, 0x02, 0x05, 0x05};
    uint32_t writeLen;
    BSL_UIO_Write(clientTlsCtx->uio, sendBufapp, sendLenapp, &writeLen);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* IN TLS1.3, mutiple ccs can be received*/
/* BEGIN_CASE */
void UT_TLS13_RFC8446_RECV_MUTI_CCS_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint32_t sendLenccs = 6;
    uint8_t sendBufccs[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    uint32_t writeLen;
    for (int i = 0; i < 5; i++) {
        BSL_UIO_Write(serverTlsCtx->uio, sendBufccs, sendLenccs, &writeLen);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    }
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */