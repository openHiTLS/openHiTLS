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
/* INCLUDE_BASE test_suite_tls13_consistency_rfc8446 */

#include <stdio.h>
#include "stub_utils.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "cert.h"
#include "securec.h"
#include "rec_wrapper.h"
#include "conn_init.h"
#include "rec.h"
#include "parse.h"
#include "hs_msg.h"
#include "hs.h"
#include "alert.h"
#include "hitls_type.h"
#include "session_type.h"
#include "hitls_crypt_init.h"
#include "common_func.h"
#include "hlt.h"
#include "process.h"
#include "rec_read.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, RecParseInnerPlaintext, TLS_Ctx *, const uint8_t *, uint32_t *, uint8_t *);
STUB_DEFINE_RET1(int32_t, HS_DoHandshake, TLS_Ctx *);


#define g_uiPort 6543
// REC_Read calls TlsRecordRead calls RecParseInnerPlaintext
int32_t RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType);

int32_t STUB_RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType)
{
    (void)ctx;
    (void)text;
    (void)textLen;
    *recType = (uint8_t)REC_TYPE_APP;

    return HITLS_SUCCESS;
}
typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
} ResumeTestInfo;

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_APP_DATA_BEFORE_FINISH_FUNC_TC001
 * @spec  Application Data MUST NOT be sent prior to sending the Finished message
 * @brief 2.Protocol Overview row5
 *        1. Initializing Configurations.
 *        2. Stay in the try finish state and send a message.
 * @expect
 *        1.Initialization succeeded.
 *        2.Return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_APP_DATA_BEFORE_FINISH_FUNC_TC001(int isClient)
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
    FRAME_LinkObj *sender = isClient ? client : server;
    FRAME_LinkObj *recver = isClient ? server : client;
    // During connection establishment, the client stops in the TRY_SEND_FINISH state.
    ASSERT_TRUE(FRAME_CreateConnection(sender, recver, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);
    /*
     * Plaintext header of the wrapped record, which is of the app type for finish and app data.
     * After the wrapped record body is parsed (that is, the body is decrypted), the last nonzero byte of the body is
     * the actual record type. This case is constructed by tampering with the rec type to the app type,
     * which should be the hs type.
     */
    STUB_REPLACE(RecParseInnerPlaintext, STUB_RecParseInnerPlaintext);;
    if (isClient) {
        ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    } else {
        ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_RESTORE(RecParseInnerPlaintext);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_NO_SUPPORTED_GROUP_FUNC_TC001
 * @spec 1. Construct a scenario where the supported groups of the client and server do not overlap. Expect the server
 *          to terminate the handshake and send a handshake_failure message after receiving the client hello message.
 * alert
 * @brief 4.1.1. Cryptographic Negotiation row 10
 * @expect
 *        1.Initialization succeeded.
 *        2.Return HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE.
 *
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NO_SUPPORTED_GROUP_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLS13Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    // Set the groups of the client
    uint16_t groups_c[] = {HITLS_EC_GROUP_SECP384R1};
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384};
    HITLS_CFG_SetGroups(config_c, groups_c, sizeof(groups_c) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));
    // Set the groups of the server
    uint16_t groups_s[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP521R1};
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512};
    HITLS_CFG_SetGroups(config_s, groups_s, sizeof(groups_s) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));
    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    bool isClient = true;
    int32_t ret = FRAME_CreateConnection(client, server, !isClient, TRY_RECV_CLIENT_HELLO);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_Accept(server->ssl);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_HANDSHAKE_FAILURE);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    FRAME_Msg parsedAlert = {0};
    uint32_t parseLen;
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(sndBuf, sndLen, &parsedAlert, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parsedAlert.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_HANDSHAKE_FAILURE);
EXIT:
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RSAE_PSS_FUNC_TC001
 * @spec
 *        The client signature algorithm is set to RSA_PSS_PSS_SHA256 and the server certificate signature algorithm
 *        is set to RSA_PSS_RSAE_SHA256, the connection fails to be established.
 * @brief 4.2.3. Signature Algorithms row 54
 *        1. Initialize configuration
 *        2. If the signature algorithms are inconsistent, the expected connection setup fails and
 *           HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE is returned.
 * @expect
 *        1.Initialization succeeded.
 *        2.Return HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RSAE_PSS_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLS13Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    // The client signature algorithm is set to RSA_PSS_PSS_SHA256
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256};
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));
    // The server signature algorithm is set to RSA_PSS_RSAE_SHA256
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256};
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    FRAME_CertInfo certInfo = {
        "rsa_pss_sha256/rsa_pss_root.der",
        "rsa_pss_sha256/rsa_pss_intCa.der",
        "rsa_pss_sha256/rsa_pss_dev.der",
        0,
        "rsa_pss_sha256/rsa_pss_dev.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RSAE_PSS_FUNC_TC002
* @spec  -
*        The signature algorithm on the client is set to RSA_PSS_RSAE_SHA256 and the signature algorithm on the server
*        is set to RSA_PSS_PSS_SHA256, the connection fails to be established.
* @brief 4.2.3. Signature Algorithms row 53
*        1. Initialize configuration
*        2. If the signature algorithms are inconsistent, the expected connection setup fails and
*           HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE is returned.
* @expect
*        1.Initialization succeeded.
*        2.Return HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE.
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RSAE_PSS_FUNC_TC002()
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLS13Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    // The signature algorithm on the client is set to RSA_PSS_RSAE_SHA256
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256};
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));
    // The signature algorithm on the server is set to RSA_PSS_PSS_SHA256
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256};
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    FRAME_CertInfo certInfo = {
        "rsa_pss_sha256/rsa_pss_root.der",
        "rsa_pss_sha256/rsa_pss_intCa.der",
        "rsa_pss_sha256/rsa_pss_dev.der",
        0,
        "rsa_pss_sha256/rsa_pss_dev.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SIG_FUNC_TC001
 * @brief 4.2.3. Signature Algorithms row 55
 *   1. Set the client server to tls1.3 and the client signature algorithm to rsa-sha1.
 *   2. Set the client server to tls1.3 and the client signature algorithm to ecdsa-sha1.
 *   3. Set the client server to tls1.3 and the hash in the client signature algorithm to des-sha-224. The expected
 *      connection establishment fails.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SIG_FUNC_TC001(int sig)
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLS13Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    uint16_t signAlgs_c[] = {(uint16_t)sig};
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));
    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RSAE_SUPPORT_BY_TLS12SERVER_FUNC_TC001
 * @brief 4.2.3. Signature Algorithms row 57
 *   1. Initialize configuration
 *   2. Set the client to tls1.3, server to tls1.2, and the signature algorithm RSA_PSS_RSAE_SHA256 on the client. The
 *      expected connection setup is successful.
 * @expect
 *   1.Initialization succeeded.
 *   2.The connection is successfully established.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RSAE_SUPPORT_BY_TLS12SERVER_FUNC_TC001()
{
    FRAME_Init();
    // tls 11, 12, 13
    HITLS_Config *config_c = HITLS_CFG_NewTLSConfig();
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    // 1. Set the client to tls1.3, server to tls1.2, and the signature algorithm RSA_PSS_RSAE_SHA256 on the client.
    uint16_t signAlgs_c[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256};
    HITLS_CFG_SetSignature(config_c, signAlgs_c, sizeof(signAlgs_c) / sizeof(uint16_t));
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256};
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));

    uint16_t cipherSuite[] = {HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config_c, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(config_s, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    // Error stack exists
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_SESSID_FROM_SH_FUNC_TC001
 * @spec  legacy_session_id_echo: The contents of the client's
 *        legacy_session_id field. Note that this field is echoed even if
 *        the client' s value corresponded to a cached pre-TLS 1.3 session
 *        which the server has chosen not to resume. A client which
 *        receives a legacy_session_id_echo field that does not match what
 *        it sent in the ClientHello MUST abort the handshake with an
 *        "illegal_parameter" alert.
 * @brief 4.1.3. Server Hello row 25
 *        1.Initialize configuration
 *        2.A client which  receives a legacy_session_id_echo field that does not match what
 *          it sent in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_SESSID_FROM_SH_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

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
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    FRAME_CleanMsg(&frameType, &parsedSH);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_SESSID_FROM_SH_FUNC_TC002
 * @spec  legacy_session_id_echo: The contents of the client's
 *        legacy_session_id field. Note that this field is echoed even if
 *        the client' s value corresponded to a cached pre-TLS 1.3 session
 *        which the server has chosen not to resume. A client which
 *        receives a legacy_session_id_echo field that does not match what
 *        it sent in the ClientHello MUST abort the handshake with an
 *        "illegal_parameter" alert.
 * @brief 4.1.3. Server Hello row 25
 *        1.Initialize configuration
 *        2.A client which receives a legacy_session_id_echo field that does not match what
 *          it sent in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_SESSID_FROM_SH_FUNC_TC002()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

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
    shMsg->sessionId.size = 0;
    shMsg->sessionId.state = MISSING_FIELD;
    shMsg->sessionIdSize.data = 0;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSH, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    FRAME_CleanMsg(&frameType, &parsedSH);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_CIPHERSUITE_FROM_SH_FUNC_TC001
 * @spec  serverSelect one of ClientHello.cipher_suites. If the server is not provided by the client, the client must
 *         terminate the handshake and respond with an illegal message. parameter alarm row 26
 * @brief  cipher_suite: The single cipher suite selected by the server from
 *         the list in ClientHello.cipher_suites. A client which receives a
 *         cipher suite that was not offered MUST abort the handshake with an "illegal_parameter" alert.
 *   1.Initialize configuration
 *   2.A client which receives a cipher suite that was not offered MUST abort the handshake with an
 *     "illegal_parameter" alert.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return ALERT_ILLEGAL_PARAMETER.
 *
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_CIPHERSUITE_FROM_SH_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

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

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_MISSING_SIG_ALG_FROM_CH_FUNC_TC001
 * @spec
 *        1. Set the client server to tls1.3 and construct the client hello message that does not contain the
 *        signature_algorithm extension. The server is expected to return the missing_extension alarm.
 * @brief If a server is authenticating via
 *         a certificate and the client has not sent a "signature_algorithms"
 *         extension, then the server MUST abort the handshake with a
 *         "missing_extension" alert
 * 4.2.3. Signature Algorithms row 51
 *   1.Initialize configuration
 *   2.A client which receives a cipher suite that was not offered MUST abort the handshake with an
 *     "illegal_parameter" alert.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return ALERT_MISSING_EXTENSION.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MISSING_SIG_ALG_FROM_CH_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg parsedCH = {0};
    uint32_t parseLen = 0;
    FRAME_Type frameType = {0};
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &parsedCH, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *chMsg = &parsedCH.body.hsMsg.body.clientHello;
    chMsg->signatureAlgorithms.exState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedCH, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_MISSING_EXTENSION);

    FrameUioUserData *userData = BSL_UIO_GetUserData(server->io);
    uint8_t *alertBuf = userData->sndMsg.msg;
    uint32_t alertLen = userData->sndMsg.len;
    FRAME_Msg parsedAlert = {0};
    uint32_t parsedAlertLen = 0;
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(alertBuf, alertLen, &parsedAlert, &parsedAlertLen) == HITLS_SUCCESS);

    ASSERT_TRUE(parsedAlert.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_MISSING_EXTENSION);
EXIT:
    FRAME_CleanMsg(&frameType, &parsedCH);
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_CERT_VERIFY_FUNC_TC001
 * @brief 4.4.3. Certificate Verify row 147 row 148
 *        1. Set the signature algorithms on the client and server to CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
 *           Change the value of signature_algorithms in the CertificateVerify message sent by the server to
 *           CERT_SIG_SCHEME_DSA_SHA224 and continue to establish a connection. Expected result: After receiving the
 *            CertificateVerify message, the client sends an alert message and the connection is disconnected.
 *       2. Set the dual-end verification, set the signature algorithm supported by the client and server to
 *           CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384, and establish a connection, Change the signature algorithm field in
 *          the CertificateVerify message sent by the client to CERT_SIG_SCHEME_DSA_SHA224. Expected result:
 *           After receiving the CertificateVerify message, the server sends an alert message and the connection
 *          is disconnected.
 * @expect
 *   1.The client sends an alert message and the connection is disconnected.
 *   2.The server sends an alert message and the connection is disconnected.
 *
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_CERT_VERIFY_FUNC_TC001(int isClient)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportClientVerify = true;
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    /* 1.Set the signature algorithms on the client and server to CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
     *   Change the value of signature_algorithms in the CertificateVerify message sent by the server to
     *   CERT_SIG_SCHEME_DSA_SHA224 and continue to establish a connection. */
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384};
    HITLS_CFG_SetSignature(tlsConfig, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    ASSERT_TRUE(FRAME_CreateConnection(client, server, isClient, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    int32_t ret;
    HITLS_Ctx *ctx = isClient ? client->ssl : server->ssl;
    HS_Ctx *hsCtx = ctx->hsCtx;
    uint8_t *buf = hsCtx->msgBuf;
    uint32_t dataLen = 0;
    HS_MsgInfo hsMsgInfo = {0};
    ret = REC_Read(ctx, REC_TYPE_HANDSHAKE, buf, &dataLen, hsCtx->bufferLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    /* 2. Set the dual-end verification, set the signature algorithm supported by the client and server to
     *    CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384, and establish a connection, Change the signature algorithm field in
     *    the CertificateVerify message sent by the client to CERT_SIG_SCHEME_DSA_SHA224. */
    memset_s(buf + HS_MSG_HEADER_SIZE, sizeof(uint16_t), CERT_SIG_SCHEME_DSA_SHA224, sizeof(uint16_t));
    ret = HS_ParseMsgHeader(ctx, buf, dataLen, &hsMsgInfo);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    HS_Msg hsMsg = {0};
    ret = HS_ParseMsg(ctx, &hsMsgInfo, &hsMsg);
    ASSERT_EQ(ret, HITLS_PARSE_UNSUPPORT_SIGN_ALG);
    ALERT_Info alertInfo = {0};
    (void)ALERT_GetInfo(ctx, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_ILLEGAL_PARAMETER);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, isClient, HS_STATE_BUTT) != HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMPTION_FUNC_TC001
 * @brief
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMPTION_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);
    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    HITLS_SetSession(client->ssl, clientSession);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FUNC_TC001
 * @brief
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HRR_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetPskServerCallback(config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);  // 1.2 psk bind with sha256
    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    HITLS_CFG_SetGroups(config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PREFER_PSS_TO_PKCS1_FUNC_TC001
 * @brief 4.4.3. Certificate Verify row 149
 *    1.Initialize configuration
 *    2. Configure the RSA certificate on the server and set the signature algorithm supported by the server to
 *    {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256}, Establish a connection and check whether
 *    the negotiated signature algorithm is CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256. Expected result:
 *    CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256 is negotiated.
 * @expect
 *   1.Initialization succeeded.
 *   2.The connection is successfully set up, and the negotiation algorithm is CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PREFER_PSS_TO_PKCS1_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLS13Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256};
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));
    uint16_t cipherSuite[] = {HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config_s, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));
    FRAME_CertInfo certInfo = {
        "rsa_pss_sha256/rsa_pss_root.der",
        "rsa_pss_sha256/rsa_pss_intCa.der",
        "rsa_pss_sha256/rsa_pss_dev.der",
        0,
        "rsa_pss_sha256/rsa_pss_dev.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfo);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    // Error stack exists
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->negotiatedInfo.signScheme, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
static void Test_ModifyFinish(HITLS_Ctx *ctx, uint8_t *buf, uint32_t *bufLen, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    /* hs msg struct, the first byte indicates the HandshakeType,
     *   the following 3 bytes indicate the remaining bytes in message
     */
    uint8_t modifiedHsMsg[] = {KEY_UPDATE, 0, 0, sizeof(uint8_t), HITLS_UPDATE_REQUESTED};
    (void)memcpy_s(buf, bufSize, modifiedHsMsg, sizeof(modifiedHsMsg));
    *bufLen = sizeof(modifiedHsMsg);
}

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_INVALID_REQ_VAL_FUNC_TC001
 * @brief 4.6.3. Key and Initialization Vector Update row 178
 *    1. Establish a connection, change the value of the updata message sent by the client to 3, and observe the server
 *        behavior. Expected result: The server returns the illegal parameter.
 *    2. Establish a connection, change the value of the updata message sent by the server to 3, and observe the client
 *        behavior. Expected result: The client returns the illegal parameter.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return ALERT_ILLEGAL_PARAMETER.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_INVALID_REQ_VAL_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    uint8_t data[] = {KEY_UPDATE, 0x00, 0x00, 0x01, 0x03};
    ASSERT_TRUE(REC_Write(clientTlsCtx, REC_TYPE_HANDSHAKE, data, sizeof(data)) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    /*  1. Establish a link, change the value of the updata message sent by the client to 3, and observe the server
        behavior. Expected result: The server returns the illegal parameter.
        2. Establish a link, change the value of the updata message sent by the server to 3, and observe the client
        behavior.*/
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_TRUE(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE);
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(serverTlsCtx, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_INVALID_REQ_VAL_FUNC_TC002
 * @brief 4.6.3. Key and Initialization Vector Update row 178
 *    1. Establish a connection, change the value of the updata message sent by the client to 3, and observe the server
 *        behavior. Expected result: The server returns the illegal parameter.
 *    2. Establish a connection, change the value of the updata message sent by the server to 3, and observe the client
 *        behavior. Expected result: The client returns the illegal parameter.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return ALERT_ILLEGAL_PARAMETER.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_INVALID_REQ_VAL_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    uint8_t data[] = {KEY_UPDATE, 0x00, 0x00, 0x01, 0x03};
    ASSERT_TRUE(REC_Write(serverTlsCtx, REC_TYPE_HANDSHAKE, data, sizeof(data)) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    /*  1. Establish a link, change the value of the updata message sent by the client to 3, and observe the server
        behavior. Expected result: The server returns the illegal parameter.
        2. Establish a link, change the value of the updata message sent by the server to 3, and observe the client
        behavior.*/
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE);
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(clientTlsCtx, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_NO_REPLY_FUNC_TC001
 * @brief 4.6.3. Key and Initialization Vector Update row 179
 *        1. After the client receives the update_requested message, the update message returned by the client is lost.
 *       The client continues to send app messages and observe the server behavior. Expected result: The server sends an
 *       alert message and the connection is disconnected.
 *       Analysis: The server application traffic secret is updated on both communication ends,
 *       The client application traffic secret is updated on the client, but the server does not
 *       update the client application traffic secret. When the server sends a message to the client,
 *       the client can parse the message, but the server cannot parse the message.
 * @expect
 *    1.the server cannot parse the message and return ALERT_BAD_RECORD_MAC
 *
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_NO_REPLY_FUNC_TC001()
{
    FRAME_Init();
    int32_t ret;
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_REQUESTED) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    uint8_t dest[READ_BUF_SIZE] = {0};
    uint32_t readbytes = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    /* 1. After the client receives the update_requested message, the update message returned by the client is lost.
     *   The client continues to send app messages and observe the server behavior. */
    uint8_t lostBuffer[MAX_RECORD_LENTH] = {0};
    uint32_t lostLen = 0;
    ret = FRAME_TransportSendMsg(client->io, lostBuffer, MAX_RECORD_LENTH, &lostLen);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_NE(lostLen, 0);

    uint8_t src[] = "Client is sending msg with new application traffic key";
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(client->ssl, src, sizeof(src), &writeLen), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    memset_s(dest, READ_BUF_SIZE, 0, READ_BUF_SIZE);
    readbytes = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_NO_REPLY_FUNC_TC002
 * @brief 4.6.3. Key and Initialization Vector Update row 179
 *        2. When the server receives the update_requested message, the update message returned by the server is lost.
 * The server continues to send app messages and observe the customer behavior. Expected result: The client sends an
 * alert message and the connection is disconnected. Analysis: The client application traffic secret is updated at both
 *       communication ends, The server application traffic secret is updated on the server, but the server application
 * traffic secret is not updated on the client. When the client sends a message to the server, the server can parse the
 * message, but the server cannot parse the message.
 *
 * @expect
 *    1.the server cannot parse the message and return ALERT_BAD_RECORD_MAC
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_WITH_NO_REPLY_FUNC_TC002()
{
    FRAME_Init();
    int32_t ret;
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_REQUESTED) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    uint8_t dest[READ_BUF_SIZE] = {0};
    uint32_t readbytes = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    /* 2. When the server receives the update_requested message, the update message returned by the server is lost. The
     * server continues to send app messages and observe the customer behavior. */
    uint8_t lostBuffer[MAX_RECORD_LENTH] = {0};
    uint32_t lostLen = 0;
    ret = FRAME_TransportSendMsg(server->io, lostBuffer, MAX_RECORD_LENTH, &lostLen);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_NE(lostLen, 0);

    uint8_t src[] = "Server is sending msg with new application traffic key";
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(server->ssl, src, sizeof(src), &writeLen), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    memset_s(dest, READ_BUF_SIZE, 0, READ_BUF_SIZE);
    readbytes = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(client->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_READ_WRITE_AFTER_FATAL_ALEART_FUNC_TC001
 * @brief 6. Alert Protocol row 206
 *   Upon receiving an fatal alert, the TLS implementation SHOULD indicate an error to the application and MUST NOT
 * allow any further data to be sent or received on the connection.
 *   1. After receiving the fatal alert, the server invokes the read interface. The invoking fails.
 *   2. After receiving the fatal alert, the server fails to invoke the write interface.
 *   3. After receiving the fatal alert, the server fails to invoke the read interface.
 *   4. After receiving the fatal alert, the server invokes the write interface. The invoking fails.
 * @expect
 *    1.the server invokes the read interface fails and return HITLS_CM_LINK_FATAL_ALERTED
 *    4.the server invokes the write interface fails and return HITLS_CM_LINK_FATAL_ALERTED
 *
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_READ_WRITE_AFTER_FATAL_ALEART_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    uint8_t data[] = {KEY_UPDATE, 0x00, 0x00, 0x01, 0x03};
    ASSERT_TRUE(REC_Write(serverTlsCtx, REC_TYPE_HANDSHAKE, data, sizeof(data)) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    /*  1. Establish a link, change the value of the updata message sent by the client to 3, and observe the server
        behavior. Expected result: The server returns the illegal parameter.
        2. Establish a link, change the value of the updata message sent by the server to 3, and observe the client
        behavior.*/
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE);
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(clientTlsCtx, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_ILLEGAL_PARAMETER);

    ASSERT_EQ(clientTlsCtx->state, CM_STATE_ALERTED);
    /* 1. After receiving the fatal alert, the server invokes the read interface.  */

    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_FATAL_ALERTED);
    uint8_t src[] = "Hello world";
    /* 4. After receiving the fatal alert, the server invokes the write interface. */
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(clientTlsCtx, src, sizeof(src), &writeLen), HITLS_CM_LINK_FATAL_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_READ_WRITE_AFTER_FATAL_ALEART_FUNC_TC002
 * @brief 6. Alert Protocol row 206
 *   Upon receiving an fatal alert, the TLS implementation SHOULD indicate an error to the application and MUST NOT
 * allow any further data to be sent or received on the connection.
 *   1. After receiving the fatal alert, the server invokes the read interface. The invoking fails.
 *   2. After receiving the fatal alert, the server fails to invoke the write interface.
 *   3. After receiving the fatal alert, the server fails to invoke the read interface.
 *   4. After receiving the fatal alert, the server invokes the write interface. The invoking fails.
 * @expect
 *    1.the server invokes the read interface fails and return HITLS_CM_LINK_FATAL_ALERTED
 *    4.the server invokes the write interface fails and return HITLS_CM_LINK_FATAL_ALERTED
 *
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_READ_WRITE_AFTER_FATAL_ALEART_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    uint8_t data[] = {KEY_UPDATE, 0x00, 0x00, 0x01, 0x03};
    ASSERT_TRUE(REC_Write(clientTlsCtx, REC_TYPE_HANDSHAKE, data, sizeof(data)) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_TRUE(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE);
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(serverTlsCtx, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_ILLEGAL_PARAMETER);

    ASSERT_EQ(serverTlsCtx->state, CM_STATE_ALERTED);
    /* 1. After receiving the fatal alert, the server invokes the read interface.  */

    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_FATAL_ALERTED);
    uint8_t src[] = "Hello world";
    /* 4. After receiving the fatal alert, the server invokes the write interface. */
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(serverTlsCtx, src, sizeof(src), &writeLen), HITLS_CM_LINK_FATAL_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC001
 * @brief 4.6.3. Key and Initialization Vector Update row 175
 *        The KeyUpdate message can be sent by any peer after the Finished message is sent.
 *        An implementation that receives a KeyUpdate message before receiving a Finished message must terminate the
 *        connection with an unexpected_message alert. When the client receives the Finish message, construct abnormal
 *        packets so that the client receives the Updata message and observe the next message sent by the client.
 *        Expected result: The next ALERT_UNEXPECTED_MESSAGE message is sent.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    bool isRecRead = true;
    RecWrapper wrapper = {TRY_RECV_FINISH, REC_TYPE_HANDSHAKE, isRecRead, NULL, Test_ModifyFinish};
    RegisterWrapper(wrapper);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC002
 * @brief 4.6.3. Key and Initialization Vector Update row 175
 *   The KeyUpdate message can be sent by any peer after the Finished message is sent.
 *   An implementation that receives a KeyUpdate message before receiving a Finished message must terminate the
 *  connection with an unexpected_message alert. When the server receives the Finish message, construct abnormal packets
 *  so that the server receives the Updata message and observe the next message sent by the server. Expected result: The
 *  next ALERT_UNEXPECTED_MESSAGE message is sent.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC002()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    bool isRecRead = true;
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH) == HITLS_SUCCESS);
    RecWrapper wrapper = {TRY_RECV_FINISH, REC_TYPE_HANDSHAKE, isRecRead, NULL, Test_ModifyFinish};
    RegisterWrapper(wrapper);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC003
 * @brief 4.6.3. Key and Initialization Vector Update row 175
 *   The KeyUpdate message can be sent by any peer after the Finished message is sent.
 *   An implementation that receives a KeyUpdate message before receiving a Finished message must terminate the
 * connection with an unexpected_message alert. When the client receives the Finish message, construct an abnormal
 * packet so that the client receives the Update message and observe the next message sent by the client. Expected
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    bool isRecRead = true;
    RecWrapper wrapper = {TRY_RECV_FINISH, REC_TYPE_HANDSHAKE, isRecRead, NULL, Test_ModifyFinish};
    RegisterWrapper(wrapper);
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(tlsConfig, &cipherSuite, 1);
    HITLS_CFG_SetPskClientCallback(tlsConfig, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(tlsConfig, (HITLS_PskServerCb)ExampleServerCb);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test    UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC004
 * @brief 4.6.3. Key and Initialization Vector Update row 175
 *   The KeyUpdate message can be sent by any peer after the Finished message is sent.
 *   An implementation that receives a KeyUpdate message before receiving a Finished message must terminate the
 * connection with an unexpected_message alert. When the PSK session is resumed and the connection is established, the
 * client constructs an abnormal packet so that the client receives the update message and observes the next message
 * sent by the client. Expected result: The next ALERT_UNEXPECTED_MESSAGE message is sent.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC004()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);
    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    HITLS_SetSession(client->ssl, clientSession);

    bool isRecRead = true;
    RecWrapper wrapper = {TRY_RECV_FINISH, REC_TYPE_HANDSHAKE, isRecRead, NULL, Test_ModifyFinish};
    RegisterWrapper(wrapper);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/**
 * @test    UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC005
 * @brief 4.6.3. Key and Initialization Vector Update row 175
 *  The KeyUpdate message can be sent by any peer after the Finished message is sent.
 *  When the server receives the finish message, construct an abnormal packet so that the server receives the update
 * message and observe the next message sent by the server. Expected result: The next ALERT_UNEXPECTED_MESSAGE message
 * is sent.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC005()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(tlsConfig, &cipherSuite, 1);
    HITLS_CFG_SetPskClientCallback(tlsConfig, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(tlsConfig, (HITLS_PskServerCb)ExampleServerCb);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH) == HITLS_SUCCESS);
    bool isRecRead = true;
    RecWrapper wrapper = {TRY_RECV_FINISH, REC_TYPE_HANDSHAKE, isRecRead, NULL, Test_ModifyFinish};
    RegisterWrapper(wrapper);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test    UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC006
 * @brief 4.6.3. Key and Initialization Vector Update row 175
 *   The KeyUpdate message can be sent by any peer after the Finished message is sent.
 *   When the PSK session is resumed and the connection is established, the server constructs an abnormal packet so that
 *   the server receives the update message and observes the next message sent by the server. Expected result: The next
 *   ALERT_UNEXPECTED_MESSAGE message is sent.
 * @expect
 *   1.Initialization succeeded.
 *   2.Return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEYUPDATE_BEFORE_FINISH_FUNC_TC006()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    HITLS_SetSession(client->ssl, clientSession);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH) == HITLS_SUCCESS);
    bool isRecRead = true;
    RecWrapper wrapper = {TRY_RECV_FINISH, REC_TYPE_HANDSHAKE, isRecRead, NULL, Test_ModifyFinish};
    RegisterWrapper(wrapper);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/**
 * @test    UT_TLS_TLS13_RFC8446_CONSISTENCY_RECVAPP_AFTER_CERT_FUNC_TC001
 * @spec A Finished message MUST be sent regardless of whether the Certificate message is empty.
 * @brief 4.4.2. Certificate row114
 * 1. The certificate message sent by the server is not empty and the app message is directly sent.
 * Expected result: The handshake between the two parties fails. The client sends an unexpected message alert. The level
 * is ALERT_Level_FATAL, the description is ALERT_UNEXPECTED_MESSAGE, and the handshake is interrupted.
 * 2. Dual-end verification: The peer certificate can be empty, the certificate message sent by the client is empty, and
 * the app message is directly sent. Expected result: The handshake between the two parties fails. The server sends an
 * unexpected message alert. The level is ALERT_Level_FATAL, the description is ALERT_UNEXPECTED_MESSAGE, and the
 * handshake is interrupted.
 * @expect
 * 1.Handshake failed. The client sends ALERT_UNEXPECTED_MESSAGE.
 * 2.Handshake failed. The server sends ALERT_UNEXPECTED_MESSAGE.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECVAPP_AFTER_CERT_FUNC_TC001(int isClient)
{
    FRAME_Init();
    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        0,
        0,
        0,
        0,
    };

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    /* 1. The certificate message sent by the server is not empty and the app message is directly sent.
     *    tlsConfig->isSupportClientVerify = true;
     * 2. Dual-end verification: The peer certificate can be empty, the certificate message sent by the client is empty,
     *    and the app message is directly sent. */
    tlsConfig->isSupportNoClientCert = true;
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(tlsConfig, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    if (isClient) {
        ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH) == HITLS_SUCCESS);
    }
    /*
     * Plaintext header of the wrapped record, which is of the app type for finish and app data.
     * After the wrapped record body is parsed (that is, the body is decrypted), the last nonzero byte of the body is
     * the actual record type. This case is constructed by tampering with the rec type to the app type, which should be
     * the hs type.
     */
    STUB_REPLACE(RecParseInnerPlaintext, STUB_RecParseInnerPlaintext);;
    if (isClient) {
        ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    } else {
        ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_RESTORE(RecParseInnerPlaintext);
}
/* END_CASE */

static int32_t SendCcs(HITLS_Ctx *ctx, uint8_t *data, uint8_t len)
{
    return REC_Write(ctx, REC_TYPE_CHANGE_CIPHER_SPEC, data, len);
}

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC001
 * @spec
 * 1. If the server receives a CCS message before receiving the client hello message, the server sends the
 *      unexpected_message alarm to terminate the connection.
 * @brief If an implementation detects a change_cipher_spec record received before the first ClientHello
 * message or after the peer' s Finished message, it MUST be treated as an unexpected record type.
 * 5. Record Protocol row 183
 * @expect
 * 1.the server sends the ALERT_UNEXPECTED_MESSAGE and terminate the connection.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_CLIENT_HELLO) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(client->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg, MAX_RECORD_LENTH, ioServerData->sndMsg.msg, ioServerData->sndMsg.len) == EOK);
    sndMsg.len = ioServerData->sndMsg.len;
    ioServerData->sndMsg.len = 0;
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
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

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC002
 * @spec
 * 1. After receiving the finished message and CCS message, the client sends the unexpected_message alarm to terminate
 * the connection.
 * 2. After receiving the finished message and CCS message, the server sends the unexpected_message alarm to terminate
 * the connection.
 * @brief If an implementation detects a change_cipher_spec record received before the first ClientHello
 * message or after the peer' s Finished message, it MUST be treated as an unexpected record type.
 * 5. Record Protocol row 183
 * @expect
 * 1.the client sends the ALERT_UNEXPECTED_MESSAGE and terminate the connection.
 * 2.the server sends the ALERT_UNEXPECTED_MESSAGE and terminate the connection.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC002(int isClient)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    uint8_t data = 1;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    if (isClient != 0) {
        ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        /* 2. After receiving the finished message and CCS message, the server sends the unexpected_message alarm to
         * terminate the connection. */
        ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        ALERT_Info info = {0};
        ALERT_GetInfo(server->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
    } else {
        memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE);
        ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
        /* 1. After receiving the finished message and CCS message, the client sends the unexpected_message alarm to
         * terminate the connection. */
        ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        ALERT_Info info = {0};
        ALERT_GetInfo(client->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_ZERO_APPMSG_FUNC_TC001
 * @spec
 * 1. Establish a connection. After the connection is established, construct an APPdata message with 0 length and send
 * it to the server. Then, send an APPdata message with data to the server. The message can be received normally.
 * 2. Establish a connection. After the connection is established, construct an APPdata message with zero length and
 * send it to the client. Then, send an APPdata message with data to the client. The message can be received normally.
 * @brief Zero-length fragments of Application Data MAY be sent, as they are potentially useful as a traffic analysis
 * countermeasure. 5.1. Record Layer row 189
 * @expect
 * 1.The connection is successfully established and received normally.
 * 2.The connection is successfully established and received normally.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ZERO_APPMSG_FUNC_TC001(int isZeroClient)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    uint8_t data[] = "";
    uint8_t appData[] = "hello world";
    uint8_t serverData[READ_BUF_SIZE] = {0};
    uint8_t clientData[READ_BUF_SIZE] = {0};
    ASSERT_TRUE((sizeof(data) <= READ_BUF_SIZE) && (sizeof(appData) <= READ_BUF_SIZE));
    if (isZeroClient != 0) {
        /* 1. Establish a connection. After the connection is established, construct an APPdata message with 0 length
         * and send it to the server. Then, send an APPdata message with data to the server.  */
        (void)memcpy_s(clientData, READ_BUF_SIZE, data, sizeof(data));
        (void)memcpy_s(serverData, READ_BUF_SIZE, appData, sizeof(appData));
    } else {
        /* 2. Establish a connection. After the connection is established, construct an APPdata message with zero length
         * and send it to the client. Then, send an APPdata message with data to the client. */
        (void)memcpy_s(clientData, READ_BUF_SIZE, appData, sizeof(appData));
        (void)memcpy_s(serverData, READ_BUF_SIZE, data, sizeof(data));
    }
    size_t serverDataSize = strlen((char *)serverData) + 1;
    size_t clientDataSize = strlen((char *)clientData) + 1;

    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(server->ssl, serverData, serverDataSize, &writeLen), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_TRUE(readLen == serverDataSize && memcmp(serverData, readBuf, readLen) == 0);

    ASSERT_EQ(HITLS_Write(client->ssl, clientData, clientDataSize, &writeLen), HITLS_SUCCESS);
    memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE);
    readLen = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_TRUE(readLen == clientDataSize && memcmp(clientData, readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_INCORRECT_LENGTH_CHMSG_FUNC_TC001
 * @spec
 * 1. If the server receives a ClientHello whose length exceeds the length of the entire packet, the server sends a
 *    decode_error alarm and the handshake fails.
 * @brief Peers which receive a message which cannot be parsed according to the syntax (e.g.,
 * have a length extending beyond the message boundary or contain an out-of-range length)
 * MUST terminate the connection with a "decode_error" alert.
 * 6. Alert Protocol row 209
 * @expect
 *  1.The server sends a ALERT_DECODE_ERROR and the handshake fails.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_INCORRECT_LENGTH_CHMSG_FUNC_TC001(void)
{
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportClientVerify = true;
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;

    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->extensionLen.state = ASSIGNED_FIELD;
    clientMsg->extensionLen.data = clientMsg->extensionLen.data + 1;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_DECODE_ERROR);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLOSE_NOTIFY_FUNC_TC001
 * @spec
 *   Establish a connection between the client and server, and then close the connection on the client. Check whether
 * the message sent by the client is a close_notify message.
 * @brief The "close_notify" alert is used to indicate orderly closure of one direction of the connection. Upon
 * receiving such an alert, the TLS implementation SHOULD indicate end-of-data to the application.
 * 6.0.0. Alert Protocol row 205
 * @expect
 *  1.The client sends a ALERT_CLOSE_NOTIFY message.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLOSE_NOTIFY_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen = clientioUserData->sndMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->recMsg.msg;
    uint32_t serverreadLen = serverioUserData->recMsg.len;
    uint32_t serverparseLen = 0;
    ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLOSE_NOTIFY_FUNC_TC003
 * @spec
 *   Establish a connection between the client and server, and then close the connection on the server. Obtain the
 * message sent by the server and check whether the message is close_notify.
 * @brief The "close_notify" alert is used to indicate orderly closure of one direction of the connection. Upon
 *        receiving such an alert, the TLS implementation SHOULD indicate end-of-data to the application.
 *        6.0.0. Alert Protocol row 205
 * @expect
 *  1.The server sends a ALERT_CLOSE_NOTIFY message.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLOSE_NOTIFY_FUNC_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(server, client, false, TRY_SEND_CERTIFICATE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);
    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->sndMsg.msg;
    uint32_t serverreadLen = serverioUserData->sndMsg.len;
    uint32_t serverparseLen = 0;
    int32_t ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->recMsg.msg;
    uint32_t clientreadLen = clientioUserData->recMsg.len;
    uint32_t clientparseLen = 0;
    ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_WRITE_FUNC_TC001
 * @spec
 * After the client sends the close_notify message, the client fails to invoke the write interface.
 * @brief Either party MAY initiate a close of its write side of the connection by sending a "close_notify" alert. Any
 *   data received after a closure alert has been received MUST be ignored.
 * 6.1.0. Alert Protocol row 213
 * @expect
 *  1.The client fails to invoke the write interface and send HITLS_CM_LINK_CLOSED
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_WRITE_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);
    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen = clientioUserData->sndMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    uint8_t data[] = "Hello World";
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(client->ssl, data, sizeof(data), &writeLen), HITLS_CM_LINK_CLOSED);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CLOSE_NOTIFY_WRITE_FUNC_TC001
 * @spec
 * After the server sends the close_notify message, the write interface fails to be invoked.
 * @brief Either party MAY initiate a close of its write side of the connection by sending a "close_notify" alert. Any
 * data received after a closure alert has been received MUST be ignored.
 * 6.1.0. Alert Protocol row 213
 * @expect
 *  1.The server fails to invoke the write interface and send HITLS_CM_LINK_CLOSED
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CLOSE_NOTIFY_WRITE_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(server, client, false, TRY_SEND_CERTIFICATE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);
    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->sndMsg.msg;
    uint32_t serverreadLen = serverioUserData->sndMsg.len;
    uint32_t serverparseLen = 0;
    int32_t ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    uint8_t data[] = "Hello World";

    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(server->ssl, data, sizeof(data), &writeLen), HITLS_CM_LINK_CLOSED);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_RECV_CLOSE_NOTIFY_CLIENTHELLO_FUNC_TC001
 * @spec
 * The connection is established normally. After receiving the close_notify message, the server receives the clienthello
 * message. The message is ignored and the connection is interrupted.
 * @brief close_notify: This alert notifies the recipient that the sender will not send any more messages on this
 * connection. Any data received after a closure alert has been received MUST be ignored.
 * 6.1.0. Alert Protocol row 211
 * @expect
 *  1.The connection is interrupted and return HITLS_CM_LINK_FATAL_ALERTED
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_RECV_CLOSE_NOTIFY_CLIENTHELLO_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen = clientioUserData->sndMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->recMsg.msg;
    uint32_t serverreadLen = serverioUserData->recMsg.len;
    uint32_t serverparseLen = 0;
    ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
                serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(server->ssl != NULL);
    serverioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_IO_BUSY);
    serverioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_CM_LINK_FATAL_ALERTED);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    serverioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_CM_LINK_FATAL_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_HRR_FUNC_TC001
 * @spec
 *   The connection is established normally. After the client receives the close_notify message and the
 * helloRetryRequest message, the client ignores the message and disconnects from the connection.
 * @brief close_notify: This alert notifies the recipient that the sender will not send any more messages on this
 *   connection. Any data received after a closure alert has been received MUST be ignored.
 * 6.1.0. Alert Protocol row 211
 * @expect
 *  1.The connection is interrupted and return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_HRR_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    HITLS_CFG_SetGroups(config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_LEVEL_WARNING, &frameMsg.body.alertMsg.alertLevel) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_CLOSE_NOTIFY, &frameMsg.body.alertMsg.alertDescription) == HITLS_SUCCESS);
    uint8_t alertBuf[MAX_RECORD_LENTH] = {0};
    uint32_t alertLen = MAX_RECORD_LENTH;
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, alertBuf, alertLen, &alertLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, alertBuf, alertLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_CM_LINK_CLOSED);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_APP_FUNC_TC001
 * @spec
 * The connection is established normally. After the client receives the close_notify message and the app message, the
 * client ignores the message and disconnects the connection.
 * @brief close_notify: This alert notifies the recipient that the sender will not send any more messages on this
 * connection. Any data received after a closure alert has been received MUST be ignored.
 * 6.1.0. Alert Protocol row 211
 * @expect
 *  1.The connection is interrupted and return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_APP_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_LEVEL_WARNING, &frameMsg.body.alertMsg.alertLevel) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_CLOSE_NOTIFY, &frameMsg.body.alertMsg.alertDescription) == HITLS_SUCCESS);
    uint8_t alertBuf[MAX_RECORD_LENTH] = {0};
    uint32_t alertLen = MAX_RECORD_LENTH;
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, alertBuf, alertLen, &alertLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, alertBuf, alertLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC001
 * @spec
 *   When the connection is established, the server sends some error alarms and closes the write end of the connection.
 * The close_notify message is not sent.
 * @brief Each party MUST send a "close_notify" alert before closing its write side of the connection, unless it has
 *   already sent some error alert. This does not have any effect on its read side of the connection.
 * 6.1.0. Alert Protocol row 214
 * @expect
 *  1.The close_notify message is not sent.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    /* The client invokes the HITLS_Connect,
        and the handshake process is not complete.Check the status of the security connection.The status is
       CM_STATE_CALL. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_LEVEL_FATAL, &frameMsg.body.alertMsg.alertLevel) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_DECODE_ERROR, &frameMsg.body.alertMsg.alertDescription) == HITLS_SUCCESS);
    uint8_t alertBuf[MAX_RECORD_LENTH] = {0};
    uint32_t alertLen = MAX_RECORD_LENTH;
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, alertBuf, alertLen, &alertLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, alertBuf, alertLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);
    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_NE(alert.level, ALERT_LEVEL_WARNING);
    ASSERT_NE(alert.description, ALERT_CLOSE_NOTIFY);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC002
 * @spec
 *   If the connection is established normally, the client sends some error alarms and closes the write end of the
 *   connection. The close_notify message is not sent.
 * @brief Each party MUST send a "close_notify" alert before closing its write side of the connection, unless it has
 *   already sent some error alert. This does not have any effect on its read side of the connection.
 * 6.1.0. Alert Protocol row 214
 * @expect
 *  1.The close_notify message is not sent.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_LEVEL_FATAL, &frameMsg.body.alertMsg.alertLevel) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_ModifyMsgInteger(ALERT_DECODE_ERROR, &frameMsg.body.alertMsg.alertDescription) == HITLS_SUCCESS);
    uint8_t alertBuf[MAX_RECORD_LENTH] = {0};
    uint32_t alertLen = MAX_RECORD_LENTH;
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, alertBuf, alertLen, &alertLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, alertBuf, alertLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);
    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_NE(alert.level, ALERT_LEVEL_WARNING);
    ASSERT_NE(alert.description, ALERT_CLOSE_NOTIFY);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC003
 * @spec
 *   A connection is set up and the client is disconnected. Before the client receives a response, the client fails to
 * invoke the read interface. After receiving the close_notify message, the server suspends the write end and returns a
 * close_notify message to close the read end.
 * @brief Each party MUST send a "close_notify" alert before closing its write side of the connection, unless it has
 *   already sent some error alert. This does not have any effect on its read side of the connection.
 * 6.1.0. Alert Protocol row 214
 * @expect
 * @expect The server receives the close_notify message and responds to the close_notify message.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_CLOSED);

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_CM_LINK_CLOSED);
    ASSERT_EQ(server->ssl->shutdownState, HITLS_RECEIVED_SHUTDOWN);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC004
 * @spec
 *   A connection is set up and the server is disconnected. Before receiving a response, the server fails to invoke the
 * read interface. After receiving the close_notify message, the client suspends the write end and responds with the
 *   close_notify message to close the read end.
 * @brief Each party MUST send a "close_notify" alert before closing its write side of the connection, unless it has
 *   already sent some error alert. This does not have any effect on its read side of the connection.
 *   6.1.0. Alert Protocol row 214
 * @expect The client receives the close_notify message and responds to the close_notify message.
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CLOSE_NOTIFY_READ_FUNC_TC004(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
     ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_CLOSED);

    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_CM_LINK_CLOSED);
    ASSERT_EQ(client->ssl->shutdownState, HITLS_RECEIVED_SHUTDOWN);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

int32_t DefaultCfgStatusParkWithSuite_1_3(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    testInfo->config = HITLS_CFG_NewTLS13Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));
    testInfo->config->isSupportExtendedMasterSecret = testInfo->isSupportExtendedMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    return StatusPark(testInfo);
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC001
* @spec -
* @title During connection establishment, the server receives a message of the undefined record type after sending the
finished message. In this case, an alert message is returned.
* @precon nan
* @brief    1. Use the default configuration on the client and server, and disable the peer end verification function on
*              the server. Expected result 1 is obtained.
*           2. When the client initiates a TLS connection request in the RECV_Client_Hello message, construct an APP
message
*               and send it to the client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC001()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.version = HITLS_VERSION_TLS13;
    /* 1. Use the default configuration on the client and server, and disable the peer end verification function on
     *    the server. */
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(testInfo.server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_RECV_FINISH), HITLS_SUCCESS);
    /* 2. When the client initiates a TLS connection request in the RECV_Client_Hello message, construct an APP message
     *    and send it to the client. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    uint8_t appdata[] = {0xff, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(
        memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len), EOK);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC002
* @spec -
* @title After the connection is established, renegotiation is not enabled. The server receives the client hello message
and
*       is expected to return an alert message.
* @precon nan
* @brief    1. Use the default configuration on the client and server, and disable the peer end check function on the
*            server. Expected result 1 is obtained.
*           2. After the connection is set up, do not enable renegotiation and the server receives the client hello
message.
*             Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC002()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.version = HITLS_VERSION_TLS13;
    /* 1. Use the default configuration on the client and server, and disable the peer end check function on the
     *    server. */
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg,
                    MAX_RECORD_LENTH,
                    ioUserData->recMsg.msg + REC_TLS_RECORD_HEADER_LEN,
                    ioUserData->recMsg.len - REC_TLS_RECORD_HEADER_LEN) == EOK);
    sndMsg.len = ioUserData->recMsg.len - REC_TLS_RECORD_HEADER_LEN;
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    REC_Write(testInfo.client->ssl, REC_TYPE_HANDSHAKE, sndMsg.msg, sndMsg.len);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    /* 2. After the link is set up, do not enable renegotiation and the server receives the client hello message. */
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC003
* @spec -
* @title    After initialization is complete, construct an app message and send it to the server. The expected alert is
*            returned.
* @precon nan
* @brief    1. Use the default configuration on the client and server, and disable the peer end verification function on
*                the server. Expected result 1 is obtained.
*           2. When the client initiates a TLS connection application request, construct an APP message and send it to
the
*            server in the RECV_CLIENT_HELLO message on the server. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The server sends the ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC003(void)
{
    FRAME_Msg parsedAlert = {0};
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportClientVerify = false;
    /* 1. Use the default configuration on the client and server, and disable the peer end verification function on
     *    the server. */
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == 0);
    /* 2. When the client initiates a TLS connection application request, construct an APP message and send it to the
     *    server in the RECV_CLIENT_HELLO message on the server. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(
        memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len), EOK);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(sndBuf, sndLen, &parsedAlert, &parseLen) == HITLS_SUCCESS);

    ASSERT_EQ(parsedAlert.recType.data, REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNEXPECTED_MESSAGE);
EXIT:
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC004
* @spec -
* @title  After initialization, construct an app message and send it to the client. The expected alert is returned.
* @precon nan
* @brief    1. Use the default configuration on the client and server, and disable peer verification on the server.
*            Expected result 1 is obtained.
*           2. When the client initiates a TLS connection application request in the RECV_SERVER_HELLO message,
construct an
*            APP message and send it to the client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC004(void)
{
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportClientVerify = false;
    /* 1. Use the default configuration on the client and server, and disable peer verification on the server. */
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == 0);
    /* 2. When the client initiates a TLS connection application request in the RECV_SERVER_HELLO message, construct an
     *    APP message and send it to the client. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(
        memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len), EOK);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_EQ(frameMsg.recType.data, REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNEXPECTED_MESSAGE);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC005
* @spec -
* @title    After the connection is established, the client receives the serverhello message when receiving the app
data. The
*           client is expected to return an alert message.
* @precon nan
* @brief    1. Use the default configuration on the client and server, and disable peer verification on the server.
*            Expected result 1 is obtained.
*           2. The client initiates a TLS connection request. After the handshake succeeds, the server constructs a
*            serverhello message and sends it to the client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC005()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.version = HITLS_VERSION_TLS13;
    /* 1. Use the default configuration on the client and server, and disable peer verification on the server. */
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    /* 2. The client initiates a TLS connection request. After the handshake succeeds, the server constructs a
     *    serverhello message and sends it to the client. */
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg,
                    MAX_RECORD_LENTH,
                    ioUserData->recMsg.msg + REC_TLS_RECORD_HEADER_LEN,
                    ioUserData->recMsg.len - REC_TLS_RECORD_HEADER_LEN) == EOK);
    sndMsg.len = ioUserData->recMsg.len - REC_TLS_RECORD_HEADER_LEN;
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    REC_Write(testInfo.server->ssl, REC_TYPE_HANDSHAKE, sndMsg.msg, sndMsg.len);
    // Inject packets to the client.
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client), HITLS_SUCCESS);
    /* The server invokes HITLS_Read to receive data. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC006
* @spec -
* @title    After the connection is established, the client receives an unknown message when receiving app data and is
*            expected to return an alert message.
* @precon nan
* @brief    1. Use the default configuration on the client and server, and disable peer verification on the server.
*            Expected result 1 is displayed.
*           2. The client initiates a TLS connection request. After the handshake succeeds, the client constructs an
unknown
*            message and sends it to the client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC006()
{
    FRAME_Init();
    ResumeTestInfo testInfo = {0};
    /* 1. Use the default configuration on the client and server, and disable peer verification on the server. */
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    /* 2. The client initiates a TLS connection request. After the handshake succeeds, the client constructs an unknown
     *     message and sends it to the client. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    uint8_t appdata[] = {0xff, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(
        memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len), EOK);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */
#define BUF_TOOLONG_LEN ((1 << 14) + 1)

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC003
* @spec -
* @title    The client sends a Change Cipher Spec message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. When the client initiates a DTLS connection establishment request and sends a Change Cipher Spec message,
the
*            client modifies one field as follows: Length is 2 ^ 14 + 1. After the modification is complete, send the
*            modification to the server. Expected result 2 is obtained.
*            3. When the server receives the Change Cipher Spec message, check the value returned by the HITLS_Accept
*            interface. Expected result 3 is obtained.
* @expect   1. The initialization is successful.
*           2. The field is successfully modified and sent to the client.
*            3. The return value of the HITLS_Accept interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC003(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_FINISH;
    testInfo.isClient = false;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    /* 1. Use the default configuration items to configure the client and server. */
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == HITLS_SUCCESS);

    ASSERT_EQ(
        FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, TRY_RECV_FINISH), HITLS_SUCCESS);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    /* 2. When the client initiates a DTLS connection establishment request and sends a Change Cipher Spec message, the
     *    client modifies one field as follows: Length is 2 ^ 14 + 1. After the modification is complete, send the
     *    modification to the server. */
    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg.body.ccsMsg.extra.data);
    frameMsg.body.ccsMsg.extra.data = certDataTemp;
    frameMsg.body.ccsMsg.extra.size = BUF_TOOLONG_LEN;
    frameMsg.body.ccsMsg.extra.state = ASSIGNED_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    /* 3. When the server receives the Change Cipher Spec message, check the value returned by the HITLS_Accept
     *    interface. */
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_TRUE(testInfo.server->ssl->hsCtx->state == TRY_RECV_FINISH);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC004
* @spec -
* @title    The client sends a Change Cipher Spec message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and client. Expected result 1 is obtained.
*           2. When the client initiates a DTLS connection establishment request and sends a Change Cipher Spec message,
the client modifies one field as follows: Length is 2 ^ 14 + 1. After the modification is complete, send the
            modification to the client. Expected result 2 is obtained.
            3. When the client receives the Change Cipher Spec message, check the value returned by the HITLS_Accept
            interface. Expected result 3 is obtained.
* @expect   1. The initialization is successful.
*           2. The field is successfully modified and sent to the client.
            3. The return value of the HITLS_Accept interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC004(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_FINISH;
    testInfo.isClient = true;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    /* 1. Use the default configuration items to configure the client and server. */
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == HITLS_SUCCESS);

    ASSERT_EQ(
        FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, TRY_RECV_FINISH), HITLS_SUCCESS);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    /* 2. When the client initiates a DTLS connection establishment request and sends a Change Cipher Spec message, the
     *    client modifies one field as follows: Length is 2 ^ 14 + 1. After the modification is complete, send the
     *    modification to the server. */
    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg.body.ccsMsg.extra.data);
    frameMsg.body.ccsMsg.extra.data = certDataTemp;
    frameMsg.body.ccsMsg.extra.size = BUF_TOOLONG_LEN;
    frameMsg.body.ccsMsg.extra.state = ASSIGNED_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    /* 3. When the client receives the Change Cipher Spec message, check the value returned by the HITLS_Accept
     *    interface. */
    ASSERT_EQ(HITLS_Accept(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_TRUE(testInfo.client->ssl->hsCtx->state == TRY_RECV_FINISH);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC001
* @spec -
* @titleThe client sends a clienthello message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. When the client initiates a DTLS connection creation request, the client needs to send a client hello
message,
*            modify the following field as follows: Length is 2 ^ 14 + 1. After the modification, the modification is
*            sent to the server. Expected result 2 is obtained.
*            3. When the server receives the client hello message, check the value returned by the HITLS_Accept
*            interface. Expected result 3 is obtained.
* @expect   1. The initialization is successful.
*           2. The field is successfully modified and sent to the client.
*            3. The return value of the HITLS_Accept interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isClient = false;
    /* 1. Use the default configuration items to configure the client and server. */
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    /* 2. When the client initiates a DTLS connection creation request, the client needs to send a client hello message,
     *    modify the following field as follows: Length is 2 ^ 14 + 1. After the modification, the modification is
     *     sent to the server. */
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientHello.sessionId.data);
    clientMsg->sessionId.state = ASSIGNED_FIELD;
    clientMsg->sessionId.size = BUF_TOOLONG_LEN;
    clientMsg->sessionId.data = certDataTemp;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    /* 3. When the server receives the client hello message, check the value returned by the HITLS_Accept
     *    interface. */
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_RECORD_OVERFLOW);

    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_RECORD_OVERFLOW);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC002
* @spec -
* @title Verify that the client receives a serverhello message with the length of 2 ^ 14 + 1. The client is expected to
*       return an alert message.
* @precon nan
* @brief    1. Create a config and server connection, and construct a server hello message with the length of 2 ^ 14
+ 1.
*            Expected result 1 is obtained.
*            2. The client invokes the HITLS_Connect interface. (Expected result 2)
* @expect   1. A success message is returned.
*            2. A failure message is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    /* 1. Create a config and server connection, and construct a server hello message with the length of 2 ^ 14 + 1. */
    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.serverHello.randomValue.data);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;

    serverMsg->randomValue.state = ASSIGNED_FIELD;
    serverMsg->randomValue.size = BUF_TOOLONG_LEN;
    serverMsg->randomValue.data = certDataTemp;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    /* 2. The client invokes the HITLS_Connect interface. */
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_RECORD_OVERFLOW);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_RECORD_OVERFLOW);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

int32_t STUB_HS_DoHandshake_Fatal(TLS_Ctx *ctx)
{
    ctx->method.sendAlert(ctx, ALERT_LEVEL_WARNING, ALERT_UNEXPECTED_MESSAGE); /* sends a fatal alert message.*/
    return HITLS_INTERNAL_EXCEPTION;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ALERT_DESCRIPTION_FUNC_TC001
* @spec All the alerts listed in Section 6.2 MUST be sent with AlertLevel=fatal and MUST be treated as error alerts
*       when received regardless of the AlertLevel in the message.
*       Unknown Alert types MUST be treated as error alerts.
* @title If the AlertLevel field in the alarm message received by the client is non-critical but the alarm type is
*        critical, the client immediately closes the connection.
* @precon nan
* @brief    6. Alert Protocol row208
*           If the AlertLevel field in the alarm message received by the client is not critical but the alarm type is
*            critical, the connection is closed immediately.
* @expect The connection is set up normally.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ALERT_DESCRIPTION_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLSConfig();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig, 0x00000030U);
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
    server->ssl->recCtx->outBuf->end = 0;
    STUB_REPLACE(HS_DoHandshake, STUB_HS_DoHandshake_Fatal);;
    int32_t ret = HITLS_Accept(server->ssl);
    ASSERT_EQ(ret, HITLS_REC_NORMAL_IO_BUSY);
    STUB_RESTORE(HS_DoHandshake);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ALERT_DESCRIPTION_FUNC_TC002
*  All alerts listed in section 6.2 of the specification must be sent with AlertLevel=Fatal and must be treated as
*    false alerts When received regardless of the AlertLevel in the message.
*   Unknown alert types must be treated as false alerts.
* @title In the alarm message received by the server, if the value of AlertLevel is not critical but the alarm type is
*        critical, the connection is closed immediately.
* @preconan
* @short    6. Alert protocol line 208
*           In the alarm message received by the server, if the value of AlertLevel is not critical but the alarm type
*            is critical, the connection is closed immediately.
* @expect    forward to normal connection establishment
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ALERT_DESCRIPTION_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLSConfig();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    HITLS_CFG_SetVersionSupport(tlsConfig, 0x00000030U);
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

    client->ssl->recCtx->outBuf->end = 0;
    STUB_REPLACE(HS_DoHandshake, STUB_HS_DoHandshake_Fatal);;
    int32_t ret = HITLS_Connect(client->ssl);
    ASSERT_EQ(ret, HITLS_REC_NORMAL_IO_BUSY);
    STUB_RESTORE(HS_DoHandshake);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_ERROR_ENUM_FUNC_TC001
* @spec  Peers which receive a message which is syntactically correct but semantically invalid
*        (e.g., a DHE share of p - 1, or an invalid enum) MUST terminate the connection with
*        an "illegal_parameter" alert.
* @title  When the client receives a server keyexchange message in which the value of type is invalid, the client
*            generates an illegal_parameter alarm and the handshake fails.
* @precon  nan
* @brief  6. Alert Protocol    row210
*         When the client receives a server keyexchange message in which the value of type is invalid, the client
*            generates an illegal_parameter alarm and the handshake fails.
* @expect  Sending an alarm
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ERROR_ENUM_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    tlsConfig->isSupportClientVerify = true;
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, SERVER_KEY_EXCHANGE, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    sendBuf[9] = 0x04;

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);

    ASSERT_EQ(HITLS_Accept(clientTlsCtx), HITLS_PARSE_UNSUPPORT_KX_CURVE_TYPE);
    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_NE(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_NE(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC001
* @spec  -
* @title  To verify that the server receives a 0-length client hello and is expected to return an alarm.
* @precon  nan
* @brief  1.Create a config and client connection, and construct a 0-length client hello. Expected result 1 is
displayed.
*         2.The client invokes the HITLS_Connect interface. Expected result 2 is obtained.
* @expect 1. Return success
*         2.Return failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == HITLS_SUCCESS);

    /* Obtain the message buffer */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    recvBuf[6] = 00;
    recvBuf[7] = 00;
    recvBuf[8] = 00;
    recvLen = 6;

    /* Invoke the test interface. Expected success in receiving and processing, and send Alert. */
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_PARSE_INVALID_MSG_LEN);

    /* Obtain the message buffer. */
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    /* Parse to msg structure */
    uint32_t parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Determine whether it is consistent with the expectation. */
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_DECODE_ERROR);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC002
* @spec  -
* @title  To verify that the client receives a 0-length server hello and returns an alert message.
* @precon  nan
* @brief  1.Create a config and server connection, and construct a 0-length server hello. Expected result 1 is
displayed. 2.The client invokes the HITLS_Connect interface. Expected result 2 is obtained.
* @expect 1.Return success
          2.Return failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite_1_3(&testInfo) == HITLS_SUCCESS);

    /* Obtain the message buffer. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    recvBuf[6] = 00;
    recvBuf[7] = 00;
    recvBuf[8] = 00;
    recvLen = 6;

    /* Invoke the test interface. Expected success in receiving and processing, and send Alert. */
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_INVALID_MSG_LEN);

    /* Obtain the message buffer. */
    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    /* Parse to msg structure */
    uint32_t parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Determine whether it is consistent with the expectation. */
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_DECODE_ERROR);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */