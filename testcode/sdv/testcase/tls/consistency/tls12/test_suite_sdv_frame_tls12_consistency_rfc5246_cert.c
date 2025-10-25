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
/* INCLUDE_BASE test_suite_tls12_consistency_rfc5246 */

#include <stdio.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "cert.h"
#include "securec.h"
#include "frame_msg.h"
#include "alert.h"
#include "bsl_list.h"
#include "app_ctx.h"
#include "hs_kx.c"
#include "common_func.h"
#include "stub_crypt.h"
#include "stub_utils.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET6(int32_t, SAL_CERT_KeyDecrypt, HITLS_Ctx *, HITLS_CERT_Key *, const uint8_t *, uint32_t, uint8_t *, uint32_t *);
STUB_DEFINE_RET7(int32_t, SAL_CRYPT_CalcEcdhSharedSecret, HITLS_Lib_Ctx *, const char *, HITLS_CRYPT_Key *, uint8_t *, uint32_t, uint8_t *, uint32_t *);

#define g_uiPort 45678

#define PREMASTERSECRETLEN 1534

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_SEND_CERTFICATE_TC001 rfc 5246 table row 51
* @title  If the server has sent a CertificateRequest message, the client must send a certificate message.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server, and enable the dual-end verification. Expected result 1 is obtained.
*         2. The client initiates a TLS over TCP link request. After the server receives the CertificateRequest message, expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client is in the TRY_SEND_CLIENT_KEY_EXCHANGE state, and the server is in the TRY_RECV_CERTIFICATIONATE state.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_SEND_CERTFICATE_TC001(void)
{
    /* Use the default configuration items to configure the client and server, and enable the dual-end verification. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_SEND_SERVER_HELLO_DONE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO_DONE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);

    // The client initiates a TLS over TCP link request.
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(testInfo.client->ssl->hsCtx->state, TRY_SEND_CLIENT_KEY_EXCHANGE);

    uint32_t readLen = 0;
    uint8_t tmp1[MAX_RECORD_LENTH] = {0};
    uint32_t tmp1Len = sizeof(tmp1);
    ASSERT_TRUE(FRAME_TransportSendMsg(testInfo.client->io, tmp1, tmp1Len, &readLen) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t tmp2[MAX_RECORD_LENTH] = {0};
    uint32_t tmp2Len = sizeof(tmp2);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, tmp2, tmp2Len) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.server->ssl->hsCtx->state == TRY_RECV_CERTIFICATE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC002
* @title During dual-end verification, the server signature algorithm does not match the certificate signature algorithm. As a result, the link fails to be established.
* @precon nan
* @brief    1. Configure dual-end verification. Set the signature algorithm to RSA_PKCS1_SHA256, cipher suite to RSA, certificate to RSA, and certificate signature to ECDSA_SHA256 on the server. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    // 1. Configure dual-end verification. Set the signature algorithm to RSA_PKCS1_SHA256, cipher suite to RSA, certificate to RSA, and certificate signature to ECDSA_SHA256 on the server.
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    uint32_t signAlgsSize = sizeof(signAlgs) / sizeof(uint16_t);
    HITLS_CFG_SetSignature(config, signAlgs, signAlgsSize);
    HITLS_CFG_SetClientVerifySupport(config, true);
    uint16_t cipherSuites[] = {HITLS_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    FRAME_CertInfo certInfoServer = {
        "ecdsa/ca-nist521.der",
        "rsa_sha/inter-3072.der",
        "rsa_sha/end-sha256.der",
        0,
        "rsa_sha/end-sha256.key.der",
        0,
    };
    FRAME_CertInfo certInfoClient = {
        "rsa_sha/ca-3072.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);


    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC003
* @title During dual-end verification, the intermediate certificate is incorrectly configured on the client. As a result, the verification on the server fails.
* @precon nan
* @brief    1. Configure dual-ended authentication. Configure a correct terminal certificate and an incorrect intermediate certificate on the client. Configure a correct certificate chain on the server. Check whether the server fails the authentication. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    // 1. Configure dual-ended authentication. Configure a correct terminal certificate and an incorrect intermediate certificate on the client. Configure a correct certificate chain on the server. Check whether the server fails the authentication.
    FRAME_CertInfo certInfoClient = {
        "ecdsa/ca-nist521.der",
        "rsa_sha/inter-3072.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_SIGNATION_FAIL_TC001
* @title Link setup failed because the signature algorithm does not match.
* @precon nan
* @brief    1. Set the client signature algorithm to ECDSA_SECP256R1_SHA256 and the server certificate signature algorithm to RSA_SHA256. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_SIGNATION_FAIL_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    uint32_t signAlgsSize = sizeof(signAlgs) / sizeof(uint16_t);
    FRAME_CertInfo certInfo = {
        "rsa_sha/ca-3072.der:rsa_sha/inter-3072.der",
        "rsa_sha/inter-3072.der",
        "rsa_sha/end-sha256.der",
        0,
        "rsa_sha/end-sha256.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);
    // 1. Set the client signature algorithm to ECDSA_SECP256R1_SHA256 and the server certificate signature algorithm to RSA_SHA256.
    ASSERT_TRUE(HITLS_SetSigalgsList(client->ssl, signAlgs, signAlgsSize) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC001
* @title The certificate signature algorithm does not match the signature algorithm set on the client. As a result, the link fails to be established.
* @precon nan
* @brief    1. Set the signature algorithm to RSA_PKCS1_SHA256 on the client, cipher suite to RSA, certificate to RSA,
                server signature algorithm to RSA_PKCS1_SHA256, and certificate signature algorithm to ECDSA_SHA256.
                Expected Certificate Verification Failure (Failed to Select a Certificate on the Server)
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SIGNATION_NOT_SUITABLE_CERT_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    // 1. Set the signature algorithm to RSA_PKCS1_SHA256 on the client, cipher suite to RSA, certificate to RSA,
    //     server signature algorithm to RSA_PKCS1_SHA256, and certificate signature algorithm to ECDSA_SHA256.
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    uint32_t signAlgsSize = sizeof(signAlgs) / sizeof(uint16_t);
    HITLS_CFG_SetSignature(config, signAlgs, signAlgsSize);
    HITLS_CFG_SetClientVerifySupport(config, true);
    uint16_t cipherSuites[] = {HITLS_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    FRAME_CertInfo certInfoClient = {
        "ecdsa/ca-nist521.der",
        "rsa_sha/inter-3072.der",
        "rsa_sha/end-sha256.der",
        0,
        "rsa_sha/end-sha256.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha/ca-3072.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC004
* @title During dual-end authentication, the client certificate is out of order, and the link fails to be established.
* @precon nan
* @brief    1. Configure dual-end verification. Configure the first certificate on the client as an intermediate
                certificate and the second certificate as a terminal certificate. Configure a correct certificate chain
                on the server. Check whether the verification fails on the server. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    // Change the certificate sequence. The intermediate certificate is used first, and then the device certificate is used.
    // 1. Configure dual-end authentication. Configure the first certificate on the client as an intermediate
    // certificate, and the second certificate as a terminal certificate. Configure a correct certificate chain on the server.
    frameMsg.body.hsMsg.body.certificate.certItem->cert.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.certificate.certItem->certLen.state = ASSIGNED_FIELD;
    struct FrameCertItem_ *tmp = frameMsg.body.hsMsg.body.certificate.certItem->next;
    frameMsg.body.hsMsg.body.certificate.certItem->next = tmp->next; // a->c
    tmp->next = frameMsg.body.hsMsg.body.certificate.certItem; // b -> a
    frameMsg.body.hsMsg.body.certificate.certItem = tmp;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_PARSE_VERIFY_SIGN_FAIL);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


static int32_t STUB_SAL_CERT_KeyDecrypt_Fail(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    (void)key;
    (void)in;
    (void)inLen;
    (void)out;
    (void)outLen;
    return HITLS_CRYPT_ERR_DECRYPT;
}

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_DECRYPT_FAIL_TC005
* @title After the premasterkey to be received by the server is modified, the connection fails to be established.
* @precon nan
* @brief    1. Configure the RSA cipher suite. When the server receives the premasterkey, change the value of the
            premasterkey and construct a decryption failure scenario. It is expected that CCS messages are sent normally
            and the link fails to be established. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_DECRYPT_FAIL_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    // 1.Configure the RSA cipher suite. Change the value of the premasterkey when the server receives the premasterkey.
    // Construct a decryption failure scenario. The CCS message is expected to be sent normally.
    uint16_t cipherSuits[] = {HITLS_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    STUB_REPLACE(SAL_CERT_KeyDecrypt, STUB_SAL_CERT_KeyDecrypt_Fail);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    STUB_RESTORE(SAL_CERT_KeyDecrypt);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);

EXIT:

    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC003
* @title The certificate carries the correct keyuage extension, and the link is successfully established.
* @precon nan
* @brief    1. Configure the server certificate with the keyuage extension and support digitalSignature. The link is successfully established. Expected result 1 is obtained.
* @expect   1. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, true);
    // 1. Set the server certificate with the keyuage extension and support digitalSignature.
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_UNSUPPORTED_TC001
* @title Invoke the hitls_connect/hitls_accept interface to initiate renegotiation. The peer end does not support renegotiation.
* @precon nan
* @brief    1. Invoke the hitls_renegotiate interface to initiate renegotiation. Expected result 1 is obtained.
            2. Invoke the hitls_connect/hitls_accept interface to initiate renegotiation. The peer end does not support renegotiation. Expected result 2 is obtained.
* @expect   1. The link enters the renegotiation state.
            2. The peer end returns a warning alert.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_UNSUPPORTED_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    HITLS_SetRenegotiationSupport(client->ssl, true);

    // 1. Invoke the hitls_renegotiate interface to initiate renegotiation.
    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    // Invoke the hitls_connect/hitls_accept interface to initiate renegotiation. The peer end does not support renegotiation.
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(client->ssl->state, CM_STATE_RENEGOTIATION);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    // Send a warning alert and ALERT_NO_RENEGOTIATION message. After receiving the message, the peer send fatal alert.
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* ============================================================================
 * Stub implementation for ECDHE-PSK bounds checking test
 * ============================================================================ */
static int32_t Stub_SAL_CRYPT_CalcEcdhSharedSecret(
    HITLS_Lib_Ctx *libCtx,
    const char *attrName,
    HITLS_CRYPT_Key *key,
    uint8_t *peerPubkey,
    uint32_t pubKeyLen,
    uint8_t *sharedSecret,
    uint32_t *sharedSecretLen)
{
    // Get the real function pointer using the auto-generated helper
    real_SAL_CRYPT_CalcEcdhSharedSecret_func_t real_func = get_real_SAL_CRYPT_CalcEcdhSharedSecret();

    if (real_func == NULL) {
        return HITLS_CRYPT_ERR_CALC_SHARED_KEY;
    }

    // Call the real function to get valid shared secret
    int32_t ret = real_func(libCtx, attrName, key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);

    if (ret == HITLS_SUCCESS) {
        // Modify the length to maximum value (1534) to test bounds checking
        // This tests the edge case where premaster secret length is at maximum
        *sharedSecretLen = PREMASTERSECRETLEN;
    }

    return ret;
}

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_ECDHE_PSK_TC001
* @title Test ECDHE-PSK with maximum premaster secret length for bounds checking
* @precon nan
* @brief    1. Configure the PSK cipher suite. When generating the premasterkey, stub SAL_CRYPT_CalcEcdhSharedSecret
            to set sharedSecretLen to 1534 (maximum value) to test bounds checking in PSK key derivation.
* @expect   1. The connection succeeds with proper bounds handling.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_ECDHE_PSK_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t cipherSuits[] = {HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA};
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t)) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskClientCallback(config, ExampleClientCb) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskServerCallback(config, ExampleServerCb) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    STUB_REPLACE(SAL_CRYPT_CalcEcdhSharedSecret, Stub_SAL_CRYPT_CalcEcdhSharedSecret);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    STUB_RESTORE(SAL_CRYPT_CalcEcdhSharedSecret);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_RSA_REMASTER_TC001
* @title After the premasterkey to be received by the server is modified, the connection fails to be established.
* @precon nan
* @brief    1. Configure the RSA cipher suite. When the server receives the premasterkey, change the value of the
            premasterkey and construct a decryption failure scenario. It is expected that CCS messages are sent normally
            and the link fails to be established. Expected result 1 is obtained.
* @expect   1. The link fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_RSA_REMASTER_TC001(int rsaEncryptLen)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_CFG_SetClientVerifySupport(config, false);
    // 1.Configure the RSA cipher suite. Change the value of the premasterkey when the server receives the premasterkey.
    // Construct a decryption failure scenario. The CCS message is expected to be sent normally.
    uint16_t cipherSuits[] = {HITLS_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_RSA;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    frameMsg.body.hsMsg.body.clientKeyExchange.pubKeySize.data = rsaEncryptLen;
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.data);
    frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.data = BSL_SAL_Calloc(1,rsaEncryptLen);
    frameMsg.body.hsMsg.body.clientKeyExchange.pubKey.size = rsaEncryptLen;

    uint32_t sendLen = MAX_RECORD_LENTH;
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, recvBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = sendLen;
    HITLS_Accept(server->ssl);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC004
* @title The certificate without keyuage extension, and the link is successfully established.
* @precon nan
* @brief    1. Configure the server certificate without keyuage extension and support CheckKeyUsage. The link is successfully established. Expected result 1 is obtained.
* @expect   1. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_KEYUSAGE_CERT_TC004(int isCheckKeyUsage)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t cipherSuits[] = {HITLS_RSA_WITH_AES_128_CBC_SHA256};
    ASSERT_TRUE(
        HITLS_CFG_SetCipherSuites(config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t)) == HITLS_SUCCESS);
    HITLS_CFG_SetClientVerifySupport(config, true);

    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);
    if (isCheckKeyUsage) {
        HITLS_SetCheckKeyUsage(client->ssl, true);
    } else {
        HITLS_SetCheckKeyUsage(client->ssl, false);
    }
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_EXTRA_CHAIN_CERT_TC001
* @title Set the intermediate certificates separately to the extra_chain and the chain, where the correct intermediate
    certificate is stored in the extra_chain and the incorrect intermediate certificate is stored in the chain, proving
    that the priority of the chain is higher than that of extra_chain.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. Analyze valid and invalid intermediate certificates separately. Expected result 2 is obtained.
3. Set valid intermediate certificates to extra_chain and invalid intermediate certificates to chain. Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. The parsing was successful.
3. Successfully set up.
4. establish the link failed, returned HITLS_CERT_ERR_VERIFY_CERT_CHAIN, proving that the priority of the chain is higher than extra_chain.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_EXTRA_CHAIN_CERT_TC001()
{
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetVerifyNoneSupport(config_c, false);
    char invalidIntCaFile[] = "../testdata/tls/certificate/der/ecdsa_sha256/inter.der";
    char validIntCaFile[] = "../testdata/tls/certificate/der/rsa_sha256/inter.der";

    HITLS_CERT_X509 *invalidIntCa = HITLS_CFG_ParseCert(config_s, (const uint8_t *)invalidIntCaFile,
        strlen(invalidIntCaFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    HITLS_CERT_X509 *validIntCa = HITLS_CFG_ParseCert(config_s, (const uint8_t *)validIntCaFile,
        strlen(validIntCaFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(invalidIntCa != NULL);
    ASSERT_TRUE(validIntCa != NULL);

    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_CFG_AddChainCert(&server->ssl->config.tlsConfig, invalidIntCa, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_AddExtraChainCert(&server->ssl->config.tlsConfig, validIntCa) == HITLS_SUCCESS);
    HITLS_CERT_Chain *extraChainCert = HITLS_CFG_GetExtraChainCerts(&server->ssl->config.tlsConfig);
    ASSERT_TRUE(extraChainCert->count == 1);
    ASSERT_TRUE(extraChainCert != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_EXTRA_CHAIN_CERT_TC002
* @title Set the intermediate certificates separately to the extra_chain and store, where the correct intermediate
    certificate is stored in the extra_chain and the incorrect intermediate certificate is stored in the store, proving
    that the priority of extra_chain is higher than that of the store.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. Analyze valid and invalid intermediate certificates separately  Expected result 2 is obtained.
3. Set valid intermediate certificates to extra_chain and invalid intermediate certificates to store. Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. The parsing was successful.
3. Successfully set up.
4. The link is set up successfullyl, returns HITLS_SUCCESS, proving that extra_chain has a higher priority than store.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_EXTRA_CHAIN_CERT_TC002()
{
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetVerifyNoneSupport(config_c, false);
    char validIntCaFile[] = "../testdata/tls/certificate/der/rsa_sha256/inter.der";
    HITLS_CERT_X509 *validIntCa = HITLS_CFG_ParseCert(config_s, (const uint8_t *)validIntCaFile,
        strlen(validIntCaFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(validIntCa != NULL);

    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        "ecdsa_sha256/inter.der",
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_CFG_AddExtraChainCert(&server->ssl->config.tlsConfig, validIntCa) == HITLS_SUCCESS);
    HITLS_CERT_Chain *extraChainCert = HITLS_CFG_GetExtraChainCerts(&server->ssl->config.tlsConfig);
    ASSERT_TRUE(extraChainCert->count == 1);
    ASSERT_TRUE(extraChainCert != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC001
* @title
* @precon Set up a certificate chain from the chain, but there is no certificate in the chain chain. There is a
    certificate in the store, and it is expected that the connection will be successfully established.
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. Load the intermediate certificate into the store. Expected result 2 is obtained.
3. Call the HITLS_CFG_BuildCertChain function to group the certificate chain, set the flag to HITLS_SBILD_CHAIN_LAGCHECK
    . Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. Successfully set up.
3. Return success.
4. The link is set up successfullyl, returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC001()
{
#ifdef HITLS_TLS_CONFIG_CERT_BUILD_CHAIN
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetVerifyNoneSupport(config_c, false);

    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_CFG_BuildCertChain(&server->ssl->config.tlsConfig, HITLS_BUILD_CHAIN_FLAG_CHECK) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC002
* @title Set up a certificate chain from the store, but there is no certificate in the store. There is a certificate in
    the chain, and it is expected that the chain will be empty after the chain is formed, resulting in a connection failure.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. Set the intermediate certificate to the chain, but there are no certificates in the Cert_store and Chain_store.
    Expected result 2 is obtained.
3. Call HITLS_CFG_BuildCertChain to group the certificate chain and set the flag to 0. Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. Successfully set up.
3. Return success.
4. Failed to establish connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC002()
{
#ifdef HITLS_TLS_CONFIG_CERT_BUILD_CHAIN
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetVerifyNoneSupport(config_c, false);

    char rootCaFile[] = "../testdata/tls/certificate/der/rsa_sha256/ca.der";
    char intCaFile[] = "../testdata/tls/certificate/der/rsa_sha256/inter.der";
    HITLS_CERT_X509 *rootCa = HITLS_CFG_ParseCert(config_s, (const uint8_t *)rootCaFile,
        strlen(rootCaFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(rootCa != NULL);
    HITLS_CERT_X509 *intCa = HITLS_CFG_ParseCert(config_s, (const uint8_t *)intCaFile,
        strlen(intCaFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(intCa != NULL);

    HITLS_CERT_Store *store = SAL_CERT_StoreNew(config_s->certMgrCtx);
    ASSERT_TRUE(store != NULL);

    SAL_CERT_StoreCtrl(config_s, store, CERT_STORE_CTRL_ADD_CERT_LIST, rootCa, NULL);
    HITLS_CFG_SetVerifyStore(config_s, store, 0);

    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        0,
        0,
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_CFG_AddChainCert(&server->ssl->config.tlsConfig, intCa, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_BuildCertChain(&server->ssl->config.tlsConfig, 0) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC003
* @title Set up a certificate chain from the chain, where there are multiple certificates and unrelated certificates.
    It is expected that after the chain is formed, only the certificates that make up the certificate chain will be
    present, and the connection will be successfully established.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. Load 2 different intermediate certificates into the chain, and there is only 1 available intermediate certificate.
    Expected result 2 is obtained.
3. Call the HITLS_CFG_BuildCertChain function to group the certificate chain, set the flag to HITLS_SBILD_CHAIN_LAGCHECK
    , Obtain the number of certificates in the chain after the chain is formed. Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. The parsing was successful.
3. Obtaining only one certificate in the chain.
4. The link is set up successfullyl, returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC003()
{
#ifdef HITLS_TLS_CONFIG_CERT_BUILD_CHAIN
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetVerifyNoneSupport(config_c, false);

    char intCaFile1[] = "../testdata/tls/certificate/der/rsa_sha256/inter.der";
    HITLS_CERT_X509 *intCa1 = HITLS_CFG_ParseCert(config_s, (const uint8_t *)intCaFile1,
        strlen(intCaFile1) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(intCa1 != NULL);
    char intCaFile2[] = "../testdata/tls/certificate/der/ecdsa_sha256/inter.der";
    HITLS_CERT_X509 *intCa2 = HITLS_CFG_ParseCert(config_s, (const uint8_t *)intCaFile2,
        strlen(intCaFile2) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(intCa2 != NULL);

    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_CFG_AddChainCert(&server->ssl->config.tlsConfig, intCa1, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_AddChainCert(&server->ssl->config.tlsConfig, intCa2, false) == HITLS_SUCCESS);
    HITLS_CERT_Chain *chainCertList = HITLS_CFG_GetChainCerts(&server->ssl->config.tlsConfig);
    ASSERT_EQ(BSL_LIST_COUNT(chainCertList), 2);
    ASSERT_TRUE(HITLS_CFG_BuildCertChain(&server->ssl->config.tlsConfig, HITLS_BUILD_CHAIN_FLAG_CHECK) == HITLS_SUCCESS);
    chainCertList = HITLS_CFG_GetChainCerts(&server->ssl->config.tlsConfig);
    ASSERT_EQ(BSL_LIST_COUNT(chainCertList), 1);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */

/** @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC004
* @title Set the flag to HITLS_BUILD_CHAIN_FLAG_NO_ROOT, and set both the intermediate certificate and the root
* certificate to the certificate store. It is expected that the root certificate will not appear in the certificate
* chain after the completion of the chain assembly.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. Load the root certificate and intermediate certificate into CertStore. Expected result 2 is obtained.
3. Call the HITLS_BuildCertChain function to group the certificate chain, set the flag to HITLS_BUILD_CHAIN_FLAG_NO_ROOT
    , Obtain the number of certificates in the chain after the chain is formed. Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. The parsing was successful.
3. Obtaining only one certificate in the chain.
4. The link is set up successfully, returns HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_BUILD_CERT_CHAIN_TC004()
{
#ifdef HITLS_TLS_CONFIG_CERT_BUILD_CHAIN
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetVerifyNoneSupport(config_c, false);

    char intCaFile[] = "../testdata/tls/certificate/der/rsa_sha256/inter.der";
    HITLS_CERT_X509 *intCa = HITLS_CFG_ParseCert(config_s, (const uint8_t *)intCaFile,
        strlen(intCaFile) + 1, TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(intCa != NULL);

    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        0,
        "rsa_sha256/server.der",
        0,
        "rsa_sha256/server.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    HITLS_CERT_Store *store = HITLS_CFG_GetCertStore(&server->ssl->config.tlsConfig);
    ASSERT_TRUE(store != NULL);

    SAL_CERT_StoreCtrl(&server->ssl->config.tlsConfig, store, CERT_STORE_CTRL_ADD_CERT_LIST, intCa, NULL);

    ASSERT_TRUE(HITLS_BuildCertChain(server->ssl, HITLS_BUILD_CHAIN_FLAG_NO_ROOT) == HITLS_SUCCESS);
    HITLS_CERT_Chain *chainCertList = HITLS_CFG_GetChainCerts(&server->ssl->config.tlsConfig);
    ASSERT_EQ(BSL_LIST_COUNT(chainCertList), 1);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */

/**
 * @test UT_TLS_TLS12_RFC5246_CONSISTENCY_VERIFY_CHAIN_TC001
 * @title Verify the certificate chain in three ways: from a file, from a directory, and from a single CA certificate.
 * @precon nan
 * @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
 *           2. Load the certificate chain from a file. Expected result 2 is obtained.
 *           3. Continue to establish the link. Expected result 3 is obtained.
 * @expect 1. The initialization is successful.
 *         2. The parsing was successful.
 *         3. The link is set up successfully, returns HITLS_SUCCESS.
 */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_VERIFY_CHAIN_TC001()
{
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetClientVerifySupport(config_s, true);
    FRAME_CertInfo certInfoClient = {
        "rsa_sha256/ca.der", 0, 0, 0, 0, 0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    const char *path = "../testdata/tls/certificate/pem/rsa_sha256/cert_chain.pem";
    int32_t ret = HITLS_CFG_UseCertificateChainFile(config_c, path);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    const char *keyPath = "../testdata/tls/certificate/pem/rsa_sha256/client.key.pem";
    HITLS_CFG_LoadKeyFile(config_c, keyPath, TLS_PARSE_FORMAT_PEM);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test UT_TLS_TLS12_RFC5246_CONSISTENCY_VERIFY_CHAIN_TC002
 * @title Verify the certificate chain in three ways: from a file, from a directory, and from a single CA certificate.
 * @precon nan
 * @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
 *           2. Load the certificate chain from a directory. Expected result 2 is obtained.
 *           3. Continue to establish the link. Expected result 3 is obtained.
 * @expect 1. The initialization is successful.
 *         2. The parsing was successful.
 *         3. The link is set up successfully, returns HITLS_SUCCESS.
 */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_VERIFY_CHAIN_TC002()
{
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetClientVerifySupport(config_s, true);
    FRAME_CertInfo certInfoClient = {
        0,
        0,
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    const char *path = "../testdata/tls/certificate/pem/rsa_sha256";
    int32_t ret = HITLS_CFG_LoadVerifyDir(config_c, path);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test UT_TLS_TLS12_RFC5246_CONSISTENCY_VERIFY_CHAIN_TC003
 * @title Verify the certificate chain in three ways: from a file, from a directory, and from a single CA certificate.
 * @precon nan
 * @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
 *           2. Load the certificate chain from a single CA certificate. Expected result 2 is obtained.
 *           3. Continue to establish the link. Expected result 3 is obtained.
 * @expect 1. The initialization is successful.
 *         2. The parsing was successful.
 *         3. The link is set up successfully, returns HITLS_SUCCESS.
 */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_VERIFY_CHAIN_TC003()
{
    FRAME_Init();

    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_s != NULL);
    HITLS_CFG_SetClientVerifySupport(config_s, true);
    FRAME_CertInfo certInfoClient = {
        0,
        "rsa_sha256/inter.der",
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    FRAME_CertInfo certInfoServer = {
        "rsa_sha256/ca.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/client.der",
        0,
        "rsa_sha256/client.key.der",
        0,
    };
    const char *caPath = "../testdata/tls/certificate/pem/rsa_sha256/ca.pem";
    int32_t ret = HITLS_CFG_LoadVerifyFile(config_c, caPath);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfoClient);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfoServer);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
