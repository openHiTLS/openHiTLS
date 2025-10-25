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

static void TestFrameChangeCerts(void *msg, void *data)
{
    (void)data;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    FRAME_CertificateMsg *certicate = &frameMsg->body.hsMsg.body.certificate;
    FrameCertItem *cert = certicate->certItem->next->next;  // 1 ->2 ->3 ->0
    cert->next = certicate->certItem->next;                 // 3->2
    certicate->certItem->next = cert;                       // 1->3
    cert->next->next = NULL;                                // 2-> 0
}

/** @
* @test SDV_TLS_TLS13_RFC8446_CONSISTENCY_TWO_DISOEDER_CHAIN_CERT_FUNC_TC001
* @spec -
* @title The certificate chain sent by the server contains two intermediate certificates, which are out of order
*   (excluding the device certificate).
* @precon nan
* @brief The sender' s certificate MUST come in the first CertificateEntry in the list.
*   1. The certificate chain sent by the server contains two intermediate certificates, and the two intermediate
*   certificates are out of order. Expected result 1 is displayed.
* @expect 1. The connection fails to be established. The error code is ALERT_BAD_CERTIFICATIONATE.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_TWO_DISOEDER_CHAIN_CERT_FUNC_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);
    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha512/otherRoot.der",
        "rsa_sha512/otherInter.der:rsa_sha512/otherInter2.der",
        "rsa_sha512/otherEnd.der",
        "rsa_sha512/otherEnd.key.der",
        "NULL",
        "NULL");
    HLT_SetClientVerifySupport(serverCtxConfig, true);
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetCertPath(clientCtxConfig,
        "rsa_sha512/otherRoot.der",
        "rsa_sha512/otherInter.der:rsa_sha512/otherInter2.der",
        "rsa_sha512/otherEnd.der",
        "rsa_sha512/otherEnd.key.der",
        "NULL",
        "NULL");
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_256_CBC_SHA");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_FrameHandle frameHandle = {
        .ctx = serverRes->ssl,
        /* 1. The certificate chain sent by the server contains two intermediate certificates, and the two intermediate
         * certificates are out of order. */
        .frameCallBack = TestFrameChangeCerts,
        .userData = NULL,
        .expectHsType = CERTIFICATE,
        .expectReType = REC_TYPE_HANDSHAKE,
        .ioState = EXP_NONE,
        .pointType = POINT_SEND,
    };
    ASSERT_TRUE(HLT_SetFrameHandle(&frameHandle) == HITLS_SUCCESS);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
    return;
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS13_RFC8446_CONSISTENCY_MIDDLE_BOX_COMPAT_FUNC_TC001
* @spec -
* @title Test TLS 1.3 connection and data transfer when middlebox compatibility mode is enabled or disabled
* @precon nan
* @brief
*   1. The server and client are configured with middlebox compatibility mode controlled by the input parameter isMiddleBoxCompat.
*   2. Establish a TLS 1.3 connection between server and client.
*   3. Verify bidirectional data transmission integrity.
* @expect 1. The TLS 1.3 connection is successfully established.
*   2. Data sent by the server is correctly received by the client (length and content match).
*   3. Data sent by the client is correctly received by the server (length and content match).
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_MIDDLE_BOX_COMPAT_FUNC_TC001(int isMiddleBoxCompat)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);
    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetClientVerifySupport(serverCtxConfig, true);
    HLT_SetMiddleBoxCompat(serverCtxConfig, isMiddleBoxCompat);
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetMiddleBoxCompat(clientCtxConfig, isMiddleBoxCompat);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    uint8_t writeData[REC_MAX_PLAIN_LENGTH] = {1};
    uint32_t writeLen = REC_MAX_PLAIN_LENGTH;
    uint8_t readData[REC_MAX_PLAIN_LENGTH] = {0};
    uint32_t readLen = REC_MAX_PLAIN_LENGTH;

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, serverRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_EQ(HLT_ProcessTlsWrite(remoteProcess, clientRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
    return;
}
/* END_CASE */
