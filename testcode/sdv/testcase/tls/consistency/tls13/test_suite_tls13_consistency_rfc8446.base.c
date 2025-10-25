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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <unistd.h>
#include "securec.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_state_recv.h"
#include "conn_init.h"
#include "app.h"
#include "record.h"
#include "rec_conn.h"
#include "session.h"
#include "recv_process.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_io.h"
#include "frame_link.h"
#include "cert.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "hlt.h"
#include "sctp_channel.h"
#include "logger.h"
#include "stub_crypt.h"
#define SIGNATURE_ALGORITHMS 0x04, 0x03 /* Fields added to the SERVER_HELLOW message */
#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */
#define TEMP_DATA_LEN 2048              /* Length of a single message */
#define ALERT_BODY_LEN 2u   /* Alert data length */

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isServerExtendMasterSecret;
    bool isSupportRenegotiation; /* Renegotiation support flag */
    bool needStopBeforeRecvCCS;  /* CCS test, so that the TRY_RECV_FINISH stops before the CCS message is received */
} HandshakeTestInfo;

int32_t StatusPark(HandshakeTestInfo *testInfo)
{
    /** Construct connection */
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Perform the CCS test so that the TRY_RECV_FINISH is stopped before the CCS message is received.
     * The default value is False, which does not affect the original test.
     */
    testInfo->client->needStopBeforeRecvCCS = testInfo->isClient ? testInfo->needStopBeforeRecvCCS : false;
    testInfo->server->needStopBeforeRecvCCS = testInfo->isClient ? false : testInfo->needStopBeforeRecvCCS;

    /** Establish a connection and stop in a certain state. */
    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    /** Construct configuration. */
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusPark(testInfo);
}

int32_t DefaultCfgStatusParkWithSuite(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    /** Construct configuration. */
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;

    return StatusPark(testInfo);
}

#define TEST_CLIENT_SEND_FAIL 1
uint32_t g_uiPort = 8889;

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

void SetFrameType(FRAME_Type *frametype, uint16_t versionType, REC_Type recordType, HS_MsgType handshakeType,
    HITLS_KeyExchAlgo keyExType)
{
    frametype->versionType = versionType;
    frametype->recordType = recordType;
    frametype->handshakeType = handshakeType;
    frametype->keyExType = keyExType;
    frametype->transportType = BSL_UIO_TCP;
}

FieldState *GetDataAddress(FRAME_Msg *data, void *member)
{
    return (FieldState *)((size_t)data + (size_t)member);
}

void Test_MisClientHelloExtension(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
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
    FieldState *extensionState = GetDataAddress(&frameMsg, user);
    *extensionState = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    ASSERT_NE(parseLen, *len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
