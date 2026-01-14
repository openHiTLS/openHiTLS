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
#include "tls.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "rec_wrapper.h"
#include "cert.h"
#include "securec.h"
#include "process.h"
#include "conn_init.h"
#include "hitls_crypt_init.h"
#include "hitls_psk.h"
#include "common_func.h"
#include "alert.h"
#include "bsl_sal.h"
/* END_HEADER */
#define MAX_BUF 16384

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    HITLS_Config *s_config;
    HITLS_Config *c_config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
} ResumeTestInfo;

static void Test_Client_Mode(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
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
    frameMsg.body.hsMsg.body.clientHello.pskModes.exData.state = ASSIGNED_FIELD;
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientHello.pskModes.exData.data);
    uint16_t version[] = { 0x03, };
    frameMsg.body.hsMsg.body.clientHello.pskModes.exData.data =
        BSL_SAL_Calloc(sizeof(version) / sizeof(uint8_t), sizeof(uint8_t));
    ASSERT_EQ(memcpy_s(frameMsg.body.hsMsg.body.clientHello.pskModes.exData.data,
        sizeof(version), version, sizeof(version)), EOK);
    frameMsg.body.hsMsg.body.clientHello.keyshares.exState = MISSING_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.state = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Server_Keyshare(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    frameMsg.body.hsMsg.body.serverHello.keyShare.data.state = ASSIGNED_FIELD;

    frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data = *(uint64_t *)user;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}



#define TEST_SERVERNAME_LENGTH 20
#define BUF_SIZE_DTO_TEST 18432
#define ROOT_DER "%s/ca.der:%s/inter.der"
#define INTCA_DER "%s/inter.der"
#define SERVER_DER "%s/server.der"
#define SERVER_KEY_DER "%s/server.key.der"
#define CLIENT_DER "%s/client.der"
#define CLIENT_KEY_DER "%s/client.key.der"
#define IP_ADDR_MAX_LEN 16
#define BYTE_SIZE 8
#define SNI_TYPE 2
#define LARGE_SIZE 1025

static int SetCertPath(HLT_Ctx_Config *ctxConfig, const char *certStr, bool isServer)
{
    int ret;
    char caCertPath[50];
    char chainCertPath[30];
    char eeCertPath[30];
    char privKeyPath[30];

    ret = sprintf_s(caCertPath, sizeof(caCertPath), ROOT_DER, certStr, certStr);
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

static void Test_Server_SVersion2(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    frameMsg.body.hsMsg.body.serverHello.supportedVersion.data.data = *(uint64_t *)user;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/* BEGIN_CASE */
void HITLS_TLS1_2_Config_SDV_23_0_5_0430(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Client_Mode
    };
    RegisterWrapper(wrapper);

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "ecdsa_sha256/ca.der", "NULL", "NULL", "NULL", "NULL", "NULL");

    clientRes = HLT_ProcessTlsInit(localProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC001
* @spec -
* @title Initialize the client server to tls1.3 and construct the selected_group carried in the key_share extension in
*         the sent serverhello message. It is not the group of the keyshareentry carried in the clienthello message or
*         the group provided in the clienthello message. As a result, the connection setup fails.
* @precon nan
* @brief 4.2.8. Key Share line 72
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC001(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    uint64_t groupreturn[] = {HITLS_EC_GROUP_SM2, };

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &groupreturn,
        Test_Server_Keyshare
    };
    RegisterWrapper(wrapper);

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
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1");
    HLT_SetTls13CipherSuites(clientCtxConfig, "HITLS_AES_128_GCM_SHA256");

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, clientRes->sslId), ALERT_FLAG_SEND);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, clientRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId), ALERT_ILLEGAL_PARAMETER);

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

static void Test_Server_Keyshare1(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    ASSERT_TRUE(frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data == *(uint64_t *)user);

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC002
* @spec  -
* @title clientHello's supported_groups is set to secp256r1. The handshake is successful.
* @precon nan
* @brief 9.1. Mandatory-to-Implement Cipher Suites line 230
* @expect 1. Expected connection setup success
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC002(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;

    uint64_t groupreturn[] = {HITLS_EC_GROUP_SECP256R1, };

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &groupreturn,
        Test_Server_Keyshare1
    };
    RegisterWrapper(wrapper);

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
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1");
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

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test SDV_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC003
* @spec -
* @title clientHello's supported_groups is set to X25519. The handshake succeeds.
* @precon nan
* @brief 9.1. Mandatory-to-Implement Cipher Suites line 230
* @expect 1. Expected connection setup success
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_KEYSHAREGROUP_FUNC_TC003(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;
    uint64_t groupreturn[] = {HITLS_EC_GROUP_CURVE25519, };

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &groupreturn,
        Test_Server_Keyshare1
    };
    RegisterWrapper(wrapper);

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

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

#define HS_RANDOM_SIZE 32u
static const uint8_t g_hrrRandom[HS_RANDOM_SIZE] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

static void Test_Server_Keyshare2(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    if (memcmp(frameMsg.body.hsMsg.body.serverHello.randomValue.data, g_hrrRandom, HS_RANDOM_SIZE) != 0) {
        frameMsg.body.hsMsg.body.serverHello.keyShare.data.state = ASSIGNED_FIELD;
        frameMsg.body.hsMsg.body.serverHello.keyShare.data.group.data = *(uint64_t *)user;
    }

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_NAMEDGROUP_FUNC_TC001
* @spec  -
* @title 1. Initialize the client and server to tls1.3, construct the scenario where ecdhe is used, construct the
*            scenario where hrr is sent, and construct the sent serverhello. The named group of the is different from
*            that in the hrr. It is expected that the client terminates the handshake and sends the illegal_parameter
*           alarm.
* @precon nan
* @brief 4.2.8. Key Share line 74
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_NAMEDGROUP_FUNC_TC001(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    uint64_t groupreturn[] = {HITLS_EC_GROUP_SM2, };

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &groupreturn,
        Test_Server_Keyshare2
    };
    RegisterWrapper(wrapper);

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);
    HLT_SetGroups(serverCtxConfig, "HITLS_EC_GROUP_CURVE25519:HITLS_EC_GROUP_SECP384R1");
    HLT_SetTls13CipherSuites(serverCtxConfig, "HITLS_AES_128_GCM_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1");
    HLT_SetTls13CipherSuites(clientCtxConfig, "HITLS_AES_128_GCM_SHA256");

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, clientRes->sslId), ALERT_FLAG_SEND);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, clientRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId), ALERT_ILLEGAL_PARAMETER);

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

static void Test_Server_SVersion(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
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

    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientHello.cipherSuites.data);
    uint16_t ciphers[3] = { 0xC02C, 0x1302, 0x1303};
    frameMsg.body.hsMsg.body.clientHello.cipherSuites.data =
    BSL_SAL_Calloc(sizeof(ciphers) / sizeof(uint16_t) + 1, sizeof(uint16_t));
    ASSERT_EQ(memcpy_s(frameMsg.body.hsMsg.body.clientHello.cipherSuites.data,
    sizeof(ciphers), ciphers, sizeof(ciphers)), EOK);
    frameMsg.body.hsMsg.body.clientHello.cipherSuites.state = ASSIGNED_FIELD;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC001
* @spec  -
* @title The supported_versions in the clientHello is extended to 0x0304 (TLS 1.3). If the server supports only 1.2, the
*         server returns a "protocol_version" warning and the handshake fails.
* @precon nan
* @brief Appendix D. Backward Compatibility line 247
* @expect
*   1. The setting is successful.
*   2. The setting is successful.
*   3. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC001( )
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Server_SVersion
    };
    RegisterWrapper(wrapper);

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);

    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(clientRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC002
* @spec  -
* @title The supported_versions field in clientHello is extended to 0x0304 (TLS 1.3). If the server supports TLS 1.3,
*        the server returns serverHello, If the value of upported_versions is changed to 0x0300, the client returns the
*        warning "ALERT_ELLEGAL_PARAMETER" and the handshake fails.
* @precon nan
* @brief Appendix D. Backward Compatibility line 247
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC002(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    uint64_t versions[] = {0x0300, };

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &versions,
        Test_Server_SVersion2
    };
    RegisterWrapper(wrapper);

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
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1");
    HLT_SetTls13CipherSuites(clientCtxConfig, "HITLS_AES_128_GCM_SHA256");

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, clientRes->sslId), ALERT_FLAG_SEND);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, clientRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId), ALERT_ILLEGAL_PARAMETER);

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

static void Test_Server_SVersion3(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverhello = &frameMsg->body.hsMsg.body.serverHello;

    serverhello->supportedVersion.exState = INITIAL_FIELD;
    serverhello->supportedVersion.exLen.state = INITIAL_FIELD;
    serverhello->supportedVersion.data.state = INITIAL_FIELD;
    serverhello->supportedVersion.data.data = 0x0304;

    FRAME_ModifyMsgInteger(HS_EX_TYPE_SUPPORTED_VERSIONS, &serverhello->supportedVersion.exType);
EXIT:
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC003
* @spec  -
* @title    clientHello version is 0x0303 and the server supports 1.3 and 1.2. In this case, the server returns
*            serverHello and selects version 1.2, If supported_versions is set to 0x0304, the client returns a
*            "ALERT_UNSUPPORTED_EXTENSION" warning and the handshake fails.
* @precon nan
* @brief Appendix D. Backward Compatibility line 247
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC003()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL,"SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetVersion(serverCtxConfig, HITLS_VERSION_TLS12, HITLS_VERSION_TLS13);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL,"CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_CleanFrameHandle();
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = Test_Server_SVersion3;
    handle.ctx = serverRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(&handle) == 0);

    clientRes = HLT_ProcessTlsInit(remoteProcess, TLS1_2, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, clientRes->sslId), ALERT_FLAG_SEND);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, clientRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId), ALERT_UNSUPPORTED_EXTENSION);
EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */

static void Test_Server_SVersion6(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
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
    frameMsg.body.hsMsg.body.clientHello.version.data = 0x0304;
    frameMsg.body.hsMsg.body.clientHello.supportedVersion.exState = MISSING_FIELD;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC010
* @spec  -
* @title ClientHello "supported_versions" extension does not exist, and ClientHello.legacy_version is TLS 1.3,
*         The server supports TLS 1.3. Check that the server aborts the handshake with the "protocol_version" alert.
* @precon nan
* @brief Appendix D. Backward Compatibility line 248
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC010()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Server_SVersion6
    };
    RegisterWrapper(wrapper);

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL,"SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL,"CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_3, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(clientRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC012
* @spec  -
* @title ClientHello "supported_versions" extension does not exist, and ClientHello.legacy_version is TLS 1.2,
*         The server only supports TLS 1.3. Check that the server aborts the handshake with the "protocol_version"
*         alert.
* @precon nan
* @brief Appendix D. Backward Compatibility line 248
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_SVERSION_FUNC_TC012()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL,"SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetVersion(serverCtxConfig, HITLS_VERSION_TLS13, HITLS_VERSION_TLS13);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL,"CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(clientRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

static void Test_Server_MasterExtKey(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
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
    ASSERT_TRUE(frameMsg.body.hsMsg.body.serverHello.extendedMasterSecret.exState == INITIAL_FIELD);

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_MASTEREXTKEY_FUNC_TC001
* @spec  -
* @title tls1.2 and tls1.3 carry the extended master key (overwrite the old and new versions). The handshake is
*         successful.
* @precon nan
* @brief Appendix D. Backward Compatibility line 244
* @expect 1. Expected connection setup failure
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_MASTEREXTKEY_FUNC_TC001()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Server_MasterExtKey
    };
    RegisterWrapper(wrapper);

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL,"SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    HLT_SetVersion(serverCtxConfig, HITLS_VERSION_TLS12, HITLS_VERSION_TLS13);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS_ALL, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL,"CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    clientRes = HLT_ProcessTlsInit(remoteProcess, TLS1_2, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_SUCCESS);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, clientRes->sslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, BUF_SIZE_DTO_TEST, 0, BUF_SIZE_DTO_TEST) == EOK);
    ASSERT_TRUE(HLT_TlsRead(serverRes->ssl, readBuf, BUF_SIZE_DTO_TEST, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

static void Test_Client_PskTicket(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
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
    frameMsg.body.hsMsg.body.clientHello.psks.identities.data->identity.data[0] += 0x01;

    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_PSKTICKET_FUNC_TC001
* @spec  -
* @title After the first connection is established, the ticket value is changed during session recovery. The session
*         recovery is expected to fail.
* @precon nan
* @brief 4.6.1. New Session Ticket Message line 158
* @expect 1. Failed to restore the expected session.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_PSKTICKET_FUNC_TC001(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;
    int32_t cnt = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportRenegotiation = false;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportRenegotiation = false;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        DataChannelParam channelParam;
        channelParam.port = g_uiPort;
        channelParam.type = connType;
        channelParam.isBlock = true;
        sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
        ASSERT_TRUE((sockFd.srcFd > 0) && (sockFd.peerFd > 0));
        remoteProcess->connFd = sockFd.peerFd;
        localProcess->connFd = sockFd.srcFd;
        remoteProcess->connType = connType;
        localProcess->connType = connType;

        int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);

        HLT_Ssl_Config *serverSslConfig;
        serverSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(serverSslConfig != NULL);
        serverSslConfig->sockFd = remoteProcess->connFd;
        serverSslConfig->connType = connType;
        ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
        HLT_RpcTlsAccept(remoteProcess, serverSslId);

        void *clientSsl = HLT_TlsNewSsl(clientConfig);
        ASSERT_TRUE(clientSsl != NULL);

        HLT_Ssl_Config *clientSslConfig;
        clientSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(clientSslConfig != NULL);
        clientSslConfig->sockFd = localProcess->connFd;
        clientSslConfig->connType = connType;

        HLT_TlsSetSsl(clientSsl, clientSslConfig);
        if (session != NULL) {
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
        }

        if (cnt != 0) {
            RecWrapper wrapper = {
                TRY_SEND_CLIENT_HELLO,
                REC_TYPE_HANDSHAKE,
                false,
                NULL,
                Test_Client_PskTicket
            };
            RegisterWrapper(wrapper);
        }

        ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);

        ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
        ASSERT_TRUE(memset_s(readBuf, BUF_SIZE_DTO_TEST, 0, BUF_SIZE_DTO_TEST) == EOK);
        ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, BUF_SIZE_DTO_TEST, &readLen) == 0);
        ASSERT_TRUE(readLen == strlen(writeBuf));
        ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

        ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
        ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);

        HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
        HLT_CloseFd(sockFd.srcFd, localProcess->connType);

        if (cnt != 0) {
            HITLS_SESS_Free(session);
            session = NULL;

            bool isReused = false;
            ASSERT_TRUE(HITLS_IsSessionReused(clientSsl, &isReused) == HITLS_SUCCESS);
            ASSERT_TRUE(isReused == false);
        }

        session = HITLS_GetDupSession(clientSsl);
        ASSERT_TRUE(session != NULL);
        cnt++;
    } while (cnt < 2);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */
