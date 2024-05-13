/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdio.h>
#include <unistd.h>
#include "stub_replace.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "session_type.h"
#include "hitls_type.h"
#include "pack.h"
#include "send_process.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "uio_base.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "cert.h"
#include "app.h"
#include "hlt.h"
#include "alert.h"
#include "securec.h"
#include "record.h"
#include "rec_write.h"
#include "rec_read.h"
#include "rec_wrapper.h"
#include "hitls_crypt_init.h"
#include "conn_init.h"
#include "cert_callback.h"
#include "change_cipher_spec.h"
#include "common_func.h"

#define PORT 11111
#define TEMP_DATA_LEN 1024              /* Length of a single message. */
#define MAX_BUF_LEN (20 * 1024)
#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */
#define ALERT_BODY_LEN 2u
#define REC_TLS_RECORD_HEADER_LEN 5     /* recode header length */
#define REC_CONN_SEQ_SIZE 8u            /* SN size */
#define GetEpochSeq(epoch, seq) (((uint64_t)(epoch) << 48) | (seq))
#define BUF_TOOLONG_LEN ((1 << 14) + 1)
typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession; /* session set to the client, used for session recovery. */
} ResumeTestInfo;

typedef struct {
    int connectExpect; // Expected connect result
    int acceptExpect;  // Expected accept result
    ALERT_Level expectLevel; // Expected alert level
    ALERT_Description expectDescription; // Expected alert description of the tested end
} TestExpect;

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
    bool needStopBeforeRecvCCS;  /* CCS test, so that the TRY_RECV_FINISH stops before the CCS message is received. */
} HandshakeTestInfo;

uint16_t GetCipherSuite(const char *cipherSuite)
{
    if (strcmp(cipherSuite, "HITLS_ECDHE_SM4_CBC_SM3") == 0) {
        return HITLS_ECDHE_SM4_CBC_SM3;
    }
    if (strcmp(cipherSuite, "HITLS_ECC_SM4_CBC_SM3") == 0) {
        return HITLS_ECC_SM4_CBC_SM3;
    }
    return 0;
}

int32_t RandBytes(uint8_t *randNum, uint32_t randLen)
{
    srand(time(0));
    const int maxNum = 256u;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return HITLS_SUCCESS;
}

int32_t GenerateEccPremasterSecret(TLS_Ctx *ctx);

int32_t RecordDecryptPrepare(TLS_Ctx *ctx, uint16_t version, uint64_t seq, REC_TextInput *cryptMsg);
int32_t RecConnDecrypt(
    TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg, uint8_t *data, uint32_t *dataLen);

int32_t STUB_GenerateEccPremasterSecret(TLS_Ctx *ctx)
{
    uint32_t offset;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *kxCtx = hsCtx->kxCtx;
    uint8_t *premasterSecret = kxCtx->keyExchParam.ecc.preMasterSecret;

    /* The first two bytes are the latest version supported by the client.*/
    /* Change the version number and construct an exception. */
    BSL_Uint16ToByte(0x0505, premasterSecret);
    offset = sizeof(uint16_t);
    /* 46 bytes secure random number */
    return SAL_CRYPT_Rand(&premasterSecret[offset], MASTER_SECRET_LEN - offset);
}

static int32_t STUB_APP_Write_Fatal(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    (void)data;
    (void)dataLen;
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    return HITLS_INTERNAL_EXCEPTION;
}

int32_t STUB_TlsRecordRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    int32_t ret;
    (void)recordType;
    (void)readLen;
    RecConnState *state = ctx->recCtx->readStates.currentState;
    uint16_t version = ctx->negotiatedInfo.version;
    uint64_t seq = state->seq;
    REC_TextInput encryptedMsg = {0};
    ret = RecordDecryptPrepare(ctx, version, seq, &encryptedMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t dataLen = num;
    ASSERT_EQ(encryptedMsg.textLen, num);
    ret = RecConnDecrypt(ctx, state, &encryptedMsg, data, &dataLen);
exit:
    return ret;
}

static void TEST_SendUnexpectCertificateVerifyMsg(void *msg, void *data)
{
    FRAME_Type *frameType = (FRAME_Type *)data;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;

    FRAME_Msg newFrameMsg = {0};
    HS_MsgType hsTypeTmp = frameType->handshakeType;
    REC_Type recTypeTmp = frameType->recordType;
    frameType->handshakeType = CERTIFICATE_VERIFY;
    FRAME_Init();
    FRAME_GetDefaultMsg(frameType, &newFrameMsg);
    HLT_TlsRegCallback(HITLS_CALLBACK_DEFAULT); // recovery callback

    frameType->handshakeType = hsTypeTmp;
    frameType->recordType = recTypeTmp;
    FRAME_CleanMsg(frameType, frameMsg);

    frameType->recordType = REC_TYPE_HANDSHAKE;
    frameType->handshakeType = CERTIFICATE_VERIFY;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    if (memcpy_s(msg, sizeof(FRAME_Msg), &newFrameMsg, sizeof(newFrameMsg)) != EOK) {
        Print("TEST_SendUnexpectCertificateMsg memcpy_s Error!");
    }
}

static void Test_ErrCertVerify(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    if (*(bool *)user) {
        return;
    }
    *(bool *)user = true;
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP11;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_VERIFY);
    ASSERT_EQ(parseLen, *len);
    frameMsg.body.hsMsg.body.certificateVerify.sign.data[0]++;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
exit:
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Finish_Len_TooLong(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP11;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);

    frameMsg.body.hsMsg.body.finished.verifyData.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.finished.verifyData.size = 12;
    frameMsg.body.hsMsg.body.finished.verifyData.data[0] = 0x00;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Finish_Len_TooLong_client(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP11;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);
    if (ctx->isClient==true){
        frameMsg.body.hsMsg.body.finished.verifyData.state = ASSIGNED_FIELD;
        frameMsg.body.hsMsg.body.finished.verifyData.size = 12;
        frameMsg.body.hsMsg.body.finished.verifyData.data[0] = 0x00;
            }
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static int32_t GetDisorderServerCertAndKeyExchMsg(FRAME_LinkObj *server, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t tmpData[READ_BUF_SIZE] = {0};
    uint32_t tmpLen = sizeof(tmpData);
    (void)HITLS_Accept(server->ssl);
    int32_t ret = FRAME_TransportSendMsg(server->io, tmpData, tmpLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    tmpLen = readLen;

    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, &data[offset], len - offset, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    offset += readLen;

    if (memcpy_s(&data[offset], len - offset, tmpData, tmpLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += tmpLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static void Test_MisSessionId(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    if (*(bool *)user) {
        return;
    }
    *(bool *)user = true;
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP11;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    ASSERT_EQ(parseLen, *len);
    frameMsg.body.hsMsg.body.serverHello.sessionId.state = MISSING_FIELD;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
exit:
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_DiffServerKeyEx(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    if (*(bool *)user) {
        return;
    }
    *(bool *)user = true;
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP11;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_KEY_EXCHANGE);
    ASSERT_EQ(parseLen, *len);
    frameType.keyExType = HITLS_KEY_EXCH_ECC;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
exit:
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

int32_t StatusGMPark(HandshakeTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateTLCPLink(testInfo->config, BSL_UIO_TCP, true);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateTLCPLink(testInfo->config, BSL_UIO_TCP, false);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    testInfo->config = HITLS_CFG_NewTLCPConfig();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCloseCheckKeyUsage(testInfo->config, false);
    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusGMPark(testInfo);
}


int32_t DefaultCfgStatusParkWithSuite(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    testInfo->config = HITLS_CFG_NewTLCPConfig();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCloseCheckKeyUsage(testInfo->config, false);
    uint16_t cipherSuits[] = {HITLS_ECDHE_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;

    return StatusGMPark(testInfo);
}

void SetFrameType(FRAME_Type *frametype, uint16_t versionType, REC_Type recordType, HS_MsgType handshakeType,
    HITLS_KeyExchAlgo keyExType)
{
    frametype->versionType = versionType;
    frametype->recordType = recordType;
    frametype->handshakeType = handshakeType;
    frametype->keyExType = keyExType;
}

static void TEST_UnexpectMsg(HLT_FrameHandle *frameHandle, TestExpect *testExpect, bool isSupportClientVerify)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    ALERT_Info alertInfo = {0};

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(serverConfig != NULL);
    if (isSupportClientVerify) {
        ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, isSupportClientVerify) == 0);
    }

    HLT_Ctx_Config *clientConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetClientVerifySupport(clientConfig, isSupportClientVerify) == 0);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLCP1_1, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Client Initialization
    clientRes = HLT_ProcessTlsInit(localProcess, TLCP1_1, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(frameHandle != NULL);
    frameHandle->ctx = clientRes->ssl;
    HLT_SetFrameHandle(frameHandle);
    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), testExpect->connectExpect);
    HLT_CleanFrameHandle();

    ALERT_GetInfo(clientRes->ssl, &alertInfo);
    ASSERT_TRUE(alertInfo.level == testExpect->expectLevel);
    ASSERT_EQ(alertInfo.description, testExpect->expectDescription);
    ASSERT_EQ(HLT_RpcGetTlsAcceptResult(serverRes->acceptId), testExpect->acceptExpect);

exit:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
