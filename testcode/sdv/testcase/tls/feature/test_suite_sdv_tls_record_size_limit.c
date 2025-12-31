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
#include <semaphore.h>
#include "process.h"
#include "securec.h"
#include "hitls_error.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "bsl_sal.h"
#include "simulate_io.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "alert.h"
#include "session_type.h"
#include "hitls_type.h"
#include "rec.h"
#include "hs_msg.h"
#include "hs_extensions.h"
#include "frame_msg.h"
#include "record.h"
#include "rec_write.h"
#include "rec_read.h"
#include "stub_utils.h"
#include "rec_wrapper.h"
#include "rec_crypto.h"
#include "bsl_log_internal.h"
#include "tls_binlog_id.h"
#include "bsl_err_internal.h"
#include "rec_buf.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET1(int32_t, REC_RecOutBufReSet, TLS_Ctx *);
STUB_DEFINE_RET2(int32_t, REC_GetMaxWriteSize, const TLS_Ctx *, uint32_t *);

#define PORT 19800
#define MAX_RECORD_LENTH (20 * 1024)
#define MAX_WRITE_LENTH (16 * 1024)
#define READ_BUF_SIZE 18432
#define REC_MAX_PLAIN_TEXT_LENGTH 16384 /* Plain content length */

int32_t STUB_REC_RecBufReSet(TLS_Ctx *ctx, bool isRenegotiatePrepare)
{
    (void)isRenegotiatePrepare;
    RecCtx *recCtx = ctx->recCtx;
    int32_t ret = RecBufResize(recCtx->inBuf, REC_MAX_PLAIN_TEXT_LENGTH + 256);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return RecBufResize(recCtx->outBuf, REC_MAX_PLAIN_TEXT_LENGTH + 256);
}

int32_t STUB_REC_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len)
{
    if (ctx == NULL || ctx->recCtx == NULL || len == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15545, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Record: input null pointer.",
            0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *len = REC_MAX_PLAIN_TEXT_LENGTH;
    return HITLS_SUCCESS;
}

int32_t STUB_REC_RecBufReSet_101(TLS_Ctx *ctx)
{
    RecCtx *recCtx = ctx->recCtx;
    int32_t ret = RecBufResize(recCtx->inBuf, 101+256);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return RecBufResize(recCtx->outBuf, 101 + 256);
}

int32_t STUB_REC_GetMaxWriteSize_101(const TLS_Ctx *ctx, uint32_t *len)
{
    if (ctx == NULL || ctx->recCtx == NULL || len == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15545, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Record: input null pointer.",
            0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *len = 101;
    return HITLS_SUCCESS;
}

static void Test_SH_RecordSizeLimit(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    frameMsg.body.hsMsg.body.serverHello.recordSizeLimit.data.state=ASSIGNED_FIELD;
    if (*(int *)user == 16385 || user == NULL) {
        frameMsg.body.hsMsg.body.serverHello.recordSizeLimit.data.data = 16386;
    } else {
        frameMsg.body.hsMsg.body.serverHello.recordSizeLimit.data.data = 63;
    }
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    FRAME_Msg frameMsg1 = {0};
        frameMsg1.recType.data = REC_TYPE_HANDSHAKE;
        frameMsg1.length.data = *len;
        frameMsg1.recVersion.data = HITLS_VERSION_TLS12;
        uint32_t parseLen1 = 0;
        FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg1, &parseLen1);

    if (*(int *)user == 16385 || user == NULL) {
        ASSERT_EQ(frameMsg1.body.hsMsg.body.serverHello.recordSizeLimit.data.data, 16386);
        FRAME_CleanMsg(&frameType, &frameMsg1);
    } else {
        ASSERT_EQ(frameMsg1.body.hsMsg.body.serverHello.recordSizeLimit.data.data, 63);
        FRAME_CleanMsg(&frameType, &frameMsg1);
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

#define RSA_CA_PATH    "rsa_sha/ca-3072.der"
#define RSA_EE_PATH1   "rsa_sha/end-sha512.der"
#define RSA_PRIV_PATH1 "rsa_sha/end-sha512.key.der"
#define RSA_EE_PATH2   "rsa_sha/end-sha384.der"
#define RSA_PRIV_PATH2 "rsa_sha/end-sha384.key.der"
#define CHAIN_CERT_PATH  "rsa_sha/inter-3072.der"
// Sending an overlong message during a single FlightTransmit. 20(ip) + 1580(handshake)
/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_PlainText_FUNC_001(int version, int connType, int c_record_size, int s_record_size)
{
#ifdef HITLS_TLS_FEATURE_FLIGHT
    bool certverifyflag = true;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, 16790, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverCtxConfig, s_record_size) == HITLS_SUCCESS);

    serverCtxConfig->isSupportClientVerify = certverifyflag;
    HLT_SetCertPath(serverCtxConfig, RSA_CA_PATH, CHAIN_CERT_PATH, RSA_EE_PATH1, RSA_PRIV_PATH1, "NULL", "NULL");

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientCtxConfig, c_record_size) == HITLS_SUCCESS);

    clientCtxConfig->isSupportClientVerify = certverifyflag;
    HLT_SetCertPath(clientCtxConfig, RSA_CA_PATH, CHAIN_CERT_PATH, RSA_EE_PATH2, RSA_PRIV_PATH2, "NULL", "NULL");

    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    uint8_t writeData[REC_MAX_PLAIN_LENGTH+ 1] = {1};
    uint32_t writeLen = REC_MAX_PLAIN_LENGTH+ 1;
    HITLS_Write(serverRes->ssl, writeData, writeLen, &writeLen);
    uint8_t readBuf[18432] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);

    if (version == TLS1_2) {
        ASSERT_EQ(writeLen, c_record_size);
        ASSERT_EQ(readLen, c_record_size);
    } else if (version == TLS1_3) {
        ASSERT_EQ(writeLen, c_record_size - 1);
        ASSERT_EQ(readLen, c_record_size - 1);
    } else if (version == DTLS1_2) {
        ASSERT_TRUE(writeLen <= (uint32_t)c_record_size);
        ASSERT_EQ(readLen, writeLen);
    }
    ASSERT_TRUE(HLT_ProcessTlsWrite(remoteProcess, clientRes, writeData, s_record_size) == 0);
    ASSERT_TRUE(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, sizeof(readBuf), &readLen) == 0);
EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
#endif /* HITLS_TLS_FEATURE_FLIGHT */
}
/* END_CASE */

uint8_t Msg[MAX_WRITE_LENTH] = {0};
static void MalformedServerHelloMsg214(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void) ctx;
    (void) bufSize;
    (void) user;
    (void) data;
    data[2] = 0x3f;  // Modify the total length of the HRR packet; the original total length of the HRR packet is 88.
    data[3] = 0xfc;
    data[74] = 0x3f; // Modify the total length of the HRR extension
    data[75] = 0xB4;
    data[88] = 0x00;  // Add cookie extension at the end of the HRR raw message.
    data[89] = 0x2c;  // HRR extension category is 44
    data[90] = 0x3f;  // Total length of HRR's cookie extension
    data[91] = 0xa4;
    data[92] = 0x3f;  // HRR's cookie extension content length
    data[93] = 0xa2;
    memset_s(Msg, MAX_WRITE_LENTH, 1, MAX_WRITE_LENTH);
    memcpy_s(Msg, 94, data, 94); // Copying hrr packets
    memcpy_s(data, MAX_WRITE_LENTH, Msg, MAX_WRITE_LENTH);
    *len = MAX_WRITE_LENTH;
    return;
}

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_PlainText_FUNC_002()
{
    RecWrapper wrapper = {
        TRY_SEND_HELLO_RETRY_REQUEST,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        MalformedServerHelloMsg214
    };
    RegisterWrapper(wrapper);

    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    bool isBlock = true;
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, isBlock);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *config_s = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(config_s != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(config_s, 64) == HITLS_SUCCESS);

    HLT_SetGroups(config_s, "HITLS_EC_GROUP_SECP256R1");
    HLT_SetPostHandshakeAuthSupport(config_s, true);
    HLT_SetClientVerifySupport(config_s, true);
    HLT_Ctx_Config *config_c = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(config_c != NULL);
    HLT_SetPostHandshakeAuthSupport(config_c, true);
    HLT_SetClientVerifySupport(config_c, true);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(config_s, 64) == HITLS_SUCCESS);

    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, config_s, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Tls_Res *clientRes = HLT_ProcessTlsInit(remoteProcess, TLS1_3, config_c, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_010(int version, int c_size, int s_size)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig, s_size) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig, c_size) == HITLS_SUCCESS);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t readData[REC_MAX_TLS13_ENCRYPTED_LEN + 1] = {0};
    uint32_t readLen = REC_MAX_TLS13_ENCRYPTED_LEN + 1;
    uint8_t writeData[REC_MAX_TLS13_ENCRYPTED_LEN+ 1] = {1};
    uint32_t writeLen = REC_MAX_PLAIN_TEXT_LENGTH;
    uint32_t writeLen1 = 0;

    HITLS_Write(clientRes->ssl, writeData, writeLen, &writeLen1);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(writeLen1, REC_MAX_PLAIN_LENGTH);
    ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_EQ(HLT_ProcessTlsWrite(remoteProcess, serverRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, clientRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(writeLen, REC_MAX_PLAIN_TEXT_LENGTH);
    ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_002(int version, int c_size, int s_size)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig, s_size) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig, c_size) == HITLS_SUCCESS);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t readData[REC_MAX_TLS13_ENCRYPTED_LEN + 1] = {0};
    uint32_t readLen = REC_MAX_TLS13_ENCRYPTED_LEN + 1;
    uint8_t writeData[REC_MAX_TLS13_ENCRYPTED_LEN+ 1] = {1};
    uint32_t writeLen = REC_MAX_TLS13_ENCRYPTED_LEN+ 1;
    uint32_t writeLen1 = 0;

    HITLS_Write(clientRes->ssl, writeData, writeLen, &writeLen1);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, readData, readLen, &readLen), 0);
    if (version ==TLS1_2) {
        ASSERT_EQ(writeLen1, REC_MAX_PLAIN_LENGTH);
        ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH);
        } else {
        ASSERT_EQ(writeLen1, REC_MAX_PLAIN_LENGTH - 1);
        ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH - 1);
        }
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_EQ(HLT_ProcessTlsWrite(remoteProcess, serverRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, clientRes, readData, readLen, &readLen), 0);
    if (version == TLS1_2) {
        ASSERT_EQ(writeLen1, REC_MAX_PLAIN_LENGTH);
        ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH);
        } else {
        ASSERT_EQ(writeLen1, REC_MAX_PLAIN_LENGTH - 1);
        ASSERT_EQ(readLen, REC_MAX_PLAIN_LENGTH - 1);
        }
    ALERT_Info info = {0};
    ALERT_GetInfo(clientRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_NO);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_007(int version, int size)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig, size) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig, size) == HITLS_SUCCESS);

    RecWrapper wrapper = {
        TRY_RECV_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        true,
        &size,
        Test_SH_RecordSizeLimit
    };
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_RECV);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId), ALERT_ILLEGAL_PARAMETER);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */
static void Test_Server_RecordSizeLimit(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, ENCRYPTED_EXTENSIONS);
    if (*(int *)user == 16385){
        data[*len - 1]= data[*len - 1] + 1;
    } else {
        data[*len - 1] = data[*len - 1] - 1;
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Client_RecordSizeLimit(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.recordSizeLimit.data.state = ASSIGNED_FIELD;
    if (user == NULL || *(int *)user == 16385){
        frameMsg.body.hsMsg.body.clientHello.recordSizeLimit.data.data = 16386;
    } else {
        frameMsg.body.hsMsg.body.clientHello.recordSizeLimit.data.data = 63;
    }
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

    if (user == NULL || *(int *)user == 16385) {
        FRAME_Msg frameMsg1 = {0};
        frameMsg1.recType.data = REC_TYPE_HANDSHAKE;
        frameMsg1.length.data = *len;
        frameMsg1.recVersion.data = HITLS_VERSION_TLS13;
        uint32_t parseLen1 = 0;
        FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg1, &parseLen1);
        ASSERT_EQ(frameMsg1.body.hsMsg.body.clientHello.recordSizeLimit.data.data, 16386);
        FRAME_CleanMsg(&frameType, &frameMsg1);
    } else {
        frameMsg.body.hsMsg.body.clientHello.recordSizeLimit.data.data = 63;
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_008(int version, int size)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig,size) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig,size) == HITLS_SUCCESS);

    RecWrapper wrapper = {
        TRY_RECV_ENCRYPTED_EXTENSIONS,
        REC_TYPE_HANDSHAKE,
        true,
        &size,
        Test_Server_RecordSizeLimit
    };
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_RECV);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId), ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_012(int version, int size)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig, size) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig, size) == HITLS_SUCCESS);

    RecWrapper wrapper = {
        TRY_RECV_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        true,
        &size,
        Test_SH_RecordSizeLimit
    };
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_RECV);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId), ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_001(int isclient)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);

    HITLS_CFG_SetRecordSizeLimit(tlsConfig, 16384);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t msg[16384 + 1] = {0x01, 0x00};
    REC_TextInput plainMsg = {  .type = REC_TYPE_APP,
                                .negotiatedVersion = HITLS_VERSION_TLS12,
                                .version = HITLS_VERSION_TLS12,
                                .text = msg,
                                .textLen = 16384 + 1};
    if (isclient) {
        RecConnState *state =  client->ssl->recCtx->writeStates.currentState;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[READ_BUF_SIZE] = {0};
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(client->ssl, state->suiteInfo,
            16384 + 1, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(server->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen + 5, writeBuf, ciphertextLen + 5);
        ioClientData->recMsg.len = ciphertextLen + 5;

        uint32_t readbytes = 0;
        uint8_t dest[READ_BUF_SIZE] = {0};
        ASSERT_EQ(HITLS_Read(server->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_RECORD_OVERFLOW);

        ALERT_Info info = {0};
        ALERT_GetInfo(server->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
    } else {
        RecConnState *state =  server->ssl->recCtx->writeStates.currentState;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[READ_BUF_SIZE] = {0};
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(server->ssl, state->suiteInfo,
            16384 + 1, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen + 5, writeBuf, ciphertextLen + 5);
        ioClientData->recMsg.len = ciphertextLen + 5;

        uint32_t readbytes = 0;
        uint8_t dest[READ_BUF_SIZE] = {0};
        ASSERT_EQ(HITLS_Read(client->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_RECORD_OVERFLOW);

        ALERT_Info info = {0};
        ALERT_GetInfo(client->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_009(int flag)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    HITLS_CFG_SetRecordSizeLimit(tlsConfig, 16385);

    tlsConfig->isSupportExtendMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    /* Configure the server to support only the non-default curve. The server sends the HRR message. */
    const uint16_t groups[] = {HITLS_EC_GROUP_CURVE25519};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(tlsConfig, groups, groupsSize);

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Client_RecordSizeLimit
    };
    RegisterWrapper(wrapper);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t msg[16386] = {0};
    memset_s(msg, MAX_WRITE_LENTH+1, 1, MAX_WRITE_LENTH+1);
    msg[16385] = REC_TYPE_APP;
    REC_TextInput plainMsg = {  .type = REC_TYPE_APP,
                                .negotiatedVersion = HITLS_VERSION_TLS13,
                                .version = HITLS_VERSION_TLS12,
                                .text = msg,
                                .textLen = 16386};
    if (flag == 0) {
        RecConnState *state =  client->ssl->recCtx->writeStates.currentState;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[18432] = {0};
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(client->ssl, state->suiteInfo, 16386, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(server->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen+5, writeBuf, ciphertextLen+5);
        ioClientData->recMsg.len = ciphertextLen+5;

        uint32_t readbytes = 0;
        uint8_t dest[READ_BUF_SIZE] = {0};
        ASSERT_EQ(HITLS_Read(server->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_RECORD_OVERFLOW);

        ALERT_Info info = {0};
        ALERT_GetInfo(server->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
    }
    else {
        RecConnState *state =  server->ssl->recCtx->writeStates.currentState;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[18432] = {0};
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(server->ssl, state->suiteInfo, 16386, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen+5, writeBuf, ciphertextLen+5);
        ioClientData->recMsg.len = ciphertextLen+5;

        uint32_t readbytes = 0;
        uint8_t dest[READ_BUF_SIZE] = {0};
        ASSERT_EQ(HITLS_Read(client->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_RECORD_OVERFLOW);

        ALERT_Info info = {0};
        ALERT_GetInfo(client->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
    }
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_011(int version, int c_size, int s_size)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig,s_size) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig,c_size) == HITLS_SUCCESS);

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &c_size,
        Test_Client_RecordSizeLimit
    };
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_MSG_HANDLE_INVALID_RECORD_SIZE_LIMIT);
    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_SEND);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId), ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */
static void Test_RecordSizeLimit_add(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(ctx->hsCtx->state, TRY_RECV_ENCRYPTED_EXTENSIONS);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, ENCRYPTED_EXTENSIONS);
    //RecordSizeLimit type
    uint32_t offset = *len;
    BSL_Uint16ToByte(HS_EX_TYPE_RECORD_SIZE_LIMIT, &data[offset]);
    offset += sizeof(uint16_t);
    BSL_Uint16ToByte(2, &data[offset]);
    offset += sizeof(uint16_t);
    BSL_Uint16ToByte(64, &data[offset]);
    offset += sizeof(uint16_t);
    uint32_t hsLen = BSL_ByteToUint24(&data[1]);
    uint32_t extLen = BSL_ByteToUint16(&data[4]);
    hsLen += offset - *len;
    extLen += offset - *len;
    BSL_Uint24ToByte(hsLen, &data[1]);
    BSL_Uint16ToByte(extLen, &data[4]);
    *len = offset;

EXIT:
    return;
}
/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_Overflow_FUNC_013(int version, int c_size, int s_size)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig,s_size) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig,c_size) == HITLS_SUCCESS);

    RecWrapper wrapper = {
        TRY_RECV_ENCRYPTED_EXTENSIONS,
        REC_TYPE_HANDSHAKE,
        true,
        &c_size,
        Test_RecordSizeLimit_add
    };
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_RECV);
    ASSERT_EQ(HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId), ALERT_UNSUPPORTED_EXTENSION);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

uint8_t certificateMsg[18432] = {0};
uint32_t certificateMsgLen = 0;
static void Copy_Certificate(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    // Stub BSL_UIO_Read to make it fail to read
    (void) ctx;
    (void) data;
    (void) len;
    (void) bufSize;
    (void) user;
    memset_s(certificateMsg, 18432, 0, 18432);
    memcpy_s(certificateMsg, *len, data, *len);
    certificateMsgLen = *len;
    return;
}

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_FUNC_002(int flag,int c_size,int s_size)
{
    FRAME_Init();
    HITLS_Config *c_tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_tlsConfig != NULL);
    HITLS_Config *s_tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(s_tlsConfig != NULL);
    HITLS_CFG_SetRecordSizeLimit(c_tlsConfig, c_size);
    HITLS_CFG_SetRecordSizeLimit(s_tlsConfig, s_size);

    c_tlsConfig->isSupportExtendMasterSecret = true;
    c_tlsConfig->isSupportClientVerify = true;
    c_tlsConfig->isSupportNoClientCert = true;
    s_tlsConfig->isSupportExtendMasterSecret = true;
    s_tlsConfig->isSupportClientVerify = true;
    s_tlsConfig->isSupportNoClientCert = true;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(c_tlsConfig, BSL_UIO_TCP);
    /* Configure the server to support only the non-default curve. The server sends the HRR message. */
    const uint16_t groups[] = {HITLS_EC_GROUP_CURVE25519};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(s_tlsConfig, groups, groupsSize);
    server = FRAME_CreateLink(s_tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Copy_Certificate
    };
    RegisterWrapper(wrapper);

    if (flag == 0) {
        ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);
        uint8_t msg[18432] = {0};
        memcpy_s(msg, certificateMsgLen, certificateMsg, certificateMsgLen);
        msg[certificateMsgLen] = REC_TYPE_HANDSHAKE;
        REC_TextInput plainMsg = {  .type = REC_TYPE_APP,
                                    .negotiatedVersion = HITLS_VERSION_TLS13,
                                    .version = HITLS_VERSION_TLS12,
                                    .text = msg,
                                    .textLen = 16624};

        RecConnState *state =  server->ssl->recCtx->writeStates.currentState;
        state->seq = 2;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[18432] = {0};
        // 16624 + ciphersuite.macLen = 16640
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(server->ssl, state->suiteInfo, 16624, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);
        ASSERT_EQ(ciphertextLen, 16640); //2^14 +256
        state->seq = 3;
        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen+5, writeBuf, ciphertextLen+5);
        ioClientData->recMsg.len = ciphertextLen+5;

        ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    }
    else {
        ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);
        uint8_t msg[18432] = {0};
        memcpy_s(msg, certificateMsgLen, certificateMsg, certificateMsgLen);
        msg[certificateMsgLen] = REC_TYPE_HANDSHAKE;
        REC_TextInput plainMsg = {  .type = REC_TYPE_APP,
                                    .negotiatedVersion = HITLS_VERSION_TLS13,
                                    .version = HITLS_VERSION_TLS12,
                                    .text = msg,
                                    .textLen = 16624};

        RecConnState *state =  client->ssl->recCtx->writeStates.currentState;
        state->seq = 0;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[18432] = {0};
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(client->ssl, state->suiteInfo, 16624, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);
        ASSERT_EQ(ciphertextLen, 16640); //2^14 +256
        state->seq = 1;
        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(server->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen+5, writeBuf, ciphertextLen+5);
        ioClientData->recMsg.len = ciphertextLen+5;

        ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    }
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(c_tlsConfig);
    HITLS_CFG_FreeConfig(s_tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_FUNC_001(int version, int connType)
{
#ifdef HITLS_TLS_FEATURE_FLIGHT
    bool certverifyflag = true;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, 16790, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverCtxConfig,16383) == HITLS_SUCCESS);

    serverCtxConfig->isSupportClientVerify = certverifyflag;
    HLT_SetCertPath(serverCtxConfig, RSA_CA_PATH, CHAIN_CERT_PATH, RSA_EE_PATH1, RSA_PRIV_PATH1, "NULL", "NULL");
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Client_RecordSizeLimit
    };
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientCtxConfig,16385) == HITLS_SUCCESS);
    clientCtxConfig->isSupportClientVerify = certverifyflag;
    HLT_SetCertPath(clientCtxConfig, RSA_CA_PATH, CHAIN_CERT_PATH, RSA_EE_PATH2, RSA_PRIV_PATH2, "NULL", "NULL");
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);
    ASSERT_TRUE(HLT_ProcessTlsWrite(remoteProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf[18432] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(localProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
EXIT:
    ClearWrapper();
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
#endif /* HITLS_TLS_FEATURE_FLIGHT */
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_FUNC_005(int version)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig, 64) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig, 100) == HITLS_SUCCESS);

    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecBufReSet_101);

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t readData[REC_MAX_PLAIN_LENGTH + 1] = {0};
    uint32_t readLen = REC_MAX_PLAIN_LENGTH + 1;
    uint8_t writeData[REC_MAX_PLAIN_LENGTH] = {1};
    uint32_t writeLen = REC_MAX_PLAIN_LENGTH;

    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_101);
    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, serverRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readData, readLen, &readLen), HITLS_REC_RECORD_OVERFLOW);
    ASSERT_EQ(writeLen, REC_MAX_PLAIN_LENGTH);

    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readData, readLen, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(serverRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
EXIT:
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(REC_GetMaxWriteSize);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_FUNC_006(int version)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(serverConfig, 100) == HITLS_SUCCESS);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetRecordSizeLimit(clientConfig, 64) == HITLS_SUCCESS);

    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize_101);
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecBufReSet_101);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t readData[REC_MAX_PLAIN_LENGTH + 1] = {0};
    uint32_t readLen = REC_MAX_PLAIN_LENGTH + 1;
    uint8_t writeData[REC_MAX_PLAIN_LENGTH+ 1] = {1};
    uint32_t writeLen = REC_MAX_PLAIN_LENGTH+ 1;

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, clientRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, readData, readLen, &readLen), HITLS_REC_RECORD_OVERFLOW);
    ASSERT_EQ(writeLen, REC_MAX_PLAIN_LENGTH+ 1);

    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, clientRes, readData, readLen, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(clientRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
EXIT:
    STUB_RESTORE(REC_GetMaxWriteSize);
    STUB_RESTORE(REC_RecOutBufReSet);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_FUNC_007(int isclient)
{
    FRAME_Init();

    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    s_config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 1400)== HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 1500)== HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);
    uint8_t msg[1400 + 1] = {0x01, 0x00};
    REC_TextInput plainMsg = {  .type = REC_TYPE_APP,
                                .negotiatedVersion = HITLS_VERSION_TLS12,
                                .version = HITLS_VERSION_TLS12,
                                .text = msg,
                                .textLen = 1400 + 1};
    if (isclient) {
        RecConnState *state =  client->ssl->recCtx->writeStates.currentState;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[READ_BUF_SIZE] = {0};
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(client->ssl, state->suiteInfo,
            1400 + 1, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(server->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen + 5, writeBuf, ciphertextLen+5);
        ioClientData->recMsg.len = ciphertextLen + 5;

        uint32_t readbytes = 0;
        uint8_t dest[READ_BUF_SIZE] = {0};
        ASSERT_EQ(HITLS_Read(server->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

        ALERT_Info info = {0};
        ALERT_GetInfo(server->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_NO);
    } else {
        RecConnState *state =  server->ssl->recCtx->writeStates.currentState;
        BSL_Uint64ToByte(state->seq, plainMsg.seq);
        uint8_t writeBuf[READ_BUF_SIZE] = {0};
        uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(server->ssl, state->suiteInfo,
            1400 + 1, false);
        RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

        writeBuf[0] = REC_TYPE_APP;
        BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
        BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

        FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
        memcpy_s(ioClientData->recMsg.msg, ciphertextLen + 5, writeBuf, ciphertextLen+5);
        ioClientData->recMsg.len = ciphertextLen + 5;

        uint32_t readbytes = 0;
        uint8_t dest[READ_BUF_SIZE] = {0};
        ASSERT_EQ(HITLS_Read(client->ssl, dest, READ_BUF_SIZE, &readbytes), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

        ALERT_Info info = {0};
        ALERT_GetInfo(client->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_NO);
    }
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_SDV_TLS_RecSizeLimit_FUNC_014(int version, int connType, int c_record_size0, int s_record_size0,
    int c_record_size, int s_record_size)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    int32_t cnt = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = 0;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    HITLS_Config *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportSessionTicket = true;
    clientCtxConfig->isSupportRenegotiation = false;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportSessionTicket = true;
    serverCtxConfig->isSupportRenegotiation = false;
    do {
        if (cnt != 0) {
            ASSERT_TRUE(HLT_SetRecordSizeLimit(serverCtxConfig,s_record_size) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_SetRecordSizeLimit(clientCtxConfig,c_record_size) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
            ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
        }else
        {
            ASSERT_TRUE(HLT_SetRecordSizeLimit(serverCtxConfig,s_record_size0) == HITLS_SUCCESS);
            clientConfig->recordSizeLimit=c_record_size0;
            ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
            ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
        }
        DataChannelParam channelParam;
        channelParam.port = 8888;
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
        // The bottom-layer connection is established.
        HLT_TlsSetSsl(clientSsl, clientSslConfig);
        if (session != NULL) {
            // Configure the session in the SSL, resume the session, and obtain the session again.
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
        }
        ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);

        ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
        ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
        ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
        ASSERT_TRUE(readLen == strlen(writeBuf));
        ASSERT_TRUE(memcmp(writeBuf, readBuf, strlen(writeBuf)) == 0);

        ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
        ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
        HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen);
        HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
        HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
        HLT_CloseFd(sockFd.srcFd, localProcess->connType);

        if (cnt != 0) {
            HITLS_SESS_Free(session);
            session = NULL;
            bool isReused = false;
            ASSERT_TRUE(HITLS_IsSessionReused(clientSsl, &isReused) == HITLS_SUCCESS);
            ASSERT_TRUE(isReused == 1);
        }
        // After the first handshake is complete, obtain and store the session.
        session = HITLS_GetDupSession(clientSsl);
        ASSERT_TRUE(session != NULL);
        ASSERT_TRUE(HITLS_SESS_HasTicket(session) == true);
        ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        cnt++;
    } while (cnt < 2);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */