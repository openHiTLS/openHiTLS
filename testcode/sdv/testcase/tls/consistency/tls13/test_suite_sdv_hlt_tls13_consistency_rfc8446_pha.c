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
#include "conn_init.h"
#include "hitls_crypt_init.h"
#include "hitls_psk.h"
#include "common_func.h"
#include "alert.h"
#include "process.h"
#include "bsl_sal.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, REC_Write, TLS_Ctx *, REC_Type, const uint8_t *, uint32_t);

#define MAX_BUF 16384

int32_t STUB_RecConnDecrypt(
    TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg, uint8_t *data, uint32_t *dataLen)
{
    (void)ctx;
    (void)state;
    memcpy_s(data, cryptMsg->textLen, cryptMsg->text, cryptMsg->textLen);
    (void)data;
    *dataLen = cryptMsg->textLen;
    return HITLS_SUCCESS;
}

// Stub function for REC_Write - used by STUB_REPLACE in test cases
// Note: Test cases can use stub mechanism, but framework cannot
int32_t Stub_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    (void)ctx;
    (void)recordType;
    (void)data;
    (void)num;
    return HITLS_SUCCESS;
}

static void Test_FinishToAPP(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);

    // Use stub mechanism directly - no ld --wrap needed
    STUB_REPLACE(REC_Write, Stub_REC_Write);;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_ServerHello_Add_PhaExtensions(
    HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    uint8_t posthandshake[] = {0x00, 0x31, 0x00, 0x00};
    frameMsg.body.hsMsg.length.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.length.data += sizeof(posthandshake);
    frameMsg.body.hsMsg.body.serverHello.extensionLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.serverHello.extensionLen.data =
        frameMsg.body.hsMsg.body.serverHello.extensionLen.data + sizeof(posthandshake);

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
    ASSERT_EQ(memcpy_s(&data[*len], bufSize - *len, &posthandshake, sizeof(posthandshake)), EOK);
    *len += sizeof(posthandshake);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_CertificateRequest_Ctx_Zero(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_REQUEST);

    frameMsg.body.hsMsg.body.certificateReq.certificateReqCtx.state = MISSING_FIELD;
    frameMsg.body.hsMsg.body.certificateReq.certificateReqCtxSize.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.certificateReq.certificateReqCtxSize.data = 0;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Certificate_Ctx_Zero(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);

    frameMsg.body.hsMsg.body.certificate.certificateReqCtx.state = MISSING_FIELD;
    frameMsg.body.hsMsg.body.certificate.certificateReqCtxSize.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.certificate.certificateReqCtxSize.data = 0;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Certificate_Ctx_NotSame(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);

    frameMsg.body.hsMsg.body.certificate.certificateReqCtx.state = ASSIGNED_FIELD;
    *(frameMsg.body.hsMsg.body.certificate.certificateReqCtx.data) += 1;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Finish_Error(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);

    frameMsg.body.hsMsg.body.finished.verifyData.state = ASSIGNED_FIELD;
    *(frameMsg.body.hsMsg.body.finished.verifyData.data) += 1;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/**
 * @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_PHA_FUNC_TC001
 * @brief tls1.3 post-handshake auth
 * base test case
 */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_PHA_FUNC_TC001()
{
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    bool isBlock = true;
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, isBlock);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *config_s = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(config_s != NULL);
    HLT_SetPostHandshakeAuth(config_s, true);
    HLT_SetClientVerifySupport(config_s, true);

    HLT_Ctx_Config *config_c = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(config_c != NULL);
    HLT_SetPostHandshakeAuth(config_c, true);
    HLT_SetClientVerifySupport(config_c, true);
    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, config_s, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Tls_Res *clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, config_c, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t src[] = "Hello world!";
    uint32_t readbytes = 0;
    uint8_t dest[READ_BUF_SIZE] = {0};
    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, clientRes, src, sizeof(src)), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, dest, READ_BUF_SIZE, &readbytes), 0);
    ASSERT_TRUE(readbytes == sizeof(src));
    ASSERT_TRUE(memcmp(src, dest, readbytes) == 0);
    memset_s(dest, READ_BUF_SIZE, 0, READ_BUF_SIZE);
EXIT:
    HLT_FreeAllProcess();
    return;
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC002
* @spec  -
* @title The client does not support post-handshake authentication, but receives the server hello message that carries
*        the extension.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client not to support post-handshake extension
*   3. Set up a connection and modify the server hello message to carry the post-handshake extension.
*   4. Observe client behavior
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. Modification succeeded.
*   4. The client returns alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC002(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply and initialize config
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the client not to support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, true);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, false);
    HLT_SetClientVerifySupport(clientConfig, true);

    // Set up a connection and modify the server hello message to carry the post-handshake extension.
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ServerHello_Add_PhaExtensions};
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // The client returns alert
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);
EXIT:
    HLT_FreeAllProcess();
    ClearWrapper();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC003
* @spec  -
* @title The client supports authentication after handshake, but receives the server hello message that carries the
*        extension.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client support post-handshake extension
*   3. Set up a connection and modify the server hello message to carry the post-handshake extension.
*   4. Observe client behavior
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. Modification succeeded.
*   4. The client returns alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC003(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply and initialize config
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the client support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, true);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, true);
    HLT_SetClientVerifySupport(clientConfig, true);

    // Set up a connection and modify the server hello message to carry the post-handshake extension.
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ServerHello_Add_PhaExtensions};
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // The client returns alert
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);
EXIT:
    HLT_FreeAllProcess();
    ClearWrapper();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC004
* @spec  -
* @title When the value of certificate_request_context in the certificate request message
*        after handshake authentication is 0, the client reports an error.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client support post-handshake extension
*   3. After the connection establishment is completed, modify the certificate_request_context of the
*       certificate request message sent by the server to 0.
*   4. Observe client behavior
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. Modification succeeded.
*   4. The client returns alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC004(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply and initialize config
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the client support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, true);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, true);
    HLT_SetClientVerifySupport(clientConfig, true);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    ASSERT_EQ(HITLS_VerifyClientPostHandshake(serverRes->ssl), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    // modify the certificate_request_context of the certificate request message sent by the server to 0.
    ClearWrapper();
    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, NULL, Test_CertificateRequest_Ctx_Zero};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HLT_TlsWrite(serverRes->ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == HITLS_SUCCESS);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);

    // The client returns alert
    ASSERT_TRUE(HLT_RpcTlsRead(remoteProcess, clientRes->sslId, readBuf, READ_BUF_SIZE, &readLen) ==
                HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC005
* @spec  -
* @title The server reports an error when the value of certificate_request_context of the
*            client certificate is 0 during authentication after handshake.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client support post-handshake extension
*   3. After the connection is established, the server initiates a certificate request and changes the value of
*      certificate_request_context in the certificate request message from the client to 0
*   4. Observe the server behavior
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. Modification succeeded.
*   4. The server returns alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC005(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply and initialize config
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the client support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, true);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, true);
    HLT_SetClientVerifySupport(clientConfig, true);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverRes->sslId) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    // changes the value of certificate_request_context in the certificate request message from the client to 0
    ClearWrapper();
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_Certificate_Ctx_Zero};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverRes->sslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientRes->ssl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_TlsWrite(clientRes->ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == HITLS_SUCCESS);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);

    // The server returns alert
    ASSERT_EQ(HLT_RpcTlsRead(remoteProcess, serverRes->sslId, readBuf, READ_BUF_SIZE, &readLen),
        HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC006
* @spec  -
* @title During post-handshake authentication, the certificate_request_context sent by the client is inconsistent with
*            that sent by the server. As a result, the server reports an error.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client support post-handshake extension
*   3. After the connection is established, the server initiates a certificate request and changes the value of
*       certificate_request_context in the certificate request message from the client
*   4. Observe the server behavior
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. Modification succeeded.
4. The server returns alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC006(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply and initialize config
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the client support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, true);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, true);
    HLT_SetClientVerifySupport(clientConfig, true);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverRes->sslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    // changes the value of certificate_request_context in the certificate request message from the client
    ClearWrapper();
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_Certificate_Ctx_NotSame};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverRes->sslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientRes->ssl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_TlsWrite(clientRes->ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == HITLS_SUCCESS);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);

    // The server returns alert
    ASSERT_EQ(HLT_RpcTlsRead(remoteProcess, serverRes->sslId, readBuf, READ_BUF_SIZE, &readLen),
        HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC007
* @spec  -
* @title After the PSK connection is established, the certificate is authenticated after handshake. The authentication is
*        successful.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file
*   2. Setting the PSK on the Client and Server
*   3. Configure the client and server to support post-handshake extension
*   4. After the connection is established, the server sends a certificate request message for backhandshake authentication.
* @expect
*   1. Initialization succeeded.
*   2. Setting succeeded.
*   3. Setting succeeded.
*   4. Authentication succeeded.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC007(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the configuration file
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the client and server to support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, true);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, true);
    HLT_SetClientVerifySupport(clientConfig, true);

    // Setting the PSK on the Client and Server
    memcpy_s(clientConfig->psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));
    memcpy_s(serverConfig->psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));
    HLT_SetCipherSuites(clientConfig, "HITLS_AES_128_GCM_SHA256");
    HLT_SetCipherSuites(serverConfig, "HITLS_AES_128_GCM_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    // the server sends a certificate request message for backhandshake authentication.
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(serverRes->ssl), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    ASSERT_TRUE(HLT_TlsWrite(serverRes->ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == HITLS_SUCCESS);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_EQ(HLT_RpcTlsRead(remoteProcess, clientRes->sslId, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, clientRes->sslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(serverRes->ssl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC008
* @spec  -
* @title The server fails to verify the finish during post-authentication.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client support post-handshake extension
*   3. After the connection is established, the server initiates a certificate request and Modify the finish message sent
*      by the client.
*   4. Observe the server behavior
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. Modification succeeded.
*   4. The server returns alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC008(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply and initialize config
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the client support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, true);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, true);
    HLT_SetClientVerifySupport(clientConfig, true);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    // the server initiates a certificate request
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverRes->sslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    // Modify the finish message sent by the client.
    ClearWrapper();
    RecWrapper wrapper = {TRY_SEND_FINISH, REC_TYPE_HANDSHAKE, false, NULL, Test_Finish_Error};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverRes->sslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientRes->ssl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_TlsWrite(clientRes->ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == HITLS_SUCCESS);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);

    // The server returns alert
    ASSERT_EQ(HLT_RpcTlsRead(remoteProcess, serverRes->sslId, readBuf, READ_BUF_SIZE, &readLen),
        HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC009
* @spec  -
* @title Two certificates request messages are sent for backhandshake authentication,
        and the required certificate_request_context is inconsistent.
* @precon  nan
* @brief
1. Apply and initialize config
2. Set the client support post-handshake extension
3. After the connection is established, the server continuously sends certificate request messages for backhandshake
authentication
4. Check whether the certificate_request_context sent by the server is the same.
* @expect
1. Initialization succeeded.
2. Set succeeded.
3. Constructed successfully.
4. Inconsistent certificate_request_context
* @prior  Level 1
* @auto  TRUE+
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC009()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    // Apply and initialize config
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Set the client support post-handshake extension
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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
    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // the server continuously sends certificate request messages
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    HITLS_Ctx *ctx = clientSsl;
    uint8_t ReqCtx1[1 * 1024] = {0};
    memcpy_s(ReqCtx1, ctx->certificateReqCtxSize, ctx->certificateReqCtx, ctx->certificateReqCtxSize);

    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    // the server continuously sends certificate request messages
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    // Inconsistent certificate_request_context
    ASSERT_TRUE(memcmp(ReqCtx1, ctx->certificateReqCtx, ctx->certificateReqCtxSize) != 0);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC011
* @spec  -
* @title The server does not allow the client to send an empty certificate. During authentication after handshake,
*        the server receives an empty certificate from the client.
* @precon  nan
* @brief
*   1. Apply for and initialize the config file. Expected result 1 is obtained.
*   2. Configure the server not to allow the client to send an empty certificate. Expected result 2 is obtained.
*   3. Configure the client to send an empty certificate. Expected result 3 is obtained.
*   4. Configure the client and server to support post-handshake extension. Expected result 4 is obtained.
*   5. Perform authentication after the connection is established. Expected result 5 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The setting is successful.
*   4. The setting is successful.
*   5. The connection is set up successfully. After receiving the client certificate, the server sends an alert message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC011()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    // Apply for and initialize the config file
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Configure the server not to allow the client to send an empty certificate
    // Configure the client and server to support post-handshake extension
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportNoClientCert = false;
    serverCtxConfig->isSupportPostHandshakeAuth = true;

    // Configure the client to send an empty certificate
    HLT_SetCertPath(
        clientCtxConfig, "rsa_sha256/ca.der:rsa_sha256/inter.der", "NULL", "NULL", "NULL", "NULL", "NULL");
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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

    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Perform authentication after the connection is established
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ret = HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);

    // the server sends an alert message.
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC012
* @spec  -
* @title The server allows the client to send an empty certificate. During authentication after handshake,
*        the server receives an empty certificate from the client.
* @precon  nan
* @brief
*   1. Apply for and initialize the config file. Expected result 1 is obtained.
*   2. Configure the server to allow the client to send an empty certificate. Expected result 2 is obtained.
*   3. Configure the client to send an empty certificate. Expected result 3 is obtained.
*   4. Configure the client and server to support post-handshake extension. Expected result 4 is obtained.
*   5. Perform authentication after the connection is established. Expected result 5 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The setting is successful.
*   4. The setting is successful.
*   5. The connection is successfully set up, and the server initiates authentication.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC012()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    // Apply for and initialize the config file
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Configure the server to allow the client to send an empty certificate.
    // Configure the client and server to support post-handshake extension
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportNoClientCert = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;

    // Configure the client to send an empty certificate
    HLT_SetCertPath(
        clientCtxConfig, "rsa_sha256/ca.der:rsa_sha256/inter.der", "NULL", "NULL", "NULL", "NULL", "NULL");
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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
    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Perform authentication after the connection is established
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    // The connection is successfully set up, and the server initiates authentication.
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC013
* @spec  -
* @title The server does not set the verification failure to continue the handshake. As a result, the server
*        verification fails during the post-handshake authentication.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1 is obtained.
*   2. Configure the client and server to support post-handshake extension. Expected result 2 is obtained.
*   3. Set the server certificate to the RSA certificate and the client certificate to the ECDSA certificate. Expected
*       result 3 is obtained.
*   4. After the connection is established, authentication is performed. Expected result 4 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The setting is successful.
*   4. The connection is successfully established, but the server fails to authenticate the certificate.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC013()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    // Apply for and initialize the configuration file
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Configure the client and server to support post-handshake extension
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    clientCtxConfig->isSupportVerifyNone = false;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportVerifyNone = false;

    // Set the server certificate to the RSA certificate and the client certificate to the ECDSA certificate.
    HLT_SetCertPath(clientCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        "ecdsa/end256-sha256.key.der",
        "NULL",
        "NULL");
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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
    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // After the connection is established, authentication is performed
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_EQ(
        HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC014
* @spec  -
* @title The server continues the handshake if the verification fails. After the handshake,
*        the server continues the handshake if the verification fails.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1 is obtained.
*   2. Configure the server not to verify the peer certificate. Expected result 2 is obtained.
*   3. Configure the client and server to support post-handshake extension. Expected result 3 is obtained.
*   4. Set the client server certificate to RSA certificate, and set the client terminal certificate to ECDSA certificate.
*       Expected result 4 is obtained.
*   5. After the connection is established, authentication is performed. Expected result 5 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The setting is successful.
*   4. The setting is successful.
*   5. The connection is successfully established and the authentication is successful.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC014()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the configuration file
    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Configure the server not to verify the peer certificate.
    // Configure the client and server to support post-handshake extension
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportVerifyNone = true;

    // Set the client server certificate to RSA certificate, and set the client terminal certificate to ECDSA
    // certificate.
    HLT_SetCertPath(clientCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        "ecdsa/end256-sha256.key.der",
        "NULL",
        "NULL");
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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

    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // authentication is performed
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_EQ(memcmp(writeBuf, readBuf, readLen), 0);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC015
* @spec  -
* @title During the authentication after the handshake on the client, the server is
*        disconnected because app messages are mixed in the sent messages.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1 is obtained.
*   2. Configure the client and server to support post-handshake extension. Expected result 2 is obtained.
*   3. Establish a connection. The server initiates a handshake for authentication. Expected result 3 is displayed.
*   4. Modify the client to send messages. Enable the client to send an app message before sending the finish message.
*       Expected result 4 is obtained.
*   5. Observe the server behavior. Expected result 5 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The connection is successfully set up and the server initiates authentication.
*   4. The client sends the message successfully.
*   5. The server sends an alert message to disconnect the connection.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC015()
{

    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    // Apply for and initialize the configuration file
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Configure the client and server to support post-handshake extension
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;

    HLT_SetCertPath(clientCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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

    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // the server initiates a handshake for authentication
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    // Enable the client to send an app message before sending the finish message.
    RecWrapper wrapper = {TRY_SEND_FINISH, REC_TYPE_HANDSHAKE, false, NULL, Test_FinishToAPP};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));

    STUB_RESTORE(REC_Write);
    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));

    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_EQ(HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen),
        HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC016
* @spec  -
* @title During authentication after handshake, the server receives multiple app messages after
*        sending the certificate request, and the processing is normal.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1 is obtained.
*   2. Configure the client and server to support post-handshake extension. Expected result 2 is obtained.
*   3. Establish a connection. The server initiates a handshake for authentication. Expected result 3 is obtained.
*   4. Send an app message to the server. After the server processes the message, check the server status.
*      Expected result 4 is obtained.
*   5. Send an app message to the server. After the server processes the message, check the server status.
*       Expected result 5 is obtained.
*   6. Continue the authentication. Expected result 6 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The connection is set up successfully, and the server sends a certificate request message.
*   4. The server is in try_recv_certifiacates state.
*   5. The server is in try_recv_certifiacates state.
*   6. The authentication is successful.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC016()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    // Apply for and initialize the configuration file
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Configure the client and server to support post-handshake extension.
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;

    HLT_SetCertPath(clientCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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

    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // The server initiates a handshake for authentication
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);

    // Send an app message to the server
    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    // Send an app message to the server
    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));

    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    // The authentication is successful.
    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC017
* @spec  -
* @title During post-handshake authentication, the server sends the app message after sending the certificate request
*   message.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1 is obtained.
*   2. Configure the client and server to support post-handshake extension. Expected result 2 is obtained.
*   3. Establish a connection. The server initiates a handshake for authentication. Expected result 3 is displayed.
*   4. The server sends an app message. Expected result 4 is obtained.
*   5. Send an app message from the server. Expected result 5 is obtained.
*   6. Continue the authentication. Expected result 6 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The connection is set up successfully, and the server sends a certificate request message.
*   4. The message is sent successfully.
*   5. The message is sent successfully.
*   6. The authentication is successful.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC017()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    // Apply for and initialize the configuration file
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // Configure the client and server to support post-handshake extension.
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;

    HLT_SetCertPath(clientCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");
    HLT_SetCertPath(serverCtxConfig,
        "rsa_sha256/ca.der:rsa_sha256/inter.der",
        "rsa_sha256/inter.der",
        "rsa_sha256/server.der",
        "rsa_sha256/server.key.der",
        "NULL",
        "NULL");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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

    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // The server initiates a handshake for authentication
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverSslId) == HITLS_SUCCESS);
    ;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    // The server sends an app message
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    // The server sends an app message
    ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    // Continue the authentication.
    HLT_TlsWrite(clientSsl, (uint8_t *)writeBuf, strlen(writeBuf));
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
    HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC018
* @spec  -
* @title Close isSupportPostHandshakeAuth of server, open isSupportClientVerify, the server send certificate request
        successfully
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client support post-handshake extension
*   3. After the connection establishment, the server sends a certificate request message for backhandshake
    authentication.
*   4. Observe client behavior
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. Authentication succeeded.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC018()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply and initialize config
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the client support post-handshake extension
    HLT_SetPostHandshakeAuth(serverConfig, false);
    HLT_SetClientVerifySupport(serverConfig, true);
    HLT_SetPostHandshakeAuth(clientConfig, true);
    HLT_SetClientVerifySupport(clientConfig, true);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    ASSERT_EQ(HITLS_VerifyClientPostHandshake(serverRes->ssl), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    const char *writeBuf = "Hello world";

    ASSERT_TRUE(HLT_TlsWrite(serverRes->ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == HITLS_SUCCESS);
    ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);

    // The client returns alert
    ASSERT_TRUE(HLT_RpcTlsRead(remoteProcess, clientRes->sslId, readBuf, READ_BUF_SIZE, &readLen) == HITLS_SUCCESS);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */
