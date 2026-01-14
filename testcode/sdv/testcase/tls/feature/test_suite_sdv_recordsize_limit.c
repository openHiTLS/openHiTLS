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
#include <stdio.h>
#include "securec.h"
#include "tls_config.h"
#include "hitls_type.h"
#include "hs.h"
#include "hitls.h"
#include "hlt.h"
#include "tls.h"
#include "common_func.h"
#include "hitls_cert.h"
#include "hitls_func.h"
#include "hitls_config.h"
#include "session_type.h"
#include "hs_ctx.h"
#include "frame_tls.h"
#include "simulate_io.h"
#include "frame_io.h"
#include "frame_link.h"
#include "hlt_type.h"
#include "record.h"
#include "alert.h"
#include "rec_crypto.h"
#include "rec_wrapper.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "session.h"
#include "pack.h"
#include "pack_extensions.h"
#include "stub_utils.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET1(int32_t, REC_RecOutBufReSet, TLS_Ctx *);
STUB_DEFINE_RET2(uint8_t, RecConnGetCbcPaddingLen, uint8_t, uint32_t);

#define MAX_CBC_PADDING_LENGTH 255
#define REC_1024_PLAIN_LENGTH 1024
#define MAX_RECORD_LENTH (20 * 1024)
#define READ_BUF_LEN_18K (18 * 1024)
#define REC_MAX_PLAIN_LENGTH 16384
#define TLC_RECORD_HEAD_LENGTH 5
#define DTLS_RECORD_HEAD_LENGTH 13
#define MAX_MAC_AND_IV_LENGTH 64
#define MAX_RECORD_PADDING_LENGTH 256
#define RECORD_WRITE_PADDING_LENGTH 16
#define DTLS_OVER_UDP_DEFAULT_PMTU 1500
#define REC_IP_UDP_HEAD_SIZE 28
#define SINGLE_CIPHER_SUITE_SIZE 2u
#define TLS_MAX_INBUFF_LENGTH (REC_MAX_PLAIN_LENGTH + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + MAX_RECORD_PADDING_LENGTH)
#define TLS_MAX_OUTBUFF_LENGTH (REC_MAX_PLAIN_LENGTH + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + RECORD_WRITE_PADDING_LENGTH)

uint8_t RecConnGetCbcPaddingLen(uint8_t blockLen, uint32_t plaintextLen);
uint8_t STUB_RecConnGetCbcPaddingLen(uint8_t blockLen, uint32_t plaintextLen)
{
    (void)blockLen;
    (void)plaintextLen;
    return MAX_CBC_PADDING_LENGTH;
}

uint8_t STUB_RecConnGetCbcPaddingLen_254(uint8_t blockLen, uint32_t plaintextLen)
{
    (void)blockLen;
    (void)plaintextLen;
    return MAX_CBC_PADDING_LENGTH - 1;
}

int32_t STUB_REC_RecBufReSet(TLS_Ctx *ctx)
{
    uint32_t inbuf_2048 = 2048 + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + MAX_RECORD_PADDING_LENGTH;
    uint32_t outbuf_max = TLS_MAX_INBUFF_LENGTH;
    RecCtx *recCtx = ctx->recCtx;
    int32_t ret = RecBufResize(recCtx->inBuf, inbuf_2048);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return RecBufResize(recCtx->outBuf, outbuf_max);
}

HITLS_Config *Creat_Config(int version)
{
    if (version == TLS1_2) {
        return HITLS_CFG_NewTLS12Config();
    } else if (version == TLS1_3) {
        return HITLS_CFG_NewTLS13Config();
    } else if (version == DTLS1_2) {
        return HITLS_CFG_NewDTLS12Config();
    }
    return NULL;
}

void Calculate_Limitsize(int version, int limit, bool isenableMiniaturization, uint32_t* inbufsize, uint32_t* outbufsize)
{
    if (version == TLS1_2) {
        *inbufsize = limit + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + MAX_RECORD_PADDING_LENGTH;
        *outbufsize = limit + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + RECORD_WRITE_PADDING_LENGTH;
    } else if (version == TLS1_3) {
        if (limit == REC_MAX_PLAIN_LENGTH) {
            *inbufsize = limit + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + MAX_RECORD_PADDING_LENGTH;
            *outbufsize = limit + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + RECORD_WRITE_PADDING_LENGTH;
        }else {
            *inbufsize = (limit-1) + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + MAX_RECORD_PADDING_LENGTH;
            *outbufsize = (limit-1) + TLC_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + RECORD_WRITE_PADDING_LENGTH;
        }
    } else if (version == DTLS1_2) {
        if (isenableMiniaturization && (limit + DTLS_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + MAX_RECORD_PADDING_LENGTH) >= DTLS_OVER_UDP_DEFAULT_PMTU) {
            *outbufsize = DTLS_OVER_UDP_DEFAULT_PMTU - REC_IP_UDP_HEAD_SIZE;
        } else {
            *outbufsize = limit + DTLS_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + RECORD_WRITE_PADDING_LENGTH;
        }
        *inbufsize = limit + DTLS_RECORD_HEAD_LENGTH + MAX_MAC_AND_IV_LENGTH + MAX_RECORD_PADDING_LENGTH;
    }
}

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC001
* @spec -
* @title TLS12 caches the peer certificate by default.
* @precon nan
* @brief
* 1. Enable the macro of variable_buffer_length. Initialize the TLS12 client and server, set up a link, and check the values of
*    ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize.
* 2. Stop the client in the Try Send Client Key Exchange state, and check the values of ctx->recCtx->inBuf->bufSize and
*    ctx->recCtx->outBuf->bufSize.
* 3. Continue to establish links.
* 4. Change the protocol version to TLS13, repeat the preceding steps, and check the values of ctx->recCtx->inBuf->bufSize
*    and ctx->recCtx->outBuf->bufSize.
* 5. Change the protocol version to DTLS 12 over UDP, repeat the preceding steps, and check the values of
*    ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize.
* @expect
* 1. ctx->recCtx->inBuf->bufSize position (16384+5+64+256 = 16709), ctx->recCtx->outBuf->bufSize position(16384+5+64+16 = 16469)
* 2. ctx->recCtx->inBuf->bufSize position (16384+5+64+256 = 16709), ctx->recCtx->outBuf->bufSize position(16384+5+64+16 = 16469)
* 3. Complete construction success
* 4. ctx->recCtx->inBuf->bufSize position (16384+5+64+256 = 16709), ctx->recCtx->outBuf->bufSize position(16384+5+64+16 = 16469)
* 5. ctx->recCtx->inBuf->bufSize configuration (16384+13+64+256 = 16717), ctx->recCtx->outBuf->bufSize configuration (16384+13+64+16 = 16477)
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC001(int version, int connType)
{
    FRAME_Init();

    uint32_t inbufsize;
    uint32_t outbufsize;
    Calculate_Limitsize(version, REC_MAX_PLAIN_LENGTH, false, &inbufsize, &outbufsize);
    if(version == DTLS1_2){
        outbufsize = DTLS_OVER_UDP_DEFAULT_PMTU - REC_IP_UDP_HEAD_SIZE;
    }

    HITLS_Config *c_config = Creat_Config(version);
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = Creat_Config(version);
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, connType);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, connType);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize);

    if (version == TLS1_3) {
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    } else {
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);
    }

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC002
* @spec -
* @title Negotiated record size during record_size_limit extension
* @precon nan
* @brief
* 1. Set record_size_limit to 2000, initialize the TLS12 client and server, and set up a link. Check the values of
*    ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize.
* 2. Stop the client in the Try Send Client Key Exchange state, and check the values of ctx->recCtx->inBuf->bufSize and
*    ctx->recCtx->outBuf->bufSize.
* 3. Continue to establish links.
* 4. Change the protocol version to TLS13, repeat the preceding steps, and check the values of ctx->recCtx->inBuf->bufSize
*    and ctx->recCtx->outBuf->bufSize.
* 5. Change the protocol version to DTLS12 over UDP, repeat the preceding steps, and check the valuesof ctx->recCtx->inBuf->bufSize
*    and ctx->recCtx->outBuf->bufSize.
* 6. Change the protocol version to DTLS12 over UDP and record-size limit to 1000. Check the values of
*   ctx->recCtx->inBuf->bufSize and record-size limit.
* @expect
* 1. ctx->recCtx->inBuf->bufSize orientation (2000+5+64+256 = 2325), ctx->recCtx->outBuf->bufSize orientation (2000+5+64+16 = 2085)
* 2. ctx->recCtx->inBuf->bufSize orientation (2000+5+64+256 = 2325), ctx->recCtx->outBuf->bufSize orientation (2000+5+64+16 = 2085)
* 3. Complete construction success
* 4. ctx->recCtx->inBuf->bufSize configuration (1999+5+64+256 = 2324), ctx->recCtx->outBuf->bufSize configuration (1999+5+64+16 = 2084)
* 5. ctx->recCtx->inBuf->bufSize configuration (1500-20-8 = 1472), ctx->recCtx->outBuf->bufSize configuration (1500-20-8 = 1472)
* 6. ctx->recCtx->inBuf->bufSize orientation (1000+13+64+256 = 1333), ctx->recCtx->outBuf->bufSize orientation (1000+13+64+16 = 1093)
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC002(int version, int connType, int limit)
{
    FRAME_Init();

    uint32_t inbufsize;
    uint32_t outbufsize;
    if (version == DTLS1_2) {
        Calculate_Limitsize(version, limit, true, &inbufsize, &outbufsize);
    } else {
        Calculate_Limitsize(version, limit, false, &inbufsize, &outbufsize);
    }

    HITLS_Config *c_config = Creat_Config(version);
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = Creat_Config(version);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, limit) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, limit) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, connType);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, connType);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    if (version == TLS1_3) {
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    } else {
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);
    }

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_CheckRecordBuffSize(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)bufSize;
    (void)user;
    (void)data;
    (void)len;

    uint32_t inbufsize;
    uint32_t outbufsize;
    Calculate_Limitsize(DTLS1_2, 900, true, &inbufsize, &outbufsize);
    ASSERT_EQ(ctx->recCtx->outBuf->bufSize, outbufsize);
EXIT:
    return;
}
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC002_UDP_900_Client()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, 8888, true);
    ASSERT_TRUE(remoteProcess != NULL);

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_KEY_EXCHANGE,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_CheckRecordBuffSize
    };
    RegisterWrapper(wrapper);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetRecordSizeLimit(serverCtxConfig, 900);
    serverCtxConfig->readAhead = 0;
    serverRes = HLT_ProcessTlsAccept(remoteProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetRecordSizeLimit(clientCtxConfig, 900);
    clientCtxConfig->readAhead = 0;
    clientRes = HLT_ProcessTlsConnect(localProcess, DTLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC002_UDP_900_Server()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, 8888, true);
    ASSERT_TRUE(remoteProcess != NULL);

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_CheckRecordBuffSize
    };
    RegisterWrapper(wrapper);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetRecordSizeLimit(serverCtxConfig, 900);
    serverRes = HLT_ProcessTlsAccept(localProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetRecordSizeLimit(clientCtxConfig, 900);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC003
* @spec -
* @title Record change in the client renegotiation scenario
* @precon nan
* @brief
* 1. Enable the variable_buffer_length feature macro. The client and server support record_size_limit. Set the negotiated
*    length to 5000 and establish a link.
* 2. Set record_size_limit to 2000 on the server and client. Check the values of ctx->recCtx->inBuf->bufSize and
*    record_size_limit.
* 3. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the server attempts to send
*    a Hello message.
* 4. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the client attempts to send
*    the key exchange packet.
* 5. Continue the renegotiation.
* @expect
* 1. The link is established, and the value of variable_buffer_length is 5000.
* 2. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (5000 + 5 + 64 + 16 = 5085)
* 3. ctx->recCtx->inBuf->bufSize (2000 + 5 + 64 + 256 = 2325) The ctx->recCtx->outBuf->bufSize value is (2000 + 5 + 64 + 16 = 2085)
* 4. ctx->recCtx->inBuf->bufSize (2000 + 5 + 64 + 256 = 2325) The ctx->recCtx->outBuf->bufSize value is (2000 + 5 + 64 + 16 = 2085)
* 5. Renegotiation completed
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC003(void)
{
    FRAME_Init();

    uint32_t inbufsize_5000;
    uint32_t outbufsize_5000;
    Calculate_Limitsize(TLS1_2, 5000, false, &inbufsize_5000, &outbufsize_5000);

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 5000) == HITLS_SUCCESS);
    HITLS_CFG_SetRenegotiationSupport(c_config, true);
    HITLS_CFG_SetRenegotiationSupport(s_config, true);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL) ;

    FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);

    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->negotiatedInfo.isRenegotiation = true);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&client->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&server->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    uint32_t inbufsize_2000;
    uint32_t outbufsize_2000;
    Calculate_Limitsize(TLS1_2, 2000, false, &inbufsize_2000, &outbufsize_2000);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize_2000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_2000);

    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC004
* @spec -
* @title Record change in the server renegotiation scenario
* @precon nan
* @brief
* 1. Enable the variable_buffer_length feature macro. The client and server support record_size_limit. Set the negotiated
*    length to 5000 and establish a link.
* 2. The server initiates renegotiation. The client and server negotiate record_size_limit to 2000. The server checks
*    ctx->recCtx->inBuf->bufSize and record_size_limit.
* 3. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the client attempts to receive
*    Hello packets from the server. Expected result 3 is displayed.
* 4. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the server attempts to send a
*    Hello message. Expected result 4 is displayed.
* 5. Continue the renegotiation.
* @expect
* 1. The link is established, and the value of variable_buffer_length is 5000.
* 2. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (5000 + 5 + 64 + 16 = 5085)
* 3. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (2000 + 5 + 64 + 16 = 5085)
* 4. ctx->recCtx->inBuf->bufSize (2000 + 5 + 64 + 256 = 2325) The ctx->recCtx->outBuf->bufSize value is (2000 + 5 + 64 + 16 = 2085)
* 5. Renegotiation completed
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC004(void)
{
    FRAME_Init();

    uint32_t inbufsize_5000;
    uint32_t outbufsize_5000;
    Calculate_Limitsize(TLS1_2, 5000, false, &inbufsize_5000, &outbufsize_5000);

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(c_config, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(s_config, true) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL) ;

    FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);

    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->negotiatedInfo.isRenegotiation = true);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&client->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&server->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);

    uint32_t inbufsize_2000;
    uint32_t outbufsize_2000;
    Calculate_Limitsize(TLS1_2, 2000, false, &inbufsize_2000, &outbufsize_2000);

    HITLS_Accept(server->ssl);
    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize_2000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_2000);

    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC005
* @spec -
* @title Enable dual-end authentication during renegotiation.
* @precon nan
* @brief
* 1. Enable the variable_buffer_length feature macro. The client and server support record_size_limit. Set the negotiated
*    length to 5000 and establish a link.
* 2. The server initiates renegotiation. The client and server negotiate record_size_limit to 2000. The server checks
*    ctx->recCtx->inBuf->bufSize and record_size_limit.
* 3. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the client attempts to receive
*    Hello packets from the server.
* 4. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the server attempts to send a
*    Hello message.
* 5. Continue the renegotiation.
* @expect
* 1. The link is established, and the value of variable_buffer_length is 5000.
* 2. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (5000 + 5 + 64 + 16 = 5085)
* 3. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (2000 + 5 + 64 + 16 = 2085)
* 4. ctx->recCtx->inBuf->bufSize (2000 + 5 + 64 + 256 = 2325) The ctx->recCtx->outBuf->bufSize value is (2000 + 5 + 64 + 16 = 2085)
* 5. Renegotiation completed
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC005(void)
{
    FRAME_Init();

    uint32_t inbufsize_5000;
    uint32_t outbufsize_5000;
    Calculate_Limitsize(TLS1_2, 5000, false, &inbufsize_5000, &outbufsize_5000);

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(c_config, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(s_config, false) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL) ;

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->negotiatedInfo.isRenegotiation = true);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&client->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&server->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);

    uint8_t readbuff[READ_BUF_LEN_18K];
    uint32_t readLen = 0;
    uint32_t inbufsize_2000;
    uint32_t outbufsize_2000;
    Calculate_Limitsize(TLS1_2, 2000, false, &inbufsize_2000, &outbufsize_2000);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    ASSERT_EQ(HITLS_Read(server->ssl, readbuff, READ_BUF_LEN_18K, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    FRAME_TrasferMsgBetweenLink(server, client);
    HITLS_Connect(client->ssl);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC006
* @spec -
* @title The length of the sent app message exceeds the plaintext size required by the record.
* @precon nan
* @brief
* 1. Enable the variable_buffer_length feature macro, set record_size_limit to 100 on the client and server, and establish a link.
* 2. The client and server invoke hitls_write to send a 200-byte app message.
* @expect
* 1. Link setup success
* 2. The output parameter value is 100, and the interface returns HITLS_SUCCESS.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC006(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 100) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 100) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL) ;

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t writeData[200] = {"abcd1234"};
    uint32_t writeLen = 200;
    uint8_t writeData2[] = {"abcd1234"};
    uint32_t writeLen2 = strlen("abcd1234");
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    uint32_t readLen = MAX_RECORD_LENTH;
    uint32_t outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, writeData, writeLen, &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, 100);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, readData, MAX_RECORD_LENTH, &readLen), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Write(server->ssl, writeData2, writeLen2, &outLen), HITLS_SUCCESS);
    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, readData, MAX_RECORD_LENTH, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, writeLen2);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);
    ASSERT_EQ(outLen, writeLen2);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC007
* @spec -
* @title The record size limit is negotiated during the first link establishment. The client initiates renegotiation
*        and fails to negotiate the record size limit.
* @precon nan
* @brief
* 1. Enable the variable_buffer_length feature macro. The client and server support record_size_limit. Set the negotiated
*    length to 5000 and establish a link.
* 2. Initiate renegotiation on the client. Check the ctx->recCtx->inBuf->bufSize and record_size_limit values.
* 3. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the server attempts to send a
*    Hello message.
* 4. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the client attempts to send the
*    key exchange packet.
* 5. Continue the renegotiation.
* @expect
* 1. The link is established, and the value of variable_buffer_length is 5000.
* 2. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (5000 + 5 + 64 + 16 = 5085)
* 3. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (16384 + 5 + 64 + 16 = 16469)
* 4. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (16384 + 5 + 64 + 16 = 16469)
* 5. Renegotiation completed
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC007(void)
{
    FRAME_Init();

    uint32_t inbufsize_5000;
    uint32_t outbufsize_5000;
    Calculate_Limitsize(TLS1_2, 5000, false, &inbufsize_5000, &outbufsize_5000);

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(c_config, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(s_config, true) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL) ;

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);

    server->ssl->config.tlsConfig.recordSizeLimit = 0;

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, TLS_MAX_OUTBUFF_LENGTH);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, TLS_MAX_OUTBUFF_LENGTH);

    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC008
* @spec -
* @title The record size limit is negotiated during the first link establishment. The server initiates renegotiation,
*        and the record size limit negotiation fails.
* @precon nan
* @brief
* 1. Enable the variable_buffer_length feature macro. The client and server support record_size_limit. Set the negotiated
*    length to 5000 and establish a link.
* 2. The server initiates renegotiation. The client does not support record_size_limit. Check the values of
*    ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize.
* 3. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the server attempts to send a
*    Hello message.
* 4. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the client attempts to send the
*    key exchange packet.
* 5. Continue the renegotiation.
* @expect
1. The link is established, and the value of variable_buffer_length is 5000.
2. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (5000 + 5 + 64 + 16 = 5085)
3. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (16384 + 5 + 64 + 16 = 16469)
4. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (16384 + 5 + 64 + 16 = 16469)
5. Renegotiation completed
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC008(void)
{
    FRAME_Init();

    uint32_t inbufsize_5000;
    uint32_t outbufsize_5000;
    Calculate_Limitsize(TLS1_2, 5000, false, &inbufsize_5000, &outbufsize_5000);

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(c_config, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(s_config, true) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL) ;

    FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);

    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->negotiatedInfo.isRenegotiation = true);

    client->ssl->config.tlsConfig.recordSizeLimit = 0 ;

    HITLS_Accept(server->ssl);
    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_5000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, TLS_MAX_OUTBUFF_LENGTH);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, TLS_MAX_OUTBUFF_LENGTH);

    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_Variable_Buffer_Length_TC009
* @spec -
* @title The record size limit is not negotiated during the first link setup and is negotiated during link renegotiation.
* @precon nan
* @brief
* 1. Enable the variable_buffer_length feature macro. The client and server do not support record_size_limit. Establish a link.
* 2. The client initiates renegotiation. The client supports record_size_limit 2000. Check the values of
*    ctx->recCtx->inBuf->bufSize and record_size_limit.
* 3. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the server attempts to send a
*    Hello message.
* 4. Check the values of ctx->recCtx->inBuf->bufSize and ctx->recCtx->outBuf->bufSize when the client attempts to send the
*    key exchange packet.
* 5. Continue the renegotiation.
* @expect
* 1. Link establishment completed
* 2. ctx->recCtx->inBuf->bufSize (16384 + 5 + 64 + 256 = 16709) The ctx->recCtx->outBuf->bufSize value is (16384 + 5 + 64 + 16 = 16469)
* 3. ctx->recCtx->inBuf->bufSize (2000 + 5 + 64 + 256 = 2325). The ctx->recCtx->outBuf->bufSize value is (200 + 5 + 64 + 16 = 2085)
* 4. ctx->recCtx->inBuf->bufSize (2000 + 5 + 64 + 256 = 2325). The ctx->recCtx->outBuf->bufSize value is (200 + 5 + 64 + 16 = 2085)
* 5. Renegotiation completed
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC009(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(c_config, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRenegotiationSupport(s_config, true) == HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);

    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 5000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 5000) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->negotiatedInfo.isRenegotiation = true);

    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&client->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(&server->ssl->config.tlsConfig, 2000) == HITLS_SUCCESS);

    uint32_t inbufsize_2000;
    uint32_t outbufsize_2000;
    Calculate_Limitsize(TLS1_2, 2000, true, &inbufsize_2000, &outbufsize_2000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, TLS_MAX_OUTBUFF_LENGTH);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, outbufsize_2000);

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->recCtx->outBuf->bufSize, outbufsize_2000);

    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_HiTLS_Variable_Buffer_Length_TC010
* @spec  -
* @title  Set recor size limit to 100 and enable the AEAD/NULL algorithm suite to send a 1000-byte APP message.
* @precon  nan
* @brief
* 1. Initialize the client and server and set record size limit to 1000.
* 2. Set the client-side and server-side cipher suites to HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
* 3. Establish a link.
* 4. Send 1000 app messages from the client to the server.
* 5. Set the cipher suite to HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 and repeat the preceding operations.
* @expect
* 1. Initialization succeeded.
* 2. Setting succeeded.
* 3. Link setup success
* 4. Data read/write success
* 5. Data read/write success
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC010(char* ciphersuite)
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
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    HLT_SetRecordSizeLimit(serverConfig, 1000);
    HLT_SetRecordSizeLimit(clientConfig, 1000);

    if (strstr(ciphersuite, "PSK") != NULL) {
        memcpy_s(clientConfig->psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));
        memcpy_s(serverConfig->psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));
    }

    HLT_SetCipherSuites(serverConfig, ciphersuite);
    HLT_SetCipherSuites(clientConfig, ciphersuite);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t writeData[1000] = {1};
    uint32_t writeLen = 1000;
    uint8_t readData[1000] = {0};
    uint32_t readLen = 1000;

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, clientRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(readLen, 1000);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_EQ(HLT_ProcessTlsWrite(remoteProcess, serverRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, clientRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(readLen, 1000);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_HiTLS_Variable_Buffer_Length_TC011
* @spec  -
* @title  Set record size limit to 1000, CBC to enable/disable EncryptThenMac, padding length to 255, and client to send
*            a 1000-byte app message.
* @precon  nan
* @brief
* 1. Initialize the client and server and set record size limit to 1000.
* 2. Set the client-side and server-side cipher suites to HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.
* 3. Set padding to 255 in RecConnGetCbcPaddingLen and establish a link.
* 4. Send 1000 app messages from the client.
* @expect
* 1. Initialization succeeded.
* 2. Setting succeeded.
* 3. Link setup success
* 4. Data read/write success
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC011(int supportEncThenMac)
{
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecBufReSet);

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
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    HLT_SetRecordSizeLimit(serverConfig, REC_1024_PLAIN_LENGTH);
    HLT_SetRecordSizeLimit(clientConfig, REC_1024_PLAIN_LENGTH);

    HLT_SetCipherSuites(serverConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
    HLT_SetCipherSuites(serverConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
    HLT_SetEncryptThenMac(serverConfig, supportEncThenMac);
    HLT_SetEncryptThenMac(clientConfig, supportEncThenMac);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t writeData[REC_1024_PLAIN_LENGTH] = {1};
    uint32_t writeLen = REC_1024_PLAIN_LENGTH;
    uint8_t readData[REC_1024_PLAIN_LENGTH] = {0};
    uint32_t readLen = REC_1024_PLAIN_LENGTH;

    HITLS_Ctx *ctx = clientRes->ssl;
    RecConnState *state = ctx->recCtx->writeStates.currentState;
    uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(ctx, state->suiteInfo,
        REC_1024_PLAIN_LENGTH, false);
    ASSERT_EQ((ciphertextLen - REC_1024_PLAIN_LENGTH - MAX_MAC_AND_IV_LENGTH), 16);
    STUB_REPLACE(RecConnGetCbcPaddingLen, STUB_RecConnGetCbcPaddingLen);

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, clientRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(readLen, REC_1024_PLAIN_LENGTH);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(RecConnGetCbcPaddingLen);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_HiTLS_Variable_Buffer_Length_TC012
* @spec  -
* @title  Set record size limit to 1000, CBC to enable/disable EncryptThenMac, padding length to 255, and server to send
*            a 1000-byte app message.
* @precon  nan
* @brief
* 1. Initialize the client and server and set record size limit to 1000.
* 2. Set the client-side and server-side cipher suites to HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.
* 3. Call the stub function RecConnGetCbcPaddingLen to set padding to 255 and establish a link.
* 4. Send 1000 app messages from the server.
* @expect
* 1. Initialization succeeded.
* 2. Setting succeeded.
* 3. Link setup success
* 4. Data read/write success
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC012(int supportEncThenMac)
{
    STUB_REPLACE(REC_RecOutBufReSet, STUB_REC_RecBufReSet);

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
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    HLT_SetRecordSizeLimit(serverConfig, REC_1024_PLAIN_LENGTH);
    HLT_SetRecordSizeLimit(clientConfig, REC_1024_PLAIN_LENGTH);

    HLT_SetCipherSuites(serverConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
    HLT_SetCipherSuites(serverConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
    HLT_SetEncryptThenMac(serverConfig, supportEncThenMac);
    HLT_SetEncryptThenMac(clientConfig, supportEncThenMac);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t writeData[REC_1024_PLAIN_LENGTH] = {1};
    uint32_t writeLen = REC_1024_PLAIN_LENGTH;
    uint8_t readData[REC_1024_PLAIN_LENGTH] = {0};
    uint32_t readLen = REC_1024_PLAIN_LENGTH;

    STUB_REPLACE(RecConnGetCbcPaddingLen, STUB_RecConnGetCbcPaddingLen);

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, serverRes, writeData, writeLen), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(readLen, REC_1024_PLAIN_LENGTH);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    STUB_RESTORE(REC_RecOutBufReSet);
    STUB_RESTORE(RecConnGetCbcPaddingLen);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_HiTLS_Variable_Buffer_Length_TC013
* @spec  -
* @title  Set record size limit to 1000. The client/server of the AEAD/NULL/CBC_ETM/CBC_MTE cipher suite receives a 1001-byte message.
* @precon  nan
* @brief
* 1. Initialize the client and server and set record size limit to 1000. Expected result 1 is displayed.
* 2. Set the client/server cipher suite to HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 and set the PSK.
* 3. Establish a link.
* 4. Send 1000 + 1 app messages from the client to the server.
* 5. Set the cipher suite to HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 and repeat the preceding operations.
* 6. Set the cipher suite to HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, set the padding length to 254, and enable or disable
*    EncryptThenMac. Repeat the preceding operations.
* @expect
* 1. Initialization succeeded.
* 2. Setting succeeded.
* 3. Link setup success
* 4. HITLS_REC_RECORD_OVERFLOW is returned and the link is disconnected.
* 5. HITLS_REC_RECORD_OVERFLOW is returned and the link is disconnected.
* 6. HITLS_REC_RECORD_OVERFLOW is returned and the link is disconnected.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_Variable_Buffer_Length_TC013(int isclient, int isEncryptThenMac)
{
    FRAME_Init();

    uint16_t ciphersuite1[] = {HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384};
    for (int i = 0; i < 2; i++){
        HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
        ASSERT_TRUE(tlsConfig != NULL);

        HITLS_CFG_SetEncryptThenMac(tlsConfig, isEncryptThenMac);
        HITLS_CFG_SetCipherSuites(tlsConfig, ciphersuite1 + i, 1);

        HITLS_CFG_SetPskClientCallback(tlsConfig, ExampleClientCb);
        HITLS_CFG_SetPskServerCallback(tlsConfig, ExampleServerCb);

        ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(tlsConfig, REC_1024_PLAIN_LENGTH) == HITLS_SUCCESS);

        FRAME_LinkObj *client = NULL;
        FRAME_LinkObj *server = NULL;
        client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
        server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
        ASSERT_TRUE(client != NULL);
        ASSERT_TRUE(server != NULL);

        ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

        ASSERT_EQ(server->ssl->recCtx->outBuf->bufSize, 1109);

        STUB_REPLACE(RecConnGetCbcPaddingLen, STUB_RecConnGetCbcPaddingLen_254);

        uint8_t msg[REC_1024_PLAIN_LENGTH + 1] = {0x01, 0x00};
        REC_TextInput plainMsg = {  .type = REC_TYPE_APP,
                                    .isEncryptThenMac = isEncryptThenMac,
                                    .negotiatedVersion = HITLS_VERSION_TLS12,
                                    .version = HITLS_VERSION_TLS12,
                                    .text = msg,
                                    .textLen = REC_1024_PLAIN_LENGTH + 1};
        if (isclient) {
            RecConnState *state =  client->ssl->recCtx->writeStates.currentState;
            BSL_Uint64ToByte(state->seq, plainMsg.seq);
            uint8_t writeBuf[READ_BUF_LEN_18K] = {0};
            uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(client->ssl, state->suiteInfo, REC_1024_PLAIN_LENGTH + 1, false);
            RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

            writeBuf[0] = REC_TYPE_APP;
            BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
            BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

            FrameUioUserData *ioClientData = BSL_UIO_GetUserData(server->io);
            memcpy_s(ioClientData->recMsg.msg, ciphertextLen+5, writeBuf, ciphertextLen+5);
            ioClientData->recMsg.len = ciphertextLen+5;

            STUB_RESTORE(RecConnGetCbcPaddingLen);
            uint32_t readbytes = 0;
            uint8_t dest[READ_BUF_LEN_18K] = {0};

            ASSERT_EQ(HITLS_Read(server->ssl, dest, READ_BUF_LEN_18K, &readbytes), HITLS_REC_RECORD_OVERFLOW);

            ALERT_Info info = {0};
            ALERT_GetInfo(server->ssl, &info);
            ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
            ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
            ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
        } else {
            RecConnState *state =  server->ssl->recCtx->writeStates.currentState;
            BSL_Uint64ToByte(state->seq, plainMsg.seq);
            uint8_t writeBuf[READ_BUF_LEN_18K] = {0};
            uint32_t ciphertextLen = RecGetCryptoFuncs(state->suiteInfo)->calCiphertextLen(server->ssl, state->suiteInfo, REC_1024_PLAIN_LENGTH + 1, false);
            RecConnEncrypt(NULL, state, &plainMsg, writeBuf + REC_TLS_RECORD_HEADER_LEN, ciphertextLen);

            writeBuf[0] = REC_TYPE_APP;
            BSL_Uint16ToByte(HITLS_VERSION_TLS12, &writeBuf[1]);
            BSL_Uint16ToByte((uint16_t)ciphertextLen, &writeBuf[REC_TLS_RECORD_LENGTH_OFFSET]);

            FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
            memcpy_s(ioClientData->recMsg.msg, ciphertextLen+5, writeBuf, ciphertextLen+5);
            ioClientData->recMsg.len = ciphertextLen+5;

            STUB_RESTORE(RecConnGetCbcPaddingLen);
            uint32_t readbytes = 0;
            uint8_t dest[READ_BUF_LEN_18K] = {0};

            ASSERT_EQ(HITLS_Read(client->ssl, dest, READ_BUF_LEN_18K, &readbytes), HITLS_REC_RECORD_OVERFLOW);

            ALERT_Info info = {0};
            ALERT_GetInfo(client->ssl, &info);
            ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
            ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
            ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
        }
        HITLS_CFG_FreeConfig(tlsConfig);
        FRAME_FreeLink(client);
        FRAME_FreeLink(server);
    }
EXIT:
;
}
/* END_CASE */
