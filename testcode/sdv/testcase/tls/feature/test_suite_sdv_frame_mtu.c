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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>
#include <regex.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include "securec.h"
#include "bsl_sal.h"
#include "sal_net.h"
#include "frame_tls.h"
#include "cert_callback.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "frame_io.h"
#include "uio_abstraction.h"
#include "tls.h"
#include "tls_config.h"
#include "logger.h"
#include "process.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "stub_utils.h"
#include "hitls_type.h"
#include "frame_link.h"
#include "session_type.h"
#include "common_func.h"
#include "hitls_func.h"
#include "hitls_cert_type.h"
#include "parser_frame_msg.h"
#include "recv_process.h"
#include "simulate_io.h"
#include "rec_wrapper.h"
#include "cipher_suite.h"
#include "alert.h"
#include "conn_init.h"
#include "pack.h"
#include "send_process.h"
#include "cert.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "hs.h"
#include "hs_state_recv.h"
#include "app.h"
#include "record.h"
#include "rec_conn.h"
#include "session.h"
#include "frame_msg.h"
#include "pack_frame_msg.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "sctp_channel.h"
#include "hitls_crypt_init.h"
#include "hitls_session.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "hitls_crypt_reg.h"
#include "crypt_errno.h"
#include "bsl_list.h"
#include "hitls_cert.h"
#include "parse_extensions_client.c"
#include "parse_extensions_server.c"
#include "parse_server_hello.c"
#include "parse_client_hello.c"
/* END_HEADER */

/* @
* @test  UT_TLS_CFG_SET_DTLS_LINK_MTU_API_TC001
* @title  Test HITLS_SetLinkMtu interface
* @brief 1. Create the TLS configuration object config.Expect result 1.
*       2. Use config to create the client and server.Expect result 2.
*       3. Invoke HITLS_SetLinkMtu, Expect result 3.
* @expect 1. The config object is successfully created.
*       2. The client and server are successfully created.
*       3. mtu >= 256, Return HITLS_SUCCESS. mtu < 256, Return HITLS_CONFIG_INVALID_LENGTH.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_DTLS_LINK_MTU_API_TC001(void)
{
    FRAME_Init();
    uint32_t mtu = 1500;

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(HITLS_SetLinkMtu(client->ssl, mtu) == HITLS_SUCCESS);

    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(HITLS_SetLinkMtu(server->ssl, mtu) == HITLS_SUCCESS);
    /* value < 256 */
    mtu = 200;
    ASSERT_TRUE(HITLS_SetLinkMtu(server->ssl, mtu) == HITLS_CONFIG_INVALID_LENGTH);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_SET_NO_QUERY_MTU_API_TC001
* @title Test the HITLS_SetNoQueryMtu interfaces.
* @precon nan
* @brief HITLS_SetNoQueryMtu
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer a non-empty TLS connection handle and set noQueryMtu to an invalid value. Expected result 2.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_NO_QUERY_MTU_API_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Apply for and initialize the configuration file
    config = HITLS_CFG_NewDTLS12Config();
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    HITLS_SetMtu(client->ssl, 16384);
    HITLS_SetMtu(server->ssl, 16384);

    bool noQueryMtu = false;
    ASSERT_TRUE(HITLS_SetNoQueryMtu(NULL, noQueryMtu) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetNoQueryMtu(client->ssl, noQueryMtu) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_SetNoQueryMtu(server->ssl, noQueryMtu) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_GET_NEED_QUERY_MTU_API_TC001
* @title Test the HITLS_GetNeedQueryMtu interfaces.
* @precon nan
* @brief HITLS_GetNeedQueryMtu
* 1. Input an empty TLS connection handle or NULL needQueryMtu pointer. Expected result 1.
* 2. Input non empty ssl ctx and non empty needQueryMtu pointer. Expected result 2.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. HITLS_SUCCES is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_GET_NEED_QUERY_MTU_API_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Apply for and initialize the configuration file
    config = HITLS_CFG_NewDTLS12Config();
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    HITLS_SetMtu(client->ssl, 16384);
    HITLS_SetMtu(server->ssl, 16384);

    bool needQueryMtu = true;
    ASSERT_TRUE(HITLS_GetNeedQueryMtu(NULL, &needQueryMtu) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetNeedQueryMtu(NULL, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetNeedQueryMtu(client->ssl, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_GetNeedQueryMtu(client->ssl, &needQueryMtu) == HITLS_SUCCESS);
    ASSERT_EQ(needQueryMtu, false);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

STUB_DEFINE_RET4(int32_t, REC_Write, TLS_Ctx *, REC_Type, const uint8_t *, uint32_t);
STUB_DEFINE_RET4(int32_t, UdpSocketCtrl, BSL_UIO *, int32_t, int32_t, void *);

int32_t STUB_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    if ((ctx == NULL) || (ctx->recCtx == NULL) ||
        (num != 0 && data == NULL) ||
        (num == 0 && recordType != REC_TYPE_APP)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15537, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record write: input null pointer.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    int32_t ret = HITLS_REC_NORMAL_IO_BUSY;
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    if (ret != HITLS_SUCCESS) {
        if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
            return ret;
        }
        bool exceeded = false;
        (void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_UDP_MTU_EXCEEDED, sizeof(bool), &exceeded);
        if (exceeded) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17362, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Record write: get EMSGSIZE error.", 0, 0, 0, 0);
            ctx->needQueryMtu = true;
        }
    }
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
    return ret;
}

int32_t STUB_UdpSocketCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    (void)uio;
    (void)larg;
    // Simulate EMSGSIZE error: always report MTU exceeded
    if (cmd == BSL_UIO_UDP_MTU_EXCEEDED) {
        *(bool *)parg = true;
    }
    return BSL_SUCCESS;
}

/** @
* @test  UT_TLS_CM_MTU_EMSGSIZE_TC001
* @title Test the HITLS_SetMaxSendFragment
* @precon nan
* @brief HITLS_SetMaxSendFragment
* 1. Create connection. Expected result 1.
* 2. set maxSendFragment to 1000 bytes. Expected result 1.
* 3. Invoke hitls_write to write 1200 bytes. Expected result 2.
* @expect 1. Returns HITLS_SUCCES
* 2. Only 1000 bytes of data is sent
@ */
/* BEGIN_CASE */
void UT_TLS_CM_MTU_EMSGSIZE_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Apply for and initialize the configuration file
    config = HITLS_CFG_NewDTLS12Config();
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    HITLS_SetMtu(client->ssl, 16384);
    HITLS_SetMtu(server->ssl, 16384);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    STUB_REPLACE(REC_Write, STUB_REC_Write);
    STUB_REPLACE(UdpSocketCtrl, STUB_UdpSocketCtrl);

    // STUB_REPLACE cannot update function pointers in structures
    // We need to manually update the UIO's method pointer to point to our STUB
    BSL_UIO *clientUio = client->ssl->uio;
    while (clientUio != NULL && BSL_UIO_GetTransportType(clientUio) != BSL_UIO_UDP) {
        clientUio = BSL_UIO_Next(clientUio);
    }
    if (clientUio != NULL) {
        clientUio->method.uioCtrl = STUB_UdpSocketCtrl;
    }

    BSL_UIO *serverUio = server->ssl->uio;
    while (serverUio != NULL && BSL_UIO_GetTransportType(serverUio) != BSL_UIO_UDP) {
        serverUio = BSL_UIO_Next(serverUio);
    }
    if (serverUio != NULL) {
        serverUio->method.uioCtrl = STUB_UdpSocketCtrl;
    }

    ASSERT_TRUE(HITLS_SetMtu(client->ssl, 500) == HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->config.pmtu, 500);
    const uint8_t sndBuf[1200] = {0};
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(client->ssl, sndBuf, sizeof(sndBuf), &writeLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(writeLen, 0);
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(UdpSocketCtrl);

    bool needQueryMtu = false;

    ASSERT_TRUE(HITLS_GetNeedQueryMtu(client->ssl, &needQueryMtu) == HITLS_SUCCESS);
    ASSERT_EQ(needQueryMtu, true);

    ASSERT_EQ(HITLS_Write(client->ssl, sndBuf, sizeof(sndBuf), &writeLen), HITLS_SUCCESS);
    /* use min mtu 256, and the encrypt cost is need to be reduced */
    ASSERT_TRUE(writeLen < 256);
    ASSERT_TRUE(writeLen > 0);
EXIT:
    STUB_RESTORE(REC_Write);
    STUB_RESTORE(UdpSocketCtrl);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */