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
#include "hitls_type.h"
#include "frame_link.h"
#include "session_type.h"
#include "common_func.h"
#include "hitls_func.h"
#include "hitls_cert_type.h"
#include "cert_mgr_ctx.h"
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
#include "uio_udp.c"
/* END_HEADER */

/** @
* @test  UT_TLS_CFG_SET_GET_REC_INBUFFER_SIZE_API_TC001
* @title Test the HITLS_CFG_SetRecInbufferSize and HITLS_CFG_GetRecInbufferSize.
* @precon nan
* @brief HITLS_CFG_SetRecInbufferSize
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer a non-empty TLS connection handle and set recInbufferSize to an invalid value. Expected result 2.
* 3. Transfer a non-empty TLS connection handle information and set recInbufferSize to a valid value. Expected result 3
* HITLS_CFG_GetRecInbufferSize
* 1. Input an empty TLS connection handle or NULL recInbufferSize pointer. Expected result 1.
* 2. Transfer a non-empty TLS connection handle and recInbufferSize pointer.Expected result 3.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. HITLS_CONFIG_INVALID_LENGTH is returned
* 3. Returns HITLS_SUCCES.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_GET_REC_INBUFFER_SIZE_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    config = HITLS_CFG_NewTLS12Config();

    uint32_t recInbufferSize = 18433;
    ASSERT_TRUE(HITLS_CFG_SetRecInbufferSize(NULL, recInbufferSize) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetRecInbufferSize(config, recInbufferSize) == HITLS_CONFIG_INVALID_LENGTH);
    /* value < 512 */
    recInbufferSize = 511;
    ASSERT_TRUE(HITLS_CFG_SetRecInbufferSize(config, recInbufferSize) == HITLS_CONFIG_INVALID_LENGTH);
    /* 18432 > value > 512 */
    recInbufferSize = 1000;
    ASSERT_TRUE(HITLS_CFG_SetRecInbufferSize(config, recInbufferSize) == HITLS_SUCCESS);

    uint32_t recInbufferSize2 = 0;
    ASSERT_TRUE(HITLS_CFG_GetRecInbufferSize(NULL, &recInbufferSize2) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetRecInbufferSize(config, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetRecInbufferSize(config, &recInbufferSize2) == HITLS_SUCCESS);
    ASSERT_EQ(recInbufferSize2, 1000);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test  UT_TLS_CM_SET_GET_REC_INBUFFER_SIZE_API_TC001
* @title Test the HITLS_SetRecInbufferSize and HITLS_GetRecInbufferSize.
* @precon nan
* @brief HITLS_SetRecInbufferSize
* 1. Input an empty TLS connection handle. Expected result 1.
* 2. Transfer a non-empty TLS connection handle and set recInbufferSize to an invalid value. Expected result 2.
* 3. Transfer a non-empty TLS connection handle information and set recInbufferSize to a valid value. Expected result 3
* HITLS_GetRecInbufferSize
* 1. Input an empty TLS connection handle or NULL recInbufferSize pointer. Expected result 1.
* 2. Transfer a non-empty TLS connection handle and recInbufferSize pointer.Expected result 3.
* @expect 1. Returns HITLS_NULL_INPUT
* 2. HITLS_CONFIG_INVALID_LENGTH is returned
* 3. Returns HITLS_SUCCES.
@ */
/* BEGIN_CASE */
void UT_TLS_CM_SET_GET_REC_INBUFFER_SIZE_API_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    config = HITLS_CFG_NewDTLS12Config();
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    /* value > 18432 */
    uint32_t recInbufferSize = 18433;
    ASSERT_TRUE(HITLS_SetRecInbufferSize(NULL, recInbufferSize) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetRecInbufferSize(ctx, recInbufferSize) == HITLS_CONFIG_INVALID_LENGTH);
    /* value < 512 */
    recInbufferSize = 511;
    ASSERT_TRUE(HITLS_SetRecInbufferSize(ctx, recInbufferSize) == HITLS_CONFIG_INVALID_LENGTH);
    /* 18432 > value > 512 */
    recInbufferSize = 1000;
    ASSERT_TRUE(HITLS_SetRecInbufferSize(ctx, recInbufferSize) == HITLS_SUCCESS);

    uint32_t recInbufferSize2 = 0;
    ASSERT_TRUE(HITLS_GetRecInbufferSize(NULL, &recInbufferSize2) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetRecInbufferSize(ctx, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetRecInbufferSize(ctx, &recInbufferSize2) == HITLS_SUCCESS);
    ASSERT_EQ(recInbufferSize2, 1000);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */
