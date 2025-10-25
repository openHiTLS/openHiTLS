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

#include "securec.h"
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
#include "cert.h"
#include "conn_init.h"
/* END_HEADER */

#define g_uiPort 12121

/** @
* @test UT_TLS_TLS12_RFC8422_CONSISTENCY_ECDHE_LOSE_POINT_FUNC_TC001
* @title clienthello does not carry the point format extension.
* @precon nan
* @brief  Set the ECC cipher suite. Before the server receives the client hello message, the point format extension is
*            removed. It is expected that the negotiation is normal and the client can receive the server hello done
*            message.
* @expect 1. The connection is set up normally and the client can receive the server hello done message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC8422_CONSISTENCY_ECDHE_LOSE_POINT_FUNC_TC001(void)
{
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == 0);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint32_t parseLen = 0;
    FRAME_ParseMsg(&frameType, ioUserData->recMsg.msg, ioUserData->recMsg.len, &frameMsg, &parseLen);
    /* Set the ECC cipher suite. Before the server receives the client hello message, the point format extension is
     *  removed. */
    frameMsg.body.hsMsg.body.clientHello.pointFormats.exState = MISSING_FIELD;
    FRAME_PackMsg(&frameType, &frameMsg, ioUserData->recMsg.msg, MAX_RECORD_LENTH, &parseLen);
    ioUserData->recMsg.len = parseLen;
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    // the client can receive the server hello done message.
    ASSERT_TRUE(
        FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO_DONE) == HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */
