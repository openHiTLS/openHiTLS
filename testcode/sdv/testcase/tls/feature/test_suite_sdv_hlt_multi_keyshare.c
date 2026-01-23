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
#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "helper.h"
#include "hitls.h"
#include "frame_tls.h"
#include "hitls_type.h"
#include "rec_wrapper.h"
#include "hs_ctx.h"
#include "tls.h"


/* END_HEADER */

#define READ_BUF_LEN_18K (18 * 1024)
#define PORT 10087

static void Test_MultiKeyShare(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)bufSize;
    (void)user;
    (void)data;
    (void)*len;
    if (ctx->hsCtx->haveHrr) {
        *(bool *)user = true;
    } else {
        *(bool *)user = false;
    }
    return;
}

/* BEGIN_CASE */
void SDV_TLS13_MULTI_KEYSHARE_TC001()
{
    bool haveHrr = false;
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);
    bool testHrr = true;
    RecWrapper wrapper = {
        TRY_SEND_FINISH,
        REC_TYPE_HANDSHAKE,
        false,
        &testHrr,
        Test_MultiKeyShare
    };
    RegisterWrapper(wrapper);
    HLT_SetGroups(serverCtxConfig, "HITLS_EC_GROUP_SECP256R1");
    HLT_SetGroups(clientCtxConfig, "X25519MLKEM768:HITLS_EC_GROUP_SECP256R1");

    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Tls_Res *clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    ASSERT_EQ(testHrr, haveHrr);
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    HLT_FreeAllProcess();
    ClearWrapper();
}
/* END_CASE */
