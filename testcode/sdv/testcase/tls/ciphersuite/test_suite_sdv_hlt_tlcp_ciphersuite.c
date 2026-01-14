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

#include <unistd.h>
#include <semaphore.h>
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "hitls.h"
#include "frame_tls.h"
#include "hitls_type.h"
/* END_HEADER */

#define READ_BUF_LEN_18K (18 * 1024)
#define PORT 10088

/* BEGIN_CASE */
void SDV_TLS_TLCP_CIPHER_SUITE_TC01(char *cipherSuiteType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    // Configure link information on the server.
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetCipherSuites(serverCtxConfig, cipherSuiteType);
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->needCheckKeyUsage = true;
    // The server listens on the TLS link.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLCP1_1, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Configure link information on the client.
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetCipherSuites(clientCtxConfig, cipherSuiteType);

    // Set up a TLCP link on the client.
    clientRes = HLT_ProcessTlsConnect(localProcess, TLCP1_1, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    ASSERT_TRUE(HLT_ProcessTlsWrite(remoteProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(localProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */