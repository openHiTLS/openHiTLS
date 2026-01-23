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
#include "hitls_build.h"
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "hitls.h"
#include "frame_tls.h"
#include "hitls_type.h"
#include "test.h"
/* END_HEADER */

#define READ_BUF_LEN_18K (18 * 1024)
#define PORT 10088


bool SkipTlsTest(int connType, int version)
{
    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS13
        case TLS1_3:
            break;
#endif
#ifdef HITLS_TLS_PROTO_TLS12
        case TLS1_2:
            break;
#endif
#ifdef HITLS_TLS_PROTO_DTLS12
        case DTLS1_2:
            break;
#endif
#ifdef HITLS_TLS_PROTO_TLCP11
        case TLCP1_1:
            break;
#endif
#ifdef HITLS_TLS_PROTO_DTLCP11
        case DTLCP1_1:
            break;
#endif
#if defined(HITLS_TLS_CONFIG_VERSION) && (defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_TLS13))
        case TLS_ALL:
            break;
#endif
        default:
            return true;
    }
    switch (connType) {
#ifdef HITLS_BSL_UIO_TCP
        case TCP:
            break;
#endif
#ifdef HITLS_BSL_UIO_UDP
        case UDP:
            break;
#endif
        default:
            return true;
    }
    return false;
}

/* BEGIN_CASE */
void SDV_TLS_BASE_CONNECT_TC01(int connType, int version)
{
    if (SkipTlsTest(connType, version)) {
        SKIP_TEST();
        return;
    }

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);
    if (version == TLCP1_1 || version == DTLCP1_1) {
        serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
        clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    } else {
        serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
        clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    }
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    // Configure link information on the server.
    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Configure link information on the client.
    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */