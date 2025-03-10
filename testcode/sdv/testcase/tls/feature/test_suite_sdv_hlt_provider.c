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

/* END_HEADER */

#define READ_BUF_LEN_18K (18 * 1024)
#define PORT 10086
int32_t g_testSecurityLevel = 0;

void SetCert(HLT_Ctx_Config *ctxConfig, char *cert)
{
    if (strncmp(cert, "RSA", strlen("RSA")) == 0) {
        HLT_SetCertPath(ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, RSA_SHA256_PRIV_PATH3,
            "NULL", "NULL");
    } else if (strncmp(cert, "ECDSA", strlen("ECDSA")) == 0) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA_CA_PATH, ECDSA_SHA_CHAIN_PATH, ECDSA_SHA256_EE_PATH,
            ECDSA_SHA256_PRIV_PATH, "NULL", "NULL");
    }
}

void SetGMCert(HLT_Ctx_Config *serverCtxConfig, HLT_Ctx_Config *clientCtxConfig, char *cert)
{
    if (strncmp(cert, "SM2", strlen("SM2")) == 0) {
        HLT_SetCertPath(serverCtxConfig, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_SERVER_ENC_CERT_PATH, SM2_SERVER_ENC_KEY_PATH,
                    SM2_SERVER_SIGN_CERT_PATH, SM2_SERVER_SIGN_KEY_PATH);
        HLT_SetCertPath(clientCtxConfig, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_CLIENT_ENC_CERT_PATH, SM2_CLIENT_ENC_KEY_PATH,
                    SM2_CLIENT_SIGN_CERT_PATH, SM2_CLIENT_SIGN_KEY_PATH);
    }
}

/* BEGIN_CASE */
void SDV_TLS13_PROVIDER_GROUP_TC001()
{
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, PORT, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

#ifdef HITLS_TLS_FEATURE_PROVIDER
    HLT_SetProviderInfo(serverCtxConfig, providerName, providerLibFmt, attrName);
    HLT_SetProviderInfo(clientCtxConfig, providerName, providerLibFmt, attrName);
#endif
    /* Set Cert */
    HLT_SetCertPath(serverCtxConfig, "NULL", "NULL", "NULL", "NULL", "NULL", "NULL");
    HLT_SetCertPath(clientCtxConfig, "NULL", "NULL", "NULL", "NULL", "NULL", "NULL");

    HITLS_CFG_SetGroups(serverCtxConfig, &group, 1);
    HLT_SetCipherSuites(serverCtxConfig, Ciphersuite);
    HLT_SetCipherSuites(clientCtxConfig, Ciphersuite);

    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Tls_Res *clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
EXIT:
    HLT_FreeCtxConfig(serverCtxConfig);
    HLT_FreeCtxConfig(clientCtxConfig);
    HLT_FreeAllProcess();
}
/* END_CASE */