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
#include "bsl_obj_internal.h"

/* END_HEADER */

#define READ_BUF_LEN_18K (18 * 1024)
#define PORT 10087

/* BEGIN_CASE */
void SDV_TLS13_PROVIDER_NEW_GROUP_SIGNALG_TC001(char *path, char *providerName, int providerLibFmt, char *group,
    char *signAlg, char *rootCa, char *interCa, char *serverCert, char *serverKey, char *clientCert, char *clientKey)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)path;
    (void)providerName;
    (void)providerLibFmt;
    (void)group;
    (void)signAlg;
    (void)rootCa;
    (void)interCa;
    (void)serverCert;
    (void)serverKey;
    (void)clientCert;
    (void)clientKey;
    SKIP_TEST();
#else
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetProviderPath(serverCtxConfig, path);
    HLT_SetProviderAttrName(serverCtxConfig, NULL);
    HLT_SetProviderPath(clientCtxConfig, path);
    HLT_SetProviderAttrName(clientCtxConfig, NULL);
    HLT_AddProviderInfo(serverCtxConfig, providerName, providerLibFmt);
    HLT_AddProviderInfo(serverCtxConfig, "default", BSL_SAL_LIB_FMT_OFF);
    HLT_AddProviderInfo(clientCtxConfig, providerName, providerLibFmt);
    HLT_AddProviderInfo(clientCtxConfig, "default", BSL_SAL_LIB_FMT_OFF);
    /* Set Cert */
    HLT_SetCertPath(serverCtxConfig, rootCa, interCa, serverCert, serverKey, "NULL", "NULL");
    HLT_SetCertPath(clientCtxConfig, rootCa, interCa, clientCert, clientKey, "NULL", "NULL");

    HLT_SetGroups(serverCtxConfig, group); // For kex or kem group
    HLT_SetGroups(clientCtxConfig, group); // For kex or kem group

    HLT_SetSignature(serverCtxConfig, signAlg);
    HLT_SetSignature(clientCtxConfig, signAlg);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_AES_128_GCM_SHA256");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_AES_128_GCM_SHA256");
    // Error stack exists
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

EXIT:
    HLT_FreeAllProcess();
    BSL_OBJ_FreeHashTable();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS13_PROVIDER_KEM_TC001(char *group)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)group;
    SKIP_TEST();
#else
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetGroups(clientCtxConfig, group); // For kex or kem group
    HLT_SetGroups(serverCtxConfig, group); // For kex or kem group

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientCtxConfig, NULL);
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
#endif
}
/* END_CASE */


/* BEGIN_CASE */
void SDV_TLS13_MULTI_PROVIDER_TC001(char *path, char *providerName, char *attrName, int providerLibFmt)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)path;
    (void)providerName;
    (void)attrName;
    (void)providerLibFmt;
    SKIP_TEST();
#else
    (void)path;
    (void)providerName;
    (void)attrName;
    (void)providerLibFmt;
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetProviderPath(serverCtxConfig, path);
    HLT_SetProviderAttrName(serverCtxConfig, attrName);
    HLT_AddProviderInfo(serverCtxConfig, providerName, providerLibFmt);
    HLT_AddProviderInfo(serverCtxConfig, "default", BSL_SAL_LIB_FMT_OFF);

    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    // Error stack exists
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HLT_FreeAllProcess();
#endif
}
/* END_CASE */