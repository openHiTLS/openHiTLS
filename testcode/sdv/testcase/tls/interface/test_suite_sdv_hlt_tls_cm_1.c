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

#include "securec.h"
#include "hlt.h"
#include "hitls_error.h"
#include "hitls_func.h"
#include "conn_init.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "alert.h"
#include "stub_utils.h"
#include "hs_common.h"
#include "change_cipher_spec.h"
#include "hs.h"
#include "simulate_io.h"
#include "rec_header.h"
#include "rec_wrapper.h"
#include "recv_client_hello.c"
#include "record.h"

#define READ_BUF_SIZE 18432
#define MAX_DIGEST_SIZE 64UL /* The longest known is SHA512 */
uint32_t g_uiPort = 8890;

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, BSL_UIO_Write, BSL_UIO *, const void *, uint32_t, uint32_t *);


static HITLS_Config *GetHitlsConfigViaVersion(int ver)
{
    HITLS_Config *config;
    int32_t ret;
    switch (ver) {
        case HITLS_VERSION_TLS12:
            config = HITLS_CFG_NewTLS12Config();
            ret = HITLS_CFG_SetCheckKeyUsage(config, false);
            if (ret != HITLS_SUCCESS) {
                return NULL;
            }
            return config;
        case HITLS_VERSION_TLS13:
            config = HITLS_CFG_NewTLS13Config();
            ret = HITLS_CFG_SetCheckKeyUsage(config, false);
            if (ret != HITLS_SUCCESS) {
                return NULL;
            }
            return config;
        case HITLS_VERSION_DTLS12:
            config = HITLS_CFG_NewDTLS12Config();
            ret = HITLS_CFG_SetCheckKeyUsage(config, false);
            if (ret != HITLS_SUCCESS) {
                return NULL;
            }
            return config;
        default:
            return NULL;
    }
}

int32_t STUB_BSL_UIO_Write(BSL_UIO *uio, const void *data, uint32_t len, uint32_t *writeLen)
{
    (void)uio;
    (void)data;
    (void)len;
    (void)writeLen;
    return BSL_INTERNAL_EXCEPTION;
}

/** @
* @test SDV_TLS_CM_KEYUPDATE_FUNC_TC001
* @title HITLS_TLS_Interface_SDV_23_0_5_102
* @precon nan
* @brief
*   1. Set the version number to tls1.3. After the connection is established, invoke the HITLS_GetKeyUpdateType interface.
*       Expected result 1 is obtained.
*   2. Set the version number to tls1.3. After the connection is created, call hitls_keyupdate successfully, and then call the
*       HITLS_GetKeyUpdateType interface. Expected result 2 is obtained.
*   3. Set the version number to tls1.3. After the connection is created, call the hitls_keyupdate interface to construct an
*       I/O exception. If the interface fails to be called, call the HITLS_GetKeyUpdateType interface again. Expected
*       result 3 is obtained.
* @expect
*   1. The return value is 255.
*   2. The return value is 255.
*   3. The return value is the configured keyupdate type.
@ */
/* BEGIN_CASE */
void SDV_TLS_CM_KEYUPDATE_FUNC_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(config != NULL);

    config->isSupportRenegotiation = true;
    ASSERT_EQ(HITLS_CFG_SetEncryptThenMac(config, true), HITLS_SUCCESS);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    uint16_t cipherSuite = HITLS_RSA_WITH_AES_128_CBC_SHA256;
    int32_t ret = HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ret = HITLS_GetKeyUpdateType(client->ssl);
    ASSERT_EQ(ret, HITLS_KEY_UPDATE_REQ_END);
    ret = HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_NOT_REQUESTED);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_SUCCESS);
    ret = HITLS_GetKeyUpdateType(client->ssl);
    ASSERT_EQ(ret, HITLS_KEY_UPDATE_REQ_END);
    STUB_REPLACE(BSL_UIO_Write, STUB_BSL_UIO_Write);;
    ret = HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_REQUESTED);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_ERR_IO_EXCEPTION);
    ret = HITLS_GetKeyUpdateType(client->ssl);
    ASSERT_EQ(ret, HITLS_UPDATE_REQUESTED);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_RESTORE(BSL_UIO_Write);
}
/* END_CASE */

/* @
* @test  SDV_CCA_EXPORT_KEY_MATERIAL_005
* @spec  -
* @title  tls1.3psk handshake key export
* @precon  nan
* @brief  1. Set the client version to TLS1.3, and expect result 1.
2. Set PSK, expected result 2 occurs.
3. Link building, with expected outcome 3
4. Call HITLS_ExportKeyingMaterial, record the output parameter 1 of the interface, and expect result 4.
5. Comparison test, obtain the remote key, record interface output parameter 2, and expect result 5.
6. Determine whether the output parameters 1 and 2 of the interface are equal, with expected result 6.
* @expect  1. set successfully
2. set successfully
3. Link established successfully
4. set successfully
5. Record success
6. equals
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_EXPORT_KEY_MATERIAL_005()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, true);
    ASSERT_TRUE(remoteProcess != NULL);

    // Server-side link information configuration
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetPsk(serverCtxConfig, "123456789");
    // Server listens on TLS connection
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Configuring Link Information on the Client
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetPsk(clientCtxConfig, "123456789");
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_AES_128_GCM_SHA256");
    HLT_SetRenegotiationSupport(clientCtxConfig, true);

    // Client TLS Connection Establishment
    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ExportMaterialParam param = { 0 };
    size_t outLen = sizeof(ExportMaterialParam);
    param.outLen = outLen;
    param.labelLen = strlen("12");
    param.contextLen = 0;
    param.useContext = 1;
    memcpy_s(param.label, sizeof(param.label), "12", strlen("12"));
    memcpy_s(param.context, sizeof(param.context), NULL, 0);
    uint8_t *readBuf = (uint8_t *)calloc(outLen, sizeof(uint8_t));
    uint32_t readLen = 0;
    ASSERT_TRUE(readBuf != NULL);
    uint8_t *localMaterial = (uint8_t *)calloc(outLen, sizeof(uint8_t));
    ASSERT_TRUE(localMaterial != NULL);
    ASSERT_EQ(HITLS_ExportKeyingMaterial(clientRes->ssl, localMaterial, outLen, "12", param.labelLen,
        (uint8_t *)NULL, 0, 1), HITLS_SUCCESS);
    ASSERT_EQ(HLT_RpcTlsWriteExportMaterial(remoteProcess, serverRes->sslId, &param), 0);
    // Read the key exported from the remote end
    ASSERT_TRUE(HLT_TlsRead(clientRes->ssl, readBuf, outLen, &readLen) == 0);
    ASSERT_TRUE(readLen == outLen);
    // Compare whether the keys exported from the local end and the remote end are consistent.
    ASSERT_TRUE(memcmp(localMaterial, readBuf, readLen) == 0);
EXIT:
    free(readBuf);
    free(localMaterial);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_CCA_EXPORT_KEY_MATERIAL_007
* @spec  -
* @title  TLS 1.2, key derivation before and after renegotiation
* @precon  nan
* @brief  "1. Set the version number to tls1.2, and there is an expected result 1.
2. Link building, with expected outcome 2
3. Call HITLS_ExportKeyingMaterial, record the output parameter 1 of the interface, and expect result 3.
4. Call HITLS_ExportKeyingMaterial, record the second output parameter of the interface, and expect result 4.
5. Determine whether the output parameters 1 and 2 of the interface are equal, with expected result 5.
6. Re-negotiation, with expected outcome 6
7. Call HITLS_ExportKeyingMaterial, record the output parameter 3 of the interface, and expect result 7.
8. Call HITLS_ExportKeyingMaterial, record the output parameter 4 of the interface, and expect result 8.
9. Determine whether the output parameters 3 and 4 of the interface are equal, with the expected result being 9.
* @expect  "1. Set successful
2. Link established successfully
3. Set successful
4. Set successful
5. equals
6. Renegotiation successful
7. Set successful
8. Set successful
9. equals
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_EXPORT_KEY_MATERIAL_007()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18889, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Server-side link information configuration
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetRenegotiationSupport(serverCtxConfig, true);
    HLT_SetClientRenegotiateSupport(serverCtxConfig, true);

    // Server listens on TLS connection
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Configuring Link Information on the Client
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetRenegotiationSupport(clientCtxConfig, true);

    // Client TLS Connection Establishment
    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ExportMaterialParam param = { 0 };
    size_t outLen = sizeof(ExportMaterialParam);
    param.outLen = outLen;
    param.labelLen = strlen("12");
    param.contextLen = 0;
    param.useContext = 1;
    memcpy_s(param.label, sizeof(param.label), "12", strlen("12"));
    memcpy_s(param.context, sizeof(param.context), NULL, 0);
    uint8_t *readBuf = (uint8_t *)calloc(outLen, sizeof(uint8_t));
    uint32_t readLen = 0;
    ASSERT_TRUE(readBuf != NULL);
    uint8_t *localMaterial = (uint8_t *)calloc(outLen, sizeof(uint8_t));
    ASSERT_TRUE(localMaterial != NULL);
    ASSERT_EQ(HITLS_ExportKeyingMaterial(clientRes->ssl, localMaterial, outLen, "12", param.labelLen,
        (uint8_t *)NULL, 0, 1), HITLS_SUCCESS);
    ASSERT_EQ(HLT_RpcTlsWriteExportMaterial(remoteProcess, serverRes->sslId, &param), 0);
    // Read the key exported from the remote end
    ASSERT_TRUE(HLT_TlsRead(clientRes->ssl, readBuf, outLen, &readLen) == 0);
    ASSERT_TRUE(readLen == outLen);
    // Compare whether the keys exported from the local end and the remote end are consistent.
    ASSERT_TRUE(memcmp(localMaterial, readBuf, readLen) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, clientRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf1[sizeof("Hello World")] = {0};
    uint32_t readLen1;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, serverRes, readBuf1, sizeof("Hello World"), &readLen1) == 0);
    ASSERT_TRUE(readLen1 == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf1, readLen1) == 0);

    // Initiate renegotiation
    ASSERT_TRUE(HITLS_Renegotiate(clientRes->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(clientRes->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    HLT_RpcTlsAccept(remoteProcess, serverRes->sslId);

    // Renegotiation successful
    HITLS_Ctx *ctx = clientRes->ssl;
    while (ctx->state == CM_STATE_RENEGOTIATION) {
        HITLS_Connect(clientRes->ssl);
        HLT_ProcessTlsRead(remoteProcess, serverRes, readBuf1, sizeof("Hello World"), &readLen1);
        ctx = clientRes->ssl;
    }
    ASSERT_EQ(ctx->state, CM_STATE_TRANSPORTING);

    ASSERT_EQ(HITLS_ExportKeyingMaterial(clientRes->ssl, localMaterial, outLen, "12", param.labelLen,
        (uint8_t *)NULL, 0, 1), HITLS_SUCCESS);
    ASSERT_TRUE(memcmp(localMaterial, readBuf, readLen) != 0);

    ASSERT_EQ(HLT_RpcTlsWriteExportMaterial(remoteProcess, serverRes->sslId, &param), 0);
    // Read the key exported from the remote end
    ASSERT_TRUE(HLT_TlsRead(clientRes->ssl, readBuf, outLen, &readLen) == 0);
    ASSERT_TRUE(readLen == outLen);
    ASSERT_TRUE(memcmp(localMaterial, readBuf, readLen) == 0);

EXIT:
    free(readBuf);
    free(localMaterial);
    HLT_FreeAllProcess();
}
/* END_CASE */