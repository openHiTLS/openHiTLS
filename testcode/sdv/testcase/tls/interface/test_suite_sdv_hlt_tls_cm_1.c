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
