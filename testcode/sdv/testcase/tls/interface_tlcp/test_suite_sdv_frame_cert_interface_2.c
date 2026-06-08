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
/* INCLUDE_BASE test_suite_interface */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>

#include "hitls_error.h"
#include "hitls_cert.h"
#include "hitls.h"
#include "hitls_func.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "cert_mgr_ctx.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "session.h"
#include "bsl_sal.h"
#include "bsl_uio.h"
#include "alert.h"
#include "cert_callback.h"
#include "crypt_eal_rand.h"
#include "hitls_crypt_reg.h"
#include "hitls_crypt_init.h"
#include "uio_base.h"
#include "hlt_type.h"
#include "hlt.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_cert_reg.h"
#include "hitls_config.h"
#include "hitls_cert_init.h"
#include "stub_utils.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "logger.h"
#include "tls_config.h"
#include "tls.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_obj.h"
#include "bsl_errno.h"
#include "hitls_x509_adapt.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_errno.h"
/* END_HEADER */

#define BUF_MAX_SIZE 4096
int32_t g_uiPort = 18886;
HITLS_CERT_X509 *HiTLS_X509_LoadCertFile(HITLS_Config *tlsCfg, const char *file);

STUB_DEFINE_RET5(int32_t, SAL_CERT_KeyCtrl, HITLS_Config *, HITLS_CERT_Key *, HITLS_CERT_CtrlCmd, void *, void *);

static int32_t STUB_SAL_CERT_KeyCtrl_UNKNOWN(HITLS_Config *config, HITLS_CERT_Key *key,
    HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (cmd == CERT_KEY_CTRL_GET_TYPE && out != NULL) {
        *(uint32_t *)out = TLS_CERT_KEY_TYPE_UNKNOWN;
        return HITLS_SUCCESS;
    }

    if (key == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (cmd > CERT_CTRL_BUTT - 1) {
        return HITLS_CERT_CTRL_ERR_INVALID_CMD;
    }
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_KeyCtrl(config, key, cmd, in, out);
#else
    ret = config->certMgrCtx->method.keyCtrl(config, key, cmd, in, out);
#endif
    return ret;
}

/* @
* @test    UT_TLS_CERT_CM_SetVerifyStore_API_TC001
* @title   The input parameters of the HITLS_SetVerifyStore and HITLS_GetVerifyStore interfaces are replaced.
* @precon  nan
* @brief   1.Invoke the HITLS_SetVerifyStore interface. The value of ctx is empty and the value of store for the CA
*            certificate is not empty. Perform shallow copy. Expected result 1 is obtained.
*          2.Invoke the HITLS_SetVerifyStore interface. Set ctx and CA certificate store to a value that is not empty.
*            Expected result 2 is obtained.
*          3.Invoke the HITLS_GetVerifyStore interface and leave tlsConfig blank. Expected result 3 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
*          3.Returns NULL
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetVerifyStore_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_CERT_Store *verifyStore = HITLS_X509_Adapt_StoreNew();
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetVerifyStore(NULL, verifyStore, false) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetVerifyStore(ctx, verifyStore, false), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetVerifyStore(ctx) == verifyStore);
    ASSERT_TRUE(HITLS_GetVerifyStore(NULL) == NULL);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CM_SetChainStore_API_TC001
* @title   The input parameters of the HITLS_SetChainStore and HITLS_GetChainStore interfaces are replaced.
* @precon  This test case covers the HITLS_SetChainStore、HITLS_GetChainStore
* @brief   1.Invoke the HITLS_SetChainStore interface. The ctx field is empty and the certificate chain store is not
*            empty. Perform shallow copy. Expected result 1 is obtained.
*          2.Invoke the HITLS_SetChainStore interface. The value of ctx is not empty and the value of store in the
*            certificate chain is not empty. Perform shallow copy. Expected result 2 is obtained.
*          3.Invoke the HITLS_GetChainStore interface and leave tlsConfig empty. Expected result 3 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
*          3.Returns NULL
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetChainStore_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_CERT_Store *chainStore = HITLS_X509_Adapt_StoreNew();

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetChainStore(NULL, chainStore, false) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetChainStore(ctx, chainStore, false), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetChainStore(ctx) == chainStore);
    ASSERT_TRUE(HITLS_GetChainStore(NULL) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */
/* @
* @test    UT_TLS_CERT_CM_SetCertStore_API_TC001
* @title   The input parameter of the HITLS_SetCertStore interface is replaced.
* @precon  This test case covers the HITLS_SetCertStore、HITLS_GetCertStore
* @brief   1.Invoke the HITLS_SetCertStore interface. The value of ctx is empty, and the value of store for the trust
*            certificate is not empty. Perform shallow copy. Expected result 1 is obtained.
*          2.Invoke the HITLS_SetCertStore interface. Ensure that ctx and store of the trust certificate are not empty.
*            Perform shallow copy. Expected result 2 is obtained.
*          3.Invoke the HITLS_GetCertStore interface and leave ctx blank. Expected result 3 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
*          3.Returns NULL
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetCertStore_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_CERT_Store *certStore = HITLS_X509_Adapt_StoreNew();

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetCertStore(NULL, certStore, false) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetCertStore(ctx, certStore, false), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetCertStore(ctx) == certStore);
    ASSERT_TRUE(HITLS_GetCertStore(NULL) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CM_SetDefaultPasswordCbUserdata_API_TC001
* @title   The input parameter of the HITLS_SetDefaultPasswordCbUserdata interface is replaced.
* @precon  This test case covers the HITLS_SetDefaultPasswordCbUserdata、HITLS_GetDefaultPasswordCbUserdata
* @brief   1.Invoke the HITLS_SetDefaultPasswordCbUserdata interface. The value of ctx is empty and the value of
*            userdata is not empty. Expected result 1 is obtained.
*          2.Invoke the HITLS_SetDefaultPasswordCbUserdata interface. The values of ctx and userdata are not empty.
*            Expected result 2 is obtained.
*          3.Invoke the HITLS_GetDefaultPasswordCbUserdata interface and leave ctx blank. Expected result 3 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
*          3.Returns NULL
           
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetDefaultPasswordCbUserdata_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_CERT_Store *certStore = HITLS_X509_Adapt_StoreNew();

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetCertStore(NULL, certStore, false) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetCertStore(ctx, certStore, false), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetCertStore(ctx) == certStore);
    ASSERT_TRUE(HITLS_GetCertStore(NULL) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test     UT_TLS_CERT_SetGetAndCheckPrivateKey_API_TC001
* @title    The error input parameter for HITLS_SetPrivateKey
* @precon   nan
* @brief  1.Invoke the HITLS_SetPrivateKey interface. Ensure that ctx is empty and privatekey is not empty.
*           Perform deep copy. Expected result 1
*         2.Invoke the HITLS_SetPrivateKey interface. Ensure that ctx is not empty and privatekey is not empty.
*           In shallow copy mode, expected result 2
*         3.Invoke the HITLS_GetPrivateKey interface. If ctx is empty, expected result 3
*         4.Invoke the HITLS_CheckPrivateKey interface. If ctx is empty, expected result 1 is obtained
* @expect 1.Back HITLS_NULL_INPUT
*         2.Back HITLS_SUCCESS
*         3.Back HITLS_NULL_INPUT
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_SetGetAndCheckPrivateKey_API_TC001(int version, char *keyFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    HITLS_CERT_Key *privatekey = HITLS_X509_Adapt_ProviderKeyParse(tlsConfig, (const uint8_t *)keyFile, sizeof(keyFile),
        TLS_PARSE_TYPE_FILE, "ASN1", NULL);
#else
    HITLS_CERT_Key *privatekey = HITLS_X509_Adapt_KeyParse(tlsConfig, (const uint8_t *)keyFile, sizeof(keyFile),
        TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
#endif

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetPrivateKey(NULL, privatekey, true) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetPrivateKey(ctx, privatekey, false) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_GetPrivateKey(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetPrivateKey(ctx) != NULL);
    ASSERT_TRUE(HITLS_CheckPrivateKey(NULL) == HITLS_NULL_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test  UT_HITLS_CERT_ClearChainCerts_API_TC001
* @title  HITLS_ClearChainCerts interface input parameter test
* @precon  nan
* @brief  1. Invoke HITLS_ClearChainCerts interface. Input empty ctx. Expected result 1
*         2. Invoke HITLS_ClearChainCerts interface. Input non-empty ctx. Expected result 2
*         3. Invoke HITLS_ClearChainCerts interface. Input non-empty ctx and empty tlsConfig->certMgrCtx,
*         Expected result 1
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_HITLS_CERT_ClearChainCerts_API_TC001(int version, char *certFile, char *addCertFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    HITLS_CERT_X509 *cert = HiTLS_X509_LoadCertFile(tlsConfig, certFile);
    ASSERT_TRUE(cert != NULL);
    HITLS_CERT_X509 *addCert = HiTLS_X509_LoadCertFile(tlsConfig, addCertFile);
    ASSERT_TRUE(addCert != NULL);

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_TRUE(HITLS_CFG_SetCertificate(tlsConfig, cert, false) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_AddChainCert(tlsConfig, addCert, false) == HITLS_SUCCESS);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_ClearChainCerts(NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_ClearChainCerts(ctx) == HITLS_SUCCESS);
    SAL_CERT_MgrCtxFree(ctx->config.tlsConfig.certMgrCtx);
    ctx->config.tlsConfig.certMgrCtx = NULL;
    ASSERT_EQ(HITLS_ClearChainCerts(ctx), HITLS_NULL_INPUT);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CFG_FILTER_UNKNOWN_KEY_TYPE_TC001
* @title   Reject certificates and private keys whose key type is unknown
* @precon  nan
* @brief   1. Create a TLS config.
*          2. Stub SAL_CERT_KeyCtrl to report TLS_CERT_KEY_TYPE_UNKNOWN.
*          3. Load a certificate and a private key file.
* @expect  1. HITLS_CFG_LoadCertFile returns HITLS_CERT_ERR_INVALID_KEY_TYPE.
*          2. HITLS_CFG_LoadKeyFile returns HITLS_CERT_ERR_INVALID_KEY_TYPE.
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_FILTER_UNKNOWN_KEY_TYPE_TC001(int version)
{
    const char *certFile = "../testdata/tls/certificate/der/ed25519/ed25519.end.der";
    const char *keyFile = "../testdata/tls/certificate/der/ed25519/ed25519.end.key.der";
    HITLS_Config *tlsConfig = NULL;

    HitlsInit();
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    STUB_REPLACE(SAL_CERT_KeyCtrl, STUB_SAL_CERT_KeyCtrl_UNKNOWN);
    ASSERT_EQ(HITLS_CFG_LoadCertFile(tlsConfig, certFile, TLS_PARSE_FORMAT_ASN1), HITLS_CERT_ERR_INVALID_KEY_TYPE);
    ASSERT_EQ(HITLS_CFG_LoadKeyFile(tlsConfig, keyFile, TLS_PARSE_FORMAT_ASN1), HITLS_CERT_ERR_INVALID_KEY_TYPE);

EXIT:
    STUB_RESTORE(SAL_CERT_KeyCtrl);
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CFG_CLEAR_VERIFY_CRLS_FUNC_TC001
* @title   Clear CRLs configured in the verify store
* @precon  nan
* @brief   1. Create a TLS config and configure an explicit verify store.
*          2. Add CA certificates into the verify store and load a CRL file.
*          3. Verify the handshake fails while the CRL is present.
*          4. Clear CRLs and verify the verify store no longer contains the CRL.
* @expect  1. HITLS_CFG_LoadCrlFile succeeds.
*          2. The revoked-certificate handshake fails before clear.
*          3. HITLS_CFG_ClearVerifyCrls succeeds.
*          4. The post-clear handshake fails with CRL-not-found instead of certificate-revoked.
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_CLEAR_VERIFY_CRLS_FUNC_TC001(int version, int vfyFlag)
{
    const char *serverCertPath = "../testdata/tls/certificate/der/ed25519/ed25519.end.der";
    const char *serverKeyPath = "../testdata/tls/certificate/der/ed25519/ed25519.end.key.der";
    const char *intCaPath = "../testdata/tls/certificate/der/ed25519/ed25519.intca.der";
    const char *caCertPath = "../testdata/tls/certificate/der/ed25519/ed25519.ca.der";
    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";
    HITLS_Config *tlsConfig = NULL;
    HITLS_CERT_Store *verifyStore = NULL;
    HITLS_CERT_X509 *caCert = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_ERROR ret = HITLS_SUCCESS;

    HitlsInit();
    FRAME_Init();
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    verifyStore = HITLS_X509_Adapt_StoreNew();
    ASSERT_TRUE(verifyStore != NULL);
    ASSERT_EQ(HITLS_CFG_SetVerifyStore(tlsConfig, verifyStore, false), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetVerifyStore(tlsConfig) == verifyStore);

    ASSERT_EQ(HITLS_CFG_LoadCertFile(tlsConfig, serverCertPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_LoadKeyFile(tlsConfig, serverKeyPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);

    caCert = HiTLS_X509_LoadCertFile(tlsConfig, caCertPath);
    ASSERT_TRUE(caCert != NULL);
    ASSERT_EQ(HITLS_CFG_AddCertToStore(tlsConfig, caCert, TLS_CERT_STORE_TYPE_VERIFY, false), HITLS_SUCCESS);

    caCert = HiTLS_X509_LoadCertFile(tlsConfig, intCaPath);
    ASSERT_TRUE(caCert != NULL);
    ASSERT_EQ(HITLS_CFG_AddCertToStore(tlsConfig, caCert, TLS_CERT_STORE_TYPE_VERIFY, false), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_SetVerifyFlags(tlsConfig, vfyFlag), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_LoadCrlFile(tlsConfig, crlPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);

    client = FRAME_CreateLinkBase(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkBase(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_GetVerifyResult(client->ssl, &ret);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_CERT_REVOKED);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    ASSERT_EQ(HITLS_CFG_ClearVerifyCrls(tlsConfig), HITLS_SUCCESS);

    client = FRAME_CreateLinkBase(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkBase(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_GetVerifyResult(client->ssl, &ret);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_CRL_NOT_FOUND);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
