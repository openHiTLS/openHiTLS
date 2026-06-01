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
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "helper.h"
#include "hitls.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "hitls_type.h"
#include "rec_wrapper.h"
#include "hs_ctx.h"
#include "hs_cert.h"
#include "parse_common.h"
#include "bsl_hash.h"
#include "cert_mgr.h"
#include "cert_callback.h"
#include "tls.h"
#include "alert.h"

/* HLT cert loader appends these paths to DEFAULT_CERT_PATH, which ends at testdata/tls/certificate/der/. */
#define PQ_CERT_BASE "../../../cert/asn1/"
#define PQ_CERT_NULL "NULL"

#define MLDSA44_CA_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa44/ca_cert.pem"
#define MLDSA44_CHAIN_PATH PQ_CERT_NULL
#define MLDSA44_EE_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa44/entity_cert.pem"
#define MLDSA44_KEY_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa44/entity_key.pem"
#define MLDSA65_CA_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa65/ca_cert.pem"
#define MLDSA65_CHAIN_PATH PQ_CERT_NULL
#define MLDSA65_EE_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa65/entity_cert.pem"
#define MLDSA65_KEY_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa65/entity_key.pem"
#define MLDSA87_CA_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa87/ca_cert.pem"
#define MLDSA87_CHAIN_PATH PQ_CERT_NULL
#define MLDSA87_EE_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa87/entity_cert.pem"
#define MLDSA87_KEY_PATH PQ_CERT_BASE "cms/signeddata/mldsa/mldsa87/entity_key.pem"
/* END_HEADER */

static uint32_t g_uiPort = 16888;

typedef struct {
    const char *caPath;
    const char *chainPath;
    const char *eePath;
    const char *keyPath;
    const char *signature;
} PqCertChain;

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *link;
    HITLS_Ctx *ctx;
    HITLS_CERT_X509 *cert;
} certCheckCtx;

static void CleanupcertCheckCtx(certCheckCtx *testCtx)
{
    if (testCtx == NULL) {
        return;
    }
    FRAME_FreeLink(testCtx->link);
    HITLS_CFG_FreeConfig(testCtx->config);
    memset(testCtx, 0, sizeof(*testCtx));
}

static int32_t InitCertCheckCtx(certCheckCtx *testCtx, const uint16_t *signAlgs, uint32_t signAlgNum,
    uint32_t certKeyType)
{
    int32_t ret;
    const char *caPath = NULL;
    const char *chainPath = NULL;
    const char *eePath = NULL;
    const char *keyPath = NULL;

    if (testCtx == NULL) {
        return HITLS_NULL_INPUT;
    }

    memset(testCtx, 0, sizeof(*testCtx));
    FRAME_Init();
    testCtx->config = HITLS_CFG_NewTLS13Config();
    if (testCtx->config == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    switch (certKeyType) {
        case TLS_CERT_KEY_TYPE_RSA:
            caPath = RSA_SHA256_CA_PATH;
            chainPath = RSA_SHA256_CHAIN_PATH;
            eePath = RSA_SHA256_EE_PATH1;
            keyPath = RSA_SHA256_PRIV_PATH1;
            break;
        case TLS_CERT_KEY_TYPE_ECDSA:
            caPath = ECDSA_SHA256_CA_PATH;
            chainPath = ECDSA_SHA256_CHAIN_PATH;
            eePath = ECDSA_SHA256_EE_PATH1;
            keyPath = ECDSA_SHA256_PRIV_PATH1;
            break;
        default:
            return HITLS_INVALID_INPUT;
    }
    ret = HiTLS_X509_LoadCertAndKey(testCtx->config, caPath, chainPath, eePath, NULL, keyPath, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (signAlgs != NULL && signAlgNum != 0) {
        ret = HITLS_CFG_SetSignature(testCtx->config, signAlgs, signAlgNum);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    testCtx->link = FRAME_CreateLinkEx(testCtx->config, BSL_UIO_TCP);
    if (testCtx->link == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    testCtx->ctx = FRAME_GetTlsCtx(testCtx->link);
    if (testCtx->ctx == NULL || testCtx->ctx->config.tlsConfig.certMgrCtx == NULL) {
        return HITLS_NULL_INPUT;
    }
    testCtx->ctx->negotiatedInfo.version = HITLS_VERSION_TLS13;

    testCtx->cert = HITLS_GetCertificate(testCtx->ctx);
    if (testCtx->cert == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_SUCCESS;
}

#ifdef HITLS_CRYPTO_MLDSA
static void RunTls13PqCertChainTest(const PqCertChain *cert)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetCertPath(serverCtxConfig, cert->caPath, cert->chainPath, cert->eePath, cert->keyPath,
        PQ_CERT_NULL, PQ_CERT_NULL);
    ASSERT_TRUE(HLT_SetSignature(serverCtxConfig, cert->signature) == 0);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetCertPath(clientCtxConfig, cert->caPath, PQ_CERT_NULL, PQ_CERT_NULL, PQ_CERT_NULL,
        PQ_CERT_NULL, PQ_CERT_NULL);
    ASSERT_TRUE(HLT_SetSignature(clientCtxConfig, cert->signature) == 0);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
}
#endif

/**
 * @test SDV_TLS13_HLT_PQC_CERT_TC001
 * @title  TLS 1.3 ML-DSA-44 certificate chain handshake
 * @precon  nan
 * @brief   Use an ML-DSA-44 end-entity certificate and chain to establish a TLS 1.3 connection.
 * @expect  1. The link establishment is successful.
 */
/* BEGIN_CASE */
void SDV_TLS13_HLT_PQC_CERT_TC001(void)
{
#ifndef HITLS_CRYPTO_MLDSA
    SKIP_TEST();
#else
    const PqCertChain cert = {
        MLDSA44_CA_PATH,
        MLDSA44_CHAIN_PATH,
        MLDSA44_EE_PATH,
        MLDSA44_KEY_PATH,
        "CERT_SIG_SCHEME_MLDSA44",
    };
    RunTls13PqCertChainTest(&cert);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS13_HLT_PQC_CERT_TC002
 * @title  TLS 1.3 ML-DSA-65 certificate chain handshake
 * @precon  nan
 * @brief   Use an ML-DSA-65 end-entity certificate and chain to establish a TLS 1.3 connection.
 * @expect  1. The link establishment is successful.
 */
/* BEGIN_CASE */
void SDV_TLS13_HLT_PQC_CERT_TC002(void)
{
#ifndef HITLS_CRYPTO_MLDSA
    SKIP_TEST();
#else
    const PqCertChain cert = {
        MLDSA65_CA_PATH,
        MLDSA65_CHAIN_PATH,
        MLDSA65_EE_PATH,
        MLDSA65_KEY_PATH,
        "CERT_SIG_SCHEME_MLDSA65",
    };
    RunTls13PqCertChainTest(&cert);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS13_HLT_PQC_CERT_TC003
 * @title  TLS 1.3 ML-DSA-87 certificate chain handshake
 * @precon  nan
 * @brief   Use an ML-DSA-87 end-entity certificate and chain to establish a TLS 1.3 connection.
 * @expect  1. The link establishment is successful.
 */
/* BEGIN_CASE */
void SDV_TLS13_HLT_PQC_CERT_TC003(void)
{
#ifndef HITLS_CRYPTO_MLDSA
    SKIP_TEST();
#else
    const PqCertChain cert = {
        MLDSA87_CA_PATH,
        MLDSA87_CHAIN_PATH,
        MLDSA87_EE_PATH,
        MLDSA87_KEY_PATH,
        "CERT_SIG_SCHEME_MLDSA87",
    };
    RunTls13PqCertChainTest(&cert);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS13_HLT_CERT_SIGALG_TC001
 * @title  Local cert sign scheme version mismatch at local cert selection
 * @precon  nan
 * @brief   Use the default RSA certificate in a TLS 1.3 handshake while only configuring a mismatched sign scheme.
 *          The local cert selection path should reject the sign scheme by certVersionBits.
 * @expect  1. The local cert selection fails with no matching sign scheme.
 */
/* BEGIN_CASE */
void SDV_TLS13_HLT_CERT_SIGALG_TC001(void)
{
    certCheckCtx testCtx = {0};
    uint16_t signScheme = CERT_SIG_SCHEME_RSA_PKCS1_SHA256;
    CERT_ExpectInfo expectCertInfo = {0};
    int32_t ret;

    ASSERT_EQ(InitCertCheckCtx(&testCtx, &signScheme, 1, TLS_CERT_KEY_TYPE_RSA), HITLS_SUCCESS);

    expectCertInfo.certType = CERT_TYPE_UNKNOWN;
    expectCertInfo.signSchemeList = &signScheme;
    expectCertInfo.signSchemeNum = 1;
    ret = HS_CheckCertInfo(testCtx.ctx, &expectCertInfo, testCtx.cert, true, true);

    ASSERT_EQ(ret, HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH);

EXIT:
    CleanupcertCheckCtx(&testCtx);
}
/* END_CASE */

/**
 * @test SDV_TLS13_HLT_CERT_SIGALG_TC002
 * @title  CertificateVerify sign scheme version mismatch
 * @precon  nan
 * @brief   Enable client authentication in TLS 1.3 and check a mismatched CertificateVerify sign scheme.
 *          The peer sign scheme should be rejected during parse.
 * @expect  1. The peer sign scheme check fails with unsupported sign algorithm.
 */
/* BEGIN_CASE */
void SDV_TLS13_HLT_CERT_SIGALG_TC002(void)
{
    certCheckCtx testCtx = {0};
    CERT_Pair peerCert = {0};
    int32_t ret;

    ASSERT_EQ(InitCertCheckCtx(&testCtx, NULL, 0, TLS_CERT_KEY_TYPE_RSA), HITLS_SUCCESS);

    peerCert.cert = testCtx.cert;
    ret = CheckPeerSignScheme(testCtx.ctx, &peerCert, CERT_SIG_SCHEME_RSA_PKCS1_SHA256);

    ASSERT_EQ(ret, HITLS_PARSE_UNSUPPORT_SIGN_ALG);
EXIT:
    CleanupcertCheckCtx(&testCtx);
}
/* END_CASE */
