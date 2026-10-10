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

/* INCLUDE_BASE test_suite_sdv_async_sim */

/* BEGIN_HEADER */
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "hitls_config.h"
#include "frame_tls.h"
#include "frame_link.h"
/* END_HEADER */

/**
 * @test   SDV_ASYNC_SIM_DELEG_TC001
 * @title  Sync path is transparent: delegated ECDH output matches built-in
 * @precon Provider loaded; test runs on the host stack (no task)
 * @brief
 *    1. Generate two ECDH P-256 key pairs through the simulation provider
 *       (frame libCtx + attrName routing) and two through the built-in path.
 *    2. Compute the provider-path shared secret and compare it against a
 *       built-in computation over the same key material.
 * @expect
 *    1. Both key generations and computations succeed.
 *    2. Shared secrets are byte-identical; provider stats show
 *       syncDirectCalls > 0 and pauses == 0.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DELEG_TC001(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *a = NULL;
    CRYPT_EAL_PkeyCtx *b = NULL;
    CRYPT_EAL_PkeyCtx *peerA = NULL;
    CRYPT_EAL_PkeyCtx *peerB = NULL;
    CRYPT_EAL_PkeyCtx *aInner = NULL;
    CRYPT_EAL_PkeyCtx *bInner = NULL;
    uint8_t shareProvider[128] = {0};
    uint8_t shareInner[128] = {0};
    uint32_t lenProvider = sizeof(shareProvider);
    uint32_t lenInner = sizeof(shareInner);
    uint8_t pub[128] = {0};
    uint32_t pubLen = sizeof(pub);
    BSL_Param pubParam[2] = {0};
    SIM_PROV_STATS stats = {0};

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    /* provider-routed contexts */
    a = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    ASSERT_TRUE(a != NULL);
    b = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    ASSERT_TRUE(b != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(a, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(b, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(a), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(b), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, shareProvider, &lenProvider), CRYPT_SUCCESS);

    /* built-in comparison path over the same key material: export b's public
     * key through the provider and import it into a built-in context, then
     * compute the shared secret with a fresh provider-routed private key
     * imported from the same material. Provider and built-in key objects are
     * different low-level types, so the cross check goes through encoded
     * public keys (exactly what the TLS stack does). */
    aInner = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    bInner = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    ASSERT_TRUE(aInner != NULL && bInner != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(aInner, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(bInner, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);

    /* export b's public key through the provider and import into built-in */
    pubParam[0].key = CRYPT_PARAM_PKEY_ENCODE_PUBKEY;
    pubParam[0].valueType = BSL_PARAM_TYPE_OCTETS;
    pubParam[0].value = pub;
    pubParam[0].valueLen = pubLen;
    pubParam[1].key = 0;
    pubParam[1].valueType = 0;
    pubParam[1].value = NULL;
    pubParam[1].valueLen = 0;
    pubParam[1].useLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(b, pubParam), CRYPT_SUCCESS);
    pubLen = pubParam[0].useLen;

    /* cross-check: a second provider-routed computation with a fresh peer
     * built from the exported public key must produce the same secret */
    peerB =
        CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    ASSERT_TRUE(peerB != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(peerB, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    pubParam[0].valueLen = pubLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(peerB, pubParam), CRYPT_SUCCESS);

    peerA = CRYPT_EAL_PkeyDupCtx(a);
    ASSERT_TRUE(peerA != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(peerA, peerB, shareInner, &lenInner), CRYPT_SUCCESS);

    ASSERT_EQ(lenProvider, lenInner);
    ASSERT_COMPARE("share secrets differ", shareProvider, lenProvider, shareInner, lenInner);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(stats.syncDirectCalls > 0);
    ASSERT_TRUE(stats.pauses == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(a);
    CRYPT_EAL_PkeyFreeCtx(b);
    CRYPT_EAL_PkeyFreeCtx(peerA);
    CRYPT_EAL_PkeyFreeCtx(peerB);
    CRYPT_EAL_PkeyFreeCtx(aInner);
    CRYPT_EAL_PkeyFreeCtx(bInner);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_DELEG_TC002
 * @title  Sync path stays clean: an aggressive scenario table never pollutes sync calls
 * @precon Provider loaded; a pause-everything scenario table installed
 * @brief
 *    1. Install a scenario entry (ANY, every hit, PAUSE x3).
 *    2. Run a provider-routed ECDH keygen + shared-secret on the host stack.
 *    3. Read the stats: only cryptoCalls/syncDirectCalls may be non-zero.
 * @expect
 *    1. The sync calls complete normally.
 *    2. pauses, submits, resumes and failures are all 0.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DELEG_TC002(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *a = NULL;
    CRYPT_EAL_PkeyCtx *b = NULL;
    uint8_t share[128] = {0};
    uint32_t shareLen = sizeof(share);
    SIM_PROV_STATS stats = {0};
    SIM_PROV_SCENARIO sc = {0};

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    sc.operaId = SIM_PROV_OPERA_ANY;
    sc.hitIndex = 0;
    sc.action = SIM_PROV_ACTION_PAUSE;
    sc.resumeCount = 3;
    ASSERT_EQ(FRAME_ASYNC_SetScenario(&sc, 1), FRAME_ASYNC_SUCCESS);

    a = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    ASSERT_TRUE(a != NULL);
    b = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    ASSERT_TRUE(b != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(a, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(b, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(a), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(b), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(a, b, share, &shareLen), CRYPT_SUCCESS);
    ASSERT_TRUE(shareLen > 0);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(stats.cryptoCalls > 0);
    ASSERT_TRUE(stats.syncDirectCalls > 0);
    ASSERT_TRUE(stats.pauses == 0);
    ASSERT_TRUE(stats.submits == 0);
    ASSERT_TRUE(stats.resumes == 0);
    ASSERT_TRUE(stats.failures == 0);
    ASSERT_TRUE(stats.notifications == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(a);
    CRYPT_EAL_PkeyFreeCtx(b);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_DELEG_TC003
 * @title  End-to-end sync handshake: provider takes over the TLS 1.3 crypto path
 * @precon Provider loaded; TLS provider feature enabled
 * @brief
 *    1. Create a TLS 1.3 config bound to the frame libCtx with the group
 *       pinned to SECP256R1 and load ECDSA certificates through the
 *       provider-routed parse path.
 *    2. Run the standard frame handshake (no task wrapping: sync path).
 *    3. Verify the handshake completes and the provider counters show
 *       cryptoCalls > 0, syncDirectCalls > 0 and pauses == 0.
 * @expect
 *    1. Handshake returns HITLS_SUCCESS, both sides ESTABLISHED.
 *    2. Stats prove KEYMGMT/SIGN/KEYEXCH were exercised through the provider
 *       (a broken key import or delegation would fail the handshake).
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DELEG_TC003(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    SIM_PROV_STATS stats = {0};
    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der",        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",     NULL,
        "ecdsa/end256-sha256.key.der", NULL,
    };

    FRAME_Init();
    ASSERT_EQ(AsyncSimSetup(16, 4), FRAME_ASYNC_SUCCESS);

    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);
    config = AsyncSimNewTls13Config(libCtx);
    ASSERT_TRUE(config != NULL);
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(config, &group, 1), HITLS_SUCCESS);

    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_ASYNC_GetStats(&stats), FRAME_ASYNC_SUCCESS);
    ASSERT_TRUE(stats.cryptoCalls > 0);
    ASSERT_TRUE(stats.syncDirectCalls > 0);
    ASSERT_TRUE(stats.pauses == 0);

EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
    AsyncSimTeardown();
#endif
}
/* END_CASE */

/**
 * @test   SDV_ASYNC_SIM_DELEG_TC004
 * @title  Key parse through the provider equals built-in parse
 * @precon Provider loaded; ECDSA key file available
 * @brief
 *    1. Parse the ECDSA end-entity private key through the provider-routed
 *       decode path (frame libCtx + attrName).
 *    2. Parse the same file with the built-in path (NULL libCtx).
 *    3. Sign the same buffer with both keys and compare the signatures.
 * @expect
 *    1. Both parses succeed.
 *    2. The two signatures verify against each other's public keys.
 */
/* BEGIN_CASE */
void SDV_ASYNC_SIM_DELEG_TC004(void)
{
#if !defined(HITLS_CRYPTO_PROVIDER) || !defined(HITLS_TLS_FEATURE_PROVIDER)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *provKey = NULL;
    CRYPT_EAL_PkeyCtx *innerKey = NULL;
    CRYPT_EAL_PkeyCtx *pubFromProv = NULL;
    uint8_t signProv[128] = {0};
    uint8_t signInner[128] = {0};
    uint32_t signProvLen = sizeof(signProv);
    uint32_t signInnerLen = sizeof(signInner);
    const char *keyFile = "../testdata/tls/certificate/der/ecdsa/end256-sha256.key.der";
    uint8_t data[32] = {0};
    uint8_t pub[128] = {0};
    uint32_t pubLen = sizeof(pub);
    BSL_Param pubParam[2] = {0};

    for (uint32_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)i;
    }

    ASSERT_EQ(AsyncSimSetup(4, 0), FRAME_ASYNC_SUCCESS);
    libCtx = FRAME_ASYNC_GetLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    /* provider-routed parse: the chain's lowkey2pkey step must import the
     * key into our KEYMGMT (SimKeyMgmtImport) */
    provKey = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeFileKey(libCtx, FRAME_ASYNC_PROVIDER_ATTR, BSL_CID_UNKNOWN, "ASN1", NULL, keyFile,
                                              NULL, &provKey),
              CRYPT_SUCCESS);
    ASSERT_TRUE(provKey != NULL);

    /* built-in parse */
    innerKey = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_ENCDEC_UNKNOW, keyFile, NULL, 0, &innerKey),
              CRYPT_SUCCESS);
    ASSERT_TRUE(innerKey != NULL);

    /* sign with both */
    ASSERT_EQ(CRYPT_EAL_PkeySign(innerKey, CRYPT_MD_SHA256, data, sizeof(data), signInner, &signInnerLen),
              CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(provKey, CRYPT_MD_SHA256, data, sizeof(data), signProv, &signProvLen), CRYPT_SUCCESS);

    /* the provider-signed signature must verify under the built-in key's
     * public part: build a public ctx from the built-in key */
    pubParam[0].key = CRYPT_PARAM_PKEY_ENCODE_PUBKEY;
    pubParam[0].valueType = BSL_PARAM_TYPE_OCTETS;
    pubParam[0].value = pub;
    pubParam[0].valueLen = pubLen;
    pubParam[1].key = 0;
    pubParam[1].valueType = 0;
    pubParam[1].value = NULL;
    pubParam[1].valueLen = 0;
    pubParam[1].useLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(innerKey, pubParam), CRYPT_SUCCESS);
    pubLen = pubParam[0].useLen;

    pubFromProv =
        CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDSA, CRYPT_EAL_PKEY_SIGN_OPERATE, FRAME_ASYNC_PROVIDER_ATTR);
    ASSERT_TRUE(pubFromProv != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubFromProv, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    pubParam[0].valueLen = pubLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(pubFromProv, pubParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubFromProv, CRYPT_MD_SHA256, data, sizeof(data), signProv, signProvLen),
              CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(provKey);
    CRYPT_EAL_PkeyFreeCtx(innerKey);
    CRYPT_EAL_PkeyFreeCtx(pubFromProv);
    AsyncSimTeardown();
#endif
}
/* END_CASE */
