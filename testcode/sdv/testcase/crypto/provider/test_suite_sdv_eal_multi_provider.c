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

#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_provider.h"
#include "crypt_params_key.h"
/* END_HEADER */

#define SHA2_OUTPUT_MAXSIZE 32
#define MAX_CIPHERTEXT_LEN 2048

#define DEFAULT_PROVIDER "default"

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t InitTwoProviders(CRYPT_EAL_LibCtx **libCtx, const char *path, const char *providerName1,
    const char *providerName2)
{
    *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(*libCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(*libCtx, path), 0);

    if (strcmp(providerName1, DEFAULT_PROVIDER) == 0) {
        ASSERT_EQ(CRYPT_EAL_ProviderLoad(*libCtx, BSL_SAL_LIB_FMT_OFF, providerName1, NULL, NULL), 0);
    } else {
        ASSERT_EQ(CRYPT_EAL_ProviderLoad(*libCtx, BSL_SAL_LIB_FMT_SO, providerName1, NULL, NULL), 0);
    }

    if (strcmp(providerName2, DEFAULT_PROVIDER) == 0) {
        ASSERT_EQ(CRYPT_EAL_ProviderLoad(*libCtx, BSL_SAL_LIB_FMT_OFF, providerName2, NULL, NULL), 0);
    } else {
        ASSERT_EQ(CRYPT_EAL_ProviderLoad(*libCtx, BSL_SAL_LIB_FMT_SO, providerName2, NULL, NULL), 0);
    }

    return 0;
EXIT:
    CRYPT_EAL_LibCtxFree(*libCtx);
    *libCtx = NULL;
    return 1;
}
#endif

void NoUsedParam(char *path, char *defProName, char *customProName, char *defAttr, char *customAttr)
{
    (void)path;
    (void)defProName;
    (void)customProName;
    (void)defAttr;
    (void)customAttr;
}

/**
 * @test SDV_PROVIDER_SHA256_TC001
 * @title SHA256 test: sha256 from no-provider, default provider or other provider
 */
/* BEGIN_CASE */
void SDV_PROVIDER_SHA256_TC001(char *path, char *defProName, char *customProName, char *customAttr,
    Hex *in, Hex *digest)
{
#if defined(HITLS_CRYPTO_MD) && defined(HITLS_CRYPTO_PROVIDER)
    CRYPT_EAL_MdCTX *ctx = NULL;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    uint8_t out[SHA2_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA2_OUTPUT_MAXSIZE;

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);

    ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, customAttr);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), 0);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, in->x, in->len), 0);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), 0);
    ASSERT_COMPARE("other provider sha256", out, outLen, digest->x, digest->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
#else
    NoUsedParam(path, defProName, customProName, NULL, customAttr);
    (void)in;
    (void)digest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PROVIDER_HMAC_TC001
 * @title HMAC test
 */
/* BEGIN_CASE */
void SDV_PROVIDER_HMAC_TC001(char *path, char *defProName, char *customProName, char *defAttr, char *customAttr,
    int algId, Hex *key, Hex *data, Hex *vecMac)
{
#if defined(HITLS_CRYPTO_HMAC) && defined(HITLS_CRYPTO_PROVIDER)
    uint8_t *out = NULL;
    uint32_t outLen = vecMac->len;
    CRYPT_EAL_MacCtx *ctx = NULL;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    BSL_Param params[] = {{0}, BSL_PARAM_END}; // Set 1 parameter for hmac

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);

    out = (uint8_t *)BSL_SAL_Malloc(outLen);
    ASSERT_TRUE(out != NULL);

    // HMAC-SHA256: hmac from default provider, sha256 from custom provider
    ctx = CRYPT_EAL_ProviderMacNewCtx(libCtx, algId, strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);
    ASSERT_EQ(CRYPT_EAL_MacSetParam(ctx, params), 0);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), 0);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), 0);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, out, &outLen), 0);
    ASSERT_COMPARE("default hmac other sha256", out, outLen, vecMac->x, vecMac->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    BSL_SAL_Free(out);
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)algId;
    (void)key;
    (void)data;
    (void)vecMac;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PROVIDER_HKDF_TC001
 * @title hkdf-hmac-sha256 provider test, hkdf-hmac from default provider, sha256 from provider1 or provider2
 */
/* BEGIN_CASE */
void SDV_PROVIDER_HKDF_TC001(char *path, char *defProName, char *customProName, char *defAttr, char *customAttr,
    int macId, Hex *key, Hex *salt, Hex *info, Hex *result)
{
#if defined(HITLS_CRYPTO_HKDF) && defined(HITLS_CRYPTO_PROVIDER)
    uint8_t *out = NULL;
    uint32_t outLen = result->len;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    BSL_Param params[7] = {{0}, {0}, {0}, {0}, {0}, {0}, BSL_PARAM_END}; // Set 6 parameters for hkdf
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);

    out = (uint8_t *)BSL_SAL_Malloc(outLen);
    ASSERT_TRUE(out != NULL);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId)), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode)), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, key->x, key->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt->x, salt->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, info->x, info->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);

    // HMAC-SHA256: hmac from default provider, sha256 from custom provider
    ctx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_HKDF, strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    // sha256 form provider2
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), 0);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), 0);
    ASSERT_COMPARE("default hkdf-hmac other sha256", out, outLen, result->x, result->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    BSL_SAL_Free(out);
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)macId;
    (void)key;
    (void)salt;
    (void)info;
    (void)result;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PROVIDER_PBKDF2_TC001
 * @title pbkdf2-hmac-sha256 provider test, pbkdf2 from default provider, sha256 from provider1 or provider2
 */
/* BEGIN_CASE */
void SDV_PROVIDER_PBKDF2_TC001(char *path, char *defProName, char *customProName, char *defAttr, char *customAttr,
    int macId, Hex *key, Hex *salt, int it, Hex *result)
{
#if defined(HITLS_CRYPTO_PBKDF2) && defined(HITLS_CRYPTO_PROVIDER)
    uint8_t *out = NULL;
    uint32_t outLen = result->len;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END}; // Set 5 parameters for pbkdf2

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);

    out = (uint8_t *)BSL_SAL_Malloc(outLen);
    ASSERT_TRUE(out != NULL);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId)), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, key->x, key->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt->x, salt->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &it, sizeof(it)), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);

    // provider1: pbkdf2, provider2: sha256
    ctx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_PBKDF2, strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    // sha256 form provider2
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), 0);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), 0);
    ASSERT_COMPARE("default pbkdf2 other sha256", out, outLen, result->x, result->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    BSL_SAL_Free(out);
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)macId;
    (void)key;
    (void)salt;
    (void)it;
    (void)result;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PROVIDER_KDFTLS12_TC001
 * @title kdftls12-hmac-sha256 provider test, kdftls12 from default provider, sha256 from provider1 or provider2
 */
/* BEGIN_CASE */
void SDV_PROVIDER_KDFTLS12_TC001(char *path, char *defProName, char *customProName, char *defAttr, char *customAttr,
    int macId, Hex *key, Hex *label, Hex *seed, Hex *result)
{
#if defined(HITLS_CRYPTO_KDFTLS12) && defined(HITLS_CRYPTO_PROVIDER)
    uint8_t *out = NULL;
    uint32_t outLen = result->len;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END}; // Set 5 parameters for kdftls12

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);

    out = (uint8_t *)BSL_SAL_Malloc(outLen);
    ASSERT_TRUE(out != NULL);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId)), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, key->x, key->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS, label->x, label->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS, seed->x, seed->len), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);

    // provider1: kdftls12, provider2: sha256
    ctx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_KDFTLS12, strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    // sha256 form provider2
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), 0);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), 0);
    ASSERT_COMPARE("default kdftls12 other sha256", out, outLen, result->x, result->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    BSL_SAL_Free(out);
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)macId;
    (void)key;
    (void)label;
    (void)seed;
    (void)result;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_RSA_SIGN_TC001
 * @title rsa-sign provider test, rsa-sign from default provider, sha256 from provider1 or provider2
 */
/* BEGIN_CASE */
void SDV_PROVIDER_RSA_SIGN_VERIFY_PKCSV15_TC001(char *path, char *defProName, char *customProName, char *defAttr,
    char *customAttr, int mdId, Hex *n, Hex *e, Hex *d, Hex *msg)
{
#if defined(HITLS_CRYPTO_RSA_SIGN) && defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15) && defined(HITLS_CRYPTO_PROVIDER)
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t signLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyPrv prvKey = {.id = CRYPT_PKEY_RSA, .key.rsaPrv.n = n->x, .key.rsaPrv.nLen = n->len,
        .key.rsaPrv.d = d->x, .key.rsaPrv.dLen = d->len};
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_RSA, .key.rsaPub.n = n->x, .key.rsaPub.nLen = n->len,
        .key.rsaPub.e = e->x, .key.rsaPub.eLen = e->len};
    BSL_Param params[2] = {{0}, BSL_PARAM_END}; // Set 1 parameter for hmac

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);
    ASSERT_EQ(TestRandInitEx(libCtx), 0);

    // rsa-sign-verify-pkcsv15 from default provider, sha256 from custom provider
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
        strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubKey), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prvKey), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId)), 0);
    signLen = MAX_CIPHERTEXT_LEN;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, msg->x, msg->len, sign, &signLen), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, msg->x, msg->len, sign, signLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_RandDeinit();
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)mdId;
    (void)n;
    (void)e;
    (void)d;
    (void)msg;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_RSA_SIGN_VERIFY_PSS_TC001
 * @title rsa-sign-verify-pss provider test, rsa-sign-verify-pss from default provider
 */
/* BEGIN_CASE */
void SDV_PROVIDER_RSA_SIGN_VERIFY_PSS_TC001(char *path, char *defProName, char *customProName, char *defAttr,
    char *customAttr, int mdId, Hex *n, Hex *e, Hex *d, Hex *msg, int saltLen)
{
#if defined(HITLS_CRYPTO_RSA_SIGN) && defined(HITLS_CRYPTO_RSA_EMSA_PSS) && defined(HITLS_CRYPTO_PROVIDER)
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {.id = CRYPT_PKEY_RSA, .key.rsaPrv.n = n->x, .key.rsaPrv.nLen = n->len,
        .key.rsaPrv.d = d->x, .key.rsaPrv.dLen = d->len};
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_RSA, .key.rsaPub.n = n->x, .key.rsaPub.nLen = n->len,
        .key.rsaPub.e = e->x, .key.rsaPub.eLen = e->len};
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t signLen = MAX_CIPHERTEXT_LEN;
    CRYPT_MD_AlgId paramMdId = (CRYPT_MD_AlgId)mdId;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &paramMdId, sizeof(paramMdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &paramMdId, sizeof(paramMdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    BSL_Param params[2] = {{0}, BSL_PARAM_END}; // Set 1 parameter for RSA

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);
    ASSERT_EQ(TestRandInitEx(libCtx), 0);

    // rsa-sign-verify-pss from default provider, sha256 from custom provider
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
        strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubKey), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prvKey), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pssParam, 0), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), 0);
    signLen = MAX_CIPHERTEXT_LEN;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, paramMdId, msg->x, msg->len, sign, &signLen), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, paramMdId, msg->x, msg->len, sign, signLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_RandDeinit();
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)mdId;
    (void)n;
    (void)e;
    (void)d;
    (void)msg;
    (void)saltLen;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_RSA_RSABSSA_BLINDING_TC001
 * @title rsa-rsabssa-blinding provider test, rsa-rsabssa-blinding from default provider
 */
/* BEGIN_CASE */
void SDV_PROVIDER_RSA_RSABSSA_BLINDING_TC001(char *path, char *defProName, char *customProName, char *defAttr,
    char *customAttr, int mdId, Hex *n, Hex *e, Hex *d, Hex *msg, int saltLen)
{
#if defined(HITLS_CRYPTO_RSA_SIGN) && defined(HITLS_CRYPTO_RSA_BSSA) && defined(HITLS_CRYPTO_PROVIDER)
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {.id = CRYPT_PKEY_RSA, .key.rsaPrv.n = n->x, .key.rsaPrv.nLen = n->len,
        .key.rsaPrv.d = d->x, .key.rsaPrv.dLen = d->len};
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_RSA, .key.rsaPub.n = n->x, .key.rsaPub.nLen = n->len,
        .key.rsaPub.e = e->x, .key.rsaPub.eLen = e->len};
#ifdef HITLS_CRYPTO_RSA_SIGN
    uint8_t blindMsg[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t blindMsgLen = MAX_CIPHERTEXT_LEN;
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    uint8_t unBlindSig[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t unBlindSigLen = MAX_CIPHERTEXT_LEN;
#endif
    uint32_t flag = CRYPT_RSA_BSSA;
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t signLen = MAX_CIPHERTEXT_LEN;
    CRYPT_MD_AlgId paramMdId = (CRYPT_MD_AlgId)mdId;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &paramMdId, sizeof(paramMdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &paramMdId, sizeof(paramMdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    BSL_Param params[2] = {{0}, BSL_PARAM_END}; // Set 1 parameter for RSA

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);
    ASSERT_EQ(TestRandInitEx(libCtx), 0);

    // rsa-rsabssa-blinding from default provider, sha256 from custom provider
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
        strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubKey), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prvKey), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pssParam, 0), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t)), 0);

#ifdef HITLS_CRYPTO_RSA_SIGN
    ASSERT_EQ(CRYPT_EAL_PkeyBlind(ctx, paramMdId, msg->x, msg->len, blindMsg, &blindMsgLen), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, blindMsg, blindMsgLen, sign, &signLen), 0);
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    ASSERT_EQ(CRYPT_EAL_PkeyUnBlind(ctx, sign, signLen, unBlindSig, &unBlindSigLen), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, paramMdId, msg->x, msg->len, unBlindSig, unBlindSigLen), 0);
#endif

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_RandDeinit();
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)mdId;
    (void)n;
    (void)e;
    (void)d;
    (void)msg;
    (void)saltLen;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PROVIDER_RSA_CRYPT_FUNC_TC001(char *path, char *defProName, char *customProName, char *defAttr,
    char *customAttr, int padMode, int mdId, Hex *n, Hex *e, Hex *d, Hex *plaintext)
{
#if defined(HITLS_CRYPTO_RSA_DECRYPT) && defined(HITLS_CRYPTO_RSA_ENCRYPT) && defined(HITLS_CRYPTO_PROVIDER)
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyPrv prvkey = {.id = CRYPT_PKEY_RSA, .key.rsaPrv.n = n->x, .key.rsaPrv.nLen = n->len,
        .key.rsaPrv.d = d->x, .key.rsaPrv.dLen = d->len};
    CRYPT_EAL_PkeyPub pubkey = {.id = CRYPT_PKEY_RSA, .key.rsaPub.n = n->x, .key.rsaPub.nLen = n->len,
        .key.rsaPub.e = e->x, .key.rsaPub.eLen = e->len};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_MD_AlgId paramMdId = (CRYPT_MD_AlgId)mdId;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &paramMdId, sizeof(paramMdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &paramMdId, sizeof(paramMdId), 0},
        BSL_PARAM_END};
    int32_t pkcsv15 = mdId;
    uint8_t pt[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t ptLen = MAX_CIPHERTEXT_LEN;
    uint8_t ct[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t ctLen = MAX_CIPHERTEXT_LEN;
    int paraSize;
    void *paraPtr;
    BSL_Param params[2] = {{0}, BSL_PARAM_END}; // Set 1 parameter for RSA

    if (padMode == CRYPT_CTRL_SET_RSA_RSAES_OAEP) {
        paraSize = 0;
        paraPtr = oaepParam;
    } else if (padMode == CRYPT_CTRL_SET_RSA_RSAES_PKCSV15) {
        paraSize = sizeof(pkcsv15);
        paraPtr = &pkcsv15;
    }

    TestMemInit();
    ASSERT_EQ(InitTwoProviders(&libCtx, path, defProName, customProName), 0);
    ASSERT_EQ(TestRandInitEx(libCtx), 0);

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_CIPHER_OPERATE,
        strlen(defAttr) == 0 ? NULL : defAttr);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prvkey), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubkey), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, padMode, paraPtr, paraSize), 0);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_MD_ATTR, BSL_PARAM_TYPE_UTF8_STR, customAttr,
        strlen(customAttr)), 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, plaintext->x, plaintext->len, ct, &ctLen), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctLen, pt, &ptLen), 0);
    ASSERT_EQ(ptLen, plaintext->len);
    ASSERT_COMPARE("rsa encrypt and decrypt", pt, ptLen, plaintext->x, plaintext->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_RandDeinit();
#else
    NoUsedParam(path, defProName, customProName, defAttr, customAttr);
    (void)padMode;
    (void)mdId;
    (void)n;
    (void)e;
    (void)d;
    (void)plaintext;
    SKIP_TEST();
#endif
}
/* END_CASE */
