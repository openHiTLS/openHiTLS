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
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_init.h"
#include "crypt_eal_provider.h"
#include "crypt_provider_local.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_eal_mac.h"
#include "eal_mac_local.h"
#include "crypt_eal_kdf.h"
#include "eal_kdf_local.h"
#include "crypt_eal_md.h"
#include "eal_md_local.h"
#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
#include "test.h"
#include "crypt_eal_cmvp.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_errno.h"
#include "crypt_eal_md.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "crypt_eal_entropy.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
/* END_HEADER */

#ifdef HITLS_CRYPTO_CMVP_SM_PURE_C
#define HITLS_CRYPTO_CMVP_SM
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/C/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_ARMV8_LE
#define HITLS_CRYPTO_CMVP_SM
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/armv8_le/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_X86_64
#define HITLS_CRYPTO_CMVP_SM
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/x86_64/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM
#ifndef HITLS_PROVIDER_LIB_NAME
#error "HITLS_PROVIDER_LIB_NAME must be defined by build system"
#endif
#define HITLS_SM_LIB_NAME HITLS_PROVIDER_LIB_NAME
#define HITLS_SM_PROVIDER_ATTR "provider=sm"

static CRYPT_EAL_LibCtx *SM_ProviderLoad(void)
{
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, HITLS_SM_PROVIDER_PATH), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, HITLS_SM_LIB_NAME, NULL, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(libCtx, CRYPT_RAND_SM4_CTR_DF, HITLS_SM_PROVIDER_ATTR, NULL, 0, NULL),
        CRYPT_SUCCESS);
    return libCtx;

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    return NULL;
}

static void SM_ProviderUnload(CRYPT_EAL_LibCtx *ctx)
{
    CRYPT_EAL_RandDeinitEx(ctx);
    CRYPT_EAL_LibCtxFree(ctx);
}

#endif /* HITLS_CRYPTO_CMVP_SM */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_PKEY_SIGN_VERIFY_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_SM
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    uint8_t signature[128] = {0};
    uint32_t signatureLen = sizeof(signature);
    uint8_t testData[] = "Test data for signing and verification with ECDSA";
    uint32_t testDataLen = sizeof(testData) - 1;

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SM3, testData, testDataLen, signature, &signatureLen), 0);
    ASSERT_TRUE(signatureLen > 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, CRYPT_MD_SM3, testData, testDataLen, signature, signatureLen),
        CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_DRBG_TEST_TC001(int algId)
{
#ifndef HITLS_CRYPTO_CMVP_SM
    (void)algId;
    SKIP_TEST();
#else
    CRYPT_EAL_RndCtx *randCtx = NULL;
    CRYPT_EAL_LibCtx *libCtx = NULL;

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    randCtx = CRYPT_EAL_ProviderDrbgNewCtx(libCtx, algId, NULL, NULL);
    ASSERT_TRUE(randCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(randCtx, NULL, 0), CRYPT_SUCCESS);

    uint8_t data[16] = {0};
    uint32_t dataLen = sizeof(data);

    ASSERT_EQ(CRYPT_EAL_Drbgbytes(randCtx, data, dataLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DrbgSeed(randCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_Drbgbytes(randCtx, data, dataLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_DrbgDeinit(randCtx);
    SM_ProviderUnload(libCtx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_MD_TEST_TC001(int algId)
{
#ifndef HITLS_CRYPTO_CMVP_SM
    (void)algId;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint8_t plaintext[128] = {0};
    uint32_t plaintextLen = sizeof(plaintext);
    uint8_t md[128] = {0};
    uint32_t mdLen = sizeof(md);

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, algId, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(mdCtx != NULL);
    int32_t ret = CRYPT_EAL_MdInit(mdCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_MdUpdate(mdCtx, plaintext, plaintextLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_MdFinal(mdCtx, md, &mdLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_MAC_TEST_TC001(int algId, int keyLen)
{
#ifndef HITLS_CRYPTO_CMVP_SM
    (void)algId;
    (void)keyLen;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_MacCtx *macCtx = NULL;
    uint8_t macKey[32] = {0};
    uint32_t macKeyLen = keyLen;
    uint8_t plaintext[128] = {0};
    uint32_t plaintextLen = sizeof(plaintext);
    uint8_t mac[128] = {0};
    uint32_t macLen = sizeof(mac);

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    macCtx = CRYPT_EAL_ProviderMacNewCtx(libCtx, algId, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(macCtx != NULL);
    int32_t ret = CRYPT_EAL_MacInit(macCtx, macKey, macKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    if (algId == CRYPT_MAC_CBC_MAC_SM4) {
        int32_t padType = CRYPT_PADDING_ZEROS;
        ASSERT_EQ(CRYPT_EAL_MacCtrl(macCtx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)),
            CRYPT_SUCCESS);
    }

    ret = CRYPT_EAL_MacUpdate(macCtx, plaintext, plaintextLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_MacFinal(macCtx, mac, &macLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MacFreeCtx(macCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_KDF_TEST_TC001(int macId, int iter, int saltLen)
{
#ifndef HITLS_CRYPTO_CMVP_SM
    (void)macId;
    (void)iter;
    (void)saltLen;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    uint8_t password[32] = {0};
    uint32_t passwordLen = sizeof(password);
    uint8_t salt[32] = {0};
    uint8_t derivedKey[32] = {0};
    uint32_t derivedKeyLen = sizeof(derivedKey);

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_PBKDF2, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    BSL_Param param[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};

    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId));
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, password, passwordLen);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    (void)BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(iter));

    int32_t ret = CRYPT_EAL_KdfSetParam(kdfCtx, param);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_KdfDerive(kdfCtx, derivedKey, derivedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_CMVP_SELFTEST_Test_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_SM
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_SelftestCtx *selftestCtx = NULL;

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    selftestCtx = CRYPT_CMVP_SelftestNewCtx(libCtx, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(selftestCtx != NULL);

    const char *version = CRYPT_CMVP_GetVersion(selftestCtx);
    ASSERT_TRUE(version != NULL);

    BSL_Param params[3] = {{0}, BSL_PARAM_END, BSL_PARAM_END};
    int32_t type = CRYPT_CMVP_KAT_TEST;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_CMVP_SELFTEST_TYPE, BSL_PARAM_TYPE_INT32,
        &type, sizeof(type)), CRYPT_SUCCESS);
    int32_t ret = CRYPT_CMVP_Selftest(selftestCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    type = CRYPT_CMVP_INTEGRITY_TEST;
    ret = CRYPT_CMVP_Selftest(selftestCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    type = CRYPT_CMVP_RANDOMNESS_TEST;
    uint8_t random[32] = {0};
    uint32_t randomLen = sizeof(random);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(libCtx, random, randomLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_CMVP_RANDOM, BSL_PARAM_TYPE_OCTETS,
        random, randomLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ret = CRYPT_CMVP_Selftest(selftestCtx, params);
    ASSERT_TRUE(ret == CRYPT_SUCCESS || ret == CRYPT_CMVP_RANDOMNESS_ERR);

EXIT:
    CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_CIPHPER_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_SM
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_CipherCtx *cipherCtx = NULL;

    uint8_t key[32] = {0};
    uint32_t keyLen = 16;
    uint8_t iv[32] = {0};
    uint32_t ivLen = 16;
    uint8_t plain[] = "Test data for signing and verification with ECDSA";
    uint32_t plainLen = sizeof(plainLen) - 1;
    uint8_t cipher[128] = {0};
    uint32_t cipherLen = sizeof(cipher);

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    cipherCtx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, CRYPT_CIPHER_SM4_CBC, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(cipherCtx != NULL);

    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, key, keyLen, iv, ivLen, true);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_CipherSetPadding(cipherCtx, CRYPT_PADDING_PKCS7);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t tmpLen = cipherLen;
    ret = CRYPT_EAL_CipherUpdate(cipherCtx, plain, plainLen, cipher, &tmpLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    cipherLen = tmpLen;
    tmpLen = sizeof(cipher) - cipherLen;
    ret = CRYPT_EAL_CipherFinal(cipherCtx, cipher + cipherLen, &tmpLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    cipherLen += tmpLen;
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(cipherCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_KDF_PARAM_CHECK_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_SM
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    uint8_t password[32] = {0};
    uint32_t passwordLen = sizeof(password);
    uint8_t salt[32] = {0};
    uint8_t derivedKey[32] = {0};

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_PBKDF2, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    int32_t iter = 1024;
    int32_t saltLen = 8;
    int32_t macId = CRYPT_MAC_HMAC_SHA256;

    BSL_Param param[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId));
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, password, passwordLen);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    (void)BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(iter));

    int32_t ret = CRYPT_EAL_KdfSetParam(kdfCtx, param);
    ASSERT_EQ(ret, CRYPT_CMVP_ERR_PARAM_CHECK);

    macId = CRYPT_MAC_HMAC_SM3;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_SUCCESS);

    iter = 1023;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_CMVP_ERR_PARAM_CHECK);

    iter = 1024;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_SUCCESS);

    saltLen = 7;
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_CMVP_ERR_PARAM_CHECK);

    saltLen = 8;
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_SUCCESS);

    uint32_t derivedKeyLen = 1;
    ret = CRYPT_EAL_KdfDerive(kdfCtx, derivedKey, derivedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_SM2_CHECK_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_SM
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pkeyCtx, pkeyCtx), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    SM_ProviderUnload(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_SM_PROVIDER_KDF_KDFTLS12_TEST_TC001(int algId, Hex *key, Hex *label, Hex *seed)
{
#ifndef HITLS_CRYPTO_CMVP_SM
    (void)algId;
    (void)key;
    (void)label;
    (void)seed;
    SKIP_TEST();
#else
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    uint32_t outLen = 32;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    libCtx = SM_ProviderLoad();
    ASSERT_TRUE(libCtx != NULL);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_KDFTLS12, HITLS_SM_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    int32_t index = 0;
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed->x, seed->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(kdfCtx, out, outLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    SM_ProviderUnload(libCtx);
#endif
}
/* END_CASE */
