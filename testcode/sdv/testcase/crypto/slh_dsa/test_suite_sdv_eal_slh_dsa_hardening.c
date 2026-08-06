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
#include <string.h>
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_params_key.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_slh_dsa.h"
#include "crypt_util_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "slh_dsa_local.h"
#include "stub_utils.h"
#include "test.h"
/* END_HEADER */
STUB_DEFINE_RET2(void *, BSL_SAL_Calloc, uint32_t, uint32_t);
STUB_DEFINE_RET6(int32_t, SlhDsaSignInternal, const CryptSlhDsaCtx *, const uint8_t *, uint32_t, const uint8_t *,
    uint8_t *, uint32_t *);
STUB_DEFINE_VOID2(BSL_SAL_CleanseData, void *, uint32_t);

static const void *g_expectedCleansePtr = NULL;
static bool g_expectedCleanseObserved = false;

static void ObserveSlhDsaCleanse(void *ptr, uint32_t size)
{
    if (ptr == g_expectedCleansePtr && size == SLH_DSA_MAX_N) {
        g_expectedCleanseObserved = true;
    }
    real_BSL_SAL_CleanseData_func_t realCleanse = get_real_BSL_SAL_CleanseData();
    if (realCleanse != NULL) {
        realCleanse(ptr, size);
    }
}

static int32_t SlhDsaSignInternalFail(const CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen,
    const uint8_t *addrand, uint8_t *sig, uint32_t *sigLen)
{
    (void)ctx;
    (void)msg;
    (void)msgLen;
    g_expectedCleansePtr = addrand;
    (void)memset(sig, 0x3c, *sigLen);
    return CRYPT_INVALID_ARG;
}

static void *SlhDsaMdCtxCallocFail(uint32_t count, uint32_t size)
{
    (void)count;
    (void)size;
    return NULL;
}

static uint32_t g_slhDsaMdCtxCallocCount = 0;

static void *SlhDsaSecondMdCtxCallocFail(uint32_t count, uint32_t size)
{
    if (g_slhDsaMdCtxCallocCount++ == 1) {
        return NULL;
    }
    real_BSL_SAL_Calloc_func_t realCalloc = get_real_BSL_SAL_Calloc();
    return realCalloc == NULL ? NULL : realCalloc(count, size);
}

uint32_t g_stubRandCounter = 0;
uint8_t **g_stubRand = NULL;
uint32_t *g_stubRandLen = NULL;

void RandInjectionInit()
{
    g_stubRandCounter = 0;
    g_stubRand = NULL;
    g_stubRandLen = NULL;
}

void RandInjectionSet(uint8_t **rand, uint32_t *len)
{
    g_stubRand = rand;
    g_stubRandLen = len;
}

int32_t RandInjection(uint8_t *rand, uint32_t randLen)
{
    memcpy(rand, g_stubRand[g_stubRandCounter], randLen);
    g_stubRandCounter++;
    return CRYPT_SUCCESS;
}

int32_t RandInjectionEx(void *libCtx, uint8_t *rand, uint32_t randLen)
{
    (void)libCtx;
    return RandInjection(rand, randLen);
}
uint32_t g_failRandCounter = 0;

int32_t RandFailAfterFirst(uint8_t *rand, uint32_t randLen)
{
    if (g_failRandCounter++ != 0) {
        return CRYPT_INVALID_ARG;
    }
    memset(rand, 0x5a, randLen);
    return CRYPT_SUCCESS;
}

int32_t RandFailAfterFirstEx(void *libCtx, uint8_t *rand, uint32_t randLen)
{
    (void)libCtx;
    return RandFailAfterFirst(rand, randLen);
}

static void InitSlhDsaPubParams(BSL_Param *params, uint8_t *pubSeed, uint8_t *pubRoot, uint32_t keyLen)
{
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pubSeed, keyLen);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pubRoot, keyLen);
    params[2] = (BSL_Param)BSL_PARAM_END;
}

static void InitSlhDsaPrvParams(BSL_Param *params, uint8_t *prvSeed, uint8_t *prvPrf, uint8_t *pubSeed,
    uint8_t *pubRoot, uint32_t keyLen)
{
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SLH_DSA_PRV_SEED, BSL_PARAM_TYPE_OCTETS, prvSeed, keyLen);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SLH_DSA_PRV_PRF, BSL_PARAM_TYPE_OCTETS, prvPrf, keyLen);
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pubSeed, keyLen);
    BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pubRoot, keyLen);
    params[4] = (BSL_Param)BSL_PARAM_END;
}

static bool IsSlhDsaKeyMaterialCleared(const CryptSlhDsaCtx *ctx)
{
    const uint8_t *key = (const uint8_t *)&ctx->prvKey;
    if (ctx->keyType != 0 || ctx->sha256MdCtx != NULL || ctx->sha512MdCtx != NULL) {
        return false;
    }
    for (uint32_t i = 0; i < sizeof(ctx->prvKey); i++) {
        if (key[i] != 0) {
            return false;
        }
    }
    return true;
}
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_VERIFY_PREHASHED_KAT_TC001(int id, Hex *key, Hex *addrand, Hex *msg, Hex *context, int hashId,
    Hex *sig, int result)
{
    (void)addrand;
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t keyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPrv prv;
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = key->x;
    prv.key.slhDsaPrv.prf = key->x + keyLen;
    prv.key.slhDsaPrv.pub.seed = key->x + keyLen * 2;
    prv.key.slhDsaPrv.pub.root = key->x + keyLen * 3;
    prv.key.slhDsaPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    if (context->len != 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, context->x, context->len), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, msg->x, msg->len, sig->x, sig->len), result);
    if (result == CRYPT_SUCCESS) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_24_PROFILE_TC001(int isProvider)
{
    static const int32_t profiles[] = {
        CRYPT_SLH_DSA_SHA2_128S,
        CRYPT_SLH_DSA_SHAKE_128S,
        CRYPT_SLH_DSA_SHA2_128F,
        CRYPT_SLH_DSA_SHAKE_128F,
        CRYPT_SLH_DSA_SHA2_192S,
        CRYPT_SLH_DSA_SHAKE_192S,
        CRYPT_SLH_DSA_SHA2_192F,
        CRYPT_SLH_DSA_SHAKE_192F,
        CRYPT_SLH_DSA_SHA2_256S,
        CRYPT_SLH_DSA_SHAKE_256S,
        CRYPT_SLH_DSA_SHA2_256F,
        CRYPT_SLH_DSA_SHAKE_256F,
        CRYPT_HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
        CRYPT_HASH_SLH_DSA_SHA2_128F_WITH_SHA256,
        CRYPT_HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
        CRYPT_HASH_SLH_DSA_SHA2_192F_WITH_SHA512,
        CRYPT_HASH_SLH_DSA_SHA2_256S_WITH_SHA512,
        CRYPT_HASH_SLH_DSA_SHA2_256F_WITH_SHA512,
        CRYPT_HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
        CRYPT_HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128,
        CRYPT_HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
        CRYPT_HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256,
        CRYPT_HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256,
        CRYPT_HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256,
    };
    static const uint32_t keyLens[] = {
        16,
        16,
        16,
        16,
        24,
        24,
        24,
        24,
        32,
        32,
        32,
        32,
        16,
        16,
        24,
        24,
        32,
        32,
        16,
        16,
        24,
        24,
        32,
        32,
    };
    static const uint32_t signLens[] = {
        7856,
        7856,
        17088,
        17088,
        16224,
        16224,
        35664,
        35664,
        29792,
        29792,
        49856,
        49856,
        7856,
        17088,
        16224,
        35664,
        29792,
        49856,
        7856,
        17088,
        16224,
        35664,
        29792,
        49856,
    };
    static const uint32_t securityBits[] = {
        128, 128, 128, 128, 192, 192, 192, 192, 256, 256, 256, 256,
        128, 128, 192, 192, 256, 256, 128, 128, 192, 192, 256, 256,
    };

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    for (uint32_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
        pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
            "provider=default", isProvider);
        ASSERT_TRUE(pkey != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, profiles[i]), CRYPT_SUCCESS);
        int32_t paraId = CRYPT_PKEY_MAX;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)), CRYPT_SUCCESS);
        ASSERT_EQ(paraId, profiles[i]);
        uint32_t keyLen = 0;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
        ASSERT_EQ(keyLen, keyLens[i]);
        ASSERT_EQ(CRYPT_EAL_PkeyGetSignLen(pkey), signLens[i]);
        ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), securityBits[i]);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        pkey = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CHECK_PRVKEY_TC002(void)
{
#if !defined(HITLS_CRYPTO_SLH_DSA_CHECK)
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *valid = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    CRYPT_EAL_PkeyCtx *invalid = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(valid != NULL && invalid != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(valid, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(invalid, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);

    uint8_t zero[16] = {0};
    uint8_t *stubRand[] = {zero, zero, zero};
    uint32_t stubRandLen[] = {sizeof(zero), sizeof(zero), sizeof(zero)};
    RandInjectionInit();
    RandInjectionSet(stubRand, stubRandLen);
    CRYPT_RandRegist(RandInjection);
    CRYPT_RandRegistEx(RandInjectionEx);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(valid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(valid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(valid, valid), CRYPT_SUCCESS);

    uint8_t prvSeed[16] = {0};
    uint8_t prvPrf[16] = {0};
    uint8_t pubSeed[16] = {0};
    uint8_t pubRoot[16] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = prvSeed;
    prv.key.slhDsaPrv.prf = prvPrf;
    prv.key.slhDsaPrv.pub.seed = pubSeed;
    prv.key.slhDsaPrv.pub.root = pubRoot;
    prv.key.slhDsaPrv.pub.len = sizeof(prvSeed);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(valid, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(prvSeed, zero, sizeof(zero)), 0);
    ASSERT_EQ(memcmp(prvPrf, zero, sizeof(zero)), 0);
    ASSERT_EQ(memcmp(pubSeed, zero, sizeof(zero)), 0);

    pubRoot[0] ^= 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(invalid, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(invalid), CRYPT_SLHDSA_ERR_ROOT_MISMATCH);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(valid, invalid), CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(valid);
    CRYPT_EAL_PkeyFreeCtx(invalid);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_EMPTY_MESSAGE_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *hashPkey = NULL;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint8_t empty = 0;
    uint8_t sig[50000] = {0};
    uint32_t sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, NULL, 0, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, &empty, 0, sig, sigLen), CRYPT_SUCCESS);

    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, &empty, 0, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, NULL, 0, sig, sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, NULL, 1, sig, &sigLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, NULL, 1, sig, sigLen), CRYPT_NULL_INPUT);
    TestErrClear();

    hashPkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(hashPkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(hashPkey, CRYPT_HASH_SLH_DSA_SHA2_128F_WITH_SHA256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(hashPkey), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(hashPkey, CRYPT_MD_SHA256, NULL, 0, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(hashPkey, CRYPT_MD_SHA256, NULL, 0, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(hashPkey);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_KEY_STATE_TC001(void)
{
#if !defined(HITLS_CRYPTO_SLH_DSA_CHECK)
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_EAL_PkeyCtx *source = NULL;
    CRYPT_EAL_PkeyCtx *imported = NULL;
    CRYPT_EAL_PkeyCtx *pubOnly = NULL;
    CRYPT_EAL_PkeyCtx *bad = NULL;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    source = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    imported = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    pubOnly = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    bad = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(source != NULL && imported != NULL && pubOnly != NULL && bad != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(source, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(imported, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubOnly, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(bad, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(source), CRYPT_SUCCESS);

    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = prvSeed;
    prv.key.slhDsaPrv.prf = prvPrf;
    prv.key.slhDsaPrv.pub.seed = pubSeed;
    prv.key.slhDsaPrv.pub.root = pubRoot;
    prv.key.slhDsaPrv.pub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(source, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(imported, &prv), CRYPT_SUCCESS);

    uint8_t exportedSeed[32] = {0};
    uint8_t exportedRoot[32] = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_PKEY_SLH_DSA;
    pub.key.slhDsaPub.seed = exportedSeed;
    pub.key.slhDsaPub.root = exportedRoot;
    pub.key.slhDsaPub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(imported, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(exportedSeed, pubSeed, 16), 0);
    ASSERT_EQ(memcmp(exportedRoot, pubRoot, 16), 0);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubOnly, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubOnly, &pub), CRYPT_SUCCESS);
    exportedRoot[0] ^= 0x01;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubOnly, &pub), CRYPT_SUCCESS);
    exportedRoot[0] ^= 0x01;

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(imported, &pub), CRYPT_SUCCESS);

    exportedRoot[0] ^= 0x01;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(imported, &pub), CRYPT_SLHDSA_ERR_KEY_EXISTS);
    TestErrClear();
    exportedRoot[0] ^= 0x01;
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(imported, imported), CRYPT_SUCCESS);

    pubRoot[0] ^= 0x01;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(bad, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(bad), CRYPT_SLHDSA_ERR_ROOT_MISMATCH);
    TestErrClear();
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(bad, bad), CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(source);
    CRYPT_EAL_PkeyFreeCtx(imported);
    CRYPT_EAL_PkeyFreeCtx(pubOnly);
    CRYPT_EAL_PkeyFreeCtx(bad);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_FAILURE_CLEANUP_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *failedGen = NULL;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    failedGen = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL && failedGen != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(failedGen, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint8_t msg[] = "failure cleanup";
    uint8_t shortSig[32];
    memset(shortSig, 0xa5, sizeof(shortSig));
    uint32_t shortSigLen = sizeof(shortSig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), shortSig, &shortSigLen),
        CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(shortSigLen, sizeof(shortSig));
    for (uint32_t i = 0; i < sizeof(shortSig); i++) {
        ASSERT_EQ(shortSig[i], 0xa5);
    }
    TestErrClear();

    uint8_t sig[17088];
    memset(sig, 0xa5, sizeof(sig));
    uint32_t sigLen = sizeof(sig);
    g_failRandCounter = 1;
    CRYPT_RandRegist(RandFailAfterFirst);
    CRYPT_RandRegistEx(RandFailAfterFirstEx);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(sigLen, sizeof(sig));
    for (uint32_t i = 0; i < sizeof(sig); i++) {
        ASSERT_EQ(sig[i], 0xa5);
    }
    TestErrClear();

    g_failRandCounter = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(failedGen), CRYPT_INVALID_ARG);

    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_PKEY_SLH_DSA;
    pub.key.slhDsaPub.seed = pubSeed;
    pub.key.slhDsaPub.root = pubRoot;
    pub.key.slhDsaPub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(failedGen, &pub), CRYPT_SLHDSA_ERR_NO_PUBKEY);

    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = prvSeed;
    prv.key.slhDsaPrv.prf = prvPrf;
    prv.key.slhDsaPrv.pub.seed = pubSeed;
    prv.key.slhDsaPrv.pub.root = pubRoot;
    prv.key.slhDsaPrv.pub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(failedGen, &prv), CRYPT_SLHDSA_ERR_NO_PRVKEY);

    TestRandDeInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    (void)memset(sig, 0xa5, sizeof(sig));
    sigLen = sizeof(sig);
    g_expectedCleansePtr = NULL;
    g_expectedCleanseObserved = false;
    STUB_REPLACE(SlhDsaSignInternal, SlhDsaSignInternalFail);
    STUB_REPLACE(BSL_SAL_CleanseData, ObserveSlhDsaCleanse);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_INVALID_ARG);
    STUB_RESTORE(SlhDsaSignInternal);
    STUB_RESTORE(BSL_SAL_CleanseData);
    ASSERT_EQ(sigLen, sizeof(sig));
    ASSERT_TRUE(g_expectedCleanseObserved);
    for (uint32_t i = 0; i < sizeof(sig); i++) {
        ASSERT_EQ(sig[i], 0);
    }
    TestErrClear();

EXIT:
    STUB_RESTORE(SlhDsaSignInternal);
    STUB_RESTORE(BSL_SAL_CleanseData);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(failedGen);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_KEY_IMPORT_MD_ATOMICITY_TC001(void)
{
    TestMemInit();
    CryptSlhDsaCtx *prvCtx = CRYPT_SLH_DSA_NewCtx();
    CryptSlhDsaCtx *pubCtx = CRYPT_SLH_DSA_NewCtx();
    int32_t algId = CRYPT_SLH_DSA_SHA2_128F;
    uint8_t prvSeed[16] = {1};
    uint8_t prvPrf[16] = {2};
    uint8_t pubSeed[16] = {3};
    uint8_t pubRoot[16] = {4};
    BSL_Param prvParams[5];
    BSL_Param pubParams[3];
    SlhDsaPrvKey oldPrvKey;
    uint8_t oldKeyType;
    void *oldSha256MdCtx;
    void *oldSha512MdCtx;
    int32_t ret;

    ASSERT_TRUE(prvCtx != NULL && pubCtx != NULL);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(prvCtx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(pubCtx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    InitSlhDsaPrvParams(prvParams, prvSeed, prvPrf, pubSeed, pubRoot, sizeof(prvSeed));
    InitSlhDsaPubParams(pubParams, pubSeed, pubRoot, sizeof(pubSeed));

    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(prvCtx, prvParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(prvCtx, prvParams), CRYPT_SUCCESS);
    ASSERT_TRUE(!IsSlhDsaKeyMaterialCleared(prvCtx));
    oldPrvKey = prvCtx->prvKey;
    oldKeyType = prvCtx->keyType;
    oldSha256MdCtx = prvCtx->sha256MdCtx;
    oldSha512MdCtx = prvCtx->sha512MdCtx;
    prvSeed[0] ^= 0xff;
    prvPrf[0] ^= 0xff;
    pubSeed[0] ^= 0xff;
    pubRoot[0] ^= 0xff;
    STUB_REPLACE(BSL_SAL_Calloc, SlhDsaMdCtxCallocFail);
    ret = CRYPT_SLH_DSA_SetPrvKeyEx(prvCtx, prvParams);
    STUB_RESTORE(BSL_SAL_Calloc);
    ASSERT_EQ(ret, CRYPT_MEM_ALLOC_FAIL);
    ASSERT_EQ(memcmp(&prvCtx->prvKey, &oldPrvKey, sizeof(oldPrvKey)), 0);
    ASSERT_EQ(prvCtx->keyType, oldKeyType);
    ASSERT_TRUE(prvCtx->sha256MdCtx == oldSha256MdCtx);
    ASSERT_TRUE(prvCtx->sha512MdCtx == oldSha512MdCtx);

    STUB_REPLACE(BSL_SAL_Calloc, SlhDsaMdCtxCallocFail);
    ret = CRYPT_SLH_DSA_SetPubKeyEx(pubCtx, pubParams);
    STUB_RESTORE(BSL_SAL_Calloc);
    ASSERT_EQ(ret, CRYPT_MEM_ALLOC_FAIL);
    ASSERT_TRUE(IsSlhDsaKeyMaterialCleared(pubCtx));

    g_slhDsaMdCtxCallocCount = 0;
    STUB_REPLACE(BSL_SAL_Calloc, SlhDsaSecondMdCtxCallocFail);
    ret = CRYPT_SLH_DSA_SetPubKeyEx(pubCtx, pubParams);
    STUB_RESTORE(BSL_SAL_Calloc);
    ASSERT_EQ(ret, CRYPT_MEM_ALLOC_FAIL);
    ASSERT_EQ(g_slhDsaMdCtxCallocCount, 2);
    ASSERT_TRUE(IsSlhDsaKeyMaterialCleared(pubCtx));

EXIT:
    STUB_RESTORE(BSL_SAL_Calloc);
    CRYPT_SLH_DSA_FreeCtx(prvCtx);
    CRYPT_SLH_DSA_FreeCtx(pubCtx);
    BSL_ERR_ClearError();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_MODE_CONSISTENCY_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *wrongContext = NULL;
    CRYPT_EAL_PkeyCtx *wrongMode = NULL;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    wrongContext = CRYPT_EAL_PkeyDupCtx(pkey);
    wrongMode = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(wrongContext != NULL && wrongMode != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(wrongMode, CRYPT_HASH_SLH_DSA_SHA2_128F_WITH_SHA256), CRYPT_SUCCESS);
    uint8_t prvSeed[16] = {0};
    uint8_t prvPrf[16] = {0};
    uint8_t pubSeed[16] = {0};
    uint8_t pubRoot[16] = {0};
    CRYPT_EAL_PkeyPrv prv = {
        .id = CRYPT_PKEY_SLH_DSA,
        .key.slhDsaPrv = {
            .seed = prvSeed,
            .prf = prvPrf,
            .pub = {.seed = pubSeed, .root = pubRoot, .len = sizeof(prvSeed)},
        },
    };
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(wrongMode, &prv), CRYPT_SUCCESS);

    uint8_t msg[] = "mode binding";
    uint8_t sig[50000] = {0};
    uint32_t sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);

    int32_t prehash = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash) - 1U),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash)), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA3_512, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA3_512, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHAKE128, msg, sizeof(msg), sig, sigLen) != CRYPT_SUCCESS);
    TestErrClear();
    prehash = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash)), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);

    uint8_t context = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(wrongContext, CRYPT_CTRL_SET_CTX_INFO, &context, sizeof(context)), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(wrongContext, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen) != CRYPT_SUCCESS);
    TestErrClear();

    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(wrongMode, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen) != CRYPT_SUCCESS);
    TestErrClear();

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(wrongMode, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash) - 1U),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(wrongMode, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash)),
        CRYPT_NOT_SUPPORT);

    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(wrongMode, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(wrongMode, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(wrongMode, CRYPT_MD_SHA512, msg, sizeof(msg), sig, sigLen),
        CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(wrongContext);
    CRYPT_EAL_PkeyFreeCtx(wrongMode);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_RFC9909_FIXED_PREHASH_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_HASH_SLH_DSA_SHA2_256F_WITH_SHA512), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    int32_t prehash = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash)),
        CRYPT_NOT_SUPPORT);

    uint8_t msg[] = "RFC 9909 HashSLH-DSA";
    uint8_t sig[50000] = {0};
    uint32_t sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen),
        CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */
