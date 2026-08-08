/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 */

/* BEGIN_HEADER */
#include <string.h>
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_slh_dsa.h"
#include "crypt_params_key.h"
#include "crypt_util_rand.h"
#include "slh_dsa_local.h"
#include "stub_utils.h"
#include "test.h"
/* END_HEADER */

STUB_DEFINE_RET2(void *, BSL_SAL_Dump, const void *, uint32_t);
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

static void *SlhDsaDumpFail(const void *src, uint32_t size)
{
    (void)src;
    (void)size;
    return NULL;
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

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t SlhDsaFailRandEx(void *libCtx, uint8_t *rand, uint32_t randLen)
{
    (void)libCtx;
    (void)rand;
    (void)randLen;
    return CRYPT_INVALID_ARG;
}
#else
static int32_t SlhDsaFailRand(uint8_t *rand, uint32_t randLen)
{
    (void)rand;
    (void)randLen;
    return CRYPT_INVALID_ARG;
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_PURE_PROFILE_TC001(int isProvider)
{
    static const int32_t profiles[] = {
        CRYPT_SLH_DSA_SHA2_128S, CRYPT_SLH_DSA_SHAKE_128S,
        CRYPT_SLH_DSA_SHA2_128F, CRYPT_SLH_DSA_SHAKE_128F,
        CRYPT_SLH_DSA_SHA2_192S, CRYPT_SLH_DSA_SHAKE_192S,
        CRYPT_SLH_DSA_SHA2_192F, CRYPT_SLH_DSA_SHAKE_192F,
        CRYPT_SLH_DSA_SHA2_256S, CRYPT_SLH_DSA_SHAKE_256S,
        CRYPT_SLH_DSA_SHA2_256F, CRYPT_SLH_DSA_SHAKE_256F
    };
    static const uint32_t keyLens[] = {16, 16, 16, 16, 24, 24, 24, 24, 32, 32, 32, 32};
    static const uint32_t signLens[] = {7856, 7856, 17088, 17088, 16224, 16224,
        35664, 35664, 29792, 29792, 49856, 49856};
    static const int32_t securityBits[] = {128, 128, 128, 128, 192, 192, 192, 192, 256, 256, 256, 256};

    TestMemInit();
    if (isProvider != 0) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
    for (uint32_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
        CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA,
            CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
        ASSERT_TRUE(pkey != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, profiles[i]), CRYPT_SUCCESS);
        int32_t paraId = CRYPT_PKEY_MAX;
        uint32_t keyLen = 0;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)), CRYPT_SUCCESS);
        ASSERT_EQ(paraId, profiles[i]);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
        ASSERT_EQ(keyLen, keyLens[i]);
        ASSERT_EQ(CRYPT_EAL_PkeyGetSignLen(pkey), signLens[i]);
        ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), securityBits[i]);
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
    TestRandDeInit();
EXIT:
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_EMPTY_MESSAGE_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint8_t sig[17088] = {0};
    uint32_t sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, NULL, 0, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, NULL, 0, sig, sigLen), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    uint8_t empty = 0;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, &empty, 0, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, &empty, 0, sig, sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, NULL, 1, sig, &sigLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, NULL, 1, sig, sigLen), CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_KEY_STATE_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *source = NULL;
    CRYPT_EAL_PkeyCtx *imported = NULL;
    CRYPT_EAL_PkeyCtx *pubOnly = NULL;
    CRYPT_EAL_PkeyCtx *bad = NULL;
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
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(imported), CRYPT_SUCCESS);

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
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(imported, &pub), CRYPT_SUCCESS);
    exportedRoot[0] ^= 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(imported, &pub), CRYPT_SLHDSA_ERR_KEY_EXISTS);
    TestErrClear();
    exportedRoot[0] ^= 1;
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(imported, imported), CRYPT_SUCCESS);

    pubRoot[0] ^= 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(bad, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(bad), CRYPT_SLHDSA_ERR_ROOT_MISMATCH);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(bad, bad), CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(source);
    CRYPT_EAL_PkeyFreeCtx(imported);
    CRYPT_EAL_PkeyFreeCtx(pubOnly);
    CRYPT_EAL_PkeyFreeCtx(bad);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CLEAN_PUB_KEY_TC001(void)
{
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    ASSERT_TRUE(ctx != NULL);
    int32_t algId = CRYPT_SLH_DSA_SHA2_128F;
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);

    uint8_t prvSeed[16] = {1};
    uint8_t prvPrf[16] = {2};
    uint8_t pubSeed[16] = {3};
    uint8_t pubRoot[16] = {4};
    CRYPT_SlhDsaPrv prv = {
        .seed = prvSeed,
        .prf = prvPrf,
        .pub = {.seed = pubSeed, .root = pubRoot, .len = sizeof(pubSeed)},
    };
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKey(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_CLEAN_PUB_KEY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(ctx->keyType, SLH_DSA_PRVKEY | SLH_DSA_PUBKEY);
    ASSERT_COMPARE("seed", ctx->prvKey.seed, sizeof(prvSeed), prvSeed, sizeof(prvSeed));
    ASSERT_COMPARE("prf", ctx->prvKey.prf, sizeof(prvPrf), prvPrf, sizeof(prvPrf));
    for (uint32_t i = 0; i < sizeof(ctx->prvKey.pub); i++) {
        ASSERT_EQ(((uint8_t *)&ctx->prvKey.pub)[i], 0);
    }

EXIT:
    CRYPT_SLH_DSA_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_KEY_IMPORT_ATOMICITY_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    CRYPT_EAL_PkeyCtx *pubOnly = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL && pubOnly != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubOnly, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);

    uint8_t prvSeed[32] = {1};
    uint8_t prvPrf[32] = {2};
    uint8_t pubSeed[32] = {3};
    uint8_t pubRoot[32] = {4};
    uint8_t expectedPrvSeed[32] = {0};
    uint8_t expectedPrvPrf[32] = {0};
    uint8_t expectedPubSeed[32] = {0};
    uint8_t expectedPubRoot[32] = {0};
    BSL_Param prvParams[5];
    InitSlhDsaPrvParams(prvParams, prvSeed, prvPrf, pubSeed, pubRoot, 16);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, prvParams), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv expected = {0};
    expected.id = CRYPT_PKEY_SLH_DSA;
    expected.key.slhDsaPrv.seed = expectedPrvSeed;
    expected.key.slhDsaPrv.prf = expectedPrvPrf;
    expected.key.slhDsaPrv.pub.seed = expectedPubSeed;
    expected.key.slhDsaPrv.pub.root = expectedPubRoot;
    expected.key.slhDsaPrv.pub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &expected), CRYPT_SUCCESS);

    /* A valid second import keeps the classic overwrite behavior. */
    prvSeed[0] ^= 0xff;
    prvPrf[0] ^= 0xff;
    pubSeed[0] ^= 0xff;
    pubRoot[0] ^= 0xff;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, prvParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &expected), CRYPT_SUCCESS);

    /* Validation must complete before any key material is changed. */
    prvParams[3].valueLen = 15;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, prvParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    prvParams[3].valueLen = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &expected), CRYPT_SUCCESS);
    ASSERT_EQ(expectedPrvSeed[0], prvSeed[0]);
    ASSERT_EQ(expectedPrvPrf[0], prvPrf[0]);
    ASSERT_EQ(expectedPubSeed[0], pubSeed[0]);
    ASSERT_EQ(expectedPubRoot[0], pubRoot[0]);
    TestErrClear();

    BSL_Param pubParams[3];
    BSL_PARAM_InitValue(&pubParams[0], CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pubSeed, 16);
    BSL_PARAM_InitValue(&pubParams[1], CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pubRoot, 15);
    pubParams[2] = (BSL_Param)BSL_PARAM_END;
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(pubOnly, pubParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_PKEY_SLH_DSA;
    pub.key.slhDsaPub.seed = expectedPubSeed;
    pub.key.slhDsaPub.root = expectedPubRoot;
    pub.key.slhDsaPub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pubOnly, &pub), CRYPT_SLHDSA_ERR_NO_PUBKEY);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pubOnly);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_FAILURE_CLEANUP_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    CRYPT_EAL_PkeyCtx *failedGen = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL && failedGen != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(failedGen, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(failedGen), CRYPT_SUCCESS);

    uint8_t msg[] = "failure cleanup";
    uint8_t shortSig[32];
    (void)memset(shortSig, 0xa5, sizeof(shortSig));
    uint32_t shortSigLen = sizeof(shortSig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), shortSig, &shortSigLen),
        CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(shortSigLen, sizeof(shortSig));
    for (uint32_t i = 0; i < sizeof(shortSig); i++) {
        ASSERT_EQ(shortSig[i], 0xa5);
    }
    TestErrClear();

    uint8_t sig[17088];
    (void)memset(sig, 0xa5, sizeof(sig));
    uint32_t sigLen = sizeof(sig);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(SlhDsaFailRandEx);
#else
    CRYPT_RandRegist(SlhDsaFailRand);
#endif
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(sigLen, sizeof(sig));
    for (uint32_t i = 0; i < sizeof(sig); i++) {
        ASSERT_EQ(sig[i], 0xa5);
    }
    TestErrClear();

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
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(NULL);
#else
    CRYPT_RandRegist(NULL);
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(failedGen);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CHECK_PRVKEY_TC002(void)
{
#if !defined(HITLS_CRYPTO_SLH_DSA_CHECK)
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *valid = NULL;
    CRYPT_EAL_PkeyCtx *invalid = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    valid = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    invalid = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(valid != NULL && invalid != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(valid, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(invalid, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(valid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(valid), CRYPT_SUCCESS);

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
    pubRoot[0] ^= 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(invalid, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(invalid), CRYPT_SLHDSA_ERR_ROOT_MISMATCH);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(valid);
    CRYPT_EAL_PkeyFreeCtx(invalid);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CONTEXT_ATOMICITY_TC001(void)
{
    TestMemInit();
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    ASSERT_TRUE(ctx != NULL);
    int32_t algId = CRYPT_SLH_DSA_SHA2_128F;
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    uint8_t original[] = {1, 2, 3};
    uint8_t replacement[] = {4, 5, 6, 7};
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_CTX_INFO, original, sizeof(original)), CRYPT_SUCCESS);
    uint8_t *oldContext = ctx->context;

    STUB_REPLACE(BSL_SAL_Dump, SlhDsaDumpFail);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_CTX_INFO, replacement, sizeof(replacement)),
        CRYPT_MEM_ALLOC_FAIL);
    STUB_RESTORE(BSL_SAL_Dump);
    ASSERT_TRUE(ctx->context == oldContext);
    ASSERT_EQ(ctx->contextLen, sizeof(original));
    ASSERT_EQ(memcmp(ctx->context, original, sizeof(original)), 0);

EXIT:
    STUB_RESTORE(BSL_SAL_Dump);
    CRYPT_SLH_DSA_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_MODE_CONSISTENCY_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_SLH_DSA_SHA2_128F), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint8_t msg[] = "mode binding";
    uint8_t sig[17088] = {0};
    uint32_t sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);

    int32_t prehash = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash) - 1U),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash)), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, msg, sizeof(msg), sig, sigLen) != CRYPT_SUCCESS);
    TestErrClear();

    prehash = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash)), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */
