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
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "hbs_wots.h"
#include "test.h"
/* END_HEADER */

static int32_t MockSkDeriveFail(const void *ctx, const void *adrs, uint8_t *out)
{
    (void)ctx; (void)adrs; (void)out;
    return CRYPT_INVALID_ARG;
}

static void MockSetChainAddr(void *adrs, uint32_t val) { (void)adrs; (void)val; }
static uint32_t MockGetAdrsLen(void) { return 32; }

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

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_API_NEW_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_GENKEY_TC001(int isProvider)
{
    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
    CRYPT_EAL_PkeyCtx *pkey = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_XMSS, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else
#endif
    {
        (void)isProvider;
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    }
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID, NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_XMSS_ERR_INVALID_ALGID);
    int32_t algId = CRYPT_XMSS_SHA2_10_256;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&algId, sizeof(algId)) ==
                CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_GETSET_KEY_TC001(void)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = CRYPT_XMSS_SHA2_10_256;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pub;
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_XMSS;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_NULL_INPUT);
    pub.key.xmssPub.seed = pubSeed;
    pub.key.xmssPub.root = pubRoot;
    pub.key.xmssPub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_XMSS_LEN_NOT_ENOUGH);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_XMSS_ERR_INVALID_KEYLEN);

    CRYPT_EAL_PkeyPrv prv;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
	uint64_t index = 0;
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_XMSS;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_NULL_INPUT);
    prv.key.xmssPrv.index = index;
    prv.key.xmssPrv.seed = prvSeed;
    prv.key.xmssPrv.prf = prvPrf;
    prv.key.xmssPrv.pub.seed = pubSeed;
    prv.key.xmssPrv.pub.root = pubRoot;
    prv.key.xmssPrv.pub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_XMSS_ERR_INVALID_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_XMSS_ERR_INVALID_KEYLEN);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_GETSET_KEY_TC002(void)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = CRYPT_XMSS_SHA2_10_256;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pub;
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_XMSS;
    pub.key.xmssPub.seed = pubSeed;
    pub.key.xmssPub.root = pubRoot;
    pub.key.xmssPub.len = 32;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prv;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
	uint64_t index = 0;
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_XMSS;
    prv.key.xmssPrv.index = index;
    prv.key.xmssPrv.seed = prvSeed;
    prv.key.xmssPrv.prf = prvPrf;
    prv.key.xmssPrv.pub.seed = pubSeed;
    prv.key.xmssPrv.pub.root = pubRoot;
    prv.key.xmssPrv.pub.len = 32;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_GENKEY_KAT_TC001(int id, Hex *key, Hex *root)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_PKEY_AlgId pkeyType = (id >= CRYPT_XMSSMT_SHA2_20_2_256) ? CRYPT_PKEY_XMSSMT : CRYPT_PKEY_XMSS;
    pkey = CRYPT_EAL_PkeyNewCtx(pkeyType);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t keyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    RandInjectionInit();
    uint32_t hashLen = (keyLen - 4) / 2;
    uint8_t *stubRand[3] = {key->x, key->x + hashLen, key->x + hashLen * 2};
    uint32_t stubRandLen[3] = {hashLen, hashLen, hashLen};
    RandInjectionSet(stubRand, stubRandLen);
    CRYPT_RandRegist(RandInjection);
    CRYPT_RandRegistEx(RandInjectionEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    uint8_t pubSeed[64] = {0};
    uint8_t pubRoot[64] = {0};
    CRYPT_EAL_PkeyPub pubOut;
    memset(&pubOut, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubOut.id = pkeyType;
    pubOut.key.xmssPub.seed = pubSeed;
    pubOut.key.xmssPub.root = pubRoot;

    pubOut.key.xmssPub.len = hashLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubOut), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(pubOut.key.xmssPub.seed, root->x, hashLen), 0);
    ASSERT_EQ(memcmp(pubOut.key.xmssPub.root, root->x + hashLen, hashLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_SIGN_KAT_TC001(int id, int index, Hex *key, Hex *msg, Hex *sig, int result)
{
    (void)key;
    (void)msg;
    (void)sig;
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_PKEY_AlgId pkeyType = (id >= CRYPT_XMSSMT_SHA2_20_2_256) ? CRYPT_PKEY_XMSSMT : CRYPT_PKEY_XMSS;
    pkey = CRYPT_EAL_PkeyNewCtx(pkeyType);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t pubLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    uint32_t keyLen = (pubLen - 4) / 2;
    CRYPT_EAL_PkeyPrv prv;
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = pkeyType;
	prv.key.xmssPrv.index = index;
    prv.key.xmssPrv.seed = key->x;
    prv.key.xmssPrv.prf = key->x + keyLen;
    prv.key.xmssPrv.pub.seed = key->x + keyLen * 2;
    prv.key.xmssPrv.pub.root = key->x + keyLen * 3;
    prv.key.xmssPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);

	uint8_t sigOut[50000] = {0};
    uint32_t sigOutLen = sizeof(sigOut);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, 0, msg->x, msg->len, sigOut, &sigOutLen), result);
    if (result == CRYPT_SUCCESS) {
        ASSERT_TRUE(sigOutLen == sig->len);
        ASSERT_TRUE(memcmp(sigOut, sig->x, sigOutLen) == 0);
    }
    if (result == CRYPT_SUCCESS) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_VERIFY_KAT_TC001(int id, Hex *key, Hex *msg, Hex *sig, int result)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_PKEY_AlgId pkeyType = (id >= CRYPT_XMSSMT_SHA2_20_2_256) ? CRYPT_PKEY_XMSSMT : CRYPT_PKEY_XMSS;
    pkey = CRYPT_EAL_PkeyNewCtx(pkeyType);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t pubLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    uint32_t keyLen = (pubLen - 4) / 2;
    CRYPT_EAL_PkeyPub pub;
    memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = pkeyType;
    pub.key.xmssPub.seed = key->x;
    pub.key.xmssPub.root = key->x + keyLen;
    pub.key.xmssPub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, msg->x, msg->len, sig->x, sig->len), result);
    if (result == CRYPT_SUCCESS) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_XMSS_DUPKEY_FUNC_TC001
 * @title  XMSS EAL Duplicate Key: Test that duplicated XMSS contexts contain only public key material.
 * @precon Prepare valid XMSS private key material and message.
 * @brief
 *    1. Create an XMSS context and set private key, expected result 1
 *    2. Duplicate the XMSS context, expected result 2
 *    3. Export public key from the duplicated context and compare it with original public key, expected result 3
 *    4. Sign with the duplicated context, expected result 4
 *    5. Sign with the original private-key context, expected result 5
 *    6. Verify the signature with both original and duplicated contexts, expected result 6
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. Duplicate context is not NULL
 *    3. Public keys match
 *    4. CRYPT_NOT_SUPPORT
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_DUPKEY_FUNC_TC001(int id, int index, Hex *key, Hex *msg)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *dupPkey = NULL;
    uint8_t *sig = NULL;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);

    uint32_t pubLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    uint32_t keyLen = (pubLen - 4) / 2;
    CRYPT_EAL_PkeyPrv prv;
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_XMSS;
    prv.key.xmssPrv.index = index;
    prv.key.xmssPrv.seed = key->x;
    prv.key.xmssPrv.prf = key->x + keyLen;
    prv.key.xmssPrv.pub.seed = key->x + keyLen * 2;
    prv.key.xmssPrv.pub.root = key->x + keyLen * 3;
    prv.key.xmssPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);

    uint32_t sigLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SIGNLEN, (void *)&sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    sig = BSL_SAL_Malloc(sigLen);
    ASSERT_TRUE(sig != NULL);

    dupPkey = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(dupPkey != NULL);

    CRYPT_EAL_PkeyPub dupPub;
    uint8_t dupPubSeed[64] = {0};
    uint8_t dupPubRoot[64] = {0};
    memset(&dupPub, 0, sizeof(CRYPT_EAL_PkeyPub));
    dupPub.id = CRYPT_PKEY_XMSS;
    dupPub.key.xmssPub.seed = dupPubSeed;
    dupPub.key.xmssPub.root = dupPubRoot;
    dupPub.key.xmssPub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(dupPkey, &dupPub), CRYPT_SUCCESS);
    ASSERT_EQ(dupPub.key.xmssPub.len, keyLen);
    ASSERT_EQ(memcmp(dupPub.key.xmssPub.seed, prv.key.xmssPrv.pub.seed, keyLen), 0);
    ASSERT_EQ(memcmp(dupPub.key.xmssPub.root, prv.key.xmssPrv.pub.root, keyLen), 0);

    uint32_t outLen = sigLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupPkey, 0, msg->x, msg->len, sig, &outLen), CRYPT_NOT_SUPPORT);
    BSL_ERR_ClearError();

    outLen = sigLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, 0, msg->x, msg->len, sig, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, sigLen);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, msg->x, msg->len, sig, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(dupPkey, 0, msg->x, msg->len, sig, outLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(sig);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(dupPkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_PARAM_NULL_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *prvPkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    prvPkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(prvPkey != NULL);

    int32_t algId = CRYPT_XMSS_SHA2_10_256;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvPkey, algId), CRYPT_SUCCESS);

    // GET_PUBKEY_LEN without setting params
    uint32_t len = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&len, sizeof(len)),
              CRYPT_XMSS_KEYINFO_NOT_SET);

    // GET_SIGNLEN without setting params
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SIGNLEN, (void *)&len, sizeof(len)),
              CRYPT_XMSS_KEYINFO_NOT_SET);

    // Sign without setting params
    uint8_t data[32] = {0};
    uint8_t sign[5000] = {0};
    uint32_t signLen = sizeof(sign);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, 0, data, sizeof(data), sign, &signLen),
              CRYPT_XMSS_KEYINFO_NOT_SET);

    // Verify without setting params
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, data, sizeof(data), sign, sizeof(sign)),
              CRYPT_XMSS_KEYINFO_NOT_SET);

    // GetPrvKey without setting params
    CRYPT_EAL_PkeyPrv prv;
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_XMSS;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_XMSS_KEYINFO_NOT_SET);

    // PairCheck: pubKey without params, prvKey with params
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pkey, prvPkey), CRYPT_XMSS_KEYINFO_NOT_SET);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(prvPkey);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_WOTS_SIGN_ERR_CLEAN_TC001
* @spec  -
* @title  WOTS+ signing error path cleanses signature buffer
* @brief
* 1.Construct a mock WOTS+ context with a failing skDerive callback.
* 2.Call HbsWots_Sign, which should fail during the first private key element derivation.
* 3.Verify the return value is not CRYPT_SUCCESS.
* 4.Verify sigLen is set to 0.
* 5.Verify the sig buffer is zeroed (cleansed) after failure.
* @expect  HbsWots_Sign ret != CRYPT_SUCCESS, sigLen is 0, sig buffer is all-zero
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_WOTS_SIGN_ERR_CLEAN_TC001(void)
{
    TestMemInit();

    const XmssFamilyAdrsOps mockAdrsOps = {
        .setChainAddr = MockSetChainAddr,
        .getAdrsLen = MockGetAdrsLen,
    };
    const XmssFamilyHashFuncs mockHashFuncs = {
        .skDerive = MockSkDeriveFail,
    };
    uint8_t pubSeed[32] = {0};
    HbsWotsCtx wotsCtx = {
        .n = 32,
        .otsLen = 67,
        .hashFuncs = &mockHashFuncs,
        .adrsOps = &mockAdrsOps,
        .pubSeed = pubSeed,
        .algoType = HBS_ALGO_XMSS,
    };

    uint32_t len = wotsCtx.otsLen;
    uint32_t n = wotsCtx.n;
    uint8_t sig[3000];
    (void)memset(sig, 0xAA, sizeof(sig));
    uint32_t sigLen = sizeof(sig);
    uint8_t adrs[32] = {0};
    uint8_t msg[32] = {0};

    int32_t ret = HbsWots_Sign(sig, &sigLen, msg, n, adrs, &wotsCtx);

    ASSERT_NE(ret, CRYPT_SUCCESS);
    ASSERT_EQ(sigLen, 0);
    /* Verify sig buffer is cleansed */
    uint8_t expectZero[3000] = {0};
    ASSERT_EQ(memcmp(sig, expectZero, len * n), 0);

EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSSMT_API_NEW_TC001
* @spec  -
* @title  XMSSMT pkey type can be created and freed
* @brief
* 1.Create pkey context with CRYPT_PKEY_XMSSMT.
* 2.Verify context is not NULL.
* 3.Free context.
* @expect  pkey != NULL
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSSMT_API_NEW_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSSMT);
    ASSERT_TRUE(pkey != NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSSMT_GETID_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyGetId returns correct type for XMSS and XMSSMT
* @brief
* 1.Create XMSS pkey ctx, set param, genkey, verify GetId returns CRYPT_PKEY_XMSS.
* 2.Create XMSSMT pkey ctx, set param, genkey, verify GetId returns CRYPT_PKEY_XMSSMT.
* 3.Ensure the two IDs are different values.
* @expect  GetId matches the creation type
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSSMT_GETID_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *xmssPkey = NULL;
    CRYPT_EAL_PkeyCtx *xmssmtPkey = NULL;
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    /* XMSS key: create, gen, verify GetId */
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        xmssPkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_XMSS,
            CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
        xmssmtPkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_XMSSMT,
            CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else
#endif
    {
        (void)isProvider;
        xmssPkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
        xmssmtPkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSSMT);
    }
    ASSERT_TRUE(xmssPkey != NULL);
    ASSERT_TRUE(xmssmtPkey != NULL);

    int32_t xmssAlgId = CRYPT_XMSS_SHA2_10_256;
    int32_t xmssmtAlgId = CRYPT_XMSSMT_SHA2_20_2_256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(xmssPkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&xmssAlgId, sizeof(xmssAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(xmssmtPkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&xmssmtAlgId, sizeof(xmssmtAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(xmssPkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(xmssmtPkey), CRYPT_SUCCESS);

    /* Core assertion: GetId must return the type used at creation */
    CRYPT_PKEY_AlgId xmssId = CRYPT_EAL_PkeyGetId(xmssPkey);
    CRYPT_PKEY_AlgId xmssmtId = CRYPT_EAL_PkeyGetId(xmssmtPkey);
    ASSERT_EQ(xmssId, CRYPT_PKEY_XMSS);
    ASSERT_EQ(xmssmtId, CRYPT_PKEY_XMSSMT);
    ASSERT_TRUE(xmssId != xmssmtId);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(xmssPkey);
    CRYPT_EAL_PkeyFreeCtx(xmssmtPkey);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSSMT_GENKEY_TC001
* @spec  -
* @title  XMSSMT key generation works with CRYPT_PKEY_XMSSMT type
* @brief
* 1.Create pkey ctx with CRYPT_PKEY_XMSSMT.
* 2.Set XMSSMT parameter and generate key.
* 3.Get public key and verify it is valid (non-zero seed/root).
* @expect  genkey succeeds, pub key retrievable
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSSMT_GENKEY_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_XMSSMT,
            CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else
#endif
    {
        (void)isProvider;
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSSMT);
    }
    ASSERT_TRUE(pkey != NULL);

    int32_t algId = CRYPT_XMSSMT_SHA2_20_2_256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    /* Verify we can retrieve the public key */
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    CRYPT_EAL_PkeyPub pub;
    memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_XMSSMT;
    pub.key.xmssPub.seed = pubSeed;
    pub.key.xmssPub.root = pubRoot;
    pub.key.xmssPub.len = 32;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSSMT_SIGN_VERIFY_TC001
* @spec  -
* @title  XMSSMT sign and verify work end-to-end with CRYPT_PKEY_XMSSMT type
* @brief
* 1.Create XMSSMT pkey ctx, set param, genkey.
* 2.Sign a message.
* 3.Verify the signature with the public key.
* 4.Verify GetId returns CRYPT_PKEY_XMSSMT.
* @expect  sign and verify both succeed
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSSMT_SIGN_VERIFY_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *sig = NULL;
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_XMSSMT,
            CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else
#endif
    {
        (void)isProvider;
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSSMT);
    }
    ASSERT_TRUE(pkey != NULL);

    int32_t algId = CRYPT_XMSSMT_SHA2_20_2_256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    /* Get signature length */
    uint32_t sigLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SIGNLEN,
        (void *)&sigLen, sizeof(sigLen)), CRYPT_SUCCESS);

    /* Sign */
    uint8_t msg[32] = {0x01, 0x02, 0x03, 0x04};
    sig = (uint8_t *)BSL_SAL_Malloc(sigLen);
    ASSERT_TRUE(sig != NULL);
    uint32_t outSigLen = sigLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, 0, msg, sizeof(msg), sig, &outSigLen), CRYPT_SUCCESS);
    ASSERT_EQ(outSigLen, sigLen);

    /* Get public key for verification */
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    CRYPT_EAL_PkeyPub pub;
    memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_XMSSMT;
    pub.key.xmssPub.seed = pubSeed;
    pub.key.xmssPub.root = pubRoot;
    pub.key.xmssPub.len = 32;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);

    /* Verify GetId returns CRYPT_PKEY_XMSSMT */
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pkey), CRYPT_PKEY_XMSSMT);

    /* Verify signature */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, msg, sizeof(msg), sig, outSigLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_Free(sig);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */
