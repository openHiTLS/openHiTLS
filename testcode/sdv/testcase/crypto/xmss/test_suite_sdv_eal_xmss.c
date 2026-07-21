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
#include "crypt_utils.h"
#include "crypt_eal_pkey.h"
#include "crypt_xmss.h"
#include "crypt_xmssmt.h"
#include "crypt_util_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "hbs_wots.h"
#include "stub_utils.h"
#include "test.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

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


/* @
* @test  SDV_CRYPTO_XMSS_SET_PARA_ID_REPEATED_TC001
* @spec  -
* @title  CRYPT_CTRL_SET_PARA_BY_ID cannot be called twice on the same context
* @brief
* 1.Create an XMSS pkey context.
* 2.Set para by id with CRYPT_XMSS_SHA2_10_256, expected CRYPT_SUCCESS.
* 3.Set para by id again with the same or different algId, expected CRYPT_XMSS_CTRL_INIT_REPEATED.
* @expect  second set returns CRYPT_XMSS_CTRL_INIT_REPEATED
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_SET_PARA_ID_REPEATED_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);

    int32_t algId = CRYPT_XMSS_SHA2_10_256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_SUCCESS);

    /* Set the same algId again — must be rejected */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_XMSS_CTRL_INIT_REPEATED);

    /* Set a different algId — also must be rejected */
    int32_t otherAlgId = CRYPT_XMSS_SHA2_16_256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&otherAlgId, sizeof(otherAlgId)), CRYPT_XMSS_CTRL_INIT_REPEATED);

    BSL_ERR_ClearError();
    ASSERT_TRUE(TestIsErrStackEmpty());

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

/**
 * @brief Verify that BDS acceleration does not change XMSS/XMSSMT signature output.
 *
 * Test procedure:
 * 1. Generate a BDS-enabled key from deterministic seed, PRF and public-seed input.
 * 2. Sign and verify a sequence of distinct messages with the BDS-enabled key.
 * 3. At selected indexes, import the same private fields without BDS state into a new context.
 * 4. Sign the same message through the original full-tree path and compare both signatures byte for byte.
 *
 * Expected result:
 * 1. Every BDS signature and full-tree signature verifies successfully.
 * 2. Both signing paths produce identical signatures at every compared index.
 * 3. XMSSMT cases cross bottom-tree and higher-layer boundaries to exercise BDS state switching.
 * 4. The signatures immediately before and after each final tested boundary use the same result on both paths.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_BDS_SIGN_COMPARE_TC001(int id, int rounds, int compareHead, Hex *key, Hex *msg)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *bdsPkey = NULL;
    CRYPT_EAL_PkeyCtx *naivePkey = NULL;
    CRYPT_PKEY_AlgId pkeyType = (id >= CRYPT_XMSSMT_SHA2_20_2_256) ? CRYPT_PKEY_XMSSMT : CRYPT_PKEY_XMSS;
    bdsPkey = CRYPT_EAL_PkeyNewCtx(pkeyType);
    ASSERT_TRUE(bdsPkey != NULL);

    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(bdsPkey, algId), CRYPT_SUCCESS);

    uint32_t pubLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(bdsPkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    uint32_t keyLen = (pubLen - 4) / 2;
    ASSERT_TRUE(key->len >= 3U * keyLen);

    RandInjectionInit();
    uint8_t *stubRand[3] = {key->x, key->x + keyLen, key->x + keyLen * 2};
    uint32_t stubRandLen[3] = {keyLen, keyLen, keyLen};
    RandInjectionSet(stubRand, stubRandLen);
    CRYPT_RandRegist(RandInjection);
    CRYPT_RandRegistEx(RandInjectionEx);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(bdsPkey), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prv;
    uint8_t prvSeed[64] = {0};
    uint8_t prvPrf[64] = {0};
    uint8_t pubSeed[64] = {0};
    uint8_t pubRoot[64] = {0};
    memset(&prv, 0, sizeof(prv));
    prv.id = pkeyType;
    prv.key.xmssPrv.seed = prvSeed;
    prv.key.xmssPrv.prf = prvPrf;
    prv.key.xmssPrv.pub.seed = pubSeed;
    prv.key.xmssPrv.pub.root = pubRoot;
    prv.key.xmssPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(bdsPkey, &prv), CRYPT_SUCCESS);

    uint8_t bdsSig[50000] = {0};
    uint8_t naiveSig[50000] = {0};
    uint8_t msgBuf[256] = {0};
    ASSERT_TRUE(msg->len >= sizeof(uint32_t) && msg->len <= sizeof(msgBuf));
    for (int i = 0; i < rounds; i++) {
        memcpy(msgBuf, msg->x, msg->len);
        PUT_UINT32_BE((uint32_t)i, msgBuf, 0);
        uint32_t bdsSigLen = sizeof(bdsSig);
        ASSERT_EQ(CRYPT_EAL_PkeySign(bdsPkey, 0, msgBuf, msg->len, bdsSig, &bdsSigLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(bdsPkey, 0, msgBuf, msg->len, bdsSig, bdsSigLen), CRYPT_SUCCESS);

        if (i >= compareHead && i + 2 < rounds) {
            continue;
        }
        naivePkey = CRYPT_EAL_PkeyNewCtx(pkeyType);
        ASSERT_TRUE(naivePkey != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(naivePkey, algId), CRYPT_SUCCESS);
        prv.key.xmssPrv.index = (uint64_t)i;
        ASSERT_EQ(CRYPT_EAL_PkeySetPrv(naivePkey, &prv), CRYPT_SUCCESS);

        uint32_t naiveSigLen = sizeof(naiveSig);
        ASSERT_EQ(CRYPT_EAL_PkeySign(naivePkey, 0, msgBuf, msg->len, naiveSig, &naiveSigLen), CRYPT_SUCCESS);
        ASSERT_TRUE(bdsSigLen == naiveSigLen);
        ASSERT_TRUE(memcmp(bdsSig, naiveSig, bdsSigLen) == 0);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(naivePkey, 0, msgBuf, msg->len, naiveSig, naiveSigLen), CRYPT_SUCCESS);
        CRYPT_EAL_PkeyFreeCtx(naivePkey);
        naivePkey = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(naivePkey);
    CRYPT_EAL_PkeyFreeCtx(bdsPkey);
    return;
}
/* END_CASE */

static void InitXmssPrvParams(BSL_Param *params, uint64_t *index, uint8_t *prvSeed, uint8_t *prvPrf,
    uint8_t *pubSeed, uint8_t *pubRoot, uint32_t keyLen, uint8_t *bdsState, uint32_t bdsStateLen)
{
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_XMSS_PRV_SEED, BSL_PARAM_TYPE_OCTETS, prvSeed, keyLen);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_XMSS_PRV_PRF, BSL_PARAM_TYPE_OCTETS, prvPrf, keyLen);
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, index, sizeof(*index));
    BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pubSeed, keyLen);
    BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pubRoot, keyLen);
    BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_XMSS_BDS_STATE, BSL_PARAM_TYPE_OCTETS, bdsState, bdsStateLen);
    params[6] = (BSL_Param)BSL_PARAM_END;
}

/**
 * @brief Verify fixed-field BDS persistence for XMSS and XMSSMT.
 *
 * Test procedure:
 * 1. Generate a source key and sign several messages to advance its BDS state.
 * 2. Export the private fields and BDS blob, including a partially built XMSSMT next tree.
 * 3. Check that the blob starts with the algorithm identifier rather than an in-memory structure marker.
 * 4. Import all private fields into a fresh destination context.
 * 5. Sign the next message with both contexts and compare the signatures byte for byte.
 *
 * Expected result:
 * 1. The destination resumes at exactly the same BDS state and private-key index.
 * 2. The first post-import signature is identical to the source signature.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_BDS_PERSIST_TC001(int id, int rounds)
{
    TestMemInit();
    TestRandInit();
    CRYPT_PKEY_AlgId pkeyType = (id >= CRYPT_XMSSMT_SHA2_20_2_256) ? CRYPT_PKEY_XMSSMT : CRYPT_PKEY_XMSS;
    CRYPT_EAL_PkeyCtx *src = CRYPT_EAL_PkeyNewCtx(pkeyType);
    CRYPT_EAL_PkeyCtx *dst = CRYPT_EAL_PkeyNewCtx(pkeyType);
    ASSERT_TRUE(src != NULL);
    ASSERT_TRUE(dst != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(src, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(dst, id), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), CRYPT_SUCCESS);

    uint8_t msg[32] = {0};
    uint8_t warmupSig[50000] = {0};
    for (int i = 0; i < rounds; i++) {
        uint32_t warmupSigLen = sizeof(warmupSig);
        msg[0] = (uint8_t)i;
        ASSERT_EQ(CRYPT_EAL_PkeySign(src, 0, msg, sizeof(msg), warmupSig, &warmupSigLen), CRYPT_SUCCESS);
    }

    uint64_t index = 0;
    uint8_t prvSeed[64] = {0};
    uint8_t prvPrf[64] = {0};
    uint8_t pubSeed[64] = {0};
    uint8_t pubRoot[64] = {0};
    uint8_t bdsState[50000] = {0};
    BSL_Param params[7];
    uint32_t pubLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    uint32_t keyLen = (pubLen - 4U) / 2U;
    InitXmssPrvParams(params, &index, prvSeed, prvPrf, pubSeed, pubRoot, keyLen, bdsState, sizeof(bdsState));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(src, params), CRYPT_SUCCESS);
    ASSERT_TRUE(params[5].useLen > 4U);
    ASSERT_TRUE(GET_UINT32_BE(bdsState, 0) == (uint32_t)id);

    params[5].valueLen = params[5].useLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(dst, params), CRYPT_SUCCESS);

    uint8_t srcSig[50000] = {0};
    uint8_t dstSig[50000] = {0};
    uint32_t srcSigLen = sizeof(srcSig);
    uint32_t dstSigLen = sizeof(dstSig);
    msg[0] = (uint8_t)rounds;
    ASSERT_EQ(CRYPT_EAL_PkeySign(src, 0, msg, sizeof(msg), srcSig, &srcSigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(dst, 0, msg, sizeof(msg), dstSig, &dstSigLen), CRYPT_SUCCESS);
    ASSERT_TRUE(srcSigLen == dstSigLen);
    ASSERT_EQ(memcmp(srcSig, dstSig, srcSigLen), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(dst);
    CRYPT_EAL_PkeyFreeCtx(src);
    return;
}
/* END_CASE */

/**
 * @brief Verify BDS structural validation and atomic private-key import.
 *
 * Test procedure:
 * 1. Generate an XMSS key and export its private fields and valid BDS blob.
 * 2. Corrupt stack offset, treehash height/index/stack usage, next leaf, booleans and stack level.
 * 3. Attempt to import every malformed blob into the context that already owns the valid key.
 * 4. Export the context again after all rejected imports.
 *
 * Expected result:
 * 1. Every malformed BDS blob is rejected with CRYPT_INVALID_ARG.
 * 2. The original index, seed, PRF, public seed, root and BDS blob remain unchanged.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_BDS_IMPORT_INVALID_TC001(void)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_XMSS_SHA2_10_256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint64_t index = 0;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    uint8_t bdsState[20000] = {0};
    BSL_Param params[7];
    InitXmssPrvParams(params, &index, prvSeed, prvPrf, pubSeed, pubRoot, sizeof(prvSeed), bdsState, sizeof(bdsState));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(pkey, params), CRYPT_SUCCESS);
    uint32_t bdsStateLen = params[5].useLen;

    uint8_t invalidBdsState[20000] = {0};
    uint32_t headerLen = 7U * (uint32_t)sizeof(uint32_t) + (uint32_t)sizeof(uint64_t);
    uint32_t stackLevelsPos = headerLen + 10U * 32U + 5U * 32U + 11U * 32U;
    uint32_t stackOffsetPos = stackLevelsPos + 11U;
    uint32_t treehashPos = stackOffsetPos + (uint32_t)sizeof(uint32_t);
    uint32_t nextLeafPos = treehashPos + 10U * (3U * (uint32_t)sizeof(uint32_t) + 1U + 32U) + 32U;
    uint32_t initializedPos = nextLeafPos + (uint32_t)sizeof(uint32_t) + 32U;
    uint32_t invalidU32Pos[] = {
        stackOffsetPos,
        treehashPos,
        treehashPos + sizeof(uint32_t),
        treehashPos + 2U * (uint32_t)sizeof(uint32_t),
        nextLeafPos,
    };
    ASSERT_TRUE(initializedPos < bdsStateLen);
    for (uint32_t i = 0; i < sizeof(invalidU32Pos) / sizeof(invalidU32Pos[0]); i++) {
        memcpy(invalidBdsState, bdsState, bdsStateLen);
        memset(invalidBdsState + invalidU32Pos[i], 0xFF, sizeof(uint32_t));
        params[5].value = invalidBdsState;
        params[5].valueLen = bdsStateLen;
        ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, params), CRYPT_INVALID_ARG);
    }

    memcpy(invalidBdsState, bdsState, bdsStateLen);
    memset(invalidBdsState + treehashPos, 0, sizeof(uint32_t));
    invalidBdsState[treehashPos + sizeof(uint32_t) - 1U] = 1U;
    params[5].value = invalidBdsState;
    params[5].valueLen = bdsStateLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, params), CRYPT_INVALID_ARG);

    uint32_t invalidBoolPos[] = {treehashPos + 3U * (uint32_t)sizeof(uint32_t), initializedPos};
    for (uint32_t i = 0; i < sizeof(invalidBoolPos) / sizeof(invalidBoolPos[0]); i++) {
        memcpy(invalidBdsState, bdsState, bdsStateLen);
        invalidBdsState[invalidBoolPos[i]] = 2U;
        params[5].value = invalidBdsState;
        params[5].valueLen = bdsStateLen;
        ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, params), CRYPT_INVALID_ARG);
    }

    memcpy(invalidBdsState, bdsState, bdsStateLen);
    invalidBdsState[stackLevelsPos] = 0xFFU;
    memset(invalidBdsState + stackOffsetPos, 0, sizeof(uint32_t));
    invalidBdsState[stackOffsetPos + sizeof(uint32_t) - 1U] = 1U;
    params[5].value = invalidBdsState;
    params[5].valueLen = bdsStateLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, params), CRYPT_INVALID_ARG);

    uint64_t afterIndex = 0;
    uint8_t afterPrvSeed[32] = {0};
    uint8_t afterPrvPrf[32] = {0};
    uint8_t afterPubSeed[32] = {0};
    uint8_t afterPubRoot[32] = {0};
    uint8_t afterBdsState[20000] = {0};
    InitXmssPrvParams(params, &afterIndex, afterPrvSeed, afterPrvPrf, afterPubSeed, afterPubRoot, sizeof(afterPrvSeed),
        afterBdsState, sizeof(afterBdsState));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(pkey, params), CRYPT_SUCCESS);
    ASSERT_TRUE(afterIndex == index);
    ASSERT_TRUE(params[5].useLen == bdsStateLen);
    ASSERT_EQ(memcmp(afterPrvSeed, prvSeed, sizeof(prvSeed)), 0);
    ASSERT_EQ(memcmp(afterPrvPrf, prvPrf, sizeof(prvPrf)), 0);
    ASSERT_EQ(memcmp(afterPubSeed, pubSeed, sizeof(pubSeed)), 0);
    ASSERT_EQ(memcmp(afterPubRoot, pubRoot, sizeof(pubRoot)), 0);
    ASSERT_EQ(memcmp(afterBdsState, bdsState, bdsStateLen), 0);

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

/* @
* @test  SDV_CRYPTO_XMSS_SET_XDR_ALG_REPEATED_TC001
* @spec  -
* @title  CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE cannot be called twice on the same context
* @brief
* 1.Create an XMSS pkey context.
* 2.Set XDR alg type with XMSS_SHA2_10_256 OID (0x00000001), expected CRYPT_SUCCESS.
* 3.Set XDR alg type again, expected CRYPT_XMSS_CTRL_INIT_REPEATED.
* 4.Also verify cross-path: SET_PARA_BY_ID after SET_XDR returns CRYPT_XMSS_CTRL_INIT_REPEATED.
* @expect  repeated set returns CRYPT_XMSS_CTRL_INIT_REPEATED
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_SET_XDR_ALG_REPEATED_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);

    /* XMSS_SHA2_10_256 XDR OID = 0x00000001 (big-endian) */
    uint8_t xdrOid[4] = {0x00, 0x00, 0x00, 0x01};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE,
        xdrOid, sizeof(xdrOid)), CRYPT_SUCCESS);

    /* Set XDR again — must be rejected */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE,
        xdrOid, sizeof(xdrOid)), CRYPT_XMSS_CTRL_INIT_REPEATED);

    /* Cross-path: SET_PARA_BY_ID after XDR init — also must be rejected */
    int32_t algId = CRYPT_XMSS_SHA2_10_256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_XMSS_CTRL_INIT_REPEATED);

    BSL_ERR_ClearError();
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_CTRL_MATRIX_TC001
* @title Cover XMSS/XMSSMT control options before and after parameter initialization
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_CTRL_MATRIX_TC001(int pkeyType, int algId)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    int32_t paraId = 0;
    int32_t invalidId = 0;
    uint32_t value = 0;
    uint8_t xdrId[4] = {0};
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)),
        CRYPT_XMSS_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE, xdrId, sizeof(xdrId)),
        CRYPT_XMSS_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &value, sizeof(value)),
        CRYPT_XMSS_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &value, sizeof(value)),
        CRYPT_XMSS_KEYINFO_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId) - 1U), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE, xdrId, sizeof(xdrId) - 1U),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &value, sizeof(value) - 1U), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &value, sizeof(value) - 1U), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId) - 1U), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &invalidId, sizeof(invalidId)),
        CRYPT_XMSS_ERR_INVALID_ALGID);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)), CRYPT_SUCCESS);
    ASSERT_EQ(paraId, algId);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE, xdrId, sizeof(xdrId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &value, sizeof(value)), CRYPT_SUCCESS);
    ASSERT_TRUE(value > 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &value, sizeof(value)), CRYPT_SUCCESS);
    ASSERT_TRUE(value > sizeof(xdrId));
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, xdrId, sizeof(xdrId)),
        CRYPT_XMSS_CTRL_INIT_REPEATED);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, -1, &value, sizeof(value)), CRYPT_NOT_SUPPORT);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_CHECK_MATRIX_TC001
* @title Cover XMSS/XMSSMT private-key and key-pair check combinations
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_CHECK_MATRIX_TC001(int pkeyType, int algId, int otherAlgId)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *empty = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    CRYPT_EAL_PkeyCtx *prv = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    CRYPT_EAL_PkeyCtx *other = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    CRYPT_EAL_PkeyCtx *badPub = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    ASSERT_TRUE(empty != NULL);
    ASSERT_TRUE(prv != NULL);
    ASSERT_TRUE(other != NULL);
    ASSERT_TRUE(badPub != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(empty), CRYPT_XMSS_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(empty, prv), CRYPT_XMSS_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prv, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(other, otherAlgId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(badPub, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(prv, other), CRYPT_XMSS_PAIRWISE_CHECK_FAIL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(prv, prv), CRYPT_SUCCESS);
    pub.id = (CRYPT_PKEY_AlgId)pkeyType;
    pub.key.xmssPub.seed = pubSeed;
    pub.key.xmssPub.root = pubRoot;
    pub.key.xmssPub.len = sizeof(pubSeed);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(prv, &pub), CRYPT_SUCCESS);
    pubRoot[0] ^= 1U;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(badPub, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(badPub, prv), CRYPT_XMSS_PAIRWISE_CHECK_FAIL);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_EAL_PkeyFreeCtx(badPub);
    CRYPT_EAL_PkeyFreeCtx(other);
    CRYPT_EAL_PkeyFreeCtx(prv);
    CRYPT_EAL_PkeyFreeCtx(empty);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_KEY_PARAM_MATRIX_TC001
* @title Cover structured XMSS/XMSSMT public-key parameter validation
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_KEY_PARAM_MATRIX_TC001(int pkeyType, int algId)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    uint8_t xdrId[4] = {0};
    uint8_t wrongXdrId[4] = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    BSL_Param params[4];
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE, xdrId, sizeof(xdrId)), CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_XMSS_XDR_TYPE, BSL_PARAM_TYPE_OCTETS, xdrId, sizeof(xdrId));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pubSeed, sizeof(pubSeed));
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pubRoot, sizeof(pubRoot));
    params[3] = (BSL_Param)BSL_PARAM_END;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(params[0].useLen, sizeof(xdrId));
    ASSERT_EQ(params[1].useLen, sizeof(pubSeed));
    ASSERT_EQ(params[2].useLen, sizeof(pubRoot));

    params[0].value = wrongXdrId;
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, params), CRYPT_XMSS_ERR_XDR_ID_UNMATCH);
    params[0].value = xdrId;
    params[2].valueLen = sizeof(pubRoot) - 1U;
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, params), CRYPT_XMSS_ERR_INVALID_KEYLEN);
    params[2].valueLen = sizeof(pubRoot);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, params), CRYPT_SUCCESS);

    params[0].valueLen = sizeof(xdrId) - 1U;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, params), CRYPT_INVALID_KEY);
    params[0].valueLen = sizeof(xdrId);
    params[1].valueLen = sizeof(pubSeed) - 1U;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, params), CRYPT_XMSS_LEN_NOT_ENOUGH);
    params[1].valueLen = sizeof(pubSeed);
    params[2].value = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, params), CRYPT_NULL_INPUT);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_DIRECT_ERROR_MATRIX_TC001
* @title Cover direct XMSS/XMSSMT null-input and invalid-XDR paths
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_DIRECT_ERROR_MATRIX_TC001(void)
{
    TestMemInit();
    CryptXmssCtx *xmss = CRYPT_XMSS_NewCtx();
    CryptXmssmtCtx *xmssmt = CRYPT_XMSSMT_NewCtx();
    uint8_t msg[1] = {0};
    uint8_t sig[1] = {0};
    uint8_t invalidXdr[4] = {0xff, 0xff, 0xff, 0xff};
    uint32_t sigLen = sizeof(sig);
    ASSERT_TRUE(xmss != NULL);
    ASSERT_TRUE(xmssmt != NULL);

    ASSERT_TRUE(CRYPT_XMSS_DupCtx(NULL) == NULL);
    ASSERT_EQ(CRYPT_XMSS_Check(UINT32_MAX, xmss, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_XMSS_Sign(NULL, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_XMSS_Ctrl(xmss, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, invalidXdr, sizeof(invalidXdr) - 1U),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_XMSS_Ctrl(xmss, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, invalidXdr, sizeof(invalidXdr)),
        CRYPT_XMSS_ERR_INVALID_XDR_ID);

    ASSERT_TRUE(CRYPT_XMSSMT_DupCtx(NULL) == NULL);
    ASSERT_EQ(CRYPT_XMSSMT_Check(UINT32_MAX, xmssmt, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_XMSSMT_Sign(NULL, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_XMSSMT_Ctrl(xmssmt, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, invalidXdr,
        sizeof(invalidXdr) - 1U), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_XMSSMT_Ctrl(xmssmt, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, invalidXdr, sizeof(invalidXdr)),
        CRYPT_XMSS_ERR_INVALID_XDR_ID);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_XMSSMT_FreeCtx(xmssmt);
    CRYPT_XMSS_FreeCtx(xmss);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_ALL_SPEC_BOUNDARY_TC001
* @title Validate public-key and signature length boundaries for every XMSS/XMSSMT parameter set
* @brief
* 1.Compare Ctrl results with the static expected public-key and signature lengths.
* 2.Check public-key input lengths n-1, n and n+1 and output capacities n-1, n and n+1.
* 3.Check signature output L-1 and verify input L-1/L+1 without executing an expensive tree traversal.
* 4.Verify failed short-buffer signing does not consume the stateful XMSS index or overwrite canaries.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_ALL_SPEC_BOUNDARY_TC001(int pkeyType, int algId, int keyLen,
    int expectedPubLen, int expectedSigLen)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    uint8_t pubSeed[66];
    uint8_t pubRoot[66];
    uint8_t prvSeed[64] = {0};
    uint8_t prvPrf[64] = {0};
    uint8_t msg[1] = {0x5a};
    uint8_t sigGuard[3] = {0xa5, 0xa5, 0xa5};
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPrv outPrv = {0};
    uint32_t actualPubLen = 0;
    uint32_t actualSigLen = 0;
    uint32_t shortSigLen = (uint32_t)expectedSigLen - 1U;
    uint64_t initialIndex = 7;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(keyLen > 0 && keyLen <= (int)sizeof(prvSeed));
    ASSERT_TRUE(expectedSigLen > 1);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &actualPubLen, sizeof(actualPubLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(actualPubLen, expectedPubLen);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &actualSigLen, sizeof(actualSigLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(actualSigLen, expectedSigLen);

    memset(pubSeed, 0x11, sizeof(pubSeed));
    memset(pubRoot, 0x22, sizeof(pubRoot));
    pub.id = (CRYPT_PKEY_AlgId)pkeyType;
    pub.key.xmssPub.seed = pubSeed + 1;
    pub.key.xmssPub.root = pubRoot + 1;
    pub.key.xmssPub.len = (uint32_t)keyLen - 1U;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_XMSS_ERR_INVALID_KEYLEN);
    pub.key.xmssPub.len = (uint32_t)keyLen + 1U;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_XMSS_ERR_INVALID_KEYLEN);
    pub.key.xmssPub.len = (uint32_t)keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_SUCCESS);

    pub.key.xmssPub.len = (uint32_t)keyLen - 1U;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_XMSS_LEN_NOT_ENOUGH);
    pub.key.xmssPub.len = (uint32_t)keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_SUCCESS);
    pub.key.xmssPub.len = (uint32_t)keyLen + 1U;
    pubSeed[keyLen + 1] = 0xa5;
    pubRoot[keyLen + 1] = 0xa5;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(pubSeed[0], 0x11);
    ASSERT_EQ(pubRoot[0], 0x22);
    ASSERT_EQ(pubSeed[keyLen + 1], 0xa5);
    ASSERT_EQ(pubRoot[keyLen + 1], 0xa5);

    prv.id = (CRYPT_PKEY_AlgId)pkeyType;
    prv.key.xmssPrv.index = initialIndex;
    prv.key.xmssPrv.seed = prvSeed;
    prv.key.xmssPrv.prf = prvPrf;
    prv.key.xmssPrv.pub.seed = pubSeed + 1;
    prv.key.xmssPrv.pub.root = pubRoot + 1;
    prv.key.xmssPrv.pub.len = (uint32_t)keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, 0, msg, sizeof(msg), sigGuard + 1, &shortSigLen),
        CRYPT_XMSS_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(shortSigLen, (uint32_t)expectedSigLen - 1U);
    ASSERT_EQ(sigGuard[0], 0xa5);
    ASSERT_EQ(sigGuard[1], 0xa5);
    ASSERT_EQ(sigGuard[2], 0xa5);

    outPrv.id = (CRYPT_PKEY_AlgId)pkeyType;
    outPrv.key.xmssPrv.seed = prvSeed;
    outPrv.key.xmssPrv.prf = prvPrf;
    outPrv.key.xmssPrv.pub.seed = pubSeed + 1;
    outPrv.key.xmssPrv.pub.root = pubRoot + 1;
    outPrv.key.xmssPrv.pub.len = (uint32_t)keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &outPrv), CRYPT_SUCCESS);
    ASSERT_TRUE(outPrv.key.xmssPrv.index == initialIndex);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, 0, msg, sizeof(msg), sigGuard + 1,
        (uint32_t)expectedSigLen - 1U), CRYPT_XMSS_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, 0, msg, sizeof(msg), sigGuard + 1,
        (uint32_t)expectedSigLen + 1U), CRYPT_XMSS_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(sigGuard[0], 0xa5);
    ASSERT_EQ(sigGuard[1], 0xa5);
    ASSERT_EQ(sigGuard[2], 0xa5);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_SIGN_MALLOC_STUB_TC001
* @title Sweep every malloc failure point through the XMSS/XMSSMT Sign API
* @brief
* 1.Generate a private key and sign successfully to count malloc calls.
* 2.Fail each malloc once while signing with the same context.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_SIGN_MALLOC_STUB_TC001(int pkeyType, int algId)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    uint8_t msg[1] = {0x5a};
    uint8_t *sig = NULL;
    uint32_t sigLen = 0;
    uint32_t totalMallocCount = 0;
    uint32_t outLen = 0;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    sig = (uint8_t *)malloc(sigLen);
    ASSERT_TRUE(sig != NULL);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    outLen = sigLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, 0, msg, sizeof(msg), sig, &outLen), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        outLen = sigLen;
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)CRYPT_EAL_PkeySign(ctx, 0, msg, sizeof(msg), sig, &outLen);
    }

EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    free(sig);
    TestRandDeInit();
    BSL_ERR_ClearError();
    return;
}
/* END_CASE */
