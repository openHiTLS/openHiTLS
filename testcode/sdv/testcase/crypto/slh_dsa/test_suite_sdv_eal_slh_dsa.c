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
#include "securec.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "test.h"
/* END_HEADER */

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
    (void)memcpy_s(rand, randLen, g_stubRand[g_stubRandCounter], randLen);
    g_stubRandCounter++;
    return CRYPT_SUCCESS;
}

int32_t RandInjectionEx(void *libCtx, uint8_t *rand, uint32_t randLen)
{
    (void)libCtx;
    return RandInjection(rand, randLen);
}

int32_t RandInjectionExSelfCheck(void *libCtx, uint8_t *rand, uint32_t randLen)
{
    if (libCtx == NULL) {
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    return RandInjection(rand, randLen);
}

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_API_NEW_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_API_CTRL_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, NULL, 0) == CRYPT_INVALID_ARG);
    uint8_t context[128] = {0};
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, context, sizeof(context)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_FLAG, NULL, 0) == CRYPT_INVALID_ARG);
    int32_t preHash = 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_FLAG, &preHash, sizeof(preHash)) ==
                CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_GENKEY_TC001(int isProvider)
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
        pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    } else
#endif 
    {
        (void)isProvider;
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    }
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID, NULL, 0) == CRYPT_INVALID_ARG);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SLHDSA_ERR_INVALID_ALGID);
    CRYPT_PKEY_ParaId algId = CRYPT_SLH_DSA_SHA2_128S;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&algId, sizeof(algId)) ==
                CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_GETSET_KEY_TC001(void)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = CRYPT_SLH_DSA_SHA2_128S;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pub;
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    (void)memset_s(&pub, sizeof(CRYPT_EAL_PkeyPub), 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_SLH_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_NULL_INPUT);
    pub.key.slhDsaPub.seed = pubSeed;
    pub.key.slhDsaPub.root = pubRoot;
    pub.key.slhDsaPub.len = sizeof(pubSeed);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);

    CRYPT_EAL_PkeyPrv prv;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_SLH_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_NULL_INPUT);
    prv.key.slhDsaPrv.seed = prvSeed;
    prv.key.slhDsaPrv.prf = prvPrf;
    prv.key.slhDsaPrv.pub.seed = pubSeed;
    prv.key.slhDsaPrv.pub.root = pubRoot;
    prv.key.slhDsaPrv.pub.len = sizeof(pubSeed);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_GETSET_KEY_TC002(void)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = CRYPT_SLH_DSA_SHA2_128S;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pub;
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    (void)memset_s(&pub, sizeof(CRYPT_EAL_PkeyPub), 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_SLH_DSA;
    pub.key.slhDsaPub.seed = pubSeed;
    pub.key.slhDsaPub.root = pubRoot;
    pub.key.slhDsaPub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prv;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = prvSeed;
    prv.key.slhDsaPrv.prf = prvPrf;
    prv.key.slhDsaPrv.pub.seed = pubSeed;
    prv.key.slhDsaPrv.pub.root = pubRoot;
    prv.key.slhDsaPrv.pub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_GENKEY_KAT_TC001(int id, Hex *key, Hex *root)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t keyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    RandInjectionInit();
    uint8_t *stubRand[3] = {key->x, key->x + keyLen, key->x + keyLen * 2};
    uint32_t stubRandLen[3] = {keyLen, keyLen, keyLen};
    RandInjectionSet(stubRand, stubRandLen);
    CRYPT_RandRegist(RandInjection);
    CRYPT_RandRegistEx(RandInjectionEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    CRYPT_EAL_PkeyPub pubOut;
    (void)memset_s(&pubOut, sizeof(CRYPT_EAL_PkeyPub), 0, sizeof(CRYPT_EAL_PkeyPub));
    pubOut.id = CRYPT_PKEY_SLH_DSA;
    pubOut.key.slhDsaPub.seed = pubSeed;
    pubOut.key.slhDsaPub.root = pubRoot;

    pubOut.key.slhDsaPub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubOut), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(pubOut.key.slhDsaPub.seed, root->x, keyLen), 0);
    ASSERT_EQ(memcmp(pubOut.key.slhDsaPub.root, root->x + keyLen, keyLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

// determinstic and no pre-hashed signature generation
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_SIGN_KAT_TC001(int isProvider, int id, Hex *key, Hex *addrand, Hex *msg, Hex *context, Hex *sig)
{
    (void)key;
    (void)addrand;
    (void)msg;
    (void)context;
    (void)sig;
    TestMemInit();
    if (isProvider) {
        CRYPT_RandRegistEx(RandInjectionExSelfCheck);
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t keyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    if (addrand->len == 0) {
        int32_t isDeterministic = 1;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, (void *)&isDeterministic,
                                     sizeof(isDeterministic)),
                  CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (void *)addrand->x, addrand->len),
                  CRYPT_SUCCESS);
    }

    CRYPT_EAL_PkeyPrv prv;
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
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
    uint8_t sigOut[50000] = {0};
    uint32_t sigOutLen = sizeof(sigOut);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg->x, msg->len, sigOut, &sigOutLen), CRYPT_SUCCESS);
    ASSERT_TRUE(sigOutLen == sig->len);
    ASSERT_TRUE(memcmp(sigOut, sig->x, sigOutLen) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_RandRegistEx(RandInjectionEx);
    return;
}
/* END_CASE */

// sign pre-hashed msg
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_SIGN_KAT_TC002(int id, Hex *key, Hex *addrand, Hex *msg, Hex *context, int preHashId, Hex *sig)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t keyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    if (addrand->len == 0) {
        int32_t isDeterministic = 1;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, (void *)&isDeterministic,
                                     sizeof(isDeterministic)),
                  CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (void *)addrand->x, addrand->len),
                  CRYPT_SUCCESS);
    }
    int32_t prehash = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_FLAG, (void *)&prehash, sizeof(prehash)),
              CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPrv prv;
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
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
    uint8_t sigOut[50000] = {0};
    uint32_t sigOutLen = sizeof(sigOut);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, preHashId, msg->x, msg->len, sigOut, &sigOutLen), CRYPT_SUCCESS);
    ASSERT_TRUE(sigOutLen == sig->len);
    ASSERT_TRUE(memcmp(sigOut, sig->x, sigOutLen) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SLH_DSA_CHECK_KEYPAIR_TC001
* @spec  -
* @title Key generation and check key pair
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CHECK_KEYPAIR_TC001(int algId)
{
#if !defined(HITLS_CRYPTO_SLH_DSA_CHECK)
    (void)algId;
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    uint32_t keyLen = 0;
#ifdef HITLS_CRYPTO_PROVIDER
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    pubKey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    prvKey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    pubKey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    prvKey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
#endif
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(pubKey != NULL);
    ASSERT_TRUE(prvKey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubKey, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvKey, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pkey, pkey), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pub;
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};

    pub.id = CRYPT_PKEY_SLH_DSA;
    pub.key.slhDsaPub.seed = pubSeed;
    pub.key.slhDsaPub.root = pubRoot;
    pub.key.slhDsaPub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubKey, &pub), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prv;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = prvSeed;
    prv.key.slhDsaPrv.prf = prvPrf;
    prv.key.slhDsaPrv.pub.seed = pubSeed;
    prv.key.slhDsaPrv.pub.root = pubRoot;
    prv.key.slhDsaPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvKey, &prv), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(prvKey, prvKey), CRYPT_SLHDSA_ERR_NO_PUBKEY);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubKey, pubKey), CRYPT_SLHDSA_ERR_NO_PRVKEY);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubKey, prvKey), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_SLH_DSA_CHECK_KEYPAIR_TC002
* @spec  -
* @title Key generation and check key pair
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CHECK_KEYPAIR_TC002(void)
{
#if !defined(HITLS_CRYPTO_SLH_DSA_CHECK)
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    int32_t algId1 = CRYPT_SLH_DSA_SHA2_128S;
    int32_t algId2 = CRYPT_SLH_DSA_SHAKE_192S;
    CRYPT_EAL_PkeyCtx *ctx1 = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    CRYPT_EAL_PkeyCtx *ctx3 = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx1 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    ctx3 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ctx3 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
#endif
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_TRUE(ctx3 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx1, ctx2), CRYPT_SLHDSA_ERR_INVALID_ALGID); // different key-info
    TestErrClear();

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx1, algId1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, algId1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx3, algId2), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx1, ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx2, ctx2), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx1, ctx2), CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SLH_DSA_CHECK_PRVKEY_TC001
* @spec  -
* @title Key generation and check prv key
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CHECK_PRVKEY_TC001(int type)
{
#if !defined(HITLS_CRYPTO_SLH_DSA_CHECK)
    (void)type;
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPrv prv = { 0 };
    uint32_t keyLen = 0;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    prvCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
#endif
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    uint32_t val = (uint32_t)type;

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_SLHDSA_ERR_INVALID_ALGID);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, val), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = prvSeed;
    prv.key.slhDsaPrv.prf = prvPrf;
    prv.key.slhDsaPrv.pub.seed = pubSeed;
    prv.key.slhDsaPrv.pub.root = pubRoot;
    prv.key.slhDsaPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_SLHDSA_ERR_NO_PRVKEY); // not set prv key.
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */
