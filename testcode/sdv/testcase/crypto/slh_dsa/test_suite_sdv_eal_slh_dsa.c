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
#include "crypt_eal_pkey.h"
#include "crypt_slh_dsa.h"
#include "crypt_util_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "stub_utils.h"
#include "test.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

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

/* @
* @test  SDV_CRYPTO_SLH_DSA_SET_PARA_ID_REPEATED_TC001
* @spec  -
* @title  CRYPT_CTRL_SET_PARA_BY_ID cannot be called twice on the same SLH-DSA context
* @brief
* 1.Create an SLH-DSA pkey context.
* 2.Set para by id with CRYPT_SLH_DSA_SHA2_128S, expected CRYPT_SUCCESS.
* 3.Set para by id again, expected CRYPT_SLHDSA_CTRL_INIT_REPEATED.
* @expect  second set returns CRYPT_SLHDSA_CTRL_INIT_REPEATED
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_SET_PARA_ID_REPEATED_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);

    int32_t algId = CRYPT_SLH_DSA_SHA2_128S;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_SUCCESS);

    /* Set the same algId again — must be rejected */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_SLHDSA_CTRL_INIT_REPEATED);

    /* Set a different algId — also must be rejected */
    int32_t otherAlgId = CRYPT_SLH_DSA_SHA2_128F;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&otherAlgId, sizeof(otherAlgId)), CRYPT_SLHDSA_CTRL_INIT_REPEATED);

    BSL_ERR_ClearError();
    ASSERT_TRUE(TestIsErrStackEmpty());

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
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, NULL, 0) == CRYPT_INVALID_ARG);
    int32_t preHash = 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &preHash, sizeof(preHash)) ==
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
    int32_t algId = CRYPT_SLH_DSA_SHA2_128S;
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
    memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
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
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
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
    memset(&pub, 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_SLH_DSA;
    pub.key.slhDsaPub.seed = pubSeed;
    pub.key.slhDsaPub.root = pubRoot;
    pub.key.slhDsaPub.len = 16;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prv;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
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
    memset(&pubOut, 0, sizeof(CRYPT_EAL_PkeyPub));
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
    int32_t isDeterministic = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, (void *)&isDeterministic,
                                 sizeof(isDeterministic)),
              CRYPT_SUCCESS);
    if (addrand->len != 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (void *)addrand->x, addrand->len),
                  CRYPT_SUCCESS);
    }

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
    int32_t isDeterministic = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, (void *)&isDeterministic,
                                 sizeof(isDeterministic)),
              CRYPT_SUCCESS);
    if (addrand->len != 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (void *)addrand->x, addrand->len),
                  CRYPT_SUCCESS);
    }
    int32_t prehash = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, (void *)&prehash, sizeof(prehash)),
              CRYPT_SUCCESS);
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
    uint8_t sigOut[50000] = {0};
    uint32_t sigOutLen = sizeof(sigOut);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, preHashId, msg->x, msg->len, sigOut, &sigOutLen), CRYPT_SUCCESS);
    ASSERT_TRUE(sigOutLen == sig->len);
    ASSERT_TRUE(memcmp(sigOut, sig->x, sigOutLen) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, (int32_t)BSL_CID_AES128_ECB, msg->x, msg->len, sigOut, &sigOutLen),
        CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
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
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
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
    memset(&prv, 0, sizeof(CRYPT_EAL_PkeyPrv));
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

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_SIGN_ADDRAND_TC001(int id)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint8_t msg[] = "hello world";
    uint8_t sig1[50000] = {0};
    uint8_t sig2[50000] = {0};
    uint32_t sigLen1 = sizeof(sig1);
    uint32_t sigLen2 = sizeof(sig2);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig1, &sigLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig2, &sigLen2), CRYPT_SUCCESS);

    ASSERT_TRUE(sigLen1 == sigLen2);
    ASSERT_TRUE(memcmp(sig1, sig2, sigLen1) != 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig1, sigLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig2, sigLen2), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_SIGN_ADDRAND_TC002(int id)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint8_t msg[] = "hello world";
    uint8_t sig1[50000] = {0};
    uint8_t sig2[50000] = {0};
    uint32_t sigLen1 = sizeof(sig1);
    uint32_t sigLen2 = sizeof(sig2);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig1, &sigLen1), CRYPT_SUCCESS);

    int32_t isDeterministic = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &isDeterministic, sizeof(isDeterministic)),
              CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig2, &sigLen2), CRYPT_SUCCESS);

    ASSERT_TRUE(sigLen1 == sigLen2);
    ASSERT_TRUE(memcmp(sig1, sig2, sigLen1) != 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig1, sigLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig2, sigLen2), CRYPT_SUCCESS);

    uint8_t sig3[50000] = {0};
    uint32_t sigLen3 = sizeof(sig3);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg), sig3, &sigLen3), CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(sig2, sig3, sigLen2) == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

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

/* @
* @test  SDV_CRYPTO_SLH_DSA_DIRECT_KEY_EX_TC001
* @title Cover direct SLH-DSA structured key APIs and parameter validation
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_DIRECT_KEY_EX_TC001(void)
{
    TestMemInit();
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    int32_t algId = CRYPT_SLH_DSA_SHA2_128S;
    uint8_t prvSeed[16] = {0};
    uint8_t prvPrf[16] = {0};
    uint8_t pubSeed[16] = {0};
    uint8_t pubRoot[16] = {0};
    BSL_Param pubParams[3];
    BSL_Param prvParams[5];
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    InitSlhDsaPubParams(pubParams, pubSeed, pubRoot, sizeof(pubSeed));
    InitSlhDsaPrvParams(prvParams, prvSeed, prvPrf, pubSeed, pubRoot, sizeof(prvSeed));

    ASSERT_EQ(CRYPT_SLH_DSA_GetPubKeyEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_SLH_DSA_GetPubKeyEx(ctx, pubParams), CRYPT_SLHDSA_ERR_NO_PUBKEY);
    ASSERT_EQ(CRYPT_SLH_DSA_GetPrvKeyEx(ctx, prvParams), CRYPT_SLHDSA_ERR_NO_PRVKEY);

    pubParams[1].value = NULL;
    ASSERT_EQ(CRYPT_SLH_DSA_SetPubKeyEx(ctx, pubParams), CRYPT_NULL_INPUT);
    pubParams[1].value = pubRoot;
    pubParams[1].valueLen = sizeof(pubRoot) - 1U;
    ASSERT_EQ(CRYPT_SLH_DSA_SetPubKeyEx(ctx, pubParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    pubParams[1].valueLen = sizeof(pubRoot);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPubKeyEx(ctx, pubParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_GetPubKeyEx(ctx, pubParams), CRYPT_SUCCESS);
    ASSERT_EQ(pubParams[0].useLen, sizeof(pubSeed));
    ASSERT_EQ(pubParams[1].useLen, sizeof(pubRoot));

    prvParams[1].valueLen = sizeof(prvPrf) - 1U;
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(ctx, prvParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    prvParams[1].valueLen = sizeof(prvPrf);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(ctx, prvParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_GetPrvKeyEx(ctx, prvParams), CRYPT_SUCCESS);
    ASSERT_EQ(prvParams[0].useLen, sizeof(prvSeed));
    ASSERT_EQ(prvParams[1].useLen, sizeof(prvPrf));

EXIT:
    BSL_ERR_ClearError();
    CRYPT_SLH_DSA_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SLH_DSA_CTRL_MATRIX_TC001
* @title Cover SLH-DSA control options, security categories, and boundary lengths
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_CTRL_MATRIX_TC001(int algId, int keyLen, int expectedSecBits)
{
    TestMemInit();
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    int32_t gotAlgId = 0;
    int32_t secBits = 0;
    int32_t flag = 1;
    int32_t invalidAlgId = 0;
    uint32_t value = 0;
    uint8_t context[256] = {0};
    uint8_t addrand[32] = {0};
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(NULL, CRYPT_CTRL_GET_SIGNLEN, &value, sizeof(value)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_PARAID, &gotAlgId, sizeof(gotAlgId)),
        CRYPT_SLHDSA_ERR_INVALID_ALGID);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &value, sizeof(value)), CRYPT_SUCCESS);
    ASSERT_EQ(value, 0);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &value, sizeof(value)), CRYPT_SUCCESS);
    ASSERT_EQ(value, 0);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SECBITS, &secBits, sizeof(secBits)), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId) - 1U), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &invalidAlgId, sizeof(invalidAlgId)),
        CRYPT_SLHDSA_ERR_INVALID_ALGID);

    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_PARAID, &gotAlgId, sizeof(gotAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(gotAlgId, algId);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SECBITS, &secBits, sizeof(secBits)), CRYPT_SUCCESS);
    ASSERT_EQ(secBits, expectedSecBits);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &value, sizeof(value)), CRYPT_SUCCESS);
    ASSERT_EQ(value, keyLen);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &value, sizeof(value)), CRYPT_SUCCESS);
    ASSERT_TRUE(value > 0);

    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_CTX_INFO, context, sizeof(context)),
        CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_CTX_INFO, context, sizeof(context) - 1U), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, addrand, (uint32_t)keyLen - 1U),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, addrand, (uint32_t)keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &flag, sizeof(flag) - 1U),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &flag, sizeof(flag)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PREHASH_MODE, &flag, sizeof(flag) - 1U), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PREHASH_MODE, &flag, sizeof(flag)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_CLEAN_PUB_KEY, &value, sizeof(value)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, -1, &value, sizeof(value)), CRYPT_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)),
        CRYPT_SLHDSA_CTRL_INIT_REPEATED);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_SLH_DSA_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SLH_DSA_SIGN_VERIFY_PARAM_TC001
* @title Cover SLH-DSA sign and verify argument short-circuit paths
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_SIGN_VERIFY_PARAM_TC001(void)
{
    TestMemInit();
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    int32_t algId = CRYPT_SLH_DSA_SHA2_128S;
    int32_t prehash = 1;
    uint8_t msg[1] = {0};
    uint8_t sig[1] = {0};
    uint32_t sigLen = 0;
    uint8_t prvSeed[16] = {0};
    uint8_t prvPrf[16] = {0};
    uint8_t pubSeed[16] = {0};
    uint8_t pubRoot[16] = {0};
    BSL_Param prvParams[5];
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_SLH_DSA_Sign(NULL, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_SLH_DSA_Verify(ctx, 0, msg, sizeof(msg), NULL, sizeof(sig)), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Sign(ctx, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_SLHDSA_ERR_NO_PRVKEY);
    ASSERT_EQ(CRYPT_SLH_DSA_Verify(ctx, 0, msg, sizeof(msg), sig, sizeof(sig)), CRYPT_SLHDSA_ERR_NO_PUBKEY);
    InitSlhDsaPrvParams(prvParams, prvSeed, prvPrf, pubSeed, pubRoot, sizeof(prvSeed));
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(ctx, prvParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Sign(ctx, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(CRYPT_SLH_DSA_Verify(ctx, 0, msg, sizeof(msg), sig, sizeof(sig)),
        CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);

    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash)), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_SLH_DSA_Sign(ctx, -1, msg, sizeof(msg), sig, &sigLen),
        CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
    ASSERT_EQ(CRYPT_SLH_DSA_Verify(ctx, -1, msg, sizeof(msg), sig, sizeof(sig)),
        CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_SLH_DSA_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SLH_DSA_ALL_SPEC_BOUNDARY_TC001
* @title Validate key and signature length boundaries for every SLH-DSA parameter set
* @brief
* 1.Compare Ctrl results with static expected key-component and signature lengths.
* 2.Check public/private key lengths n-1, n and n+1.
* 3.Check context, addrand, short signature output and invalid verify input boundaries.
* 4.Verify failed operations do not overwrite input/output canaries.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_ALL_SPEC_BOUNDARY_TC001(int algId, int keyLen, int expectedSigLen)
{
    TestMemInit();
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    uint8_t prvSeed[34];
    uint8_t prvPrf[34];
    uint8_t pubSeed[34];
    uint8_t pubRoot[34];
    uint8_t context[256] = {0};
    uint8_t msg[1] = {0x5a};
    uint8_t sigGuard[3] = {0xa5, 0xa5, 0xa5};
    BSL_Param pubParams[3];
    BSL_Param prvParams[5];
    uint32_t actualKeyLen = 0;
    uint32_t actualSigLen = 0;
    uint32_t shortSigLen = (uint32_t)expectedSigLen - 1U;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(keyLen > 0 && keyLen <= 32);
    ASSERT_TRUE(expectedSigLen > 1);
    memset(prvSeed, 0x11, sizeof(prvSeed));
    memset(prvPrf, 0x22, sizeof(prvPrf));
    memset(pubSeed, 0x33, sizeof(pubSeed));
    memset(pubRoot, 0x44, sizeof(pubRoot));
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &actualKeyLen, sizeof(actualKeyLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(actualKeyLen, keyLen);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &actualSigLen, sizeof(actualSigLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(actualSigLen, expectedSigLen);

    InitSlhDsaPubParams(pubParams, pubSeed + 1, pubRoot + 1, (uint32_t)keyLen - 1U);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPubKeyEx(ctx, pubParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    InitSlhDsaPubParams(pubParams, pubSeed + 1, pubRoot + 1, (uint32_t)keyLen + 1U);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPubKeyEx(ctx, pubParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    InitSlhDsaPubParams(pubParams, pubSeed + 1, pubRoot + 1, (uint32_t)keyLen);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPubKeyEx(ctx, pubParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_GetPubKeyEx(ctx, pubParams), CRYPT_SUCCESS);
    ASSERT_EQ(pubParams[0].useLen, keyLen);
    ASSERT_EQ(pubParams[1].useLen, keyLen);
    pubParams[0].valueLen = (uint32_t)keyLen - 1U;
    ASSERT_EQ(CRYPT_SLH_DSA_GetPubKeyEx(ctx, pubParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    pubParams[0].valueLen = (uint32_t)keyLen + 1U;
    pubParams[1].valueLen = (uint32_t)keyLen + 1U;
    ASSERT_EQ(CRYPT_SLH_DSA_GetPubKeyEx(ctx, pubParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);

    InitSlhDsaPrvParams(prvParams, prvSeed + 1, prvPrf + 1, pubSeed + 1, pubRoot + 1,
        (uint32_t)keyLen - 1U);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(ctx, prvParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    InitSlhDsaPrvParams(prvParams, prvSeed + 1, prvPrf + 1, pubSeed + 1, pubRoot + 1,
        (uint32_t)keyLen + 1U);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(ctx, prvParams), CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
    InitSlhDsaPrvParams(prvParams, prvSeed + 1, prvPrf + 1, pubSeed + 1, pubRoot + 1,
        (uint32_t)keyLen);
    ASSERT_EQ(CRYPT_SLH_DSA_SetPrvKeyEx(ctx, prvParams), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SLH_DSA_GetPrvKeyEx(ctx, prvParams), CRYPT_SUCCESS);
    ASSERT_EQ(prvParams[0].useLen, keyLen);
    ASSERT_EQ(prvParams[1].useLen, keyLen);

    if (algId == CRYPT_SLH_DSA_SHA2_128S) {
        ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_CTX_INFO, context, 255), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_CTX_INFO, context, 256),
            CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW);
    }
    if (algId == CRYPT_SLH_DSA_SHA2_128S || algId == CRYPT_SLH_DSA_SHA2_192S ||
        algId == CRYPT_SLH_DSA_SHA2_256S) {
        ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, pubSeed + 1,
            (uint32_t)keyLen - 1U), CRYPT_INVALID_ARG);
        ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, pubSeed + 1,
            (uint32_t)keyLen + 1U), CRYPT_INVALID_ARG);
        ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, pubSeed + 1,
            (uint32_t)keyLen), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_SLH_DSA_Sign(ctx, 0, msg, sizeof(msg), sigGuard + 1, &shortSigLen),
        CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(shortSigLen, (uint32_t)expectedSigLen - 1U);
    ASSERT_EQ(CRYPT_SLH_DSA_Verify(ctx, 0, msg, sizeof(msg), sigGuard + 1,
        (uint32_t)expectedSigLen - 1U), CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(CRYPT_SLH_DSA_Verify(ctx, 0, msg, sizeof(msg), sigGuard + 1,
        (uint32_t)expectedSigLen + 1U), CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
    ASSERT_EQ(sigGuard[0], 0xa5);
    ASSERT_EQ(sigGuard[1], 0xa5);
    ASSERT_EQ(sigGuard[2], 0xa5);
    ASSERT_EQ(prvSeed[0], 0x11);
    ASSERT_EQ(prvSeed[keyLen + 1], 0x11);
    ASSERT_EQ(pubRoot[0], 0x44);
    ASSERT_EQ(pubRoot[keyLen + 1], 0x44);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_SLH_DSA_FreeCtx(ctx);
    return;
}
/* END_CASE */

static CryptSlhDsaCtx *SlhDsaNewSignCtx(int32_t algId, uint32_t keyLen)
{
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    BSL_Param prvParams[5];
    int32_t deterministic = 1;
    if (ctx == NULL) {
        return NULL;
    }
    if (CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)) != CRYPT_SUCCESS ||
        CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &deterministic,
            sizeof(deterministic)) != CRYPT_SUCCESS) {
        CRYPT_SLH_DSA_FreeCtx(ctx);
        return NULL;
    }
    memset(prvSeed, 0x11, keyLen);
    memset(prvPrf, 0x22, keyLen);
    memset(pubSeed, 0x33, keyLen);
    memset(pubRoot, 0x44, keyLen);
    InitSlhDsaPrvParams(prvParams, prvSeed, prvPrf, pubSeed, pubRoot, keyLen);
    if (CRYPT_SLH_DSA_SetPrvKeyEx(ctx, prvParams) != CRYPT_SUCCESS) {
        CRYPT_SLH_DSA_FreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

/* @
* @test  SDV_CRYPTO_SLH_DSA_SIGN_MALLOC_STUB_TC001
* @title Sweep every malloc failure point through the SLH-DSA Sign API
* @brief
* 1.Sign successfully to count malloc calls.
* 2.Fail each malloc once while signing with the same context.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_SIGN_MALLOC_STUB_TC001(int algId, int keyLen)
{
    TestMemInit();
    CryptSlhDsaCtx *ctx = NULL;
    uint8_t msg[1] = {0x5a};
    uint8_t *sig = NULL;
    uint32_t sigLen = 0;
    uint32_t totalMallocCount = 0;
    uint32_t outLen = 0;

    ctx = SlhDsaNewSignCtx(algId, (uint32_t)keyLen);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_SLH_DSA_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    sig = (uint8_t *)malloc(sigLen);
    ASSERT_TRUE(sig != NULL);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    outLen = sigLen;
    ASSERT_EQ(CRYPT_SLH_DSA_Sign(ctx, 0, msg, sizeof(msg), sig, &outLen), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        outLen = sigLen;
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)CRYPT_SLH_DSA_Sign(ctx, 0, msg, sizeof(msg), sig, &outLen);
    }

EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_SLH_DSA_FreeCtx(ctx);
    free(sig);
    BSL_ERR_ClearError();
    return;
}
/* END_CASE */
