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
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PARA_BY_ID, NULL, 0) == CRYPT_INVALID_ARG);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_XMSS_ERR_INVALID_ALGID);
    CRYPT_PKEY_ParaId algId = CRYPT_XMSS_SHA2_10_256;
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
    (void)memset_s(&pub, sizeof(CRYPT_EAL_PkeyPub), 0, sizeof(CRYPT_EAL_PkeyPub));
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
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
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
    (void)memset_s(&pub, sizeof(CRYPT_EAL_PkeyPub), 0, sizeof(CRYPT_EAL_PkeyPub));
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
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_XMSS;
    prv.key.xmssPrv.index = index;
    prv.key.xmssPrv.seed = prvSeed;
    prv.key.xmssPrv.prf = prvPrf;
    prv.key.xmssPrv.pub.seed = pubSeed;
    prv.key.xmssPrv.pub.root = pubRoot;
    prv.key.xmssPrv.pub.len = 32;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
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
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
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
    (void)memset_s(&pubOut, sizeof(CRYPT_EAL_PkeyPub), 0, sizeof(CRYPT_EAL_PkeyPub));
    pubOut.id = CRYPT_PKEY_XMSS;
    pubOut.key.xmssPub.seed = pubSeed;
    pubOut.key.xmssPub.root = pubRoot;

    pubOut.key.xmssPub.len = hashLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubOut), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(pubOut.key.xmssPub.seed, root->x, hashLen), 0);
    ASSERT_EQ(memcmp(pubOut.key.xmssPub.root, root->x + hashLen, hashLen), 0);

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
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t pubLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    uint32_t keyLen = (pubLen - 4) / 2;
    CRYPT_EAL_PkeyPrv prv;
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_XMSS;
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
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t pubLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PUBKEY_LEN, (void *)&pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    uint32_t keyLen = (pubLen - 4) / 2;
    CRYPT_EAL_PkeyPub pub;
    (void)memset_s(&pub, sizeof(CRYPT_EAL_PkeyPub), 0, sizeof(CRYPT_EAL_PkeyPub));
    pub.id = CRYPT_PKEY_XMSS;
    pub.key.xmssPub.seed = key->x;
    pub.key.xmssPub.root = key->x + keyLen;
    pub.key.xmssPub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, msg->x, msg->len, sig->x, sig->len), result);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */
