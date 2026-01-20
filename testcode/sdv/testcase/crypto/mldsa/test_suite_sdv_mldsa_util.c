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
#include "hitls_build.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_algid.h"
#include "crypt_mldsa.h"
#include "ml_dsa_local.h"
#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
/* END_HEADER */

/* @
* @test  SDV_CRYPTO_MLDSA_CHECK_KEYPAIR_TC001
* @spec  -
* @title Key pair generation function test
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_CHECK_KEYPAIR_TC001(int type)
{
#if !defined(HITLS_CRYPTO_MLDSA_CHECK)
    (void)type;
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    CRYPT_EAL_PkeyPub pubKey = { 0 };
    uint32_t prvKeyLen = 4896; // max len = 4896
    uint32_t pubKeyLen = 2592; // max len = 2592
    uint8_t *prvKeyBuf = BSL_SAL_Malloc(prvKeyLen);
    uint8_t *pubKeyBuf = BSL_SAL_Malloc(pubKeyLen);
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    pubCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    prvCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
#endif
    ASSERT_TRUE(pubKeyBuf != NULL);
    ASSERT_TRUE(prvKeyBuf != NULL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(pubCtx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    prvKey.id = CRYPT_PKEY_ML_DSA;
    pubKey.id = CRYPT_PKEY_ML_DSA;

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, type), CRYPT_SUCCESS);
    prvKey.key.mldsaPrv.len = prvKeyLen;
    prvKey.key.mldsaPrv.data =  prvKeyBuf;
    pubKey.key.mldsaPub.len = pubKeyLen;
    pubKey.key.mldsaPub.data =  pubKeyBuf;

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx, ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pubKey), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(prvCtx, pubCtx), CRYPT_MLDSA_INVALID_PRVKEY); // pub prv mismatch
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, pubCtx), CRYPT_MLDSA_INVALID_PRVKEY); // no prv
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BSL_SAL_Free(prvKeyBuf);
    BSL_SAL_Free(pubKeyBuf);
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_CHECK_KEYPAIR_TC002
* @spec  -
* @title Key pair generation function invalid test
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_CHECK_KEYPAIR_TC002(void)
{
#if !defined(HITLS_CRYPTO_MLDSA_CHECK)
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    int32_t bits1 = CRYPT_MLDSA_TYPE_MLDSA_44;
    int32_t bits2 = CRYPT_MLDSA_TYPE_MLDSA_65;
    CRYPT_EAL_PkeyCtx *ctx1 = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    CRYPT_EAL_PkeyCtx *ctx3 = NULL;

#ifdef HITLS_CRYPTO_PROVIDER
    ctx1 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    ctx3 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ctx3 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
#endif
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_TRUE(ctx3 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx1, ctx2), CRYPT_MLDSA_KEYINFO_NOT_SET); // different key-info
    TestErrClear();

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx1, bits1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, bits1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx3, bits2), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx1, ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx2, ctx2), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx1, ctx2), CRYPT_MLDSA_PAIRWISE_CHECK_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_CHECK_PRVKEY_TC001
* @spec  -
* @title Key generation and check prv key
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_CHECK_PRVKEY_TC001(int type)
{
#if !defined(HITLS_CRYPTO_MLDSA_CHECK)
    (void)type;
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPrv sk = { 0 };
    uint32_t skLen = 0;
    CRYPT_ML_DSA_Ctx *tmp = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    prvCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
#endif
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    uint32_t val = (uint32_t)type;
    sk.id = CRYPT_PKEY_ML_DSA;

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_MLDSA_KEYINFO_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, val), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &skLen, sizeof(skLen)), CRYPT_SUCCESS);
    sk.key.mldsaPrv.len = skLen;
    sk.key.mldsaPrv.data =  BSL_SAL_Malloc(skLen);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &sk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_MLDSA_INVALID_PRVKEY); // no dk
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &sk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_SUCCESS); // dk is set

    tmp = (CRYPT_ML_DSA_Ctx *)prvCtx->key;
    tmp->prvLen = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_MLDSA_INVALID_PRVKEY); // dk is set

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BSL_SAL_Free(sk.key.mldsaPrv.data);
    TestRandDeInit();
#endif
}
/* END_CASE */
