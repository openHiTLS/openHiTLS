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
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_util_rand.h"
/* END_HEADER */

static uint8_t gMlDsaRandBuf[3][32] = { 0 };
uint32_t gMlDsaRandNum = 0;
static int32_t TEST_MLDSARandom(uint8_t *randNum, uint32_t randLen)
{
    memcpy_s(randNum, randLen, gMlDsaRandBuf[gMlDsaRandNum], 32);
    gMlDsaRandNum++;
    return 0;
}

static int32_t TEST_MLDSARandomEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void) libCtx;
    return TEST_MLDSARandom(randNum, randLen);
}

/* @
* @test  SDV_CRYPTO_MLDSA_API_TC001
* @spec  -
* @title  Test the MLDSA external interface.
* @precon  nan
* @brief
* 1.Generate the context.
* 2.Call the copy and cmp interfaces.
* @expect
* 1.success
* 2.The result is same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_API_TC001(int type, int setBits)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx1 = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    CRYPT_EAL_PkeyCtx *ctx3 = NULL;
 
#ifdef HITLS_CRYPTO_PROVIDER
    ctx1 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
#endif
    ASSERT_TRUE(ctx1 != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyGen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_PROVIDER
    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
#endif
    ASSERT_TRUE(ctx2 != NULL);
    val = (uint32_t)type;
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyGen(ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    ctx3 = CRYPT_EAL_PkeyDupCtx(ctx1);
    ASSERT_TRUE(ctx3 != NULL);
    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx3);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t secBits = CRYPT_EAL_PkeyGetSecurityBits(ctx1);
    ASSERT_EQ(secBits, setBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_FUNC_KEYGEN_TC001
* @spec  -
* @title  Generate public and private key tests.
* @precon  nan
* @brief
* 1.Registers a random number that returns the specified value.
* 2.Call the key generation interface.
* @expect
* 1.success
* 2.The public and private key is same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_KEYGEN_TC001(int type, Hex *d, Hex *testPubkey, Hex *testPrvKey)
{
    TestMemInit();
    gMlDsaRandNum = 0;
    memcpy_s(gMlDsaRandBuf[0], 32, d->x, d->len);
    CRYPT_RandRegist(TEST_MLDSARandom);
    CRYPT_RandRegistEx(TEST_MLDSARandomEx);
 
    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_ML_DSA;
    pubKey.key.mldsaPub.len = testPubkey->len;
    pubKey.key.mldsaPub.data = BSL_SAL_Malloc(testPubkey->len);
    ASSERT_TRUE(pubKey.key.mldsaPub.data != NULL);

    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    prvKey.id = CRYPT_PKEY_ML_DSA;
    prvKey.key.mldsaPrv.len = testPrvKey->len;
    prvKey.key.mldsaPrv.data = BSL_SAL_Malloc(testPrvKey->len);
    ASSERT_TRUE(prvKey.key.mldsaPrv.data != NULL);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    pubKey.key.mldsaPub.len = testPubkey->len;
    ret = CRYPT_EAL_PkeyGetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_KEY_NOT_SET);

    prvKey.key.mldsaPrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeyGetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_KEY_NOT_SET);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    pubKey.key.mldsaPub.len = testPubkey->len - 1;
    ret = CRYPT_EAL_PkeyGetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_LEN_NOT_ENOUGH);

    pubKey.key.mldsaPub.len = testPubkey->len;
    ret = CRYPT_EAL_PkeyGetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    prvKey.key.mldsaPrv.len = testPrvKey->len - 1;
    ret = CRYPT_EAL_PkeyGetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_LEN_NOT_ENOUGH);

    prvKey.key.mldsaPrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeyGetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ASSERT_COMPARE("compare pubkey", pubKey.key.mldsaPub.data, pubKey.key.mldsaPub.len, testPubkey->x, testPubkey->len);
    ASSERT_COMPARE("compare prvkey", prvKey.key.mldsaPrv.data, prvKey.key.mldsaPrv.len, testPrvKey->x, testPrvKey->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(pubKey.key.mldsaPub.data);
    BSL_SAL_FREE(prvKey.key.mldsaPrv.data);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_FUNC_SIGNDATA_TC001
* @spec  -
* @title  Signature test.
* @precon  nan
* @brief
* 1.Registers a random number that returns the specified value.
* 2.Set the private key.
* 3.Call the signature interface.
* @expect
* 1.success
* 2.success
* 3.The signature value is consistent with the test vector.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_SIGNDATA_TC001(int type, Hex *seed, Hex *testPrvKey, Hex *msg, Hex *sign)
{
    TestMemInit();
    gMlDsaRandNum = 0;
    memcpy_s(gMlDsaRandBuf[0], 32, seed->x, seed->len);
    CRYPT_RandRegist(TEST_MLDSARandom);
    CRYPT_RandRegistEx(TEST_MLDSARandomEx);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t outLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_EQ(outLen, sign->len);
    uint8_t *out = BSL_SAL_Malloc(outLen);

    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    prvKey.id = CRYPT_PKEY_ML_DSA;
    prvKey.key.mldsaPrv.data = testPrvKey->x;
    prvKey.key.mldsaPrv.len = testPrvKey->len - 1;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_KEYLEN_ERROR);

    prvKey.key.mldsaPrv.len = testPrvKey->len + 1;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_KEYLEN_ERROR);

    prvKey.key.mldsaPrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("compare sign", out, outLen, sign->x, sign->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(out);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_FUNC_VERIFYDATA_TC001
* @spec  -
* @title  Verify test.
* @precon  nan
* @brief
* 1.Set the public key.
* 2.Call the verify interface.
* @expect
* 1.success
* 2.The verify value is consistent with the test vector.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_VERIFYDATA_TC001(int type, Hex *testPubKey, Hex *msg, Hex *sign, int res)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_ML_DSA;
    pubKey.key.mldsaPub.data = testPubKey->x;

    pubKey.key.mldsaPub.len = testPubKey->len - 1;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_KEYLEN_ERROR);

    pubKey.key.mldsaPub.len = testPubKey->len + 1;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_MLDSA_KEYLEN_ERROR);

    pubKey.key.mldsaPub.len = testPubKey->len;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg->x, msg->len, sign->x, sign->len);
    if (res == 1) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_NE(ret, CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_FUNC_SIGNDATA_TC002
* @spec  -
* @title  Signature test.
* @precon  nan
* @brief
* 1.Registers a random number that returns the specified value.
* 2.Set the private key and additional messages.
* 3.Call the signature interface.
* @expect
* 1.success
* 2.success
* 3.The signature value is consistent with the test vector.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_SIGNDATA_TC002(int type, Hex *seed, Hex *testPrvKey, Hex *msg, Hex *ctxText,
    Hex *sign, int deterministic, int externalMu, int encodeCtx)
{
    TestMemInit();
    gMlDsaRandNum = 0;
    memcpy_s(gMlDsaRandBuf[0], 32, seed->x, seed->len);
    CRYPT_RandRegist(TEST_MLDSARandom);
    CRYPT_RandRegistEx(TEST_MLDSARandomEx);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)deterministic;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)encodeCtx;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)externalMu;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t outLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_EQ(outLen, sign->len);
    uint8_t *out = BSL_SAL_Malloc(outLen);

    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    prvKey.id = CRYPT_PKEY_ML_DSA;
    prvKey.key.mldsaPrv.data = testPrvKey->x;
    prvKey.key.mldsaPrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("compare sign", out, outLen, sign->x, sign->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(out);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_FUNC_VERIFYDATA_TC002
* @spec  -
* @title  Verify test.
* @precon  nan
* @brief
* 1.Set the public key.
* 2.Call the verify interface.
* @expect
* 1.success
* 2.The verify value is consistent with the test vector.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_VERIFYDATA_TC002(int type, Hex *testPubKey, Hex *msg, Hex *sign, Hex *ctxText, int externalMu, int encodeCtx, int res)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)encodeCtx;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)externalMu;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_ML_DSA;
    pubKey.key.mldsaPub.data = testPubKey->x;
    pubKey.key.mldsaPub.len = testPubKey->len;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg->x, msg->len, sign->x, sign->len);
    if (res == 0) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    } else {
        ASSERT_NE(ret, CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_FUNC_SIGN_TC001
* @spec  -
* @title  Signature test.
* @precon  nan
* @brief
* 1.Registers a random number that returns the specified value.
* 2.Set the private key and additional messages.
* 3.Call the signature interface.
* @expect
* 1.success
* 2.success
* 3.The signature value is consistent with the test vector.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_SIGN_TC001(int type, int hashId, Hex *seed, Hex *testPrvKey, Hex *msg, Hex *ctxText,
    Hex *sign, int deterministic, int externalMu, int encodeCtx)
{
    TestMemInit();
    gMlDsaRandNum = 0;
    memcpy_s(gMlDsaRandBuf[0], 32, seed->x, seed->len);
    CRYPT_RandRegist(TEST_MLDSARandom);
    CRYPT_RandRegistEx(TEST_MLDSARandomEx);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)deterministic;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)encodeCtx;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (uint32_t)externalMu;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t outLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_EQ(outLen, sign->len);
    uint8_t *out = BSL_SAL_Malloc(outLen);

    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    prvKey.id = CRYPT_PKEY_ML_DSA;
    prvKey.key.mldsaPrv.data = testPrvKey->x;
    prvKey.key.mldsaPrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = 1;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PREHASH_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySign(ctx, hashId, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("compare sign", out, outLen, sign->x, sign->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(out);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLDSA_FUNC_VERIFY_TC001
* @spec  -
* @title  Verify test.
* @precon  nan
* @brief
* 1.Set the public key.
* 2.Call the verify interface.
* @expect
* 1.success
* 2.The verify value is consistent with the test vector.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_VERIFY_TC001(int type, int hashId, Hex *testPubKey, Hex *msg, Hex *sign, Hex *ctxText, int externalMu, int encodeCtx, int res)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (int32_t)encodeCtx;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = (int32_t)externalMu;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_ML_DSA;
    pubKey.key.mldsaPub.data = testPubKey->x;
    pubKey.key.mldsaPub.len = testPubKey->len;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = 1;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PREHASH_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(ctx, hashId, msg->x, msg->len, sign->x, sign->len);
    if (res == 0) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    } else {
        ASSERT_NE(ret, CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_MLDSA_FUNC_PROVIDER_TC001
 * @title  To test the provisioner function.
 * @precon Registering memory-related functions.
 * @brief
 *    Invoke the signature and signature verification functions to test the function correctness.
 * @expect
 *    Success, and contexts are not NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_MLDSA_FUNC_PROVIDER_TC001(int type, Hex *testPubKey, Hex *testPrvKey, Hex *msg, Hex *context, Hex *sign)
{
    TestMemInit();
    TestRandInitSelfCheck();
    uint8_t *out = NULL;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, context->x, context->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    val = 1;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t outLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_EQ(outLen, sign->len);
    out = BSL_SAL_Malloc(outLen);
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    prvKey.id = CRYPT_PKEY_ML_DSA;
    prvKey.key.mldsaPrv.data = testPrvKey->x;
    prvKey.key.mldsaPrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("compare sign", out, outLen, sign->x, sign->len);

    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_ML_DSA;
    pubKey.key.mldsaPub.len = testPubKey->len;
    pubKey.key.mldsaPub.data = testPubKey->x;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg->x, msg->len, sign->x, sign->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
#endif
    ASSERT_TRUE(ctx2 != NULL);

    val = (uint32_t)type;
    ret = CRYPT_EAL_PkeySetParaById(ctx2, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyGen(ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGetPub(ctx2, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(pubKey.key.mldsaPub.len, testPubKey->len);
    ret = CRYPT_EAL_PkeyGetPrv(ctx2, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(prvKey.key.mldsaPrv.len, testPrvKey->len);

    val = 1;
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PREHASH_FLAG, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySign(ctx2, CRYPT_MD_SHA256, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(ctx2, CRYPT_MD_SHA256, msg->x, msg->len, out, outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ret = CRYPT_EAL_PkeyCmp(ctx, ctx2);
    ASSERT_NE(ret, CRYPT_SUCCESS);
    (void)TestErrClear();

    CRYPT_EAL_PkeyCtx *ctx3 = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctx3 != NULL);
    ret = CRYPT_EAL_PkeyCmp(ctx, ctx3);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx3, CRYPT_MD_SHA256, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(ctx3, CRYPT_MD_SHA256, msg->x, msg->len, out, outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    BSL_SAL_Free(out);
    TestRandDeInit();
}
/* END_CASE */
