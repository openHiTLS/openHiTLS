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
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "eal_pkey_local.h"
#include "crypt_eal_codecs.h"
/* END_HEADER */

/* @
 * @test SDV_CRYPTO_COMPOSITE_API_TC001
 * @spec -
 * @title Test Composite ML-DSA API: context, key generation, and key I/O.
 * @precon nan
 * @brief
 * 1.Create two contexts (ctxA, ctxB).
 * 2.Set parameters by ID, including error test.
 * 3.Generate keys for ctxA.
 * 4.Export keys from ctxA (GetPub/GetPrv).
 * 5.Import keys into ctxB (SetPub/SetPrv).
 * @expect
 * 1.Contexts and key operations succeed.
 * 2.Key I/O is successful.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_API_TC001(int type)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctxA = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    CRYPT_EAL_PkeyCtx *ctxB = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    int32_t val = CRYPT_PKEY_PARAID_MAX;
    ASSERT_TRUE(ctxA != NULL);
    ASSERT_TRUE(ctxB != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_INVALID_ARG);
    val = (int32_t)type;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxB, val), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctxA), CRYPT_SUCCESS);

    uint32_t pubKeyLen = 0;
    uint32_t prvKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen)),
        CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pk = { 0 };
    pk.id = CRYPT_PKEY_COMPOSITE;
    pk.key.compositePub.len = pubKeyLen;
    pk.key.compositePub.data = BSL_SAL_Malloc(pubKeyLen);
    ASSERT_TRUE(pk.key.compositePub.data != NULL);
    
    CRYPT_EAL_PkeyPrv sk = { 0 };
    sk.id = CRYPT_PKEY_COMPOSITE;
    sk.key.compositePrv.len = prvKeyLen;
    sk.key.compositePrv.data = BSL_SAL_Malloc(prvKeyLen);
    ASSERT_TRUE(sk.key.compositePrv.data != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctxA, &pk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctxA, &sk), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctxB, &pk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctxB, &sk), CRYPT_SUCCESS);
EXIT:

    BSL_SAL_Free(pk.key.compositePub.data);
    BSL_SAL_Free(sk.key.compositePrv.data);
    CRYPT_EAL_PkeyFreeCtx(ctxA);
    CRYPT_EAL_PkeyFreeCtx(ctxB);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_SIGN_TC001
 * @spec -
 * @title Test Composite ML-DSA signature and verification.
 * @precon Private and public key data is available.
 * @brief
 * 1.Create context and set parameters.
 * 2.Set the private key.
 * 3.Call the signature interface.
 * 4.Set the public key.
 * 5.Call the verification interface.
 * @expect
 * 1.Signature operation succeeds.
 * 2.Verification operation succeeds.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_SIGN_TC001(int type, Hex *ctxText, Hex *testPrvKey, Hex *testPubKey, Hex *msg)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    prvKey.id = CRYPT_PKEY_COMPOSITE;
    prvKey.key.compositePrv.data = testPrvKey->x;
    prvKey.key.compositePrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t outLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    uint8_t *out = BSL_SAL_Malloc(outLen);
    ASSERT_TRUE(out != NULL);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    
    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_COMPOSITE;
    pubKey.key.compositePub.data = testPubKey->x;
    pubKey.key.compositePub.len = testPubKey->len;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg->x, msg->len, out, outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t outLenWithCtx = CRYPT_EAL_PkeyGetSignLen(ctx);
    uint8_t *outWithCtx = BSL_SAL_Malloc(outLenWithCtx);
    ASSERT_TRUE(outWithCtx != NULL);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, msg->x, msg->len, outWithCtx, &outLenWithCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg->x, msg->len, outWithCtx, outLenWithCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(out);
    BSL_SAL_Free(outWithCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_VERIFY_TC001
 * @spec -
 * @title Test Composite ML-DSA signature verification with pre-generated signature.
 * @precon Public key, message, and signature data is available.
 * @brief
 * 1.Create context and set parameters.
 * 2.Set the public key.
 * 3.Call the verification interface with message and signature.
 * @expect
 * 1.Verification operation succeeds.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_VERIFY_TC001(int type, Hex *ctxText, Hex *testPubKey, Hex *msg, Hex *sign, Hex *signWithCtx)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_COMPOSITE;
    pubKey.key.compositePub.data = testPubKey->x;
    pubKey.key.compositePub.len = testPubKey->len;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg->x, msg->len, sign->x, sign->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg->x, msg->len, signWithCtx->x, signWithCtx->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_CHECK_KEYPAIR_TC001
 * @spec -
 * @title Test Composite ML-DSA keypair check API.
 * @precon ML-DSA Keypair check is enabled (HITLS_CRYPTO_COMPOSITE_CHECK defined).
 * @brief
 * 1. Create contexts (ctx, pubCtx, prvCtx) and set parameters.
 * 2. Test keypair check before key generation (expect failure).
 * 3. Generate a keypair in ctx.
 * 4. Test keypair check on the generated keypair (expect success).
 * 5. Extract public key (pk) and private key (sk) from ctx.
 * 6. Set private key in prvCtx and public key in pubCtx.
 * 7. Test keypair check with mismatched public/private contexts (expect failure).
 * 8. Test keypair check with a public key context as the private key context (expect failure, no private key).
 * 9. Test keypair check with public key context as the public key context and private key context as the private
 *    key context (expect success).
 * @expect
 * 1. Keypair check succeeds only when both public and private keys are present and match.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_CHECK_KEYPAIR_TC001(int type)
{
#if !defined(HITLS_CRYPTO_COMPOSITE_CHECK)
    (void)type;
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    pubCtx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    prvCtx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
#endif
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(pubCtx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx, ctx), CRYPT_COMPOSITE_KEYINFO_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, type), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx, ctx), CRYPT_SUCCESS);

    uint32_t pubKeyLen = 0;
    uint32_t prvKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen)),
        CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pk = { 0 };
    pk.id = CRYPT_PKEY_COMPOSITE;
    pk.key.compositePub.len = pubKeyLen;
    pk.key.compositePub.data = BSL_SAL_Malloc(pubKeyLen);
    ASSERT_TRUE(pk.key.compositePub.data != NULL);
 
    CRYPT_EAL_PkeyPrv sk = { 0 };
    sk.id = CRYPT_PKEY_COMPOSITE;
    sk.key.compositePrv.len = prvKeyLen;
    sk.key.compositePrv.data = BSL_SAL_Malloc(prvKeyLen);
    ASSERT_TRUE(sk.key.compositePrv.data != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &sk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &sk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pk), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(prvCtx, pubCtx), CRYPT_MLDSA_INVALID_PRVKEY); // pub prv mismatch
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, pubCtx), CRYPT_MLDSA_INVALID_PRVKEY); // no prv
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BSL_SAL_Free(sk.key.compositePrv.data);
    BSL_SAL_Free(pk.key.compositePub.data);
    TestRandDeInit();
#endif
}
/* END_CASE */
