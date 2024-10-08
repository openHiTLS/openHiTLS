/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "crypt_bn.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_curve25519.h"
#include "eal_pkey_local.h"
#include "crypt_eal_rand.h"
#include "securec.h"

#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0
void *malloc_fail(uint32_t size)
{
    (void)size;
    return NULL;
}

static void Set_Curve25519_Prv(CRYPT_EAL_PkeyPrv *prv, int id, uint8_t *key, uint32_t keyLen)
{
    prv->id = id;
    prv->key.curve25519Prv.data = key;
    prv->key.curve25519Prv.len = keyLen;
}

static void Set_Curve25519_Pub(CRYPT_EAL_PkeyPub *pub, int id, uint8_t *key, uint32_t keyLen)
{
    pub->id = id;
    pub->key.curve25519Pub.data = key;
    pub->key.curve25519Pub.len = keyLen;
}
/* END_HEADER */


/**
 * @test   SDV_CRYPTO_CURVE25519_VERIFY_PROVIDER_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyVerify test for the default provider.
 * @precon Prepare data for verify.
 * @brief
 *    1. Create the context of the ed25519 algorithm using the default provider, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPrv method to set private key, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySign method to sign, expected result 2.
 *    4. Call the CRYPT_EAL_PkeyVerify method, where all parameters are valid, expected result 2
 *    5. Call the CRYPT_EAL_PkeyVerify method, where other parameters are valid, but :
 *        (1) hashId != CRYPT_MD_SHA512, expected result 3
 *        (2) data = NULL, expected result 4
 *        (3) sign = NULL, expected result 4
 *        (4) signLen = 0 | 63 | 65, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_CURVE25519_HASH_METH_ERROR
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_CURVE25519_SIGNLEN_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_VERIFY_PROVIDER_API_TC001(void)
{
    int hashId = CRYPT_MD_SHA512;
    uint8_t data[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t sign[CRYPT_CURVE25519_SIGNLEN] = {0};
    uint32_t signLen = sizeof(sign);
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, CRYPT_PKEY_ED25519, key, CRYPT_CURVE25519_KEYLEN);
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, CRYPT_PKEY_ED25519, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_ED25519, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, hashId, data, sizeof(data), sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, data, sizeof(data), sign, signLen),
        CRYPT_CURVE25519_HASH_METH_ERROR);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, data, sizeof(data), sign, signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, NULL, sizeof(data), sign, signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, data, sizeof(data), NULL, signLen), CRYPT_NULL_INPUT);

    signLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, data, sizeof(data), sign, signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);
    signLen = CRYPT_CURVE25519_SIGNLEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, data, sizeof(data), sign, signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);
    signLen = CRYPT_CURVE25519_SIGNLEN + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, data, sizeof(data), sign, signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);
exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_SET_PARA_PROVIDER_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeySetPara test for the default provider.
 * @precon nan
 * @brief
 *    1. Create the context of the curve25519 algorithm using the default provider, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method, where parameter para.id is CRYPT_PKEY_*25519, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySetPara method, where parameter para.id is not CRYPT_PKEY_*25519, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_EAL_ALG_NOT_SUPPORT
 *    3. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_SET_PARA_PROVIDER_API_TC001(int id)
{
    TestMemInit();
    CRYPT_EAL_PkeyPara para;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    para.id = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_EAL_ALG_NOT_SUPPORT);
    para.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_EAL_ERR_ALGID);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_CURVE25519_KEY_GEN_PROVIDER_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyGen test for the defalut provider.
 * @precon nan
 * @brief
 *    1. Create the context of the curve25519 algorithm using the defalut provider, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGen method, where pkey is NULL, expected result 1.
 *    3. Call the CRYPT_EAL_PkeyGen method, where pkey is valid, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_NO_REGIST_RAND
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_KEY_GEN_PROVIDER_API_TC001(int id)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_NO_REGIST_RAND);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_CURVE25519_SET_PUB_PROVIDER_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeySetPub test for the default provider.
 * @precon Create a valid public key pub.
 * @brief
 *    1. Create the context of the curve25519 algorithm using the default provider, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPub method:
 *       (1). pkey = NULL, expected result 2.
 *       (2). pub = NULL, expected result 2.
 *       (3). pub.data = NULL, expected result 2.
 *       (4). pub.len = 0, expected result 2.
 *       (5). pub.id != pkey.id, expected result 3.
 *       (6). pub.len = 33|31, expected result 4.
 *       (7). All parameters are valid, expected result 5.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_ERR_ALGID
 *    4. CRYPT_CURVE25519_KEYLEN_ERROR
 *    5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_SET_PUB_PROVIDER_API_TC001(int id)
{
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, id, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, NULL), CRYPT_NULL_INPUT);
    pub.key.curve25519Pub.data = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_NULL_INPUT);
    pub.key.curve25519Pub.data = key;
    pub.key.curve25519Pub.len = 0;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(NULL, &pub), CRYPT_NULL_INPUT);

    pub.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_EAL_ERR_ALGID);

    pub.id = id;
    pub.key.curve25519Pub.len = CRYPT_CURVE25519_KEYLEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_CURVE25519_KEYLEN_ERROR);
    pub.key.curve25519Pub.len = CRYPT_CURVE25519_KEYLEN + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_CURVE25519_KEYLEN_ERROR);
    pub.key.curve25519Pub.len = CRYPT_CURVE25519_KEYLEN;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_KEY_GEN_PROVIDER_API_TC002
 * @title  CURVE25519: CRYPT_EAL_PkeyGen test for the default provider.
 * @precon nan
 * @brief
 *    1. Create the context of the curve25519 algorithm using the default provider, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Generate a key pair, expected result 2.
 *    4. Call the CRYPT_EAL_PkeyGetPub method to get public key, expected result 2.
 *    5. Call the CRYPT_EAL_PkeyGetPub method to get private key, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Success
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_KEY_GEN_PROVIDER_API_TC002(int id)
{
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPub pub;
    Set_Curve25519_Pub(&pub, id, key, CRYPT_CURVE25519_KEYLEN);
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, id, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    /* Sets the entropy source. */
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_DUP_CTX_PROVIDER_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyDupCtx test for the default provider.
 * @precon nan
 * @brief
 *    1. Create the context of the ed25519 algorithm using the default provider, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Generate a key pair, expected result 2.
 *    4. Call the CRYPT_EAL_PkeyDupCtx method to dup ed25519 context, expected result 2.
 *    5. Call the CRYPT_EAL_PkeyGetPub method to obtain the public key from the contexts, expected result 2.
 *    6. Compare public keys, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. The two public keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_DUP_CTX_PROVIDER_API_TC001(int id)
{
    uint8_t key1[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t key2[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, id, key1, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *newPkey = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(newPkey != NULL);
    ASSERT_EQ(newPkey->references.count, 1);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    pub.key.curve25519Pub.data = key2;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(newPkey, &pub), CRYPT_SUCCESS);

    ASSERT_COMPARE("curve25519 copy ctx", key1, CRYPT_CURVE25519_KEYLEN, key2, CRYPT_CURVE25519_KEYLEN);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newPkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_CMP_PROVIDER_FUNC_TC001
 * @title  Curve25519: The input and output parameters address are the same.
 * @precon Vector: private key and public key.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the curve25519 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 2
 *    3. Set public key for ctx1, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 4
 *    5. Set public key for ctx2, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    5-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_CMP_PROVIDER_FUNC_TC001(int algId, Hex *pubKey)
{
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, algId, pubKey->x, pubKey->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, algId, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, algId, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_CURVE25519_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_CURVE25519_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_X25519_EXCH_PROVIDER_FUNC_TC001
 * @title  X25519 key exchange test: generate key pair and key exchange for the default provider.
 * @precon nan
 * @brief
 *    1. Create two contexts(pkey1, pkey2) of the ed25519 algorithm using the default provider, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Generate a key pair, expected result 2.
 *    4. Compute the shared key from the privite value in pkey1 and the public vlaue in pkey2, expected result 2.
 *    5. Compute the shared key from the privite value in pkey2 and the public vlaue in pkey1, expected result 2.
 *    6. Compare the shared keys computed in the preceding two steps, expected result 3.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. Success.
 *    3. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_X25519_EXCH_PROVIDER_FUNC_TC001(void)
{
#ifndef HITLS_CRYPTO_X25519
    SKIP_TEST();
#endif
    uint8_t share1[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t share2[CRYPT_CURVE25519_KEYLEN] = {0};
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_X25519, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_X25519, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    // Sets the entropy source.
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey2, pkey1, share2, &share2Len), CRYPT_SUCCESS);
    ASSERT_EQ(share1Len, share2Len);
    ASSERT_EQ(memcmp(share1, share2, share1Len), 0);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_X25519_EXCH_PROVIDER_FUNC_TC002
 * @title  X25519 key exchange test: set the key or copy the context, and exchange the key.
 * @precon Test Vectors for X25519: One's public key, The other's private key, Their shared key
 * @brief
 *    1. Create two contexts(pkey1, pkey2) of the X25519 algorithm, expected result 1.
 *    2. Set the public key and private key for pkey1 and pkey2, expected result 2.
 *    3. Compute the shared key from the privite value in pkey1 and the public vlaue in pkey2, expected result 2.
 *    4. Compare the shared key computed by step 5 and the share secret vector, expected result 3.
 *    5. Copy the two contexts, expected result 2.
 *    6. Repeat steps 3 and 4 above.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. Success.
 *    3. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_X25519_EXCH_PROVIDER_FUNC_TC002(Hex *pubkey, Hex *prvkey, Hex *share)
{
#ifndef HITLS_CRYPTO_X25519
    SKIP_TEST();
#endif
    uint8_t shareKey[CRYPT_CURVE25519_KEYLEN];
    uint32_t shareLen = sizeof(shareKey);
    CRYPT_EAL_PkeyCtx *cpyCtx1 = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx2 = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};

    Set_Curve25519_Pub(&pub, CRYPT_PKEY_X25519, pubkey->x, pubkey->len);
    Set_Curve25519_Prv(&prv, CRYPT_PKEY_X25519, prvkey->x, prvkey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey1, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey2, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareKey, &shareLen), CRYPT_SUCCESS);
    ASSERT_EQ(shareLen, share->len);
    ASSERT_EQ(memcmp(shareKey, share->x, shareLen), 0);

    cpyCtx1 = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    cpyCtx2 = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    ASSERT_TRUE(cpyCtx1 != NULL && cpyCtx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx1, pkey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx2, pkey2), CRYPT_SUCCESS);
    shareLen = sizeof(shareKey);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(cpyCtx1, cpyCtx2, shareKey, &shareLen), CRYPT_SUCCESS);
    ASSERT_EQ(shareLen, share->len);
    ASSERT_EQ(memcmp(shareKey, share->x, shareLen), 0);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx1);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx2);
}
/* END_CASE */