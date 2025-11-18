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
#include "curve25519_local.h"
#include "crypt_curve25519.h"

#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE  0
#define CRYPT_EAL_PKEY_CIPHER_OPERATE   1
#define CRYPT_EAL_PKEY_EXCH_OPERATE     2
#define CRYPT_EAL_PKEY_SIGN_OPERATE     4

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
 * @test   SDV_CRYPTO_CURVE25519_SET_PARA_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeySetPara test.
 * @precon nan
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method, where parameter para.id is CRYPT_PKEY_*25519, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySetPara method, where parameter para.id is not CRYPT_PKEY_*25519, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_EAL_ALG_NOT_SUPPORT
 *    3. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_SET_PARA_API_TC001(int id, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyPara para;
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    para.id = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_EAL_ALG_NOT_SUPPORT);
    para.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_EAL_ERR_ALGID);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_SET_PRV_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeySetPrv test.
 * @precon Create a valid private key prv.
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1). pkey = NULL, expected result 2.
 *       (2). prv = NULL, expected result 2.
 *       (3). prv.data = NULL, expected result 2.
 *       (4). prv.len = 0, expected result 2.
 *       (5). prv.id != pkey.id, expected result 3.
 *       (6). prv.len = 33|31, expected result 4.
 *       (7). All parameters are valid, expected result 5.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_ERR_ALGID
 *    4. CRYPT_CURVE25519_KEYLEN_ERROR
 *    5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_SET_PRV_API_TC001(int id, int isProvider)
{
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, id, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, NULL), CRYPT_NULL_INPUT);
    prv.key.curve25519Prv.data = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_NULL_INPUT);
    prv.key.curve25519Prv.data = key;
    prv.key.curve25519Prv.len = 0;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(NULL, &prv), CRYPT_NULL_INPUT);

    prv.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_EAL_ERR_ALGID);

    prv.id = id;
    prv.key.curve25519Prv.len = CRYPT_CURVE25519_KEYLEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_CURVE25519_KEYLEN_ERROR);
    prv.key.curve25519Prv.len = CRYPT_CURVE25519_KEYLEN + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_CURVE25519_KEYLEN_ERROR);
    prv.key.curve25519Prv.len = CRYPT_CURVE25519_KEYLEN;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_SET_PUB_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeySetPub test.
 * @precon Create a valid public key pub.
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
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
void SDV_CRYPTO_CURVE25519_SET_PUB_API_TC001(int id)
{
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, id, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
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
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_GET_PRV_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyGetPrv test.
 * @precon Create a valid private key prv.
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetPrv method, where all parameters are valid, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySetPrv method to set private key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyGetPrv method, where other parameters are valid, but:
 *       (1). pkey = NULL, expected result 4.
 *       (2). prv = NULL, expected result 4.
 *       (5). prv.id != pkey.id, expected result 5.
 *       (6). prv.len = 31, expected result 6.
 *       (6). prv.len = 33, expected result 7.
 *       (7). All parameters are valid, expected result 7.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_CURVE25519_NO_PRVKEY
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_EAL_ERR_ALGID
 *    6. CRYPT_CURVE25519_KEYLEN_ERROR
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_GET_PRV_API_TC001(int id, int isProvider)
{
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, id, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_CURVE25519_NO_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, NULL), CRYPT_NULL_INPUT);

    prv.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_EAL_ERR_ALGID);

    prv.id = id;
    prv.key.curve25519Prv.len = CRYPT_CURVE25519_KEYLEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_CURVE25519_KEYLEN_ERROR);
    prv.key.curve25519Prv.len = CRYPT_CURVE25519_KEYLEN;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
    prv.key.curve25519Prv.len = CRYPT_CURVE25519_KEYLEN + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_GET_PUB_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyGetPub test.
 * @precon Create a valid public key pub.
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetPub method, where all parameters are valid, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySetPub method to set private key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyGetPub method, where other parameters are valid, but :
 *       (1). pkey = NULL, expected result 4.
 *       (2). pub = NULL, expected result 4.
 *       (5). pub.id != pkey.id, expected result 5.
 *       (6). pub.len = 31, expected result 6.
 *       (6). pub.len = 33, expected result 7.
 *       (7). All parameters are valid, expected result 7.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_CURVE25519_NO_PUBKEY
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_EAL_ERR_ALGID
 *    6. CRYPT_CURVE25519_KEYLEN_ERROR
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_GET_PUB_API_TC001(int id, int isProvider)
{
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPub pub;
    Set_Curve25519_Pub(&pub, id, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_CURVE25519_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, NULL), CRYPT_NULL_INPUT);

    pub.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_EAL_ERR_ALGID);

    pub.id = id;
    pub.key.curve25519Pub.len = CRYPT_CURVE25519_KEYLEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_CURVE25519_KEYLEN_ERROR);
    pub.key.curve25519Pub.len = CRYPT_CURVE25519_KEYLEN;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    pub.key.curve25519Pub.len = CRYPT_CURVE25519_KEYLEN + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_GET_KEY_LEN_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyGetKeyLen test.
 * @precon nan
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetKeyLen method, where pkey is NULL, expected result 1.
 *    3. Call the CRYPT_EAL_PkeyGetKeyLen method, where pkey is valid, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Reutrn 0.
 *    3. Return CRYPT_CURVE25519_KEYLEN(32)
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_GET_KEY_LEN_API_TC001(int id, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(NULL), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(pkey), CRYPT_CURVE25519_KEYLEN);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_KEY_GEN_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyGen test.
 * @precon nan
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGen method, where pkey is NULL, expected result 1.
 *    3. Call the CRYPT_EAL_PkeyGen method, where pkey is valid, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_NO_REGIST_RAND
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_KEY_GEN_API_TC001(int id)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_NO_REGIST_RAND);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_KEY_GEN_API_TC002
 * @title  CURVE25519: CRYPT_EAL_PkeyGen test.
 * @precon nan
 * @brief
 *    1. Create the context of the curve25519 algorithm, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Generate a key pair, expected result 2.
 *    4. Call the CRYPT_EAL_PkeyGetPub method to get public key, expected result 2.
 *    5. Call the CRYPT_EAL_PkeyGetPub method to get private key, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Success
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_KEY_GEN_API_TC002(int id, int isProvider)
{
    if (IsCurve25519AlgDisabled(id)) {
        SKIP_TEST();
    }
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPub pub;
    Set_Curve25519_Pub(&pub, id, key, CRYPT_CURVE25519_KEYLEN);
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, id, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    /* Sets the entropy source. */
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_SIGN_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeySign test.
 * @precon Prepare data for signature.
 * @brief
 *    1. Create the context of the ed25519 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySign method, where all parameters are valid, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySetPrv method to set private key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeySign method, where other parameters are valid, but :
 *        (1) hashId != CRYPT_MD_SHA512, expected result 4
 *        (2) data = NULL, expected result 4
 *        (3) sign = NULL, expected result 4
 *        (4) signLen = NULL, expected result 4
 *        (5) signLen = 0 | 63, expected result 5
 *        (6) signLen = 64 | 65, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_CURVE25519_NO_PRVKEY
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_EAL_ERR_ALGID
 *    5. CRYPT_NULL_INPUT
 *    6. CRYPT_CURVE25519_SIGNLEN_ERROR
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_SIGN_API_TC001(int isProvider)
{
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t data[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t sign[CRYPT_CURVE25519_SIGNLEN] = {0};
    uint32_t signLen = sizeof(sign);
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, CRYPT_PKEY_ED25519, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, &signLen), CRYPT_CURVE25519_NO_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, data, sizeof(data), sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, NULL, sizeof(data), sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), NULL, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), (uint8_t *)sign, NULL), CRYPT_NULL_INPUT);

    signLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, &signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);
    signLen = CRYPT_CURVE25519_SIGNLEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, &signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);

    signLen = CRYPT_CURVE25519_SIGNLEN;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, &signLen), CRYPT_SUCCESS);
    signLen = CRYPT_CURVE25519_SIGNLEN + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, &signLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_VERIFY_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyVerify test.
 * @precon Prepare data for verify.
 * @brief
 *    1. Create the context of the ed25519 algorithm, expected result 1.
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
 *    3. CRYPT_EAL_ERR_ALGID
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_CURVE25519_SIGNLEN_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_VERIFY_API_TC001(int isProvider)
{
    uint8_t data[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t sign[CRYPT_CURVE25519_SIGNLEN] = {0};
    uint32_t signLen = sizeof(sign);
    uint8_t key[CRYPT_CURVE25519_KEYLEN] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, CRYPT_PKEY_ED25519, key, CRYPT_CURVE25519_KEYLEN);
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, CRYPT_PKEY_ED25519, key, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, data, sizeof(data), sign, signLen), CRYPT_EAL_ERR_ALGID);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, NULL, sizeof(data), sign, signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, data, sizeof(data), NULL, signLen), CRYPT_NULL_INPUT);

    signLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);
    signLen = CRYPT_CURVE25519_SIGNLEN - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);
    signLen = CRYPT_CURVE25519_SIGNLEN + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, data, sizeof(data), sign, signLen), CRYPT_CURVE25519_SIGNLEN_ERROR);

EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_DUP_CTX_API_TC001
 * @title  CURVE25519: CRYPT_EAL_PkeyDupCtx test.
 * @precon nan
 * @brief
 *    1. Create the context of the ed25519 algorithm, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Generate a key pair, expected result 2.
 *    4. Call the CRYPT_EAL_PkeyDupCtx method to dup ed25519 context, expected result 2.
 *    5. Call the CRYPT_EAL_PkeyGetPub method to obtain the public key from the contexts, expected result 2.
 *    6. Compare public keys, expected result 3.
 *    7. Call the CRYPT_EAL_PkeyComputeShareKey method to compute the shared key from the dupCtx and ctx,
 *      expected result 7.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. The two public keys are the same.
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS
 *    6. The two public keys are the same.
 *    7. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_DUP_CTX_API_TC001(int id)
{
    uint8_t key1[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t key2[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t data[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t sign[CRYPT_CURVE25519_SIGNLEN] = {0};
    uint32_t signLen = sizeof(sign);
    uint8_t sharedKey1[CRYPT_CURVE25519_KEYLEN] = {0};
    uint32_t sharedLen1 = sizeof(sharedKey1);
    uint8_t sharedKey2[CRYPT_CURVE25519_KEYLEN] = {0};
    uint32_t sharedLen2 = sizeof(sharedKey2);
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, id, key1, CRYPT_CURVE25519_KEYLEN);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
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

    if (id == CRYPT_PKEY_ED25519) {
        ASSERT_EQ(CRYPT_EAL_PkeySign(newPkey, CRYPT_MD_SHA512, data, sizeof(data), sign, &signLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(newPkey, CRYPT_MD_SHA512, data, sizeof(data), sign, signLen), CRYPT_SUCCESS);
    } else if (id == CRYPT_PKEY_X25519) {
        ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(newPkey, pkey, sharedKey1, &sharedLen1),
            CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey, newPkey, sharedKey2, &sharedLen2),
            CRYPT_SUCCESS);
        ASSERT_COMPARE("shared key", sharedKey1, CRYPT_CURVE25519_KEYLEN, sharedKey2, CRYPT_CURVE25519_KEYLEN);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newPkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED25519_SIGN_FUNC_TC001
 * @title  ED25519 signature test: set the key and sign.
 * @precon Test Vectors for Ed25519: SECRET KEY, MESSAGE(different length), SIGNATURE
 * @brief
 *    1. Create the context of the ed25519 algorithm, expected result 1.
 *    2. Set the private key for ed25519, expected result 2.
 *    3. Compute the signature of ed25519, expected result 2.
 *    4. Compare the signature computed by step 3 and the signature vector, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Success.
 *    3. The signature calculation result is the same as the signature vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED25519_SIGN_FUNC_TC001(Hex *key, Hex *msg, Hex *sign, int isProvider)
{
    uint8_t *out = NULL;
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_Curve25519_Prv(&prv, CRYPT_PKEY_ED25519, key->x, key->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);

    outLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    out = calloc(1u, outLen);
    ASSERT_TRUE(out != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA512, msg->x, msg->len, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, sign->x, sign->len), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    free(out);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED25519_VERIFY_FUNC_TC001
 * @title  ED25519 signature verification test: set the public key and verify the signature.
 * @precon Test Vectors for Ed25519: PUBLIC KEY, MESSAGE(different length), SIGNATURE
 * @brief
 *    1. Create the context of the ed25519 algorithm, expected result 1.
 *    2. Set the public key for ed25519, expected result 2.
 *    3. Verify the signature of ed25519, expected result 2.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED25519_VERIFY_FUNC_TC001(Hex *key, Hex *msg, Hex *sign, int isProvider)
{
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, CRYPT_PKEY_ED25519, key->x, key->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED25519_SIGN_VERIFY_FUNC_TC001
 * @title  ED25519: Set(or copy) the key, sign, and verify the signature.
 * @precon Test Vectors for Ed25519: SECRET KEY, PUBLIC KEY, MESSAGE(different length), SIGNATURE
 * @brief
 *    1. Create the context of the ed25519 algorithm, expected result 1
 *    2. Set the private key for ed25519, expected result 2
 *    3. Set the public key for ed25519(Public key and private key can coexist.), expected result 2
 *    4. Compute the signature of ed25519, expected result 2
 *    5. Compare Signatures, expected result 3.
 *    6. Verify the signature of ed25519, expected result 2.
 *    7. Copy the context of ed25519, expected result 2.
 *    8. Repeat steps 4 through 6 above.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Success.
 *    3. The signature calculation result is the same as the signature vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED25519_SIGN_VERIFY_FUNC_TC001(Hex *prvKey, Hex *pubKey, Hex *msg, Hex *sign, int isProvider)
{
#ifndef HITLS_CRYPTO_ED25519
    SKIP_TEST();
#endif
    uint8_t out[CRYPT_CURVE25519_SIGNLEN] = {0};
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};

    Set_Curve25519_Pub(&pub, CRYPT_PKEY_ED25519, pubKey->x, pubKey->len);
    Set_Curve25519_Prv(&prv, CRYPT_PKEY_ED25519, prvKey->x, prvKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, msg->x, msg->len, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, sign->x, sign->len), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);

    cpyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, CRYPT_MD_SHA512, msg->x, msg->len, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, sign->x, sign->len), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, CRYPT_MD_SHA512, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_X25519_EXCH_FUNC_TC001
 * @title  X25519 key exchange test: generate key pair and key exchange.
 * @precon nan
 * @brief
 *    1. Create two contexts(pkey1, pkey2) of the ed25519 algorithm, expected result 1.
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
void SDV_CRYPTO_X25519_EXCH_FUNC_TC001(int isProvider)
{
#ifndef HITLS_CRYPTO_X25519
    SKIP_TEST();
#endif
    uint8_t share1[CRYPT_CURVE25519_KEYLEN] = {0};
    uint8_t share2[CRYPT_CURVE25519_KEYLEN] = {0};
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_X25519,
    CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_X25519,
    CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    // Sets the entropy source.
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey2, pkey1, share2, &share2Len), CRYPT_SUCCESS);
    ASSERT_EQ(share1Len, share2Len);
    ASSERT_EQ(memcmp(share1, share2, share1Len), 0);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_X25519_EXCH_FUNC_TC002
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
void SDV_CRYPTO_X25519_EXCH_FUNC_TC002(Hex *pubkey, Hex *prvkey, Hex *share, int isProvider)
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

    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_X25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_X25519,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey1, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey2, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareKey, &shareLen), CRYPT_SUCCESS);
    ASSERT_EQ(shareLen, share->len);
    ASSERT_EQ(memcmp(shareKey, share->x, shareLen), 0);

    cpyCtx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_X25519,
    CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    cpyCtx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_X25519,
    CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx1 != NULL && cpyCtx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx1, pkey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx2, pkey2), CRYPT_SUCCESS);
    shareLen = sizeof(shareKey);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(cpyCtx1, cpyCtx2, shareKey, &shareLen), CRYPT_SUCCESS);
    ASSERT_EQ(shareLen, share->len);
    ASSERT_EQ(memcmp(shareKey, share->x, shareLen), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx1);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_CMP_FUNC_TC001
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
void SDV_CRYPTO_CURVE25519_CMP_FUNC_TC001(int algId, Hex *pubKey, int isProvider)
{
    CRYPT_EAL_PkeyPub pub = {0};
    Set_Curve25519_Pub(&pub, algId, pubKey->x, pubKey->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default",
        isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default",
        isProvider);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_CURVE25519_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_CURVE25519_NO_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ED25519_KEY_PAIR_CHECK_FUNC_TC001
 * @title  Ed25519: key pair check.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(pubCtx, prvCtx) of the ed25519 algorithm, expected result 1
 *    2. Set public key for pubCtx, expected result 2
 *    3. Set private key for prvCtx, expected result 3
 *    4. Check whether the public key matches the private key, expected result 4
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. Return CRYPT_SUCCESS when expect is 1, CRYPT_CURVE25519_VERIFY_FAIL otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ED25519_KEY_PAIR_CHECK_FUNC_TC001(Hex *pubkey, Hex *prvkey, int expect, int isProvider)
{
#if !defined(HITLS_CRYPTO_ED25519_CHECK)
    (void)prvkey;
    (void)pubkey;
    (void)expect;
    (void)isProvider;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    int expectRet = expect == 1 ? CRYPT_SUCCESS : CRYPT_CURVE25519_PAIRWISE_CHECK_FAIL;

    Set_Curve25519_Prv(&prv, CRYPT_PKEY_ED25519, prvkey->x, prvkey->len);
    Set_Curve25519_Pub(&pub, CRYPT_PKEY_ED25519, pubkey->x, pubkey->len);

    TestMemInit();

    pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519, CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=default", isProvider);
    prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ED25519, CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), expectRet);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_GET_KEY_BITS_FUNC_TC001
 * @title  CURVE25519: get key bits.
 * @brief
 *    1. Create a context of the Curve25519 algorithm, expected result 1
 *    2. Get key bits, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_GET_KEY_BITS_FUNC_TC001(int id, int keyBits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(pkey) == (uint32_t)keyBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_GET_SECURITY_BITS_FUNC_TC001
 * @title  CURVE25519 CRYPT_EAL_PkeyGetSecurityBits test.
 * @precon nan
 * @brief
 *    1. Create the context of the X25519 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyGetSecurityBits Obtains secbits, expected result 2
 * @expect
 *    1. Success, and the context is not null.
 *    2. The return value is secBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_GET_SECURITY_BITS_FUNC_TC001(int id, int secBits)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetSecurityBits(pkey) == (uint32_t)secBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_KEY_PAIR_CHECK_FUNC_TC001
 * @brief  CURVE25519: key pair check.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_KEY_PAIR_CHECK_FUNC_TC001(int id, int isProvider)
{
#if !defined(HITLS_CRYPTO_ED25519_CHECK) && !defined(HITLS_CRYPTO_X25519_CHECK)
    (void)id;
    (void)isProvider;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pubCtx = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE,
        "provider=default", isProvider);
    prvCtx = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_CURVE25519_NO_PRVKEY); // no prv key and pub key.

    ASSERT_EQ(CRYPT_EAL_PkeyGen(prvCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_CURVE25519_NO_PUBKEY); // no pub key

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pubCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_CURVE25519_PAIRWISE_CHECK_FAIL);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(prvCtx, prvCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, pubCtx), CRYPT_SUCCESS);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CURVE25519_PRV_KEY_CHECK_FUNC_TC001
 * @brief CURE25519: private key check.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_PRV_KEY_CHECK_FUNC_TC001(int id, int isProvider)
{
#if !defined(HITLS_CRYPTO_ED25519_CHECK) && !defined(HITLS_CRYPTO_X25519_CHECK)
    (void)id;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_CURVE25519_Ctx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_CURVE25519_NO_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);
    ctx = (CRYPT_CURVE25519_Ctx *)pkey->key;
    (void)memset_s(ctx->prvKey, CRYPT_CURVE25519_KEYLEN, 0, CRYPT_CURVE25519_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_CURVE25519_INVALID_PRVKEY);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
static int32_t ImportCurve25519Pkey(const BSL_Param *param, void *args)
{
    CRYPT_CURVE25519_Ctx *importEd25519Ctx = CRYPT_ED25519_NewCtx();
    if (importEd25519Ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_CURVE25519_Import(importEd25519Ctx, param);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_CURVE25519_FreeCtx(importEd25519Ctx);
        return ret;
    }
    *((CRYPT_CURVE25519_Ctx **)args) = importEd25519Ctx;
    return CRYPT_SUCCESS;
}
#endif

/**
 * @test   SDV_CRYPTO_CURVE25519_Import_Export_FUNC_TC001
 * @title  CRYPT_CURVE25519_Import and CRYPT_CURVE25519_Export test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CURVE25519_Import_Export_FUNC_TC001(void)
{
#ifndef HITLS_CRYPTO_KEY_DECODE_CHAIN
    SKIP_TEST();
#else
    CRYPT_CURVE25519_Ctx *srcCurve25519Ctx = NULL;
    CRYPT_CURVE25519_Ctx *dstCurve25519Ctx = NULL;
    BSL_Param param[3] = {
        {CRYPT_PARAM_PKEY_PROCESS_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ImportCurve25519Pkey, 0, 0},
        {CRYPT_PARAM_PKEY_PROCESS_ARGS, BSL_PARAM_TYPE_CTX_PTR, &dstCurve25519Ctx, 0, 0},
        BSL_PARAM_END
    };
    uint8_t data[2] = {1};
    uint32_t dataLen = sizeof(data);
    uint8_t signBuf[CRYPT_CURVE25519_SIGNLEN] = {0};
    uint32_t signBufLen = sizeof(signBuf); 
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    srcCurve25519Ctx = CRYPT_ED25519_NewCtx();
    ASSERT_TRUE(srcCurve25519Ctx != NULL);
    ASSERT_EQ(CRYPT_ED25519_GenKey(srcCurve25519Ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CURVE25519_Export(srcCurve25519Ctx, param), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_CURVE25519_Sign(srcCurve25519Ctx, CRYPT_MD_SHA512, data, dataLen, signBuf, &signBufLen),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CURVE25519_Verify(dstCurve25519Ctx, CRYPT_MD_SHA512, data, dataLen, signBuf, signBufLen),
        CRYPT_SUCCESS);
EXIT:
    CRYPT_CURVE25519_FreeCtx(srcCurve25519Ctx);
    CRYPT_CURVE25519_FreeCtx(dstCurve25519Ctx);
#endif
}
/* END_CASE */
