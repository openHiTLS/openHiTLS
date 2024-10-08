/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */

#include <stdint.h>
#include <stdbool.h>
#include "securec.h"

#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"

#define UINT8_MAX_NUM 255
#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0
static int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
    return 0;
}

static void Set_DH_Para(
    CRYPT_EAL_PkeyPara *para, uint8_t *p, uint8_t *q, uint8_t *g, uint32_t pLen, uint32_t qLen, uint32_t gLen)
{
    para->id = CRYPT_PKEY_DH;
    para->para.dhPara.p = p;
    para->para.dhPara.q = q;
    para->para.dhPara.g = g;
    para->para.dhPara.pLen = pLen;
    para->para.dhPara.qLen = qLen;
    para->para.dhPara.gLen = gLen;
}

static void Set_DH_Prv(CRYPT_EAL_PkeyPrv *prv, uint8_t *key, uint32_t keyLen)
{
    prv->id = CRYPT_PKEY_DH;
    prv->key.dhPrv.data = key;
    prv->key.dhPrv.len = keyLen;
}

static void Set_DH_Pub(CRYPT_EAL_PkeyPub *pub, uint8_t *key, uint32_t keyLen)
{
    pub->id = CRYPT_PKEY_DH;
    pub->key.dhPub.data = key;
    pub->key.dhPub.len = keyLen;
}
/* END_HEADER */

/**
 * @test   SDV_CRYPTO_DH_PROVIDER_FUNC_TC001
 * @title  DH Key exchange vector test for the default provider.
 * @precon Registering memory-related functions.
 *         NIST test vectors.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm using the default provider, expected result 1
 *    2. Set parameters for pkey1, expected result 2
 *    3. Call the CRYPT_EAL_PkeyComputeShareKey method: pkey1(A.prvKey) and pkey2(B.pubKey), expected result 3
 *    4. Check whether the generated key is consistent with the vector, expected result 4
 *    5. Call the CRYPT_EAL_PkeyComputeShareKey method: pkey1(B.prvKey) and pkey2(A.pubKey), expected result 5
 *    6. Check whether the generated key is consistent with the vector, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. Both are consistent.
 *    5. CRYPT_SUCCESS
 *    6. Both are consistent.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_PROVIDER_FUNC_TC001(Hex *p, Hex *g, Hex *q, Hex *prv1, Hex *pub1, Hex *prv2, Hex *pub2, Hex *share)
{
    CRYPT_RandRegist(RandFunc);
    uint8_t shareLocal[1030];
    uint32_t shareLen = sizeof(shareLocal);

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prv1->x, prv1->len);
    Set_DH_Pub(&pub, pub2->x, pub2->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(shareLen == share->len);
    ASSERT_TRUE(memcmp(shareLocal, share->x, shareLen) == 0);

    Set_DH_Prv(&prv, prv2->x, prv2->len);
    Set_DH_Pub(&pub, pub1->x, pub1->len);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(shareLen == share->len);
    ASSERT_TRUE(memcmp(shareLocal, share->x, shareLen) == 0);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_DH_PROVIDER_FUNC_TC002
 * @title  DH Key exchange test: Generate key pairs for the default provider.
 * @precon Registering memory-related functions.
 *         Nist test vectors: DH parameters.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm using the default provider, expected result 1
 *    2. Set parameters for pkey1 and pkey2, expected result 2
 *    3. Generate key pairs, expected result 2
 *    4. Compute the shared key from the privite value in pkey1 and the public vlaue in peky2, expected result 2.
 *    5. Compute the shared key from the privite value in pkey2 and the public vlaue in pkey1, expected result 2.
 *    6. Compare the shared keys computed in the preceding two steps, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_PROVIDER_FUNC_TC002(Hex *p, Hex *g, Hex *q)
{
    CRYPT_RandRegist(RandFunc);
    uint8_t share1[1030];
    uint8_t share2[1030];
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey2) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey2, pkey1, share2, &share2Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(share1Len == share2Len);
    ASSERT_TRUE(memcmp(share1, share2, share1Len) == 0);
exit:
    CRYPT_RandRegist(NULL);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GET_PRV_PROVIDER_API_TC001
 * @title  DH CRYPT_EAL_PkeyGetPrv: Invalid parameter for the default provider.
 * @precon Registering memory-related functions.
 *         DH parameters and private key.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm using the default provider, expected result 1.
 *    2. Set para, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPrv method: all parameters are valid, expected result 3
 *    4. Call the CRYPT_EAL_PkeySetPrv method: all parameters are valid, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGetPrv method: prv.data=NULL, expected result 5
 *    6. Call the CRYPT_EAL_PkeyGetPrv method: prv.len < prvKeyLen, expected result 6
 *    7. Compare the setted public key with the obtained public key, expected result 7
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_DH_KEYINFO_ERROR
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_NULL_INPUT
 *    6. CRYPT_DH_BUFF_LEN_NOT_ENOUGH
 *    7. The two private keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_GET_PRV_PROVIDER_API_TC001(Hex *p, Hex *g, Hex *q, Hex *prvKey)
{
    uint8_t output[1030];
    uint32_t outLen = sizeof(output);
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, output, outLen);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prv) == CRYPT_DH_KEYINFO_ERROR);

    prv.key.dhPrv.data = prvKey->x;
    prv.key.dhPrv.len = prvKey->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_SUCCESS);

    prv.key.dhPrv.data = NULL;
    prv.key.dhPrv.len = outLen;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prv) == CRYPT_NULL_INPUT);

    prv.key.dhPrv.data = output;
    prv.key.dhPrv.len = prvKey->len - 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prv) == CRYPT_DH_BUFF_LEN_NOT_ENOUGH);

    prv.key.dhPrv.len = p->len > q->len ? p->len : q->len;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_TRUE(prv.key.dhPrv.len == prvKey->len);
    ASSERT_TRUE(memcmp(output, prvKey->x, prvKey->len) == 0);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GET_PUB_PROVIDER_API_TC001
 * @title  DH CRYPT_EAL_PkeyGetPub: Invalid parameter for the default provider.
 * @precon Registering memory-related functions.
 *         Public key.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm using the default provider, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetPub method: all parameters are valid, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPub method: all parameters are valid, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGetPub method: pub.data=NULL, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGetPub method: pub.len < pubKeyLen, expected result 5
 *    6. Compare the setted public key with the obtained public key, expected result 6.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_DH_KEYINFO_ERROR
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_DH_BUFF_LEN_NOT_ENOUGH
 *    6. The two public keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_GET_PUB_PROVIDER_API_TC001(Hex *pubKey)
{
    uint8_t output[1030];
    uint32_t outLen = sizeof(output);
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Pub(&pub, output, outLen);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pub) == CRYPT_DH_KEYINFO_ERROR);

    pub.key.dhPub.data = pubKey->x;
    pub.key.dhPub.len = pubKey->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pub) == CRYPT_SUCCESS);

    pub.key.dhPub.data = NULL;
    pub.key.dhPub.len = outLen;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pub) == CRYPT_NULL_INPUT);

    pub.key.dhPub.data = output;
    pub.key.dhPub.len = pubKey->len - 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pub) == CRYPT_DH_BUFF_LEN_NOT_ENOUGH);

    pub.key.dhPub.len = pubKey->len;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(pub.key.dhPub.len == pubKey->len);
    ASSERT_TRUE(memcmp(output, pubKey->x, pubKey->len) == 0);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_DH_DUP_CTX_PROVIDER_FUNC_TC001
 * @title  DH: CRYPT_EAL_PkeyDupCtx test for the default provider.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context of the dh algorithm using the default provider, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Set para by CRYPT_DH_RFC7919_8192 and, generate a key pair, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyDupCtx method to dup dh context, expected result 4.
 *    5. Call the CRYPT_EAL_PkeyCmp method to compare public key, expected result 5.
 *    6. Call the CRYPT_EAL_PkeyGetKeyBits to get keyLen from contexts, expected result 6.
 *    7. Call the CRYPT_EAL_PkeyGetPub method to obtain the public key from the contexts, expected result 7.
 *    8. Compare public keys, expected result 8.
 *    9. Get para id from dupCtx, expected result 9.
 * @expect
 *    1. Success, and context is not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. The key length obtained from both contexts is the same.
 *    7. CRYPT_SUCCESS
 *    8. The two public keys are the same.
 *    9. Para id is CRYPT_DH_RFC7919_8192.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_DUP_CTX_PROVIDER_FUNC_TC001(void)
{
    uint8_t *pubKey1 = NULL;
    uint8_t *pubKey2 = NULL;
    uint32_t keyLen1;
    uint32_t keyLen2;
    CRYPT_PKEY_ParaId paraId = CRYPT_DH_RFC7919_8192;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, paraId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, dupCtx), CRYPT_SUCCESS);

    keyLen1 = CRYPT_EAL_PkeyGetKeyBits(ctx);
    keyLen2 = CRYPT_EAL_PkeyGetKeyBits(dupCtx);
    ASSERT_EQ(keyLen1, keyLen2);

    pubKey1 = calloc(1u, keyLen1);
    pubKey2 = calloc(1u, keyLen2);
    ASSERT_TRUE(pubKey1 != NULL && pubKey2 != NULL);

    Set_DH_Pub(&pub, pubKey1, keyLen1);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_SUCCESS);
    Set_DH_Pub(&pub, pubKey2, keyLen2);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(dupCtx, &pub), CRYPT_SUCCESS);

    ASSERT_COMPARE("Compare dup key", pubKey1, keyLen1, pubKey2, keyLen2);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetParaId(dupCtx) == paraId);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    BSL_SAL_Free(pubKey1);
    BSL_SAL_Free(pubKey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC001
 * @title  DH CRYPT_EAL_PkeySetParaEx: Invalid parameter (NULL).
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetParaEx method: p = null, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetParaEx method: pLen = 0, expected result 2
 *    4. Call the CRYPT_EAL_PkeySetParaEx method: g = null, expected result 2
 *    5. Call the CRYPT_EAL_PkeySetParaEx method: gLen = 0, expected result 2
 *    6. Call the CRYPT_EAL_PkeySetParaEx method: q = null, qLen != 0, expected result 2
 *    7. Call the CRYPT_EAL_PkeySetParaEx method: ctx = null, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    3. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC001(Hex *p, Hex *g, Hex *q)
{
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, NULL, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);
    CRYPT_Param param;
    param.param = &para.para.dhPara;
    param.paramLen = sizeof(para.para.dhPara);
    ASSERT_TRUE_AND_LOG("p is null", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = 0;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("pLen is zero", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.pLen = p->len;
    para.para.dhPara.g = NULL;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("g is null", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.g = g->x;
    para.para.dhPara.gLen = 0;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("gLen is zero", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.gLen = g->len;
    para.para.dhPara.q = NULL;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("q is null but qLen != 0", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.q = q->x;
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(NULL, &param) == CRYPT_NULL_INPUT);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC002
 * @title  DH CRYPT_EAL_PkeySetParaEx: Invalid parameter(length).
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetParaEx method: pLen > 8192, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetParaEx method: pLen < 768, expected result 2
 *    4. Call the CRYPT_EAL_PkeySetParaEx method: pLen > 768, but actual data Len < 768, expected result 3
 *    5. Call the CRYPT_EAL_PkeySetParaEx method: qLen < 160, expected result 3
 *    6. Call the CRYPT_EAL_PkeySetParaEx method: qLen > pLen, expected result 2
 *    7. Call the CRYPT_EAL_PkeySetParaEx method: qLen > 160, but actual data Len < 160, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    3. CRYPT_DH_PARA_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC002(Hex *p, Hex *g, Hex *q)
{
    uint8_t longBuf[1030] = {0};
    uint32_t bufLen = sizeof(longBuf);
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, longBuf, q->x, g->x, bufLen, q->len, g->len);
    CRYPT_Param param;
    param.param = &para.para.dhPara;
    param.paramLen = sizeof(para.para.dhPara);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    longBuf[0] = 1;
    longBuf[1024] = 1;
    ASSERT_TRUE_AND_LOG("p greater than 8192", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = 95;  // 768 / 8 = 96, 96 - 1 = 95
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("p smaller than 768", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    (void)memset_s(longBuf, sizeof(longBuf), 0, sizeof(longBuf));
    longBuf[p->len - 1] = 1;
    para.para.dhPara.p = longBuf;
    para.para.dhPara.pLen = p->len;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("p greater than 768 but value smaller than 768 bits",
        CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = p->len;
    para.para.dhPara.qLen = 19;  // 160 / 8 = 20, 19 < 20
    para.para.dhPara.q = longBuf;
    (void)memset_s(longBuf, sizeof(longBuf), 0, sizeof(longBuf));
    longBuf[18] = 1;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("q smaller than 160", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    para.para.dhPara.qLen = p->len + 1;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("q longer than p", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    (void)memset_s(longBuf, sizeof(longBuf), 0, sizeof(longBuf));
    longBuf[20] = 1;
    para.para.dhPara.qLen = 21;
    param.param = &para.para.dhPara;
    ASSERT_TRUE_AND_LOG("q greater than 160 but value smaller than 160 bits",
        CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC003
 * @title  DH CRYPT_EAL_PkeySetParaEx: Invalid parameter (value).
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetParaEx method: p is an even number, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetParaEx method: q is an even number, expected result 2
 *    4. Call the CRYPT_EAL_PkeySetParaEx method: g=0, expected result 2
 *    5. Call the CRYPT_EAL_PkeySetParaEx method: g=1, expected result 2
 *    6. Call the CRYPT_EAL_PkeySetParaEx method: g=p-1, expected result 2
 *    7. Call the CRYPT_EAL_PkeySetParaEx method: q=p-1, expected result 2
 *    8. Call the CRYPT_EAL_PkeySetParaEx method: q=p-2, expected result 2
 *    9. Call the CRYPT_EAL_PkeySetParaEx method: q=p+2>p, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_DH_PARA_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC003(Hex *p, Hex *g, Hex *q)
{
    uint8_t buf[1030];
    uint32_t bufLen = sizeof(buf);
    CRYPT_EAL_PkeyPara para = {0};

    Set_DH_Para(&para, NULL, q->x, g->x, 0, q->len, g->len);
    CRYPT_Param param;
    param.param = &para.para.dhPara;
    param.paramLen = sizeof(para.para.dhPara);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    int last = p->len - 1;
    ASSERT_TRUE(memcpy_s(buf, bufLen, p->x, p->len) == 0);
    buf[last] += 1;  // p is even

    para.para.dhPara.p = buf;
    para.para.dhPara.pLen = p->len;
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    ASSERT_TRUE(memcpy_s(buf, bufLen, q->x, q->len) == 0);
    last = q->len - 1;
    buf[last] += 1;  // q is even
    para.para.dhPara.p = p->x;
    para.para.dhPara.q = buf;
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    (void)memset_s(buf, sizeof(buf), 0, sizeof(buf));  // g = 0
    para.para.dhPara.q = q->x;
    para.para.dhPara.g = buf;
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    last = g->len - 1;
    buf[last] = 1;  // g = 1
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    last = p->len - 1;
    para.para.dhPara.gLen = p->len;
    ASSERT_TRUE(memcpy_s(buf, bufLen, p->x, p->len) == 0);
    buf[last] -= 1;  // g = p - 1
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    // q = p - 1
    para.para.dhPara.g = g->x;
    para.para.dhPara.gLen = g->len;
    para.para.dhPara.q = buf;
    para.para.dhPara.qLen = p->len;
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    buf[last] -= 1;  // q = p - 2
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

    buf[last] += 4;  // q = p - 2 + 4 = p + 2 > p
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_DH_PARA_ERROR);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC004
 * @title  DH CRYPT_EAL_PkeySetParaEx: Repeated call.
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetParaEx method with normal parameters, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetParaEx method with normal parameters again, expected result 3
 *    4. Call the CRYPT_EAL_PkeySetParaEx method: pLen < 768, expected result 4
 *    5. Call the CRYPT_EAL_PkeySetParaEx method with normal parameters again, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARAEX_PROVIDER_API_TC004(Hex *p, Hex *g, Hex *q)
{
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    CRYPT_Param param;
    param.param = &para.para.dhPara;
    param.paramLen = sizeof(para.para.dhPara);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_DH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_SUCCESS);
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_SUCCESS);
    
    para.para.dhPara.pLen = 95;  // 768 / 8 = 96, 95 < 96
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.pLen = p->len;
    param.param = &para.para.dhPara;
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */