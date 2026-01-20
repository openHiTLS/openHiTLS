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
#include <stdbool.h>
#include "securec.h"

#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "crypt_bn.h"
#include "dh_local.h"
#include "crypt_dh.h"
#include "eal_pkey_local.h"
#include "crypt_params_key.h"

#define UINT8_MAX_NUM 255
static int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
    return 0;
}

static int32_t RandFuncEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
    return 0;
}

static int32_t RandFuncExSelfCheck(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    if (libCtx == NULL) {
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
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
 * @test   SDV_CRYPTO_DH_FUNC_TC001
 * @title  DH Key exchange vector test.
 * @precon Registering memory-related functions.
 *         NIST test vectors.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm, expected result 1
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
void SDV_CRYPTO_DH_FUNC_TC001(
    Hex *p, Hex *g, Hex *q, Hex *prv1, Hex *pub1, Hex *prv2, Hex *pub2, Hex *share, int isProvider)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t shareLocal[1030];
    uint32_t shareLen = sizeof(shareLocal);

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prv1->x, prv1->len);
    Set_DH_Pub(&pub, pub2->x, pub2->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
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
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_FUNC_TC002
 * @title  DH Key exchange test: Generate key pairs.
 * @precon Registering memory-related functions.
 *         Nist test vectors: DH parameters.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm, expected result 1
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
void SDV_CRYPTO_DH_FUNC_TC002(Hex *p, Hex *g, Hex *q, int isProvider)
{
    CRYPT_RandRegist(RandFunc);
    if (isProvider) {
        CRYPT_RandRegistEx(RandFuncExSelfCheck);
    } else {
        CRYPT_RandRegistEx(RandFuncEx);
    }
    uint8_t share1[1030];
    uint8_t share2[1030];
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey2) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey2, pkey1, share2, &share2Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(share1Len == share2Len);
    ASSERT_TRUE(memcmp(share1, share2, share1Len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_FUNC_TC003
 * @title  DH Key exchange test: Set parameters based on the ID to generate key pairs.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm, expected result 1
 *    2. Set parameters byt id for pkey1 and pkey2, expected result 2
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
void SDV_CRYPTO_DH_FUNC_TC003(int id, int isProvider)
{
    uint8_t share1[1030];
    uint8_t share2[1030];
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(pkey1, id) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(pkey2, id) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey2) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey2, pkey1, share2, &share2Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(share1Len == share2Len);
    ASSERT_TRUE(memcmp(share1, share2, share1Len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_FUNC_TC004
 * @title  DH Key exchange test: Generate a key pair repeatedly.
 * @precon Registering memory-related functions.
 *         Nist test vectors: DH parameters.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm, expected result 1
 *    2. Set parameters for pkey1 and pkey2, expected result 2
 *    3. Generate a key pair repeatedly, expected result 2
 *    4. Compute the shared key from the privite value in pkey1 and the public vlaue in peky2, expected result 2.
 *    5. Compute the shared key from the privite value in pkey2 and the public vlaue in pkey1, expected result 2.
 *    6. Compare the shared keys computed in the preceding two steps, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_FUNC_TC004(Hex *p, Hex *g, Hex *q, int isProvider)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t share1[1030];
    uint8_t share2[1030];
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey2) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey2, pkey1, share2, &share2Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(share1Len == share2Len);
    ASSERT_TRUE(memcmp(share1, share2, share1Len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_FUNC_TC005
 * @title  DH Key exchange failed. The public key is invalid.
 * @precon Registering memory-related functions.
 *         Nist test vectors: DH parameters, private key, public key.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm, expected result 1.
 *    2. Set parameters for pkey1, expected result 2
 *    3. Call the CRYPT_EAL_PkeyComputeShareKey method:
 *       (1) pkey1(valid prvKey), pkey2(pubKey = p - 1), expected result 3
 *       (2) pkey1(valid prvKey), pkey2(pubKey ^ q mod p != 1), expected result 3
 *       (3) pkey1(valid prvKey), pkey2(pubKey = 0), expected result 3
 *       (4) pkey1(valid prvKey), pkey2(pubKey = 1), expected result 3
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_DH_KEYINFO_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_FUNC_TC005(Hex *p, Hex *g, Hex *q, Hex *prv1, int isProvider)
{
    uint8_t shareLocal[1030];
    uint32_t shareLen = sizeof(shareLocal);

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    uint8_t *tmpPub = (uint8_t *)malloc(sizeof(uint8_t) * p->len);
    ASSERT_TRUE(tmpPub != NULL);
    ASSERT_TRUE(memcpy_s(tmpPub, p->len, p->x, p->len) == 0);
    int last = p->len - 1;
    tmpPub[last] -= 1;  // pubKey = p - 1

    Set_DH_Prv(&prv, prv1->x, prv1->len);
    Set_DH_Pub(&pub, tmpPub, p->len);
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen), CRYPT_DH_KEYINFO_ERROR);

    ASSERT_TRUE(memset_s(tmpPub, p->len, 0, p->len) == 0);  // pubKey = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen), CRYPT_DH_KEYINFO_ERROR);

    tmpPub[last] = 1;  // pubKey = 1
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen), CRYPT_DH_KEYINFO_ERROR);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    if (tmpPub != NULL) {
        free(tmpPub);
    }
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_FUNC_TC006
 * @title  Key exchange failure vector test, invalid vector.
 * @precon Registering memory-related functions.
 *         NIST test vectors.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm, expected result 1.
 *    2. Set parameters for pkey1, expected result 2
 *    3. Call the CRYPT_EAL_PkeyComputeShareKey method: pkey1(A.prvKey) and pkey2(B.pubKey)
 *    4. Check whether the generated shared key is consistent with the vector
 *    5. Call the CRYPT_EAL_PkeyComputeShareKey method: pkey1(B.prvKey) and pkey2(A.pubKey)
 *    6. Check whether the generated key is consistent with the vector
 *    7. Check the values returned in steps 3 to 6, expected result 3
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_SUCCESS
 *    3. At least one failure or the generated key and vector are not equal.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_FUNC_TC006(
    Hex *p, Hex *g, Hex *q, Hex *prv1, Hex *pub1, Hex *prv2, Hex *pub2, Hex *share, int isProvider)
{
    uint8_t shareLocal[1030];
    uint32_t shareLen = sizeof(shareLocal);
    int ret1, ret2;
    int cmpRet1, cmpRet2;

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prv1->x, prv1->len);
    Set_DH_Pub(&pub, pub2->x, pub2->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ret1 = CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen);
    cmpRet1 = memcmp(shareLocal, share->x, share->len);

    Set_DH_Prv(&prv, prv2->x, prv2->len);
    Set_DH_Pub(&pub, pub1->x, pub1->len);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ret2 = CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen);

    ret2 = CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen);
    cmpRet2 = memcmp(shareLocal, share->x, share->len);

    ASSERT_TRUE(ret1 != CRYPT_SUCCESS || cmpRet1 != 0 || ret2 != CRYPT_SUCCESS || cmpRet2 != 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARA_API_TC001
 * @title  DH CRYPT_EAL_PkeySetPara: Invalid parameter (NULL).
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method: p = null, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPara method: pLen = 0, expected result 2
 *    4. Call the CRYPT_EAL_PkeySetPara method: g = null, expected result 2
 *    5. Call the CRYPT_EAL_PkeySetPara method: gLen = 0, expected result 2
 *    6. Call the CRYPT_EAL_PkeySetPara method: q = null, qLen != 0, expected result 2
 *    7. Call the CRYPT_EAL_PkeySetPara method: ctx = null, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    3. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARA_API_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, NULL, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE_AND_LOG("p is null", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = 0;
    ASSERT_TRUE_AND_LOG("pLen is zero", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.pLen = p->len;
    para.para.dhPara.g = NULL;
    ASSERT_TRUE_AND_LOG("g is null", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.g = g->x;
    para.para.dhPara.gLen = 0;
    ASSERT_TRUE_AND_LOG("gLen is zero", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.gLen = g->len;
    para.para.dhPara.q = NULL;
    ASSERT_TRUE_AND_LOG("q is null but qLen != 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.q = q->x;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(NULL, &para) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARA_API_TC002
 * @title  DH CRYPT_EAL_PkeySetPara: Invalid parameter(length).
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method: pLen > 8192, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPara method: pLen < 768, expected result 2
 *    4. Call the CRYPT_EAL_PkeySetPara method: pLen > 768, but actual data Len < 768, expected result 3
 *    5. Call the CRYPT_EAL_PkeySetPara method: qLen < 160, expected result 3
 *    6. Call the CRYPT_EAL_PkeySetPara method: qLen > pLen, expected result 2
 *    7. Call the CRYPT_EAL_PkeySetPara method: qLen > 160, but actual data Len < 160, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    3. CRYPT_DH_PARA_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARA_API_TC002(Hex *p, Hex *g, Hex *q, int isProvider)
{
    uint8_t longBuf[1030] = {0};
    uint32_t bufLen = sizeof(longBuf);
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, longBuf, q->x, g->x, bufLen, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    longBuf[0] = 1;
    longBuf[1024] = 1;

    ASSERT_TRUE_AND_LOG("p greater than 8192", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = 95;  // 768 / 8 = 96, 96 - 1 = 95
    ASSERT_TRUE_AND_LOG("p smaller than 768", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    (void)memset_s(longBuf, sizeof(longBuf), 0, sizeof(longBuf));
    longBuf[p->len - 1] = 1;
    para.para.dhPara.p = longBuf;
    para.para.dhPara.pLen = p->len;
    ASSERT_TRUE_AND_LOG("p greater than 768 but value smaller than 768 bits",
        CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = p->len;
    para.para.dhPara.qLen = 19;  // 160 / 8 = 20, 19 < 20
    para.para.dhPara.q = longBuf;
    (void)memset_s(longBuf, sizeof(longBuf), 0, sizeof(longBuf));
    longBuf[18] = 1;
    ASSERT_TRUE_AND_LOG("q smaller than 160", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    para.para.dhPara.qLen = p->len + 1;
    ASSERT_TRUE_AND_LOG("q longer than p", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    (void)memset_s(longBuf, sizeof(longBuf), 0, sizeof(longBuf));
    longBuf[20] = 1;
    para.para.dhPara.qLen = 21;
    ASSERT_TRUE_AND_LOG("q greater than 160 but value smaller than 160 bits",
        CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARA_API_TC003
 * @title  DH CRYPT_EAL_PkeySetPara: Invalid parameter (value).
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method: p is an even number, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPara method: q is an even number, expected result 2
 *    4. Call the CRYPT_EAL_PkeySetPara method: g=0, expected result 2
 *    5. Call the CRYPT_EAL_PkeySetPara method: g=1, expected result 2
 *    6. Call the CRYPT_EAL_PkeySetPara method: g=p-1, expected result 2
 *    7. Call the CRYPT_EAL_PkeySetPara method: q=p-1, expected result 2
 *    8. Call the CRYPT_EAL_PkeySetPara method: q=p-2, expected result 2
 *    9. Call the CRYPT_EAL_PkeySetPara method: q=p+2>p, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_DH_PARA_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARA_API_TC003(Hex *p, Hex *g, Hex *q, int isProvider)
{
    uint8_t buf[1030];
    uint32_t bufLen = sizeof(buf);
    CRYPT_EAL_PkeyPara para = {0};

    Set_DH_Para(&para, NULL, q->x, g->x, 0, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    int last = p->len - 1;
    ASSERT_TRUE(memcpy_s(buf, bufLen, p->x, p->len) == 0);
    buf[last] += 1;  // p is even

    para.para.dhPara.p = buf;
    para.para.dhPara.pLen = p->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    ASSERT_TRUE(memcpy_s(buf, bufLen, q->x, q->len) == 0);
    last = q->len - 1;
    buf[last] += 1;  // q is even
    para.para.dhPara.p = p->x;
    para.para.dhPara.q = buf;

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    (void)memset_s(buf, sizeof(buf), 0, sizeof(buf));  // g = 0
    para.para.dhPara.q = q->x;
    para.para.dhPara.g = buf;

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    last = g->len - 1;
    buf[last] = 1;  // g = 1
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    last = p->len - 1;
    para.para.dhPara.gLen = p->len;
    ASSERT_TRUE(memcpy_s(buf, bufLen, p->x, p->len) == 0);
    buf[last] -= 1;  // g = p - 1
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    // q = p - 1
    para.para.dhPara.g = g->x;
    para.para.dhPara.gLen = g->len;
    para.para.dhPara.q = buf;
    para.para.dhPara.qLen = p->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    buf[last] -= 1;  // q = p - 2
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

    buf[last] += 4;  // q = p - 2 + 4 = p + 2 > p
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_DH_PARA_ERROR);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARA_API_TC004
 * @title  DH CRYPT_EAL_PkeySetPara: Repeated call.
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method with normal parameters, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPara method with normal parameters again, expected result 3
 *    4. Call the CRYPT_EAL_PkeySetPara method: pLen < 768, expected result 4
 *    5. Call the CRYPT_EAL_PkeySetPara method with normal parameters again, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARA_API_TC004(Hex *p, Hex *g, Hex *q, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    para.para.dhPara.pLen = 95;  // 768 / 8 = 96, 95 < 96

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.dhPara.pLen = p->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PRV_API_TC001
 * @title  DH: CRYPT_EAL_PkeySetPrv test.
 * @precon Registering memory-related functions.
 *         DH parameters and private key.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPrv method before CRYPT_EAL_PkeySetPara, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPara method to set para, expected result 3
 *    4. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1). pkey = NULL, expected result 4.
 *       (2). prv = NULL, expected result 4.
 *       (3). prv.data = NULL, expected result 4.
 *       (4). prv.len = 0, expected result 4.
 *       (5). prv.id != pkey.id, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_DH_PARA_ERROR
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PRV_API_TC001(Hex *p, Hex *g, Hex *q, Hex *prvKey, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prvKey->x, prvKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_DH_PARA_ERROR);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(NULL, &prv) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, NULL) == CRYPT_NULL_INPUT);

    prv.key.dhPrv.data = NULL;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_NULL_INPUT);

    prv.key.dhPrv.data = prvKey->x;
    prv.key.dhPrv.len = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PRV_API_TC002
 * @title  DH: CRYPT_EAL_PkeySetPrv test. Boundary value test for the private key.
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method to set para(q = NULL), expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) prvKey = p - 1, expected result 3
 *       (2) prvKey = p - 2, expected result 4
 *    4. Call the CRYPT_EAL_PkeySetPara method to set para(q != NULL), expected result 5
 *    5. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) prvKey = q, expected result 6
 *       (1) prvKey = 0, expected result 7
 *       (1) prvKey = 1, expected result 8
 *       (1) prvKey = q - 1, expected result 9
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_DH_KEYINFO_ERROR
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_DH_KEYINFO_ERROR
 *    7. CRYPT_SUCCESS
 *    8. CRYPT_DH_KEYINFO_ERROR
 *    9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PRV_API_TC002(Hex *p, Hex *g, Hex *q, int isProvider)
{
    uint8_t *tmpPrv = NULL;
    int last;
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, NULL, g->x, p->len, 0, g->len);

    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = CRYPT_PKEY_DH;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    tmpPrv = (uint8_t *)malloc(sizeof(uint8_t) * p->len);
    ASSERT_TRUE(memcpy_s(tmpPrv, p->len, p->x, p->len) == 0);
    last = p->len - 1;
    tmpPrv[last] -= 1;  // tmpPrv = p - 1, Vectors are guaranteed not to wrap around.

    prv.key.dhPrv.data = tmpPrv;
    prv.key.dhPrv.len = p->len;

    ASSERT_TRUE_AND_LOG("prvKey = p - 1", CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_DH_KEYINFO_ERROR);

    tmpPrv[last] -= 1;  // tmpPrv = p - 2, Vectors are guaranteed not to wrap around.
    ASSERT_TRUE_AND_LOG("prvKey = p - 2", CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_SUCCESS);

    para.para.dhPara.q = q->x;
    para.para.dhPara.qLen = q->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    /* In normal para, p>q does not exceed the threshold. */
    ASSERT_TRUE(memcpy_s(tmpPrv, p->len, q->x, q->len) == 0);
    prv.key.dhPrv.len = q->len;
    ASSERT_TRUE_AND_LOG("prvKey = q", CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_DH_KEYINFO_ERROR);

    last = q->len - 1;
    tmpPrv[last] -= 1;
    ASSERT_TRUE_AND_LOG("prvKey = q - 1", CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_SUCCESS);

    (void)memset_s(tmpPrv, p->len, 0, p->len);
    ASSERT_TRUE_AND_LOG("prvKey = 0", CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_DH_KEYINFO_ERROR);

    last = q->len - 1;
    tmpPrv[last] = 1;
    ASSERT_TRUE_AND_LOG("prvKey = 1", CRYPT_EAL_PkeySetPrv(pkey, &prv) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    if (tmpPrv != NULL) {
        free(tmpPrv);
    }
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PUB_API_TC001
 * @title  DH CRYPT_EAL_PkeySetPub: Invalid parameter(NULL).
 * @precon Registering memory-related functions.
 *         Public key.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPub method:
 *       (1) pkey = null, expected result 2
 *       (2) pubKey = null, expected result 2
 *       (3) pubKeyLen = 0, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PUB_API_TC001(Hex *pubKey, int isProvider)
{
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Pub(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(NULL, &pub) == CRYPT_NULL_INPUT);

    pub.key.dhPub.data = NULL;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pub) == CRYPT_NULL_INPUT);

    pub.key.dhPub.data = pubKey->x;
    pub.key.dhPub.len = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pub) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PUB_API_TC002
 * @title  DH CRYPT_EAL_PkeySetPub: Invalid parameter(Overlong public key).
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPub method:
 *       (1) pub array Len > 8192, actual Len > 8192, expected result 2
 *       (2) pub array Len > 8192, actual Len < 8192, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_DH_KEYINFO_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PUB_API_TC002(int isProvider)
{
    uint8_t pubKey[1025] = {0};  // 8192/8 + 1 = 1025
    uint32_t pubLen = sizeof(pubKey);
    pubKey[0] = 1;
    pubKey[1024] = 5;  // 1024 is last block
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Pub(&pub, pubKey, pubLen);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pub) == CRYPT_DH_KEYINFO_ERROR);

    pubKey[0] = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pub) == CRYPT_DH_KEYINFO_ERROR);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GET_PRV_API_TC001
 * @title  DH CRYPT_EAL_PkeyGetPrv: Invalid parameter.
 * @precon Registering memory-related functions.
 *         DH parameters and private key.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
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
void SDV_CRYPTO_DH_GET_PRV_API_TC001(Hex *p, Hex *g, Hex *q, Hex *prvKey, int isProvider)
{
    uint8_t output[1030];
    uint32_t outLen = sizeof(output);
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, output, outLen);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
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

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GET_PUB_API_TC001
 * @title  DH CRYPT_EAL_PkeyGetPub: Invalid parameter.
 * @precon Registering memory-related functions.
 *         Public key.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
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
void SDV_CRYPTO_DH_GET_PUB_API_TC001(Hex *p, Hex *g, Hex *q, Hex *pubKey, int isProvider)
{
    uint8_t output[1030];
    uint32_t outLen = sizeof(output);
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Pub(&pub, output, outLen);
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pub) == CRYPT_DH_PARA_ERROR);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

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

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GET_KEY_LEN_API_TC001
 * @title  CRYPT_EAL_PkeyGetKeyLen test.
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetKeyLen, expected result 2
 *    3. Set para, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGetKeyLen, expected result 4
 * @expect
 *    1. Success, and context is not NULL.
 *    2. 0 is returned because the parameter is not set.
 *    3. CRYPT_SUCCESS
 *    4. The obtained length is equal to p->len.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_GET_KEY_LEN_API_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(pkey), 0);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(pkey), p->len);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GEN_API_TC001
 * @title  DH CRYPT_EAL_PkeyGen test.
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGen method: pkey = NULL, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGen method: pkey != NULL, expected result 3
 *    4. Set para, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGen method: pkey != NULL, expected result 5
 *    6. Initializes the random number, expected result 6
 *    7. Call the CRYPT_EAL_PkeyGen method: pkey != NULL, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_DH_PARA_ERROR
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_NO_REGIST_RAND
 *    6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_GEN_API_TC001(Hex *p, Hex *g, Hex *q)
{
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(NULL) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_DH_PARA_ERROR);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_NO_REGIST_RAND);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_SET_PARA_BY_ID_API_TC001
 * @title  DH CRYPT_EAL_PkeySetParaById test: invalid pkey or wrong ID.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context(pkey) of the dh algorithm, expected result 1
 *    2. Call the PkeySetParaById method: pkey = NULL, expected result 2
 *    3. Call the PkeySetParaById method: invalid id, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_ERR_NEW_PARA_FAIL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_SET_PARA_BY_ID_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(NULL, CRYPT_DH_RFC3526_2048) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(pkey, 100) == CRYPT_EAL_ERR_NEW_PARA_FAIL);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_EXCH_API_TC001
 * @title  DH CRYPT_EAL_PkeyComputeShareKey test: Invalid parameter(NULL).
 * @precon Registering memory-related functions.
 *         DH vectors.
 * @brief
 *    1. Create two contexts(pkey1, pkey2) of the dh algorithm, expected result 1
 *    2. Set the correct public key for pkey2, expected result 2
 *    3. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 3
 *    4. Set the correct para and private key for pkey1, expected result 4
 *    5. Call the CRYPT_EAL_PkeyComputeShareKey method: pkey=null, expected result 5
 *    6. Call the CRYPT_EAL_PkeyComputeShareKey method: pubKey=null, expected result 5
 *    7. Call the CRYPT_EAL_PkeyComputeShareKey method: share=null, expected result 5
 *    8. Call the CRYPT_EAL_PkeyComputeShareKey method: shareLen=null, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_DH_PARA_ERROR
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_EXCH_API_TC001(Hex *p, Hex *g, Hex *q, Hex *pubKey, Hex *prvKey, int isProvider)
{
    uint8_t share[1030];
    uint32_t shareLen = sizeof(share);
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prvKey->x, prvKey->len);
    Set_DH_Pub(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share, &shareLen) == CRYPT_DH_PARA_ERROR);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(NULL, pkey2, share, &shareLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, NULL, share, &shareLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, NULL, &shareLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, (uint8_t *)share, NULL) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_EXCH_API_TC002
 * @title  DH CRYPT_EAL_PkeyComputeShareKey test: Invalid parameter(The public key or private key is missing).
 * @precon Registering memory-related functions.
 *         DH vectors.
 * @brief
 *    1. Create the contexts of the dh algorithm, expected result 1.
 *    2. Set the correct para, expected result 2
 *    3. Call the CRYPT_EAL_PkeyComputeShareKey method: no private key, expected result 3
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method: no public key, expected result 4
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_DH_KEYINFO_ERROR
 *    4. CRYPT_DH_KEYINFO_ERROR
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_EXCH_API_TC002(Hex *p, Hex *g, Hex *q, Hex *pubKey, Hex *prvKey, int isProvider)
{
    uint8_t share[1030];
    uint32_t shareLen = sizeof(share);

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prvKey->x, prvKey->len);
    Set_DH_Pub(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey3 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL && pkey3 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey3, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share, &shareLen) == CRYPT_DH_KEYINFO_ERROR);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey3, pkey2, share, &shareLen) == CRYPT_DH_KEYINFO_ERROR);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    CRYPT_EAL_PkeyFreeCtx(pkey3);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_EXCH_API_TC003
 * @title  DH CRYPT_EAL_PkeyComputeShareKey test: Invalid parameter(The length of the output parameter is insufficient).
 * @precon Registering memory-related functions.
 *         DH vectors.
 * @brief
 *    1. Create the contexts of the dh algorithm, expected result 1.
 *    2. Set the correct para and keys, expected result 2
 *    3. Call the CRYPT_EAL_PkeyComputeShareKey method: shareLen=keyLen-1, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_DH_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_EXCH_API_TC003(Hex *p, Hex *g, Hex *q, Hex *pubKey, Hex *prvKey, int isProvider)
{
    uint8_t share[1030];
    uint32_t shareLen;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prvKey->x, prvKey->len);
    Set_DH_Pub(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);

    shareLen = CRYPT_EAL_PkeyGetKeyLen(pkey1) - 1;

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, (uint8_t *)share, &shareLen), CRYPT_DH_BUFF_LEN_NOT_ENOUGH);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GET_PARA_API_TC001
 * @title  DH CRYPT_EAL_PkeyGetPara test.
 * @precon Registering memory-related functions.
 *         DH parameters.
 * @brief
 *    1. Create the contexts of the dh algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeySetPara method with correct parameters, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPara method: para.id != pkey.id, expected result 3
 *    4. Call the CRYPT_EAL_PkeySetPara method: pkey=NULL or para=NULL, expected result 4
 *    5. Call the CRYPT_EAL_PkeySetPara method with correct parameters, expected result 5
 *    6. Check whether the configured parameters are the same as the obtained parameters, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_EAL_ERR_ALGID
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_SUCCESS
 *    6. Parameters are equal.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_GET_PARA_API_TC001(Hex *p, Hex *q, Hex *g, int isProvider)
{
    uint8_t buf_p[1030] = {0};
    uint32_t bufLen = sizeof(buf_p);
    uint8_t buf_q[1030] = {0};
    uint8_t buf_g[1030] = {0};

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPara para2 = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Para(&para2, buf_p, buf_q, buf_g, bufLen, bufLen, bufLen);
    para2.id = CRYPT_PKEY_RSA;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pKey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pKey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pKey, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(pKey, &para2) == CRYPT_EAL_ERR_ALGID);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(NULL, &para2) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(pKey, NULL) == CRYPT_NULL_INPUT);

    para2.id = CRYPT_PKEY_DH;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(pKey, &para2) == CRYPT_SUCCESS);
    ASSERT_TRUE(para.para.dhPara.pLen == para2.para.dhPara.pLen);
    ASSERT_TRUE(memcmp(para.para.dhPara.p, para2.para.dhPara.p, para.para.dhPara.pLen) == 0);
    ASSERT_TRUE(para.para.dhPara.qLen == para2.para.dhPara.qLen);
    ASSERT_TRUE(memcmp(para.para.dhPara.q, para2.para.dhPara.q, para.para.dhPara.qLen) == 0);
    ASSERT_TRUE(para.para.dhPara.gLen == para2.para.dhPara.gLen);
    ASSERT_TRUE(memcmp(para.para.dhPara.g, para2.para.dhPara.g, para.para.dhPara.gLen) == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pKey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_DH_CMP_API_TC001
 * @title  DH: CRYPT_EAL_PkeyCmp invalid parameter test.
 * @precon Registering memory-related functions.
 *         para id and public key.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the dh algorithm, expected result 1
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
void SDV_CRYPTO_DH_CMP_API_TC001(int paraId, Hex *pubKey, int isProvider)
{
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Pub(&pub, pubKey->x, pubKey->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_DH_KEYINFO_ERROR);  // no key and no para

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx1, paraId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_DH_KEYINFO_ERROR);  // ctx2 no pubkey

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_DH_PARA_ERROR);  // ctx2 no para

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_CTRL_API_TC001
 * @title  DH: CRYPT_EAL_PkeyCtrl test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context(ctx) of the dh algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl method:
 *       (1) val = NULL, expected result 2
 *       (2) len = 0, expected result 3
 *       (3) opt = CRYPT_CTRL_SET_RSA_PADDING, expected result 4
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_DH_UNSUPPORTED_CTRL_OPTION
 *    4. CRYPT_DH_UNSUPPORTED_CTRL_OPTION
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_CTRL_API_TC001(int isProvider)
{
    int32_t ref = 1;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_UP_REFERENCES, NULL, sizeof(uint32_t)), BSL_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_UP_REFERENCES, &ref, 0), BSL_INVALID_ARG);
    ASSERT_EQ(
        CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, &ref, sizeof(int32_t)), CRYPT_DH_UNSUPPORTED_CTRL_OPTION);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_DH_DUP_CTX_FUNC_TC001
 * @title  DH: CRYPT_EAL_PkeyDupCtx test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context of the dh algorithm, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Set para by CRYPT_DH_RFC7919_8192 and, generate a key pair, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyDupCtx method to dup dh context, expected result 4.
 *    5. Call the CRYPT_EAL_PkeyCmp method to compare public key, expected result 5.
 *    6. Call the CRYPT_EAL_PkeyGetKeyBits to get keyLen from contexts, expected result 6.
 *    7. Call the CRYPT_EAL_PkeyGetPub method to obtain the public key from the contexts, expected result 7.
 *    8. Compare public keys, expected result 8.
 *    9. Get para id from dupCtx, expected result 9.
 *    10. Call the CRYPT_EAL_PkeyComputeShareKey method to compute the shared key from the dupCtx and ctx,
 *      expected result 10.
 * @expect
 *    1. Success, and context is not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. The key length obtained from both contexts is the same.
 *    7. CRYPT_SUCCESS
 *    8. The two public keys are the same.
 *    9. Para id is CRYPT_DH_RFC7919_8192.
 *    10. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_DUP_CTX_FUNC_TC001(int isProvider)
{
    uint8_t *pubKey1 = NULL;
    uint8_t *pubKey2 = NULL;
    uint32_t keyLen1;
    uint32_t keyLen2;
    CRYPT_PKEY_ParaId paraId = CRYPT_DH_RFC7919_8192;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    uint8_t share1[1030];
    uint8_t share2[1030];
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    TestMemInit();

    ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
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

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx, dupCtx, share1, &share1Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(dupCtx, ctx, share2, &share2Len) == CRYPT_SUCCESS);
    ASSERT_TRUE(share1Len == share2Len);
    ASSERT_TRUE(memcmp(share1, share2, share1Len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    BSL_SAL_Free(pubKey1);
    BSL_SAL_Free(pubKey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_GET_KEY_BITS_FUNC_TC001
 * @title  DH: get key bits.
 * @brief
 *    1. Create a context of the DH algorithm, expected result 1
 *    2. Get key bits, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_GET_KEY_BITS_FUNC_TC001(int id, int keyBits, Hex *p, Hex *g, Hex *q, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    CRYPT_EAL_PkeyPara para;
    para.id = id;
    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = p->len;
    para.para.dhPara.q = q->x;
    para.para.dhPara.qLen = q->len;
    para.para.dhPara.g = g->x;
    para.para.dhPara.gLen = g->len;

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(pkey) == (uint32_t)keyBits);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_TEST_FLAG_SET_TC002
 * @title  for test dh flag setting no leading flag.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_TEST_FLAG_SET_TC001(Hex *p, Hex *g, Hex *q, Hex *prv1, Hex *pub2, Hex *share, int isProvider)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t shareLocal[1030];
    uint32_t shareLen = sizeof(shareLocal);
    uint32_t flag = CRYPT_DH_NO_PADZERO;

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    Set_DH_Prv(&prv, prv1->x, prv1->len);
    Set_DH_Pub(&pub, pub2->x, pub2->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_DH_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(shareLen == share->len - 1); // The highest bit of this vector is 0
    ASSERT_TRUE(memcmp(shareLocal, share->x + 1, shareLen) == 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_CHECK_KEYPAIR_TC001
 * @brief
 *   Create a dh key pairs to check the key pair consistency.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_CHECK_KEYPAIR_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
#if !defined(HITLS_CRYPTO_DH_CHECK)
    (void)p;
    (void)g;
    (void)q;
    (void)isProvider;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pkey, pkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_CHECK_KEYPAIR_TC002
 * @brief
 *   Create a dh key pairs to check the key pair consistency.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_CHECK_KEYPAIR_TC002(int id, int isProvider)
{
#if !defined(HITLS_CRYPTO_DH_CHECK)
    (void)id;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(pkey, id) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pkey, pkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_CHECK_KEYPAIR_INVALIED_TC001
 * @brief
 *   Create a dh key pairs to check the key pair consistency.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_CHECK_KEYPAIR_INVALIED_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
#if !defined(HITLS_CRYPTO_DH_CHECK)
    (void)p;
    (void)g;
    (void)q;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    uint8_t pubKey[1030];
    uint32_t pubKeyLen = sizeof(pubKey);
    uint8_t prvKey[1030];
    uint32_t prvKeyLen = sizeof(prvKey);
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_DH_Pub(&pub, pubKey, pubKeyLen);
    Set_DH_Prv(&prv, prvKey, prvKeyLen);
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_TRUE(pubCtx != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pubCtx, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(prvCtx, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS); // get prv and pub
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(NULL, NULL) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pubCtx, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx) == CRYPT_NULL_INPUT); // no prv key
    TestErrClear();

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(prvCtx, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pubCtx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx) == CRYPT_DH_PAIRWISE_CHECK_FAIL);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_CHECK_PRV_TC001
 * @brief
 *   Create a dh key pairs to check the prv key.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_CHECK_PRV_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
#if !defined(HITLS_CRYPTO_DH_CHECK)
    (void)p;
    (void)g;
    (void)q;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    int32_t bits;
    CRYPT_EAL_PkeyPara para = {0};
    Set_DH_Para(&para, p->x, q->x, g->x, p->len, q->len, g->len);
    BN_BigNum *x = NULL;
    CRYPT_DH_Ctx *ctx = NULL;
    BN_BigNum *maxValue = NULL;

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS); // get prv and pub
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ctx = (CRYPT_DH_Ctx *)pkey->key;
    x = ctx->x;
    if (q->len != 0) {
        ctx->x = ctx->para->q;
        ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_DH_INVALID_PRVKEY);
    } else {
        maxValue = BN_Create(0);
        bits = BN_Bits(ctx->para->p);
        ASSERT_EQ(BN_SetLimb(maxValue, 1), CRYPT_SUCCESS);
        BN_Lshift(maxValue, maxValue, bits);
        ctx->x = maxValue;
        ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_DH_INVALID_PRVKEY);
    }
    ctx->x = x;
EXIT:
    BN_Destroy(maxValue);
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DH_FUNC_TC001
 * @title  DH Key exchange vector test.
 * @precon Registering memory-related functions.
 *         NIST test vectors.
 * @brief
 *    1. Create the contexts(pkey1, pkey2) of the dh algorithm, expected result 1
 *    2. Set parameters with no info for pkey1, expected result 2
 *    3. Set parameters with p,p,g info for pkey1, expected result 2
 *    3. Call the CRYPT_EAL_PkeyComputeShareKey method: pkey1(A.prvKey) and pkey2(B.pubKey), expected result 3
 *    4. Check whether the generated key is consistent with the vector, expected result 4
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. Both are consistent.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DH_FUNC_SET_PARAM_EX_TC001(Hex *p, Hex *g, Hex *q, Hex *prvBuf, Hex *pubBuf, Hex *share, int isProvider)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)p;
    (void)q;
    (void)g;
    (void)prvBuf;
    (void)pubBuf;
    (void)share;
    (void)isProvider;
    SKIP_TEST();
#else
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t shareLocal[1030];
    uint32_t shareLen = sizeof(shareLocal);
    
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DH_Prv(&prv, prvBuf->x, prvBuf->len);
    Set_DH_Pub(&pub, pubBuf->x, pubBuf->len);
    
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
     CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DH,
     CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);
    
    BSL_Param param[4] = {0};
    // If no param is set, the setEx is also success
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey1, param) == CRYPT_SUCCESS);
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_DH_P, BSL_PARAM_TYPE_OCTETS, p->x, p->len);
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_DH_Q, BSL_PARAM_TYPE_OCTETS, q->x, q->len);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_DH_G, BSL_PARAM_TYPE_OCTETS, g->x, g->len);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(pkey1, param) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, shareLocal, &shareLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(shareLen == share->len);
    ASSERT_TRUE(memcmp(shareLocal, share->x, shareLen) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
#endif
}
/* END_CASE */
