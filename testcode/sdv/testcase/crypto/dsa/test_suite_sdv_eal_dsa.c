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
#include <pthread.h>
#include "securec.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_dsa.h"
#include "dsa_local.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "stub_utils.h"
#include "crypt_util_rand.h"

#include "crypt_encode.h"
#include "crypt_eal_md.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, BN_RandRangeEx, void *, BN_BigNum *, const BN_BigNum *);
STUB_DEFINE_RET3(int32_t, CRYPT_EAL_RandbytesEx, CRYPT_EAL_LibCtx *, uint8_t *, uint32_t);

/* ============================================================================
 * Constants and Helper Functions
 * ============================================================================ */
#define SUCCESS 0
#define ERROR (-1)
#define BITS_OF_BYTE 8
static uint8_t g_kRandBuf[64];
static uint32_t g_kRandBufLen = 0;


extern int32_t CryptDsaFips1864GenPq(CRYPT_DSA_Ctx *ctx, DSA_FIPS186_4_Para *fipsPara, uint32_t type,
    BSL_Buffer *seed, uint32_t *counter);
extern int32_t CryptDsaFips1864ValidatePq(int32_t algId, void *libCtx, const char *mdAttr, uint32_t type,
    BSL_Buffer *seed, CRYPT_DSA_Para *dsaPara, uint32_t counter);
extern int32_t CryptDsaFips1864GenUnverifiableG(CRYPT_DSA_Para *dsaPara, uint64_t *hRet);
extern int32_t CryptDsaFips1864GenVerifiableG(void *libCtx, const char *mdAttr, DSA_FIPS186_4_Para *fipsPara, BSL_Buffer *seed, CRYPT_DSA_Para *dsaPara);
extern int32_t CryptDsaFips1864PartialValidateG(const CRYPT_DSA_Para *dsaPara);
extern int32_t CryptDsaFips1864ValidateG(void *libCtx, const char *mdAttr, DSA_FIPS186_4_Para *fipsPara, BSL_Buffer *seed, CRYPT_DSA_Para *dsaPara);

// Custom random function to return fixed K value for signature tests
int32_t STUB_RandForSignature(uint8_t *byte, uint32_t len)
{
    if (len > sizeof(g_kRandBuf)) {
        return CRYPT_NULL_INPUT;
    }
    // Return the fixed K value from test vector
    return memcpy_s(byte, len, g_kRandBuf, len);
}

int32_t STUB_RandForSignatureEx(void *libCtx, uint8_t *byte, uint32_t len)
{
    (void)libCtx;
    return STUB_RandForSignature(byte, len);
}

int32_t STUB_RandRangeK(void *libCtx, BN_BigNum *r, const BN_BigNum *p)
{
    (void)p;
    (void)libCtx;
    BN_Bin2Bn(r, g_kRandBuf, g_kRandBufLen);
    return CRYPT_SUCCESS;
}

int Compute_Md(CRYPT_MD_AlgId mdId, Hex *msgIn, Hex *mdOut)
{
    uint32_t outLen;
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint32_t mdOutLen = CRYPT_EAL_MdGetDigestSize(mdId);
    ASSERT_TRUE(mdOutLen != 0);
    mdOut->x = (uint8_t *)malloc(mdOutLen);
    ASSERT_TRUE(mdOut->x != NULL);
    mdOut->len = mdOutLen;
    outLen = mdOutLen;
    mdCtx = CRYPT_EAL_MdNewCtx(mdId);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdNewCtx", mdCtx != NULL);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdInit", CRYPT_EAL_MdInit(mdCtx) == 0);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdUpdate", CRYPT_EAL_MdUpdate(mdCtx, msgIn->x, msgIn->len) == 0);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_MdFinal", CRYPT_EAL_MdFinal(mdCtx, mdOut->x, &outLen) == 0);
    mdOut->len = outLen;
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return SUCCESS;

EXIT:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    free(mdOut->x);
    mdOut->x = NULL;
    return ERROR;
}

void Set_DSA_Para(
    CRYPT_EAL_PkeyPara *para, CRYPT_EAL_PkeyPrv *prv, CRYPT_EAL_PkeyPub *pub, Hex *P, Hex *Q, Hex *G, Hex *X, Hex *Y)
{
    para->id = CRYPT_PKEY_DSA;
    para->para.dsaPara.p = P->x;
    para->para.dsaPara.pLen = P->len;
    para->para.dsaPara.q = Q->x;
    para->para.dsaPara.qLen = Q->len;
    para->para.dsaPara.g = G->x;
    para->para.dsaPara.gLen = G->len;

    if (prv && X) {
        prv->id = CRYPT_PKEY_DSA;
        prv->key.dsaPrv.data = X->x;
        prv->key.dsaPrv.len = X->len;
    }
    if (pub && Y) {
        pub->id = CRYPT_PKEY_DSA;
        pub->key.dsaPub.data = Y->x;
        pub->key.dsaPub.len = Y->len;
    }
}

static void Set_DSA_Pub(CRYPT_EAL_PkeyPub *pub, uint8_t *key, uint32_t keyLen)
{
    pub->id = CRYPT_PKEY_DSA;
    pub->key.dsaPub.data = key;
    pub->key.dsaPub.len = keyLen;
}

static void Set_DSA_Prv(CRYPT_EAL_PkeyPrv *prv, uint8_t *key, uint32_t keyLen)
{
    prv->id = CRYPT_PKEY_DSA;
    prv->key.dsaPrv.data = key;
    prv->key.dsaPrv.len = keyLen;
}

int SignEncode(uint8_t *vectorSign, uint32_t *vectorSignLen, Hex *R, Hex *S, BN_BigNum **bnR, BN_BigNum **bnS)
{
    *bnR = BN_Create(R->len * BITS_OF_BYTE);
    *bnS = BN_Create(S->len * BITS_OF_BYTE);
    ASSERT_EQ(BN_Bin2Bn(*bnR, R->x, R->len), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Bin2Bn(*bnS, S->x, S->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeSign(*bnR, *bnS, vectorSign, vectorSignLen), CRYPT_SUCCESS);
    return CRYPT_SUCCESS;

EXIT:
    return ERROR;
}

/**
 * @test   SDV_CRYPTO_DSA_SET_PARA_API_TC001
 * @title  DSA: CRYPT_EAL_PkeySetPara test.
 * @precon Registering memory-related functions.
 *         Dsa para vertors.
 * @brief
 *    1. Create the context of the dsa algorithm, expected result 1.
 *    2. CRYPT_EAL_PkeySetPara: para = NULL, expected result 2.
 *    3. CRYPT_EAL_PkeySetPara, expected result 3, the parameters are as follows:
 *       (1) p != NULL, pLen = 0
 *       (2) p = NULL, pLen != 0
 *       (3) q != NULL, qLen = 0
 *       (4) q = NULL, qLen != 0
 *       (5) g != NULL, gLen = 0
 *       (6) g = NULL, gLen != 0
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_ERR_NEW_PARA_FAIL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_SET_PARA_API_TC001(Hex *p, Hex *q, Hex *g, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t tmp[1];
    CRYPT_EAL_PkeyPara para;
    para.id = CRYPT_PKEY_DSA;
    para.para.dsaPara.p = p->x;
    para.para.dsaPara.pLen = p->len;
    para.para.dsaPara.q = q->x;
    para.para.dsaPara.qLen = q->len;
    para.para.dsaPara.g = g->x;
    para.para.dsaPara.gLen = g->len;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, NULL), CRYPT_NULL_INPUT);

    if (p->x == NULL) {
        para.para.dsaPara.p = tmp;
        ASSERT_TRUE_AND_LOG("p != NULL, pLen = 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

        para.para.dsaPara.p = p->x;
        para.para.dsaPara.pLen = 128;
        ASSERT_TRUE_AND_LOG("p = NULL, pLen != 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);
        para.para.dsaPara.pLen = p->len;
    }
    if (q->x == NULL) {
        para.para.dsaPara.q = tmp;
        ASSERT_TRUE_AND_LOG("q != NULL, qLen = 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

        para.para.dsaPara.q = q->x;
        para.para.dsaPara.qLen = 20;
        ASSERT_TRUE_AND_LOG("q == NULL, qLen != 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);
        para.para.dsaPara.qLen = q->len;
    }
    if (g->x == NULL) {
        para.para.dsaPara.g = tmp;
        ASSERT_TRUE_AND_LOG("g != NULL, gLen = 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

        para.para.dsaPara.g = g->x;
        para.para.dsaPara.gLen = 128;
        ASSERT_TRUE_AND_LOG("g!= NULL, gLen != 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_CMP_API_TC001
 * @title  DSA: CRYPT_EAL_PkeyCmp test.
 * @precon Registering memory-related functions.
 *         Dsa para vertors.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the dsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 2
 *    3. Set public key and para for ctx1, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 4
 *    5. Set public key and para for ctx2, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_DSA_ERR_KEY_INFO
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_DSA_ERR_KEY_INFO
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_CMP_API_TC001(Hex *p, Hex *q, Hex *g, Hex *y, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DSA_Para(&para, NULL, &pub, p, q, g, NULL, y);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_DSA_ERR_KEY_INFO);  // no key and no para

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx1, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_DSA_ERR_KEY_INFO);  // ctx2 no pubkey

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx2, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_CTRL_API_TC001
 * @title  DSA: CRYPT_EAL_PkeyCtrl test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context(ctx) of the dsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl method:
 *       (1) val = NULL, expected result 2
 *       (2) len = 0, expected result 3
 *       (3) opt = CRYPT_CTRL_SET_RSA_PADDING, expected result 4
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_DSA_UNSUPPORTED_CTRL_OPTION
 *    4. CRYPT_DSA_UNSUPPORTED_CTRL_OPTION
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_CTRL_API_TC001(int isProvider)
{
    int32_t ref = 1;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_UP_REFERENCES, NULL, sizeof(uint32_t)), BSL_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_UP_REFERENCES, &ref, 0), BSL_INVALID_ARG);
    ASSERT_EQ(
        CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, &ref, sizeof(int32_t)), CRYPT_DSA_UNSUPPORTED_CTRL_OPTION);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_GET_PARA_API_TC001
 * @title  DSA: CRYPT_EAL_PkeyGetPara test.
 * @precon Registering memory-related functions.
 *         Dsa para vertors.
 * @brief
 *    1. Create the contexts of the dsa algorithm, expected result 1.
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
void SDV_CRYPTO_DSA_GET_PARA_API_TC001(Hex *p, Hex *q, Hex *g, int isProvider)
{
    uint8_t buf_p[1030] = {0};
    uint32_t bufLen = sizeof(buf_p);
    uint8_t buf_q[1030] = {0};
    uint8_t buf_g[1030] = {0};
    Hex getP = {buf_p, bufLen};
    Hex getQ = {buf_q, bufLen};
    Hex getG = {buf_g, bufLen};

    CRYPT_EAL_PkeyPara para1 = {0};
    CRYPT_EAL_PkeyPara para2 = {0};
    Set_DSA_Para(&para1, NULL, NULL, p, q, g, NULL, NULL);
    Set_DSA_Para(&para2, NULL, NULL, &getP, &getQ, &getG, NULL, NULL);
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pKey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
    ASSERT_TRUE(pKey != NULL);

    para2.id = CRYPT_PKEY_RSA;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pKey, &para1) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(pKey, &para2) == CRYPT_EAL_ERR_ALGID);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(NULL, &para2) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(pKey, NULL) == CRYPT_NULL_INPUT);

    para2.id = CRYPT_PKEY_DSA;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPara(pKey, &para2) == CRYPT_SUCCESS);
    ASSERT_TRUE(para1.para.dsaPara.pLen == para2.para.dsaPara.pLen);
    ASSERT_TRUE(memcmp(para1.para.dsaPara.p, para2.para.dsaPara.p, para1.para.dsaPara.pLen) == 0);
    ASSERT_TRUE(para1.para.dsaPara.qLen == para2.para.dsaPara.qLen);
    ASSERT_TRUE(memcmp(para1.para.dsaPara.q, para2.para.dsaPara.q, para1.para.dsaPara.qLen) == 0);
    ASSERT_TRUE(para1.para.dsaPara.gLen == para2.para.dsaPara.gLen);
    ASSERT_TRUE(memcmp(para1.para.dsaPara.g, para2.para.dsaPara.g, para1.para.dsaPara.gLen) == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pKey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_SIGN_VERIFY_FUNC_TC001
 * @title  DSA: Set(or copy) the key, sign, and verify the signature.
 * @precon Registering memory-related functions.
 *         Dsa vertors.
 * @brief
 *    1. Mock BN_RandRange method to generate vector K.
 *    2. Create the context of the dsa algorithm, expected result 1.
 *    3. Set para, private key and public key, expected result 2.
 *    4. Call the CRYPT_EAL_PkeyGetSignLen method to get sign length, expected result 3.
 *    5. Allocate the memory for the signature, expected result 4.
 *    6. Encoding r and s vectors, expected result 5.
 *    7. Sign and compare the signatures of hitls and vector, expected result 6.
 *    8. Verify, expected result 7.
 *    9. Copy the ctx and repeat steps 7 through 8.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. signLen > 0
 *    4. Success
 *    5. Success
 *    6. CRYPT_SUCCESS, the two signatures are the same.
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_SIGN_VERIFY_FUNC_TC001(
    int hashId, Hex *P, Hex *Q, Hex *G, Hex *Msg, Hex *X, Hex *Y, Hex *K, Hex *R, Hex *S, int isProvider)
{
    if (IsMdAlgDisabled(hashId)) {
        SKIP_TEST();
    }
    uint32_t signLen;
    uint8_t *vectorSign = NULL;
    uint8_t *hitlsSign = NULL;
    uint32_t vectorSignLen, hitlsSignOutLen;
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;

    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    Set_DSA_Para(&para, &prv, &pub, P, Q, G, X, Y);

    ASSERT_EQ(memcpy_s(g_kRandBuf, sizeof(g_kRandBuf), K->x, K->len), 0);
    g_kRandBufLen = K->len;

    TestMemInit();
    // Register custom random function to return fixed K value from test vector
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    ASSERT_TRUE(signLen > 0);

    /* Encoding r and s vectors */
    vectorSign = (uint8_t *)malloc(signLen);
    vectorSignLen = signLen;
    ASSERT_EQ(SignEncode(vectorSign, &vectorSignLen, R, S, &bnR, &bnS), CRYPT_SUCCESS);

    /* Sign */
    hitlsSign = (uint8_t *)malloc(signLen);
    hitlsSignOutLen = signLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, hashId, Msg->x, Msg->len, hitlsSign, &hitlsSignOutLen), CRYPT_SUCCESS);

    /* Compare the signatures of hitls and vector. */
    ASSERT_EQ(hitlsSignOutLen, vectorSignLen);
    ASSERT_EQ(memcmp(vectorSign, hitlsSign, hitlsSignOutLen), 0);

    /* Verify */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, Msg->x, Msg->len, hitlsSign, hitlsSignOutLen), CRYPT_SUCCESS);

    /* Copy the ctx and verify the signature. */
    cpyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);
    hitlsSignOutLen = signLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, hashId, Msg->x, Msg->len, hitlsSign, &hitlsSignOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, hashId, Msg->x, Msg->len, hitlsSign, hitlsSignOutLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    free(vectorSign);
    free(hitlsSign);
    BN_Destroy(bnR);
    BN_Destroy(bnS);
    BSL_ERR_RemoveErrorStack(true);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_SIGN_VERIFY_DATA_FUNC_TC001
 * @title  DSA sets the key and performs signature and signature verification tests on the hash data.
 * @precon Registering memory-related functions.
 *         Dsa vertors.
 * @brief
 *    1. Mock BN_RandRange method to generate vector K.
 *    2. Create the context of the dsa algorithm, expected result 1.
 *    3. Set para, private key and public key, expected result 2.
 *    4. Call the CRYPT_EAL_PkeyGetSignLen method to get sign length, expected result 3.
 *    5. Allocate the memory for the signature, expected result 4.
 *    6. Encoding r and s vectors, expected result 5.
 *    7. Compute the hash of the msg, sign and compare the signatures of hitls and vector, expected result 6.
 *    8. Verify, expected result 7.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. signLen > 0
 *    4. Success
 *    5. Success
 *    6. CRYPT_SUCCESS, the two signatures are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_SIGN_VERIFY_DATA_FUNC_TC001(
    int hashId, Hex *P, Hex *Q, Hex *G, Hex *Msg, Hex *X, Hex *Y, Hex *K, Hex *R, Hex *S, int isProvider)
{
    if (IsMdAlgDisabled(hashId)) {
        SKIP_TEST();
    }
    uint32_t signLen;
    uint8_t *vectorSign = NULL;
    uint8_t *hitlsSign = NULL;
    uint32_t vectorSignLen, hitlsSignOutLen;
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    Hex mdOut = {0};

    ASSERT_EQ(memcpy_s(g_kRandBuf, sizeof(g_kRandBuf), K->x, K->len), 0);
    g_kRandBufLen = K->len;

    CRYPT_EAL_PkeyPara para;
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub;
    Set_DSA_Para(&para, &prv, &pub, P, Q, G, X, Y);

    TestMemInit();
    // Register custom random function to return fixed K value from test vector
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    ASSERT_TRUE(signLen > 0);

    /* Encoding r and s vectors */
    vectorSign = (uint8_t *)malloc(signLen);
    vectorSignLen = signLen;
    ASSERT_EQ(SignEncode(vectorSign, &vectorSignLen, R, S, &bnR, &bnS), CRYPT_SUCCESS);

    /* Calculates the hash of the msg. */
    ASSERT_EQ(Compute_Md(hashId, Msg, &mdOut), SUCCESS);

    /* Sign */
    hitlsSign = (uint8_t *)malloc(signLen);
    hitlsSignOutLen = signLen;
    ASSERT_EQ(CRYPT_EAL_PkeySignData(pkey, mdOut.x, mdOut.len, hitlsSign, &hitlsSignOutLen), CRYPT_SUCCESS);

    /* Compare the signatures of hitls and vector. */
    ASSERT_EQ(hitlsSignOutLen, vectorSignLen);
    ASSERT_EQ(memcmp(vectorSign, hitlsSign, hitlsSignOutLen), 0);

    /* Verify the signature of the hash data. */
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(pkey, mdOut.x, mdOut.len, hitlsSign, hitlsSignOutLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    if (mdOut.x != NULL) {
        free(mdOut.x);
    }
    free(vectorSign);
    free(hitlsSign);
    BN_Destroy(bnR);
    BN_Destroy(bnS);
    BSL_ERR_RemoveErrorStack(true);
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_GEN_FUNC_TC001
 * @title  DSA function test (gen a key pair).
 * @precon Registering memory-related functions.
 *         Dsa vertors.
 * @brief
 *    1. Init the drbg, expected result 1.
 *    2. Create the context(ctx) of the DSA algorithm, expected result 2.
 *    3. Set para for dsa, expected result 3.
 *    4. Generate a key pair, expected result 4.
 *    5. Call the CRYPT_EAL_PkeyGetSignLen method to get sign length, expected result 5.
 *    6. Allocate the memory for the signature, expected result 6.
 *    7. Sign, expected result 7.
 *    8. Verify, expected result 8.
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. Success, and two contexts are not NULL.
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. signLen > 0
 *    6. Success
 *    7. CRYPT_SUCCESS
 *    8. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GEN_FUNC_TC001(Hex *p, Hex *q, Hex *g, Hex *data, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t *sign = NULL;
    uint32_t signLen;

    Set_DSA_Para(&para, NULL, NULL, p, q, g, NULL, NULL);

    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx, &para), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(signLen > 0);
    sign = (uint8_t *)malloc(signLen);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, data->x, data->len, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, data->x, data->len, sign, signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    free(sign);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_DUP_CTX_FUNC_TC001
 * @title  DSA: CRYPT_EAL_PkeyDupCtx test.
 * @precon Registering memory-related functions.
 *         Dsa vertors.
 * @brief
 *    1. Create the context of the dsa algorithm, expected result 1.
 *    2. Init the drbg, expected result 2.
 *    3. Set para and generate a key pair, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyDupCtx method to dup dsa context, expected result 4.
 *    5. Call the CRYPT_EAL_PkeyCmp method to compare public key, expected result 5.
 *    6. Call the CRYPT_EAL_PkeyGetKeyBits to get keyLen from contexts, expected result 6.
 *    7. Call the CRYPT_EAL_PkeyGetPub method to obtain the public key from the contexts, expected result 7.
 *    8. Compare public keys, expected result 8.
 *    9. Call the CRYPT_EAL_PkeyGetPrv method to obtain the private key from the contexts, expected result 9.
 *    10. Compare privates keys, expected result 10.
 *    11. Call the sign/verify method to sign the message with the dupkey, expected result 11.
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Success, and context is not NULL.
 *    5. CRYPT_SUCCESS
 *    6. The key length obtained from both contexts is the same.
 *    7. CRYPT_SUCCESS
 *    8. The two public keys are the same.
 *    9. CRYPT_SUCCESS
 *    10. The two private keys are the same.
 *    11. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_DUP_CTX_FUNC_TC001(Hex *p, Hex *q, Hex *g, int isProvider)
{
    uint8_t *key1 = NULL;
    uint8_t *key2 = NULL;
    uint32_t keyLen1, keyLen2;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pub1, pub2;
    CRYPT_EAL_PkeyPrv prv1, prv2;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen;
    char *msg = "Hello, openHiTLS";
    uint32_t msgLen = strlen(msg);
    Set_DSA_Para(&para, NULL, NULL, p, q, g, NULL, NULL);

    TestMemInit();
    ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, dupCtx), CRYPT_SUCCESS);

    keyLen1 = CRYPT_EAL_PkeyGetKeyBits(ctx);
    keyLen2 = CRYPT_EAL_PkeyGetKeyBits(dupCtx);
    ASSERT_EQ(keyLen1, keyLen2);

    key1 = calloc(1u, keyLen1);
    key2 = calloc(1u, keyLen2);
    ASSERT_TRUE(key1 != NULL && key2 != NULL);

    Set_DSA_Pub(&pub1, key1, keyLen1);
    Set_DSA_Pub(&pub2, key2, keyLen2);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(dupCtx, &pub2), CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare public key", key1, pub1.key.dsaPub.len, key2, pub2.key.dsaPub.len);

    Set_DSA_Prv(&prv1, key1, keyLen1);
    Set_DSA_Prv(&prv2, key2, keyLen2);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(dupCtx, &prv2), CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare private key", key1, prv1.key.dsaPrv.len, key2, prv2.key.dsaPrv.len);
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(signLen > 0);
    sign = (uint8_t *)malloc(signLen);
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupCtx, CRYPT_MD_SHA256, (uint8_t *)msg, msgLen, sign, &signLen),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(dupCtx, CRYPT_MD_SHA256, (uint8_t *)msg, msgLen, sign, signLen),
        CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    BSL_SAL_Free(key1);
    BSL_SAL_Free(key2);
    BSL_SAL_Free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_KEY_PAIR_CHECK_FUNC_TC001
 * @title  DSA: key pair check.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(pubCtx, prvCtx) of the dsa algorithm, expected result 1
 *    2. Set para and public key for pubCtx, expected result 2
 *    3. Set para and private key for prvCtx, expected result 3
 *    4. Init the drbg, expected result 5, expected result 4
 *    5. Check whether the public key matches the private key, expected result 5
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. Return CRYPT_SUCCESS when expect is 1, CRYPT_DSA_VERIFY_FAIL otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_KEY_PAIR_CHECK_FUNC_TC001(Hex *P, Hex *Q, Hex *G, Hex *X, Hex *Y, int expect)
{
#if !defined(HITLS_CRYPTO_DSA_CHECK)
    (void)P;
    (void)Q;
    (void)G;
    (void)X;
    (void)Y;
    (void)expect;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    int expectRet = expect == 1 ? CRYPT_SUCCESS : CRYPT_DSA_PAIRWISE_CHECK_FAIL;

    Set_DSA_Para(&para, &prv, &pub, P, Q, G, X, Y);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DSA);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DSA);
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pubCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(prvCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), expectRet);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_GET_KEY_BITS_FUNC_TC001
 * @title  DSA: get key bits.
 * @brief
 *    1. Create a context of the DSA algorithm, expected result 1
 *    2. Get key bits, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GET_KEY_BITS_FUNC_TC001(int id, int keyBits, Hex *P, Hex *Q, Hex *G, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    CRYPT_EAL_PkeyPara para;
    para.id = CRYPT_PKEY_DSA;
    para.para.dsaPara.p = P->x;
    para.para.dsaPara.pLen = P->len;
    para.para.dsaPara.q = Q->x;
    para.para.dsaPara.qLen = Q->len;
    para.para.dsaPara.g = G->x;
    para.para.dsaPara.gLen = G->len;

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(pkey) == (uint32_t)keyBits);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_GET_SEC_BITS_FUNC_TC001
 * @title  DSA CRYPT_EAL_PkeyGetSecurityBits test.
 * @precon nan
 * @brief
 *    1. Create the context of the dsa algorithm, expected result 1
 *    2. Set dsa para, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetSecurityBits Obtains secbits, expected result 3
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. The return value is secBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GET_SEC_BITS_FUNC_TC001(int id, int secBits, Hex *P, Hex *Q, Hex *G)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(id);
    ASSERT_TRUE(pkey != NULL);
    CRYPT_EAL_PkeyPara para;
    para.id = CRYPT_PKEY_DSA;
    para.para.dsaPara.p = P->x;
    para.para.dsaPara.pLen = P->len;
    para.para.dsaPara.q = Q->x;
    para.para.dsaPara.qLen = Q->len;
    para.para.dsaPara.g = G->x;
    para.para.dsaPara.gLen = G->len;

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), secBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

#ifdef HITLS_CRYPTO_DSA_GEN_PARA
static uint8_t *g_dsa_seed = NULL;
static int32_t ref = 0;

int32_t STUB_CRYPT_EAL_Randbytes(uint8_t *byte, uint32_t len)
{
    if (ref == 0) {
        (void)memcpy_s(byte, len, g_dsa_seed, len);
        ref = 1;
    } else {
        for (uint32_t i = 0; i < len; i++) {
            byte[i] = (uint8_t)(rand() % 255); // mod 255 get 8bit number.
        }
    }
    return CRYPT_SUCCESS;
}

int32_t STUB_CRYPT_EAL_RandbytesEx(CRYPT_EAL_LibCtx *libCtx, uint8_t *byte, uint32_t len)
{
    (void)libCtx;
    return STUB_CRYPT_EAL_Randbytes(byte, len);
}

#endif /* HITLS_CRYPTO_DSA */

/* BEGIN_CASE */
void SDV_CRYPTO_DSA_VERIFY_PQ_FUNC_TC001(int algId, Hex *seed, char *pHex, char *qHex)
{
#ifndef HITLS_CRYPTO_DSA_GEN_PARA
    (void)algId;
    (void)seed;
    (void)pHex;
    (void)qHex;
    SKIP_TEST();
#else
    BSL_Buffer seedTmp = {seed->x, seed->len};
    BN_BigNum *p = NULL;
    BN_BigNum *q = NULL;
    ASSERT_EQ(BN_Hex2Bn(&p, pHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&q, qHex), CRYPT_SUCCESS);
    CRYPT_DSA_Para dsaPara = {p, q, NULL};
    uint32_t counter = 5;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CryptDsaFips1864ValidatePq(algId, NULL, NULL, CRYPT_DSA_FFC_PARAM, &seedTmp, &dsaPara, counter), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    TestRandDeInit();
    BN_Destroy(p);
    BN_Destroy(q);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GEN_PQ_FUNC_TC001(int algId, int L, int N, Hex *seed, char *pHex, char *qHex)
{
#ifndef HITLS_CRYPTO_DSA_GEN_PARA
    (void)algId;
    (void)L;
    (void)N;
    (void)seed;
    (void)pHex;
    (void)qHex;
    SKIP_TEST();
#else
    BN_BigNum *pReq = NULL;
    BN_BigNum *qReq = NULL;
    uint32_t counter = 0;
    g_dsa_seed = seed->x;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    STUB_REPLACE(CRYPT_EAL_RandbytesEx, STUB_CRYPT_EAL_RandbytesEx);
    CRYPT_RandRegist(STUB_CRYPT_EAL_Randbytes);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx((CRYPT_EAL_RandFuncEx)STUB_CRYPT_EAL_RandbytesEx);
#endif
    ref = 0;
    DSA_FIPS186_4_Para fipsPara = {algId, 0, L, N};
    BSL_Buffer seedTmp = {seed->x, seed->len};
    CRYPT_DSA_Ctx *ctx = CRYPT_DSA_NewCtx();
    ASSERT_TRUE(ctx != NULL);
    CRYPT_DSA_Para *dsaPara = (CRYPT_DSA_Para *)BSL_SAL_Calloc(1, sizeof(CRYPT_DSA_Para));
    ASSERT_TRUE(dsaPara != NULL);
    ctx->para = dsaPara;
    ASSERT_EQ(CryptDsaFips1864GenPq(ctx, &fipsPara, CRYPT_DSA_FFC_PARAM, &seedTmp, &counter), CRYPT_SUCCESS);
    ASSERT_EQ(CryptDsaFips1864ValidatePq(algId, NULL, NULL, CRYPT_DSA_FFC_PARAM, &seedTmp, ctx->para, counter), 0);
    ASSERT_EQ(BN_Hex2Bn(&pReq, pHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&qReq, qHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Cmp(ctx->para->p, pReq), 0);
    ASSERT_EQ(BN_Cmp(ctx->para->q, qReq), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_RandDeinit();
    STUB_RESTORE(CRYPT_EAL_RandbytesEx);
    TestRandDeInit();
    g_dsa_seed = NULL;
    CRYPT_DSA_FreeCtx(ctx);
    BN_Destroy(pReq);
    BN_Destroy(qReq);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GEN_G_FUNC_TC001(char *pHex, char *qHex, char *gHex)
{
#ifndef HITLS_CRYPTO_DSA_GEN_PARA
    (void)pHex;
    (void)qHex;
    (void)gHex;
    SKIP_TEST();
#else
    BN_BigNum *p = NULL;
    BN_BigNum *q = NULL;
    BN_BigNum *gReq = NULL;
    ASSERT_EQ(BN_Hex2Bn(&p, pHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&q, qHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&gReq, gHex), CRYPT_SUCCESS);
    CRYPT_DSA_Para dsaPara = {p, q, NULL};
    uint64_t h = 0;
    ASSERT_EQ(CryptDsaFips1864GenUnverifiableG(&dsaPara, &h), CRYPT_SUCCESS);
    ASSERT_EQ(CryptDsaFips1864PartialValidateG(&dsaPara), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Cmp(dsaPara.g, gReq), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BN_Destroy(p);
    BN_Destroy(q);
    BN_Destroy(dsaPara.g);
    BN_Destroy(gReq);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GEN_G_FUNC_TC002(int algId, int index, Hex *seed, char *pHex, char *qHex)
{
#ifndef HITLS_CRYPTO_DSA_GEN_PARA
    (void)algId;
    (void)index;
    (void)seed;
    (void)pHex;
    (void)qHex;
    SKIP_TEST();
#else
    BN_BigNum *p = NULL;
    BN_BigNum *q = NULL;
    ASSERT_EQ(BN_Hex2Bn(&p, pHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&q, qHex), CRYPT_SUCCESS);
    DSA_FIPS186_4_Para fipsPara = {algId, index, 0, 0};
    BSL_Buffer seedTmp = {seed->x, seed->len};
    CRYPT_DSA_Para dsaPara = {p, q, NULL};
    ASSERT_EQ(CryptDsaFips1864GenVerifiableG(NULL, NULL, &fipsPara, &seedTmp, &dsaPara), CRYPT_SUCCESS);
    ASSERT_EQ(CryptDsaFips1864ValidateG(NULL, NULL, &fipsPara, &seedTmp, &dsaPara), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BN_Destroy(p);
    BN_Destroy(q);
    BN_Destroy(dsaPara.g);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GEN_G_FUNC_TC003(int algId, int index, Hex *seed, char *pHex, char *qHex)
{
#ifndef HITLS_CRYPTO_DSA_GEN_PARA
    (void)algId;
    (void)index;
    (void)seed;
    (void)pHex;
    (void)qHex;
    SKIP_TEST();
#else
    BN_BigNum *p = NULL;
    BN_BigNum *q = NULL;
    ASSERT_EQ(BN_Hex2Bn(&p, pHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&q, qHex), CRYPT_SUCCESS);
    DSA_FIPS186_4_Para fipsPara = {algId, index, 0, 0};
    BSL_Buffer seedTmp = {seed->x, seed->len};
    CRYPT_DSA_Para dsaPara = {p, q, NULL};
    ASSERT_EQ(CryptDsaFips1864GenVerifiableG(NULL, NULL, &fipsPara, &seedTmp, &dsaPara), CRYPT_DSA_ERR_TRY_CNT);
EXIT:
    BN_Destroy(p);
    BN_Destroy(q);
    BN_Destroy(dsaPara.g);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_DSA_GEN_G_FUNC_TC004(int algId, int index, Hex *seed, char *pHex, char *qHex, char *gHex)
{
#ifndef HITLS_CRYPTO_DSA_GEN_PARA
    (void)algId;
    (void)index;
    (void)seed;
    (void)pHex;
    (void)qHex;
    (void)gHex;
    SKIP_TEST();
#else
    BN_BigNum *p = NULL;
    BN_BigNum *q = NULL;
    BN_BigNum *gReq = NULL;
    ASSERT_EQ(BN_Hex2Bn(&p, pHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&q, qHex), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Hex2Bn(&gReq, gHex), CRYPT_SUCCESS);
    DSA_FIPS186_4_Para fipsPara = {algId, index, 0, 0};
    BSL_Buffer seedTmp = {seed->x, seed->len};
    CRYPT_DSA_Para dsaPara = {p, q, NULL};
    ASSERT_EQ(CryptDsaFips1864GenVerifiableG(NULL, NULL, &fipsPara, &seedTmp, &dsaPara), CRYPT_SUCCESS);
    ASSERT_EQ(CryptDsaFips1864ValidateG(NULL, NULL, &fipsPara, &seedTmp, &dsaPara), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Cmp(dsaPara.g, gReq), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BN_Destroy(p);
    BN_Destroy(q);
    BN_Destroy(gReq);
    BN_Destroy(dsaPara.g);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_DSA_KEY_PAIR_GEN_BY_PARAM_FUNC_TC001(int flag, int gIndex, int isProvider)
{
#ifndef HITLS_CRYPTO_DSA_GEN_PARA
    (void)flag;
    (void)gIndex;
    (void)isProvider;
    SKIP_TEST();
#else
    int32_t algId = CRYPT_MD_SHA256;
    uint32_t L = 2048;
    uint32_t N = 256;
    uint32_t seedLen = 256;
    int32_t index = gIndex;
    BSL_Param params[6] = {
        {CRYPT_PARAM_DSA_ALGID, BSL_PARAM_TYPE_INT32, &algId, sizeof(int32_t), 0},
        {CRYPT_PARAM_DSA_PBITS, BSL_PARAM_TYPE_UINT32, &L, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_QBITS, BSL_PARAM_TYPE_UINT32, &N, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_SEEDLEN, BSL_PARAM_TYPE_UINT32, &seedLen, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_GINDEX, BSL_PARAM_TYPE_INT32, &index, sizeof(int32_t), 0},
        BSL_PARAM_END
    };
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *sign = NULL;
    TestMemInit();
    #ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_DSA_ERR_KEY_PARA);
    TestErrClear();
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GEN_PARA, params, 0), CRYPT_SUCCESS);
    uint32_t genFlag = (uint8_t)flag;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_GEN_FLAG, &genFlag, sizeof(genFlag)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    ASSERT_NE(signLen, 0);
    sign = (uint8_t *)BSL_SAL_Calloc(signLen, 1);
    ASSERT_TRUE(sign != NULL);

    uint8_t data[] = "testdata";
    uint32_t dataLen = 8;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, data, dataLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, data, dataLen, sign, signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_Free(sign);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_CHECK_KEYPAIR_TC001
 * @brief
 *   Create a dsa key pairs to check the key pair consistency.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_CHECK_KEYPAIR_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
#if !defined(HITLS_CRYPTO_DSA_CHECK)
    (void)p;
    (void)g;
    (void)q;
    (void)isProvider;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyPara para = {0};
    Set_DSA_Para(&para, NULL, NULL, p, q, g, NULL, NULL);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pkey, pkey) == CRYPT_SUCCESS);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_CHECK_KEYPAIR_INVALIED_TC001
 * @brief
 *   Create a dsa key pairs to check the key pair consistency.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_CHECK_KEYPAIR_INVALIED_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
#if !defined(HITLS_CRYPTO_DSA_CHECK)
    (void)p;
    (void)g;
    (void)q;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    uint8_t pubKey[1030];
    uint32_t pubKeyLen = sizeof(pubKey);
    uint8_t prvKey[1030];
    uint32_t prvKeyLen = sizeof(prvKey);
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_DSA_Pub(&pub, pubKey, pubKeyLen);
    Set_DSA_Prv(&prv, prvKey, prvKeyLen);
    CRYPT_EAL_PkeyPara para = {0};
    Set_DSA_Para(&para, NULL, NULL, p, q, g, NULL, NULL);

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
    CRYPT_EAL_PkeyCtx *pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
        isProvider);
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

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(prvCtx, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pubCtx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx) == CRYPT_DSA_PAIRWISE_CHECK_FAIL);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_DSA_CHECK_PRV_TC001
 * @brief
 *   Create a dsa key pairs to check the prv key.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DSA_CHECK_PRV_TC001(Hex *p, Hex *g, Hex *q, int isProvider)
{
#if !defined(HITLS_CRYPTO_DSA_CHECK)
    (void)p;
    (void)g;
    (void)q;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    int32_t bits;
    CRYPT_EAL_PkeyPara para = {0};
    Set_DSA_Para(&para, NULL, NULL, p, q, g, NULL, NULL);
    BN_BigNum *x = NULL;
    CRYPT_DSA_Ctx *ctx = NULL;
    BN_BigNum *maxValue = NULL;

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
            isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS); // get prv and pub
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ctx = (CRYPT_DSA_Ctx *)pkey->key;
    x = ctx->x;
    if (q->len != 0) {
        ctx->x = ctx->para->q;
        ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_DSA_INVALID_PRVKEY);
    } else {
        maxValue = BN_Create(0);
        bits = BN_Bits(ctx->para->p);
        ASSERT_EQ(BN_SetLimb(maxValue, 1), CRYPT_SUCCESS);
        BN_Lshift(maxValue, maxValue, bits);
        ctx->x = maxValue;
        ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_DSA_INVALID_PRVKEY);
    }
    ctx->x = x;
EXIT:
    BN_Destroy(maxValue);
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
}
/* END_CASE */
