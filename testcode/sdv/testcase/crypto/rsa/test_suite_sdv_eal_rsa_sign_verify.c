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
/* INCLUDE_BASE test_suite_sdv_eal_rsa */

/* BEGIN_HEADER */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "bsl_errno.h"
#include "crypt_eal_md.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "crypt_bn.h"
#include "crypt_rsa.h"
#include "rsa_local.h"

/* END_HEADER */

int MD_Data(CRYPT_MD_AlgId mdId, Hex *msgIn, Hex *mdOut)
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
    return FAIL;
}

/**
 * @test   SDV_CRYPTO_RSA_SIGN_API_TC001
 * @title  RSA CRYPT_EAL_PkeySign: Wrong parameters.
 * @precon Create the context of the rsa algorithm, set private key and set padding type to pkcsv15:
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) pkey = null, expected result 1.
 *       (2) data = null, dataLen = 0, expected result 2.
 *       (3) data = null, dataLen != 0, expected result 3.
 *       (4) data != null, dataLen = 0, expected result 4.
 *       (5) sign = null, signLen != 0, expected result 5.
 *       (6) sign != null, signLen = 0, expected result 6.
 *       (7) sign != null, signLen == NULL, expected result 7.
 *    2. Call the CRYPT_EAL_PkeySetPrv method with incorrect hash id, expected result 8:
 *       CRYPT_MD_MD5, CRYPT_MD_SHA1, CRYPT_MD_SM3, CRYPT_MD_MAX
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_NULL_INPUT
 *    6. CRYPT_RSA_BUFF_LEN_NOT_ENOUGH
 *    7. CRYPT_NULL_INPUT
 *    8. Return CRYPT_RSA_ERR_ALGID or CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_API_TC001(Hex *n, Hex *d, int isProvider)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *data = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen = d->len + 1;
    uint32_t dataLen = signLen;
    int32_t pkcsv15 = CRYPT_MD_SHA224;
    CRYPT_MD_AlgId errIdList[] = {CRYPT_MD_MD5, CRYPT_MD_SHA1, CRYPT_MD_SM3, CRYPT_MD_MAX};

    /* Malloc signature buffer */
    sign = (uint8_t *)malloc(signLen);
    data = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(sign != NULL && data != NULL);
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(NULL, CRYPT_MD_SHA224, data, dataLen, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, NULL, 0, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, NULL, dataLen, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, 0, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, dataLen, NULL, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, dataLen, sign, NULL), CRYPT_NULL_INPUT);
    signLen = 0;
    ASSERT_EQ(
        CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, data, dataLen, sign, &signLen), CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);

    signLen = dataLen;
    for (int i = 0; i < (int)(sizeof(errIdList) / sizeof(CRYPT_MD_AlgId)); i++) {
        ret = CRYPT_EAL_PkeySign(pkeyCtx, errIdList[i], data, dataLen, sign, &signLen);
        ASSERT_TRUE(ret == CRYPT_RSA_ERR_ALGID || ret == CRYPT_EAL_ERR_ALGID);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(data);
    free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC001
 * @title  RSA EAL layer signature function test: PKCSV15, sha224
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Set the padding algorithm to PKCS15 and set the hash value to SHA224, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method with invalid mdId, expected result 4
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_EAL_ERR_ALGID
 *    5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC001(Hex *n, Hex *d, Hex *msg, Hex *sign, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen = sign->len;
    int32_t pkcsv15 = CRYPT_MD_SHA224;

    /* Malloc signature buffer */
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);
    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC002
 * @title  RSA EAL layer signature function test: PKCSV15
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Set the padding algorithm to PKCS15 and set the hash value to SHA2, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 4
 *    5. Compare the signature result and the signature vector., expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC002(int mdId, Hex *n, Hex *d, Hex *msg, Hex *sign, int isProvider)
{
#if !defined(HITLS_CRYPTO_RSA_SIGN) || !defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15)
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    int32_t pkcsv15 = mdId;
    uint8_t *signdata = NULL;
    uint32_t signLen;

    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), 0);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    ASSERT_EQ(signLen, sign->len);
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("CRYPT_EAL_PkeySign Compare", sign->x, sign->len, signdata, signLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC001
 * @title  RSA EAL layer signature function test: Pss
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Set the padding algorithm to PKCS15 and set the hash value to SHA2, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 4
 *    5. Compare the signature result and the signature vector., expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC001(int mdId, Hex *n, Hex *d, Hex *msg, Hex *sign, Hex *salt, int isProvider)
{
#if !defined(HITLS_CRYPTO_RSA_SIGN) || !defined(HITLS_CRYPTO_RSA_EMSA_PSS)
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    int i;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &salt->len, sizeof(salt->len), 0},
        BSL_PARAM_END};
    uint8_t *signdata = NULL;
    uint32_t signLen = sign->len;

    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    /* Malloc signature buffer */
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    /* Repeat signature 2 times. */
    for (i = 0; i < 2; i++) {
        if (salt->len != 0) {
            ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_SALT, salt->x, salt->len), CRYPT_SUCCESS);
        }
        ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("Compare Sign Data", signdata, signLen, sign->x, sign->len);
        signLen = sign->len;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC002
 * @title  RSA EAL layer signature function test: Pss with different salt lengths.
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Initialize the DRBG, expected result 2
 *    3. Set the private key for pkeyCtx, expected result 3
 *    4. Set the padding algorithm to PSS and set the hash value to SHA2, expected result 4
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC002(int mdId, Hex *n, Hex *d, Hex *msg, int saltLen, int isProvider)
{
#if !defined(HITLS_CRYPTO_RSA_SIGN) || !defined(HITLS_CRYPTO_RSA_EMSA_PSS) || !defined(HITLS_CRYPTO_DRBG)
        SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_DRBG
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    ASSERT_TRUE(signLen != 0);
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC003
 * @title  RSA EAL layer signature function test: Do not set the salt length of PSS.
 * @precon Vectors: private key, msg.
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set the private key for pkeyCtx, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Set the padding algorithm to PSS, saltLen is 0 | -1 | -2, expected result 4
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC003(Hex *n, Hex *d, Hex *msg, int saltLen, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPrv privaKey = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen;
    int32_t mdId = CRYPT_MD_SHA224;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    SetRsaPrvKey(&privaKey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &privaKey), CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_DRBG
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    ASSERT_TRUE(signLen != 0);
    signdata = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SHA224, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(signdata);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC001
 * @title  RSA EAL sign/verify and signData/verifyData:PKCSV15, sha256
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetPara, where bits are: 1024/2048/4096, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGen to generate a key pair again, expected result 5
 *    6. Set padding type to pkcsv15, expected result 6
 *    7. Call the CRYPT_EAL_PkeySign method and use pkey to sign a piece of data, expected result 7
 *    8. Call the CRYPT_EAL_PkeyVerify method and use pkey to verify the signed data, expected result 8
 *    9. Call the CRYPT_EAL_PkeySignData method and use pkey to sign a piece of hash data, expected result 9
 *    10. Call the CRYPT_EAL_PkeyVerifyData method and use pkey to verify the signed data, expected result 10
 *    11. Allocate the memory for the CRYPT_EAL_PkeyCtx, named cpyCtx, expected result 11
 *    12. Call the CRYPT_EAL_PkeyCopyCtx to copy pkeyCtx, expected result 12
 *    13. Call the CRYPT_EAL_PkeySignData method and use cpyCtx to sign a piece of data, expected result 13
 *    14. Call the CRYPT_EAL_PkeyVerifyData method and use cpyCtx to verify the signed data, expected result 14
 * @expect
 *    1. Success, and context is not NULL.
 *    2-10. CRYPT_SUCCESS
 *    11. Success.
 *    12-14. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC001(int bits, int isProvider)
{
#ifndef HITLS_CRYPTO_SHA256
    SKIP_TEST();
#endif
    uint32_t signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    int mdId = CRYPT_MD_SHA256;
    uint8_t data[500] = {0};
    const uint32_t dataLen = sizeof(data);
    uint8_t hash[32];  // SHA256 digest length: 32
    const uint32_t hashLen = sizeof(hash);
    uint8_t e[] = {1, 0, 1};

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    int32_t pkcsv15 = mdId;
    CRYPT_EAL_PkeyPara para = {0};

    SetRsaPara(&para, e, 3, bits);

    uint8_t *sign = malloc(signLen);
    ASSERT_TRUE_AND_LOG("Malloc Sign Buffer", sign != NULL);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, data, dataLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data, dataLen, sign, signLen), CRYPT_SUCCESS);

    signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    memset_s(hash, sizeof(hash), 'A', sizeof(hash));
    ASSERT_EQ(CRYPT_EAL_PkeySignData(pkey, hash, hashLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(pkey, hash, hashLen, sign, signLen), CRYPT_SUCCESS);

    cpyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);

    signLen = (bits + 7) >> 3;
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, mdId, data, dataLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, mdId, data, dataLen, sign, signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PSS_FUNC_TC001
 * @title  RSA EAL signData/verifyData: pss, sha256, saltLen=32bytes
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetPara, where bits is 1025, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Set padding type to pkcsv15 and set salt(32 bytes), expected result 5
 *    6. Call the CRYPT_EAL_PkeySignData method and use pkey to sign a piece of data, expected result 6
 *    7. Call the CRYPT_EAL_PkeyVerifyData method and use pkey to verify the signed data, expected result 7
 *    8. Allocate the memory for the CRYPT_EAL_PkeyCtx, named cpyCtx, expected result 8
 *    9. Call the CRYPT_EAL_PkeyCopyCtx to copy pkeyCtx, expected result 9
 *    10. Call the CRYPT_EAL_PkeySignData method and use cpyCtx to sign a piece of data, expected result 10
 *    11. Call the CRYPT_EAL_PkeyVerifyData method and use cpyCtx to verify the signed data, expected result 11
 * @expect
 *    1. Success, and context is not NULL.
 *    2-7. CRYPT_SUCCESS
 *    8. Success.
 *    9-11. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PSS_FUNC_TC001(int bits, int isProvider)
{
#ifndef HITLS_CRYPTO_SHA256
    SKIP_TEST();
#endif
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    int32_t mdId = CRYPT_MD_SHA256;
    int32_t saltLen = 32;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t salt[100];
    uint32_t signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    uint8_t hash[32];                    // SHA256 digest length 32
    const uint32_t hashLen = sizeof(hash);

    memset_s(hash, sizeof(hash), 'A', sizeof(hash));
    (void)memset_s(salt, sizeof(salt), 'A', sizeof(salt));
    uint8_t *sign = malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    SetRsaPara(&para, e, 3, bits);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_TRUE_AND_LOG("Malloc Sign Buffer", sign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, (uint8_t *)salt, 32), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySignData(pkey, hash, hashLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(pkey, hash, hashLen, sign, signLen), CRYPT_SUCCESS);

    cpyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(cpyCtx, CRYPT_CTRL_SET_RSA_SALT, (uint8_t *)salt, 32), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySignData(cpyCtx, hash, hashLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(cpyCtx, hash, hashLen, sign, signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC002
 * @title  RSA EAL sign/verify:Generate a key pair, set pubKey, PKCSV15, sha256
 * @precon
 * @brief
 *    1. Create the contexts(pkey, pkey2) of the rsa algorithm, expected result 1
 *    2. Set para for pkey and pkey2, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Get public key from pkey, expected result 5
 *    6. Set public key for pkey2, expected result 6
 *    7. Set padding type to pkcsv15 for pkey and pkey2, expected result 7
 *    8. Call the CRYPT_EAL_PkeySign method and use pkey to sign a piece of data, expected result8
 *    9. Call the CRYPT_EAL_PkeyVerify method and use pkey2 to verify the signed data, expected result 9
 * @expect
 *    1. Success, and context is not NULL.
 *    2-9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC002(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    uint8_t pubN[600];
    uint8_t pubE[600];
    uint8_t e[] = {1, 0, 1};
    uint8_t sign[200];
    uint32_t signLen = 200;  // 200bytes is greater than 1024 bits.
    uint8_t data[500] = {0};
    const uint32_t dataLen = 500;

    SetRsaPara(&para, e, 3, 1024);
    SetRsaPubKey(&pubKey, pubN, 600, pubE, 600);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey2, &para), CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, data, dataLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey2, CRYPT_MD_SHA256, data, dataLen, sign, signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC003
 * @title  RSA EAL sign/verify:Generate a key pair, set prvKey, PKCSV15, sha256
 * @precon
 * @brief
 *    1. Create the contexts(pkey, pkey2) of the rsa algorithm, expected result 1
 *    2. Set para for pkey and pkey2, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Get private key from pkey, expected result 5
 *    6. Set private key for pkey2, expected result 6
 *    7. Set padding type to pkcsv15 for pkey and pkey2, expected result 7
 *    8. Call the CRYPT_EAL_PkeySign method and use pkey2 to sign a piece of data, expected result8
 *    9. Call the CRYPT_EAL_PkeyVerify method and use pkey to verify the signed data, expected result 9
 * @expect
 *    1. Success, and context is not NULL.
 *    2-9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC003(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    uint8_t prvD[600];
    uint8_t prvN[600];
    uint8_t prvP[600];
    uint8_t prvQ[600];
    uint8_t e[] = {1, 0, 1};
    uint8_t sign[600];
    uint32_t signLen = 600;  // 600bytes > 1024bits
    uint8_t data[500] = {0};
    uint32_t dataLen = sizeof(data);

    SetRsaPara(&para, e, 3, 1024);
    prvKey.id = CRYPT_PKEY_RSA;
    prvKey.key.rsaPrv.d = prvD;
    prvKey.key.rsaPrv.dLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.n = prvN;
    prvKey.key.rsaPrv.nLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.p = prvP;
    prvKey.key.rsaPrv.pLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.q = prvQ;
    prvKey.key.rsaPrv.qLen = 600;  // 600bytes > 1024bits
    prvKey.key.rsaPrv.dP = NULL;
    prvKey.key.rsaPrv.dPLen = 0;
    prvKey.key.rsaPrv.dQ = NULL;
    prvKey.key.rsaPrv.dQLen = 0;
    prvKey.key.rsaPrv.qInv = NULL;
    prvKey.key.rsaPrv.qInvLen = 0;

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey2, &para), CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey2, &prvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey2, CRYPT_MD_SHA256, data, dataLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, data, dataLen, sign, signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_VERIFY_PKCSV15_FUNC_TC001
 * @title  Rsa verify-PKCS15
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pkeyCtx, expected result 2
 *    3. Set padding type to pkcsv15 for pkeyCtx, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method and use pkeyCtx to verify the signed data, expected result 4
 *    5. Calculate the hash value of msg, expected result 5
 *    6. Call the CRYPT_EAL_PkeyVerifyData method and use pkeyCtx to verify the signed data, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 *    5. SUCCESS
 *    6. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_VERIFY_PKCSV15_FUNC_TC001(
    int mdAlgId, Hex *n, Hex *e, Hex *msg, Hex *sign, int expect, int isProvider)
{
#if !defined(HITLS_CRYPTO_RSA_VERIFY) || !defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15)
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    int ret;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPub publicKey = {0};
    int32_t pkcsv15 = mdAlgId;
    Hex mdOut = {0};

    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);

    /* Set the public key.*/
    SetRsaPubKey(&publicKey, n->x, n->len, e->x, e->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkeyCtx, &publicKey), CRYPT_SUCCESS);

    /* Set padding. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(pkeyCtx, mdAlgId, msg->x, msg->len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

    ASSERT_TRUE(MD_Data(mdAlgId, msg, &mdOut) == SUCCESS);
    ret = CRYPT_EAL_PkeyVerifyData(pkeyCtx, mdOut.x, mdOut.len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

    ret = CRYPT_EAL_PkeyVerifyData(NULL, mdOut.x, mdOut.len, sign->x, sign->len);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyVerifyData", ret != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    free(mdOut.x);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC001
 * @title  Rsa verify-PSS
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pkeyCtx, expected result 2
 *    3. Set padding type to PSS for pkeyCtx, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method and use pkeyCtx to verify the signed data, expected result 4
 *    5. Calculate the hash value of msg, expected result 5
 *    6. Call the CRYPT_EAL_PkeyVerifyData method and use pkeyCtx to verify the signed data, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 *    5. SUCCESS
 *    6. Reutrn CRYPT_SUCCESS when expect is 0, otherwise return CRYPT_RSA_NOR_VERIFY_FAIL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC001(
    int mdAlgId, Hex *n, Hex *e, Hex *salt, Hex *msg, Hex *sign, int expect, int isProvider)
{
#if !defined(HITLS_CRYPTO_RSA_VERIFY) || !defined(HITLS_CRYPTO_RSA_EMSA_PSS)
        SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    int ret;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPub publicKey = {0};
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &salt->len, sizeof(salt->len), 0},
        BSL_PARAM_END};
    Hex mdOut = {0};

    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);

    /* Set the public key.*/
    SetRsaPubKey(&publicKey, n->x, n->len, e->x, e->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkeyCtx, &publicKey), CRYPT_SUCCESS);

    /* Set padding. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(pkeyCtx, mdAlgId, msg->x, msg->len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

    ASSERT_TRUE(MD_Data(mdAlgId, msg, &mdOut) == SUCCESS);
    ret = CRYPT_EAL_PkeyVerifyData(pkeyCtx, mdOut.x, mdOut.len, sign->x, sign->len);
    if (expect == SUCCESS) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_RSA_NOR_VERIFY_FAIL);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    if (mdOut.x != NULL) {
        free(mdOut.x);
    }
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC002
 * @title  RSA verify PSS: saltLen is CRYPT_RSA_SALTLEN_TYPE_AUTOLEN
 * @precon
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pkeyCtx, expected result 2
 *    3. Set padding type to PSS(saltLen is CRYPT_RSA_SALTLEN_TYPE_AUTOLEN) for pkeyCtx, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method and use pkeyCtx to verify the signed data, expected result 4
 *    5. Calculate the hash value of msg, expected result 5
 *    6. Call the CRYPT_EAL_PkeyVerifyData method and use pkeyCtx to verify the signed data, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC002(int mdAlgId, Hex *n, Hex *e, Hex *msg, Hex *sign, int isProvider)
{
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyPub publicKey = {0};
    uint32_t signLen = CRYPT_RSA_SALTLEN_TYPE_AUTOLEN;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &signLen, sizeof(signLen), 0},
        BSL_PARAM_END};
    TestMemInit();

    pkeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyCtx != NULL);

    /* Set the public key.*/
    SetRsaPubKey(&publicKey, n->x, n->len, e->x, e->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkeyCtx, &publicKey), CRYPT_SUCCESS);

    /* Set padding. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, mdAlgId, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_BLINDING_FUNC_TC001
 * @title  RSA EAL sign and verify with blinding.
 * @precon nan
 * @brief
 *    1. Create the context(pkeyCtx) of the rsa algorithm, expected result 1
 *    2. Set para, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Set CRYPT_RSA_BLINDING flag, expected result 5
 *    6. Set padding type, expected result 6
 *    7. Sign with HiTLS, expected result 7
 *    8. Verify with HiTLS, expected result 8
 * @expect
 *    1. Success, and context is not NULL.
 *    2-8. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_BLINDING_FUNC_TC001(int keyLen, int hashId, int padMode, Hex *msg, int saltLen, int isProvider)
{
    TestMemInit();
    if (IsMdAlgDisabled(hashId)) {
        SKIP_TEST();
    }
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t dataLen = MAX_CIPHERTEXT_LEN;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *newCtx = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    int paraSize;
    void *paraPtr;

    SetRsaPara(&para, e, 3, keyLen);
    int32_t pkcsv15 = hashId;
    if (padMode == CRYPT_CTRL_SET_RSA_EMSA_PSS) {
        paraSize = 0;
        paraPtr = pssParam;
    } else if (padMode == CRYPT_CTRL_SET_RSA_EMSA_PKCSV15) {
        paraSize = sizeof(pkcsv15);
        paraPtr = &pkcsv15;
    }

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, padMode, paraPtr, paraSize) == CRYPT_SUCCESS);
    uint32_t flag = CRYPT_RSA_BLINDING;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);

    /* private key signature */
    ASSERT_TRUE(CRYPT_EAL_PkeySign(pkey, hashId, msg->x, msg->len, sign, &dataLen) == CRYPT_SUCCESS);

    /* public key verify */
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(pkey, hashId, msg->x, msg->len, sign, dataLen) == CRYPT_SUCCESS);

    newCtx = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(newCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(newCtx, hashId, msg->x, msg->len, sign, &dataLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_BLINDING_FUNC_TC002
 * @title  RSA: Pkcsv15, Blinding, Signature.
 * @precon nan
 * @brief
 *    1. Create the context of the rsa algorithm, expected result 1
 *    2. Set private key, EMSA_PKCSV15 and CRYPT_RSA_BLINDING flag, expected result 2
 *    3. Initialize the drbg, expected result 3
 *    4. Signature, expected result 4
 *    5. Dup the context, and sign with new context, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS.
 *    5. Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_BLINDING_FUNC_TC002(int mdId, Hex *p, Hex *q, Hex *n, Hex *d, Hex *msg, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *newCtx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen;
    uint32_t flag = CRYPT_RSA_BLINDING;
    int32_t pkcsv15 = mdId;

    SetRsaPrvKey(&prv, n->x, n->len, d->x, d->len);
    prv.key.rsaPrv.p = p->x;
    prv.key.rsaPrv.pLen = p->len;
    prv.key.rsaPrv.q = q->x;
    prv.key.rsaPrv.qLen = q->len;

    TestMemInit();
#ifdef HITLS_CRYPTO_DRBG
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);  // Random numbers need to be generated during blinding.
#endif
    ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);

    /* Malloc signature buffer */
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    signdata = (uint8_t *)calloc(1u, signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    newCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(newCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(newCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(newCtx);
    free(signdata);
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_KEY_PAIR_CHECK_FUNC_TC001
 * @title  RSA: key pair check.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(pubCtx, prvCtx) of the rsa algorithm, expected result 1
 *    2. Set public key for pubCtx, expected result 2
 *    3. Set private key for prvCtx, expected result 3
 *    4. Check whether the public key matches the private key, expected result 4
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. Return CRYPT_SUCCESS when expect is 1, CRYPT_RSA_NOR_VERIFY_FAIL otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_KEY_PAIR_CHECK_FUNC_TC001(Hex *n, Hex *e, Hex *d, int expect, int isProvider)
{
#if !defined(HITLS_CRYPTO_RSA_CHECK)
    (void)n;
    (void)e;
    (void)d;
    (void)expect;
    (void)isProvider;
    SKIP_TEST();
#else
#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    int expectRet = expect == 1 ? CRYPT_SUCCESS : CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE;

    SetRsaPubKey(&pubKey, n->x, n->len, e->x, e->len);
    SetRsaPrvKey(&prvKey, n->x, n->len, d->x, d->len);

    TestMemInit();
    pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prvKey), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), expectRet);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
#endif // HITLS_CRYPTO_RSA_CHECK
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_RSABSSA_BLINDING_FUNC_TC001
 * @title  RSA: Blind signature basic functionality test
 * @precon Registering memory-related functions
 * @brief
 *    1. Create RSA context and generate key pair
 *    2. Set PSS parameters and blind signature flag
 *    3. Perform blind operation on message
 *    4. Sign the blinded message with private key
 *    5. Unblind the signature
 *    6. Verify the unblinded signature with public key
 *    7. Dup the context, and sign-verify with new context
 * @expect
 *    All operations return CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_RSABSSA_BLINDING_FUNC_TC001(int mdId, Hex *n, Hex *e, Hex *d, Hex *msg, int saltLen,
    int isProvider)
{
#ifndef HITLS_CRYPTO_RSA_BSSA
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t signLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyCtx *newCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
#ifdef HITLS_CRYPTO_RSA_SIGN
    uint8_t blindMsg[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t blindMsgLen = MAX_CIPHERTEXT_LEN;
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    uint8_t unBlindSig[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t unBlindSigLen = MAX_CIPHERTEXT_LEN;
#endif
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    SetRsaPubKey(&pubKey, n->x, n->len, e->x, e->len);
    SetRsaPrvKey(&prvKey, n->x, n->len, d->x, d->len);
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pssParam, 0), CRYPT_SUCCESS);
    uint32_t flag = CRYPT_RSA_BSSA;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_RSA_SIGN
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, mdId, msg->x, msg->len, blindMsg, &blindMsgLen) == CRYPT_SUCCESS);

    /* private key signature */
    ASSERT_TRUE(CRYPT_EAL_PkeySignData(pkey, blindMsg, blindMsgLen, sign, &signLen) == CRYPT_SUCCESS);
#endif

#ifdef HITLS_CRYPTO_RSA_VERIFY
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, sign, signLen, unBlindSig, &unBlindSigLen) == CRYPT_SUCCESS);
    /* public key verify */
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(pkey, mdId, msg->x, msg->len, unBlindSig, unBlindSigLen) == CRYPT_SUCCESS);
#endif

    newCtx = CRYPT_EAL_PkeyDupCtx(pkey); // dup ctx
    ASSERT_TRUE(newCtx != NULL);
#ifdef HITLS_CRYPTO_RSA_SIGN
    ASSERT_TRUE(CRYPT_EAL_PkeySignData(newCtx, blindMsg, blindMsgLen, sign, &signLen) == CRYPT_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_VERIFY
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(newCtx, mdId, msg->x, msg->len, unBlindSig, unBlindSigLen) == CRYPT_SUCCESS);
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_RSABSSA_BLINDING_FUNC_TC002
 * @title  RSA: Blind signature with known test vectors
 * @precon Registering memory-related functions
 * @brief
 *    1. Initialize RSA context with known key pairs
 *    2. Set PSS parameters and blind signature parameters
 *    3. Verify blind factor computation
 *    4. Perform blind signature operation with test vectors
 *    5. Compare results with expected values
 * @expect
 *    1. All operations return CRYPT_SUCCESS
 *    2. All computed values match the test vectors
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_RSABSSA_BLINDING_FUNC_TC002(Hex *e, Hex *nBuff, Hex *d, Hex *prepared_msg, Hex *salt, Hex *invBuf,
    Hex *blindMsgBuf, Hex *blindSigBuf, Hex *sigBuf, int isStub)
{
#ifndef HITLS_CRYPTO_RSA_BSSA
    SKIP_TEST();
#endif
    (void)sigBuf;
    TestMemInit();
    uint32_t ret;
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t signLen = MAX_CIPHERTEXT_LEN;
    uint8_t blindMsg[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t blindMsgLen = MAX_CIPHERTEXT_LEN;
#ifdef HITLS_CRYPTO_VERIFY
    uint8_t unBlindSig[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t unBlindSigLen = MAX_CIPHERTEXT_LEN;
#endif
    uint8_t rBuf[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t rBufLen = MAX_CIPHERTEXT_LEN;

    BN_BigNum *invN = NULL;
    BN_BigNum *inv = BN_Create(0);
    BN_BigNum *n = BN_Create(0);
    BN_BigNum *r = BN_Create(0);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_NE(inv, NULL);
    ASSERT_NE(n, NULL);
    ASSERT_NE(r, NULL);
    ASSERT_NE(opt, NULL);

    ret = BN_Bin2Bn(n, nBuff->x, nBuff->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = BN_Bin2Bn(inv, invBuf->x, invBuf->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = BN_ModInv(r, inv, n, opt);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = BN_Bn2Bin(r, rBuf, &rBufLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_MD_AlgId mdId = CRYPT_MD_SHA384;
    uint32_t saltLen = salt->len;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);

    CRYPT_EAL_PkeyPrv priKey = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};

    SetRsaPubKey(&pubKey, nBuff->x, nBuff->len, e->x, e->len);
    SetRsaPrvKey(&priKey, nBuff->x, nBuff->len, d->x, d->len);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &priKey), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    if (isStub) {
        CRYPT_RandRegist(STUB_ReplaceRandom);
        CRYPT_RandRegistEx(STUB_ReplaceRandomEx);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    // set pss param.
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pssParam, 0)
        == CRYPT_SUCCESS);
    if (salt->len != 0) {
        ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, salt->x, salt->len) == CRYPT_SUCCESS);
    }
    if (isStub) {
        memcpy_s(g_RandBuf, TMP_BUFF_LEN, rBuf, rBufLen);
    } else {
        ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, rBuf, rBufLen) == CRYPT_SUCCESS);
    }

    uint32_t flag = CRYPT_RSA_BSSA;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, prepared_msg->x, prepared_msg->len, blindMsg,
        &blindMsgLen) == CRYPT_SUCCESS);
    ret = memcmp(blindMsgBuf->x, blindMsg, blindMsgBuf->len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(blindMsgBuf->len, blindMsgLen);

    ASSERT_TRUE(CRYPT_EAL_PkeySignData(pkey, blindMsg, blindMsgLen, sign, &signLen) == CRYPT_SUCCESS);
    ret = memcmp(blindSigBuf->x, sign, blindSigBuf->len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(blindSigBuf->len, signLen);

#ifdef HITLS_CRYPTO_VERIFY
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, sign, signLen, unBlindSig, &unBlindSigLen) == CRYPT_SUCCESS);
    ret = memcmp(sigBuf->x, unBlindSig, sigBuf->len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(sigBuf->len, unBlindSigLen);

    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA384, prepared_msg->x, prepared_msg->len, unBlindSig,
        unBlindSigLen) == CRYPT_SUCCESS);
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BN_OptimizerDestroy(opt);
    BN_Destroy(inv);
    BN_Destroy(n);
    BN_Destroy(r);
    BN_Destroy(invN);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_RSABSSA_BLINDING_INVALID_PARAM_TC001
 * @title  RSA: Blind signature invalid parameter test
 * @precon Registering memory-related functions
 * @brief
 *    1. Test null pointer handling:
 *       - Test PkeyBlind/PkeyUnBlind with NULL context
 *       - Test PkeyBlind/PkeyUnBlind with NULL input/output buffers
 *       - Test PkeyBlind/PkeyUnBlind with NULL length pointers
 *    2. Test unsupported algorithm:
 *       - Test blind operations with ECDH key context
 *    3. Test RSA context without key information:
 *       - Test blind operations before setting key parameters
 *    4. Test buffer size validation:
 *       - Test with insufficient output buffer size
 *    5. Test padding configuration:
 *       - Test blind operations without setting padding
 *       - Test with mismatched hash algorithm (SHA256 vs SHA384)
 *    6. Test blind parameter controls:
 *       - Test NULL and invalid parameters for BSSA controls
 *       - Test getting blind factor inverse without setting output buffer.
 * @expect
 *    - CRYPT_NULL_INPUT for null pointer parameters
 *    - CRYPT_EAL_ALG_NOT_SUPPORT for unsupported algorithms
 *    - CRYPT_RSA_NO_KEY_INFO when key info missing
 *    - CRYPT_RSA_BUFF_LEN_NOT_ENOUGH for small buffers
 *    - CRYPT_RSA_PADDING_NOT_SUPPORTED for invalid padding
 *    - CRYPT_RSA_ERR_MD_ALGID for mismatched hash
 *    - CRYPT_INVALID_ARG for invalid blind parameters
 *    - CRYPT_RSA_ERR_NO_BLIND_INFO when blind factor not set
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_RSABSSA_BLINDING_INVALID_PARAM_TC001(void)
{
    TestMemInit();
    uint8_t msg[] = "test message";
    uint32_t msgLen = strlen((char *)msg);
    uint8_t blindMsg[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t blindMsgLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t unBlindSig[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t unBlindSigLen = MAX_CIPHERTEXT_LEN;
    uint8_t sign[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t signLen = MAX_CIPHERTEXT_LEN;
    uint32_t smallLen = 16;
    // Test null pointer parameters
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(NULL, CRYPT_MD_SHA384, msg, msgLen, blindMsg, &blindMsgLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(NULL, sign, signLen, unBlindSig, &unBlindSigLen) == CRYPT_NULL_INPUT);

    // gen key
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, msg, msgLen, blindMsg, NULL) == CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, sign, signLen, unBlindSig, &unBlindSigLen) == CRYPT_EAL_ALG_NOT_SUPPORT);
    CRYPT_EAL_PkeyFreeCtx(pkey);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    SetRsaPara(&para, e, 3, 1024);

    // set key param
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
#endif

    // Test input null
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, NULL, msgLen, blindMsg, &blindMsgLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, msg, msgLen, NULL, &blindMsgLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, msg, msgLen, blindMsg, NULL) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, NULL, signLen, unBlindSig, &unBlindSigLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, sign, signLen, NULL, &unBlindSigLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, sign, signLen, unBlindSig, NULL) == CRYPT_NULL_INPUT);

    // Test no key info.
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, msg, msgLen, blindMsg, &smallLen)
        == CRYPT_RSA_ERR_NO_PUBKEY_INFO);
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, sign, signLen, unBlindSig, &unBlindSigLen)
        == CRYPT_RSA_ERR_NO_PUBKEY_INFO);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    // Output buff is not enough.
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, msg, msgLen, blindMsg, &smallLen)
        == CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, msg, msgLen, unBlindSig, &smallLen) == CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);

    // pad type is wrong.
    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA384, msg, msgLen, blindMsg, &blindMsgLen)
        == CRYPT_RSA_PADDING_NOT_SUPPORTED);
    ASSERT_TRUE(CRYPT_EAL_PkeyUnBlind(pkey, msg, msgLen, unBlindSig, &unBlindSigLen)
        == CRYPT_RSA_PADDING_NOT_SUPPORTED);

    CRYPT_MD_AlgId mdId = CRYPT_MD_SHA384;
    uint32_t saltLen = 0;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pssParam, 0)
        == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyBlind(pkey, CRYPT_MD_SHA256, msg, msgLen, blindMsg, &unBlindSigLen)
        == CRYPT_RSA_ERR_MD_ALGID);

    uint8_t rBufTest[128] = {1}; // due to key bits = 1024
    uint8_t rBufTest1[128] = {0}; // due to key bits = 1024
    uint32_t rBufTestLen = 128;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, rBufTest, rBufTestLen) == CRYPT_SUCCESS);
    // repeated set
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, rBufTest, rBufTestLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R, rBufTest1, rBufTestLen)
        == CRYPT_RSA_ERR_BSSA_PARAM);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_PASS_TC001
 * @title  RSA EAL sign/verify: ISO9796-2 PMR, variable bits/hash, |m| = mL_len + 1
 * @precon nan
 * @brief
 *    1. Create RSA context and set key size and exponent, expected result 1.
 *    2. Generate key pair, expected result 2.
 *    3. Set padding to ISO9796-2 with given hash, expected result 3.
 *    4. Sign a message with length mL_len + 1, expected result 4.
 *    5. Verify the signature, expected result 5.
 * @expect
 *    1-5. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_PASS_TC001(int isProvider, int bits, int mdAlgId)
{
#if !defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2) || !defined(HITLS_CRYPTO_RSA_SIGN) || \
    !defined(HITLS_CRYPTO_RSA_VERIFY)
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t *msg = NULL;
    uint8_t *signBuf = NULL;
    uint32_t signLen = 0;
    int32_t mdId = mdAlgId;
    uint32_t keyBytes = (uint32_t)((bits + 7) >> 3);
    uint32_t hashLen = CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)mdId);
    uint32_t mLLen = 0;
    uint32_t msgLen = 0;
    BSL_Param isoParam[2] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END};

    ASSERT_TRUE(hashLen != 0);
    ASSERT_TRUE(keyBytes >= hashLen + 2);
    mLLen = keyBytes - hashLen - 2;
    msgLen = mLLen + 1;

    msg = BSL_SAL_Malloc(msgLen);
    signBuf = BSL_SAL_Malloc(keyBytes);
    ASSERT_TRUE(msg != NULL && signBuf != NULL);
    for (uint32_t i = 0; i < msgLen; i++) {
        msg[i] = (uint8_t)i;
    }
    signLen = keyBytes;

    SetRsaPara(&para, e, sizeof(e), bits);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2, isoParam, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, msg, msgLen, signBuf, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, msg, msgLen, signBuf, signLen), CRYPT_SUCCESS);

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(signBuf);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_DETER_TC001
 * @title  RSA EAL sign/verify: ISO9796-2 PMR deterministic signature
 * @precon nan
 * @brief
 *    1. Create RSA context and set key size and exponent, expected result 1.
 *    2. Generate key pair, expected result 2.
 *    3. Set padding to ISO9796-2 with given hash, expected result 3.
 *    4. Sign the same message twice, expected result 4.
 *    5. Verify both signatures, expected result 5.
 *    6. Compare the two signatures, expected result 6.
 * @expect
 *    1-6. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_DETER_TC001(int isProvider, int bits, int mdAlgId)
{
#if !defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2) || !defined(HITLS_CRYPTO_RSA_SIGN) || \
    !defined(HITLS_CRYPTO_RSA_VERIFY)
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t *msg = NULL;
    uint8_t *sign1 = NULL;
    uint8_t *sign2 = NULL;
    uint32_t signLen1 = 0;
    uint32_t signLen2 = 0;
    int32_t mdId = mdAlgId;
    uint32_t keyBytes = (uint32_t)((bits + 7) >> 3);
    uint32_t hashLen = CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)mdId);
    uint32_t mLLen = 0;
    uint32_t msgLen = 0;
    BSL_Param isoParam[2] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END};

    ASSERT_TRUE(hashLen != 0);
    ASSERT_TRUE(keyBytes >= hashLen + 2);
    mLLen = keyBytes - hashLen - 2;
    msgLen = mLLen + 1;

    msg = BSL_SAL_Malloc(msgLen);
    sign1 = BSL_SAL_Malloc(keyBytes);
    sign2 = BSL_SAL_Malloc(keyBytes);
    ASSERT_TRUE(msg != NULL && sign1 != NULL && sign2 != NULL);
    for (uint32_t i = 0; i < msgLen; i++) {
        msg[i] = (uint8_t)i;
    }
    signLen1 = keyBytes;
    signLen2 = keyBytes;

    SetRsaPara(&para, e, sizeof(e), bits);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2, isoParam, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, msg, msgLen, sign1, &signLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, msg, msgLen, sign2, &signLen2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, msg, msgLen, sign1, signLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, msg, msgLen, sign2, signLen2), CRYPT_SUCCESS);
    ASSERT_EQ(signLen1, signLen2);
    ASSERT_EQ(memcmp(sign1, sign2, signLen1), 0);

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(sign1);
    BSL_SAL_Free(sign2);
}
/* END_CASE */
/**
 * @test   SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_BOUNDARY_TC001
 * @title  RSA EAL sign/verify: ISO9796-2 PMR boundary lengths
 * @precon nan
 * @brief
 *    1. Create RSA context and set key size and exponent, expected result 1.
 *    2. Generate key pair, expected result 2.
 *    3. Set padding to ISO9796-2 with given hash, expected result 3.
 *    4. Sign/verify with |m| = mL_len, expected result 4.
 *    5. Sign with |m| = mL_len - 1, expected result 5.
 * @expect
 *    1-4. CRYPT_SUCCESS.
 *    5. CRYPT_RSA_ERR_INPUT_VALUE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_BOUNDARY_TC001(int isProvider, int bits, int mdAlgId)
{
#if !defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2) || !defined(HITLS_CRYPTO_RSA_SIGN) || \
    !defined(HITLS_CRYPTO_RSA_VERIFY)
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t *msg = NULL;
    uint8_t *signBuf = NULL;
    uint32_t signLen = 0;
    int32_t mdId = mdAlgId;
    uint32_t keyBytes = (uint32_t)((bits + 7) >> 3);
    uint32_t hashLen = CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)mdId);
    uint32_t mLLen = 0;
    uint32_t shortLen = 0;
    BSL_Param isoParam[2] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END};

    ASSERT_TRUE(hashLen != 0);
    ASSERT_TRUE(keyBytes >= hashLen + 2);
    mLLen = keyBytes - hashLen - 2;
    ASSERT_TRUE(mLLen > 0);
    shortLen = mLLen - 1;

    msg = BSL_SAL_Malloc(mLLen);
    signBuf = BSL_SAL_Malloc(keyBytes);
    ASSERT_TRUE(msg != NULL && signBuf != NULL);
    for (uint32_t i = 0; i < mLLen; i++) {
        msg[i] = (uint8_t)i;
    }

    SetRsaPara(&para, e, sizeof(e), bits);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2, isoParam, 0), CRYPT_SUCCESS);

    signLen = keyBytes;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, msg, mLLen, signBuf, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, msg, mLLen, signBuf, signLen), CRYPT_SUCCESS);

    signLen = keyBytes;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, msg, shortLen, signBuf, &signLen), CRYPT_RSA_ERR_INPUT_VALUE);

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(signBuf);
}
/* END_CASE */
/**
 * @test   SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_NEGATIVE_TC001
 * @title  RSA EAL sign/verify: ISO9796-2 PMR negative cases
 * @precon nan
 * @brief
 *    1. Create RSA context and set key size and exponent, expected result 1.
 *    2. Generate key pair, expected result 2.
 *    3. Set padding to ISO9796-2 with given hash, expected result 3.
 *    4. Tamper one bit of signature and verify, expected result 4.
 *    5. Tamper one bit of message and verify, expected result 5.
 *    6. Recover EM and tamper header/trailer, expected result 6.
 *    7. Recover EM and tamper hash, expected result 7.
 * @expect
 *    1-3. CRYPT_SUCCESS.
 *    4-7. CRYPT_RSA_NOR_VERIFY_FAIL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_NEGATIVE_TC001(int isProvider, int bits, int mdAlgId)
{
#if !defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2) || !defined(HITLS_CRYPTO_RSA_SIGN) || \
    !defined(HITLS_CRYPTO_RSA_VERIFY)
    (void)isProvider;
    (void)bits;
    (void)mdAlgId;
    SKIP_TEST();
    return;
#else
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
        return;
    }
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_RSA_Ctx *rsaCtx = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint8_t e[] = {1, 0, 1};
    uint8_t *msg = NULL;
    uint8_t *msgTamper = NULL;
    uint8_t *sign = NULL;
    uint8_t *signTamper = NULL;
    uint8_t *em = NULL;
    uint8_t *emTamper = NULL;
    uint8_t *hash = NULL;
    uint8_t *mlHash = NULL;
    uint8_t *pubN = NULL;
    uint8_t *pubE = NULL;
    uint32_t signLen = 0;
    uint32_t emLen = 0;
    int32_t mdId = mdAlgId;
    uint32_t keyBytes = (uint32_t)((bits + 7) >> 3);
    uint32_t hashLen = CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)mdId);
    uint32_t mLLen = 0;
    uint32_t msgLen = 0;
    uint32_t mlHashLen = 0;
    BSL_Param isoParam[2] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END};

    ASSERT_TRUE(hashLen != 0);
    ASSERT_TRUE(keyBytes >= hashLen + 2);
    mLLen = keyBytes - hashLen - 2;
    msgLen = mLLen + 1;
    mlHashLen = mLLen + hashLen;

    msg = BSL_SAL_Malloc(msgLen);
    msgTamper = BSL_SAL_Malloc(msgLen);
    sign = BSL_SAL_Malloc(keyBytes);
    signTamper = BSL_SAL_Malloc(keyBytes);
    em = BSL_SAL_Malloc(keyBytes);
    emTamper = BSL_SAL_Malloc(keyBytes);
    hash = BSL_SAL_Malloc(hashLen);
    mlHash = BSL_SAL_Malloc(mlHashLen);
    pubN = BSL_SAL_Malloc(keyBytes);
    pubE = BSL_SAL_Malloc(keyBytes);
    ASSERT_TRUE(msg != NULL && msgTamper != NULL && sign != NULL && signTamper != NULL &&
        em != NULL && emTamper != NULL && hash != NULL && mlHash != NULL &&
        pubN != NULL && pubE != NULL);
    for (uint32_t i = 0; i < msgLen; i++) {
        msg[i] = (uint8_t)i;
    }

    SetRsaPara(&para, e, sizeof(e), bits);
    SetRsaPubKey(&pubKey, pubN, keyBytes, pubE, keyBytes);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2, isoParam, 0), CRYPT_SUCCESS);

    signLen = keyBytes;
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, msg, msgLen, sign, &signLen), CRYPT_SUCCESS);

    (void)memcpy(signTamper, sign, signLen);
    signTamper[signLen - 1] ^= 0x01;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, msg, msgLen, signTamper, signLen), CRYPT_RSA_NOR_VERIFY_FAIL);

    (void)memcpy(msgTamper, msg, msgLen);
    msgTamper[0] ^= 0x01;
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, msgTamper, msgLen, sign, signLen), CRYPT_RSA_NOR_VERIFY_FAIL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_SUCCESS);
    rsaCtx = CRYPT_RSA_NewCtx();
    ASSERT_TRUE(rsaCtx != NULL);
    ASSERT_EQ(CRYPT_RSA_SetPubKey(rsaCtx, &pubKey.key.rsaPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_RSA_Ctrl(rsaCtx, CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2, isoParam, 0), CRYPT_SUCCESS);

    mdCtx = CRYPT_EAL_MdNewCtx(mdId);
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MdInit(mdCtx) == 0);
    ASSERT_TRUE(CRYPT_EAL_MdUpdate(mdCtx, msg, msgLen) == 0);
    ASSERT_TRUE(CRYPT_EAL_MdFinal(mdCtx, hash, &hashLen) == 0);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    mdCtx = NULL;

    if (mLLen > 0) {
        (void)memcpy(mlHash, msg, mLLen);
    }
    (void)memcpy(mlHash + mLLen, hash, hashLen);

    emLen = keyBytes;
    ASSERT_EQ(CRYPT_RSA_PubEnc(rsaCtx, sign, signLen, em, &emLen), CRYPT_SUCCESS);

    (void)memcpy(emTamper, em, emLen);
    emTamper[0] ^= 0x01;
    ASSERT_EQ(CRYPT_RSA_VerifyIso9796_2(mlHash, mlHashLen, emTamper, emLen), CRYPT_RSA_NOR_VERIFY_FAIL);

    (void)memcpy(emTamper, em, emLen);
    emTamper[emLen - 1] ^= 0x01;
    ASSERT_EQ(CRYPT_RSA_VerifyIso9796_2(mlHash, mlHashLen, emTamper, emLen), CRYPT_RSA_NOR_VERIFY_FAIL);

    (void)memcpy(emTamper, em, emLen);
    emTamper[emLen - hashLen - 1] ^= 0x01;
    ASSERT_EQ(CRYPT_RSA_VerifyIso9796_2(mlHash, mlHashLen, emTamper, emLen), CRYPT_RSA_NOR_VERIFY_FAIL);

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    TestRandDeInit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_RSA_FreeCtx(rsaCtx);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(msgTamper);
    BSL_SAL_Free(sign);
    BSL_SAL_Free(signTamper);
    BSL_SAL_Free(em);
    BSL_SAL_Free(emTamper);
    BSL_SAL_Free(hash);
    BSL_SAL_Free(mlHash);
    BSL_SAL_Free(pubN);
    BSL_SAL_Free(pubE);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_VECTOR_TC001
 * @title  RSA EAL sign/verify: ISO9796-2 vector
 * @precon nan
 * @brief
 *    1. Create sign/verify contexts, expected result 1.
 *    2. Set private/public key, expected result 2.
 *    3. Set padding to ISO9796-2 with given hash, expected result 3.
 *    4. Call CRYPT_EAL_PkeySign to compute signature, expected result 4.
 *    5. Compare signature with vector, expected result 5.
 *    6. Call CRYPT_EAL_PkeyVerify with vector signature, expected result 6.
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2-4,6. CRYPT_SUCCESS
 *    5. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SIGN_VERIFY_ISO9796_2_VECTOR_TC001(
    int mdAlgId, Hex *n, Hex *e, Hex *d, Hex *msg, Hex *sign, int isProvider)
{
#if !defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2) || !defined(HITLS_CRYPTO_RSA_SIGN) || \
    !defined(HITLS_CRYPTO_RSA_VERIFY)
    SKIP_TEST();
#endif
    if (IsMdAlgDisabled(mdAlgId)) {
        SKIP_TEST();
    }

    CRYPT_EAL_PkeyCtx *pkeySign = NULL;
    CRYPT_EAL_PkeyCtx *pkeyVerify = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t *signdata = NULL;
    uint32_t signLen = 0;
    int32_t mdId = mdAlgId;
    BSL_Param isoParam[2] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END};

    SetRsaPrvKey(&prvKey, n->x, n->len, d->x, d->len);
    SetRsaPubKey(&pubKey, n->x, n->len, e->x, e->len);

    TestMemInit();

    pkeySign = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeySign != NULL);

    pkeyVerify = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkeyVerify != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeySign, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkeyVerify, &pubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeySign, CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2, isoParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyVerify, CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2, isoParam, 0), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(pkeySign);
    ASSERT_EQ(signLen, sign->len);
    signdata = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeySign, mdAlgId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(signLen, sign->len);
    ASSERT_COMPARE("CRYPT_EAL_PkeySign Compare", sign->x, sign->len, signdata, signLen);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyVerify, mdAlgId, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeySign);
    CRYPT_EAL_PkeyFreeCtx(pkeyVerify);
    BSL_SAL_Free(signdata);
}
/* END_CASE */
