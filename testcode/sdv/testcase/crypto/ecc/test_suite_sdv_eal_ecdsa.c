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
/* INCLUDE_BASE test_suite_sdv_eal_ecc */

/* BEGIN_HEADER */

int SignEncode(Hex *R, Hex *S, uint8_t *vectorSign, uint32_t *vectorSignLen)
{
    int ret;
    BN_BigNum *bnR = BN_Create(R->len * BITS_OF_BYTE);
    BN_BigNum *bnS = BN_Create(S->len * BITS_OF_BYTE);
    ASSERT_TRUE(bnS != NULL && bnR != NULL);
    ASSERT_TRUE(BN_Bin2Bn(bnR, R->x, R->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Bin2Bn(bnS, S->x, S->len) == CRYPT_SUCCESS);
    ret = CRYPT_EAL_EncodeSign(bnR, bnS, vectorSign, vectorSignLen);
EXIT:
    BN_Destroy(bnR);
    BN_Destroy(bnS);
    return ret;
}
/* END_HEADER */

/**
 * @test   SDV_CRYPTO_ECDSA_NEW_CTX_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyNewCtx test.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create a pkey structure, algId is CRYPT_PKEY_ECDSA, expected result 1
 *    2. Releases the pkey structure, expected result 2
 * @expect
 *    1. Success, and the structure is not NULL.
 *    1. No memory leakage occurs.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_NEW_CTX_API_TC001(void)
{
    ASSERT_TRUE(EAL_PkeyNewCtx_Api_TC001(CRYPT_PKEY_ECDSA) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PARA_BY_ID_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeySetParaById: Test the validity of input parameters.
 * @precon
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetParaById method:
 *       (1) context = NULL, expected result 2.
 *       (2) CRYPT_PKEY_ParaId = CRYPT_ECC_NISTP224, expected result 3.
 *       (3) CRYPT_PKEY_ParaId = CRYPT_ECC_NISTP256, expected result 3.
 *       (4) CRYPT_PKEY_ParaId = CRYPT_ECC_NISTP384, expected result 3.
 *       (5) CRYPT_PKEY_ParaId = CRYPT_ECC_NISTP521, expected result 3.
 *       (6) CRYPT_PKEY_ParaId = CRYPT_ECC_BRAINPOOLP256R1, expected result 3.
 *       (7) CRYPT_PKEY_ParaId = CRYPT_ECC_BRAINPOOLP384R1, expected result 3.
 *       (8) CRYPT_PKEY_ParaId = CRYPT_ECC_BRAINPOOLP512R1, expected result 3.
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PARA_BY_ID_API_TC001(void)
{
    ASSERT_TRUE(EAL_PkeySetParaById_Api_TC001(CRYPT_PKEY_ECDSA) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PARA_BY_ID_API_TC002
 * @title  Repeat to set different curves.
 * @precon nan
 * @brief
 *    1. Create context(ecdsaPkey) of the ECDSA algorithm, expected result 1
 *    2. Set elliptic curve type to P224, expected result 2
 *    3. Set elliptic curve type to paraId, expected result 3
 *    4. Set private key, expected result 4
 *    5. Take over random numbers, mock BN_RandRange to generate randVector.
 *    6. Compute the signature by ecdsaPkey, expected result 5
 *    7. Compares the hitls signature, expected result 6
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PARA_BY_ID_API_TC002(
    int paraId, int mdId, Hex *prvKeyVector, Hex *plainText, Hex *signR, Hex *signS, Hex *randVector, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    int ret, vectorSignLen, hitlsSginLen;
    uint8_t *vectorSign = NULL;
    uint8_t *hitlsSign = NULL;
    CRYPT_EAL_PkeyPrv ecdsaPrvkey = {0};

    TestMemInit();

    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ecdsaPkey != NULL);
    ASSERT_TRUE_AND_LOG(
        "SetParaById NISTP224", CRYPT_EAL_PkeySetParaById(ecdsaPkey, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("SetParaById", CRYPT_EAL_PkeySetParaById(ecdsaPkey, paraId) == CRYPT_SUCCESS);

    /* Take over random numbers. */
    ASSERT_TRUE(memcpy_s(gkRandBuf, sizeof(gkRandBuf), randVector->x, randVector->len) == 0);
    gkRandBufLen = randVector->len;
    
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif

    /* Set private key */
    Ecc_SetPrvKey(&ecdsaPrvkey, CRYPT_PKEY_ECDSA, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdsaPkey, &ecdsaPrvkey), CRYPT_SUCCESS);

    /* Signature */
    hitlsSginLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    hitlsSign = (uint8_t *)malloc(hitlsSginLen);
    ASSERT_TRUE(hitlsSign != NULL);
    ret = CRYPT_EAL_PkeySign(ecdsaPkey, mdId, plainText->x, plainText->len, hitlsSign, (uint32_t *)&hitlsSginLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Encode the R and S of the vector. */
    vectorSignLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    vectorSign = (uint8_t *)malloc(vectorSignLen);
    ASSERT_TRUE(vectorSign != NULL);
    ret = SignEncode(signR, signS, vectorSign, (uint32_t *)&vectorSignLen);
    ASSERT_TRUE_AND_LOG("SignEncode", ret == CRYPT_SUCCESS);

    /* Compare the results of HiTLS vs. Vector. */
    ASSERT_EQ(hitlsSginLen, vectorSignLen);
    ASSERT_TRUE(memcmp(vectorSign, hitlsSign, hitlsSginLen) == 0);

EXIT:
    free(hitlsSign);
    free(vectorSign);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SIGN_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeySign: Test the validity of parameters.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id(P-224) and set private key, expected result 2
 *    3. Call the CRYPT_EAL_PkeySign method:
 *       (1) pkey = null, expected result 3
 *       (2) msg = null, expected result 4
 *       (3) sign = NULL, signLen != 0, expected result 5
 *       (4) sign != NULL, signLen = 0, expected result 6
 *       (5) sign != NULL, signLen = 1, expected result 7
 *       (6) msg != NULL, msgLen = 0, expected result 8
 *       (7) Correct parameters, expected result 9
 *    4. Compare the signgures of HiTLS and vector, expected result 10
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3-5. CRYPT_NULL_INPUT
 *    6-7. CRYPT_DSA_BUFF_LEN_NOT_ENOUGH
 *    8-9. CRYPT_SUCCESS
 *    10. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SIGN_API_TC001(
    int mdId, Hex *prvKeyVector, Hex *msg, Hex *signR, Hex *signS, Hex *randVector, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    int vectorSignLen;
    uint32_t signLen;
    uint8_t *vectorSign = NULL;
    uint8_t *sign = NULL;
    CRYPT_EAL_PkeyPrv ecdsaPrvkey = {0};

    /* Register memory */
    TestMemInit();
    /* Take over random numbers. */
    ASSERT_TRUE(memcpy_s(gkRandBuf, sizeof(gkRandBuf), randVector->x, randVector->len) == 0);
    gkRandBufLen = randVector->len;
    
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif

    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ecdsaPkey != NULL);
    /* Set para by curve id and set private key. */
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ecdsaPkey, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);
    Ecc_SetPrvKey(&ecdsaPrvkey, CRYPT_PKEY_ECDSA, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdsaPkey, &ecdsaPrvkey), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeySign. */
    signLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    sign = (uint8_t *)malloc(signLen);
    ASSERT_TRUE(sign != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(NULL, mdId, msg->x, msg->len, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ecdsaPkey, mdId, NULL, msg->len, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ecdsaPkey, mdId, msg->x, msg->len, NULL, &signLen), CRYPT_NULL_INPUT);
    signLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ecdsaPkey, mdId, msg->x, msg->len, sign, &signLen), CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH);
    signLen = 1;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ecdsaPkey, mdId, msg->x, msg->len, sign, &signLen), CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH);

    signLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    /* The plaintext length is 0 and the other parameters are normal, and it is expected to succeed. */
    ASSERT_EQ(CRYPT_EAL_PkeySign(ecdsaPkey, mdId, msg->x, 0, sign, &signLen), CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ecdsaPkey, mdId, msg->x, msg->len, sign, (uint32_t *)&signLen) == CRYPT_SUCCESS);

    /* Encode the R and S of the vector. */
    vectorSignLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    vectorSign = (uint8_t *)malloc(vectorSignLen);
    ASSERT_TRUE(vectorSign != NULL);
    ASSERT_TRUE_AND_LOG(
        "SignEncode", SignEncode(signR, signS, vectorSign, (uint32_t *)&vectorSignLen) == CRYPT_SUCCESS);

    /* Compare the results of HiTLS vs. Vector. */
    ASSERT_EQ(signLen, vectorSignLen);
    ASSERT_TRUE(memcmp(vectorSign, sign, signLen) == 0);

EXIT:
    free(sign);
    free(vectorSign);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SIGN_API_TC002
 * @title  ECDSA CRYPT_EAL_PkeySign: Missing private key.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id(P-224), expected result 2
 *    3. Call the CRYPT_EAL_PkeySign method to compute signature,expected result 3
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_ECDSA_ERR_EMPTY_KEY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SIGN_API_TC002(int mdId, Hex *plainText, int isProvider)
{
    uint32_t hitlsSignLen;
    uint8_t *hitlsSign = NULL;
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;

    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ecdsaPkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ecdsaPkey, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Signature */
    hitlsSignLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    hitlsSign = (uint8_t *)malloc(hitlsSignLen);
    ASSERT_TRUE(hitlsSign != NULL);

    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeySign No PrvKey",
        CRYPT_EAL_PkeySign(ecdsaPkey, mdId, plainText->x, plainText->len, hitlsSign, &hitlsSignLen) ==
            CRYPT_ECDSA_ERR_EMPTY_KEY);

EXIT:
    free(hitlsSign);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SIGN_API_TC003
 * @title  ECDSA CRYPT_EAL_PkeySign: Missing private key.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id(P-224) and set private key, expected result 2
 *    3. Call the CRYPT_EAL_PkeySign method to compute signature,expected result 3
 *    4. Mock BN_RandRange to STUB_RandRangeK
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature,expected result 4
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NO_REGIST_RAND
 *    4. CRYPT_ECDSA_ERR_TRY_CNT on randVector is 0, otherwise CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SIGN_API_TC003(
    int mdId, Hex *prvKeyVector, Hex *plainText, Hex *randVector, int result, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    int ret, hitlsSginLen;
    uint8_t *hitlsSign = NULL;
    CRYPT_EAL_PkeyPrv ecdsaPrvkey = {0};

    /* Register memory */
    TestMemInit();

    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ecdsaPkey != NULL);

    /* Set para by curve id and set private key */
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ecdsaPkey, CRYPT_ECC_NISTP256) == CRYPT_SUCCESS);
    Ecc_SetPrvKey(&ecdsaPrvkey, CRYPT_PKEY_ECDSA, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdsaPkey, &ecdsaPrvkey), CRYPT_SUCCESS);

    /* Signature */
    hitlsSginLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    hitlsSign = (uint8_t *)malloc(hitlsSginLen);
    ASSERT_TRUE(hitlsSign != NULL);
    ret = CRYPT_EAL_PkeySign(ecdsaPkey, mdId, plainText->x, plainText->len, hitlsSign, (uint32_t *)&hitlsSginLen);
    ASSERT_EQ(ret, CRYPT_NO_REGIST_RAND);

    /* Take over random numbers. */
    ASSERT_TRUE(memcpy_s(gkRandBuf, sizeof(gkRandBuf), randVector->x, randVector->len) == 0);
    gkRandBufLen = randVector->len;
    
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif

    ret = CRYPT_EAL_PkeySign(ecdsaPkey, mdId, plainText->x, plainText->len, hitlsSign, (uint32_t *)&hitlsSginLen);
    if (result == 1) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        /* Accept either CRYPT_ECDSA_ERR_TRY_CNT or CRYPT_BN_RAND_GEN_FAIL for invalid k values */
        ASSERT_TRUE(ret == CRYPT_ECDSA_ERR_TRY_CNT || ret == CRYPT_BN_RAND_GEN_FAIL);
    }

EXIT:
    free(hitlsSign);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SIGN_DATA_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeySign: Test the validity of parameters.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id(P-224) and set private key, expected result 2
 *    3. Call the CRYPT_EAL_PkeySignData method:
 *       (1) pkey = null, expected result 3
 *       (2) msg = null, msgLen != 0, expected result 3
 *       (3) msg != NULL, msgLen = 0, expected result 3
 *       (4) sign = NULL, signLen != 0, expected result 6
 *       (5) sign != NULL, signLen = NULL, expected result 7
 *       (6) Correct parameters, expected result 8
 *       (7) sign != NULL, signLen = 0, expected result 9
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3-4. CRYPT_ERR_ALGID
 *    5-7. CRYPT_NULL_INPUT
 *    8. CRYPT_NO_REGIST_RAND
 *    9. CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SIGN_DATA_API_TC001(Hex *prvKeyVector, Hex *msg, int isProvider)
{
    uint32_t hitlsSignLen;
    uint8_t *hitlsSign = NULL;
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    CRYPT_EAL_PkeyPrv ecdsaPrvkey = {0};

    TestMemInit();

    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ecdsaPkey != NULL);

    /* Set para by curve id and set private key */
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ecdsaPkey, CRYPT_ECC_NISTP256) == CRYPT_SUCCESS);
    Ecc_SetPrvKey(&ecdsaPrvkey, CRYPT_PKEY_ECDSA, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdsaPkey, &ecdsaPrvkey), CRYPT_SUCCESS);

    /* Signature */
    hitlsSignLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    hitlsSign = (uint8_t *)malloc(hitlsSignLen);
    ASSERT_TRUE(hitlsSign != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySignData(NULL, msg->x, msg->len, hitlsSign, &hitlsSignLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ecdsaPkey, NULL, msg->len, hitlsSign, &hitlsSignLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ecdsaPkey, msg->x, 0, hitlsSign, &hitlsSignLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ecdsaPkey, msg->x, msg->len, NULL, &hitlsSignLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ecdsaPkey, msg->x, msg->len, hitlsSign, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ecdsaPkey, msg->x, msg->len, hitlsSign, &hitlsSignLen), CRYPT_NO_REGIST_RAND);
    hitlsSignLen = 0;
    ASSERT_EQ(
        CRYPT_EAL_PkeySignData(ecdsaPkey, msg->x, msg->len, hitlsSign, &hitlsSignLen), CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH);

EXIT:
    free(hitlsSign);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_CTRL_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyCtrl: Test the validity of opt.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl method:
 *       (1) opt = CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, expected result 2
 *       (2) opt = CRYPT_CTRL_SET_ECC_POINT_FORMAT, expected result 3
 *       (3) opt = CRYPT_CTRL_SET_ECC_USE_COFACTOR_MODE, expected result 4
 *       (4) opt = CRYPT_CTRL_SET_SM2_USER_ID, expected result 5
 *       (5) opt = CRYPT_CTRL_SET_RSA_PADDING, expected result 6
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_ECDSA_ERR_UNSUPPORTED_CTRL_OPTION
 *    5. CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION
 *    6. CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_CTRL_API_TC001(int type, int expect)
{
    ASSERT_TRUE(EAL_PkeyCtrl_Api_TC001(CRYPT_PKEY_ECDSA, type, expect) == SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_CTRL_API_TC002
 * @title  ECDSA CRYPT_EAL_PkeyCtrl: Test the validity of pkey and value.
 * @precon nan
 * @brief
 *    1. Create the context of the ECDSA algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl method:
 *       (1) pkey = null, expected result 2
 *       (2) val = null, len = 0, expected result 3
 *       (3) val = null, len != 0, expected result 4
 *       (4) val != null, len = 0, expected result 5
 *       (5) PointFormat = CRYPT_POINT_MAX, expected result 6
 *       (6) PointFormat = CRYPT_POINT_COMPRESSED, expected result 7
 *       (7) PointFormat = CRYPT_POINT_UNCOMPRESSED, expected result 8
 *       (8) PointFormat = CRYPT_POINT_HYBRID, expected result 9
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-4. CRYPT_NULL_INPUT
 *    5. CRYPT_ECC_PKEY_ERR_CTRL_LEN
 *    6. CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT
 *    7-9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_CTRL_API_TC002(void)
{
    ASSERT_TRUE(EAL_PkeyCtrl_Api_TC002(CRYPT_PKEY_ECDSA) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_CTRL_API_TC003
 * @title  ECDSA CRYPT_EAL_PkeyCtrl: Test the effect of the point format on the key.
 * @precon public key point
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the para by eccId(p-192/224/256/384/512, bp256r1/384r1/512/r1), expected result 2
 *    3. Convert the format of the public key vector to COMPRESSED, expected result 3
 *    4. Set the public key, expected result 4
 *    5. Call the CRYPT_EAL_PkeyCtrl method to set point format to COMPRESSED, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCtrl method to set point format to HYBRID, expected result 6
 *    7. Get the public key, expected result 7
 *    8. Convert the format of the public key vector to HYBRID, expected result 8
 *    9. Compare the output of the preceding two steps, expected result 9
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-7. CRYPT_SUCCESS
 *    9. The two are same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_CTRL_API_TC003(int eccId, Hex *pubKeyX, Hex *pubKeyY)
{
    ASSERT_TRUE(EAL_PkeyCtrl_Api_TC003(CRYPT_PKEY_ECDSA, eccId, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_GET_PRV_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyGetPrv: Test the validity of parameters.
 * @precon private key
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the para by eccId(p-224), expected result 2
 *    3. Get the private key when there is no private key, expected result 3
 *    4. Set the private key, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGetPrv method:
 *       (1) pkey = null, expected result 5
 *       (2) prv = null, expected result 6
 *       (3) pkey.id != prv.id, expected result 7
 *       (4) Correct parameters, expected result 8
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_ECC_PKEY_ERR_EMPTY_KEY
 *    4. CRYPT_SUCCESS
 *    5-6. CRYPT_NULL_INPUT
 *    7. CRYPT_EAL_ERR_ALGID
 *    8. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_GET_PRV_API_TC001(Hex *prvKey)
{
    ASSERT_TRUE(EAL_PkeyGetPrv_Api_TC001(CRYPT_PKEY_ECDSA, prvKey) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_GET_PUB_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyGetPub: Test the validity of parameters.
 * @precon public key point
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the para by eccId(p-224), expected result 2
 *    3. Get the public key when there is no public key, expected result 3
 *    4. Set the public key, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) pkey = null, expected result 5
 *       (2) pub = null, expected result 6
 *       (3) pkey.id != pub.id, expected result 7
 *       (4) Correct parameters, expected result 8
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_ECC_PKEY_ERR_EMPTY_KEY
 *    4. CRYPT_SUCCESS
 *    5-6. CRYPT_NULL_INPUT
 *    7. CRYPT_EAL_ERR_ALGID
 *    8. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_GET_PUB_API_TC001(Hex *pubKeyX, Hex *pubKeyY)
{
    ASSERT_TRUE(EAL_PkeyGetPub_Api_TC001(CRYPT_PKEY_ECDSA, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PRV_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeySetPrv: Test the validity of parameters.
 * @precon Prepare valid private key and invalid private key.
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the the valid private key before setting the curve, expected result 2
 *    3. Set the para by eccId(p-224), expected result 3
 *    4. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) pkey = null, expected result 4
 *       (2) prv = null, expected result 5
 *       (3) pkey.id != prv.id, expected result 6
 *       (4) Set the valid private key, expected result 7
 *       (5) Set the invalid private key, expected result 8
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_SUCCESS
 *    4-5. CRYPT_NULL_INPUT
 *    6. CRYPT_EAL_ERR_ALGID
 *    7. CRYPT_SUCCESS
 *    8. CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PRV_API_TC001(Hex *prvKey, Hex *errorPrvKey)
{
    ASSERT_TRUE(EAL_PkeySetPrv_Api_TC001(CRYPT_PKEY_ECDSA, prvKey, errorPrvKey) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PRV_API_TC002
 * @title  Check whether the public key is cleared when the private key is set.
 * @precon private key, public key point
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the para by eccId(p-224), expected result 2
 *    3. Set the the public key, expected result 3
 *    4. Set the the private key, expected result 4
 *    5. Get the the public key, expected result 5
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-5. CRYPT_SUCCESSY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PRV_API_TC002(Hex *prvKey, Hex *pubKeyX, Hex *pubKeyY)
{
    ASSERT_TRUE(EAL_PkeySetPrv_Api_TC002(CRYPT_PKEY_ECDSA, prvKey, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PUB_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeySetPub: Test the validity of parameters.
 * @precon Prepare valid public key.
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the the public key before setting the curve, expected result 2
 *    3. Set the para by eccId(p-224), expected result 3
 *    4. Call the CRYPT_EAL_PkeySetPub method:
 *       (1) pkey = null, expected result 4
 *       (2) pub = null, expected result 5
 *       (3) pkey.id != pub.id, expected result 6
 *       (4) Set the valid public key, expected result 7
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_SUCCESS
 *    4-5. CRYPT_NULL_INPUT
 *    6. CRYPT_EAL_ERR_ALGID
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PUB_API_TC001(Hex *pubKeyVector)
{
    ASSERT_TRUE(EAL_PkeySetPub_Api_TC001(CRYPT_PKEY_ECDSA, pubKeyVector) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PUB_API_TC002
 * @title  Check whether the private key is cleared when the public key is set.
 * @precon public key, private key
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the para by eccId(p-224), expected result 2
 *    3. Set the the private key, expected result 3
 *    4. Set the the public key, expected result 4
 *    5. Get the the private key, expected result 5
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-5. CRYPT_SUCCESSY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PUB_API_TC002(Hex *prvKey, Hex *pubKey)
{
    ASSERT_TRUE(EAL_PkeySetPub_Api_TC002(CRYPT_PKEY_ECDSA, prvKey, pubKey) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PUB_API_TC003
 * @title  Test the function of setting public keys of different lengths.
 * @precon Public keys of different lengths.
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the para by eccId(p-192/224/256/384/512, bp256r1/384r1/512/r1), expected result 2
 *    3. Set public keys of different lengths, expected result 3
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESSY
 *    3. CRYPT_ECC_ERR_POINT_CODE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PUB_API_TC003(int eccId, Hex *pubKey, Hex *errorPubKey, int isProvider)
{
    ASSERT_TRUE(EAL_PkeySetPub_Api_TC003(CRYPT_PKEY_ECDSA, eccId, pubKey, errorPubKey, isProvider) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_GET_PARA_ID_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyGetParaId test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Get para id before creating context, expected result 1
 *    2. Create the context of the ECDSA algorithm, expected result 2
 *    3. Set para id(p-192/224/256/384/512), expected result 3
 *    4. Get para id, expected result 4
 * @expect
 *    1. CRYPT_PKEY_PARAID_MAX
 *    2. Success, and the context is not NULL.
 *    3. CRYPT_SUCCESS
 *    4. The obtained id is the same as the set id.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_GET_PARA_ID_API_TC001(int id)
{
    ASSERT_TRUE(EAL_PkeyGetParaId_Api_TC001(CRYPT_PKEY_ECDSA, id) == 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_CMP_FUNC_TC001
 * @title  ECDSA: CRYPT_EAL_PkeyCmp test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the ecdsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 2
 *    3. Set para id CRYPT_ECC_NISTP224 and public key for ctx1, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 4
 *    5. Set para id CRYPT_ECC_NISTP256 for ctx2, expected result 5
 *    6. Set public key for ctx2, expected result 6
 *    7. Set para id CRYPT_ECC_NISTP224 and public key for ctx2, expected result 7
 *    8. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 8
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_ECC_ERR_POINT_CODE
 *    7. CRYPT_SUCCESS
 *    8. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_CMP_FUNC_TC001(Hex *pubKeyX, Hex *pubKeyY)
{
    ASSERT_TRUE(EAL_PkeyCmp_Api_TC001(CRYPT_PKEY_ECDSA, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_VERIFY_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyVerify: Test the validity of parameters.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id(P-224), expected result 2
 *    3. Verify when there is no public key, expected result 3
 *    4. Set public key, expected result 4
 *    5. Call the CRYPT_EAL_PkeyVerify method:
 *       (1) pkey = null, expected result 5
 *       (2) data = null, dataLen != 0, expected result 6
 *       (3) data = null or data != null, and dataLen = 0, expected result 7
 *       (4) sign = null, signLen != 0 or signLen = 0, expected result 8
 *       (5) sign != null, signLen = 0, expected result 9
 *       (6) sign != null, signLen = 1, expected result 10
 *       (7) Correct parameters, expected result 11
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_ECDSA_ERR_EMPTY_KEY
 *    4. CRYPT_SUCCESS
 *    5-6. CRYPT_NULL_INPUT
 *    7. CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH
 *    8-9. CRYPT_NULL_INPUT
 *    10. CRYPT_DSA_DECODE_FAIL
 *    11. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_VERIFY_API_TC001(Hex *data, Hex *pubKeyX, Hex *pubKeyY, Hex *sign, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub ecdsaPubkey;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};
    CRYPT_MD_AlgId mdId = CRYPT_MD_SHA224;

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("New ECDSA Pkey", pkey != NULL);

    /* Set para by curve id. */
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_ECC_NISTP224), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("EccPointToBuffer", EccPointToBuffer(pubKeyX, pubKeyY, 1, &pubKeyVector) == CRYPT_SUCCESS);

    /* Verify when there is no public key. */
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(pkey, mdId, data->x, data->len, sign->x, sign->len) == CRYPT_ECDSA_ERR_EMPTY_KEY);

    /* Set public key. */
    Ecc_SetPubKey(&ecdsaPubkey, CRYPT_PKEY_ECDSA, pubKeyVector.data, pubKeyVector.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &ecdsaPubkey), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyVerify. */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(NULL, mdId, data->x, data->len, sign->x, sign->len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, NULL, data->len, sign->x, sign->len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, NULL, 0, sign->x, sign->len), CRYPT_ECDSA_VERIFY_FAIL);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data->x, 0, sign->x, sign->len), CRYPT_ECDSA_VERIFY_FAIL);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data->x, data->len, NULL, sign->len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data->x, data->len, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data->x, data->len, sign->x, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data->x, data->len, sign->x, 1), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data->x, data->len, sign->x, sign->len), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SIGN_VERIFY_FUNC_TC002
 * @title  ED25519 sets the keys and performs signature and verifiy tests on the hash data.
 * @precon nan
 * @brief
 *    1. Create context(ecdsaPkey) of the ECDSA algorithm, expected result 1
 *    2. Set elliptic curve type, private key, expected result 2
 *    3. Take over random numbers, mock BN_RandRange to generate randVector.
 *    4. Sign the hash data(all 0x00 or all 0xFF) using ecdsaPkey, expected result 3
 *    5. Reset the stubbed function.
 *    6. Create context(ecdsaPkey2) of the ECDSA algorithm, expected result 4
 *    7. Set elliptic curve type, public key, expected result 5
 *    9. Verify the signature by ecdsaPkey2, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Success, and context is not NULL.
 *    5-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SIGN_VERIFY_FUNC_TC002(int eccId, Hex *prvKeyVector, Hex *hashData,
    Hex *randVector, Hex *pubKeyX, Hex *pubKeyY, int pointFormat, int isProvider)
{
    uint32_t hitlsSignLen;
    uint8_t *hitlsSign = NULL;
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    CRYPT_EAL_PkeyCtx *ecdsaPkey2 = NULL;
    CRYPT_EAL_PkeyPrv ecdsaPrvkey = {0};
    CRYPT_EAL_PkeyPub ecdsaPubkey;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};

    /* Register memory */
    TestMemInit();

    /* Create an ECDSA context for signing*/
    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ecdsaPkey != NULL);

    /* Set para by curve id and set private key */
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeySetParaById", CRYPT_EAL_PkeySetParaById(ecdsaPkey, eccId) == CRYPT_SUCCESS);
    Ecc_SetPrvKey(&ecdsaPrvkey, CRYPT_PKEY_ECDSA, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdsaPkey, &ecdsaPrvkey), CRYPT_SUCCESS);

    /* Take over random numbers. */
    ASSERT_TRUE(memcpy_s(gkRandBuf, sizeof(gkRandBuf), randVector->x, randVector->len) == 0);
    gkRandBufLen = randVector->len;
    
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif

    /* Sign hash data */
    hitlsSignLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    hitlsSign = (uint8_t *)malloc(hitlsSignLen);
    ASSERT_TRUE(hitlsSign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ecdsaPkey, hashData->x, hashData->len, hitlsSign, &hitlsSignLen), CRYPT_SUCCESS);

    /* Reset the stubbed function */

    /* Create an ESA context for signature verification. */
    ecdsaPkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyNewCtx", ecdsaPkey2 != NULL);

    /* Set para by curve id and set public key */
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeySetParaById", CRYPT_EAL_PkeySetParaById(ecdsaPkey2, eccId) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG(
        "EccPointToBuffer", EccPointToBuffer(pubKeyX, pubKeyY, pointFormat, &pubKeyVector) == CRYPT_SUCCESS);
    Ecc_SetPubKey(&ecdsaPubkey, CRYPT_PKEY_ECDSA, pubKeyVector.data, pubKeyVector.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ecdsaPkey2, &ecdsaPubkey), CRYPT_SUCCESS);

    /* Verify hash data */
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ecdsaPkey2, hashData->x, hashData->len, hitlsSign, hitlsSignLen), CRYPT_SUCCESS);

EXIT:
    free(hitlsSign);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_VERIFY_DATA_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyVerifyData: Test the validity of parameters.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id, expected result 2
 *    3. Verify when there is no public key, expected result 3
 *    4. Set public key, expected result 4
 *    5. Call the CRYPT_EAL_PkeyVerify method:
 *       (1) pkey = null, expected result 5
 *       (2) data = null, dataLen != 0 || data != null, dataLen == 0 expected result 5
 *       (3) sign = null, signLen != 0 or signLen = 0, expected result 8
 *       (4) sign != null, signLen = 0, expected result 9
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_ECDSA_ERR_EMPTY_KEY
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_INVALID_ARG
 *    6-9. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_VERIFY_DATA_API_TC001(
    int paraId, Hex *hashData, Hex *pubKeyX, Hex *pubKeyY, Hex *sign, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub ecdsaPubkey;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    /* Set para by curve id */
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraId), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("EccPointToBuffer", EccPointToBuffer(pubKeyX, pubKeyY, 1, &pubKeyVector) == CRYPT_SUCCESS);

    ASSERT_TRUE(
        CRYPT_EAL_PkeyVerifyData(pkey, hashData->x, hashData->len, sign->x, sign->len) == CRYPT_ECDSA_ERR_EMPTY_KEY);

    /* Set public key */
    Ecc_SetPubKey(&ecdsaPubkey, CRYPT_PKEY_ECDSA, pubKeyVector.data, pubKeyVector.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &ecdsaPubkey), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyVerifyData. */
    ASSERT_TRUE(CRYPT_EAL_PkeyVerifyData(NULL, hashData->x, hashData->len, sign->x, sign->len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerifyData(pkey, NULL, hashData->len, sign->x, sign->len) == CRYPT_INVALID_ARG);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerifyData(pkey, hashData->x, 0, sign->x, sign->len) == CRYPT_INVALID_ARG);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerifyData(pkey, hashData->x, hashData->len, NULL, sign->len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerifyData(pkey, hashData->x, hashData->len, NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerifyData(pkey, hashData->x, hashData->len, sign->x, 0) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_GET_SECURITY_BITS_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyGetSecurityBits: Test the validity of parameters.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id, expected result 2
 *    3. Call the CRYPT_EAL_PkeyVerify method and set the parameter to null, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method and the parameter is correct, expected result 4
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. The return value is 0.
 *    4. The return value is not 0.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_GET_SECURITY_BITS_API_TC001(int paraId, int securitybits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    /* Create an ECDSA context */
    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("New ECDSA Pkey", ecdsaPkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdsaPkey, paraId), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyGetSecurityBits. */
    ASSERT_TRUE(CRYPT_EAL_PkeyGetSecurityBits(NULL) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetSecurityBits(ecdsaPkey) == (uint32_t)securitybits);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_GET_KEY_BITS_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeyGetKeyBits: Test the validity of parameters.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set para by curve id, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetKeyBits method and set the parameter to null, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGetKeyBits method and the parameter is correct, expected result 4
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. The return value is 0.
 *    4. The return value is not 0.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_GET_KEY_BITS_API_TC001(int paraId, int keyBitsLen, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    /* Create an ECDSA context */

    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("New ECDSA Pkey", ecdsaPkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdsaPkey, paraId), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyGetKeyBits. */
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(NULL) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(ecdsaPkey) == (uint32_t)keyBitsLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PARA_API_TC001
 * @title  ECDSA CRYPT_EAL_PkeySetPara: Test the validity of parameters.
 * @precon Prepare valid private key and invalid private key.
 * @brief
 *    1. Create the context of the ecdsa algorithm, expected result 1
 *    2. Set the para by eccId, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetPara method:
 *       (1) pkey = null, expected result 3
 *       (2) para = null, expected result 4
 *       (3) pkey.id != para.id, expected result 5
 *       (4) The parameter structure is empty, expected result 6
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3-4. CRYPT_NULL_INPUT
 *    5. CRYPT_EAL_ERR_ALGID
 *    6. CRYPT_EAL_ERR_NEW_PARA_FAIL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PARA_API_TC001(int paraId, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraId), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeySetPara. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(NULL, &para), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, NULL), CRYPT_NULL_INPUT);
    para.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_EAL_ERR_ALGID);
    para.id = CRYPT_PKEY_ECDSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SIGN_VERIFY_FUNC_TC001
 * @title  ECDSA sign and verify test: different hash and curve.
 * @precon nan
 * @brief
 *    1. Init the drbg, expected result 1
 *    2. Create context(ecdsaPkey) of the ECDSA algorithm, expected result 2
 *    3. Set elliptic curve type, private key and public key, expected result 3
 *    4. Take over random numbers, mock BN_RandRange to generate randVector.
 *    5. Compute the signature by ecdsaPkey, expected result 4
 *    6. Compares the hitls signature, expected result 5
 *    7. Verify the signature by ecdsaPkey, expected result 6
 *    8. Call the CRYPT_EAL_PkeyCopyCtx method to copy the context, expected result 7
 *    9. Use the copied context for signing and verification, expected result 8
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. Both are the same.
 *    6-8. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SIGN_VERIFY_FUNC_TC001(int eccId, int mdId, Hex *prvKeyVector, Hex *msg, Hex *signR, Hex *signS,
    Hex *randVector, Hex *pubKeyX, Hex *pubKeyY, int pointFormat, int isProvider)
{
    if (IsCurveDisabled(eccId) || IsMdAlgDisabled(mdId)) {
        SKIP_TEST();
    }
    int ret, vectorSignLen, hitlsSginLen;
    uint8_t *vectorSign = NULL;
    uint8_t *hitlsSign = NULL;
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    CRYPT_EAL_PkeyPrv ecdsaPrvkey = {0};
    CRYPT_EAL_PkeyPub ecdsaPubkey;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("New ECDSA Pkey", ecdsaPkey != NULL);

    /* Set para by curve id */
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdsaPkey, eccId), CRYPT_SUCCESS);
    /* Set private key */
    Ecc_SetPrvKey(&ecdsaPrvkey, CRYPT_PKEY_ECDSA, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdsaPkey, &ecdsaPrvkey), CRYPT_SUCCESS);
    /* Set public key */
    ret = EccPointToBuffer(pubKeyX, pubKeyY, pointFormat, &pubKeyVector);
    ASSERT_TRUE_AND_LOG("EccPointToBuffer", ret == CRYPT_SUCCESS);
    Ecc_SetPubKey(&ecdsaPubkey, CRYPT_PKEY_ECDSA, pubKeyVector.data, pubKeyVector.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ecdsaPkey, &ecdsaPubkey), CRYPT_SUCCESS);

    /* Take over random numbers. */
    ASSERT_TRUE(memcpy_s(gkRandBuf, sizeof(gkRandBuf), randVector->x, randVector->len) == 0);
    gkRandBufLen = randVector->len;
    
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif

    /* Signature */
    hitlsSginLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    hitlsSign = (uint8_t *)malloc(hitlsSginLen);
    ASSERT_TRUE(hitlsSign != NULL);
    ret = CRYPT_EAL_PkeySign(ecdsaPkey, mdId, msg->x, msg->len, hitlsSign, (uint32_t *)&hitlsSginLen);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeySign", ret == CRYPT_SUCCESS);

    /* Encode the R and S of the vector. */
    vectorSignLen = CRYPT_EAL_PkeyGetSignLen(ecdsaPkey);
    vectorSign = (uint8_t *)malloc(vectorSignLen);
    ASSERT_TRUE(vectorSign != NULL);
    ret = SignEncode(signR, signS, vectorSign, (uint32_t *)&vectorSignLen);
    ASSERT_TRUE_AND_LOG("SignEncode", ret == CRYPT_SUCCESS);

    /* Compare the results of HiTLS vs. Vector. */
    ASSERT_EQ(hitlsSginLen, vectorSignLen);
    ASSERT_TRUE(memcmp(vectorSign, hitlsSign, hitlsSginLen) == 0);


    /* Verify */
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ecdsaPkey, mdId, msg->x, msg->len, hitlsSign, hitlsSginLen) == CRYPT_SUCCESS);

    /* Copy the contexts: sign and verify */
    cpyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, ecdsaPkey), CRYPT_SUCCESS);
    hitlsSginLen = CRYPT_EAL_PkeyGetSignLen(cpyCtx);
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, mdId, msg->x, msg->len, hitlsSign, (uint32_t *)&hitlsSginLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, mdId, msg->x, msg->len, hitlsSign, hitlsSginLen), CRYPT_SUCCESS);

EXIT:
    free(hitlsSign);
    free(vectorSign);
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    TestRandDeInit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_SET_PUB_FUNC_TC001
 * @title  Test set public key.
 * @precon nan
 * @brief
 *    1. Init the drbg, expected result 1
 *    2. Create context(ecdsaPkey) of the ECDSA algorithm, expected result 2
 *    3. Set elliptic curve type, private key and public key, expected result 3
 *    4. Convert the format of the public key vector to COMPRESSED, expected result 4
 *    5. Call the CRYPT_EAL_PkeySetPub to set public key, expected result 5
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. Success, and context is not NULL.
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS on result=1
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_SET_PUB_FUNC_TC001(
    int eccId, Hex *publicX, Hex *publicY, int result, int pointFormat, int isProvider)
{
    if (IsCurveDisabled(eccId)) {
        SKIP_TEST();
    }
    int ret;
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    CRYPT_EAL_PkeyPub ECDSAPubkey;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("New ECDSA Pkey", ecdsaPkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdsaPkey, eccId), CRYPT_SUCCESS);

    ret = EccPointToBuffer(publicX, publicY, pointFormat, &pubKeyVector);
    ASSERT_TRUE_AND_LOG("EccPointToBuffer", ret == CRYPT_SUCCESS);
    Ecc_SetPubKey(&ECDSAPubkey, CRYPT_PKEY_ECDSA, pubKeyVector.data, pubKeyVector.len);
    if (result == 1) {
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(ecdsaPkey, &ECDSAPubkey), CRYPT_SUCCESS);
    } else {
        ASSERT_NE(CRYPT_EAL_PkeySetPub(ecdsaPkey, &ECDSAPubkey), CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_GET_PARA_FUNC_TC001
 * @title  ECD CRYPT_EAL_PkeyGetPara test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create context of the ECDSA algorithm, expected result 1
 *    2. Set para, expected result 2
 *    3. Get para, expected result 3
 *    4. Check whether the set parameters and the obtained parameters are the same, expected result 4
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. The parameters are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_GET_PARA_FUNC_TC001(Hex *p, Hex *a, Hex *b, Hex *x, Hex *y, Hex *n, Hex *h)
{
    ASSERT_TRUE(EAL_PkeyGetPara_Func_TC001(CRYPT_PKEY_ECDSA, p, a, b, x, y, n, h) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_GEN_KEY_FUNC_TC001
 * @title  ECDSA CRYPT_EAL_PkeyGen test.
 * @precon nan
 * @brief
 *    1. Create context of the ECDSA algorithm, expected result 1
 *    2. Set elliptic curve type, expected result 2
 *    3. Mock BN_RandRange to STUB_RandRangeK
 *    4. Init the drbg, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGen method to generate a key pair, expected result 5
 *    6. Get public key and private key, expected result 6
 *    7. Compare the getted key and vector, expected result 7
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. non
 *    4-6. CRYPT_SUCCESS
 *    7. The getted key and vector are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_GEN_KEY_FUNC_TC001(
    int eccId, Hex *prvKeyVector, Hex *pubKeyX, Hex *pubKeyY, int pointFormat, int isProvider)
{
    if (IsCurveDisabled(eccId)) {
        SKIP_TEST();
    }
    Ecc_GenKey(CRYPT_PKEY_ECDSA, eccId, prvKeyVector, pubKeyX, pubKeyY, pointFormat, isProvider);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_KEY_PAIR_CHECK_FUNC_TC001
 * @title  ECDSA: key pair check.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(pubCtx, prvCtx) of the ecdsa algorithm, expected result 1
 *    2. Init the drbg, expected result 2
 *    3. Set para for pubCtx, expected result 3
 *    4. Set public key for pubCtx, expected result 4
 *    5. Set para and private key for prvCtx, expected result 5
 *    6. Check whether the public key matches the private key, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. Return CRYPT_SUCCESS when expect is 1, CRYPT_ECDSA_VERIFY_FAIL otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_KEY_PAIR_CHECK_FUNC_TC001(
    int eccId, Hex *prvKeyVector, Hex *pubKeyX, Hex *pubKeyY, int pointFormat, int expect)
{
#if !defined(HITLS_CRYPTO_ECDSA_CHECK)
    (void)eccId;
    (void)prvKeyVector;
    (void)pubKeyX;
    (void)pubKeyY;
    (void)pointFormat;
    (void)expect;
    SKIP_TEST();
#else
    if (IsCurveDisabled(eccId)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};
    int expectRet = expect == 1 ? CRYPT_SUCCESS : CRYPT_ECDSA_PAIRWISE_CHECK_FAIL;

    ASSERT_EQ(EccPointToBuffer(pubKeyX, pubKeyY, pointFormat, &pubKeyVector), CRYPT_SUCCESS);
    Ecc_SetPubKey(&pub, CRYPT_PKEY_ECDSA, pubKeyVector.data, pubKeyVector.len);
    Ecc_SetPrvKey(&prv, CRYPT_PKEY_ECDSA, prvKeyVector->x, prvKeyVector->len);

    TestMemInit();
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    /* pubCtx*/
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, eccId), CRYPT_SUCCESS);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pub), CRYPT_SUCCESS);

    /* prvCtx*/
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, eccId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), expectRet);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ECDSA_API_TC026
* @title ECDSA get key length
* @brief
1.create ECDSA context. Expect result 1
2.set curve,expect result 2
3.get key length, expect result 3
* @expect  1.context created successfully
2.Success
3.Success
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_API_TC026(int paraId, int keyLen, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdsaPkey, paraId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(ecdsaPkey), keyLen);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_GETSECURITYBITS_API_TC001
 * @title  Get security bits test
 * @brief
 *    1. Create context of the ECDSA algorithm, expected result 1
 *    2. Set curve type, expected result 2
 *    3. Get para, expected result 3
 *    4. Obtain security bits are the same, expected result 4
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. The security bits are correct.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_GETSECURITYBITS_API_TC001(int eccId, Hex *prvKeyVector, int secBits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *ecdsaPkey = NULL;
    CRYPT_EAL_PkeyPrv ecdsaPrvkey = {0};

    ecdsaPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("New ECDH Pkey", ecdsaPkey != NULL);
    // Set elliptic curve type CRYPT_ECC_NISTP224 = 13
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdsaPkey, eccId), CRYPT_SUCCESS);
    // Set private key
    ecdsaPrvkey.id = CRYPT_PKEY_ECDSA;
    ecdsaPrvkey.key.eccPrv.data = prvKeyVector->x;
    ecdsaPrvkey.key.eccPrv.len = prvKeyVector->len;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdsaPkey, &ecdsaPrvkey), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetSecurityBits(ecdsaPkey) == (uint32_t)secBits);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ecdsaPkey);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_CHECK_KEYPAIR_FUNC_TC001
 * @title  ECDSA CRYPT_EAL_PkeyPairCheck test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_CHECK_KEYPAIR_FUNC_TC001(int paraid, int isProvider)
{
#if !defined(HITLS_CRYPTO_ECDSA_CHECK)
    (void)paraid;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    uint8_t wrong[KEY_MAX_LEN] = {1};
    CRYPT_EAL_PkeyPub ecdsaPubKey = {0};
    CRYPT_EAL_PkeyPrv ecdsaPrvKey = {0};

    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};
    KeyData prvKeyVector = {{0}, KEY_MAX_LEN};
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(pubCtx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, paraid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, paraid), CRYPT_SUCCESS);

    Ecc_SetPubKey(&ecdsaPubKey, CRYPT_PKEY_ECDSA, pubKeyVector.data, pubKeyVector.len);
    Ecc_SetPrvKey(&ecdsaPrvKey, CRYPT_PKEY_ECDSA, prvKeyVector.data, prvKeyVector.len);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pkey, pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &ecdsaPubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &ecdsaPrvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &ecdsaPubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &ecdsaPrvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SUCCESS);

    ecdsaPrvKey.key.eccPrv.data = wrong;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &ecdsaPrvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_ECDSA_PAIRWISE_CHECK_FAIL);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDSA_CHECK_PRVKEY_FUNC_TC001
 * @title  ECDSA CRYPT_EAL_PkeyPrvCheck test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_CHECK_PRVKEY_FUNC_TC001(int paraid, int isProvider)
{
#if !defined(HITLS_CRYPTO_ECDSA_CHECK)
    (void)paraid;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_EAL_PkeyPrv ecdsaPrvKey = {0};
    CRYPT_ECDSA_Ctx *ctx = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *prvKey = NULL;

    KeyData prvKeyVector = {{0}, KEY_MAX_LEN};
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, paraid), CRYPT_SUCCESS);

    Ecc_SetPrvKey(&ecdsaPrvKey, CRYPT_PKEY_ECDSA, prvKeyVector.data, prvKeyVector.len);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ctx = (CRYPT_ECDSA_Ctx *)pkey->key;
    prvKey = ctx->prvkey;
    n = ECC_GetParaN(ctx->para);

    (void)BN_Copy(prvKey, n);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_ECDSA_INVALID_PRVKEY);

    (void)BN_SubLimb(prvKey, prvKey, 1); // key = n - 1
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    (void)BN_Zeroize(prvKey); // key = 0
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_ECDSA_INVALID_PRVKEY);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BN_Destroy(n);
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
static int32_t ImportEcdsaPkey(const BSL_Param *param, void *args)
{
    CRYPT_ECDSA_Ctx *importEcdsaCtx = CRYPT_ECDSA_NewCtx();
    if (importEcdsaCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_ECDSA_Import(importEcdsaCtx, param);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ECDSA_FreeCtx(importEcdsaCtx);
        return ret;
    }
    *((CRYPT_ECDSA_Ctx **)args) = importEcdsaCtx;
    return CRYPT_SUCCESS;
}
#endif

/**
 * @test   SDV_CRYPTO_ECDSA_Import_Export_FUNC_TC001
 * @title  ECDSA CRYPT_ECDSA_Import and CRYPT_ECDSA_Export test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDSA_Import_Export_FUNC_TC001(void)
{
#ifndef HITLS_CRYPTO_KEY_DECODE_CHAIN
    SKIP_TEST();
#else
    CRYPT_ECDSA_Ctx *srcEcdsaCtx = NULL;
    CRYPT_ECDSA_Ctx *dstEcdsaCtx = NULL;
    CRYPT_PKEY_ParaId eccId = CRYPT_ECC_NISTP256;
    uint8_t msg[2] = {1, 2};
    uint8_t sign[130];
    uint32_t signLen = sizeof(sign);
    BSL_Param param[3] = {
        {CRYPT_PARAM_PKEY_PROCESS_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ImportEcdsaPkey, 0, 0},
        {CRYPT_PARAM_PKEY_PROCESS_ARGS, BSL_PARAM_TYPE_CTX_PTR, &dstEcdsaCtx, 0, 0},
        BSL_PARAM_END
    };
    
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    srcEcdsaCtx = CRYPT_ECDSA_NewCtx();
    ASSERT_TRUE(srcEcdsaCtx != NULL);
    CRYPT_ECDSA_Ctrl(srcEcdsaCtx, CRYPT_CTRL_SET_PARA_BY_ID, &eccId, sizeof(CRYPT_PKEY_ParaId));
    ASSERT_EQ(CRYPT_ECDSA_Gen(srcEcdsaCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDSA_Export(srcEcdsaCtx, param), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_ECDSA_Sign(srcEcdsaCtx, CRYPT_MD_SHA256, msg, sizeof(msg), sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_ECDSA_Verify(dstEcdsaCtx, CRYPT_MD_SHA256, msg, sizeof(msg), sign, signLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_ECDSA_FreeCtx(srcEcdsaCtx);
    CRYPT_ECDSA_FreeCtx(dstEcdsaCtx);
#endif
}
/* END_CASE */
