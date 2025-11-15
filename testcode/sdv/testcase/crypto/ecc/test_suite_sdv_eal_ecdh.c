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
#include "crypt_ecc.h"
#include "ecc_local.h"
/* END_HEADER */
#define ECDH_MAX_BIT_LEN 521

/**
 * @test   SDV_CRYPTO_ECDH_NEW_CTX_API_TC001
 * @title  ECDH CRYPT_EAL_PkeyNewCtx test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create a pkey structure, algId is CRYPT_PKEY_ECDH, expected result 1
 *    2. Releases the pkey structure, expected result 2
 * @expect
 *    1. Success, and the structure is not NULL.
 *    2. No memory leakage occurs.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_NEW_CTX_API_TC001(void)
{
    ASSERT_TRUE(EAL_PkeyNewCtx_Api_TC001(CRYPT_PKEY_ECDH) == SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_SET_PARA_BY_ID_API_TC001
 * @title  ECDH CRYPT_EAL_PkeySetParaById: Test the validity of input parameters.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
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
void SDV_CRYPTO_ECDH_SET_PARA_BY_ID_API_TC001(void)
{
    ASSERT_TRUE(EAL_PkeySetParaById_Api_TC001(CRYPT_PKEY_ECDH) == SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_EXCH_API_TC001
 * @title  ECDH CRYPT_EAL_PkeyComputeShareKey: Test the validity of parameters.
 * @precon Registering memory-related functions.
 *         Test Vectors for ECDH : public key, private key, share secret
 * @brief
 *    1. Create two contexts(ecdhPkey, ecdhPkey2, peerEcdhPkey) of the ECDH algorithm, expected result 1
 *    2. ecdhPkey: Set elliptic curve type and private key, expected result 2
 *    3. peerEcdhPkey: Set elliptic curve type and public key, expected result 3
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method before init the drbg, expected result 4:
 *    5. Call the CRYPT_EAL_PkeyComputeShareKey method:
 *       (1) pkey = NULL, expected result 5
 *       (2) pubPkey = NULL, expected result 6
 *       (3) share = NULL, shareLen != 0, expected result 7
 *       (4) share != NULL, shareLen = NULL, expected result 8
 *       (5) share != NULL, shareLen = 1, expected result 9
 *       (6) all parameters are valid, but the local ctx does not have a private key, expected result 10
 *       (7) pkey.id != pubPkey.id, expected result 11
 *       (8) all parameters are valid, expected result 12
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_NO_REGIST_RAND
 *    5-8. CRYPT_NULL_INPUT
 *    9. CRYPT_ECC_BUFF_LEN_NOT_ENOUGH
 *    10. CRYPT_ECDH_ERR_EMPTY_KEY
 *    11. CRYPT_EAL_ERR_ALGID
 *    12. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_EXCH_API_TC001(Hex *prvKeyVector, Hex *peerPubKeyVector, Hex *shareKeyVector)
{
    CRYPT_EAL_PkeyCtx *ecdhPkey = NULL;
    CRYPT_EAL_PkeyCtx *ecdhPkey2 = NULL;
    CRYPT_EAL_PkeyCtx *peerEcdhPkey = NULL;
    CRYPT_EAL_PkeyPrv ecdhPrvkey = {0};
    CRYPT_EAL_PkeyPub peerEcdhPubkey;
    uint8_t *shareKey = NULL;
    uint32_t shareKeyLen;

    TestMemInit();

    ecdhPkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    ecdhPkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    peerEcdhPkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    ASSERT_TRUE(ecdhPkey != NULL && ecdhPkey2 != NULL && peerEcdhPkey != NULL);

    /* Local: Set elliptic curve type and private key. */
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdhPkey, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    Ecc_SetPrvKey(&ecdhPrvkey, CRYPT_PKEY_ECDH, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdhPkey, &ecdhPrvkey), CRYPT_SUCCESS);

    /* Peer: Set elliptic curve type and public key. */
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(peerEcdhPkey, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    Ecc_SetPubKey(&peerEcdhPubkey, CRYPT_PKEY_ECDH, peerPubKeyVector->x, peerPubKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(peerEcdhPkey, &peerEcdhPubkey), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyComputeShareKey. */
    shareKey = (uint8_t *)malloc(shareKeyVector->len);
    ASSERT_TRUE(shareKey != NULL);
    shareKeyLen = shareKeyVector->len;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(NULL, peerEcdhPkey, shareKey, &shareKeyLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ecdhPkey, NULL, shareKey, &shareKeyLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ecdhPkey, peerEcdhPkey, NULL, &shareKeyLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ecdhPkey, peerEcdhPkey, shareKey, NULL), CRYPT_NULL_INPUT);

    shareKeyLen = 1;  // 1 is invalid
    ASSERT_EQ(
        CRYPT_EAL_PkeyComputeShareKey(ecdhPkey, peerEcdhPkey, shareKey, &shareKeyLen), CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ecdhPkey2, peerEcdhPkey, shareKey, &shareKeyLen), CRYPT_ECDH_ERR_EMPTY_KEY);

    ecdhPkey->id = CRYPT_PKEY_DH;
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ecdhPkey, peerEcdhPkey, shareKey, &shareKeyLen), CRYPT_EAL_ERR_ALGID);
    ecdhPkey->id = CRYPT_PKEY_ECDH;
    shareKeyLen = shareKeyVector->len;
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ecdhPkey, peerEcdhPkey, shareKey, &shareKeyLen), CRYPT_SUCCESS);
EXIT:
    free(shareKey);
    CRYPT_EAL_PkeyFreeCtx(ecdhPkey);
    CRYPT_EAL_PkeyFreeCtx(ecdhPkey2);
    CRYPT_EAL_PkeyFreeCtx(peerEcdhPkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_CTRL_API_TC001
 * @title  ECDH CRYPT_EAL_PkeyCtrl: Test the validity of opt.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
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
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION
 *    6. CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_CTRL_API_TC001(int type, int expect)
{
    ASSERT_TRUE(EAL_PkeyCtrl_Api_TC001(CRYPT_PKEY_ECDH, type, expect) == SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_CTRL_API_TC002
 * @title  ECDH CRYPT_EAL_PkeyCtrl: Test the validity of pkey and value.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
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
void SDV_CRYPTO_ECDH_CTRL_API_TC002(void)
{
    ASSERT_TRUE(EAL_PkeyCtrl_Api_TC002(CRYPT_PKEY_ECDH) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_CTRL_API_TC003
 * @title  ECDH CRYPT_EAL_PkeyCtrl: Test the effect of the point format on the key.
 * @precon Registering memory-related functions.
 *         public key point
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
 *    2. Set the para by eccId(p-224/256/384/512, bp256r1/384r1/512/r1), expected result 2
 *    3. Convert the format of the public key vector to COMPRESSED, expected result 3
 *    4. Set the public key, expected result 4
 *    5. Call the CRYPT_EAL_PkeyCtrl method to set point format to COMPRESSED, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCtrl method to set point format to HYBRID, expected result 6
 *    7. Get the public key, expected result 7
 *    8. Convert the format of the public key vector to HYBRID, expected result 8
 *    9. Compare the output of the preceding two steps, expected result 9
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-8. CRYPT_SUCCESS
 *    9. The two are same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_CTRL_API_TC003(int eccId, Hex *pubKeyX, Hex *pubKeyY)
{
    if (IsCurveDisabled(eccId)) {
        SKIP_TEST();
    }
    ASSERT_TRUE(EAL_PkeyCtrl_Api_TC003(CRYPT_PKEY_ECDH, eccId, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_GET_PRV_API_TC001
 * @title  ECDH CRYPT_EAL_PkeyGetPrv: Test the validity of parameters.
 * @precon Registering memory-related functions.
 *         private key
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
 *    2. Set the para by eccId(p-224), expected result 2
 *    3. Get the private key when there is no private key, expected result 3
 *    4. Set the private key, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGetPrv method:
 *       (1) pkey = null, expected result 5
 *       (2) prv = null, expected result 6
 *       (3) pkey.id != prv.id, expected result 7
 *       (4) Correct parameters., expected result 8
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
void SDV_CRYPTO_ECDH_GET_PRV_API_TC001(Hex *prvKey)
{
    ASSERT_TRUE(EAL_PkeyGetPrv_Api_TC001(CRYPT_PKEY_ECDH, prvKey) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_GET_PUB_API_TC001
 * @title  ECDH CRYPT_EAL_PkeyGetPub: Test the validity of parameters.
 * @precon Registering memory-related functions.
 *         public key point
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
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
void SDV_CRYPTO_ECDH_GET_PUB_API_TC001(Hex *pubKeyX, Hex *pubKeyY)
{
    ASSERT_TRUE(EAL_PkeyGetPub_Api_TC001(CRYPT_PKEY_ECDH, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_SET_PRV_API_TC001
 * @title  ECDH CRYPT_EAL_PkeySetPrv: Test the validity of parameters.
 * @precon Registering memory-related functions.
 *         Prepare valid private key and invalid private key.
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
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
void SDV_CRYPTO_ECDH_SET_PRV_API_TC001(Hex *prvKey, Hex *errorPrvKey)
{
    ASSERT_TRUE(EAL_PkeySetPrv_Api_TC001(CRYPT_PKEY_ECDH, prvKey, errorPrvKey) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_SET_PRV_API_TC002
 * @title  Check whether the public key is cleared when the private key is set.
 * @precon Registering memory-related functions.
 *         private key, public key point
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
 *    2. Set the para by eccId(p-224), expected result 2
 *    3. Set the the public key, expected result 3
 *    4. Set the the private key, expected result 4
 *    5. Get the the public key, expected result 5
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-5. CRYPT_SUCCESSY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_SET_PRV_API_TC002(Hex *prvKey, Hex *pubKeyX, Hex *pubKeyY)
{
    ASSERT_TRUE(EAL_PkeySetPrv_Api_TC002(CRYPT_PKEY_ECDH, prvKey, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_SET_PUB_API_TC001
 * @title  ECDH CRYPT_EAL_PkeySetPub: Test the validity of parameters.
 * @precon Prepare valid public key.
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
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
void SDV_CRYPTO_ECDH_SET_PUB_API_TC001(Hex *pubKeyVector)
{
    ASSERT_TRUE(EAL_PkeySetPub_Api_TC001(CRYPT_PKEY_ECDH, pubKeyVector) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_SET_PUB_API_TC002
 * @title  Check whether the private key is cleared when the public key is set.
 * @precon Registering memory-related functions.
 *         public key, private key
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
 *    2. Set the para by eccId(p-224), expected result 2
 *    3. Set the the private key, expected result 3
 *    4. Set the the public key, expected result 4
 *    5. Get the the private key, expected result 5
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-5. CRYPT_SUCCESSY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_SET_PUB_API_TC002(Hex *prvKey, Hex *pubKey)
{
    ASSERT_TRUE(EAL_PkeySetPub_Api_TC002(CRYPT_PKEY_ECDH, prvKey, pubKey) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_SET_PUB_API_TC003
 * @title  Test the function of setting public keys of different lengths.
 * @precon Public keys of different lengths.
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
 *    2. Set the para by eccId(p-224/256/384/512, bp256r1/384r1/512/r1), expected result 2
 *    3. Set public keys of different lengths, expected result 3
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESSY
 *    3. CRYPT_ECC_ERR_POINT_CODE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_SET_PUB_API_TC003(int eccId, Hex *pubKey, Hex *errorPubKey, int isProvider)
{
    ASSERT_TRUE(EAL_PkeySetPub_Api_TC003(CRYPT_PKEY_ECDSA, eccId, pubKey, errorPubKey, isProvider) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_GET_PARA_ID_API_TC001
 * @title  ECDH CRYPT_EAL_PkeyGetParaId test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Get para id before creating context, expected result 1
 *    1. Create the context of the ecdh algorithm, expected result 2
 *    2. Set para id(p-224/256/384/512), expected result 3
 *    3. Get para id, expected result 4
 * @expect
 *    1. CRYPT_PKEY_PARAID_MAX
 *    2. Success, and the context is not NULL.
 *    3. CRYPT_SUCCESS
 *    4. The obtained id is the same as the set id.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_GET_PARA_ID_API_TC001(int id)
{
    ASSERT_TRUE(EAL_PkeyGetParaId_Api_TC001(CRYPT_PKEY_ECDH, id) == 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_DUP_CTX_API_TC001
 * @title  ECDH CRYPT_EAL_PkeyDupCtx test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the context(pKeyCtx) of the ecdh algorithm, expected result 1
 *    2. Set the para by eccId(p-224/256/384/512, bp256r1/384r1/512/r1), expected result 2
 *    3. Call the CRYPT_EAL_PkeyDupCtx to dup context where the parameter is null, expected result 3
 *    4. Call the CRYPT_EAL_PkeyDupCtx to dup context(newCtx), expected result 4
 *    5. Get the reference count, expected result 5
 *    6. Compare the pkey ids obtained from pKeyCtx and newCtx, , expected result 6
 *    7. Compare the curve ids obtained from pKeyCtx and newCtx, expected result 7
 *    8. Compute the shared key with pKeyCtx and newCtx, expected result 8
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESSY
 *    3. Return null.
 *    4. Return non-null.
 *    5. The reference count is 1.
 *    6-7. Both are the same.
 *    8. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_DUP_CTX_API_TC001(int paraId, int isProvider)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    uint8_t shareKey1[1030];
    uint32_t shareKeyLen1 = sizeof(shareKey1);
    uint8_t shareKey2[1030];
    uint32_t shareKeyLen2 = sizeof(shareKey2);

    CRYPT_EAL_PkeyCtx *pKeyCtx = NULL;
    CRYPT_EAL_PkeyCtx *newCtx = NULL;

    pKeyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pKeyCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(pKeyCtx, (CRYPT_PKEY_ParaId)paraId) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyDupCtx(NULL) == NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pKeyCtx), CRYPT_SUCCESS);

    newCtx = CRYPT_EAL_PkeyDupCtx(pKeyCtx);
    ASSERT_TRUE(newCtx != NULL);

    ASSERT_EQ(newCtx->references.count, 1);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetId(pKeyCtx) == CRYPT_EAL_PkeyGetId(newCtx));
    ASSERT_TRUE(CRYPT_EAL_PkeyGetParaId(pKeyCtx) == CRYPT_EAL_PkeyGetParaId(newCtx));

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pKeyCtx, newCtx, shareKey1, &shareKeyLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(newCtx, pKeyCtx, shareKey2, &shareKeyLen2), CRYPT_SUCCESS);
    ASSERT_COMPARE("shared key", shareKey1, shareKeyLen1, shareKey2, shareKeyLen2);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pKeyCtx);
    CRYPT_EAL_PkeyFreeCtx(newCtx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_CMP_FUNC_TC001
 * @title  ECDH: CRYPT_EAL_PkeyCmp test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the ecdh algorithm, expected result 1
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
void SDV_CRYPTO_ECDH_CMP_FUNC_TC001(Hex *pubKeyX, Hex *pubKeyY)
{
    ASSERT_TRUE(EAL_PkeyCmp_Api_TC001(CRYPT_PKEY_ECDH, pubKeyX, pubKeyY) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_EXCH_FUNC_TC001
 * @title  ECDH key exchange test: set the key and exchange the key.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(ecdhPkey, peerEcdhPubPkey) of the ECDH algorithm, expected result 1
 *    2. Init the drbg, expected result 2
 *    3. ecdhPkey: Set elliptic curve type(p-224/256/384/512, bp256r1/384r1/512/r1) and private key, expected result 3
 *    4. peerEcdhPubPkey: Set elliptic curve type(p-224/256/384/512, bp256r1/384r1/512/r1) and public key(compressed/
 *       uncompressed/hybrid), expected result 4
 *    5. Compute the shared key, expected result 5
 *    6. Compare the output shared secret and shared secret vector, expected result 6
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. The two shared secrets are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_EXCH_FUNC_TC001(
    int eccId, Hex *prvKeyVector, Hex *pubKeyX, Hex *pubKeyY, int pointFormat, Hex *shareKeyVector, int isProvider)
{
    if (IsCurveDisabled(eccId)) {
        SKIP_TEST();
    }
    int ret;
    CRYPT_EAL_PkeyCtx *ecdhPkey = NULL;
    CRYPT_EAL_PkeyCtx *peerEcdhPubPkey = NULL;
    CRYPT_EAL_PkeyPrv ecdhPrvkey = {0};
    CRYPT_EAL_PkeyPub peerEcdhPubkey;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};
    uint8_t *shareKey = NULL;
    uint32_t shareKeyLen;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ecdhPkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    peerEcdhPubPkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    ASSERT_TRUE(ecdhPkey != NULL && peerEcdhPubPkey != NULL);

    /* Local: Set elliptic curve type and private key. */
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ecdhPkey, eccId), CRYPT_SUCCESS);
    Ecc_SetPrvKey(&ecdhPrvkey, CRYPT_PKEY_ECDH, prvKeyVector->x, prvKeyVector->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ecdhPkey, &ecdhPrvkey), CRYPT_SUCCESS);

    /* Peer: Set elliptic curve type and public key. */
    /* Create a key structure to store the public key. */
    ret = EccPointToBuffer(pubKeyX, pubKeyY, pointFormat, &pubKeyVector);
    ASSERT_TRUE_AND_LOG("EccPointToVector", ret == CRYPT_SUCCESS);
    Ecc_SetPubKey(&peerEcdhPubkey, CRYPT_PKEY_ECDH, pubKeyVector.data, pubKeyVector.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(peerEcdhPubPkey, eccId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(peerEcdhPubPkey, &peerEcdhPubkey), CRYPT_SUCCESS);

    /* Compute share secret. */
    shareKeyLen = CRYPT_EAL_PkeyGetKeyLen(ecdhPkey);
    ASSERT_TRUE(shareKeyLen > shareKeyVector->len);
    shareKey = (uint8_t *)malloc(shareKeyVector->len);
    ASSERT_TRUE(shareKey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ecdhPkey, peerEcdhPubPkey, shareKey, &shareKeyLen), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("Compare ShareKey Len", shareKeyLen == shareKeyVector->len);
    ASSERT_COMPARE("Compare ShareKey", shareKey, shareKeyLen, shareKeyVector->x, shareKeyVector->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ecdhPkey);
    CRYPT_EAL_PkeyFreeCtx(peerEcdhPubPkey);
    TestRandDeInit();
    free(shareKey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_GET_PARA_FUNC_TC001
 * @title  ECDH CRYPT_EAL_PkeyGetPara test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create context of the ECDH algorithm, expected result 1
 *    2. Set para, expected result 2
 *    3. Get para, expected result 3
 *    4. Check whether the set parameters and the obtained parameters are the same, expected result 4
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. The parameters are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_GET_PARA_FUNC_TC001(Hex *p, Hex *a, Hex *b, Hex *x, Hex *y, Hex *n, Hex *h)
{
    ASSERT_TRUE(EAL_PkeyGetPara_Func_TC001(CRYPT_PKEY_ECDH, p, a, b, x, y, n, h) == 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_GEN_KEY_FUNC_TC001
 * @title  ECDH CRYPT_EAL_PkeyGen test.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create context of the ECDH algorithm, expected result 1
 *    2. Set elliptic curve type, expected result 2
 *    3. Mock BN_RandRange to STUB_RandRangeK, expected result 3
 *    4. Init the drbg, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGen method to generate a key pair, expected result 5
 *    6. Get public key and private key, expected result 6
 *    7. Compare the getted key and vector, expected result 7
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. CRYPT_SUCCESS
 *    3. SUccess.
 *    4-6. CRYPT_SUCCESS
 *    7. The getted key and vector are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_GEN_KEY_FUNC_TC001(
    int eccId, Hex *prvKeyVector, Hex *pubKeyX, Hex *pubKeyY, int pointFormat, int isProvider)
{
    if (IsCurveDisabled(eccId)) {
        SKIP_TEST();
    }
    Ecc_GenKey(CRYPT_PKEY_ECDH, eccId, prvKeyVector, pubKeyX, pubKeyY, pointFormat, isProvider);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_GET_KEY_BITS_FUNC_TC001
 * @title  ECDH: get key bits.
 * @brief
 *    1. Create a context of the ECDH algorithm, expected result 1
 *    2. Get key bits, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_GET_KEY_BITS_FUNC_TC001(int paraid, int keyBits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraid), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(pkey) == (uint32_t)keyBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_GET_SEC_BITS_FUNC_TC001
 * @title  ECDH CRYPT_EAL_PkeyGetSecurityBits test.
 * @precon nan
 * @brief
 *    1. Create the context of the ecdh algorithm, expected result 1
 *    2. Set ecdh para, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetSecurityBits Obtains secbits, expected result 3
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. The return value is secBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_GET_SEC_BITS_FUNC_TC001(int paraid, int secBits)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), secBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_CHECK_KEYPAIR_FUNC_TC001
 * @title  ECDH CRYPT_EAL_PkeyPairCheck test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_CHECK_KEYPAIR_FUNC_TC001(int paraid, int isProvider)
{
#if !defined(HITLS_CRYPTO_ECDH_CHECK)
    (void)paraid;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    uint8_t wrong[KEY_MAX_LEN] = {1};
    CRYPT_EAL_PkeyPub ecdhPubKey = {0};
    CRYPT_EAL_PkeyPrv ecdhPrvKey = {0};

    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};
    KeyData prvKeyVector = {{0}, KEY_MAX_LEN};
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(pubCtx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, paraid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, paraid), CRYPT_SUCCESS);

    Ecc_SetPubKey(&ecdhPubKey, CRYPT_PKEY_ECDH, pubKeyVector.data, pubKeyVector.len);
    Ecc_SetPrvKey(&ecdhPrvKey, CRYPT_PKEY_ECDH, prvKeyVector.data, prvKeyVector.len);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pkey, pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &ecdhPubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &ecdhPrvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &ecdhPubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &ecdhPrvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SUCCESS);

    ecdhPrvKey.key.eccPrv.data = wrong;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &ecdhPrvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_ECDH_PAIRWISE_CHECK_FAIL);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECDH_CHECK_PRVKEY_FUNC_TC001
 * @title  ECDH CRYPT_EAL_PkeyPrvCheck test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECDH_CHECK_PRVKEY_FUNC_TC001(int paraid, int isProvider)
{
#if !defined(HITLS_CRYPTO_ECDH_CHECK)
    (void)paraid;
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_EAL_PkeyPrv ecdhPrvKey = {0};
    CRYPT_ECDH_Ctx *ctx = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *prvKey = NULL;

    KeyData prvKeyVector = {{0}, KEY_MAX_LEN};
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ECDH,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, paraid), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, paraid), CRYPT_SUCCESS);

    Ecc_SetPrvKey(&ecdhPrvKey, CRYPT_PKEY_ECDH, prvKeyVector.data, prvKeyVector.len);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ctx = (CRYPT_ECDH_Ctx *)pkey->key;
    prvKey = ctx->prvkey;
    n = ECC_GetParaN(ctx->para);

    (void)BN_Copy(prvKey, n);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_ECDH_INVALID_PRVKEY);

    (void)BN_SubLimb(prvKey, prvKey, 1); // key = n - 1
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    (void)BN_Zeroize(prvKey); // key = 0
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_ECDH_INVALID_PRVKEY);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BN_Destroy(n);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ECC_MUL_CAL_TEST_FUNC_TC001
 * @title  ECDH SDV_CRYPTO_ECC_MUL_CAL_TEST_FUNC_TC001 test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECC_MUL_CAL_TEST_FUNC_TC001(int paraId)
{
    if (IsCurveDisabled(paraId) && paraId != CRYPT_ECC_SM2) {
        SKIP_TEST();
    }
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ECC_Para *para = ECC_NewPara(paraId);
    ASSERT_TRUE(para != NULL);
    BN_BigNum *N = ECC_GetParaN(para);
    ASSERT_TRUE(N != NULL);
    BN_BigNum *rand = BN_Create(0);
    ASSERT_TRUE(rand != NULL);
    ASSERT_EQ(BN_RandRange(rand, N), CRYPT_SUCCESS);

    ECC_Point *point1 = ECC_NewPoint(para);
    ASSERT_TRUE(point1 != NULL);
    ECC_Point *point2 = ECC_NewPoint(para);
    ASSERT_TRUE(point2 != NULL);
    ECC_Point *point3 = ECC_NewPoint(para);
    ASSERT_TRUE(point3 != NULL);

    // cal N*G
    ASSERT_EQ(ECC_PointMul(para, point1, N, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(ECP_PointMulFast(para, point2, N, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(ECC_PointCmp(para, point1, point2), CRYPT_SUCCESS);
    // cal random*G
    ASSERT_EQ(ECC_PointMul(para, point1, rand, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(ECP_PointMulFast(para, point2, rand, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(ECC_PointCmp(para, point1, point2), CRYPT_SUCCESS);
    // cal random*Point
    ASSERT_EQ(ECC_PointMul(para, point2, rand, point1), CRYPT_SUCCESS);
    ASSERT_EQ(ECP_PointMulFast(para, point3, rand, point1), CRYPT_SUCCESS);
    ASSERT_EQ(ECC_PointCmp(para, point2, point3), CRYPT_SUCCESS);

EXIT:
    ECC_FreePara(para);
    ECC_FreePoint(point1);
    ECC_FreePoint(point2);
    ECC_FreePoint(point3);
    BN_Destroy(rand);
    BN_Destroy(N);
    TestRandDeInit();
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_ECC_ADD_CAL_TEST_FUNC_TC001
 * @title  ECDH SDV_CRYPTO_ECC_ADD_CAL_TEST_FUNC_TC001 test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ECC_ADD_CAL_TEST_FUNC_TC001(int paraId, Hex *bk1, Hex *bk2, Hex *bk3)
{
    if (IsCurveDisabled(paraId) && paraId != CRYPT_ECC_SM2) {
        SKIP_TEST();
    }
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ECC_Para *para = ECC_NewPara(paraId);
    ECC_Point *twoG = ECC_NewPoint(para);
    ECC_Point *pt1 = ECC_NewPoint(para);
    ECC_Point *pt2 = ECC_NewPoint(para);
    ECC_Point *r1 = ECC_NewPoint(para);
    ECC_Point *r2 = ECC_NewPoint(para);

    BN_BigNum *bnk1 = BN_Create(0);
    BN_BigNum *bnk2 = BN_Create(0);
    BN_BigNum *bnk3 = BN_Create(0);

    ASSERT_TRUE(bnk1 != NULL);
    ASSERT_TRUE(bnk2 != NULL);
    ASSERT_TRUE(bnk3 != NULL);
    ASSERT_TRUE(twoG != NULL);
    ASSERT_TRUE(pt1 != NULL);
    ASSERT_TRUE(pt2 != NULL);
    ASSERT_TRUE(r1 != NULL);
    ASSERT_TRUE(r2 != NULL);

    ASSERT_EQ(BN_Bin2Bn(bnk1, bk1->x, bk1->len), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Bin2Bn(bnk2, bk2->x, bk2->len), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Bin2Bn(bnk3, bk3->x, bk3->len), CRYPT_SUCCESS);
    // cal 2*G
    ASSERT_EQ(ECP_PointMulFast(para, twoG, bnk3, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(ECP_PointMulFast(para, pt1, bnk1, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(ECP_PointMulFast(para, pt2, bnk2, twoG), CRYPT_SUCCESS);

    ASSERT_EQ(ECC_PointAddAffine(para, r1, pt1, pt2), CRYPT_SUCCESS);

    ASSERT_EQ(ECC_PointMulAdd(para, r2, bnk1, bnk2, twoG), CRYPT_SUCCESS);
    ASSERT_EQ(ECC_PointCmp(para, r1, r2), CRYPT_SUCCESS);

EXIT:
    ECC_FreePara(para);
    ECC_FreePoint(twoG);
    ECC_FreePoint(pt1);
    ECC_FreePoint(pt2);
    ECC_FreePoint(r1);
    ECC_FreePoint(r2);
    BN_Destroy(bnk1);
    BN_Destroy(bnk2);
    BN_Destroy(bnk3);
    TestRandDeInit();
}
/* END_CASE */
