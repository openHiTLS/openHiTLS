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
#include <stdint.h>
#include "bsl_params.h"
#include "crypt_params_key.h"
/* END_HEADER */
#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0

static bool NeedPadSkip(int padMode)
{
    switch (padMode) {
#ifdef HITLS_CRYPTO_RSAES_OAEP
        case CRYPT_CTRL_SET_RSA_RSAES_OAEP:
            return false;
#endif
#ifdef HITLS_CRYPTO_RSAES_PKCSV15
        case CRYPT_CTRL_SET_RSA_RSAES_PKCSV15:
            return false;
#endif
#ifdef HITLS_CRYPTO_RSAES_PKCSV15_TLS
        case CRYPT_CTRL_SET_RSA_RSAES_PKCSV15_TLS:
            return false;
#endif
#ifdef HITLS_CRYPTO_RSA_NO_PAD
        case CRYPT_CTRL_SET_RSA_PADDING:
            return false;
#endif
        default:
            return true;
    }
}

/**
 * @test   SDV_CRYPTO_RSA_CRYPT_FUNC_TC001
 * @title  RSA: public key encryption and private key
 * @precon Vectors: a rsa key pair.
 * @brief
 *    1. Create the context(pkey) of the rsa algorithm, expected result 1
 *    2. Initialize the DRBG.
 *    3. Set private key and padding mode, expected result 2
 *    4. Call the CRYPT_EAL_PkeyDecrypt to decrypt ciphertext, expected result 3
 *    5. Compare the decrypted output with the expected output, expected result 4
 *    6. Set public key and padding mode, expected result 5
 *    7. Call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 6
 *    8. Check the length of output data, expected result 7
 *    9. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output data of step 6, expected result 8
 *    10. Compare the output data of step 8 with the output data of step 6, expected result 9
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Both are the same.
 *    5-6. CRYPT_SUCCESS
 *    7. It is equal to ciphertext->len.
 *    8. CRYPT_SUCCESS
 *    9. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CRYPT_FUNC_TC001(
    int keyLen, int padMode, int hashId, Hex *n, Hex *e, Hex *d, Hex *plaintext, Hex *ciphertext, int isProvider)
{
    if (NeedPadSkip(padMode) || IsMdAlgDisabled(hashId)) {
        SKIP_TEST();
    }
    int paraSize;
    void *paraPtr;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyPub pubkey = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};
    int32_t pkcsv15 = hashId;
#ifdef HITLS_CRYPTO_RSA_DECRYPT
    uint8_t pt[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t ptLen = MAX_CIPHERTEXT_LEN;
#endif
#ifdef HITLS_CRYPTO_RSA_ENCRYPT
    uint8_t ct[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t ctLen = MAX_CIPHERTEXT_LEN;
#endif
    int32_t noPad = CRYPT_RSA_NO_PAD;

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);
    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);
    if (padMode == CRYPT_CTRL_SET_RSA_RSAES_OAEP) {
        paraSize = 0;
        paraPtr = oaepParam;
    } else if (padMode == CRYPT_CTRL_SET_RSA_RSAES_PKCSV15) {
        paraSize = sizeof(pkcsv15);
        paraPtr = &pkcsv15;
    } else if (padMode == CRYPT_CTRL_SET_RSA_PADDING) {
        paraSize = sizeof(noPad);
        paraPtr = &noPad;
    }

    ASSERT_TRUE(ciphertext->len == KEYLEN_IN_BYTES((uint32_t)keyLen));
    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

#ifdef HITLS_CRYPTO_DRBG
    if (padMode != CRYPT_CTRL_SET_RSA_PADDING) {
        CRYPT_RandRegist(RandFunc);
        CRYPT_RandRegistEx(RandFuncEx);
    }
#endif

#ifdef HITLS_CRYPTO_RSA_DECRYPT
    /* HiTLS private key decrypts the data. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prvkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, padMode, paraPtr, paraSize), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, ciphertext->x, ciphertext->len, pt, &ptLen), CRYPT_SUCCESS);
    ASSERT_EQ(ptLen, plaintext->len);
    ASSERT_EQ(memcmp(pt, plaintext->x, ptLen), 0);
#endif

#ifdef HITLS_CRYPTO_RSA_ENCRYPT
    /* HiTLS public key encrypt */
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pubkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, padMode, paraPtr, paraSize), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, plaintext->x, plaintext->len, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(ctLen, ciphertext->len);
#endif

#if defined(HITLS_CRYPTO_RSA_DECRYPT) && defined(HITLS_CRYPTO_RSA_ENCRYPT)
    /* HiTLS private key decrypt */
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &ptLen), CRYPT_SUCCESS);
    ASSERT_EQ(ptLen, plaintext->len);
    ASSERT_EQ(memcmp(pt, plaintext->x, ptLen), 0);
#endif

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    CRYPT_EAL_RandDeinit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_CRYPT_FUNC_TC002
 * @title  RSA EAL abnormal test: The encryption and decryption padding modes do not match.
 * @precon Vectors: a rsa key pair, plaintext
 * @brief
 *    1. Create the context(pkey) of the rsa algorithm, expected result 1
 *    2. Initialize the DRBG.
 *    3. Set public key, and set padding mode to OAEP, expected result 2
 *    4. Call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 3
 *    5. Set private key, and set padding mode to PKCSV15, expected result 4
 *    6. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output of step 4, expected result 5
 *    7. Set private key, and set padding mode to OAEP, expected result 6
 *    8. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output of step 4, expected result 7
 *    9. Compare the output data of step 8 with plaintext, expected result 8
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. CRYPT_RSA_NOR_VERIFY_FAIL
 *    6-7. CRYPT_SUCCESS
 *    8. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CRYPT_FUNC_TC002(Hex *n, Hex *e, Hex *d, Hex *plaintext, int isProvider)
{
    TestMemInit();
    uint8_t ct[MAX_CIPHERTEXT_LEN] = {0};
    uint8_t pt[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t msgLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyPub pubkey = {0};
    int32_t hashId = CRYPT_MD_SHA1;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};
    int32_t pkcsv15 = CRYPT_MD_SHA1;

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);
    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

#ifdef HITLS_CRYPTO_DRBG
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
#endif

    /* HiTLS public key encrypt: OAEP */
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pubkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, plaintext->x, plaintext->len, ct, &msgLen) == CRYPT_SUCCESS);

    /* HiTLS private key encrypt: PKCSV15 */
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15, sizeof(pkcsv15)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, msgLen, pt, &msgLen) == CRYPT_RSA_NOR_VERIFY_FAIL);

    /* HiTLS private key encrypt: OAEP */
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, msgLen, pt, &msgLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(msgLen == plaintext->len);
    ASSERT_TRUE(memcmp(pt, plaintext->x, msgLen) == 0);

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    CRYPT_EAL_RandDeinit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_CRYPT_FUNC_TC003
 * @title  RSA: Label test for OAP encryption and decryption
 * @precon Vectors: a rsa key pair, plaintext and label.
 * @brief
 *    1. Create the context(pkey) of the rsa algorithm, expected result 1
 *    2. Initialize the DRBG.
 *    3. Set public key and private key, expected result 2
 *    4. Set padding type to OAEP and set oaep-label, expected result 3
 *    5. Call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 4
 *    6. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output of step 6, expected result 5
 *    7. Compare the output data of step 6 with plaintext, expected result 6
 *    8. Call the CRYPT_EAL_PkeyCopyCtx to copy pkey, expected result 7
 *    9. Call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 8
 *    10. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output of step 8, expected result 9
 * @expect
 *    1. Success, and context is not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. Both are the same.
 *    7-9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CRYPT_FUNC_TC003(Hex *n, Hex *e, Hex *d, Hex *plaintext, Hex *label, int isProvider)
{
#if !defined(HITLS_CRYPTO_SHA2) || !defined(HITLS_CRYPTO_RSA_ENCRYPT) || !defined(HITLS_CRYPTO_RSA_DECRYPT) || \
    !defined(HITLS_CRYPTO_RSAES_OAEP)
    SKIP_TEST();
#endif
    uint8_t ct[MAX_CIPHERTEXT_LEN] = {0};
    uint8_t pt[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t msgLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyPub pubkey = {0};
    int32_t hashId = CRYPT_MD_SHA256;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};
    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);
    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

#ifdef HITLS_CRYPTO_DRBG
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
#endif

    /* HiTLS pubenc, prvdec */
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pubkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_OAEP_LABEL, label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, plaintext->x, plaintext->len, ct, &msgLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, ct, msgLen, pt, &msgLen), CRYPT_SUCCESS);
    ASSERT_TRUE(msgLen == plaintext->len);
    ASSERT_TRUE(memcmp(pt, plaintext->x, msgLen) == 0);

    /* HiTLS copy ctx, pubenc, prvdec */
    cpyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);

    msgLen = MAX_CIPHERTEXT_LEN;
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(cpyCtx, plaintext->x, plaintext->len, ct, &msgLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(cpyCtx, ct, msgLen, pt, &msgLen) == CRYPT_SUCCESS);

EXIT:
#ifdef HITLS_CRYPTO_DRBG
    CRYPT_EAL_RandDeinit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
}
/* END_CASE */

