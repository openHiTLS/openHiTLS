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
#include "crypt_local_types.h"
#include "crypt_rsa.h"
/* END_HEADER */

STUB_DEFINE_RET6(int32_t, CRYPT_CalcHash, void *, const EAL_MdMethod *, const CRYPT_ConstData *, uint32_t, uint8_t *, uint32_t *);
STUB_DEFINE_RET6(int32_t, CRYPT_Mgf1, void *, const EAL_MdMethod *, const uint8_t *, const uint32_t , uint8_t *, uint32_t);
STUB_DEFINE_RET5(int32_t, CRYPT_RSA_PrvDec, const CRYPT_RSA_Ctx *, const uint8_t *, uint32_t , uint8_t *, uint32_t *);
STUB_DEFINE_RET3(int32_t, CRYPT_RandEx, void *, uint8_t *, uint32_t );

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
    CRYPT_MD_AlgId mdId = hashId;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
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
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
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
    CRYPT_MD_AlgId hashId = CRYPT_MD_SHA1;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};
    int32_t pkcsv15 = CRYPT_MD_SHA1;

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);
    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
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
    CRYPT_MD_AlgId hashId = CRYPT_MD_SHA256;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};
    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);
    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
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
        CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
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

/**
 * @test   SDV_CRYPTO_RSA_CRYPT_FUNC_TC004
 * @title  RSA: Label test for OAEP encryption and decryption
 * @precon Vectors: a rsa key pair, plaintext and label.
 * @brief
 *    1. Create the context(pkey) of the rsa algorithm, expected result 1
 *    2. Initialize the DRBG.
 *    3. gen rsa key, expected result 2
 *    4. Set padding type to OAEP and set oaep-label, expected result 3
 *    5. Call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 4
 *    6. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output of step 6, expected result 5
 *    7. Compare the output data of step 6 with plaintext, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CRYPT_FUNC_TC004(int bits, Hex *in, int isProvider)
{
#if !defined(HITLS_CRYPTO_SHA1) || !defined(HITLS_CRYPTO_RSA_ENCRYPT) || !defined(HITLS_CRYPTO_RSA_DECRYPT) || \
    !defined(HITLS_CRYPTO_RSAES_OAEP)
    SKIP_TEST();
#endif
    uint8_t ct[MAX_CIPHERTEXT_LEN] = {0};
    uint8_t pt[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t ctLen = MAX_CIPHERTEXT_LEN;
    uint32_t msgLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_MD_AlgId hashId = CRYPT_MD_SHA1;
    uint8_t e[] = {1, 0, 1};
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};
    TestMemInit();
    CRYPT_EAL_PkeyPara para = {0};
    SetRsaPara(&para, e, 3, bits);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

#ifdef HITLS_CRYPTO_DRBG
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
#endif
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen), CRYPT_SUCCESS);
    ASSERT_TRUE(msgLen == in->len);
    ASSERT_TRUE(memcmp(pt, in->x, msgLen) == 0);
    ct[1] -= 1;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen), CRYPT_RSA_NOR_VERIFY_FAIL);
EXIT:
#ifdef HITLS_CRYPTO_DRBG
    CRYPT_EAL_RandDeinit();
#endif
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

static uint8_t randBuf[] = {
    0xA3,0x97,0xA2,0x55,0x53,0xBE,0xF1,0xFC,0xF9,0x79,0x6B,0x52,0x14,0x13,0xE9,0xE2,0x2D,0x51,0x8E,0x1F,
};

static uint8_t decBuf[] = { // decryption buffer, the first bytes != 0x00
    0x01,0x78,0x46,0xec,0x35,0x6d,0x41,0xad,0xfd,0x4d,0x93,0xe4,0x85,0x42,0x87,0xf3,0xf3,0x05,0xc2,0xe8,0x95,0x53,0x15,
    0x66,0xd2,0x16,0x89,0x89,0xdb,0x0e,0xe4,0xcd,0x13,0xf7,0x3f,0x8b,0x26,0x94,0xb7,0x8b,0x9b,0x2b,0xa6,0x68,0x2e,0xe6,
    0xbf,0x70,0xf0,0xd3,0x83,0x12,0xeb,0x20,0x19,0x6e,0x8a,0x9d,0x77,0x89,0x38,0x38,0xfa,0xc3,0xd1,0x9a,0xb1,0x6e,0xec,
    0x88,0x79,0x6f,0xae,0xab,0xa0,0xda,0x56,0xef,0x2a,0x34,0xcd,0xb4,0xa3,0x28,0xea,0xa6,0xe8,0xfb,0x00,0xf0,0x5d,0xae,
    0x31,0xed,0x7d,0x7c,0x05,0x9e,0xe9,0x82,0x63,0xd0,0x77,0xcd,0xc1,0x7f,0xd6,0xdf,0x24,0xde,0x4d,0xff,0x9b,0x4c,0x7e,
    0x9a,0xb3,0xc8,0xb8,0xd2,0x0e,0x9d,0xb0,0x5b,0x4d,0xb4,0x1b,0xee,0xce,0xf6,0x35,0x4e,0x83,0xf9,0x2f,0x32,0xf5,0x02,
    0x4b,0x76,0xd8,0x5c,0x73,0x56,0x2d,0xfd,0xd3,0xbb,0x0a,0x6e,0x8e,0xa1,0x6c,0x9f,0x91,0xd5,0xb0,0x69,0x42,0x3f,0xf9,
    0x3d,0x58,0x4b,0xce,0x1a,0xb9,0x30,0x31,0x8f,0x47,0xa2,0xa0,0x38,0x5a,0x8a,0x37,0x6c,0x1d,0x1c,0xee,0xcc,0x71,0xd6,
    0x77,0x7c,0x12,0x63,0x34,0x56,0xc4,0x0c,0xa1,0x62,0xaa,0x25,0xbb,0x58,0x38,0x82,0x50,0xd6,0xd2,0x1d,0x1f,0xc8,0x56,
    0x4a,0x8d,0x72,0x9b,0x8c,0x28,0x2b,0x90,0x65,0x26,0x51,0xa1,0xc1,0xb0,0x77,0x7a,0x97,0x68,0xc6,0x25,0x00,0x8e,0x2c,
    0xd1,0xc4,0xff,0x7b,0x82,0xb1,0xa6,0x80,0xdd,0x3b,0xa7,0xba,0x6f,0x50,0x01,0x84,0x3a,0x8d,0x40,0x5b,0x04,0xf2,0xec,
    0xf7,0xe3,0x25
};
static uint8_t seedMaskbuffer0[] = { // seedMask
    0xdb,0xd1,0x4e,0x60,0x3e,0xff,0x5c,0x01,0xb4,0xea,0x8f,0xd7,0x56,0x94,0x1a,0x11,0x28,0x93,0x66,0x8a
};

static uint8_t dbbuffer1[] = { // right decryption dbBuffer
    0x89,0x2c,0xc5,0x3c,0x48,0xe2,0xc2,0xd6,0x3c,0xb1,0x72,0xfc,0x62,0x5f,0x93,0xb6,0x3b,0x6f,0x8c,0x92,0x2b,0xa6,0x68,
    0x2e,0xe6,0xbf,0x70,0xf0,0xd3,0x83,0x12,0xeb,0x20,0x19,0x6e,0x8a,0x9d,0x77,0x89,0x38,0x38,0xfa,0xc3,0xd1,0x9a,0xb1,
    0x6e,0xec,0x88,0x79,0x6f,0xae,0xab,0xa0,0xda,0x56,0xef,0x2a,0x34,0xcd,0xb4,0xa3,0x28,0xea,0xa6,0xe8,0xfb,0x00,0xf0,
    0x5d,0xae,0x31,0xed,0x7d,0x7c,0x05,0x9e,0xe9,0x82,0x63,0xd0,0x77,0xcd,0xc1,0x7f,0xd6,0xdf,0x24,0xde,0x4d,0xff,0x9b,
    0x4c,0x7e,0x9a,0xb3,0xc8,0xb8,0xd2,0x0e,0x9d,0xb0,0x5b,0x4d,0xb4,0x1b,0xee,0xce,0xf6,0x35,0x4e,0x83,0xf9,0x2f,0x32,
    0xf5,0x02,0x4b,0x76,0xd8,0x5c,0x73,0x56,0x2d,0xfd,0xd3,0xbb,0x0a,0x6e,0x8e,0xa1,0x6c,0x9f,0x91,0xd5,0xb0,0x69,0x42,
    0x3f,0xf9,0x3d,0x58,0x4b,0xce,0x1a,0xb9,0x30,0x31,0x8f,0x47,0xa2,0xa0,0x38,0x5a,0x8a,0x37,0x6c,0x1d,0x1c,0xee,0xcc,
    0x71,0xd6,0x77,0x7c,0x12,0x63,0x34,0x56,0xc4,0x0c,0xa1,0x62,0xaa,0x25,0xbb,0x58,0x38,0x82,0x50,0xd6,0xd2,0x1d,0x1f,
    0xc8,0x56,0x4a,0x8d,0x72,0x9b,0x8c,0x28,0x2b,0x90,0x65,0x26,0x51,0xa1,0xc1,0xb0,0x77,0x7a,0x97,0x68,0xc6,0x25,0x00,
    0x8e,0x2c,0xd1,0xc4,0xff,0x7b,0x82,0xb1,0xa6,0x80,0xdd,0x3b,0xa7,0xba,0x6f,0x50,0x01,0x84,0x3a,0x8c,0x41,0x59,0x07,
    0xf6,0xe9,0xf1,0xe4,0x2d,
};

static uint8_t dbbuffer2[] = { // no 01 in decryption dbBuffer
    0x89,0x2c,0xc5,0x3c,0x48,0xe2,0xc2,0xd6,0x3c,0xb1,0x72,0xfc,0x62,0x5f,0x93,0xb6,0x3b,0x6f,0x8c,0x92,0x2b,0xa6,0x68,
    0x2e,0xe6,0xbf,0x70,0xf0,0xd3,0x83,0x12,0xeb,0x20,0x19,0x6e,0x8a,0x9d,0x77,0x89,0x38,0x38,0xfa,0xc3,0xd1,0x9a,0xb1,
    0x6e,0xec,0x88,0x79,0x6f,0xae,0xab,0xa0,0xda,0x56,0xef,0x2a,0x34,0xcd,0xb4,0xa3,0x28,0xea,0xa6,0xe8,0xfb,0x00,0xf0,
    0x5d,0xae,0x31,0xed,0x7d,0x7c,0x05,0x9e,0xe9,0x82,0x63,0xd0,0x77,0xcd,0xc1,0x7f,0xd6,0xdf,0x24,0xde,0x4d,0xff,0x9b,
    0x4c,0x7e,0x9a,0xb3,0xc8,0xb8,0xd2,0x0e,0x9d,0xb0,0x5b,0x4d,0xb4,0x1b,0xee,0xce,0xf6,0x35,0x4e,0x83,0xf9,0x2f,0x32,
    0xf5,0x02,0x4b,0x76,0xd8,0x5c,0x73,0x56,0x2d,0xfd,0xd3,0xbb,0x0a,0x6e,0x8e,0xa1,0x6c,0x9f,0x91,0xd5,0xb0,0x69,0x42,
    0x3f,0xf9,0x3d,0x58,0x4b,0xce,0x1a,0xb9,0x30,0x31,0x8f,0x47,0xa2,0xa0,0x38,0x5a,0x8a,0x37,0x6c,0x1d,0x1c,0xee,0xcc,
    0x71,0xd6,0x77,0x7c,0x12,0x63,0x34,0x56,0xc4,0x0c,0xa1,0x62,0xaa,0x25,0xbb,0x58,0x38,0x82,0x50,0xd6,0xd2,0x1d,0x1f,
    0xc8,0x56,0x4a,0x8d,0x72,0x9b,0x8c,0x28,0x2b,0x90,0x65,0x26,0x51,0xa1,0xc1,0xb0,0x77,0x7a,0x97,0x68,0xc6,0x25,0x00,
    0x8e,0x2c,0xd1,0xc4,0xff,0x7b,0x82,0xb1,0xa6,0x80,0xdd,0x3b,0xa7,0xba,0x6f,0x50,0x01,0x84,0x3a,0x8d,0x40,0x5b,0x04,
    0xf2,0xec,0xf7,0xe3,0x25
};

static uint8_t dbbuffer3[] = { // after 01, no message data
    0x89,0x2c,0xc5,0x3c,0x48,0xe2,0xc2,0xd6,0x3c,0xb1,0x72,0xfc,0x62,0x5f,0x93,0xb6,0x3b,0x6f,0x8c,0x92,0x2b,0xa6,0x68,
    0x2e,0xe6,0xbf,0x70,0xf0,0xd3,0x83,0x12,0xeb,0x20,0x19,0x6e,0x8a,0x9d,0x77,0x89,0x38,0x38,0xfa,0xc3,0xd1,0x9a,0xb1,
    0x6e,0xec,0x88,0x79,0x6f,0xae,0xab,0xa0,0xda,0x56,0xef,0x2a,0x34,0xcd,0xb4,0xa3,0x28,0xea,0xa6,0xe8,0xfb,0x00,0xf0,
    0x5d,0xae,0x31,0xed,0x7d,0x7c,0x05,0x9e,0xe9,0x82,0x63,0xd0,0x77,0xcd,0xc1,0x7f,0xd6,0xdf,0x24,0xde,0x4d,0xff,0x9b,
    0x4c,0x7e,0x9a,0xb3,0xc8,0xb8,0xd2,0x0e,0x9d,0xb0,0x5b,0x4d,0xb4,0x1b,0xee,0xce,0xf6,0x35,0x4e,0x83,0xf9,0x2f,0x32,
    0xf5,0x02,0x4b,0x76,0xd8,0x5c,0x73,0x56,0x2d,0xfd,0xd3,0xbb,0x0a,0x6e,0x8e,0xa1,0x6c,0x9f,0x91,0xd5,0xb0,0x69,0x42,
    0x3f,0xf9,0x3d,0x58,0x4b,0xce,0x1a,0xb9,0x30,0x31,0x8f,0x47,0xa2,0xa0,0x38,0x5a,0x8a,0x37,0x6c,0x1d,0x1c,0xee,0xcc,
    0x71,0xd6,0x77,0x7c,0x12,0x63,0x34,0x56,0xc4,0x0c,0xa1,0x62,0xaa,0x25,0xbb,0x58,0x38,0x82,0x50,0xd6,0xd2,0x1d,0x1f,
    0xc8,0x56,0x4a,0x8d,0x72,0x9b,0x8c,0x28,0x2b,0x90,0x65,0x26,0x51,0xa1,0xc1,0xb0,0x77,0x7a,0x97,0x68,0xc6,0x25,0x00,
    0x8e,0x2c,0xd1,0xc4,0xff,0x7b,0x82,0xb1,0xa6,0x80,0xdd,0x3b,0xa7,0xba,0x6f,0x50,0x01,0x84,0x3a,0x8d,0x40,0x5b,0x04,
    0xf2,0xec,0xf7,0xe3,0x24
};

static uint8_t dbbuffer4[] = { // after 00, no 01, it will be 00, 02
    0x89,0x2c,0xc5,0x3c,0x48,0xe2,0xc2,0xd6,0x3c,0xb1,0x72,0xfc,0x62,0x5f,0x93,0xb6,0x3b,0x6f,0x8c,0x92,0x2b,0xa6,0x68,
    0x2e,0xe6,0xbf,0x70,0xf0,0xd3,0x83,0x12,0xeb,0x20,0x19,0x6e,0x8a,0x9d,0x77,0x89,0x38,0x38,0xfa,0xc3,0xd1,0x9a,0xb1,
    0x6e,0xec,0x88,0x79,0x6f,0xae,0xab,0xa0,0xda,0x56,0xef,0x2a,0x34,0xcd,0xb4,0xa3,0x28,0xea,0xa6,0xe8,0xfb,0x00,0xf0,
    0x5d,0xae,0x31,0xed,0x7d,0x7c,0x05,0x9e,0xe9,0x82,0x63,0xd0,0x77,0xcd,0xc1,0x7f,0xd6,0xdf,0x24,0xde,0x4d,0xff,0x9b,
    0x4c,0x7e,0x9a,0xb3,0xc8,0xb8,0xd2,0x0e,0x9d,0xb0,0x5b,0x4d,0xb4,0x1b,0xee,0xce,0xf6,0x35,0x4e,0x83,0xf9,0x2f,0x32,
    0xf5,0x02,0x4b,0x76,0xd8,0x5c,0x73,0x56,0x2d,0xfd,0xd3,0xbb,0x0a,0x6e,0x8e,0xa1,0x6c,0x9f,0x91,0xd5,0xb0,0x69,0x42,
    0x3f,0xf9,0x3d,0x58,0x4b,0xce,0x1a,0xb9,0x30,0x31,0x8f,0x47,0xa2,0xa0,0x38,0x5a,0x8a,0x37,0x6c,0x1d,0x1c,0xee,0xcc,
    0x71,0xd6,0x77,0x7c,0x12,0x63,0x34,0x56,0xc4,0x0c,0xa1,0x62,0xaa,0x25,0xbb,0x58,0x38,0x82,0x50,0xd6,0xd2,0x1d,0x1f,
    0xc8,0x56,0x4a,0x8d,0x72,0x9b,0x8c,0x28,0x2b,0x90,0x65,0x26,0x51,0xa1,0xc1,0xb0,0x77,0x7a,0x97,0x68,0xc6,0x25,0x00,
    0x8e,0x2c,0xd1,0xc4,0xff,0x7b,0x82,0xb1,0xa6,0x80,0xdd,0x3b,0xa7,0xba,0x6f,0x50,0x01,0x84,0x3a,0x8d,0x40,0x5b,0x04,
    0xf2,0xec,0xf5,0xe2,0x24
};

static uint8_t dbbuffer5[] = { // no 01 after hash, and the value of hash is all 01.
    0x52,0x14,0x67,0xd3,0x17,0x88,0x88,0xda,0x0f,0xe5,0xcc,0x12,0xf6,0x3e,0x8a,0x27,0x95,0xb6,0x8a,0x9a,0x2b,0xa6,0x68,
    0x2e,0xe6,0xbf,0x70,0xf0,0xd3,0x83,0x12,0xeb,0x20,0x19,0x6e,0x8a,0x9d,0x77,0x89,0x38,0x38,0xfa,0xc3,0xd1,0x9a,0xb1,
    0x6e,0xec,0x88,0x79,0x6f,0xae,0xab,0xa0,0xda,0x56,0xef,0x2a,0x34,0xcd,0xb4,0xa3,0x28,0xea,0xa6,0xe8,0xfb,0x00,0xf0,
    0x5d,0xae,0x31,0xed,0x7d,0x7c,0x05,0x9e,0xe9,0x82,0x63,0xd0,0x77,0xcd,0xc1,0x7f,0xd6,0xdf,0x24,0xde,0x4d,0xff,0x9b,
    0x4c,0x7e,0x9a,0xb3,0xc8,0xb8,0xd2,0x0e,0x9d,0xb0,0x5b,0x4d,0xb4,0x1b,0xee,0xce,0xf6,0x35,0x4e,0x83,0xf9,0x2f,0x32,
    0xf5,0x02,0x4b,0x76,0xd8,0x5c,0x73,0x56,0x2d,0xfd,0xd3,0xbb,0x0a,0x6e,0x8e,0xa1,0x6c,0x9f,0x91,0xd5,0xb0,0x69,0x42,
    0x3f,0xf9,0x3d,0x58,0x4b,0xce,0x1a,0xb9,0x30,0x31,0x8f,0x47,0xa2,0xa0,0x38,0x5a,0x8a,0x37,0x6c,0x1d,0x1c,0xee,0xcc,
    0x71,0xd6,0x77,0x7c,0x12,0x63,0x34,0x56,0xc4,0x0c,0xa1,0x62,0xaa,0x25,0xbb,0x58,0x38,0x82,0x50,0xd6,0xd2,0x1d,0x1f,
    0xc8,0x56,0x4a,0x8d,0x72,0x9b,0x8c,0x28,0x2b,0x90,0x65,0x26,0x51,0xa1,0xc1,0xb0,0x77,0x7a,0x97,0x68,0xc6,0x25,0x00,
    0x8e,0x2c,0xd1,0xc4,0xff,0x7b,0x82,0xb1,0xa6,0x80,0xdd,0x3b,0xa7,0xba,0x6f,0x50,0x01,0x84,0x3a,0x8d,0x40,0x5b,0x04,
    0xf2,0xec,0xf7,0xe3,0x25
};

int32_t STUB_CRYPT_RandEx(void *libCtx, uint8_t *rand, uint32_t randLen)
{
    (void)libCtx;
    (void)randLen;
    (void)memcpy_s(rand, sizeof(randBuf), randBuf, sizeof(randBuf));
    return 0;
}

static int times1 = 0;
static int flag;

static int32_t STUB_CRYPT_Mgf1(void *provCtx, const EAL_MdMethod *hashMethod, const uint8_t *seed, const uint32_t seedLen,
    uint8_t *mask, uint32_t maskLen)
{
    (void)provCtx;
    (void)hashMethod;
    (void)seed;
    (void)seedLen;
    (void)maskLen;
    if (times1 < 1) {
        times1++;
        (void)memcpy_s(mask, sizeof(seedMaskbuffer0), seedMaskbuffer0, sizeof(seedMaskbuffer0));
        return 0;
    }
    if (flag == 1) {
        (void)memcpy_s(mask, sizeof(dbbuffer1), dbbuffer1, sizeof(dbbuffer1));
    } else if (flag == 2) {
        (void)memcpy_s(mask, sizeof(dbbuffer2), dbbuffer2, sizeof(dbbuffer1));
    } else if (flag == 3) {
        (void)memcpy_s(mask, sizeof(dbbuffer3), dbbuffer3, sizeof(dbbuffer1));
    } else if (flag == 4) {
        (void)memcpy_s(mask, sizeof(dbbuffer4), dbbuffer4, sizeof(dbbuffer1));
    } else if (flag == 5) {
        (void)memcpy_s(mask, sizeof(dbbuffer5), dbbuffer5, sizeof(dbbuffer1));
    }
    return 0;
};

static uint8_t hashBuf[] = {
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01
};

static int32_t STUB_CRYPT_CalcHash(void *provCtx, const EAL_MdMethod *hashMethod, const CRYPT_ConstData *hashData,
    uint32_t size, uint8_t *out, uint32_t *outlen)
{
    (void)provCtx;
    (void)hashMethod;
    (void)hashData;
    (void)size;
    (void)out;
    (void)outlen;
    (void)memcpy_s(out, sizeof(hashBuf), hashBuf, sizeof(hashBuf));
    *outlen = sizeof(hashBuf);
    return 0;
};

static int32_t STUB_CRYPT_RSA_PrvDec(const CRYPT_RSA_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    (void)input;
    (void)inputLen;
    (void)memcpy_s(out, sizeof(decBuf), decBuf, sizeof(decBuf));
    *outLen = sizeof(decBuf);
    return 0;
}

/**
 * @test   SDV_CRYPTO_RSA_INVLAID_DECRYPT_TEST
 * @title  RSA: Invalid OAEP decryption test with various failure cases
 * @precon Vectors: a rsa key pair and plaintext.
 * @brief
 *    1. Create the context(pkey) of the rsa algorithm, expected result 1
 *    2. Initialize the DRBG.
 *    3. Set public key and padding mode to OAEP, expected result 2
 *    4. fixed the random, call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 3
 *    5. Set private key and padding mode to OAEP, expected result 4
 *    6. Set output buffer to small size (1 byte), expected result 5
 *    7. Call the CRYPT_EAL_PkeyDecrypt to decrypt with small buffer, expected result 6
 *    8. Replace CRYPT_Mgf1 with stub function, expected result 7
 *    9. Test correct decryption, expected result 8
 *    10. Test decryption with no 0x01 in dbBuffer, expected result 9
 *    11. Test decryption with no message data after 0x01, expected result 10
 *    12. Test decryption with no 0x01 after 0x00 in dbBuffer, expected result 11
 *    13. Replace CRYPT_CalcHash with stub function, expected result 12
 *    14. Test decryption when no 0x01 in dbBuffer and hash value is all 0x01, expected result 13
 *    15. Restore stubs and replace private-decrypt with a stub that returns malformed buffer, expected result 14
 *    16. Call decrypt and expect verification failure due to malformed decrypted buffer, expected result 15
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS when setting public key and OAEP params.
 *    3. CRYPT_SUCCESS for encryption.
 *    4. CRYPT_SUCCESS when setting private key and OAEP params.
 *    5. CRYPT_RSA_NOR_VERIFY_FAIL when output buffer is too small.
 *    6. After stubbing MGF1, CRYPT_SUCCESS for decryption.
 *    7. Decrypted plaintext matches the original.
 *    8. CRYPT_RSA_NOR_VERIFY_FAIL when no 0x01 in dbBuffer.
 *    9. CRYPT_SUCCESS with msgLen equals 0 when no message after 0x01.
 *    10. CRYPT_RSA_NOR_VERIFY_FAIL when no 0x01 after 0x00 in dbBuffer.
 *    11. CRYPT_RSA_NOR_VERIFY_FAIL when hash check fails (hash all 0x01).
 *    12. After restoring and stubbing private-decrypt to a malformed buffer, CRYPT_RSA_NOR_VERIFY_FAIL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_INVLAID_DECRYPT_TEST(Hex *n, Hex *e, Hex *d, Hex *plaintext, int isProvider)
{
    TestMemInit();
    uint8_t ct[MAX_CIPHERTEXT_LEN] = {1};
    uint8_t pt[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t msgLen = MAX_CIPHERTEXT_LEN;
    uint32_t ctLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyPub pubkey = {0};
    CRYPT_MD_AlgId hashId = CRYPT_MD_SHA1;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);
    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pubkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(CRYPT_RandEx, STUB_CRYPT_RandEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, plaintext->x, plaintext->len, ct, &ctLen) == CRYPT_SUCCESS);
    STUB_RESTORE(CRYPT_RandEx);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // test the output buffer is too small
    msgLen = 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen) == CRYPT_RSA_NOR_VERIFY_FAIL);

    STUB_REPLACE(CRYPT_Mgf1, STUB_CRYPT_Mgf1);
    // test the correct decryption
    flag = 1;
    times1 = 0;
    msgLen = MAX_CIPHERTEXT_LEN;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(msgLen == plaintext->len);
    ASSERT_TRUE(memcmp(pt, plaintext->x, msgLen) == 0);

    // test invalid decryption of no 01 in dbBuffer
    times1 = 0;
    flag = 2;
    msgLen = MAX_CIPHERTEXT_LEN;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen) == CRYPT_RSA_NOR_VERIFY_FAIL);

    // test invalid decryption of no msg after 01 in dbBuffer
    times1 = 0;
    flag = 3;
    msgLen = MAX_CIPHERTEXT_LEN;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(msgLen == 0);

    // test invalid decryption of no 01, after 00 in dbBuffer
    times1 = 0;
    flag = 4;
    msgLen = MAX_CIPHERTEXT_LEN;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen) == CRYPT_RSA_NOR_VERIFY_FAIL);

    // test invalid decryption of no 01 in dbBuffer, and all hash value is 01
    STUB_REPLACE(CRYPT_CalcHash, STUB_CRYPT_CalcHash);
    times1 = 0;
    flag = 5;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen) == CRYPT_RSA_NOR_VERIFY_FAIL);

    STUB_RESTORE(CRYPT_CalcHash);
    STUB_RESTORE(CRYPT_Mgf1);
    // sutb decryption buffer, the first bytes != 0x00
    STUB_REPLACE(CRYPT_RSA_PrvDec, STUB_CRYPT_RSA_PrvDec);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, ctLen, pt, &msgLen) == CRYPT_RSA_NOR_VERIFY_FAIL);

EXIT:
    STUB_RESTORE(CRYPT_RSA_PrvDec);
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

