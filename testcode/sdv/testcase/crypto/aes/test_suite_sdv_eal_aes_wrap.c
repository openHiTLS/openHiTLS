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
#include <pthread.h>
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "bsl_sal.h"
#include "securec.h"

#define MAX_OUTPUT 5000
#define MCT_INNER_LOOP 1000
#define AES_BLOCKSIZE 16

#define MAX_DATA_LEN 1024
#define AES_TAG_LEN 16
#define AES_128_KEY_LEN   16
#define AES_192_KEY_LEN   24
#define AES_256_KEY_LEN   32
#define MAX_IV_LEN        8
/* END_HEADER */

/**
 * @test  SDV_CRYPTO_EAL_AES_WRAP_API_TC001
 * @title  AES WRAP NOPAD abnormal input parameter test.
 * @precon nan
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call CRYPT_EAL_CipherInit set key, the keyLen is abnormal. Expected result 2 is obtained.
 *    3.Call CRYPT_EAL_CipherInit set iv, the ivLen is abnormal. Expected result 2 is obtained.
 *    4.Call CRYPT_EAL_CipherUpdate, the inLen is abnormal. Expected result 3 is obtained.
 *    5.Call CRYPT_EAL_CipherUpdate, the outLen is abnormal. Expected result 3 is obtained.
 * @expect
 *    1.Success.
 *    2.Failed. Return CRYPT_AES_ERR_KEYLEN.
 *    3.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    4.Failed. Return CRYPT_MODE_ERR_INPUT_LEN.
 *    5.Failed. Return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_WRAP_API_TC001(void)
{
    TestMemInit();
    uint8_t out[MAX_DATA_LEN + 8];
    uint8_t in[MAX_DATA_LEN];
    uint8_t key[AES_BLOCKSIZE + 1];
    uint8_t iv[AES_BLOCKSIZE];
    uint32_t outLen = MAX_DATA_LEN;
    uint32_t inLen = MAX_DATA_LEN;
    uint32_t keyLen = AES_BLOCKSIZE;
    uint32_t ivLen = 8;
 
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_WRAP_NOPAD);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 7, iv, ivLen, true), CRYPT_AES_ERR_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, 7, true), CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, 9, true), CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, 7, out, &outLen), CRYPT_MODE_ERR_INPUT_LEN);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, 17, out, &outLen), CRYPT_MODE_ERR_INPUT_LEN);
    outLen = 7;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen), CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
    outLen = MAX_DATA_LEN;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen), CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
    outLen = MAX_DATA_LEN + 8;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen), CRYPT_SUCCESS);

    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, false), CRYPT_SUCCESS);
    inLen = MAX_DATA_LEN - 1;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, outLen, in, &inLen), CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
    inLen = MAX_DATA_LEN + 8;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, outLen, in, &inLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_EAL_AES_WRAP_PAD_API_TC001
 * @title  AES WRAP PAD abnormal input parameter test.
 * @precon nan
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call CRYPT_EAL_CipherInit set key, the keyLen is abnormal. Expected result 2 is obtained.
 *    3.Call CRYPT_EAL_CipherInit set iv, the ivLen is abnormal. Expected result 2 is obtained.
 *    4.Call CRYPT_EAL_CipherUpdate, the outLen is abnormal. Expected result 3 is obtained.
 * @expect
 *    1.Success.
 *    2.Failed. Return CRYPT_AES_ERR_KEYLEN.
 *    3.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    4.Failed. Return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_WRAP_PAD_API_TC001(void)
{
    TestMemInit();
    uint8_t out[MAX_DATA_LEN + AES_BLOCKSIZE];
    uint8_t in[MAX_DATA_LEN];
    uint8_t key[AES_BLOCKSIZE + 1];
    uint8_t iv[AES_BLOCKSIZE];
    uint32_t outLen = MAX_DATA_LEN;
    uint32_t inLen = MAX_DATA_LEN;
    uint32_t keyLen = AES_BLOCKSIZE;
    uint32_t ivLen = 4;
 
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_WRAP_PAD);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 7, iv, ivLen, true), CRYPT_AES_ERR_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, 3, true), CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, 5, true), CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);

    outLen = 7;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen), CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
    outLen = MAX_DATA_LEN;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen - 1, out, &outLen), CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
    outLen = MAX_DATA_LEN + 8;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen - 1, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ((inLen + 8), outLen);

    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, false), CRYPT_SUCCESS);
    inLen = MAX_DATA_LEN - 1;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, outLen, in, &inLen), CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
    inLen = outLen;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, outLen, in, &inLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_EAL_AES_WRAP_FUNC_TC001
 * @title  Encrypt and Decrypt vector test.
 * @precon nan
 * @brief
 *    1.Initialize the CTX. Expected result 1 is obtained.
 *    2.Call CRYPT_EAL_CipherUpdate. Expected result 2 is obtained.
 *    3.Compare ciphertext data. Expected result 3 is obtained.
 * @expect
 *    1.Success.
 *    2.Success.
 *    3.The ciphertext is the same as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_WRAP_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    TestMemInit();
    uint32_t len = 0;
    if (enc == 0) {  // Decrypt
        len = in->len - MAX_IV_LEN;
    } else {
        len = in->len + MAX_IV_LEN;
        if (algId == CRYPT_CIPHER_AES128_WRAP_PAD || algId == CRYPT_CIPHER_AES192_WRAP_PAD ||
            algId == CRYPT_CIPHER_AES256_WRAP_PAD) {
            len = len + (MAX_IV_LEN - (in->len % MAX_IV_LEN)); // Add padding len;
        }
    }
    uint8_t *outTmp = BSL_SAL_Malloc(len);
    ASSERT_TRUE(outTmp != NULL);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len), CRYPT_SUCCESS);
    ASSERT_EQ(len, out->len);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
EXIT:
    BSL_SAL_Free(outTmp);
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_EAL_AES_WRAP_FUNC_TC002
 * @title  AES-WRAP Use the default IV test.
 * @precon nan
 * @brief
 *    1.Initialize the CTX. Expected result 1 is obtained.
 *    2.Call CRYPT_EAL_CipherUpdate. Expected result 2 is obtained.
 * @expect
 *    1.Success.
 *    2.Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_WRAP_FUNC_TC002(int isProvider, int algId, int KeyLen)
{
    (void)isProvider;
    TestMemInit();
    uint8_t out1[MAX_DATA_LEN + 8];
    uint8_t out2[MAX_DATA_LEN + 8];
    uint8_t in1[MAX_DATA_LEN];
    uint8_t in2[MAX_DATA_LEN];
    uint8_t key[KeyLen + 1];
    uint32_t outLen = MAX_DATA_LEN;
    uint32_t inLen = MAX_DATA_LEN;
    uint32_t keyLen = KeyLen;
 
 #ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_CipherCtx *ctx = (isProvider == 0) ? CRYPT_EAL_CipherNewCtx(algId) :
        CRYPT_EAL_ProviderCipherNewCtx(NULL, algId, "provider=default");
#else
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
#endif
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, NULL, 0, true), CRYPT_SUCCESS);

    outLen = MAX_DATA_LEN + 8;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in1, inLen, out1, &outLen), CRYPT_SUCCESS);

    outLen = MAX_DATA_LEN + 8;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in1, inLen, out2, &outLen), CRYPT_SUCCESS);
    /* The ciphertext of multiple updates is consistent. */
    ASSERT_TRUE(memcmp(out1, out2, outLen) == 0);

    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, NULL, 0, false), CRYPT_SUCCESS);
    inLen = MAX_DATA_LEN + 8;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out1, outLen, in1, &inLen), CRYPT_SUCCESS);

    inLen = MAX_DATA_LEN + 8;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out1, outLen, in2, &inLen), CRYPT_SUCCESS);
    /* The plaintext of multiple updates is consistent. */
    ASSERT_TRUE(memcmp(in1, in2, inLen) == 0);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_EAL_AES_WRAP_FUNC_TC003
 * @title  Encrypt and Decrypt test. The input and output memory are the same.
 * @precon nan
 * @brief
 *    1.Initialize the CTX. Expected result 1 is obtained.
 *    2.Call CRYPT_EAL_CipherUpdate. Expected result 2 is obtained.
 *    3.Compare ciphertext data. Expected result 3 is obtained.
 * @expect
 *    1.Success.
 *    2.Success.
 *    3.The ciphertext is the same as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_WRAP_FUNC_TC003(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    TestMemInit();
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;

    ASSERT_EQ(memcpy_s(outTmp, MAX_OUTPUT, in->x, in->len), EOK);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, outTmp, in->len, outTmp, &len), CRYPT_SUCCESS);
    ASSERT_EQ(len, out->len);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CIPHER_AES_WRAP_NOT_ALIGN_TC001
 * @title  AES-WRAP Non-Aligned Address Encryption and Decryption Test.
 * @precon nan
 * @brief
 *    1.Test for AES-WRAP encryption, where all buffer addresses are not aligned, with expected result 1.
 *    2.Test for AES-WRAP decryption, where all buffer addresses are not aligned, with expected result 2.
 * @expect
 *    1.Encryption succeeds and ciphertext matches the vector
 *    2.Decryption succeeds and plaintext matches the vector
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CIPHER_AES_WRAP_NOT_ALIGN_TC001(int algId, Hex *key, Hex *plainText, Hex *cipherText)
{
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t keyTmp[MAX_DATA_LEN] __attribute__((aligned(8))) = {0};
    uint8_t ptTmp[MAX_DATA_LEN] __attribute__((aligned(8))) = {0};
    uint8_t ctTmp[MAX_DATA_LEN] __attribute__((aligned(8))) = {0};
    uint8_t* pKey = keyTmp + 1;
    uint8_t* pPt = ptTmp + 1;
    uint8_t* pCt = ctTmp + 1;
    uint32_t leftLen = MAX_DATA_LEN - 1;
    uint32_t totalLen = 0;

    ASSERT_TRUE(memcpy_s(pKey, MAX_DATA_LEN - 1, key->x, key->len) == EOK);
    ASSERT_TRUE(memcpy_s(pPt, MAX_DATA_LEN - 1, plainText->x, plainText->len) == EOK);
    TestMemInit();

    // Encrypt
    ASSERT_TRUE((ctx = CRYPT_EAL_CipherNewCtx(algId)) != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, pKey, key->len, NULL, 0, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pPt, plainText->len, pCt, &leftLen) == CRYPT_SUCCESS);
    totalLen = leftLen;
    leftLen = MAX_DATA_LEN - 1 - totalLen;
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, pCt + totalLen, &leftLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("AES-WRAP compare Ct", pCt, totalLen + leftLen, cipherText->x, cipherText->len);

    CRYPT_EAL_CipherDeinit(ctx);
    leftLen = MAX_DATA_LEN - 1;
    // Decrypt
    ASSERT_TRUE(memcpy_s(pCt, MAX_DATA_LEN - 1, cipherText->x, cipherText->len) == EOK);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, pKey, key->len, NULL, 0, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pCt, cipherText->len, pPt, &leftLen) == CRYPT_SUCCESS);
    totalLen = leftLen;
    leftLen = MAX_DATA_LEN - 1 - totalLen;
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, pPt + totalLen, &leftLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("AES-WRAP compare Pt", pPt, totalLen + leftLen, plainText->x, plainText->len);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */
