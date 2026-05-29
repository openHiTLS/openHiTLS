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

#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "bsl_sal.h"
#include <string.h>

/* END_HEADER */

/* ===================================================================
 * INIT_API tests
 * =================================================================== */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_INIT_API_TC001
 * @title  CRYPT_EAL_CipherInit NULL parameter test
 * @precon nan
 * @brief
 *    1. Init(NULL, key, keyLen, iv, ivLen, true). Expected CRYPT_NULL_INPUT.
 *    2. Init(ctx, NULL, keyLen, iv, ivLen, true). Expected CRYPT_NULL_INPUT.
 *    3. Init(ctx, key, keyLen, NULL, ivLen, true). Expected CRYPT_NULL_INPUT.
 * @expect
 *    1-3. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_INIT_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(NULL, key, sizeof(key), iv, sizeof(iv), true), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, NULL, sizeof(key), iv, sizeof(iv), true), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), NULL, sizeof(iv), true), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_INIT_API_TC002
 * @title  CRYPT_EAL_CipherInit invalid key/iv length test
 * @precon nan
 * @brief
 *    1. Init with keyLen=15 (short 1). Expected CRYPT_INVALID_ARG.
 *    2. Init with keyLen=17 (long 1). Expected CRYPT_INVALID_ARG.
 *    3. Init with ivLen=15 (short 1). Expected CRYPT_INVALID_ARG.
 *    4. Init with ivLen=17 (long 1). Expected CRYPT_INVALID_ARG.
 * @expect
 *    1-4. Return CRYPT_INVALID_ARG.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_INIT_API_TC002(void)
{
    TestMemInit();
    uint8_t key[17] = {0};
    uint8_t iv[17] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 15, iv, 16, true), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 17, iv, 16, true), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 15, true), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 17, true), CRYPT_INVALID_ARG);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD128A_INIT_API_TC001
 * @title  CRYPT_EAL_CipherInit invalid key length for ASCON-AEAD128A
 * @precon nan
 * @brief
 *    1. Init with keyLen=15. Expected CRYPT_INVALID_ARG.
 *    2. Init with keyLen=17. Expected CRYPT_INVALID_ARG.
 * @expect
 *    1-2. Return CRYPT_INVALID_ARG.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD128A_INIT_API_TC001(void)
{
    TestMemInit();
    uint8_t key[17] = {0};
    uint8_t iv[16] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128A);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 15, iv, sizeof(iv), true), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 17, iv, sizeof(iv), true), CRYPT_INVALID_ARG);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD80PQ_INIT_API_TC001
 * @title  CRYPT_EAL_CipherInit invalid key length for ASCON-AEAD80PQ
 * @precon nan
 * @brief
 *    1. Init with keyLen=19. Expected CRYPT_INVALID_ARG.
 *    2. Init with keyLen=21. Expected CRYPT_INVALID_ARG.
 * @expect
 *    1-2. Return CRYPT_INVALID_ARG.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD80PQ_INIT_API_TC001(void)
{
    TestMemInit();
    uint8_t key[21] = {0};
    uint8_t iv[16] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD80PQ);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 19, iv, sizeof(iv), true), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 21, iv, sizeof(iv), true), CRYPT_INVALID_ARG);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* ===================================================================
 * REINIT_API tests
 * =================================================================== */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_REINIT_API_TC001
 * @title  CRYPT_EAL_CipherReinit NULL parameter test
 * @precon nan
 * @brief
 *    1. Init. Expected SUCCESS.
 *    2. Reinit(ctx, NULL, ivLen). Expected CRYPT_NULL_INPUT.
 *    3. Reinit(NULL, iv, ivLen). Expected CRYPT_NULL_INPUT.
 * @expect
 *    1. CRYPT_SUCCESS. 2-3. CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_REINIT_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, NULL, sizeof(iv)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(NULL, iv, sizeof(iv)), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_REINIT_API_TC002
 * @title  CRYPT_EAL_CipherReinit invalid iv length test
 * @precon nan
 * @brief
 *    1. Init. Expected SUCCESS.
 *    2. Reinit with ivLen=15. Expected CRYPT_INVALID_ARG.
 *    3. Reinit with ivLen=17. Expected CRYPT_INVALID_ARG.
 * @expect
 *    1. CRYPT_SUCCESS. 2-3. CRYPT_INVALID_ARG.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_REINIT_API_TC002(void)
{
    TestMemInit();
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, 15), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, 17), CRYPT_INVALID_ARG);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_REINIT_API_TC003
 * @title  CRYPT_EAL_CipherReinit before Init test
 * @precon nan
 * @brief
 *    1. Reinit before Init. Expected CRYPT_EAL_ERR_STATE.
 * @expect
 *    1. CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_REINIT_API_TC003(void)
{
    TestMemInit();
    uint8_t iv[16] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv)), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* ===================================================================
 * UPDATE_API tests
 * =================================================================== */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_UPDATE_API_TC001
 * @title  CRYPT_EAL_CipherUpdate NULL/zero parameter test
 * @precon nan
 * @brief
 *    1. Update(NULL, in, len, out, &outLen). Expected CRYPT_NULL_INPUT.
 *    2. Update(ctx, NULL, len, out, &outLen). Expected CRYPT_NULL_INPUT.
 *    3. Update(ctx, in, 0, out, &outLen). Expected CRYPT_SUCCESS.
 *    4. Update(ctx, in, len, NULL, &outLen). Expected CRYPT_NULL_INPUT.
 *    5. Update(ctx, in, len, out, NULL). Expected CRYPT_NULL_INPUT.
 * @expect
 *    1,2,4,5: CRYPT_NULL_INPUT. 3: CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_UPDATE_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t data[16] = {0};
    uint8_t aad[8] = {0};
    uint8_t out[32];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(NULL, data, sizeof(data), out, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, NULL, sizeof(data), out, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), NULL, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), out, NULL), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_UPDATE_API_TC002
 * @title  CRYPT_EAL_CipherUpdate before Init test
 * @precon nan
 * @brief
 *    1. Update before Init. Expected CRYPT_EAL_ERR_STATE.
 * @expect
 *    1. CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_UPDATE_API_TC002(void)
{
    TestMemInit();
    uint8_t data[16] = {0};
    uint8_t out[32];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), out, &outLen), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* ===================================================================
 * FINAL_API tests
 * =================================================================== */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC001
 * @title  CRYPT_EAL_CipherFinal normal encrypt test
 * @precon nan
 * @brief
 *    1. Init->SetAAD->Update->Final. All CRYPT_SUCCESS.
 * @expect
 *    1. All CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[32] = {0};
    uint8_t out[64];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC002
 * @title  CRYPT_EAL_CipherFinal encrypt/decrypt round-trip test
 * @precon nan
 * @brief
 *    1. Encrypt pt→ct. Expected SUCCESS.
 *    2. Decrypt ct→pt'. Expected SUCCESS, pt' == pt.
 * @expect
 *    1-2. CRYPT_SUCCESS, plaintext matches.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC002(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[32] = {0};
    uint8_t ct[64] = {0}, out[64] = {0};
    uint32_t ctLen = sizeof(ct), outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    /* Encrypt */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Decrypt */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC003
 * @title  CRYPT_EAL_CipherFinal different IV gives different CT test
 * @precon nan
 * @brief
 *    1. Encrypt with IV1. Expected SUCCESS.
 *    2. Encrypt same pt with IV2. Expected SUCCESS.
 *    3. CT1 != CT2.
 * @expect
 *    1-2. CRYPT_SUCCESS. 3. Ciphertexts differ.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC003(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv1[16] = {0}, iv2[16] = {1}, aad[8] = {0}, pt[32] = {0};
    uint8_t ct1[64] = {0}, ct2[64] = {0};
    uint32_t ctLen1 = sizeof(ct1), ctLen2 = sizeof(ct2);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt with IV1 */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv1, sizeof(iv1), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct1, &ctLen1), CRYPT_SUCCESS);
    ctLen1 = sizeof(ct1);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct1, &ctLen1), CRYPT_SUCCESS);
    /* Encrypt with IV2 */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv2, sizeof(iv2), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct2, &ctLen2), CRYPT_SUCCESS);
    ctLen2 = sizeof(ct2);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct2, &ctLen2), CRYPT_SUCCESS);
    ASSERT_NE(memcmp(ct1, ct2, ctLen1), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC004
 * @title  CRYPT_EAL_CipherFinal Reinit test
 * @precon nan
 * @brief
 *    1. Init(badIV) -> SetAAD(badAAD). Expected SUCCESS.
 *    2. Reinit(goodIV) -> SetAAD(goodAAD). Expected SUCCESS.
 *    3. Update->Final. Expected SUCCESS.
 * @expect
 *    1-3. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC004(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, badIv[16] = {0xFF};
    uint8_t aad[8] = {0}, badAad[8] = {0xFF};
    uint8_t pt[32] = {0}, ct[64] = {0};
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), badIv, sizeof(badIv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, badAad, sizeof(badAad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC005
 * @title  CRYPT_EAL_CipherFinal multi-segment encrypt/decrypt test
 * @precon nan
 * @brief
 *    1. Encrypt pt in 2 segments. Expected SUCCESS.
 *    2. Decrypt ct in 2 segments. Expected SUCCESS.
 *    3. Decrypted plaintext matches pt.
 * @expect
 *    1-3. CRYPT_SUCCESS, plaintext matches.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC005(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0};
    uint8_t pt[100] = {0}, ct[128] = {0}, out[128] = {0};
    uint32_t ctLen, outLen;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt: 2 segments */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, 40, ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct) - 40;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt + 40, sizeof(pt) - 40, ct + 40, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Decrypt: 2 segments */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC006
 * @title  CRYPT_EAL_CipherFinal no message (AAD only) test
 * @precon nan
 * @brief
 *    1. Init->SetAAD->Final. Expected SUCCESS.
 * @expect
 *    1. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC006(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0};
    uint8_t out[32];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC007
 * @title  CRYPT_EAL_CipherFinal no AAD test
 * @precon nan
 * @brief
 *    1. Init->Update->Final without SetAAD. Expected SUCCESS.
 * @expect
 *    1. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC007(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t pt[32] = {0}, out[64] = {0};
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC008
 * @title  CRYPT_EAL_CipherFinal tampered ciphertext tag verification fail test
 * @precon nan
 * @brief
 *    1. Encrypt pt→ct. Expected SUCCESS.
 *    2. Tamper ct[0] ^= 1. Expected SUCCESS.
 *    3. Decrypt tampered ct. Expected tag verification failure.
 * @expect
 *    1-2. CRYPT_SUCCESS. 3. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC008(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[32] = {0};
    uint8_t ct[64] = {0};
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Tamper ciphertext first byte */
    ct[0] ^= 0x01;
    /* Decrypt - should fail tag verification */
    uint8_t out[64] = {0};
    uint32_t outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_NE(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC009
 * @title  CRYPT_EAL_CipherFinal tampered tag verification fail test
 * @precon nan
 * @brief
 *    1. Encrypt pt→ct. Expected SUCCESS.
 *    2. Tamper last byte (tag). Expected SUCCESS.
 *    3. Decrypt tampered ct. Expected tag verification failure.
 * @expect
 *    1-2. CRYPT_SUCCESS. 3. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC009(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[32] = {0};
    uint8_t ct[64] = {0};
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Tamper tag last byte */
    ct[ctLen - 1] ^= 0xFF;
    /* Decrypt - should fail */
    uint8_t out[64] = {0};
    uint32_t outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_NE(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC010
 * @title  CRYPT_EAL_CipherFinal deinit then update/final state test
 * @precon nan
 * @brief
 *    1. Init. Expected SUCCESS.
 *    2. Deinit. Expected SUCCESS.
 *    3. Update after Deinit. Expected CRYPT_EAL_ERR_STATE.
 *    4. Final after Deinit. Expected CRYPT_EAL_ERR_STATE.
 * @expect
 *    1-2. CRYPT_SUCCESS. 3-4. CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC010(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t out[32];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, NULL, 0, out, &outLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC011
 * @title  CRYPT_EAL_CipherFinal Final after Final state test
 * @precon nan
 * @brief
 *    1. Init->SetAAD->Update->Final (first). Expected SUCCESS.
 *    2. Final again. Expected CRYPT_EAL_ERR_STATE.
 * @expect
 *    1. CRYPT_SUCCESS. 2. CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC011(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[8] = {0};
    uint8_t ct[32];
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC012
 * @title  CRYPT_EAL_CipherFinal Update after Final state test
 * @precon nan
 * @brief
 *    1. Init->SetAAD->Update->Final. Expected SUCCESS.
 *    2. Update after Final. Expected CRYPT_EAL_ERR_STATE.
 * @expect
 *    1. CRYPT_SUCCESS. 2. CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC012(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[8] = {0};
    uint8_t ct[32];
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC013
 * @title  CRYPT_EAL_CipherFinal wrong key tag verification fail test
 * @precon nan
 * @brief
 *    1. Encrypt with key1. Expected SUCCESS.
 *    2. Decrypt same ciphertext with key2. Expected tag verification failure.
 * @expect
 *    1. CRYPT_SUCCESS. 2. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC013(void)
{
    TestMemInit();
    uint8_t key1[16] = {0}, key2[16] = {0xFF};
    uint8_t iv[16] = {0}, aad[8] = {0}, pt[32] = {0};
    uint8_t ct[64] = {0};
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt with key1 */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key1, sizeof(key1), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Decrypt with key2 - should fail */
    uint8_t out[64] = {0};
    uint32_t outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key2, sizeof(key2), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_NE(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC014
 * @title  CRYPT_EAL_CipherFinal wrong AAD tag verification fail test
 * @precon nan
 * @brief
 *    1. Encrypt with AAD1. Expected SUCCESS.
 *    2. Decrypt with AAD2. Expected tag verification failure.
 * @expect
 *    1. CRYPT_SUCCESS. 2. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC014(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t aad1[8] = {0}, aad2[8] = {0xFF};
    uint8_t pt[32] = {0}, ct[64] = {0};
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt with AAD1 */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad1, sizeof(aad1)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Decrypt with AAD2 - should fail */
    uint8_t out[64] = {0};
    uint32_t outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad2, sizeof(aad2)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_NE(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FINAL_API_TC015
 * @title  CRYPT_EAL_CipherFinal truncated ciphertext tag verification fail test
 * @precon nan
 * @brief
 *    1. Encrypt pt→ct. Expected SUCCESS.
 *    2. Truncate ct by 1 byte. Expected SUCCESS.
 *    3. Decrypt truncated ct. Expected tag verification failure.
 * @expect
 *    1-2. CRYPT_SUCCESS. 3. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FINAL_API_TC015(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[32] = {0};
    uint8_t ct[64] = {0};
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Truncate ct by 1 byte */
    ctLen -= 1;
    uint8_t out[64] = {0};
    uint32_t outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_NE(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC002
 * @title  ASCON-AEAD128 long plaintext (1KB) round-trip consistency test
 * @precon nan
 * @brief
 *    1. Encrypt 1KB pt. Expected SUCCESS.
 *    2. Decrypt ct→pt'. Expected SUCCESS, pt' matches pt.
 * @expect
 *    1-2. CRYPT_SUCCESS, pt' matches pt.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC002(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t pt[1024];
    uint8_t ct[1056];
    uint8_t out[1056];
    uint32_t ctLen = sizeof(ct);
    uint32_t outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(i & 0xFF);
    }
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt 1KB */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Decrypt */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC003
 * @title  ASCON-AEAD128 long AD (1KB) + empty PT round-trip consistency test
 * @precon nan
 * @brief
 *    1. Encrypt empty PT with 1KB AD. Expected SUCCESS.
 *    2. Decrypt with same AD→pt'. Expected SUCCESS.
 * @expect
 *    1-2. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC003(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t aad[1024];
    uint8_t ct[32];
    uint8_t out[32];
    uint32_t ctLen = sizeof(ct);
    uint32_t outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(aad); i++) {
        aad[i] = (uint8_t)(i & 0xFF);
    }
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* Decrypt with same long AD */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC004
 * @title  ASCON-AEAD128 long PT (1KB) + long AD (1KB) round-trip test
 * @precon nan
 * @brief
 *    1. Encrypt 1KB PT with 1KB AD. Expected SUCCESS.
 *    2. Decrypt→pt' matches pt. Expected SUCCESS.
 * @expect
 *    1-2. CRYPT_SUCCESS, pt' matches pt.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC004(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t aad[1024];
    uint8_t pt[1024];
    uint8_t ct[1056];
    uint8_t out[1056];
    uint32_t ctLen = sizeof(ct);
    uint32_t outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(i & 0xFF);
        aad[i] = (uint8_t)((i * 7) & 0xFF);
    }
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* ---- More round-trip consistency tests: various sizes & variants ---- */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC005
 * @title  ASCON-AEAD128 long PT 64B round-trip test
 * @precon nan
 * @brief  Encrypt/decrypt 64-byte plaintext, verify consistency.
 * @expect CRYPT_SUCCESS, plaintext matches.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC005(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t pt[64];
    uint8_t ct[96], out[96];
    uint32_t ctLen = sizeof(ct), outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i & 0xFF);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC006
 * @title  ASCON-AEAD128 long PT 128B round-trip test
 * @precon nan
 * @brief  Encrypt/decrypt 128-byte plaintext, verify consistency.
 * @expect CRYPT_SUCCESS, plaintext matches.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC006(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t pt[128];
    uint8_t ct[160], out[160];
    uint32_t ctLen = sizeof(ct), outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i & 0xFF);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC007
 * @title  ASCON-AEAD128 long PT 256B round-trip test
 * @precon nan
 * @brief  Encrypt/decrypt 256-byte plaintext, verify consistency.
 * @expect CRYPT_SUCCESS, plaintext matches.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC007(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t pt[256];
    uint8_t ct[288], out[288];
    uint32_t ctLen = sizeof(ct), outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i & 0xFF);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC008
 * @title  ASCON-AEAD128A long PT 512B round-trip test
 * @precon nan
 * @brief  Encrypt/decrypt 512-byte plaintext with AEAD128A.
 * @expect CRYPT_SUCCESS, plaintext matches.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC008(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t pt[512];
    uint8_t ct[544], out[544];
    uint32_t ctLen = sizeof(ct), outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i & 0xFF);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128A);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC009
 * @title  ASCON-AEAD128A long AD 512B round-trip test
 * @precon nan
 * @brief  Encrypt/decrypt empty PT with 512-byte AD using AEAD128A.
 * @expect CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC009(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t aad[512];
    uint8_t ct[32], out[32];
    uint32_t ctLen = sizeof(ct), outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(aad); i++) aad[i] = (uint8_t)(i & 0xFF);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128A);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC010
 * @title  ASCON-AEAD80PQ long PT 512B round-trip test
 * @precon nan
 * @brief  Encrypt/decrypt 512-byte plaintext with AEAD80PQ.
 * @expect CRYPT_SUCCESS, plaintext matches.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC010(void)
{
    TestMemInit();
    uint8_t key[20] = {0}, iv[16] = {0};
    uint8_t pt[512];
    uint8_t ct[544];
    uint8_t out[544];
    uint32_t ctLen = sizeof(ct);
    uint32_t outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i & 0xFF);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD80PQ);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt, sizeof(pt)), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC011
 * @title  ASCON-AEAD80PQ long AD 512B round-trip test
 * @precon nan
 * @brief  Encrypt/decrypt empty PT with 512-byte AD using AEAD80PQ.
 * @expect CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC011(void)
{
    TestMemInit();
    uint8_t key[20] = {0}, iv[16] = {0};
    uint8_t aad[512];
    uint8_t ct[32];
    uint8_t out[32];
    uint32_t ctLen = sizeof(ct);
    uint32_t outLen = sizeof(out);
    for (uint32_t i = 0; i < sizeof(aad); i++) aad[i] = (uint8_t)(i & 0xFF);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD80PQ);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* ===================================================================
 * CTRL_API tests
 * =================================================================== */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_CTRL_API_TC001
 * @title  CRYPT_EAL_CipherCtrl SET_AAD null parameter test
 * @precon nan
 * @brief
 *    1. Init. Expected SUCCESS.
 *    2. SET_AAD with aad=NULL, aadLen!=0. Expected CRYPT_NULL_INPUT.
 *    3. SET_AAD with ctx=NULL. Expected CRYPT_NULL_INPUT.
 * @expect
 *    1. CRYPT_SUCCESS. 2-3. CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_CTRL_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[20] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, NULL, sizeof(aad)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(NULL, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_CTRL_API_TC002
 * @title  CRYPT_EAL_CipherCtrl SET_AAD before Init test
 * @precon nan
 * @brief
 *    1. SET_AAD before Init. Expected CRYPT_EAL_ERR_STATE.
 * @expect
 *    1. CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_CTRL_API_TC002(void)
{
    TestMemInit();
    uint8_t aad[20] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_CTRL_API_TC003
 * @title  CRYPT_EAL_CipherCtrl SET_AAD repeat test
 * @precon nan
 * @brief
 *    1. Init->SET_AAD. Expected SUCCESS.
 *    2. SET_AAD again. Expected failure (already set).
 * @expect
 *    1. CRYPT_SUCCESS. 2. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_CTRL_API_TC003(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[20] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_CTRL_API_TC004
 * @title  CRYPT_EAL_CipherCtrl SET_AAD zero length test
 * @precon nan
 * @brief
 *    1. Init->SET_AAD with aadLen=0. Expected SUCCESS.
 * @expect
 *    1. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_CTRL_API_TC004(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, NULL, 0), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_CTRL_API_TC005
 * @title  CRYPT_EAL_CipherCtrl GET_TAG null/unsupported test
 * @precon nan
 * @brief
 *    1. Encrypt to produce tag.
 *    2. GET_TAG with tag=NULL. Expected CRYPT_NULL_INPUT.
 *    3. Unsupported CRYPT_CTRL command. Expected CRYPT_EAL_ERR_STATE.
 * @expect
 *    1. CRYPT_SUCCESS. 2. CRYPT_NULL_INPUT. 3. CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_CTRL_API_TC005(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[8] = {0};
    uint8_t ct[32], tag[16];
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    /* GET_TAG with NULL tag */
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, NULL, sizeof(tag)), CRYPT_NULL_INPUT);
    /* Unsupported CTRL command - returns state error */
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, tag, sizeof(tag)), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_CTRL_API_TC006
 * @title  CRYPT_EAL_CipherCtrl GET_TAG before Init test
 * @precon nan
 * @brief
 *    1. GET_TAG before Init or Final. Expected failure.
 * @expect
 *    1. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_CTRL_API_TC006(void)
{
    TestMemInit();
    uint8_t tag[16];
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_NE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, sizeof(tag)), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_SETPADDING_API_TC001
 * @title  CRYPT_EAL_CipherSetPadding not supported for AEAD test
 * @precon nan
 * @brief
 *    1. Init->SetAAD->SetPadding. Expected != CRYPT_SUCCESS.
 * @expect
 *    1. != CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_SETPADDING_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_ZEROS), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_GETPADDING_API_TC001
 * @title  CRYPT_EAL_CipherGetPadding not supported for AEAD test
 * @precon nan
 * @brief
 *    1. Init->SetAAD->GetPadding. Expected CRYPT_PADDING_MAX_COUNT.
 * @expect
 *    1. CRYPT_PADDING_MAX_COUNT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_GETPADDING_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherGetPadding(ctx), CRYPT_PADDING_MAX_COUNT);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_GETTAG_API_TC001
 * @title  CRYPT_EAL_CipherCtrl GET_TAG normal test
 * @precon nan
 * @brief
 *    1. Encrypt. Expected SUCCESS.
 *    2. GET_TAG. Expected SUCCESS.
 *    3. Verify tag matches output tag. Expected match.
 * @expect
 *    1-2. CRYPT_SUCCESS. 3. Tags match.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_GETTAG_API_TC001(void)
{
    TestMemInit();
    uint8_t key[16] = {0}, iv[16] = {0}, aad[8] = {0}, pt[32] = {0};
    uint8_t ct[64], tag[16];
    uint32_t ctLen = sizeof(ct);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt, sizeof(pt), ct, &ctLen), CRYPT_SUCCESS);
    ctLen = sizeof(ct);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, sizeof(tag)), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(tag, ct + sizeof(pt), 16), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* ===================================================================
 * FUNC tests (encrypt/decrypt round-trip + KAT verification)
 * =================================================================== */

/**
 * @test  SDV_CRYPTO_ASCONAEAD_FUNC_TC001
 * @title  ASCON-AEAD128 encrypt/decrypt functional test with optional KAT verification
 * @precon nan
 * @brief
 *    1. Encrypt pt->ct using key/iv/aad. Expected SUCCESS.
 *    2. Compare ct with expectedCt if provided.
 *    3. Decrypt ct->pt'. Expected SUCCESS, pt'==pt.
 * @expect
 *    1. CRYPT_SUCCESS. 2. ct matches expectedCt. 3. pt' matches pt.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD_FUNC_TC001(Hex *key, Hex *iv, Hex *aad, Hex *pt, Hex *expectedCt)
{
    TestMemInit();
    uint8_t out[256];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128);
    ASSERT_TRUE(ctx != NULL);
    /* Encrypt */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt->x, pt->len, out, &outLen), CRYPT_SUCCESS);
    uint32_t finalLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &finalLen), CRYPT_SUCCESS);
    uint32_t totalLen = finalLen;
    if (expectedCt->x != NULL && expectedCt->len > 0) {
        ASSERT_EQ(totalLen, expectedCt->len);
        ASSERT_EQ(memcmp(out, expectedCt->x, expectedCt->len), 0);
    }
    /* Decrypt */
    CRYPT_EAL_CipherDeinit(ctx);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, totalLen, out, &outLen), CRYPT_SUCCESS);
    finalLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &finalLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt->x, pt->len), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD128A_FUNC_TC001
 * @title  ASCON-AEAD128A encrypt/decrypt functional test with KAT verification
 * @precon nan
 * @brief
 *    1. Encrypt pt->ct using key/iv/aad. Expected SUCCESS.
 *    2. Compare ct with expectedCt if provided.
 *    3. Decrypt ct->pt'. Expected SUCCESS, pt'==pt.
 * @expect
 *    1. CRYPT_SUCCESS. 2. ct matches expectedCt. 3. pt' matches pt.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD128A_FUNC_TC001(Hex *key, Hex *iv, Hex *aad, Hex *pt, Hex *expectedCt)
{
    TestMemInit();
    uint8_t out[256];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD128A);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt->x, pt->len, out, &outLen), CRYPT_SUCCESS);
    uint32_t finalLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &finalLen), CRYPT_SUCCESS);
    uint32_t totalLen = finalLen;
    if (expectedCt->x != NULL && expectedCt->len > 0) {
        ASSERT_EQ(totalLen, expectedCt->len);
        ASSERT_EQ(memcmp(out, expectedCt->x, expectedCt->len), 0);
    }
    CRYPT_EAL_CipherDeinit(ctx);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, totalLen, out, &outLen), CRYPT_SUCCESS);
    finalLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &finalLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt->x, pt->len), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_ASCONAEAD80PQ_FUNC_TC001
 * @title  ASCON-AEAD80PQ encrypt/decrypt functional test with KAT verification
 * @precon nan
 * @brief
 *    1. Encrypt pt->ct using key/iv/aad. Expected SUCCESS.
 *    2. Compare ct with expectedCt if provided.
 *    3. Decrypt ct->pt'. Expected SUCCESS, pt'==pt.
 * @expect
 *    1. CRYPT_SUCCESS. 2. ct matches expectedCt. 3. pt' matches pt.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ASCONAEAD80PQ_FUNC_TC001(Hex *key, Hex *iv, Hex *aad, Hex *pt, Hex *expectedCt)
{
    TestMemInit();
    uint8_t out[256];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ASCON_AEAD80PQ);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt->x, pt->len, out, &outLen), CRYPT_SUCCESS);
    uint32_t finalLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &finalLen), CRYPT_SUCCESS);
    uint32_t totalLen = finalLen;
    if (expectedCt->x != NULL && expectedCt->len > 0) {
        ASSERT_EQ(totalLen, expectedCt->len);
        ASSERT_EQ(memcmp(out, expectedCt->x, expectedCt->len), 0);
    }
    CRYPT_EAL_CipherDeinit(ctx);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, totalLen, out, &outLen), CRYPT_SUCCESS);
    finalLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &finalLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, pt->x, pt->len), 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */
