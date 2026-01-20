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
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "eal_pkey_local.h"
#include "securec.h"
/* END_HEADER */

/* @
* @test  SDV_CRYPTO_HYBRID_API_TC001
* @spec  -
* @title  Check the value returned by the ctrl interface meets the expectation.
* @precon  nan
* @brief
* 1.Create the context of the algorithm.
* 2.Call CRYPT_EAL_PkeyCtrl to set and get parameters in the context.
* @expect  1.success 2.success
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HYBRID_API_TC001(int algid, int type, int ekLen, int ctLen, int skLen)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctxA = CRYPT_EAL_PkeyNewCtx((int32_t)algid);
    ASSERT_TRUE(ctxA != NULL);

    int32_t val = CRYPT_PKEY_PARAID_MAX;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_ERR_ALGID);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, 0, &val, sizeof(val)), CRYPT_NOT_SUPPORT);

    val = (int32_t)type;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(encapsKeyLen, ekLen);

    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(cipherLen, ctLen);

    uint32_t sharedLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLen, sizeof(sharedLen)), CRYPT_SUCCESS);
    ASSERT_EQ(sharedLen, skLen);

    if (type != CRYPT_HYBRID_X25519_MLKEM512 && type != CRYPT_HYBRID_X25519_MLKEM768 && type !=
        CRYPT_HYBRID_X25519_MLKEM1024) {
        val = CRYPT_POINT_COMPRESSED;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &val, sizeof(val)), CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctxA);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HYBRID_ENCAPS_DECAPS_FUNC_TC001
* @spec  -
* @title  Generating key pairs and key exchange tests
* @precon  nan
* @brief
* 1.Registers the callback function of the memory and random.
* 2.Create a context for key exchange and set parameters.
* 3.Generating a key pair.
* 4.Perform key exchange.
* 5.Check whether the shared keys are the same.
* @expect  1.success 2.success 3.success 4.success 5.The shared key is the same.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HYBRID_ENCAPS_DECAPS_FUNC_TC001(int algid, int type, int isProvider)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    CRYPT_EAL_PkeyCtx *ctxA = NULL;
    CRYPT_EAL_PkeyCtx *ctxB = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        ctxA = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algid, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
        ASSERT_TRUE(ctxA != NULL);
        ctxB = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algid, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
        ASSERT_TRUE(ctxB != NULL);
    } else
#endif    
    {
        (void) isProvider;
        ctxA = CRYPT_EAL_PkeyNewCtx(algid);
        ASSERT_TRUE(ctxA != NULL);
        ctxB = CRYPT_EAL_PkeyNewCtx(algid);
        ASSERT_TRUE(ctxB != NULL);
    }

    uint32_t val = (uint32_t)type;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxB, val), CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen)),
        CRYPT_SUCCESS);
    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen)),
        CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = algid;
    ek.key.kemEk.len = encapsKeyLen;
    ek.key.kemEk.data = BSL_SAL_Malloc(encapsKeyLen);
    ASSERT_TRUE(ek.key.kemEk.data != NULL);

    uint32_t sharedLenA = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLenA, sizeof(sharedLenA)), CRYPT_SUCCESS);
    uint8_t *sharedKeyA = BSL_SAL_Malloc(sharedLenA);
    ASSERT_TRUE(sharedKeyA != NULL);
    uint32_t sharedLenB = sharedLenA;
    uint8_t *sharedKeyB = BSL_SAL_Malloc(sharedLenB);
    ASSERT_TRUE(sharedKeyB != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctxA), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctxA, &ek), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctxB, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctxB, ciphertext, &cipherLen, sharedKeyA, &sharedLenA), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctxA, ciphertext, cipherLen, sharedKeyB, &sharedLenB), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare sharedKey", sharedKeyB, sharedLenB, sharedKeyA, sharedLenA);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(ek.key.kemEk.data);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKeyA);
    BSL_SAL_Free(sharedKeyB);
    CRYPT_EAL_PkeyFreeCtx(ctxA);
    CRYPT_EAL_PkeyFreeCtx(ctxB);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* Use default random numbers for end-to-end testing */
/* BEGIN_CASE */
void SDV_CRYPTO_HYBRID_ENCAPS_DECAPS_API_TC002(int algid, int type, int isProvider)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctxA = NULL;
    CRYPT_EAL_PkeyCtx *ctxB = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        ctxA = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algid, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
        ASSERT_TRUE(ctxA != NULL);
        ctxB = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algid, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
        ASSERT_TRUE(ctxB != NULL);
    } else
#endif    
    {
        (void) isProvider;
        ctxA = CRYPT_EAL_PkeyNewCtx(algid);
        ASSERT_TRUE(ctxA != NULL);
        ctxB = CRYPT_EAL_PkeyNewCtx(algid);
        ASSERT_TRUE(ctxB != NULL);
    }

    uint32_t val = (uint32_t)type;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxB, val), CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen)),
        CRYPT_SUCCESS);
    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen)),
        CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = algid;
    ek.key.kemEk.len = encapsKeyLen;
    ek.key.kemEk.data = BSL_SAL_Malloc(encapsKeyLen);
    ASSERT_TRUE(ek.key.kemEk.data != NULL);

    uint32_t sharedLenA = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLenA, sizeof(sharedLenA)), CRYPT_SUCCESS);
    uint8_t *sharedKeyA = BSL_SAL_Malloc(sharedLenA);
    ASSERT_TRUE(sharedKeyA != NULL);
    uint32_t sharedLenB = sharedLenA;
    uint8_t *sharedKeyB = BSL_SAL_Malloc(sharedLenB);
    ASSERT_TRUE(sharedKeyB != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctxA), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctxA, &ek), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctxB, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctxB, ciphertext, &cipherLen, sharedKeyA, &sharedLenA), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctxA, ciphertext, cipherLen, sharedKeyB, &sharedLenB), CRYPT_SUCCESS);
EXIT:
    BSL_SAL_Free(ek.key.kemEk.data);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKeyA);
    BSL_SAL_Free(sharedKeyB);
    CRYPT_EAL_PkeyFreeCtx(ctxA);
    CRYPT_EAL_PkeyFreeCtx(ctxB);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HYBRID_ENCAPS_DECAPS_FUNC_TC002
* @spec  -
* @title  Setting the key pair and key exchange test
* @precon  nan
* @brief
* 1.Registers the callback function of the memory and random.
* 2.Create a context for key exchange and set parameters.
* 3.Setting a key pair.
* 4.Perform key exchange.
* 5.Check whether the shared keys are the same.
* @expect  1.success 2.success 3.success 4.success 5.The shared key is the same.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HYBRID_ENCAPS_DECAPS_FUNC_TC002(int algid, int type, int isProvider, Hex *encapsKeyA, Hex *decapsKeyA)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    CRYPT_EAL_PkeyCtx *ctxA = NULL;
    CRYPT_EAL_PkeyCtx *ctxB = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        ctxA = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algid, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
        ASSERT_TRUE(ctxA != NULL);
        ctxB = CRYPT_EAL_ProviderPkeyNewCtx(NULL, algid, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
        ASSERT_TRUE(ctxB != NULL);
    } else
#endif
    {
        (void)isProvider;
        ctxA = CRYPT_EAL_PkeyNewCtx(algid);
        ASSERT_TRUE(ctxA != NULL);
        ctxB = CRYPT_EAL_PkeyNewCtx(algid);
        ASSERT_TRUE(ctxB != NULL);
    }
    uint32_t val = (uint32_t)type;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxB, val), CRYPT_SUCCESS);
    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen)),
        CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);

    uint32_t sharedLenA = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLenA, sizeof(sharedLenA)), CRYPT_SUCCESS);
    uint8_t *sharedKeyA = BSL_SAL_Malloc(sharedLenA);
    ASSERT_TRUE(sharedKeyA != NULL);
    uint32_t sharedLenB = sharedLenA;
    uint8_t *sharedKeyB = BSL_SAL_Malloc(sharedLenB);
    ASSERT_TRUE(sharedKeyB != NULL);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = algid;
    ek.key.kemEk.len = encapsKeyA->len;
    ek.key.kemEk.data = encapsKeyA->x;
    CRYPT_EAL_PkeyPrv dk = { 0 };
    dk.id = algid;
    dk.key.kemDk.len = decapsKeyA->len;
    dk.key.kemDk.data = decapsKeyA->x;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctxA, &dk), CRYPT_SUCCESS);

    ek.key.kemEk.len = encapsKeyA->len;
    ek.key.kemEk.data = encapsKeyA->x;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctxB, &ek), CRYPT_SUCCESS);
    uint32_t decapsLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsLen, sizeof(decapsLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(decapsLen, dk.key.kemDk.len);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctxA, &dk), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare private key", dk.key.kemDk.data, dk.key.kemDk.len, decapsKeyA->x, decapsKeyA->len);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctxB, ciphertext, &cipherLen, sharedKeyB, &sharedLenB), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctxA, ciphertext, cipherLen, sharedKeyA, &sharedLenA), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare sharedKey", sharedKeyB, sharedLenB, sharedKeyA, sharedLenA);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKeyA);
    BSL_SAL_Free(sharedKeyB);
    CRYPT_EAL_PkeyFreeCtx(ctxA);
    CRYPT_EAL_PkeyFreeCtx(ctxB);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */
