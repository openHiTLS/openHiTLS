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
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "crypt_eal_init.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_implprovider.h"
#include "drbg_local.h"
#include "eal_md_local.h"
#include "eal_drbg_local.h"
#include "bsl_err_internal.h"
#include "bsl_err.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "crypt_provider.h"
#include "crypt_drbg.h"
/* END_HEADER */

#define CTR_AES128_SEEDLEN (32)
#define AES_BLOCK_LEN (16)
#define TEST_DRBG_DATA_SIZE (256)
#define DRBG_OUTPUT_SIZE (1024)
#define DRBG_MAX_OUTPUT_SIZE (65536)
#define DRBG_MAX_ADIN_SIZE (65536)

typedef struct {
    bool entropyState;
    bool nonceState;
} CallBackCtl_t;

typedef enum {
    RAND_AES128_KEYLEN = 16,
    RAND_AES192_KEYLEN = 24,
    RAND_AES256_KEYLEN = 32,
} RAND_AES_KeyLen;

CallBackCtl_t g_callBackCtl = { 0 };

typedef struct {
    CRYPT_Data *entropy;
    CRYPT_Data *nonce;
    CRYPT_Data *pers;

    CRYPT_Data *addin1;
    CRYPT_Data *entropyPR1;

    CRYPT_Data *addin2;
    CRYPT_Data *entropyPR2;

    CRYPT_Data *retBits;
} DRBG_Vec_t;

#define DRBG_FREE(ptr)       \
    do {                     \
        if ((ptr) != NULL) { \
            free(ptr);       \
        }                    \
    } while (0)

static int32_t PthreadRWLockNew(BSL_SAL_ThreadLockHandle *lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    pthread_rwlock_t *newLock;
    newLock = (pthread_rwlock_t *)malloc(sizeof(pthread_rwlock_t));
    if (newLock == NULL) {
        return BSL_MALLOC_FAIL;
    }
    if (pthread_rwlock_init(newLock, NULL) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    *lock = newLock;
    return BSL_SUCCESS;
}

static void PthreadRWLockFree(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return;
    }
    pthread_rwlock_destroy((pthread_rwlock_t *)lock);
    DRBG_FREE(lock);
}

static int32_t PthreadRWLockReadLock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_rdlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t PthreadRWLockWriteLock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_wrlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t PthreadRWLockUnlock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_unlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static uint64_t PthreadGetId(void)
{
    return (uint64_t)pthread_self();
}

static void RegThreadFunc(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_NEW_CB_FUNC, PthreadRWLockNew);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_FREE_CB_FUNC, PthreadRWLockFree);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC, PthreadRWLockReadLock);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, PthreadRWLockWriteLock);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC, PthreadRWLockUnlock);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, PthreadGetId);
}

static void seedCtxFree(DRBG_Vec_t *seedCtx)
{
    if (seedCtx != NULL) {
        DRBG_FREE(seedCtx->entropy);
        DRBG_FREE(seedCtx->entropyPR1);
        DRBG_FREE(seedCtx->entropyPR2);
        DRBG_FREE(seedCtx->addin1);
        DRBG_FREE(seedCtx->addin2);
        DRBG_FREE(seedCtx->nonce);
        DRBG_FREE(seedCtx->retBits);
        DRBG_FREE(seedCtx->pers);
    }
    free(seedCtx);
}

static DRBG_Vec_t *seedCtxMem(void)
{
    DRBG_Vec_t *seedCtx;

    seedCtx = calloc(1u, sizeof(DRBG_Vec_t));
    ASSERT_TRUE(seedCtx != NULL);
    seedCtx->entropy = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->entropy != NULL);
    seedCtx->entropyPR1 = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->entropyPR1 != NULL);
    seedCtx->entropyPR2 = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->entropyPR2 != NULL);
    seedCtx->addin1 = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->addin1 != NULL);
    seedCtx->addin2 = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->addin2 != NULL);
    seedCtx->nonce = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->nonce != NULL);
    seedCtx->retBits = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->retBits != NULL);
    seedCtx->pers = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_TRUE(seedCtx->pers != NULL);

    return seedCtx;
EXIT:
    seedCtxFree(seedCtx);
    return NULL;
}

/* Initializes the drbg context seed. Internally, ensure that the parameters are correct. */
static void seedCtxCfg(DRBG_Vec_t *seedCtx, Hex *entropy, Hex *nonce, Hex *pers, Hex *addin1, Hex *entropyPR1,
    Hex *addin2, Hex *entropyPR2, Hex *retBits)
{
    seedCtx->entropy->data = entropy->x;
    seedCtx->entropy->len = entropy->len;
    seedCtx->nonce->data = nonce->x;
    seedCtx->nonce->len = nonce->len;
    seedCtx->pers->data = pers->x;
    seedCtx->pers->len = pers->len;
    seedCtx->addin1->data = addin1->x;
    seedCtx->addin1->len = addin1->len;
    seedCtx->entropyPR1->data = entropyPR1->x;
    seedCtx->entropyPR1->len = entropyPR1->len;
    seedCtx->addin2->data = addin2->x;
    seedCtx->addin2->len = addin2->len;
    seedCtx->entropyPR2->data = entropyPR2->x;
    seedCtx->entropyPR2->len = entropyPR2->len;
    seedCtx->retBits->data = retBits->x;
    seedCtx->retBits->len = retBits->len;
}

static int32_t getEntropyError(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    (void)lenRange;
    CallBackCtl_t *state = (CallBackCtl_t *)ctx;
    if (state->entropyState != 0) {
        entropy = NULL;
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    uint32_t entroyLen = sizeof(uint8_t) * TEST_DRBG_DATA_SIZE;
    entropy->data = calloc(1u, entroyLen);
    entropy->len = entroyLen;
    return CRYPT_SUCCESS;
}

static void cleanEntropyError(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    if (entropy != NULL && entropy->data != NULL) {
        free(entropy->data);
    }
    return;
}

static int32_t getNonceError(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    (void)lenRange;
    CallBackCtl_t *state = (CallBackCtl_t *)ctx;
    if (state->nonceState != 0) {
        nonce = NULL;
        return CRYPT_DRBG_FAIL_GET_NONCE;
    }
    uint32_t nonceLen = sizeof(uint8_t) * TEST_DRBG_DATA_SIZE;
    nonce->data = calloc(1u, nonceLen);
    nonce->len = nonceLen;
    return CRYPT_SUCCESS;
}

static void cleanNonceError(void *ctx, CRYPT_Data *nonce)
{
    (void)ctx;
    if (nonce != NULL && nonce->data != NULL) {
        free(nonce->data);
    }
    return;
}

static int32_t getEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    if (ctx == NULL || entropy == NULL || lenRange == NULL) {
        return CRYPT_NULL_INPUT;
    }
    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;

    if (seedCtx->entropy->len > lenRange->max || seedCtx->entropy->len < lenRange->min) {
        return CRYPT_DRBG_INVALID_LEN;
    }

    entropy->data = seedCtx->entropy->data;
    entropy->len = seedCtx->entropy->len;

    return CRYPT_SUCCESS;
}

static void cleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    if (ctx == NULL || entropy == NULL) {
        return;
    }
    return;
}

static int32_t getNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    if (ctx == NULL || nonce == NULL || lenRange == NULL) {
        return CRYPT_NULL_INPUT;
    }

    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;

    if (seedCtx->nonce->len > lenRange->max || seedCtx->nonce->len < lenRange->min) {
        return CRYPT_DRBG_INVALID_LEN;
    }

    nonce->data = seedCtx->nonce->data;
    nonce->len = seedCtx->nonce->len;

    return CRYPT_SUCCESS;
}

static void cleanNonce(void *ctx, CRYPT_Data *nonce)
{
    if (ctx == NULL || nonce == NULL) {
        return;
    }
    return;
}

static int32_t getEntropyUnCheckPara(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    (void)lenRange;
    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;
    entropy->data = seedCtx->entropy->data;
    entropy->len = seedCtx->entropy->len;

    return CRYPT_SUCCESS;
}

static int32_t getNonceUnCheckPara(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    (void)lenRange;
    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;

    nonce->data = seedCtx->nonce->data;
    nonce->len = seedCtx->nonce->len;

    return CRYPT_SUCCESS;
}

static void regSeedMeth(CRYPT_RandSeedMethod *seedMeth)
{
    seedMeth->getEntropy = getEntropy;
    seedMeth->cleanEntropy = cleanEntropy;
    seedMeth->getNonce = getNonce;
    seedMeth->cleanNonce = cleanNonce;
}

static void drbgDataInit(CRYPT_Data *data, uint32_t size)
{
    uint8_t *dataTmp = NULL;
    if (size != 0) {
        dataTmp = malloc(sizeof(uint8_t) * size);
        if (dataTmp == NULL) {
            return;
        }
        (void)memset_s(dataTmp, size, 0, size);
    }
    data->data = dataTmp;
    data->len = size;
}

static void drbgDataFree(CRYPT_Data *data)
{
    if (data != NULL) {
        if (data->data != NULL) {
            free(data->data);
        }
    }
}

/* Mapping between RAND and specific random number generation algorithms */
static const int g_drbgMethodMap[] = {
    CRYPT_MD_SHA1,
    CRYPT_MD_SHA224,
    CRYPT_MD_SHA256,
    CRYPT_MD_SHA384,
    CRYPT_MD_SHA512,
    CRYPT_MD_SM3,
    CRYPT_MAC_HMAC_SHA1,
    CRYPT_MAC_HMAC_SHA224,
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
    CRYPT_SYM_AES128,
    CRYPT_SYM_AES192,
    CRYPT_SYM_AES256,
    CRYPT_SYM_AES128,
    CRYPT_SYM_AES192,
    CRYPT_SYM_AES256
};

static uint32_t GetAesKeyLen(int id, uint32_t *keyLen)
{
    switch (id) {
        case CRYPT_SYM_AES128:
            *keyLen = RAND_AES128_KEYLEN;
            break;
        case CRYPT_SYM_AES192:
            *keyLen = RAND_AES192_KEYLEN;
            break;
        case CRYPT_SYM_AES256:
            *keyLen = RAND_AES256_KEYLEN;
            break;
        default:
            return CRYPT_DRBG_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

static void InitSeedCtx(CRYPT_RAND_AlgId id, DRBG_Vec_t *seedCtx, CRYPT_Data *data)
{
    if (id < CRYPT_RAND_AES128_CTR || id > CRYPT_RAND_AES256_CTR) {
        drbgDataInit(data, TEST_DRBG_DATA_SIZE);
        seedCtx->entropy = data;
        seedCtx->nonce = data;
    } else {
        uint32_t keyLen = 0;
        GetAesKeyLen(g_drbgMethodMap[id - CRYPT_RAND_SHA1], &keyLen);
        drbgDataInit(data, (AES_BLOCK_LEN + keyLen));
        seedCtx->entropy = data;
    }
    return;
}

static int sdvCryptEalRandSeedAdinApiTest(uint8_t *addin, uint32_t addinLen)
{
    int ret;
    uint8_t *output = NULL;

    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;
    ASSERT_EQ(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, &seedCtx, NULL, 0), CRYPT_SUCCESS);

    output = malloc(sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_TRUE(output != NULL);
    (void)memset_s(output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE, 0, sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ret = CRYPT_EAL_RandbytesWithAdin(output, DRBG_OUTPUT_SIZE, NULL, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_RandSeedWithAdin(addin, addinLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_RandSeed();
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_RandDeinit();
    drbgDataFree(&data);
    free(output);
    return ret;
}

static int sdvCryptEalDrbgSeedAdinApiTest(uint8_t *addin, uint32_t addinLen)
{
    int ret;
    uint8_t *output = NULL;

    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    void *drbgCtx = NULL;

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;
    drbgCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);

    output = malloc(sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_TRUE(output != NULL);
    (void)memset_s(output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE, 0, sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ret = CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_OUTPUT_SIZE, NULL, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_DrbgSeedWithAdin(drbgCtx, addin, addinLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_DrbgSeed(drbgCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbgCtx);
    drbgDataFree(&data);
    free(output);
    return ret;
}

static void sdvCryptEalThreadTest(void *drbgCtx)
{
    int i = 0;
    int ret;
    uint8_t *output = NULL;

    output = malloc(sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_TRUE(output != NULL);

    for (i = 0; i < 100; i++) { // Perform 100 * 2 times random number generation in the thread.
        ret = CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE, NULL, 0);
        ASSERT_EQ(ret, CRYPT_SUCCESS);

        ret = CRYPT_EAL_DrbgSeedWithAdin(drbgCtx, NULL, 0);
        ASSERT_EQ(ret, CRYPT_SUCCESS);

        ret = CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE, NULL, 0);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

EXIT:
    DRBG_FREE(output);
    return;
}

static void sdvCryptGlobalThreadTest(void)
{
    int i = 0;
    uint8_t *output = NULL;

    output = malloc(sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_TRUE(output != NULL);

    for (i = 0; i < 100; i++) { // Perform 100 times random number generation in the thread.
        ASSERT_EQ(CRYPT_EAL_Randbytes(output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    }

EXIT:
    DRBG_FREE(output);
    return;
}

/**
 * @test   SDV_CRYPT_DRBG_RAND_INIT_API_TC001
 * @title  Use different algorithm ID to initialize the DRBG.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandInit, expected result 2.
 *    3.Call CRYPT_EAL_DrbgNew, expected result 3.
 * @expect
 *    1.successful.
 *    2.Success with or without a random number seed.
 *    3.successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_INIT_API_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    void *drbg = NULL;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    seedMeth.getEntropy = getEntropy;
    seedMeth.cleanEntropy = cleanEntropy;

    InitSeedCtx(algId, &seedCtx, &data);
    ASSERT_EQ(CRYPT_EAL_RandInit(algId, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    ASSERT_EQ(CRYPT_EAL_RandInit(algId, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_DrbgDeinit(drbg);
    drbgDataFree(&data);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_INIT_API_TC002
 * @title  DRBG initialization test,the value of data is 0 or 255.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandInit, expected result 2.
 *    3.Call CRYPT_EAL_DrbgNew, expected result 3.
 * @expect
 *    1.successful.
 *    2.successful.
 *    3.successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_INIT_API_TC002(int agId, int value, int size)
{
    uint8_t *pers = malloc(size);
    ASSERT_TRUE(pers != NULL);
    ASSERT_EQ(memset_s(pers, size, value, size), 0);
    void *drbg = NULL;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, size);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;

    ASSERT_EQ(CRYPT_EAL_RandInit(agId, &seedMeth, (void *)&seedCtx, pers, size), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    drbg = CRYPT_EAL_DrbgNew(agId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    CRYPT_EAL_DrbgDeinit(drbg);

EXIT:
    CRYPT_EAL_RandDeinit();
    drbgDataFree(&data);
    free(pers);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_INIT_API_TC003
 * @title  Test the impact of persLen on DRGB initialization.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandInit, expected result 2.
 *    3.Call CRYPT_EAL_DrbgNew, expected result 3.
 * @expect
 *    1.successful.
 *    2.successful.
 *    3.successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_INIT_API_TC003(int agId, int size)
{
    uint8_t *pers = malloc(TEST_DRBG_DATA_SIZE);
    ASSERT_TRUE(pers != NULL);
    void *drbg = NULL;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, size);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;

    ASSERT_EQ(CRYPT_EAL_RandInit(agId, &seedMeth, (void *)&seedCtx, pers, size), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    drbg = CRYPT_EAL_DrbgNew(agId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    CRYPT_EAL_DrbgDeinit(drbg);

EXIT:
    CRYPT_EAL_RandDeinit();
    drbgDataFree(&data);
    free(pers);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_INIT_API_TC004
 * @title  DRBG is initialized repeatedly.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandInit, expected result 2.
 *    3.Call CRYPT_EAL_RandInit again, expected result 3.
 * @expect
 *    1.successful.
 *    2.successful.
 *    3.return failed.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_INIT_API_TC004(int algId)
{
    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;

    ASSERT_EQ(CRYPT_EAL_RandInit(algId, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_RandInit(algId, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_EAL_ERR_DRBG_REPEAT_INIT);

EXIT:
    CRYPT_EAL_RandDeinit();
    drbgDataFree(&data);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_INIT_API_TC005
 * @title  DRBG initialization test,the configuration context parameter is empty.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandInit, expected result 2.
 *    3.Call CRYPT_EAL_DrbgNew, expected result 3.
 * @expect
 *    1.successful.
 *    2.successful.
 *    3.return NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_INIT_API_TC005(int algId)
{
    DRBG_Vec_t seedCtx = { 0 };
    void *drbg = NULL;

    ASSERT_EQ(CRYPT_EAL_RandInit(algId, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    ASSERT_NE(CRYPT_EAL_RandInit(algId, NULL, &seedCtx, NULL, 0), CRYPT_SUCCESS);
    drbg = CRYPT_EAL_DrbgNew(algId, NULL, NULL);
    ASSERT_TRUE(drbg != NULL);
    CRYPT_EAL_DrbgDeinit(drbg);
    drbg = CRYPT_EAL_DrbgNew(algId, NULL, &seedCtx);
    ASSERT_TRUE(drbg == NULL);
EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_DrbgDeinit(drbg);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_INIT_API_TC006
 * @title  DRBG initialization test,use the abnormal persLen.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandInit, expected result 2.
 *    3.Call CRYPT_EAL_DrbgNew, expected result 3.
 * @expect
 *    1.successful.
 *    2.return failed.
 *    3.return NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_INIT_API_TC006(int algId, int keyLen)
{
    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    uint8_t *pers = NULL;
    void *drbg = NULL;

    pers = malloc(TEST_DRBG_DATA_SIZE + keyLen);
    ASSERT_TRUE(pers != NULL);
    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, keyLen + 16);
    seedCtx.entropy = &data;
    seedCtx.nonce = &data;
    ASSERT_NE(CRYPT_EAL_RandInit(algId, &seedMeth, (void *)&seedCtx, pers, keyLen + 16 + 1), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, pers, keyLen + 16 + 1), CRYPT_SUCCESS);
    CRYPT_EAL_DrbgDeinit(drbg);
    ASSERT_EQ(CRYPT_EAL_RandInit(algId, &seedMeth, (void *)&seedCtx, pers, keyLen + 16), CRYPT_SUCCESS);
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    free(data.data);
    free(pers);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_SEED_ADIN_API_TC001
* @title  When the RAND is initialized and a random number has been generated,
  the counter is reset when the random number is obtained from personal data.
 * @precon nan
 * @brief
 *    1.Call sdvCryptEalRandSeedAdinApiTest,addinData is NULL, expected result 1.
 *    2.Call sdvCryptEalRandSeedAdinApiTest,addinData not NULL, expected result 2.
 * @expect
 *    1.All operations succeeded.
 *    2.All operations succeeded.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_SEED_ADIN_API_TC001(void)
{
    uint8_t *addinData = NULL;

    ASSERT_EQ(sdvCryptEalRandSeedAdinApiTest(NULL, 0), CRYPT_SUCCESS);

    addinData = malloc(sizeof(uint8_t) * DRBG_MAX_ADIN_SIZE);
    ASSERT_TRUE(addinData != NULL);
    ASSERT_EQ(sdvCryptEalRandSeedAdinApiTest(addinData, sizeof(uint8_t) * DRBG_MAX_ADIN_SIZE), CRYPT_SUCCESS);

EXIT:
    free(addinData);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_DRBG_SEED_ADIN_API_TC001
* @title  When the DRBG is initialized and a random number has been generated,
  the counter is reset when the random number is obtained from personal data.
 * @precon nan
 * @brief
 *    1.Call sdvCryptEalDrbgSeedAdinApiTest,addinData is NULL, expected result 1.
 *    2.Call sdvCryptEalDrbgSeedAdinApiTest,addinData not NULL, expected result 2.
 * @expect
 *    1.All operations succeeded.
 *    2.All operations succeeded.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_DRBG_SEED_ADIN_API_TC001(void)
{
    uint8_t *addinData = NULL;

    ASSERT_EQ(sdvCryptEalDrbgSeedAdinApiTest(NULL, 0), CRYPT_SUCCESS);

    addinData = malloc(sizeof(uint8_t) * DRBG_MAX_ADIN_SIZE);
    ASSERT_TRUE(addinData != NULL);
    ASSERT_EQ(sdvCryptEalDrbgSeedAdinApiTest(addinData, sizeof(uint8_t) * DRBG_MAX_ADIN_SIZE), CRYPT_SUCCESS);

EXIT:
    free(addinData);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_SEED_ADIN_API_TC002
* @title  Call random interface before CRYPT_EAL_RandInit.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_RandbytesWithAdin, expected result 1.
 *    2.Call CRYPT_EAL_Randbytes, expected result 2.
 *    3.Call CRYPT_EAL_RandSeedWithAdin, expected result 3.
 *    4.Call CRYPT_EAL_RandSeed, expected result 4.
 * @expect
 *    1.return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL.
 *    2.return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL.
 *    3.return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL.
 *    4.return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_SEED_ADIN_API_TC002(void)
{
    uint8_t data[TEST_DRBG_DATA_SIZE] = {0};
    ASSERT_EQ(CRYPT_EAL_RandbytesWithAdin(data, TEST_DRBG_DATA_SIZE, NULL, 0), CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
    ASSERT_EQ(CRYPT_EAL_Randbytes(data, TEST_DRBG_DATA_SIZE), CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
    ASSERT_EQ(CRYPT_EAL_RandSeedWithAdin(NULL, 0), CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
    ASSERT_EQ(CRYPT_EAL_RandSeed(), CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_BYTES_ADIN_ERR_PARA_API_TC001
 * @title  CRYPT_EAL_RandbytesWithAdin abnormal parameter test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_DrbgbytesWithAdin,use normal parameters, expected result 1.
 *    2.Call CRYPT_EAL_DrbgbytesWithAdin,the array length is abnormal, expected result 2.
 * @expect
 *    1.All interface succeeded.
 *    2.The interface returns an exception.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_BYTES_ADIN_ERR_PARA_API_TC001(int algId)
{
    uint8_t *output = malloc(sizeof(uint8_t) * (DRBG_MAX_OUTPUT_SIZE + 1));
    ASSERT_TRUE(output != NULL);
    uint8_t *addin = malloc(sizeof(uint8_t) * DRBG_MAX_ADIN_SIZE);
    ASSERT_TRUE(addin != NULL);

    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);
    seedCtx.entropy = &data;
    seedCtx.nonce = &data;

    TestMemInit();
    CRYPT_EAL_RndCtx *drbgCtx = CRYPT_EAL_DrbgNew(algId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);

    memset_s(addin, DRBG_MAX_ADIN_SIZE, 0, DRBG_MAX_ADIN_SIZE);
    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_MAX_OUTPUT_SIZE, addin, DRBG_MAX_ADIN_SIZE),
        CRYPT_SUCCESS);

    memset_s(addin, DRBG_MAX_ADIN_SIZE, 'F', DRBG_MAX_ADIN_SIZE);
    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_MAX_OUTPUT_SIZE, addin, DRBG_MAX_ADIN_SIZE),
        CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_MAX_OUTPUT_SIZE, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_MAX_OUTPUT_SIZE, addin, 0), CRYPT_SUCCESS);

    memset_s(addin, DRBG_MAX_ADIN_SIZE, 0, DRBG_MAX_ADIN_SIZE);
    ASSERT_NE(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, 0, addin, DRBG_MAX_ADIN_SIZE), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_MAX_OUTPUT_SIZE + 1, addin, DRBG_MAX_ADIN_SIZE),
        CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, NULL, 0, addin, DRBG_MAX_ADIN_SIZE), CRYPT_SUCCESS);

EXIT:
    free(addin);
    free(output);
    CRYPT_EAL_DrbgDeinit(drbgCtx);
    drbgDataFree(&data);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_BYTES_ERR_PARA_API_TC001
 * @title  Test the CRYPT_EAL_Randbytes interface for generating random numbers.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_Randbytes,use normal parameters, expected result 2.
 *    3.Call CRYPT_EAL_Randbytes,the array length is abnormal, expected result 3.
 * @expect
 *    1.successful.
 *    2.All interface succeeded.
 *    3.The interface returns an exception.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_BYTES_ERR_PARA_API_TC001(void)
{
    uint8_t *output = malloc(DRBG_MAX_OUTPUT_SIZE + 1);
    ASSERT_TRUE(output != NULL);

    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.nonce = &data;
    seedCtx.entropy = &data;
    ASSERT_EQ(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_Randbytes(output, DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Randbytes(output, DRBG_MAX_OUTPUT_SIZE), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_Randbytes(output, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Randbytes(output, DRBG_MAX_OUTPUT_SIZE + 1), CRYPT_SUCCESS); // MAX SIZE + 1
    ASSERT_EQ(CRYPT_EAL_Randbytes(NULL, 0), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_RandDeinit();
    drbgDataFree(&data);
    free(output);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_BYTES_ERR_PARA_API_TC001
 * @title  Test the CRYPT_EAL_Drbgbytes interface for generating random numbers.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_Drbgbytes,use normal parameters, expected result 2.
 *    3.Call CRYPT_EAL_Drbgbytes,the array length is abnormal, expected result 3.
 * @expect
 *    1.successful.
 *    2.All interface succeeded.
 *    3.The interface returns an exception.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_BYTES_ERR_PARA_API_TC001(void)
{
    uint8_t *output = malloc(DRBG_MAX_OUTPUT_SIZE + 1);
    ASSERT_TRUE(output != NULL);
    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    void *drbg = NULL;

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.nonce = &data;
    seedCtx.entropy = &data;
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg, output, DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg, output, DRBG_MAX_OUTPUT_SIZE), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_Drbgbytes(drbg, output, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg, output, DRBG_MAX_OUTPUT_SIZE + 1), CRYPT_SUCCESS); // MAX SIZE + 1
    ASSERT_NE(CRYPT_EAL_Drbgbytes(drbg, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(NULL, output, DRBG_OUTPUT_SIZE), CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    drbgDataFree(&data);
    free(output);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_FORK_RESEED_FUNC_TC001
 * @title  Detect whether the fork event will trigger a reseeding.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_Drbgbytes, use normal parameters, expected result 2.
 * @expect
 *    1.successful.
 *    2.All interface succeeded.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_FORK_RESEED_FUNC_TC001(void)
{
    uint8_t *output = malloc(DRBG_MAX_OUTPUT_SIZE + 1);
    ASSERT_TRUE(output != NULL);
    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    void *drbg = NULL;
    DRBG_Ctx *ctx = NULL;
    int32_t forkId;
    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.nonce = &data;
    seedCtx.entropy = &data;
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0) == CRYPT_SUCCESS);

    ctx = (DRBG_Ctx *)((CRYPT_EAL_RndCtx *)drbg)->ctx;
    forkId = ++ctx->forkId;
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg, output, DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    ASSERT_NE(ctx->forkId, forkId);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    drbgDataFree(&data);
    BSL_SAL_Free(output);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_FORK_RESEED_FUNC_TC002
 * @title  Fork reseed behavior test with two DRBG instances.
 * @precon nan
 * @brief
 *    1.Initialize two DRBG instances with the same seed parameters, expected result 1.
 *    2.Call CRYPT_EAL_Drbgbytes for both instances, expected result 2.
 *    3.Modify the forkId of one DRBG instance and call CRYPT_EAL_Drbgbytes, expected result 3.
 * @expect
 *    1.Both DRBG instances are initialized successfully.
 *    2.The generated random numbers are identical before fork reseed.
 *    3.The fork reseed is triggered and the generated random numbers are different.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_FORK_RESEED_FUNC_TC002(int algId)
{
    uint8_t *out1 = malloc(DRBG_MAX_OUTPUT_SIZE + 1);
    uint8_t *out2 = malloc(DRBG_MAX_OUTPUT_SIZE + 1);
    ASSERT_TRUE(out1 != NULL && out2 != NULL);

    CRYPT_RandSeedMethod seedMeth = {0};
    CRYPT_Data data = {0};
    DRBG_Vec_t seedCtx = {0};

    void *drbg1 = NULL;
    void *drbg2 = NULL;
    int32_t forkId;

    DRBG_Ctx *ctx1 = NULL;
    DRBG_Ctx *ctx2 = NULL;

    TestMemInit();
    regSeedMeth(&seedMeth);
    InitSeedCtx(algId, &seedCtx, &data);

    drbg1 = CRYPT_EAL_DrbgNew(algId, &seedMeth, &seedCtx);
    drbg2 = CRYPT_EAL_DrbgNew(algId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg1 != NULL && drbg2 != NULL);

    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(drbg1, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(drbg2, NULL, 0), CRYPT_SUCCESS);

    ctx1 = (DRBG_Ctx *)((CRYPT_EAL_RndCtx *)drbg1)->ctx;
    ctx2 = (DRBG_Ctx *)((CRYPT_EAL_RndCtx *)drbg2)->ctx;
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(ctx1->forkId, ctx2->forkId);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg1, out1, DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg2, out2, DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out1, out2, DRBG_OUTPUT_SIZE), 0);

    forkId = ++ctx2->forkId;
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg2, out2, DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    ASSERT_NE(ctx2->forkId, forkId);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg1, out1, DRBG_OUTPUT_SIZE), CRYPT_SUCCESS);
    ASSERT_NE(memcmp(out1, out2, DRBG_OUTPUT_SIZE), 0);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg1);
    CRYPT_EAL_DrbgDeinit(drbg2);
    drbgDataFree(&data);
    BSL_SAL_Free(out1);
    BSL_SAL_Free(out2);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_RAND_SEED_ADIN_ERR_PARA_API_TC001
 * @title  Test the CRYPT_EAL_RandSeedWithAdin interface.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandSeedWithAdin,use exception parameters, expected result 2.
 * @expect
 *    1.successful.
 *    2.The interface returns an exception.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_SEED_ADIN_ERR_PARA_API_TC001(void)
{
    uint32_t addinLen = sizeof(uint8_t) * DRBG_MAX_ADIN_SIZE;
    uint8_t *addin = malloc(addinLen);
    ASSERT_TRUE(addin != NULL);
    memset_s(addin, addinLen, 0, addinLen);

    TestMemInit();
    ASSERT_NE(CRYPT_EAL_RandSeedWithAdin(addin, 0), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_RandSeedWithAdin(addin, addinLen), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_RandSeedWithAdin(NULL, addinLen), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_RandSeedWithAdin(NULL, 0), CRYPT_SUCCESS);

EXIT:
    free(addin);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_SEED_ADIN_ERR_PARA_API_TC001
 * @title  Test the CRYPT_EAL_DrbgSeedWithAdin interface.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_DrbgSeedWithAdin,use normal parameters, expected result 2.
 *    3.Call CRYPT_EAL_DrbgSeedWithAdin,the array length is abnormal, expected result 3.
 * @expect
 *    1.successful.
 *    2.All interface succeeded.
 *    3.The interface returns an exception.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_SEED_ADIN_ERR_PARA_API_TC001(void)
{
    uint8_t *addin;
    uint32_t addinLen = sizeof(uint8_t) * DRBG_MAX_ADIN_SIZE;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    void *drbg = NULL;

    addin = malloc(addinLen);
    ASSERT_TRUE(addin != NULL);
    memset_s(addin, addinLen, 0, addinLen);

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.nonce = &data;
    seedCtx.entropy = &data;
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DrbgSeedWithAdin(drbg, addin, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgSeedWithAdin(drbg, addin, addinLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgSeedWithAdin(drbg, NULL, 0), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_DrbgSeedWithAdin(NULL, addin, addinLen), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_DrbgSeedWithAdin(drbg, NULL, addinLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    free(addin);
    free(data.data);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_SEED_ADIN_ERR_PARA_API_TC001
 * @title  Random number generation test.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandbytesWithAdin num times, expected result 2.
 * @expect
 *    1.successful.
 *    2.All interface succeeded.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_RAND_NUM_FUNC_TC001(int agId, int num, int dataSize)
{
    if (IsRandAlgDisabled(agId)) {
        SKIP_TEST();
    }
    int i;
    uint8_t *output = NULL;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    CRYPT_Data data = { 0 };

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, dataSize);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;
    ASSERT_EQ(CRYPT_EAL_RandInit(agId, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);

    output = malloc(sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_TRUE(output != NULL);
    for (i = 0; i < num; i++) {
        ASSERT_EQ(CRYPT_EAL_RandbytesWithAdin(output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE, NULL, 0), CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_RandDeinit();
    drbgDataFree(&data);
    free(output);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_NUM_FUNC_TC001
 * @title  Random number generation test.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_DrbgbytesWithAdin num times, expected result 2.
 * @expect
 *    1.successful.
 *    2.All interface succeeded.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_NUM_FUNC_TC001(int agId, int num, int dataSize)
{
    if (IsRandAlgDisabled(agId)) {
        SKIP_TEST();
    }
    int i;
    uint8_t *output = NULL;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    CRYPT_Data data = { 0 };
    void *drbgCtx = NULL;

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, dataSize);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;
    drbgCtx = CRYPT_EAL_DrbgNew(agId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);

    output = malloc(sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_TRUE(output != NULL);
    for (i = 0; i < num; i++) {
        ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE, NULL, 0), CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_DrbgDeinit(drbgCtx);
    drbgDataFree(&data);
    free(output);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_PTHREAD_FUNC_TC001
 * @title  DRGB multi-thread function test.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Create 10 threads for execute CRYPT_EAL_Randbytes, expected result 2.
 * @expect
 *    1.init successful.
 *    2.All threads are executed successfully..
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_PTHREAD_FUNC_TC001(int agId)
{
    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    RegThreadFunc();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;

    ASSERT_EQ(CRYPT_EAL_RandInit(agId, &seedMeth, &seedCtx, NULL, 0), CRYPT_SUCCESS);
    for(uint32_t iter = 0; iter < 10; iter++) {
        pthread_t thrd;
        ASSERT_EQ(pthread_create(&thrd, NULL, (void *)sdvCryptGlobalThreadTest, NULL), 0);
        pthread_join(thrd, NULL);
    }

EXIT:
    CRYPT_EAL_RandDeinit();
    drbgDataFree(&data);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_CLEANENTROPY_FUNC_TC001
 * @title  Failed to obtain the entropy source test.
 * @precon nan
 * @brief
 *    1.Register the interface that fails to obtain the entropy source, expected result 1.
 *    2.Initialize the random number seed, expected result 2.
 * @expect
 *    1.register successful.
 *    2.Failed to initialize the random number seed.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_CLEANENTROPY_FUNC_TC001(int agId)
{
    CallBackCtl_t seedCtx = { 0 };
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyError,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonceError,
        .cleanNonce = cleanNonceError,
    };
    void *drbg = NULL;

    TestMemInit();
    seedCtx.entropyState = 1;
    ASSERT_NE(CRYPT_EAL_RandInit(agId, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);
    drbg = CRYPT_EAL_DrbgNew(agId, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_GETENTROPY_FUNC_TC001
 * @title  Failed to obtain the entropy source test.
 * @precon nan
 * @brief
 *    1.Do not register the entropy source obtaining function., expected result 1.
 *    2.Initialize the random number seed, expected result 2.
 * @expect
 *    1.register successful.
 *    2.Failed to initialize the random number seed.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_GETENTROPY_FUNC_TC001(int agId)
{
    CallBackCtl_t seedCtx = { 0 };
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = NULL,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonceError,
        .cleanNonce = cleanNonceError,
    };
    void *drbg = NULL;

    TestMemInit();
    ASSERT_NE(CRYPT_EAL_RandInit(agId, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);
    drbg = CRYPT_EAL_DrbgNew(agId, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_GETENTROPY_FUNC_TC002
 * @title  To verify that the entropy data is empty and the length is 0 or a non-zero value.
 * @precon nan
 * @brief
 *    1.Registering the callback function, expected result 1.
 *    2.The entropy->data is empty and the length is 0,initialize the random number seed, expected result 2.
 *    2.The entropy->data is empty and the length not 0,initialize the random number seed, expected result 3.
 * @expect
 *    1.Register successful.
 *    2.Failed to initialize the random number seed.
 *    3.Failed to initialize the random number seed.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_GETENTROPY_FUNC_TC002(void)
{
    DRBG_Vec_t seedCtx = { 0 };
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyUnCheckPara,
        .cleanEntropy = cleanEntropy,
        .getNonce = NULL,
        .cleanNonce = NULL,
    };
    void *drbg = NULL;

    TestMemInit();
    seedCtx.entropy = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_DrbgDeinit(drbg);
    seedCtx.entropy->len = 1; // Set the entropy length to 1 verify that the data is empty but the data length is not 0.
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    DRBG_FREE(seedCtx.entropy);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_GETNONCE_FUNC_TC001
 * @title  Test that the nonce data is empty and the length is 0 or a non-zero value.
 * @precon nan
 * @brief
 *    1.Registering the callback function, expected result 1.
 *    2.The nonce->data is empty and the length is 0,initialize the random number seed, expected result 2.
 *    2.The nonce->data is empty and the length not 0,initialize the random number seed, expected result 3.
 * @expect
 *    1.Register successful.
 *    2.Failed to initialize the random number seed.
 *    3.Failed to initialize the random number seed.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_GETNONCE_FUNC_TC001(void)
{
    DRBG_Vec_t seedCtx = { 0 };
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyError,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonceUnCheckPara,
        .cleanNonce = cleanNonceError,
    };
    void *drbg = NULL;

    TestMemInit();
    seedCtx.nonce = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_DrbgDeinit(drbg);

    seedCtx.nonce->len = 1; // Set the nonce length to 1 verify that the data is empty but the data length is not 0.
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    DRBG_FREE(seedCtx.nonce);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_GETNONCE_FUNC_TC002
 * @title  Failed to obtain nonce during DRBG initialization.
 * @precon nan
 * @brief
 *    1.Registering the interface for failed to obtain the nonce, expected result 1.
 *    2.Initializing the DRBG, expected result 2.
 * @expect
 *    1.Register successful.
 *    2.Failed to initialize the random number seed.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_GETNONCE_FUNC_TC002(void)
{
    DRBG_Vec_t seedCtx = { 0 };
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyError,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonce,
        .cleanNonce = cleanNonce,
    };
    void *drbg = NULL;

    TestMemInit();
    seedCtx.nonce = calloc(1u, sizeof(CRYPT_Data));
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, NULL, 0), CRYPT_SUCCESS);

    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    DRBG_FREE(seedCtx.nonce);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_GETNONCE_FUNC_TC003
 * @title  Failed to obtain nonce during DRBG instantiation.
 * @precon nan
 * @brief
 *    1.Registering the interface for failed to obtain the nonce, expected result 1.
 *    2.Initializing the DRBG, expected result 2.
 * @expect
 *    1.Register successful.
 *    2.Failed to initialize the random number seed.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_GETNONCE_FUNC_TC003(void)
{
    CallBackCtl_t seedCtx = { 0 };
    CRYPT_RandSeedMethod seedMeth = {
        .getNonce = getNonceError,
        .cleanNonce = cleanNonceError,
        .getEntropy = getEntropyError,
        .cleanEntropy = cleanEntropyError,
    };
    void *drbg = NULL;
    TestMemInit();

    seedCtx.nonceState = 1;
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA224, &seedMeth, (void *)&seedCtx, NULL, 0) != CRYPT_SUCCESS);

    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA224, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_NE(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_INSTANTIATE_FUNC_TC001
 * @title  The personal data provided during DRBG instantiation is empty.
 * @precon nan
 * @brief
 *    1.set the personal data is empty.
 *    2.Initializing the DRBG, expected result 1.
 *    3.Uninitializing the DRBG, expected result 2.
 * @expect
 *    1.The DRBG is successfully initialized regardless of whether the data field is empty.
 *    2.The DRBG is successfully uninitialized.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_INSTANTIATE_FUNC_TC001(void)
{
    CRYPT_Data *pers = NULL;
    DRBG_Vec_t seedCtx = { 0 };
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyError,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonceError,
        .cleanNonce = cleanNonceError,
    };

    TestMemInit();
    pers = calloc(1u, sizeof(CRYPT_Data));

    ASSERT_EQ(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, pers->data, pers->len),
        CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    void *drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(drbg, pers->data, pers->len), CRYPT_SUCCESS);
    CRYPT_EAL_DrbgDeinit(drbg);
    drbg = NULL;
    pers->data = calloc(DRBG_MAX_ADIN_SIZE + 1, sizeof(uint8_t));
    pers->len = DRBG_MAX_ADIN_SIZE + 1;
    ASSERT_EQ(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx, pers->data, pers->len),
        CRYPT_SUCCESS);
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, (void *)&seedCtx);
    ASSERT_TRUE(drbg != NULL);
    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(drbg, pers->data, pers->len), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_RandDeinit();
    DRBG_FREE(pers->data);
    DRBG_FREE(pers);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_DUP_API_TC001
 * @title  Test the DRBG dup interface.
 * @precon nan
 * @brief
 *    1.Call DRBG_NewHashCtx create ctx, expected result 1.
 *    2.Call dup function,give an empty input parameter, expected result 2.
 *    3.Call dup function,give the correct DRBG context, expected result 3.
 * @expect
 *    1.successful.
 *    2.The interface returns a null pointer.
 *    3.The interface returns new ctx.
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_DUP_API_TC001(int algId)
{
    CRYPT_RandSeedMethod seedMeth = { 0 };
    CRYPT_Data data = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.nonce = &data;
    seedCtx.entropy = &data;
    CRYPT_EAL_RndCtx *drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbg != NULL);
    DRBG_Ctx *ctx = (DRBG_Ctx*)(drbg->ctx);
    DRBG_Ctx *newCtx = ctx->meth->dup(ctx);
    ASSERT_TRUE(newCtx != NULL);
    ASSERT_TRUE(ctx->meth->dup(NULL) == NULL);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    DRBG_Free(newCtx);
    drbgDataFree(&data);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_PTHREAD_FUNC_TC002
 * @title  DRGB multi-thread function test.
 * @precon nan
 * @brief
 *    1.Initialize 10 drbgCtx, expected result 1.
 *    2.Create 10 threads for execute CRYPT_EAL_DrbgbytesWithAdin, expected result 2.
 * @expect
 *    1.init successful.
 *    2.All threads are executed successfully..
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_PTHREAD_FUNC_TC002(int agId)
{
    if (IsRandAlgDisabled(agId)) {
        SKIP_TEST();
    }
    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    RegThreadFunc();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;
    for (uint32_t iter = 0; iter < 10; iter++) {
        pthread_t thrd;
        void *drbgCtx = CRYPT_EAL_DrbgNew(agId, &seedMeth, &seedCtx);
        ASSERT_TRUE(drbgCtx != NULL);
        ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);
        ASSERT_EQ(pthread_create(&thrd, NULL, (void *)sdvCryptEalThreadTest, drbgCtx), 0);
        pthread_join(thrd, NULL);
        CRYPT_EAL_DrbgDeinit(drbgCtx);
        drbgCtx = NULL;
    }
EXIT:
    drbgDataFree(&data);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_DRBG_PTHREAD_FUNC_TC003
 * @title  DRGB multi-thread function test.
 * @precon nan
 * @brief
 *    1.Initialize drbgCtx, expected result 1.
 *    2.Create 10 threads for execute CRYPT_EAL_DrbgbytesWithAdin, expected result 2.
 * @expect
 *    1.init successful.
 *    2.All threads are executed successfully..
 */
/* BEGIN_CASE */
void SDV_CRYPT_DRBG_PTHREAD_FUNC_TC003(int agId)
{
    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };

    TestMemInit();
    RegThreadFunc();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;
    void *drbgCtx = CRYPT_EAL_DrbgNew(agId, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);
    for (uint32_t iter = 0; iter < 10; iter++) {
        pthread_t thrd;
        ASSERT_EQ(pthread_create(&thrd, NULL, (void *)sdvCryptEalThreadTest, drbgCtx), 0);
        pthread_join(thrd, NULL);
    }
EXIT:
    CRYPT_EAL_DrbgDeinit(drbgCtx);
    drbgDataFree(&data);
    return;
}
/* END_CASE */

static int32_t getEntropyWithoutSeedCtx(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)ctx;
    (void)strength;
    (void)lenRange;
    uint32_t entroyLen = sizeof(uint8_t) * TEST_DRBG_DATA_SIZE;
    entropy->data = calloc(1u, entroyLen);
    entropy->len = entroyLen;
    return CRYPT_SUCCESS;
}

static int32_t getEntropyWithoutSeedCtxSpecial(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)ctx;
    (void)strength;
    (void)lenRange;
    uint32_t entroyLen = sizeof(uint8_t) * CTR_AES128_SEEDLEN;
    entropy->data = calloc(1u, entroyLen);
    entropy->len = entroyLen;
    return CRYPT_SUCCESS;
}

static int32_t getNonceWithoutSeedCtx(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)ctx;
    (void)strength;
    (void)lenRange;
    uint32_t nonceLen = sizeof(uint8_t) * TEST_DRBG_DATA_SIZE;
    nonce->data = calloc(1u, nonceLen);
    nonce->len = nonceLen;
    return CRYPT_SUCCESS;
}

/**
 * @test   SDV_CRYPT_EAL_RAND_BYTES_FUNC_TC001
 * @title  Generating random numbers based on entropy sources.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandbytesWithAdin, expected result 2.
 *    3.Call CRYPT_EAL_Randbytes get random numbers, expected result 3.
 * @expect
 *    1.init successful.
 *    2.successful.
 *    3.Random number generated successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RAND_BYTES_FUNC_TC001(int id, Hex *entropy, Hex *nonce, Hex *pers, Hex *addin1, Hex *entropyPR1,
    Hex *addin2, Hex *entropyPR2, Hex *retBits)
{
    if (IsRandAlgDisabled(id)){
        SKIP_TEST();
    }
    uint8_t output[DRBG_MAX_OUTPUT_SIZE];
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t *seedCtx;
    regSeedMeth(&seedMeth);

    TestMemInit();

    seedCtx = seedCtxMem();
    ASSERT_TRUE(seedCtx != NULL);
    seedCtxCfg(seedCtx, entropy, nonce, pers, addin1, entropyPR1, addin2, entropyPR2, retBits);

    ASSERT_EQ(CRYPT_EAL_RandInit((CRYPT_RAND_AlgId)id, &seedMeth, (void *)seedCtx, seedCtx->pers->data,
        seedCtx->pers->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_RandbytesWithAdin(output, sizeof(uint8_t) * retBits->len, addin1->x, addin1->len),
        CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_Randbytes(output, sizeof(uint8_t) * retBits->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandIsValidAlgId(id), true);
EXIT:
    CRYPT_EAL_RandDeinit();
    seedCtxFree(seedCtx);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_DRBG_BYTES_FUNC_TC001
 * @title  Generating random numbers based on entropy sources.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_DrbgbytesWithAdin, expected result 2.
 *    3.Call CRYPT_EAL_Drbgbytes get random numbers, expected result 3.
 * @expect
 *    1.Init successful.
 *    2.Successful.
 *    3.Random number generated successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_DRBG_BYTES_FUNC_TC001(int id, Hex *entropy, Hex *nonce, Hex *pers, Hex *addin1, Hex *entropyPR1,
    Hex *addin2, Hex *entropyPR2, Hex *retBits)
{
    if (IsRandAlgDisabled(id)){
        SKIP_TEST();
    }
    uint8_t *output = NULL;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t *seedCtx;
    void *drbgCtx = NULL;
    regSeedMeth(&seedMeth);

    TestMemInit();

    seedCtx = seedCtxMem();
    ASSERT_TRUE(seedCtx != NULL);
    seedCtxCfg(seedCtx, entropy, nonce, pers, addin1, entropyPR1, addin2, entropyPR2, retBits);
    drbgCtx = CRYPT_EAL_DrbgNew(id, &seedMeth, seedCtx);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);

    output = malloc(sizeof(uint8_t) * retBits->len);
    ASSERT_TRUE(output != NULL);

    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, sizeof(uint8_t) * retBits->len, addin1->x, addin1->len),
        CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbgCtx, output, sizeof(uint8_t) * retBits->len), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbgCtx);
    seedCtxFree(seedCtx);
    free(output);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_RAND_BYTES_FUNC_TC002
 * @title  Generating random numbers based on entropy sources,the user only provides the seed method,
           not the seed context.
 * @precon nan
 * @brief
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandSeed, expected result 2.
 *    3.Call CRYPT_EAL_Randbytes get random numbers, expected result 3.
 * @expect
 *    1.init successful.
 *    2.successful.
 *    3.Random number generated successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RAND_BYTES_FUNC_TC002(int id)
{
    if (IsRandAlgDisabled(id)){
        SKIP_TEST();
    }
    uint8_t output[DRBG_MAX_OUTPUT_SIZE];
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyWithoutSeedCtx,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonceWithoutSeedCtx,
        .cleanNonce = cleanNonceError,
    };

    TestMemInit();

    /* The DRBG-CTR mode requires the entropy source length of a specific length, and seedMeth needs to generate
       entropy of the corresponding length.(DRBG-CTR AES128/AES192/AES256 length is 32, 40, 48).
    */
    if (id == CRYPT_RAND_AES128_CTR || id == CRYPT_RAND_AES192_CTR || id == CRYPT_RAND_AES256_CTR) {
        seedMeth.getEntropy = getEntropyWithoutSeedCtxSpecial;
        seedMeth.getNonce = NULL;
        seedMeth.cleanNonce = NULL;
    }
    ASSERT_EQ(CRYPT_EAL_RandInit((CRYPT_RAND_AlgId)id, &seedMeth, NULL, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandSeed(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Randbytes(output, DRBG_MAX_OUTPUT_SIZE), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_RAND_DEFAULT_PROVIDER_BYTES_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 * Generating random numbers based on entropy sources
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandbytesWithAdin, expected result 2.
 *    3.Call CRYPT_EAL_Randbytes get random numbers, expected result 3.
 * @expect
 *    1.init successful.
 *    2.successful.
 *    3.Random number generated successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RAND_DEFAULT_PROVIDER_BYTES_FUNC_TC001(int id, Hex *entropy, Hex *nonce, Hex *pers,
    Hex *addin1, Hex *entropyPR1, Hex *addin2, Hex *entropyPR2, Hex *retBits)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)id;
    (void)entropy;
    (void)nonce;
    (void)pers;
    (void)addin1;
    (void)entropyPR1;
    (void)addin2;
    (void)entropyPR2;
    (void)retBits;
    SKIP_TEST();
#else
    if (IsRandAlgDisabled(id)) {
        SKIP_TEST();
    }
    uint8_t output[DRBG_MAX_OUTPUT_SIZE];
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t *seedCtx;
    regSeedMeth(&seedMeth);

    TestMemInit();

    seedCtx = seedCtxMem();
    ASSERT_TRUE(seedCtx != NULL);
    seedCtxCfg(seedCtx, entropy, nonce, pers, addin1, entropyPR1, addin2, entropyPR2, retBits);

    BSL_Param param[6] = {0};
    ASSERT_EQ(BSL_PARAM_InitValue(&param[0],
        CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, seedCtx, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[1],
        CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[2],
        CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[3],
        CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getNonce, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[4],
        CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanNonce, 0), BSL_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)id, "provider=default",
        seedCtx->pers->data, seedCtx->pers->len, param), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandbytesWithAdinEx(NULL, output, sizeof(uint8_t) * retBits->len, addin1->x, addin1->len),
        CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, sizeof(uint8_t) * retBits->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandIsValidAlgId(id), true);
EXIT:
    CRYPT_EAL_RandDeinitEx(NULL);
    seedCtxFree(seedCtx);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_DRBG_DEFAULT_PROVIDER_BYTES_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 * Generating random numbers based on entropy sources.
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_DrbgbytesWithAdin, expected result 2.
 *    3.Call CRYPT_EAL_Drbgbytes get random numbers, expected result 3.
 * @expect
 *    1.Init successful.
 *    2.Successful.
 *    3.Random number generated successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_DRBG_DEFAULT_PROVIDER_BYTES_FUNC_TC001(int id, Hex *entropy, Hex *nonce, Hex *pers,
    Hex *addin1, Hex *entropyPR1, Hex *addin2, Hex *entropyPR2, Hex *retBits)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)id;
    (void)entropy;
    (void)nonce;
    (void)pers;
    (void)addin1;
    (void)entropyPR1;
    (void)addin2;
    (void)entropyPR2;
    (void)retBits;
    SKIP_TEST();
#else  
    if (IsRandAlgDisabled(id)) {
        SKIP_TEST();
    }
    uint8_t *output = NULL;
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t *seedCtx;
    void *drbgCtx = NULL;
    regSeedMeth(&seedMeth);

    TestMemInit();

    seedCtx = seedCtxMem();
    ASSERT_TRUE(seedCtx != NULL);
    seedCtxCfg(seedCtx, entropy, nonce, pers, addin1, entropyPR1, addin2, entropyPR2, retBits);

    BSL_Param param[6] = {0};
    ASSERT_EQ(BSL_PARAM_InitValue(&param[0],
        CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, seedCtx, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[1],
        CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[2],
        CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[3],
        CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getNonce, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[4],
        CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanNonce, 0), BSL_SUCCESS);

    drbgCtx = CRYPT_EAL_ProviderDrbgNewCtx(NULL, (CRYPT_RAND_AlgId)id, "provider=default", param);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);

    output = malloc(sizeof(uint8_t) * retBits->len);
    ASSERT_TRUE(output != NULL);

    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, sizeof(uint8_t) * retBits->len, addin1->x, addin1->len),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbgCtx, output, sizeof(uint8_t) * retBits->len), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbgCtx);
    seedCtxFree(seedCtx);
    free(output);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_RAND_DEFAULT_PROVIDER_BYTES_FUNC_TC002
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 * Generating random numbers based on entropy sources,the user only provides the seed method,
 * not the seed context.
 *    1.Initialize the random number seed, expected result 1.
 *    2.Call CRYPT_EAL_RandSeed, expected result 2.
 *    3.Call CRYPT_EAL_Randbytes get random numbers, expected result 3.
 *    4.Initialize the random number without seedMeth, expected result 4.
 * @expect
 *    1.init successful.
 *    2.successful.
 *    3.Random number generated successfully.
 *    4.init successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RAND_DEFAULT_PROVIDER_BYTES_FUNC_TC002(int id)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)id;
    SKIP_TEST();
#else
    if (IsRandAlgDisabled(id)) {
        SKIP_TEST();
    }
    uint8_t output[DRBG_MAX_OUTPUT_SIZE];
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyWithoutSeedCtx,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonceWithoutSeedCtx,
        .cleanNonce = cleanNonceError,
    };

    TestMemInit();

    /* The DRBG-CTR mode requires the entropy source length of a specific length, and seedMeth needs to generate
       entropy of the corresponding length.(DRBG-CTR AES128/AES192/AES256 length is 32, 40, 48).
    */
    if (id == CRYPT_RAND_AES128_CTR || id == CRYPT_RAND_AES192_CTR || id == CRYPT_RAND_AES256_CTR) {
        seedMeth.getEntropy = getEntropyWithoutSeedCtxSpecial;
        seedMeth.getNonce = NULL;
        seedMeth.cleanNonce = NULL;
    }
    BSL_Param param[6] = {0};
    ASSERT_EQ(BSL_PARAM_InitValue(&param[0],
        CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, NULL, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[1],
        CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[2],
        CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[3],
        CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getNonce, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[4],
        CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanNonce, 0), BSL_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)id, "provider=default", NULL, 0, param), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandSeedEx(NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, DRBG_MAX_OUTPUT_SIZE), CRYPT_SUCCESS);
    CRYPT_EAL_DrbgDeinit(CRYPT_EAL_GetGlobalLibCtx()->drbg);
    CRYPT_EAL_GetGlobalLibCtx()->drbg = NULL;
    param[1] = (BSL_Param){0, 0, NULL, 0, 0};
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)id, "provider=default", NULL, 0, param), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandSeedEx(NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, DRBG_MAX_OUTPUT_SIZE), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_RandDeinitEx(NULL);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_RAND_DEFAULT_PROVIDER_BYTES_FUNC_TC003(int id)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)id;
    SKIP_TEST();
#else
    if (IsRandAlgDisabled(id)) {
        SKIP_TEST();
    }
    uint8_t output[DRBG_MAX_OUTPUT_SIZE];
    CRYPT_RandSeedMethod seedMeth = {
        .getEntropy = getEntropyWithoutSeedCtx,
        .cleanEntropy = cleanEntropyError,
        .getNonce = getNonceWithoutSeedCtx,
        .cleanNonce = cleanNonceError,
    };
    TestMemInit();

    BSL_Param param[6] = {0};
    ASSERT_EQ(BSL_PARAM_InitValue(&param[0],
        CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getNonce, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[1],
        CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanNonce, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[2],
        CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, NULL, 0), BSL_SUCCESS);
        
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)id, "provider=default", NULL, 0, NULL),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandSeedEx(NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, DRBG_MAX_OUTPUT_SIZE), CRYPT_SUCCESS);
    CRYPT_EAL_DrbgDeinit(CRYPT_EAL_GetGlobalLibCtx()->drbg);
    CRYPT_EAL_GetGlobalLibCtx()->drbg = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)id, "provider=default", NULL, 0, param),
        CRYPT_EAL_ERR_DRBG_INIT_FAIL);
    param[2] = (BSL_Param){0, 0, NULL, 0, 0};
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)id, "provider=default", NULL, 0, param),
        CRYPT_EAL_ERR_DRBG_INIT_FAIL);
EXIT:
    CRYPT_EAL_RandDeinitEx(NULL);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_DRBG_SET_PREDICTION_RESISTANCE_API_TC001()
{
    uint8_t *output = NULL;
    void *drbgCtx = NULL;
    CRYPT_Data data = { 0 };
    CRYPT_RandSeedMethod seedMeth = { 0 };
    DRBG_Vec_t seedCtx = { 0 };
    bool pr = true;

    TestMemInit();
    regSeedMeth(&seedMeth);
    drbgDataInit(&data, TEST_DRBG_DATA_SIZE);

    seedCtx.entropy = &data;
    seedCtx.nonce = &data;

    drbgCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);

    output = malloc(sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_TRUE(output != NULL);
    (void)memset_s(output, sizeof(uint8_t) * DRBG_OUTPUT_SIZE, 0, sizeof(uint8_t) * DRBG_OUTPUT_SIZE);
    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_OUTPUT_SIZE, NULL, 0), CRYPT_SUCCESS);

    CRYPT_EAL_DrbgDeinit(drbgCtx);
    drbgCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &seedMeth, &seedCtx);
    ASSERT_TRUE(drbgCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_DrbgCtrl(drbgCtx, CRYPT_CTRL_SET_PREDICTION_RESISTANCE, &pr, sizeof(pr)), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(drbgCtx, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DrbgbytesWithAdin(drbgCtx, output, DRBG_OUTPUT_SIZE, NULL, 0), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(drbgCtx);
    drbgDataFree(&data);
    free(output);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_PRIMARY_DRBG_RESEED_FUNC_TC001
 * @title  DRGB get seed ctx and reseed test.
 * @precon nan
 * @brief
 *    1.Initialize the random number and obtain the seed.
 *    2.Call the reseed function and obtain a random number.
 * @expect
 *    1.successful.
 *    2.successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_PRIMARY_DRBG_RESEED_FUNC_TC001(int algId)
{
#if (!defined(HITLS_CRYPTO_ENTROPY))
    (void)algId;
#else
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    uint8_t addin[40] = {1, 2, 3, 4};
    uint8_t randByte[64];
    uint32_t working = 0;
    TestMemInit();

    ASSERT_TRUE(CRYPT_EAL_GetSeedCtx(true) == NULL);
    ASSERT_EQ(CRYPT_EAL_DrbgCtrl(NULL, CRYPT_CTRL_GET_WORKING_STATUS, &working, sizeof(working)), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_RandInit(algId, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
    CRYPT_EAL_RndCtx *seedCtx = CRYPT_EAL_GetSeedCtx(true);
    ASSERT_EQ(CRYPT_EAL_DrbgCtrl(seedCtx, CRYPT_CTRL_GET_WORKING_STATUS, &working, sizeof(working)), CRYPT_SUCCESS);
    ASSERT_EQ(working, 1);
    ASSERT_EQ(CRYPT_EAL_DrbgSeedWithAdin(seedCtx, addin, sizeof(addin)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Randbytes(randByte, sizeof(randByte)), CRYPT_SUCCESS);

    seedCtx = CRYPT_EAL_GetSeedCtx(false);
    ASSERT_EQ(CRYPT_EAL_DrbgCtrl(seedCtx, CRYPT_CTRL_GET_WORKING_STATUS, &working, sizeof(working)), CRYPT_SUCCESS);
    ASSERT_EQ(working, 1);
    ASSERT_EQ(CRYPT_EAL_DrbgSeedWithAdin(seedCtx, addin, sizeof(addin)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Randbytes(randByte, sizeof(randByte)), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_RandDeinit();
    return;
#endif
}
/* END_CASE */

/** 
 * @test   SDV_PRIMARY_DRBG_VECTOR_FUN_TC001
 * @title  DRBG vector function test.
 * @precon nan
 * @brief
 *    1.Initialize the random number with the seed method and the seed context.
 *    2.Call the CRYPT_EAL_Randbytes function and obtain a random number.
 *    3.Compare the random number with the vector(witch is generated randomly).
 * @expect
 *    1.successful.
 *    2.successful.
 *    3.successful.
 */
/* BEGIN_CASE */
void SDV_PRIMARY_DRBG_VECTOR_FUN_TC001(int algId, int entropyLen, Hex *result)
{
#if (!defined(HITLS_CRYPTO_ENTROPY) || !defined(HITLS_BSL_PARAMS))
    (void)algId;
    (void)entropyLen;
    (void)result;
    SKIP_TEST();
#else
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    uint8_t output[32]; // Test Vector length
    uint32_t len = 32;
    uint8_t *entropy = BSL_SAL_Malloc(entropyLen);
    ASSERT_TRUE(entropy != NULL);
    (void)memset_s(entropy, entropyLen, 0xff, entropyLen);
    uint8_t nonce[20];
    (void)memset_s(nonce, sizeof(nonce), 0xff, sizeof(nonce));
    unsigned char pers[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    unsigned char addition[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

    CRYPT_RandSeedMethod seedMeth = {0};
    regSeedMeth(&seedMeth);
    DRBG_Vec_t *seedCtx = seedCtxMem();
    ASSERT_TRUE(seedCtx != NULL);
    Hex entropyHex = {.x = entropy, .len = entropyLen};
    Hex persHex = {.x = pers, .len = sizeof(pers)};
    Hex additionHex = {.x = addition, .len = sizeof(addition)};
    Hex nonceHex = {.x = nonce, .len = sizeof(nonce)};
    Hex nullHex = {.x = NULL, .len = 0};
    seedCtxCfg(seedCtx, &entropyHex, &nonceHex, &persHex, &additionHex, &nullHex, &nullHex, &nullHex, &nullHex);

    BSL_Param param[6] = {0};
    ASSERT_EQ(BSL_PARAM_InitValue(&param[0],
        CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, seedCtx, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[1],
        CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[2],
        CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanEntropy, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[3],
        CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getNonce, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[4],
        CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanNonce, 0), BSL_SUCCESS);
   
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)algId, NULL, pers, sizeof(pers), param),
        CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, len), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(output, result->x, result->len), 0);
EXIT:
    seedCtxFree(seedCtx);
    BSL_SAL_Free(entropy);
    CRYPT_EAL_RandDeinitEx(NULL);
    return;
#endif
}
/* END_CASE */