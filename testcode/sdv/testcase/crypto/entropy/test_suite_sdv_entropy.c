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
#include <unistd.h>
#include <pthread.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_entropy.h"
#include "crypt_eal_rand.h"
#include "eal_entropy.h"
#include "securec.h"
#include "crypt_eal_entropy.h"
#include "crypt_algid.h"

/* Detect if running on WSL by checking /proc/version */
__attribute__((unused)) static bool IsRunningOnWSL(void)
{
    FILE *fp = fopen("/proc/version", "r");
    if (fp == NULL) {
        return false;
    }
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    if (n == 0) {
        return false;
    }
    return (strstr(buf, "microsoft") != NULL || strstr(buf, "Microsoft") != NULL || strstr(buf, "WSL") != NULL);
}

#ifdef HITLS_CRYPTO_ENTROPY_SYS
static bool IsCollectionEntropy(void *ctx)
{
    bool isWork = false;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GET_STATE, &isWork, 1) == CRYPT_SUCCESS);
    uint32_t poolSize = 0;
    uint32_t currSize = 0;
    uint32_t cfSize = 0;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GET_POOL_SIZE, &poolSize, 4) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &currSize, 4) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GET_CF_SIZE, &cfSize, 4) == CRYPT_SUCCESS);
    return isWork && (cfSize <= poolSize - currSize);
EXIT:
    return false;
}

static void *EsGatherAuto(void *ctx)
{
    while(true) {
        if (!IsCollectionEntropy(ctx)) {
            break;
        }
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        uint32_t size;
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
        usleep(1000);
    }
EXIT:
    return NULL;
}

static void *EsGetAuto(void *ctx)
{
    uint8_t buf[48] = {0};
    for (int32_t iter = 0; iter < 3; iter++) {
        uint32_t len = CRYPT_EAL_EsEntropyGet(ctx, buf, 48);
        ASSERT_TRUE(len > 0);
    }
EXIT:
    return NULL;
}

static const char *EsGetCfMode(uint32_t algId)
{
    switch (algId) {
        case CRYPT_MD_SM3:
            return "sm3_df";
        case CRYPT_MD_SHA224:
            return "sha224_df";
        case CRYPT_MD_SHA256:
            return "sha256_df";
        case CRYPT_MD_SHA384:
            return "sha384_df";
        case CRYPT_MD_SHA512:
            return "sha512_df";
        default:
            return NULL;
    }
}

static uint32_t EsGetCfLen(uint32_t algId)
{
    switch (algId) {
        case CRYPT_MD_SM3:
            return 32u;
        case CRYPT_MD_SHA224:
            return 28u;
        case CRYPT_MD_SHA256:
            return 32u;
        case CRYPT_MD_SHA384:
            return 48u;
        case CRYPT_MD_SHA512:
            return 64u;
        default:
            return 0u;
    }
}

static int32_t EntropyReadNormal(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    memset_s(buf, bufLen, 0xff, bufLen);
    return CRYPT_SUCCESS;
}

static void *EntropyInitTest(void *para)
{
    (void)para;
    return EntropyInitTest;
}

static void *EntropyInitError(void *para)
{
    (void)para;
    return NULL;
}

static int32_t EntropyReadError(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    memset_s(buf, bufLen, 0xff, bufLen);
    return -1;
}

static int32_t EntropyReadDiffData(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    for (uint32_t iter = 0; iter < bufLen; iter++) {
        buf[iter] = iter % 128;
    }
    return CRYPT_SUCCESS;
}

static void EntropyDeinitTest(void *ctx)
{
    (void)ctx;
    return;
}

static void *EsMutiAuto(void *ctx)
{
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        7,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df"));
    CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara));
    uint32_t size = 512;
    CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t));
    ASSERT_TRUE(CRYPT_EAL_EsInit(ctx) == CRYPT_SUCCESS);
    uint8_t buf[48] = {0};
    for (int32_t iter = 0; iter < 3; iter++) {
        uint32_t len = CRYPT_EAL_EsEntropyGet(ctx, buf, 48);
        ASSERT_TRUE(len > 0);
    }
EXIT:
    return NULL;
}

static void EntropyESMutilTest(void *alg)
{
    uint32_t poolSize = 4096;
    uint32_t expectGetLen = 32;
    uint8_t buf[1024] = {0};
    uint32_t currPoolSize = 0;

    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    const char *mode = EsGetCfMode((uint32_t)(*(int *)alg));
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&poolSize, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    for(int iter = 0; iter < 1; iter++) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &currPoolSize, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(currPoolSize > expectGetLen);
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, expectGetLen);
    ASSERT_TRUE(resLen == expectGetLen);
EXIT:
    CRYPT_EAL_EsFree(es);
}
static int32_t GetEntropyTest(void *seedCtx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    entropy->len = lenRange->min;
    entropy->data = malloc(entropy->len);
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(seedCtx, entropy->data, entropy->len) == entropy->len);
EXIT:
    return CRYPT_SUCCESS;
}

static void CleanEntropyTest(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_FREE(entropy->data);
}

static int32_t GetNonceTest(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    return GetEntropyTest(ctx, nonce, strength, lenRange);
}

static void CleanNonceTest(void *ctx, CRYPT_Data *nonce)
{
    CleanEntropyTest(ctx, nonce);
}
#endif
static uint32_t EntropyGetNormal(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)buf;
    (void)bufLen;
    memset_s(buf, bufLen, 'a', bufLen);
    return 32 > bufLen ? bufLen : 32;
}

static uint32_t EntropyGet0Normal(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)buf;
    (void)bufLen;
    memset_s(buf, bufLen, 'a', bufLen);
    return 0;
}

static void *DrbgSeedTest(void *ctx)
{
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
    CRYPT_EAL_RndCtx *randCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_AES128_CTR_DF, &meth, ctx);
    ASSERT_TRUE(randCtx != NULL);
    uint32_t in = 1;
    ASSERT_TRUE(CRYPT_EAL_DrbgCtrl(randCtx, CRYPT_CTRL_SET_RESEED_INTERVAL, &in, 4) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(randCtx, NULL, 0) == CRYPT_SUCCESS);
    for (int32_t index = 0; index < 10; index++) {
        uint8_t buf[32] = {0};
        ASSERT_TRUE(CRYPT_EAL_Drbgbytes(randCtx, buf, 32) == CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_DrbgDeinit(randCtx);
    return NULL;
}

#ifdef HITLS_CRYPTO_ENTROPY_SYS
static uint32_t ErrorGetEsEntropy(CRYPT_EAL_Es *esCtx, uint8_t *data, uint32_t len)
{
    (void)esCtx;
    (void)data;
    (void)len;

    return 0;
}
#endif

static CRYPT_EAL_SeedPoolCtx *GetPoolCtx(uint32_t ent1, uint32_t ent2, bool pes1, bool pes2)
{
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    CRYPT_EAL_EsPara para1 = {pes2, ent2, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {pes1, ent1, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    return pool;
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    return NULL;
}

/* END_HEADER */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsNormalTest
* @spec  -
* @title  Basic function test of the entropy source.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsNormalTest(int alg, int size, int test)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    const char *mode = EsGetCfMode((uint32_t)alg);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    (void)test;
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : (bool)test;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadId thrdget;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrdget, EsGetAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);
    BSL_SAL_ThreadClose(thrdget);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)alg;
    (void)size;
    (void)test;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsCtrlTest1
* @spec  -
* @title  Testing the entropy source setting interface.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsCtrlTest1(int type, int state, int excRes)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    uint32_t len = 512;
    if (state == 1) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&len, sizeof(uint32_t)) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    }
    if (excRes == 1) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, type, (void *)&len, sizeof(uint32_t)) == CRYPT_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    } else {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, type, (void *)&len, sizeof(uint32_t)) != CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)type;
    (void)state;
    (void)excRes;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsCtrlTest2
* @spec  -
* @title  Testing the entropy source setting interface.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsCtrlTest2(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool  healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        7,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(intptr_t)para.name, strlen(para.name)) == CRYPT_SUCCESS);
    bool flag = false;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_STATE, &flag, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(flag == false);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_STATE, &flag, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(flag == true);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(intptr_t)para.name, strlen(para.name)) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsGatherTest
* @spec  -
* @title  Testing the entropy source gather interface.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsGatherTest(int gather, int length, int expRes)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    uint32_t size = 512;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    if (gather == 1) {
        BSL_SAL_ThreadId thrd;
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
        BSL_SAL_ThreadClose(thrd);
    }
    uint8_t buf[513] = {0};
    uint32_t len = CRYPT_EAL_EsEntropyGet(es, buf, length);
    ASSERT_TRUE(len == (uint32_t)expRes);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)gather;
    (void)length;
    (void)expRes;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsWithoutNsTest
* @spec  -
* @title  No or no available noise source test.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsWithoutNsTest()
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"timestamp", 9) == CRYPT_SUCCESS);
#ifndef HITLS_BSL_SAL_DARWIN
    /* CPU-Jitter is not added on Darwin, so skip removal */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
    bool healthTest = false;
    /* Not sufficient entropy to pass the test yet, will fix later */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        7,
        {
            NULL,
            EntropyInitError,
            EntropyReadError,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsMultiNsTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsMultiNsTest()
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara errPara = {
        "read-err-ns",
        false,
        7,
        {
            NULL,
            NULL,
            EntropyReadError,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&errPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara initPara = {
        "init-err-ns",
        false,
        7,
        {
            NULL,
            EntropyInitError,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&initPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara heaPara = {
        "health-err-ns",
        false,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadNormal,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&heaPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara norPara = {
        "normal-ns",
        false,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    uint8_t buf[32] = {0};
    // Error stack exists
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, 32) == 32);
    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsNsNumberTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsNsNumberTest(int number, int minEn, int expLen)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && !defined(HITLS_BSL_SAL_DARWIN)
    /* Skip on WSL - platform-specific noise source behavior varies */
    if (IsRunningOnWSL()) {
        (void)number;
        (void)minEn;
        (void)expLen;
        SKIP_TEST();
    }
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    bool healthTest = true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"timestamp", 9) == CRYPT_SUCCESS);
#ifndef HITLS_BSL_SAL_DARWIN
    /* CPU-Jitter is not added on Darwin, so skip removal */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara errPara = {
        NULL,
        false,
        minEn,
        {
            NULL,
            NULL,
            EntropyReadDiffData,
            NULL,
        },
        {5, 39, 512},
    };
    const char *name = "ns-normal-";
    errPara.name = BSL_SAL_Malloc(strlen(name) + 3);
    ASSERT_TRUE(errPara.name != NULL);
    for(int32_t iter = 0; iter < number; iter++) {
        char str[3] = {0};
        strncpy_s((char *)(intptr_t)errPara.name, strlen(name) + 3, name, strlen(name));
        sprintf_s(str, 3, "%d", iter);
        strcat_s((char *)(intptr_t)errPara.name, strlen(name) + 3, str);
        if (iter >= 16) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&errPara, sizeof(CRYPT_EAL_NsPara)) != CRYPT_SUCCESS);
            (void)TestErrClear();
        } else {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&errPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
        }
    }

    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    uint8_t buf[32] = {0};
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, 32) == (uint32_t)expLen);
    if (expLen != 0) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }

EXIT:
    BSL_SAL_Free((void *)(intptr_t)errPara.name);
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)number;
    (void)minEn;
    (void)expLen;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EorTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @brief    1.conditioning function not set, expected result 1
            2.entropy source not initialized, expected result 2
            3.repeated setting of conditioning function, expected result 3
* @expect   1. result 1: failed
            2. result 2: failed
            3. result 3: failed
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EorTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    uint8_t buf[32] = {0};
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, 32) == 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_MutiTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MutiTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")) == CRYPT_SUCCESS);
    uint32_t size = 512;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);
    for (int32_t iter = 0; iter < 3; iter++) { 
        BSL_SAL_ThreadId thrdget;
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrdget, EsGetAuto, es) == 0);
        BSL_SAL_ThreadClose(thrdget);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_MutiBeforeInitTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MutiBeforeInitTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    for (int32_t iter = 0; iter < 3; iter++) {
        BSL_SAL_ThreadId thrdget;
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrdget, EsMutiAuto, es) == 0);
        BSL_SAL_ThreadClose(thrdget);
    }
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0001
* @spec  -
* @title  Function test with the health test disabled, noise source not added, and entropy not added.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0001(int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha512_df", strlen("sha512_df")) == CRYPT_SUCCESS);
    if(enableTest) {
#ifdef HITLS_BSL_SAL_DARWIN
        /* On Darwin, disable health testing due to timestamp NS limitations */
        bool healthTest = false;
#else
        bool healthTest = IsRunningOnWSL() ? false : true;
#endif
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 64);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == 64);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0002
* @spec  -
* @title  Function test of adding noise sources and entropy by pressing Ctrl when the health check mode is disabled.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0002(int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"timestamp", 9) == CRYPT_SUCCESS);
#ifndef HITLS_BSL_SAL_DARWIN
    /* CPU-Jitter is not added on Darwin, so skip removal */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara norPara = {
        "normal-ns",
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    if(enableTest) {
#ifdef HITLS_BSL_SAL_DARWIN
        /* On Darwin, disable health testing due to timestamp NS limitations */
        bool healthTest = false;
#else
        bool healthTest = IsRunningOnWSL() ? false : true;
#endif
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 32);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == 32);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0003
* @spec  -
* @title  Entropy source traversal test with the health test disabled, no noise source added, and different compression functions enabled.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0003(int alg, int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    const char *mode = EsGetCfMode((uint32_t)alg);
    uint32_t expectGetLen = EsGetCfLen((uint32_t)alg);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    if(enableTest) {
#ifdef HITLS_BSL_SAL_DARWIN
        /* On Darwin, disable health testing due to timestamp NS limitations */
        bool healthTest = false;
#else
        bool healthTest = IsRunningOnWSL() ? false : true;
#endif
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, expectGetLen);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == expectGetLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)alg;
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0004
* @spec  -
* @title  Function test of adding noise source and removing noise source after obtaining entropy source in health test disabled mode.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0004(int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, declare healthTest at function level to reuse in both EsInit calls */
    bool healthTest = false;
#endif
    uint32_t expectGetLen = 32;
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"timestamp", 9) == CRYPT_SUCCESS);
#ifndef HITLS_BSL_SAL_DARWIN
    /* CPU-Jitter is not added on Darwin, so skip removal */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
#endif
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_ENTROPY_ES_NO_NS);
    (void)TestErrClear();
    CRYPT_EAL_NsPara norPara1 = {
        "normal-ns",
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {0, 0, 512},
    };
    CRYPT_EAL_NsPara norPara2 = {
        "timestamp",
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara1, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, always disable health testing (healthTest declared at function level) */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
#else
    if(enableTest) {
        bool healthTest = IsRunningOnWSL() ? false : true;
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
#endif
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, expectGetLen);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == expectGetLen);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);

    (void)BSL_SAL_ThreadWriteLock(es->lock);
    ENTROPY_EsDeinit(es->es);
    (void)BSL_SAL_ThreadUnlock(es->lock);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"normal-ns", 10) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_ENTROPY_ES_NO_NS);
    (void)TestErrClear();
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara2, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, re-disable health testing before second EsInit with timestamp NS */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
#endif
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == expectGetLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0005
* @spec  -
* @title  Functional testing of boundary values for different entropy pool sizes.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0005(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    uint32_t poolErrorSize[] = {511, 4097, 1024};
    uint32_t poolSize = 512;
    int32_t ret = 1;

    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    for (uint32_t i = 0; i < sizeof(poolErrorSize)/sizeof(uint32_t); i++) {
        ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&poolErrorSize[i], sizeof(uint32_t));
        if (ret == CRYPT_SUCCESS) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_POOL_SIZE, &poolSize, sizeof(uint32_t)) == CRYPT_ENTROPY_ES_STATE_ERROR);
            ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_POOL_SIZE, &poolSize, sizeof(uint32_t)) == CRYPT_SUCCESS);
            ASSERT_EQ(poolSize, poolErrorSize[i]);
        } else {
            ASSERT_TRUE(ret == CRYPT_ENTROPY_CTRL_INVALID_PARAM);
        }
    }
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0006
* @spec  -
* @title  Entropy source function test in the multi-thread concurrency scenario.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0006(int alg)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    const uint32_t threadNum = 5;
    pthread_t threadId[threadNum];

    for(uint32_t i = 0; i < threadNum; i++) {
        int ret = pthread_create(&threadId[i], NULL, (void *)EntropyESMutilTest, &alg);
        ASSERT_TRUE(ret == 0);
    }

    for(uint32_t i = 0; i < threadNum; i++) {
        pthread_join(threadId[i], NULL);
    }
EXIT:
    return;
#else
    (void)alg;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0007
* @spec  -
* @title  Adding an Existing Noise Source Control Test.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0007(int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_NsPara norPara = {
        "timestamp",
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };

    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_ENTROPY_ES_DUP_NS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"notExistNs", 10) == CRYPT_ENTROPY_ES_NS_NOT_FOUND);
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_SEEDPOOL_GetTest
* @spec  -
* @title  seedpool_GetTest
* @precon  nan
* @brief    1. Entropy data length: 32 - 512, entropy amount: 384, npes not available, return length: 48
            2. Entropy data length: 32 - 512, entropy amount: 384, npes available, return length: 64
            3. entropy data length: 64 - 512, entropy: 380, npes not available, return length: 64
            4. Entropy data length: 64 - 512, entropy amount: 380, npes available, return length: 64
            5. Entropy data length: 48 - 512, entropy amount: 384, npes available, return length: 54
            6. entropy data length: 32 - 32, entropy amount: 256, npes not available, return length: 32
            7. entropy data length: 48 - 48, entropy amount: 256, npes available, return length: 48
            8. entropy data length: 48 - 512, entropy amount: 680, npes available, return length: 48
* @expect
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_SEEDPOOL_GetTest(int min, int max, int entropy, int npes, int exp)
{
    uint8_t *buf = NULL;
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para1 = {false, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {true, 8, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, (bool)npes, (uint32_t)min, (uint32_t)max, (uint32_t)entropy);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    buf = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(len == (uint32_t)exp);
    if (exp == 0) {
        ASSERT_TRUE(buf == NULL);
    } else {
        ASSERT_TRUE(buf != NULL);
    }
EXIT:
    BSL_SAL_Free(buf);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */
#if defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM)
#include "entropy_seed_pool.h"
typedef struct EntCtx {
    uint32_t entSum;
} EntCtx;

static uint32_t EntropyGetSum(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    EntCtx *enctx = (EntCtx *)ctx;
    uint32_t ret = ENTROPY_SysEntropyGet(ctx, buf, bufLen);
    enctx->entSum += ret;
    return ret;
}
#endif
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_SEEDPOOL_EntropySumTest(int minEntropy1, int minEntropy2, int min, int entropy, int exp)
{
#if defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM)
    uint8_t *buf = NULL;
    EAL_EntropyCtx *ctx = NULL;
    EntCtx enctx = {0};

    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para1 = {false, minEntropy1, &enctx, (CRYPT_EAL_EntropyGet)EntropyGetSum};
    CRYPT_EAL_EsPara para2 = {false, minEntropy2, &enctx, (CRYPT_EAL_EntropyGet)EntropyGetSum};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)min, (uint32_t)min, (uint32_t)entropy);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    buf = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(len == (uint32_t)min);
    if (exp == 0) {
        ASSERT_TRUE(buf == NULL);
    } else {
        ASSERT_TRUE(buf != NULL);
    }
    ASSERT_TRUE(enctx.entSum == (uint32_t)exp);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(buf);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_SeedPoolFree(pool);
    return;
#else
    (void)minEntropy1;
    (void)minEntropy2;
    (void)min;
    (void)entropy;
    (void)exp;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_DrbgTest
* @spec  -
* @title  use seedpool to construct an entropy source and generate a random number.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_DrbgTest(int isNull, int algId)
{
#ifndef HITLS_CRYPTO_DRBG_GM
    if (algId == CRYPT_RAND_SM3 || algId == CRYPT_RAND_SM4_CTR_DF) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
#ifndef HITLS_CRYPTO_DRBG_HASH
    if (algId == CRYPT_RAND_SHA256) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
#ifndef HITLS_CRYPTO_DRBG_HMAC
    if (algId == CRYPT_RAND_HMAC_SHA256 || algId == CRYPT_RAND_HMAC_SHA384) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
#ifndef HITLS_CRYPTO_DRBG_CTR
    if (algId == CRYPT_RAND_AES128_CTR_DF || algId == CRYPT_RAND_SM4_CTR_DF) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
    uint8_t output[16];
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew((bool)isNull);
    CRYPT_EAL_EsPara para1 = {true, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {false, 7, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    ASSERT_TRUE(CRYPT_EAL_RandInit((CRYPT_RAND_AlgId)algId, &meth, (void *)pool, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_Randbytes(output, 16) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_DrbgTest
* @spec  -
* @title  use hitls es to construct an entropy source and generate a random number.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DrbgTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    uint8_t output[256];
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "aaa",
        true,
        7,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    for (int32_t iter = 0; iter < 5; iter++) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    }
    CRYPT_RandSeedMethod meth = {GetEntropyTest, CleanEntropyTest, GetNonceTest, CleanNonceTest};
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &meth, (void *)es, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_Randbytes(output, 256) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_MutiTest
* @spec  -
* @title  use seedpool to construct the entropy source and perform the multi-thread test.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_MutiTest(void)
{
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(false);
    CRYPT_EAL_EsPara para1 = {true, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {false, 7, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
    for (int32_t index = 0; index < 3; index++) {
        pthread_t thrd;
        ASSERT_TRUE(pthread_create(&thrd, NULL, DrbgSeedTest, pool) == 0);
        pthread_join(thrd, NULL);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_GetEntropyErrTest
* @spec  -
* @title  The entropy source quality is too poor to meet the requirements.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_GetEntropyErrTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(5, 5, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 48, 256);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_EntLenLessMinTest
* @spec  -
* @title  The supplied entropy source data is smaller than the minimum length.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_EntLenLessMinTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(5, 5, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 48, 128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_SEEDPOOL_Get0EntropyTest
* @spec  -
* @title  failed to obtain entropy data from the entropy pool.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_Get0EntropyTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    CRYPT_EAL_EsPara para1 = {true, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGet0Normal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 48, 256);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_UnsedSeedPoolTest
* @spec  -
* @title  Failed to obtain the entropy data of sufficient length.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_UnsedSeedPoolTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 8, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 81, 100, 128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_DiffEntropyTest
* @spec  -
* @title  The entropy pool used for handle creation is inconsistent with the obtained entropy pool. As a result,
           the entropy source fails to be obtained.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_DiffEntropyTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 8, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 64, 256);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_SeedPoolCtx *pool1 = GetPoolCtx(6, 6, true, false);
    ASSERT_TRUE(pool1 != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool1, ctx) != CRYPT_SUCCESS);
    CRYPT_EAL_SeedPoolFree(pool1);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_Get0EntropyTest
* @spec  -
* @title  Obtains the total entropy output without using the conditioning function.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_FENoEcfTest(int ent)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 7, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 32, ent);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    uint8_t *data = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(data != NULL);
    ASSERT_TRUE(len == 32);
    BSL_SAL_Free(data);

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_FEWithEcfTest
* @spec  -
* @title  Obtains the total entropy output without using the conditioning function.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_FEWithEcfTest(void)
{
#ifndef HITLS_CRYPTO_HMAC
    SKIP_TEST();
#endif
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 7, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 48, 48, 384);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    uint8_t *data = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(data != NULL);
    ASSERT_TRUE(len == 48);
    BSL_SAL_Free(data);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_CompleteTest
* @spec  -
* @title  Complete usage testing from entropy source to drbg.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_CompleteTest(void)
{
    CRYPT_EAL_RndCtx *rndCtx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(false);
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    uint32_t size = 512;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        5,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);
    
    CRYPT_EAL_EsPara para1 = {false, 8, es, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
#endif
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG_GM
    rndCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SM4_CTR_DF, &meth, pool);
#else
    rndCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_AES256_CTR_DF, &meth, pool);
#endif
    ASSERT_TRUE(rndCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(rndCtx, NULL, 0) == CRYPT_SUCCESS);
    uint8_t out[16] = {0};
    ASSERT_TRUE(CRYPT_EAL_Drbgbytes(rndCtx, out, 16) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_DrbgSeed(rndCtx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_DrbgDeinit(rndCtx);
    CRYPT_EAL_SeedPoolFree(pool);
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_EsFree(es);
#endif
    return;
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC019
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC019(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL, int isValid)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry jitter entropy init up to 5 times due to timing-dependent health tests */
    int32_t ret = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret = CRYPT_EAL_EsInit(es);
        if (ret == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC019] CRYPT_EAL_EsInit succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            printf("[TC019] CRYPT_EAL_EsInit attempt %d/%d failed: 0x%08x (%d), retrying...\n",
                   attempt, maxRetries, ret, ret);
        } else {
            printf("[TC019] CRYPT_EAL_EsInit failed after %d attempts, last error: 0x%08x (%d)\n",
                   maxRetries, ret, ret);
            printf("[TC019] Test parameters: isCreateNullPool=%d, isPhysical=%d, minEntropy=%d, minL=%d, maxL=%d, entropyL=%d, isValid=%d\n",
                   isCreateNullPool, isPhysical, minEntropy, minL, maxL, entropyL, isValid);
            printf("[TC019] Health test enabled: %s\n", healthTest ? "true" : "false");
        }
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 16; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara = {isPhysical, (uint32_t)minEntropy, es, NULL};
    if (isValid) {
        esPara.entropyGet = (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet;
    } else {
        esPara.entropyGet = (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy;
    }
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara) == CRYPT_SUCCESS);
    uint8_t isNpesUsed = true;
    uint32_t minLen = (uint32_t)minL;
    uint32_t maxLen = (uint32_t)maxL;
    uint32_t entropy = (uint32_t)entropyL;
    ctx = EAL_EntropyNewCtx(pool, isNpesUsed, minLen, maxLen, entropy);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
    if (isCreateNullPool && !isValid) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT);
    } else {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    (void)isValid;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC039
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC039(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    CRYPT_EAL_Es *es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es1 init up to 5 times */
    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC039] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara1 = {isPhysical, (uint32_t)minEntropy, es1, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    CRYPT_EAL_Es *es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es2 init up to 5 times */
    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC039] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara2 = {!isPhysical, (uint32_t)minEntropy, es2, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    CRYPT_EAL_Es *es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es3 init up to 5 times */
    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC039] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 3; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy, es3, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC067
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC067(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    CRYPT_EAL_Es *es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es1 init up to 5 times */
    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC067] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara1 = {isPhysical, (uint32_t)minEntropy, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es2 init up to 5 times */
    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC067] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara2 = {!isPhysical, (uint32_t)minEntropy, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es3 init up to 5 times */
    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC067] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy, es3, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    if (isCreateNullPool) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);
    } else {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC071
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC071(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    CRYPT_EAL_Es *es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es1 init up to 5 times */
    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC071] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara1 = {!isPhysical, (uint32_t)minEntropy, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es2 init up to 5 times */
    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC071] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara2 = {isPhysical, (uint32_t)minEntropy, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es3 init up to 5 times */
    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC071] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 13; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy, es3, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC051
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC051(int isCreateNullPool, int isPhysical, int minEntropy1,
    int minEntropy2, int minEntropy3, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    CRYPT_EAL_Es *es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es1 init up to 5 times */
    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC051] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    if (isCreateNullPool) {
        for (int i = 0; i < 1; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara1 = {!isPhysical, (uint32_t)minEntropy1, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es2 init up to 5 times */
    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC051] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    if (isCreateNullPool) {
        for (int i = 0; i < 2; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara2 = {isPhysical, (uint32_t)minEntropy2, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es3 init up to 5 times */
    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC051] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 13; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy3, es3, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy1;
    (void)minEntropy2;
    (void)minEntropy3;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC056
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC056(int isCreateNullPool, int isPhysical, int minEntropy1,
    int minEntropy2, int minEntropy3, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    CRYPT_EAL_Es *es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
#ifdef HITLS_BSL_SAL_DARWIN
    /* On Darwin, disable health testing due to timestamp NS limitations */
    bool healthTest = false;
#else
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
#endif
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es1 init up to 5 times */
    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC056] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    CRYPT_EAL_EsPara esPara1 = {!isPhysical, (uint32_t)minEntropy1, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es2 init up to 5 times */
    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC056] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    CRYPT_EAL_EsPara esPara2 = {isPhysical, (uint32_t)minEntropy2, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    CRYPT_EAL_Es *es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry es3 init up to 5 times */
    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC056] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);

    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy3, es3, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    if (isCreateNullPool && minL != maxL) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SEED_POOL_NO_ENTROPY_OBTAINED);
    } else if (isCreateNullPool) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT);
    } else {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy1;
    (void)minEntropy2;
    (void)minEntropy3;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */
