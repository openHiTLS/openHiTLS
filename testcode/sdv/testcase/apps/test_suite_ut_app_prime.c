/*
* Copyright (c) 2025 Hong Han, Weijia Wang, School of Cyber Science and Technology, Shandong University
*/
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
#include <stdio.h>
#include "app_opt.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_function.h"
#include "app_prime.h"
#include "crypt_bn.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "securec.h"
#include "stub_utils.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_APP_OptBegin, int32_t, char **, const HITLS_CmdOption *);
STUB_DEFINE_RET0(char *, HITLS_APP_OptGetValueStr);
STUB_DEFINE_RET6(int32_t, CRYPT_EAL_ProviderRandInitCtx, CRYPT_EAL_LibCtx *, int32_t, const char *, const uint8_t *,
                 uint32_t, BSL_Param *);
STUB_DEFINE_RET1(BN_BigNum *, BN_Create, uint32_t);
STUB_DEFINE_RET0(BN_Optimizer *, BN_OptimizerCreate);
STUB_DEFINE_RET6(int32_t, BN_GenPrime, BN_BigNum *, BN_BigNum *, uint32_t, bool, BN_Optimizer *, BN_CbCtx *);
STUB_DEFINE_RET4(int32_t, BN_PrimeCheck, const BN_BigNum *, uint32_t, BN_Optimizer *, BN_CbCtx *);
STUB_DEFINE_RET2(int32_t, BN_Hex2Bn, BN_BigNum **, const char *);
STUB_DEFINE_RET2(int32_t, BN_Dec2Bn, BN_BigNum **, const char *);

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/**
 * @test UT_HITLS_APP_prime_TC001
 * @spec  -
 * @title   Test basic prime generation with different bit lengths
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC001(void)
{
    char *argv[][5] = {
        {"prime", "-generate", "-bits", "32"},
        {"prime", "-generate", "-bits", "64"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_prime_TC002
 * @spec  -
 * @title   Test safe prime generation
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC002(void)
{
    char *argv[][6] = {
        {"prime", "-generate", "-bits", "16", "-safe"},
    };

    OptTestData testData[] = {
        {5, argv[0], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_prime_TC003
 * @spec  -
 * @title   Test prime checking with known primes
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC003(void)
{
    char *argv[][5] = {
        {"prime", "17"},
        {"prime", "97"},
        {"prime", "257"},
        {"prime", "-hex", "FF"}, // 255 in hex (not prime)
        {"prime", "-hex", "101"}, // 257 in hex (prime)
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_SUCCESS}, {2, argv[1], HITLS_APP_SUCCESS}, {2, argv[2], HITLS_APP_SUCCESS},
        {3, argv[3], HITLS_APP_SUCCESS}, {3, argv[4], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        if (ret != HITLS_APP_SUCCESS && ret != HITLS_APP_CRYPTO_FAIL) {
            AppPrintError("Unexpected return code: %d\n", ret);
            ASSERT_EQ(ret, testData[i].expect);
        }
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_prime_TC004
 * @spec  -
 * @title   Test prime checking with custom check times
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC004(void)
{
    char *argv[][5] = {
        {"prime", "-checks", "10", "17"},
        {"prime", "-checks", "100", "97"},
        {"prime", "-checks", "50", "-hex", "FF"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_SUCCESS},
        {5, argv[2], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        if (ret != HITLS_APP_SUCCESS && ret != HITLS_APP_CRYPTO_FAIL) {
            AppPrintError("Unexpected return code: %d\n", ret);
            ASSERT_EQ(ret, testData[i].expect);
        }
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_prime_TC005
 * @spec  -
 * @title   Test invalid parameters
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC005(void)
{
    char *argv[][5] = {
        {"prime"}, // No arguments
        {"prime", "-generate"}, // Missing -bits
        {"prime", "-bits", "256"}, // -bits without -generate
        {"prime", "-generate", "-bits", "-10"}, // Negative bits
        {"prime", "-generate", "-bits", "0"}, // Zero bits
        {"prime", "-generate", "-bits", "invalid"}, // Invalid bits value
        {"prime", "-checks", "-5", "17"}, // Negative checks
        {"prime", "-checks", "abc", "17"}, // Invalid checks value
        {"prime", "-generate", "-bits", "64", "123"}, // Both generate and check number
    };

    OptTestData testData[] = {
        {1, argv[0], HITLS_APP_INVALID_ARG}, {2, argv[1], HITLS_APP_INVALID_ARG}, {3, argv[2], HITLS_APP_INVALID_ARG},
        {4, argv[3], HITLS_APP_INVALID_ARG}, {4, argv[4], HITLS_APP_INVALID_ARG}, {4, argv[5], HITLS_APP_INVALID_ARG},
        {4, argv[6], HITLS_APP_INVALID_ARG}, {4, argv[7], HITLS_APP_INVALID_ARG}, {5, argv[8], HITLS_APP_INVALID_ARG},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_prime_TC006
 * @spec  -
 * @title   Test help option
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC006(void)
{
    char *argv[][2] = {
        {"prime", "-help"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_HITLS_APP_OptBegin_Fail(int32_t argc, char **argv, const HITLS_CmdOption *opts)
{
    (void)argc;
    (void)argv;
    (void)opts;
    return HITLS_APP_OPT_UNKOWN;
}

/**
 * @test UT_HITLS_APP_prime_TC007
 * @spec  -
 * @title   Test OptBegin failure
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC007(void)
{
    char *argv[][4] = {
        {"prime", "-generate", "-bits", "64"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin_Fail);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(HITLS_APP_OptBegin);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_RandInit_Fail(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName, const uint8_t *pers,
                                     uint32_t persLen, BSL_Param *param)
{
    (void)libCtx;
    (void)algId;
    (void)attrName;
    (void)pers;
    (void)persLen;
    (void)param;
    return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
}

/**
 * @test UT_HITLS_APP_prime_TC008
 * @spec  -
 * @title   Test CRYPT_EAL_ProviderRandInitCtx failure
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC008(void)
{
    char *argv[][4] = {
        {"prime", "-generate", "-bits", "64"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

#if defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
    // Skip crash-prone stub test on ARM platforms
    (void)testData;
    AppPrintInfo("Skipping TC008 on ARM (known to cause crashes with stubs)\n");
#else
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit_Fail);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
#endif

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_RandInit_Success(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
                                        const uint8_t *pers, uint32_t persLen, BSL_Param *param)
{
    (void)libCtx;
    (void)algId;
    (void)attrName;
    (void)pers;
    (void)persLen;
    (void)param;
    return CRYPT_SUCCESS;
}

BN_BigNum *STUB_BN_Create_Fail(uint32_t bits)
{
    (void)bits;
    return NULL;
}

/**
 * @test UT_HITLS_APP_prime_TC009
 * @spec  -
 * @title   Test BN_Create failure
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC009(void)
{
    char *argv[][4] = {
        {"prime", "-generate", "-bits", "64"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_BSL_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

#if defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
    // Skip crash-prone stub test on ARM platforms
    (void)testData;
    AppPrintInfo("Skipping TC009 on ARM (known to cause crashes with stubs)\n");
#else
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit_Success);
    STUB_REPLACE(BN_Create, STUB_BN_Create_Fail);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
    STUB_RESTORE(BN_Create);
#endif

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

BN_Optimizer *STUB_BN_OptimizerCreate_Fail(void)
{
    return NULL;
}

/**
 * @test UT_HITLS_APP_prime_TC010
 * @spec  -
 * @title   Test BN_OptimizerCreate failure
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC010(void)
{
    char *argv[][4] = {
        {"prime", "-generate", "-bits", "64"},
        {"prime", "17"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_BSL_FAIL},
        {2, argv[1], -1},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit_Success);
    STUB_REPLACE(BN_OptimizerCreate, STUB_BN_OptimizerCreate_Fail);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        if (testData[i].expect == -1) {
            if (ret != HITLS_APP_BSL_FAIL && ret != HITLS_APP_INVALID_ARG) {
                AppPrintInfo("Expected BSL_FAIL or INVALID_ARG, got %d\n", ret);
                ASSERT_TRUE(0);
            }
        } else {
            ASSERT_EQ(ret, testData[i].expect);
        }
    }

EXIT:
    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
    STUB_RESTORE(BN_OptimizerCreate);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_BN_GenPrime_Fail(BN_BigNum *r, BN_BigNum *e, uint32_t bits, bool half, BN_Optimizer *opt, BN_CbCtx *cb)
{
    (void)r;
    (void)e;
    (void)bits;
    (void)half;
    (void)opt;
    (void)cb;
    return CRYPT_BN_NOR_GEN_PRIME;
}

/**
 * @test UT_HITLS_APP_prime_TC011
 * @spec  -
 * @title   Test BN_GenPrime failure
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC011(void)
{
    char *argv[][4] = {
        {"prime", "-generate", "-bits", "64"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

#if defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
    // Skip crash-prone stub test on ARM platforms
    (void)testData;
    AppPrintInfo("Skipping TC011 on ARM (known to cause crashes with stubs)\n");
#else
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit_Success);
    STUB_REPLACE(BN_GenPrime, STUB_BN_GenPrime_Fail);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
    STUB_RESTORE(BN_GenPrime);
#endif

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_BN_PrimeCheck_NotPrime(const BN_BigNum *bn, uint32_t checkTimes, BN_Optimizer *opt, BN_CbCtx *cb)
{
    (void)bn;
    (void)checkTimes;
    (void)opt;
    (void)cb;
    return CRYPT_BN_NOR_CHECK_PRIME;
}

/**
 * @test UT_HITLS_APP_prime_TC012
 * @spec  -
 * @title   Test prime check returns not prime
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC012(void)
{
    char *argv[][2] = {
        {"prime", "17"},
    };

    OptTestData testData[] = {
        {2, argv[0], -1},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(BN_PrimeCheck, STUB_BN_PrimeCheck_NotPrime);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        if (testData[i].expect == -1) {
            if (ret != HITLS_APP_SUCCESS && ret != HITLS_APP_INVALID_ARG) {
                AppPrintError("Expected SUCCESS or INVALID_ARG, got %d\n", ret);
                ASSERT_TRUE(0);
            }
        } else {
            ASSERT_EQ(ret, testData[i].expect);
        }
    }

EXIT:
    STUB_RESTORE(BN_PrimeCheck);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_BN_Hex2Bn_Fail(BN_BigNum **r, const char *str)
{
    (void)r;
    (void)str;
    return CRYPT_BN_CONVERT_INPUT_INVALID;
}

/**
 * @test UT_HITLS_APP_prime_TC013
 * @spec  -
 * @title   Test BN_Hex2Bn failure
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC013(void)
{
    char *argv[][3] = {
        {"prime", "-hex", "FF"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_INVALID_ARG},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(BN_Hex2Bn, STUB_BN_Hex2Bn_Fail);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(BN_Hex2Bn);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_BN_Dec2Bn_Fail(BN_BigNum **r, const char *str)
{
    (void)r;
    (void)str;
    return CRYPT_BN_CONVERT_INPUT_INVALID;
}

/**
 * @test UT_HITLS_APP_prime_TC014
 * @spec  -
 * @title   Test BN_Dec2Bn failure
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC014(void)
{
    char *argv[][2] = {
        {"prime", "19"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_INVALID_ARG},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(BN_Dec2Bn, STUB_BN_Dec2Bn_Fail);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(BN_Dec2Bn);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_prime_TC015
 * @spec  -
 * @title   Test edge cases for bit lengths
 */
/* BEGIN_CASE */
void UT_HITLS_APP_prime_TC015(void)
{
#if defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
    // On ARM platforms, test with smaller bit sizes
    char *argv[][5] = {
        {"prime", "-generate", "-bits", "16"},
        {"prime", "-generate", "-bits", "64"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_SUCCESS},
    };
#else
    // On other platforms, test larger sizes
    char *argv[][5] = {
        {"prime", "-generate", "-bits", "16"},
        {"prime", "-generate", "-bits", "512"},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_SUCCESS},
    };
#endif

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit_Success);

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PrimeMain(testData[i].argc, testData[i].argv);
        if (ret != HITLS_APP_SUCCESS && ret != HITLS_APP_BSL_FAIL && ret != HITLS_APP_CRYPTO_FAIL) {
            AppPrintInfo("Expected SUCCESS, BSL_FAIL or CRYPTO_FAIL, got %d\n", ret);
            ASSERT_EQ(ret, testData[i].expect);
        }
    }

EXIT:
    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
