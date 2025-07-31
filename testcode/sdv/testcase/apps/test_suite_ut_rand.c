
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
#include "bsl_uio.h"
#include "uio_abstraction.h"
#include "crypt_eal_rand.h"
#include "app_errno.h"
#include "bsl_base64.h"
#include "crypt_errno.h"
#include "app_rand.h"
#include "app_function.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "stub_replace.h"

/* END_HEADER */

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_rand.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

/**
 * @test UT_HITLS_APP_rand_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC001(void)
{
    char *argv[][10] = {
        {"rand", "-hex", "10"},
        {"rand", "10"},
        {"rand", "-base64", "10"},
        {"rand", "-out", "TC001_binary.txt", "10"},
        {"rand", "-out", "TC001_hex.txt", "-hex", "10"},
        {"rand", "-out", "TC001_base64.txt", "-base64", "10"}
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_SUCCESS},
        {2, argv[1], HITLS_APP_SUCCESS},
        {3, argv[2], HITLS_APP_SUCCESS},
        {4, argv[3], HITLS_APP_SUCCESS},
        {5, argv[4], HITLS_APP_SUCCESS},
        {5, argv[5], HITLS_APP_SUCCESS}
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_rand_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC002(void)
{
    char *argv[][5] = {
        {"rand", "-base64", "-out", "1.txt", "10"},
        {"rand", "-hex", "-out", "D:\\outfile\\1.txt", "10"},
        {"rand", "-hex", "1.txt", "10"},
        {"rand", "-out"}
    };

    OptTestData testData[] =
    {
        {5, argv[0], HITLS_APP_SUCCESS},
        {5, argv[1], HITLS_APP_SUCCESS},
        {4, argv[2], HITLS_APP_OPT_UNKOWN},
        {2, argv[3], HITLS_APP_OPT_UNKOWN}
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_rand_TC003
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC003(void)
{
    char *argv[][4] = {
        {"rand", "1231-31231"},
        {"rand", "asdsaldsalkdsjadl"},
        {"rand", "2147483648"},
        {"rand", "-10"},
        {"rand", "2312/0"},
        {"rand", "-out", "D:\\outfile\\1.txt", "123"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {2, argv[1], HITLS_APP_OPT_VALUE_INVALID},
        {2, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {2, argv[3], HITLS_APP_OPT_UNKOWN},    //带了'-'误认为是命令
        {2, argv[4], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[5], HITLS_APP_SUCCESS}
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_rand_TC004
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC004函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC004(void)
{
    char *argv[][2] = {
        {"rand", "-help"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_HITLS_APP_OptBegin(int32_t argc, char **argv, const HITLS_CmdOption *opts)
{
    (void)argc;
    (void)argv;
    (void)opts;
    return HITLS_APP_OPT_UNKOWN;
}

/**
 * @test UT_HITLS_APP_rand_TC005
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC005函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC005(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

void *STUB_SAL_Calloc(uint32_t num, uint32_t size)
{
    (void)num;
    (void)size;
    return NULL;
}

/**
 * @test UT_HITLS_APP_rand_TC006
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC006函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC006(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_SAL_Calloc, STUB_SAL_Calloc);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
        {"rand", "-base64", "10"},
        {"rand", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_CRYPTO_FAIL},
        {3, argv[1], HITLS_APP_CRYPTO_FAIL},
        {2, argv[2], HITLS_APP_CRYPTO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

int32_t STUB_BSL_UIO_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    (void)uio;
    (void)cmd;
    (void)larg;
    (void)parg;
    return BSL_NULL_INPUT;
}

/**
 * @test UT_HITLS_APP_rand_TC007
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC007函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC007(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_UIO_Ctrl, STUB_BSL_UIO_Ctrl);
    char *argv[][4] = {
        {"rand", "-hex", "2049"},
        {"rand", "-out", "1.txt", "10"},
        {"rand", "-out", "D:\\outfile\\1.txt", "10"}
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_UIO_FAIL},
        {4, argv[1], HITLS_APP_UIO_FAIL},
        {4, argv[2], HITLS_APP_UIO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_RandInit(
    CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    const uint8_t *pers, uint32_t persLen, BSL_Param *param)
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
 * @test UT_HITLS_APP_rand_TC008
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC008函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC008(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_Randbytes(void *libctx, uint8_t *byte, uint32_t len)
{
    (void)byte;
    (void)len;
    (void)libctx;
    return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL;
}

/**
 * @test UT_HITLS_APP_rand_TC009
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC009函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC009(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, CRYPT_EAL_RandbytesEx, STUB_CRYPT_EAL_Randbytes);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

BSL_UIO *STUB_BSL_UIO_New(const BSL_UIO_Method *method)
{
    (void)method;
    return NULL;
}

/**
 * @test UT_HITLS_APP_rand_TC0010
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC0010函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC0010(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_UIO_New, STUB_BSL_UIO_New);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_UIO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

char *STUB_HITLS_APP_OptGetValueStr(void)
{
    return NULL;
}

/**
 * @test UT_HITLS_APP_rand_TC0011
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC0011函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC0011(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, HITLS_APP_OptGetValueStr, STUB_HITLS_APP_OptGetValueStr);
    char *argv[][4] = {{"rand", "-out", "1.txt", "10"}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

int32_t STUB_HITLS_APP_OptWriteUio(BSL_UIO *uio, uint8_t *buf, uint32_t outLen, int32_t format)
{
    (void)uio;
    (void)buf;
    (void)outLen;
    (void)format;
    return HITLS_APP_UIO_FAIL;
}

/**
 * @test UT_HITLS_APP_rand_TC0012
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC0012函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC0012(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, HITLS_APP_OptWriteUio, STUB_HITLS_APP_OptWriteUio);
    char *argv[][4] = {{"rand", "-out", "1.txt", "10"}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

bool IsFileExist(const char *fileName)
{
    FILE *f = fopen(fileName, "r");
    if (f == NULL) {
        return false;
    }
    fclose(f);
    return true;
}

/**
 * @test UT_HITLS_APP_rand_TC0013
 * @spec  -
 * @title   测试UT_HITLS_APP_rand_TC0013函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC0013(void)
{
    char* filename = "TC0013_binary.txt";
    char *argv[][10] = {
        {"rand", "-out", filename, "10"},
        {"rand", "-out", filename, "-hex", "10"},
        {"rand", "-out", filename, "-base64", "10"}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {5, argv[1], HITLS_APP_SUCCESS},
        {5, argv[2], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        ASSERT_TRUE(IsFileExist(filename) == false);
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
        ASSERT_TRUE(IsFileExist(filename));
        remove(filename);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
