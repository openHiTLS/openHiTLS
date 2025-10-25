
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
#include "app_provider.h"
#include "app_sm.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_ui.h"
#include "stub_utils.h"

/* END_HEADER */

/* Platform-specific dynamic library extension for testing */
#ifdef __APPLE__
#define BSL_SAL_DL_EXT "dylib"
#else
#define BSL_SAL_DL_EXT "so"
#endif

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_APP_OptBegin, int32_t, char **, const HITLS_CmdOption *);
STUB_DEFINE_RET4(int32_t, BSL_UIO_Ctrl, BSL_UIO *, int32_t, int32_t, void *);
STUB_DEFINE_RET6(int32_t, CRYPT_EAL_ProviderRandInitCtx, CRYPT_EAL_LibCtx *, int32_t, const char *, const uint8_t *, uint32_t, BSL_Param *);
STUB_DEFINE_RET3(int32_t, CRYPT_EAL_RandbytesEx, CRYPT_EAL_LibCtx *, uint8_t *, uint32_t);
STUB_DEFINE_RET1(BSL_UIO *, BSL_UIO_New, const BSL_UIO_Method *);
STUB_DEFINE_RET0(char *, HITLS_APP_OptGetValueStr);
STUB_DEFINE_RET4(int32_t, HITLS_APP_OptWriteUio, BSL_UIO *, uint8_t *, uint32_t, int32_t);
STUB_DEFINE_RET5(int32_t, BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdParam *, char *, uint32_t *, const BSL_UI_CheckDataCallBack, void *);
STUB_DEFINE_RET1(int32_t, HITLS_APP_SM_IntegrityCheck, AppProvider *);
STUB_DEFINE_RET0(int32_t, HITLS_APP_SM_RootUserCheck);


#define WORK_PATH "./rand_workpath"
#define PASSWORD "a1234567"

#ifdef HITLS_CRYPTO_CMVP_SM_PURE_C
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/C/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_ARMV8_LE
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/armv8_le/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_X86_64
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/x86_64/lib"
#endif

#define HITLS_SM_LIB_NAME "libhitls_sm." BSL_SAL_DL_EXT
#define HITLS_SM_PROVIDER_ATTR "provider=sm"

#define SM_PARAM \
    "-sm", "-workpath", WORK_PATH, \
    "-provider", HITLS_SM_LIB_NAME, \
    "-provider-path", HITLS_SM_PROVIDER_PATH, \
    "-provider-attr", HITLS_SM_PROVIDER_ATTR

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_rand.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

static int32_t AppInit(void)
{
    int32_t ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (APP_Create_LibCtx() == NULL) {
        (void)AppPrintError("Create g_libCtx failed\n");
        return HITLS_APP_INVALID_ARG;
    }
    return HITLS_APP_SUCCESS;
}

static void AppUninit(void)
{
    AppPrintErrorUioUnInit();
    HITLS_APP_FreeLibCtx();
}

#ifdef HITLS_APP_SM_MODE
static int32_t STUB_BSL_UI_ReadPwdUtil(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    char result[] = PASSWORD;
    (void)strcpy_s(buff, *buffLen, result);
    *buffLen = (uint32_t)strlen(buff) + 1;
    return BSL_SUCCESS;
}

static int32_t STUB_HITLS_APP_SM_IntegrityCheck(AppProvider *provider)
{
    (void)provider;
    return HITLS_APP_SUCCESS;
}

static int32_t STUB_HITLS_APP_SM_RootUserCheck(void)
{
    return HITLS_APP_SUCCESS;
}
#endif

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

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
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

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
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

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
AppUninit();
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

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
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
    STUB_REPLACE(HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(HITLS_APP_OptBegin);
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
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    STUB_REPLACE(BSL_UIO_Ctrl, STUB_BSL_UIO_Ctrl);
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
    STUB_RESTORE(BSL_UIO_Ctrl);
    AppUninit();
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
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_Randbytes(CRYPT_EAL_LibCtx *libctx, uint8_t *byte, uint32_t len)
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
    STUB_REPLACE(CRYPT_EAL_RandbytesEx, STUB_CRYPT_EAL_Randbytes);
    char *argv[][3] = {
        {"rand", "-hex", "10"},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(CRYPT_EAL_RandbytesEx);
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
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    STUB_REPLACE(BSL_UIO_New, STUB_BSL_UIO_New);
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
    STUB_RESTORE(BSL_UIO_New);
    AppUninit();
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
    STUB_REPLACE(HITLS_APP_OptGetValueStr, STUB_HITLS_APP_OptGetValueStr);
    char *argv[][4] = {{"rand", "-out", "1.txt", "10"}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(HITLS_APP_OptGetValueStr);
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
    STUB_REPLACE(HITLS_APP_OptWriteUio, STUB_HITLS_APP_OptWriteUio);
    char *argv[][4] = {{"rand", "-out", "1.txt", "10"}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(HITLS_APP_OptWriteUio);
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

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        ASSERT_TRUE(IsFileExist(filename) == false);
        int ret = HITLS_RandMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
        ASSERT_TRUE(IsFileExist(filename));
        remove(filename);
    }

EXIT:
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_rand_TC0014
 * @spec  -
 * @title   Test the random function in SM mode.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rand_TC0014(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    system("rm -rf " WORK_PATH);
    system("mkdir -p " WORK_PATH);
    STUB_REPLACE(BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_REPLACE(HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_REPLACE(HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);
    char *argv[] = {"rand", SM_PARAM, "-hex", "10", NULL};

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_RandMain(sizeof(argv) / sizeof(argv[0]) - 1, argv), HITLS_APP_SUCCESS);

EXIT:
    AppUninit();
    STUB_RESTORE(BSL_UI_ReadPwdUtil);
    STUB_RESTORE(HITLS_APP_SM_IntegrityCheck);
    STUB_RESTORE(HITLS_APP_SM_RootUserCheck);
    system("rm -rf " WORK_PATH);
#endif
    return;
}
/* END_CASE */
