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
#include <limits.h>
#include "securec.h"
#include "stub_replace.h"
#include "test.h"
#include "bsl_uio.h"
#include "bsl_types.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_file.h"
#include "string.h"
#include "uio_abstraction.h"
#include "crypt_errno.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_function.h"
#include "app_provider.h"
#include "app_kdf.h"
#include "app_sm.h"
#include "bsl_ui.h"

/* END_HEADER */
#define KDF_MAX_ARGC 22
#define MAX_BUFSIZE (1024 * 8)
#define WORK_PATH "./kdf_workpath"
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

#define HITLS_SM_LIB_NAME "libhitls_sm.so"
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

static int32_t STUB_HITLS_APP_SM_IntegrityCheck(void)
{
    return HITLS_APP_SUCCESS;
}

static int32_t STUB_HITLS_APP_SM_RootUserCheck(void)
{
    return HITLS_APP_SUCCESS;
}
#endif

static void PreProcArgs(char *args, int *argc, char **argv)
{
    uint32_t len = strlen(args);
    argv[(*argc)++] = args;
    for (uint32_t i = 0; i < len; i++) {
        if (args[i] == ' ') {
            args[i] = '\0';
            argv[(*argc)++] = args + i + 1;
        }
    }
    if (APP_GetCurrent_LibCtx() == NULL) {
        if (APP_Create_LibCtx() == NULL) {
            (void)AppPrintError("Create g_libCtx failed\n");
        }
    }
}

static int32_t CompareOutByData(char *file1, Hex *data)
{
    int ret = 1;
    BSL_Buffer buff = {0};
    char hexStr[2 * MAX_BUFSIZE + 1] = {0};
    for (uint32_t i = 0; i < data->len; ++i) {
        sprintf(hexStr + 2 * i, "%02x", data->x[i]);
    }
    uint32_t hexLen = strlen(hexStr);
    ASSERT_EQ(BSL_SAL_ReadFile(file1, &buff.data, &buff.dataLen), 0);
    ASSERT_EQ(buff.dataLen, hexLen);

    ASSERT_COMPARE("Compare out data", buff.data, buff.dataLen, hexStr, hexLen);
    ret = 0;
EXIT:
    BSL_SAL_Free(buff.data);
    return ret;
}

/**
 * @test   UT_HITLS_APP_KDF_InvalidOpt_TC001
 * @title  Test the invalid parameters of the kdf command.
 * @brief  Enter parameters and return the error code expectRet.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KDF_InvalidOpt_TC001(char *opts, int expectRet)
{
    int argc = 0;
    char *argv[KDF_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_KdfMain(argc, argv), expectRet);
EXIT:
    AppUninit();
    BSL_SAL_Free(tmp);
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_KDF_NormalOpt_TC001
 * @title  Test the normal parameters of the kdf command.
 * @brief  Enter parameters and return HITLS_APP_SUCCESS.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KDF_NormalOpt_TC001(char *opts, char *outFile, Hex *expectData)
{
    int argc = 0;
    char *argv[KDF_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_KdfMain(argc, argv), HITLS_APP_SUCCESS);
    ASSERT_EQ(CompareOutByData(outFile, expectData), HITLS_APP_SUCCESS);
EXIT:
    AppUninit();
    BSL_SAL_Free(tmp);
    remove(outFile);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_kdf_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_kdf_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_kdf_TC002(void)
{
    char *argv[][2] = {
        {"kdf", "-help"},
    };
    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_KdfMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_kdf_TC003
 * @title  Test the sm mode of the kdf command.
 * @brief  Enter parameters and return HITLS_APP_SUCCESS.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_kdf_TC003(char *outFile, Hex *expectData)
{
#ifndef HITLS_APP_SM_MODE
    (void)outFile;
    (void)expectData;
    SKIP_TEST();
#else
    system("rm -rf " WORK_PATH);
    system("mkdir -p " WORK_PATH);
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *argv[] = {"kdf", SM_PARAM, "-mac", "hmac-sm3", "-pass", "passwordPASSWORDpassword",
        "-salt", "saltSALTsaltSALTsaltSALTsaltSALTsalt", "-keylen", "40", "-out", outFile,
        "-iter", "1024", "pbkdf2", NULL};
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_KdfMain(sizeof(argv) / sizeof(argv[0]) - 1, argv), HITLS_APP_SUCCESS);
    ASSERT_EQ(CompareOutByData(outFile, expectData), HITLS_APP_SUCCESS);
EXIT:
    AppUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
    system("rm -rf " WORK_PATH);
    remove(outFile);
#endif
}
/* END_CASE */
