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
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <securec.h>
#include "app_passwd.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "bsl_ui.h"
#include "stub_replace.h"
/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_passwd.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */
/* END_HEADER */

#define BSL_SUCCESS 0

typedef struct {
    int argc;
    char **argv;
    int expect;
} PasswdTestData;

int32_t STUB_BSL_UI_ReadPwdUtil(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen, const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    char result[] = "12345678";
    (void)strcpy_s(buff, *buffLen, result);
    *buffLen = (uint32_t)strlen(buff) + 1;
    return BSL_SUCCESS;
}

/**
 * @test UT_HITLS_APP_passwd_TC001
 * @spec  -
 * @title   test UT_HITLS_APP_passwd_TC001 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_passwd_TC001(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    char *argv[][10] = {
        {"passwd", "-help"},
        {"passwd", "-sha512"},
        {"passwd", "-sha512", "-out", "PasswdOutFile"},
        {"passwd", "-sha256"},
        {"passwd"}
    };

    PasswdTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
        {2, argv[1], HITLS_APP_SUCCESS},
        {4, argv[2], HITLS_APP_SUCCESS},
        {2, argv[3], HITLS_APP_OPT_UNKOWN},
        {1, argv[4], HITLS_APP_OPT_VALUE_INVALID}
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(PasswdTestData)); ++i) {
        int ret = HITLS_PasswdMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

int32_t STUB_BSL_UI_ReadPwdUtilIsZero(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen, const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    (void)buff;
    (void)buffLen;
    return BSL_SUCCESS;
}

int32_t STUB_BSL_UI_ReadPwdUtilIs1024(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    char result[] =
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "1111111111111111111111111111111111";
        printf("=======%d\n", *buffLen);
    (void)strcpy_s(buff, *buffLen, result);
    *buffLen = (uint32_t)strlen(result) + 1;
        printf("=======%d\n", *buffLen);
    return BSL_SUCCESS;
}

/* *
 * @test UT_HITLS_APP_passwd_TC002
 * @spec  -
 * @title   test UT_HITLS_APP_passwd_TC002 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_passwd_TC002(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtilIsZero);
    char *argv[][10] = {
        {"passwd", "-sha512", "-out", "PasswdOutFile"},
    };

    PasswdTestData testData[] = {
        {4, argv[0], HITLS_APP_PASSWD_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(PasswdTestData)); ++i) {
        int ret = HITLS_PasswdMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

/* *
 * @test UT_HITLS_APP_passwd_TC003
 * @spec  -
 * @title   test UT_HITLS_APP_passwd_TC003 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_passwd_TC003(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtilIs1024);
    char *argv[][10] = {
        {"passwd", "-sha512", "-out", "PasswdOutFile"},
    };

    PasswdTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(PasswdTestData)); ++i) {
        int ret = HITLS_PasswdMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */