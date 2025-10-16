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
#include "app_mac.h"

/* END_HEADER */
#define MAC_MAX_ARGC 22
#define MAX_BUFSIZE (1024 * 8)

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

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
 * @test   UT_HITLS_APP_MAC_InvalidOpt_TC001
 * @title  Test the invalid parameters of the mac command.
 * @brief  Enter parameters and return the error code expectRet.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_MAC_InvalidOpt_TC001(char *opts, int expectRet)
{
    system("echo what do ya want for nothing? > test.txt");
    int argc = 0;
    char *argv[MAC_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_MacMain(argc, argv), expectRet);
EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_MAC_NormalOpt_TC001
 * @title  Test the normal parameters of the mac command.
 * @brief  Enter parameters and return HITLS_APP_SUCCESS.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_MAC_NormalOpt_TC001(char *opts, char *outFile, Hex *expectData)
{
    printf("----------------------------------MAC_NormalOpt:");
    int argc = 0;
    char *argv[MAC_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_MacMain(argc, argv), HITLS_APP_SUCCESS);
    ASSERT_EQ(CompareOutByData(outFile, expectData), HITLS_APP_SUCCESS);
EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
    remove(outFile);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_mac_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_mac_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_mac_TC002(void)
{
    char *argv[][10] = {
        {"mac", "-help"},
    };
    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_MacMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */