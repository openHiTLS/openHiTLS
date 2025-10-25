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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "securec.h"
#include "stub_utils.h"
#include "test.h"
#include "bsl_uio.h"
#include "bsl_types.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_file.h"
#include "uio_abstraction.h"
#include "crypt_errno.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_function.h"
#include "app_pkeyutl.h"
#include "app_provider.h"

/* END_HEADER */
#define PKEYUTL_MAX_ARGC 22
#define TEST_FILE_PATH "out_test.bin"
#define TEST_INFILE_PATH "../testdata/apps/mac/test.txt"
#define TEST_PRV_PATH "../testdata/apps/sm2/prv.pem"
#define TEST_PUB_PATH "../testdata/apps/sm2/pub.pem"
#define TEST_PEERPRV_PATH "../testdata/apps/sm2/prv1.pem"
#define TEST_PEERPUB_PATH "../testdata/apps/sm2/pub1.pem"
#define TEST_DECFILE_PATH "plain.txt"

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

static int32_t CompareOutByFile(char *file1, char *file2)
{
    int ret = 1;
    BSL_Buffer buff1 = {0};
    BSL_Buffer buff2 = {0};
    ASSERT_EQ(BSL_SAL_ReadFile(file1, &buff1.data, &buff1.dataLen), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(file2, &buff2.data, &buff2.dataLen), 0);
    ASSERT_EQ(buff1.dataLen, buff2.dataLen);
    ASSERT_COMPARE("Compare out data", buff1.data, buff1.dataLen, buff2.data, buff2.dataLen);
    ret = 0;
EXIT:
    BSL_SAL_Free(buff1.data);
    BSL_SAL_Free(buff2.data);
    return ret;
}

/**
 * @test UT_HITLS_APP_PKEYUTL_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_PKEYUTL_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEYUTL_TC001(char *opts, int expectRet)
{
    int argc = 0;
    char *argv[PKEYUTL_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyUtlMain(argc, argv), expectRet);
EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_PKEYUTL_InvaildOpt_TC001
 * @title  Test the invaild parameters of the pkeyutl command.
 * @brief  Enter parameters and return HITLS_APP_SUCCESS.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEYUTL_InvaildOpt_TC001(char *opts, int expectRet)
{
    int argc = 0;
    char *argv[PKEYUTL_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyUtlMain(argc, argv), expectRet);
EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_PKEYUTL_NormalOpt_TC002
 * @title  Test the normal parameters of the pkeyutl command.
 * @brief  Enter parameters and return HITLS_APP_SUCCESS.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEYUTL_NormalOpt_TC002(char *opts, char *outFile, char *expectFile)
{
    int argc = 0;
    char *argv[PKEYUTL_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyUtlMain(argc, argv), 0);
    ASSERT_EQ(CompareOutByFile(outFile, expectFile), HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
    remove(outFile);
    remove("R1.bin");
    remove("R2.bin");
    remove("share1.key");
    remove("share2.key");
    remove("r1.bin");
    remove("r2.bin");
    remove("out_test.bin");
}
/* END_CASE */