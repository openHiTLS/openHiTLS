
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
#include "securec.h"
#include "stub_replace.h"
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
#include "app_x509.h"

/* END_HEADER */
#define X509_MAX_ARGC 22

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

static int32_t CompareOutByData(char *file1, Hex *data)
{
    int ret = 1;
    BSL_Buffer buff = {0};
    ASSERT_EQ(BSL_SAL_ReadFile(file1, &buff.data, &buff.dataLen), 0);
    ASSERT_EQ(buff.dataLen, data->len);
    ASSERT_COMPARE("Compare out data", buff.data, buff.dataLen, data->x, data->len);
    ret = 0;
EXIT:
    BSL_SAL_Free(buff.data);
    return ret;
}

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_x509.c
 * ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */

/**
 * @test   UT_HITLS_APP_X509_InvalidOpt_TC001
 * @title  Test the invalid parameters of the x509 command.
 * @brief  Enter parameters and return the error code expectRet.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_X509_InvalidOpt_TC001(char *opts, int expectRet)
{
    int argc = 0;
    char *argv[X509_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_X509Main(argc, argv), expectRet);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_X509_NormalOpt_TC001
 * @title  Test the normal parameters of the x509 command.
 * @brief  Enter parameters and return HITLS_APP_SUCCESS.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_X509_NormalOpt_TC001(char *opts)
{
    int argc = 0;
    char *argv[X509_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_X509Main(argc, argv), HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_X509_FormatConvert_TC001
 * @title  Test certificate format conversion.
 * @brief  The input format is 'inform', the output format is 'outform', and the output result is the same as that of
 *         out.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_X509_FormatConvert_TC001(char *opts, char *outFile, char *expectFile)
{
    int argc = 0;
    char *argv[X509_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_X509Main(argc, argv), 0);
    ASSERT_EQ(CompareOutByFile(outFile, expectFile), HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
    remove(outFile);
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_X509_Print_TC001
 * @title  Test certificate format conversion.
 * @brief  The input format is 'inform', the output format is 'outform', and the output result is the same as that of
 *         out.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_X509_Print_TC001(char *opts, char *outFile, Hex *expectOut)
{
    int argc = 0;
    char *argv[X509_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_X509Main(argc, argv), 0);
    ASSERT_EQ(CompareOutByData(outFile, expectOut), HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
    remove(outFile);
}
/* END_CASE */
