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
#include "app_errno.h"
#include "crypt_errno.h"
#include "app_list.h"
#include "app_function.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "stub_utils.h"

/* END_HEADER */

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_list.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

/**
 * @test UT_HITLS_APP_LIST_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_LIST_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_TC001(void)
{
    char *argv[][20] = {
        {"list", "-all-algorithms"},
        {"list", "-digest-algorithms"},
        {"list", "-cipher-algorithms"},
        {"list", "-asym-algorithms"},
        {"list", "-mac-algorithms"},
        {"list", "-rand-algorithms"},
        {"list", "-kdf-algorithms"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_SUCCESS},
        {2, argv[1], HITLS_APP_SUCCESS},
        {2, argv[2], HITLS_APP_SUCCESS},
        {2, argv[3], HITLS_APP_SUCCESS},
        {2, argv[4], HITLS_APP_SUCCESS},
        {2, argv[5], HITLS_APP_SUCCESS},
        {2, argv[6], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_ListMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_LIST_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_LIST_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_TC002(void)
{
    char *argv[][20] = {
        {"list", "-ttt"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_ListMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */