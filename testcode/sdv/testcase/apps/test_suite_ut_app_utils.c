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
#include "app_errno.h"
#include "app_print.h"
#include "app_utils.h"
#include "bsl_sal.h"
#include "stub_utils.h"

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */
/* END_HEADER */

STUB_DEFINE_RET2(void *, BSL_SAL_Dump, const void *, uint32_t);

static void *BSL_SAL_DumpNull(const void *src, uint32_t size)
{
    (void)src;
    (void)size;
    return NULL;
}

#define TEST_PASS_ENV "HITLS_APP_TEST_PASSWD"
#define TEST_MISSING_PASS_ENV "HITLS_APP_TEST_MISSING_PASSWD"

/**
 * @test UT_HITLS_APP_PARSE_PASSWD_ENV_TC001
 * @spec  -
 * @title Test parsing a password from an environment variable
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PARSE_PASSWD_ENV_TC001(void)
{
    char *pass = NULL;
    const char *envValue = NULL;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(setenv(TEST_PASS_ENV, "123456", 1), 0);
    envValue = getenv(TEST_PASS_ENV);
    ASSERT_NE(envValue, NULL);
    ASSERT_EQ(HITLS_APP_ParsePasswd("env:" TEST_PASS_ENV, &pass), HITLS_APP_SUCCESS);
    ASSERT_TRUE(strcmp(pass, envValue) == 0);
    ASSERT_TRUE(pass != envValue);

EXIT:
    if (pass != NULL) {
        BSL_SAL_ClearFree(pass, strlen(pass));
    }
    (void)unsetenv(TEST_PASS_ENV);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PARSE_PASSWD_ENV_TC002
 * @spec  -
 * @title Test parsing a password from a missing environment variable
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PARSE_PASSWD_ENV_TC002(void)
{
    char *pass = NULL;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(unsetenv(TEST_MISSING_PASS_ENV), 0);
    ASSERT_EQ(HITLS_APP_ParsePasswd("env:" TEST_MISSING_PASS_ENV, &pass), HITLS_APP_PASSWD_FAIL);
    ASSERT_EQ(pass, NULL);

EXIT:
    BSL_SAL_FREE(pass);
    (void)unsetenv(TEST_MISSING_PASS_ENV);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PARSE_PASSWD_ENV_TC003
 * @spec  -
 * @title Test an empty environment variable name
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PARSE_PASSWD_ENV_TC003(void)
{
    char *pass = NULL;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_APP_ParsePasswd("env:", &pass), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(pass, NULL);

EXIT:
    BSL_SAL_FREE(pass);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PARSE_PASSWD_ENV_TC004
 * @spec  -
 * @title Test parsing an empty password from an environment variable
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PARSE_PASSWD_ENV_TC004(void)
{
    char *pass = NULL;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(setenv(TEST_PASS_ENV, "", 1), 0);
    ASSERT_EQ(HITLS_APP_ParsePasswd("env:" TEST_PASS_ENV, &pass), HITLS_APP_SUCCESS);
    ASSERT_TRUE(strcmp(pass, "") == 0);

EXIT:
    BSL_SAL_FREE(pass);
    (void)unsetenv(TEST_PASS_ENV);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PARSE_PASSWD_ENV_TC005
 * @spec  -
 * @title Test a memory allocation failure when copying an environment password
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PARSE_PASSWD_ENV_TC005(void)
{
    char *pass = NULL;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(setenv(TEST_PASS_ENV, "123456", 1), 0);
    STUB_REPLACE(BSL_SAL_Dump, BSL_SAL_DumpNull);
    ASSERT_EQ(HITLS_APP_ParsePasswd("env:" TEST_PASS_ENV, &pass), HITLS_APP_MEM_ALLOC_FAIL);
    ASSERT_EQ(pass, NULL);

EXIT:
    STUB_RESTORE(BSL_SAL_Dump);
    BSL_SAL_FREE(pass);
    (void)unsetenv(TEST_PASS_ENV);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
