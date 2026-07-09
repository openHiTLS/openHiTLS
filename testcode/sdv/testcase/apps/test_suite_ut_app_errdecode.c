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
#include <string.h>
#include "app_errdecode.h"
#include "app_errno.h"
#include "app_print.h"

#define ARGC_TWO_ARGS 2
#define ARGC_THREE_ARGS 3
#define ARGC_FOUR_ARGS 4
/* END_HEADER */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC001
 * @spec  -
 * @title   Test help options
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC001(void)
{
    char *argv1[] = {"errdecode", "-h"};
    char *argv2[] = {"errdecode", "-help"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC002
 * @spec  -
 * @title   Test basic error code parsing
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC002(void)
{
    char *argv1[] = {"errdecode", "0x00000000"};
    char *argv2[] = {"errdecode", "0x0E000065"};
    char *argv3[] = {"errdecode", "0"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv3);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC003
 * @spec  -
 * @title   Test verbose mode
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC003(void)
{
    char *argv1[] = {"errdecode", "-v", "0x1408F10B"};
    char *argv2[] = {"errdecode", "--verbose", "0x0E000065"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_THREE_ARGS, argv1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_ErrdecodeMain(ARGC_THREE_ARGS, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC004
 * @spec  -
 * @title   Test invalid input handling
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC004(void)
{
    char *argv1[] = {"errdecode", "invalid_input"};
    char *argv2[] = {"errdecode", "0xGGGG"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv1);
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

    ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv2);
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC005
 * @spec  -
 * @title   Test error stack mode
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC005(void)
{
    char *argv[] = {"errdecode", "--stack"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC006
 * @spec  -
 * @title   Test unknown option handling
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC006(void)
{
    char *argv[] = {"errdecode", "-unknown"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv);
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC007
 * @spec  -
 * @title   Test decimal format error codes
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC007(void)
{
    char *argv1[] = {"errdecode", "101"};
    char *argv2[] = {"errdecode", "234881125"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_ErrdecodeMain(ARGC_TWO_ARGS, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC008
 * @spec  -
 * @title   Test batch processing of multiple error codes
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC008(void)
{
    char *argv[] = {"errdecode", "0x00000000", "0x0E000065", "0x06000001"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_FOUR_ARGS, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ERRDECODE_TC009
 * @spec  -
 * @title   Test -hex forces digit-only input to be parsed as hexadecimal
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ERRDECODE_TC009(void)
{
    char *argv[] = {"errdecode", "-hex", "06000001"};
    FILE *fp = tmpfile();
    char output[256] = {0};

    ASSERT_NE(fp, NULL);
    ASSERT_EQ(AppPrintErrorUioInit(fp), HITLS_APP_SUCCESS);

    int ret = HITLS_ErrdecodeMain(ARGC_THREE_ARGS, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    ASSERT_EQ(fflush(fp), 0);
    ASSERT_EQ(fseek(fp, 0, SEEK_SET), 0);
    ASSERT_TRUE(fread(output, 1, sizeof(output) - 1, fp) > 0);
    ASSERT_TRUE(strstr(output, "error:0000000006000001:CIPHER:cipher_init:initialization failed") != NULL);

EXIT:
    AppPrintErrorUioUnInit();
    if (fp != NULL) {
        fclose(fp);
    }
    return;
}
/* END_CASE */
