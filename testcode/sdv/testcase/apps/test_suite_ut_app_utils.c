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
#include <unistd.h>
#include "app_errno.h"
#include "app_print.h"
#include "app_utils.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_ui.h"
#include "stub_utils.h"

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */
/* END_HEADER */

STUB_DEFINE_RET2(void *, BSL_SAL_Dump, const void *, uint32_t);
STUB_DEFINE_RET5(int32_t, BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdParam *, char *, uint32_t *,
    const BSL_UI_CheckDataCallBack, void *);

#define TEST_PASS_ENV "HITLS_APP_TEST_PASSWD"
#define TEST_MISSING_PASS_ENV "HITLS_APP_TEST_MISSING_PASSWD"
#define TEST_PASS_FILE "test_app_utils_passwd.tmp"

enum {
    TEST_PASS_SOURCE_ARG = 0,
    TEST_PASS_SOURCE_ENV,
    TEST_PASS_SOURCE_FILE,
    TEST_PASS_SOURCE_STDIN,
    TEST_PASS_SOURCE_NULL_ARG,
    TEST_PASS_SOURCE_NULL_OUT,
    TEST_PASS_SOURCE_UNKNOWN,
    TEST_PASS_SOURCE_EMPTY_ENV,
    TEST_PASS_SOURCE_MISSING_ENV,
    TEST_PASS_SOURCE_EMPTY_FILE,
    TEST_PASS_SOURCE_MISSING_FILE,
    TEST_PASS_SOURCE_STDIN_EOF
};

enum {
    TEST_LINE_END_NONE = 0,
    TEST_LINE_END_LF,
    TEST_LINE_END_CRLF
};

enum {
    TEST_NO_FAULT = 0,
    TEST_DUMP_FAULT
};

enum {
    TEST_TERMINAL_NORMAL = 0,
    TEST_TERMINAL_NULL_PARAM,
    TEST_TERMINAL_NULL_OUT,
    TEST_TERMINAL_VERIFY
};

static int32_t g_terminalReadRet = BSL_SUCCESS;
static uint32_t g_terminalPassLen = 0;

static void *BSL_SAL_DumpNull(const void *src, uint32_t size)
{
    (void)src;
    (void)size;
    return NULL;
}

static int32_t BSL_UI_ReadPwdUtilStub(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    if (g_terminalReadRet != BSL_SUCCESS) {
        return g_terminalReadRet;
    }
    if (*buffLen <= g_terminalPassLen) {
        return BSL_UI_OUTPUT_BUFF_TOO_SHORT;
    }
    (void)memset(buff, 'a', g_terminalPassLen);
    buff[g_terminalPassLen] = '\0';
    *buffLen = g_terminalPassLen + 1;
    return BSL_SUCCESS;
}

static char *CreatePassword(int32_t passwordLen)
{
    if (passwordLen < 0) {
        return NULL;
    }
    char *password = malloc((size_t)passwordLen + 1);
    if (password == NULL) {
        return NULL;
    }
    (void)memset(password, 'a', (size_t)passwordLen);
    password[passwordLen] = '\0';
    return password;
}

static char *CreatePassArg(const char *prefix, const char *password)
{
    size_t argLen = strlen(prefix) + strlen(password) + 1;
    char *passArg = malloc(argLen);
    if (passArg == NULL) {
        return NULL;
    }
    (void)snprintf(passArg, argLen, "%s%s", prefix, password);
    return passArg;
}

static int32_t WritePasswordFile(const char *password, int32_t lineEnding)
{
    FILE *file = fopen(TEST_PASS_FILE, "wb");
    if (file == NULL) {
        return -1;
    }
    size_t passwordLen = strlen(password);
    int32_t ret = fwrite(password, 1, passwordLen, file) == passwordLen ? 0 : -1;
    if (ret == 0 && lineEnding == TEST_LINE_END_LF) {
        ret = fwrite("\n", 1, 1, file) == 1 ? 0 : -1;
    } else if (ret == 0 && lineEnding == TEST_LINE_END_CRLF) {
        ret = fwrite("\r\n", 1, 2, file) == 2 ? 0 : -1;
    }
    if (fclose(file) != 0) {
        ret = -1;
    }
    return ret;
}

/**
 * @test UT_HITLS_APP_PARSE_PASSWD_TC001
 * @spec  -
 * @title Test password sources and length boundaries
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PARSE_PASSWD_TC001(int sourceType, int passwordLen, int lineEnding, int minLen,
    int faultType, int expect)
{
    char *password = NULL;
    char *allocatedArg = NULL;
    char *pass = NULL;
    const char *passArg = NULL;
    char **passOut = &pass;
    int savedStdinFd = -1;
    char fileArg[sizeof("file:") + sizeof(TEST_PASS_FILE)] = {0};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(unsetenv(TEST_MISSING_PASS_ENV), 0);
    (void)remove(TEST_PASS_FILE);
    password = CreatePassword(passwordLen);
    if (passwordLen >= 0) {
        ASSERT_NE(password, NULL);
    }

    switch (sourceType) {
        case TEST_PASS_SOURCE_ARG:
        case TEST_PASS_SOURCE_NULL_OUT:
            allocatedArg = CreatePassArg("pass:", password);
            ASSERT_NE(allocatedArg, NULL);
            passArg = allocatedArg;
            break;
        case TEST_PASS_SOURCE_ENV:
            ASSERT_EQ(setenv(TEST_PASS_ENV, password, 1), 0);
            passArg = "env:" TEST_PASS_ENV;
            break;
        case TEST_PASS_SOURCE_FILE:
        case TEST_PASS_SOURCE_STDIN:
            ASSERT_EQ(WritePasswordFile(password, lineEnding), 0);
            if (sourceType == TEST_PASS_SOURCE_FILE) {
                (void)snprintf(fileArg, sizeof(fileArg), "file:%s", TEST_PASS_FILE);
                passArg = fileArg;
                break;
            }
            savedStdinFd = dup(STDIN_FILENO);
            ASSERT_TRUE(savedStdinFd >= 0);
            ASSERT_NE(freopen(TEST_PASS_FILE, "rb", stdin), NULL);
            passArg = "stdin";
            break;
        case TEST_PASS_SOURCE_NULL_ARG:
            passArg = NULL;
            break;
        case TEST_PASS_SOURCE_UNKNOWN:
            passArg = "unknown";
            break;
        case TEST_PASS_SOURCE_EMPTY_ENV:
            passArg = "env:";
            break;
        case TEST_PASS_SOURCE_MISSING_ENV:
            passArg = "env:" TEST_MISSING_PASS_ENV;
            break;
        case TEST_PASS_SOURCE_EMPTY_FILE:
            passArg = "file:";
            break;
        case TEST_PASS_SOURCE_MISSING_FILE:
            passArg = "file:test_app_utils_missing.tmp";
            (void)remove("test_app_utils_missing.tmp");
            break;
        case TEST_PASS_SOURCE_STDIN_EOF:
            ASSERT_EQ(WritePasswordFile("", TEST_LINE_END_NONE), 0);
            savedStdinFd = dup(STDIN_FILENO);
            ASSERT_TRUE(savedStdinFd >= 0);
            ASSERT_NE(freopen(TEST_PASS_FILE, "rb", stdin), NULL);
            passArg = "stdin";
            break;
        default:
            ASSERT_TRUE(false);
    }
    if (sourceType == TEST_PASS_SOURCE_NULL_OUT) {
        passOut = NULL;
    }
    if (faultType == TEST_DUMP_FAULT) {
        STUB_REPLACE(BSL_SAL_Dump, BSL_SAL_DumpNull);
    }

    ASSERT_EQ(HITLS_APP_ParsePasswd(passArg, (uint32_t)minLen, passOut), expect);
    if (expect == HITLS_APP_SUCCESS && passArg != NULL) {
        ASSERT_NE(pass, NULL);
        ASSERT_EQ(strlen(pass), (size_t)passwordLen);
        ASSERT_TRUE(memcmp(pass, password, (size_t)passwordLen) == 0);
    } else {
        ASSERT_EQ(pass, NULL);
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Dump);
    if (savedStdinFd >= 0) {
        (void)dup2(savedStdinFd, STDIN_FILENO);
        (void)close(savedStdinFd);
        clearerr(stdin);
    }
    if (pass != NULL) {
        BSL_SAL_ClearFree(pass, strlen(pass) + 1);
    }
    free(allocatedArg);
    free(password);
    (void)unsetenv(TEST_PASS_ENV);
    (void)unsetenv(TEST_MISSING_PASS_ENV);
    (void)remove(TEST_PASS_FILE);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_GET_PASSWD_FROM_TERMINAL_TC001
 * @spec  -
 * @title Test terminal password length and read errors
 */
/* BEGIN_CASE */
void UT_HITLS_APP_GET_PASSWD_FROM_TERMINAL_TC001(int readRet, int passwordLen, int minLen, int argType,
    int expect)
{
    BSL_UI_ReadPwdParam param = {"password", NULL, false};
    BSL_UI_ReadPwdParam *paramPtr = &param;
    char *pass = NULL;
    char **passOut = &pass;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    g_terminalReadRet = readRet;
    g_terminalPassLen = (uint32_t)passwordLen;
    STUB_REPLACE(BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdUtilStub);
    if (argType == TEST_TERMINAL_NULL_PARAM) {
        paramPtr = NULL;
    } else if (argType == TEST_TERMINAL_NULL_OUT) {
        passOut = NULL;
    } else if (argType == TEST_TERMINAL_VERIFY) {
        param.verify = true;
    }

    ASSERT_EQ(HITLS_APP_GetPasswdFromTerminal(paramPtr, (uint32_t)minLen, passOut), expect);
    if (expect == HITLS_APP_SUCCESS) {
        ASSERT_NE(pass, NULL);
        ASSERT_EQ(strlen(pass), (size_t)passwordLen);
        for (int32_t i = 0; i < passwordLen; i++) {
            ASSERT_EQ(pass[i], 'a');
        }
    } else {
        ASSERT_EQ(pass, NULL);
    }

EXIT:
    STUB_RESTORE(BSL_UI_ReadPwdUtil);
    if (pass != NULL) {
        BSL_SAL_ClearFree(pass, strlen(pass) + 1);
    }
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
