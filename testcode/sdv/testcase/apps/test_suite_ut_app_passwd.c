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
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "app_errno.h"
#include "app_passwd.h"
#include "app_print.h"
#include "bsl_errno.h"
#include "bsl_ui.h"
#include "stub_utils.h"
#include "test.h"
/* END_HEADER */

typedef struct {
    int argc;
    char **argv;
    int expect;
} PasswdTestData;

typedef struct {
    int argc;
    char **argv;
    const char *expect;
} PasswdOutputData;

#define PASSWD_LIMIT_TEST_BASE_LEN 256
#define PASSWD_LIMIT_TEST_LONG_LEN (PASSWD_LIMIT_TEST_BASE_LEN + 1)
#define PASSWD_LIMIT_TEST_BUF_LEN 512

STUB_DEFINE_RET5(int32_t, BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdParam *, char *, uint32_t *,
    const BSL_UI_CheckDataCallBack, void *);

static int32_t AppInit(void)
{
    int32_t ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

static void AppUninit(void)
{
    AppPrintErrorUioUnInit();
}

static int32_t WriteFile(const char *fileName, const char *data)
{
    FILE *fp = fopen(fileName, "w");
    ASSERT_NE(fp, NULL);
    ASSERT_EQ(fputs(data, fp) >= 0, 1);
    ASSERT_EQ(fclose(fp), 0);
    fp = NULL;
    return HITLS_APP_SUCCESS;
EXIT:
    if (fp != NULL) {
        (void)fclose(fp);
    }
    return HITLS_APP_UIO_FAIL;
}

static int32_t ReadFileToBuf(const char *fileName, char *buf, uint32_t bufLen)
{
    FILE *fp = fopen(fileName, "r");
    ASSERT_NE(fp, NULL);
    size_t len = fread(buf, 1, bufLen - 1, fp);
    ASSERT_EQ(ferror(fp), 0);
    buf[len] = '\0';
    ASSERT_EQ(fclose(fp), 0);
    fp = NULL;
    return HITLS_APP_SUCCESS;
EXIT:
    if (fp != NULL) {
        (void)fclose(fp);
    }
    return HITLS_APP_UIO_FAIL;
}

static void RestoreStdoutByFd(int savedStdoutFd)
{
    if (savedStdoutFd >= 0) {
        (void)fflush(stdout);
        (void)dup2(savedStdoutFd, STDOUT_FILENO);
        clearerr(stdout);
    }
}

static void RestoreStderrByFd(int savedStderrFd)
{
    if (savedStderrFd >= 0) {
        (void)fflush(stderr);
        (void)dup2(savedStderrFd, STDERR_FILENO);
        clearerr(stderr);
    }
}

static void RestoreStdinByFd(int savedStdinFd)
{
    if (savedStdinFd >= 0) {
        (void)dup2(savedStdinFd, STDIN_FILENO);
        clearerr(stdin);
    }
}

static int32_t RunPasswdWithStdout(int argc, char **argv, const char *outFile, int savedStdoutFd,
    char *buf, uint32_t bufLen)
{
    (void)memset(buf, 0, bufLen);
    ASSERT_NE(freopen(outFile, "w", stdout), NULL);
    ASSERT_EQ(HITLS_PasswdMain(argc, argv), HITLS_APP_SUCCESS);
    RestoreStdoutByFd(savedStdoutFd);
    ASSERT_EQ(ReadFileToBuf(outFile, buf, bufLen), HITLS_APP_SUCCESS);
    return HITLS_APP_SUCCESS;
EXIT:
    RestoreStdoutByFd(savedStdoutFd);
    return HITLS_APP_UIO_FAIL;
}

static int32_t RunPasswdWithStdoutAndStderr(int argc, char **argv, const char *outFile, const char *errFile,
    int savedStdoutFd, int savedStderrFd, char *outBuf, uint32_t outBufLen, char *errBuf, uint32_t errBufLen)
{
    (void)memset(outBuf, 0, outBufLen);
    (void)memset(errBuf, 0, errBufLen);
    ASSERT_NE(freopen(outFile, "w", stdout), NULL);
    ASSERT_NE(freopen(errFile, "w", stderr), NULL);
    ASSERT_EQ(HITLS_PasswdMain(argc, argv), HITLS_APP_SUCCESS);
    RestoreStdoutByFd(savedStdoutFd);
    RestoreStderrByFd(savedStderrFd);
    ASSERT_EQ(ReadFileToBuf(outFile, outBuf, outBufLen), HITLS_APP_SUCCESS);
    ASSERT_EQ(ReadFileToBuf(errFile, errBuf, errBufLen), HITLS_APP_SUCCESS);
    return HITLS_APP_SUCCESS;
EXIT:
    RestoreStdoutByFd(savedStdoutFd);
    RestoreStderrByFd(savedStderrFd);
    return HITLS_APP_UIO_FAIL;
}

static void FillPassword(char *password, uint32_t passwordLen)
{
    (void)memset(password, 'a', passwordLen);
    password[passwordLen] = '\0';
}

static int32_t StubReadPwdVerify(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)checkDataCallBack;
    (void)callBackData;

    const char *password = "alpha";
    uint32_t passwordLen = (uint32_t)strlen(password) + 1;

    ASSERT_NE(param, NULL);
    ASSERT_EQ(param->verify, true);
    ASSERT_NE(buff, NULL);
    ASSERT_NE(buffLen, NULL);
    ASSERT_TRUE(*buffLen >= passwordLen);
    (void)memcpy(buff, password, passwordLen);
    *buffLen = passwordLen;
    return BSL_SUCCESS;
EXIT:
    return HITLS_APP_STDIN_FAIL;
}

static int32_t StubReadPwdLong(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)checkDataCallBack;
    (void)callBackData;
    ASSERT_NE(param, NULL);
    ASSERT_EQ(param->verify, false);
    ASSERT_NE(buff, NULL);
    ASSERT_NE(buffLen, NULL);
    ASSERT_TRUE(*buffLen > PASSWD_LIMIT_TEST_LONG_LEN);
    FillPassword(buff, PASSWD_LIMIT_TEST_LONG_LEN);
    *buffLen = PASSWD_LIMIT_TEST_LONG_LEN + 1;
    return BSL_SUCCESS;
EXIT:
    return HITLS_APP_STDIN_FAIL;
}

/**
 * @test UT_HITLS_APP_PASSWD_TC001
 * @spec  -
 * @title Test passwd command options
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PASSWD_TC001(void)
{
    char *argv[][8] = {
        {"passwd", "-noverify", "-salt", "12345678", "alpha"},
        {"passwd", "-salt", "12345678", "alpha"},
        {"passwd", "alpha"},
        {"passwd", "-salt", "12345678901234567890", "alpha"},
        {"passwd", "-salt", "./Az09", "alpha"},
        {"passwd", "-salt", "12345678", ""},
        {"passwd", "-rounds", "1000", "-salt", "12345678", ""},
        {"passwd", "-rounds", "999999999", "-salt", "12345678", ""},
        {"passwd", "-6"},

        {"passwd", "-help"},
        {"passwd", "--help"},

        {"passwd", "alpha", "beta"},
        {"passwd", "-stdin", "alpha"},
        {"passwd", "-unknown"},

        {"passwd", "-salt", "", "alpha"},
        {"passwd", "-salt", "$", "alpha"},
        {"passwd", "-salt", "12$34", "alpha"},
        {"passwd", "-salt", "$$$", "alpha"},
        {"passwd", "-salt", "12=34", "alpha"},
        {"passwd", "-salt", "12:34", "alpha"},
        {"passwd", "-salt", "12\n34", "alpha"},
        {"passwd", "-salt", "1234567890123456$bad", "alpha"},
        {"passwd", "-rounds", "999", "-salt", "12345678", "alpha"},
        {"passwd", "-rounds", "1000000000", "-salt", "12345678", "alpha"},
        {"passwd", "-rounds", "0", "-salt", "12345678", "alpha"},

        {"passwd", "-salt", "rounds=10000$12345678", "alpha"},
        {"passwd", "-salt", "rounds=999$12345678", ""},
        {"passwd", "-salt", "rounds=1000000000$12345678", ""},
        {"passwd", "-salt", "rounds=abc$12345678", "alpha"},
        {"passwd", "-rounds", "10000", "-salt", "rounds=10000$12345678", "alpha"},
        {"passwd", "-salt", "rounds=20000$12345678", "-rounds", "10000", "alpha"},
        {"passwd", "-rounds", "10000", "-rounds", "20000", "alpha"},
        {"passwd", "-salt", "rounds=1000$", "alpha"},
        {"passwd", "-salt", "aaa", "-salt", "bbb"},
        {"passwd", "-salt", "rounds=1000$aaa", "-salt", "bbb"},
        {"passwd", "-salt", "aaa", "-salt", "rounds=1000$bbb"}
    };

    PasswdTestData testData[] = {
        {5, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_SUCCESS},
        {2, argv[2], HITLS_APP_SUCCESS},
        {4, argv[3], HITLS_APP_SUCCESS},
        {4, argv[4], HITLS_APP_SUCCESS},
        {4, argv[5], HITLS_APP_SUCCESS},
        {6, argv[6], HITLS_APP_SUCCESS},
        {6, argv[7], HITLS_APP_SUCCESS},
        {2, argv[8], HITLS_APP_OPT_UNKOWN},
        {2, argv[9], HITLS_APP_HELP},
        {2, argv[10], HITLS_APP_HELP},
        {3, argv[11], HITLS_APP_OPT_UNKOWN},
        {3, argv[12], HITLS_APP_OPT_UNKOWN},
        {2, argv[13], HITLS_APP_OPT_UNKOWN},
        {4, argv[14], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[15], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[16], HITLS_APP_SUCCESS},
        {4, argv[17], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[18], HITLS_APP_SUCCESS},
        {4, argv[19], HITLS_APP_SUCCESS},
        {4, argv[20], HITLS_APP_SUCCESS},
        {4, argv[21], HITLS_APP_SUCCESS},
        {6, argv[22], HITLS_APP_OPT_VALUE_INVALID},
        {6, argv[23], HITLS_APP_OPT_VALUE_INVALID},
        {6, argv[24], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[25], HITLS_APP_SUCCESS},
        {4, argv[26], HITLS_APP_SUCCESS},
        {4, argv[27], HITLS_APP_SUCCESS},
        {4, argv[28], HITLS_APP_SUCCESS},
        {6, argv[29], HITLS_APP_OPT_VALUE_INVALID},
        {6, argv[30], HITLS_APP_OPT_VALUE_INVALID},
        {6, argv[31], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[32], HITLS_APP_OPT_VALUE_INVALID},
        {5, argv[33], HITLS_APP_OPT_VALUE_INVALID},
        {5, argv[34], HITLS_APP_OPT_VALUE_INVALID},
        {5, argv[35], HITLS_APP_OPT_VALUE_INVALID}
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(PasswdTestData)); i++) {
        int ret = HITLS_PasswdMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PASSWD_TC002
 * @spec  -
 * @title Test passwd fixed SHA-crypt vectors
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PASSWD_TC002(void)
{
    const char *outFile = "passwd_vector.txt";
    int savedStdoutFd = dup(STDOUT_FILENO);
    char buf[512] = {0};
    char *argvSalt[] = {"passwd", "-salt", "12345678", "alpha"};
    char *argvRounds[] = {"passwd", "-rounds", "10000", "-salt", "12345678", "alpha"};
    char *argvDefaultRounds[] = {"passwd", "-rounds", "5000", "-salt", "12345678", "alpha"};
    char *argvSaltRounds[] = {"passwd", "-salt", "rounds=10000$12345678", "alpha"};
    char *argvSaltMinRounds[] = {"passwd", "-salt", "rounds=999$12345678", "alpha"};
    char *argvSaltSuffix[] = {"passwd", "-salt", "12345678$ignored", "alpha"};
    char *argvEmptyWithSalt[] = {"passwd", "-salt", "12345678", ""};
    char *argvEmptyDefault[] = {"passwd", ""};
    const char *expectSha512 =
        "$6$12345678$WEAmWVsiIEQDnOqFXtk9f.Hv08k9MiA.iRsYaAnWGaCHXLp/ZGIKfp5XKfowVlH5SEnkUWp322wNcH4fB7YXr/\n";
    const char *expectSha512Rounds =
        "$6$rounds=10000$12345678$h10bSxuO1HrsQprIANuBqrRJ6p0KJZoU3b.YIAdQoAh4qwPQoMWIyEBzCfDZ7Vdw58JlurHARHtcpENPYahMV/\n";
    const char *expectSha512DefaultRounds =
        "$6$rounds=5000$12345678$WEAmWVsiIEQDnOqFXtk9f.Hv08k9MiA.iRsYaAnWGaCHXLp/ZGIKfp5XKfowVlH5SEnkUWp322wNcH4fB7YXr/\n";
    const char *expectSha512MinRounds =
        "$6$rounds=1000$12345678$erEQpLw9h2l2mk34XG2spN7SRKxWvVqg9MGPpqcdTzB6HfhirN81hXCApMtegcAfoaoof7S4dRPlAbCidQLAS0\n";
    PasswdOutputData testData[] = {
        {4, argvSalt, expectSha512},
        {6, argvRounds, expectSha512Rounds},
        {6, argvDefaultRounds, expectSha512DefaultRounds},
        {4, argvSaltRounds, expectSha512Rounds},
        {4, argvSaltMinRounds, expectSha512MinRounds},
        {4, argvSaltSuffix, expectSha512},
        {4, argvEmptyWithSalt, "<NULL>\n"},
        {2, argvEmptyDefault, "<NULL>\n"}
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    remove(outFile);
    ASSERT_NE(savedStdoutFd, -1);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(PasswdOutputData)); i++) {
        (void)memset(buf, 0, sizeof(buf));
        ASSERT_NE(freopen(outFile, "w", stdout), NULL);
        ASSERT_EQ(HITLS_PasswdMain(testData[i].argc, testData[i].argv), HITLS_APP_SUCCESS);
        RestoreStdoutByFd(savedStdoutFd);
        ASSERT_EQ(ReadFileToBuf(outFile, buf, sizeof(buf)), HITLS_APP_SUCCESS);
        ASSERT_EQ(strcmp(buf, testData[i].expect), 0);
    }

EXIT:
    RestoreStdoutByFd(savedStdoutFd);
    if (savedStdoutFd >= 0) {
        (void)close(savedStdoutFd);
    }
    remove(outFile);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PASSWD_TC003
 * @spec  -
 * @title Test passwd stdin input
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PASSWD_TC003(void)
{
    const char *stdinFile = "passwd_stdin.txt";
    const char *emptyStdinFile = "passwd_stdin_empty.txt";
    const char *stdoutFile = "passwd_stdin_out.txt";
    int savedStdinFd = dup(STDIN_FILENO);
    int savedStdoutFd = dup(STDOUT_FILENO);
    char outputBuf[512] = {0};
    char *argvStdin[] = {"passwd", "-salt", "12345678", "-stdin"};
    const char *expectedOutput =
        "<NULL>\n"
        "$6$12345678$WEAmWVsiIEQDnOqFXtk9f.Hv08k9MiA.iRsYaAnWGaCHXLp/ZGIKfp5XKfowVlH5SEnkUWp322wNcH4fB7YXr/\n"
        "<NULL>\n"
        "$6$12345678$9Lw6OAzbawRCczKBxgpaRM6caWA9Qe5JlbeRSzIdIfYbYmcyn4JRf0A1QonGFtNZ3S8AOKxPEN7LkqN.zGHBx0\n";

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    remove(stdinFile);
    remove(emptyStdinFile);
    remove(stdoutFile);
    ASSERT_NE(savedStdinFd, -1);
    ASSERT_NE(savedStdoutFd, -1);
    ASSERT_EQ(WriteFile(stdinFile, "\nalpha\n\nbeta"), HITLS_APP_SUCCESS);
    ASSERT_NE(freopen(stdinFile, "r", stdin), NULL);
    ASSERT_NE(freopen(stdoutFile, "w", stdout), NULL);
    ASSERT_EQ(HITLS_PasswdMain(4, argvStdin), HITLS_APP_SUCCESS);
    RestoreStdoutByFd(savedStdoutFd);
    RestoreStdinByFd(savedStdinFd);
    ASSERT_EQ(ReadFileToBuf(stdoutFile, outputBuf, sizeof(outputBuf)), HITLS_APP_SUCCESS);
    ASSERT_EQ(strcmp(outputBuf, expectedOutput), 0);

    (void)memset(outputBuf, 0, sizeof(outputBuf));
    ASSERT_EQ(WriteFile(emptyStdinFile, ""), HITLS_APP_SUCCESS);
    ASSERT_NE(freopen(emptyStdinFile, "r", stdin), NULL);
    ASSERT_NE(freopen(stdoutFile, "w", stdout), NULL);
    ASSERT_EQ(HITLS_PasswdMain(4, argvStdin), HITLS_APP_SUCCESS);
    RestoreStdoutByFd(savedStdoutFd);
    ASSERT_EQ(ReadFileToBuf(stdoutFile, outputBuf, sizeof(outputBuf)), HITLS_APP_SUCCESS);
    ASSERT_EQ(strcmp(outputBuf, ""), 0);

EXIT:
    RestoreStdoutByFd(savedStdoutFd);
    RestoreStdinByFd(savedStdinFd);
    if (savedStdinFd >= 0) {
        (void)close(savedStdinFd);
    }
    if (savedStdoutFd >= 0) {
        (void)close(savedStdoutFd);
    }
    remove(stdinFile);
    remove(emptyStdinFile);
    remove(stdoutFile);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PASSWD_TC004
 * @spec  -
 * @title Test passwd terminal input
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PASSWD_TC004(void)
{
    const char *outFile = "passwd_terminal_out.txt";
    int savedStdoutFd = dup(STDOUT_FILENO);
    char buf[512] = {0};
    char *argvVerify[] = {"passwd", "-salt", "12345678"};
    const char *expectedOutput =
        "$6$12345678$WEAmWVsiIEQDnOqFXtk9f.Hv08k9MiA.iRsYaAnWGaCHXLp/ZGIKfp5XKfowVlH5SEnkUWp322wNcH4fB7YXr/\n";

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    remove(outFile);
    ASSERT_NE(savedStdoutFd, -1);

    STUB_REPLACE(BSL_UI_ReadPwdUtil, StubReadPwdVerify);
    ASSERT_EQ(RunPasswdWithStdout(3, argvVerify, outFile, savedStdoutFd, buf, sizeof(buf)), HITLS_APP_SUCCESS);
    STUB_RESTORE(BSL_UI_ReadPwdUtil);
    ASSERT_EQ(strcmp(buf, expectedOutput), 0);

EXIT:
    STUB_RESTORE(BSL_UI_ReadPwdUtil);
    RestoreStdoutByFd(savedStdoutFd);
    if (savedStdoutFd >= 0) {
        (void)close(savedStdoutFd);
    }
    remove(outFile);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PASSWD_TC005
 * @spec  -
 * @title Test passwd password length limit
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PASSWD_TC005(void)
{
    const char *inputFile = "passwd_limit_stdin.txt";
    const char *outFile = "passwd_limit_out.txt";
    const char *errFile = "passwd_limit_err.txt";
    int savedStdinFd = dup(STDIN_FILENO);
    int savedStdoutFd = dup(STDOUT_FILENO);
    int savedStderrFd = dup(STDERR_FILENO);
    int warnLen = 0;
    char passwordBase[PASSWD_LIMIT_TEST_BASE_LEN + 1] = {0};
    char passwordLong[PASSWD_LIMIT_TEST_LONG_LEN + 1] = {0};
    char stdinLong[PASSWD_LIMIT_TEST_LONG_LEN + 2] = {0};
    char expect[PASSWD_LIMIT_TEST_BUF_LEN] = {0};
    char expectWarn[PASSWD_LIMIT_TEST_BUF_LEN] = {0};
    char buf[PASSWD_LIMIT_TEST_BUF_LEN] = {0};
    char errBuf[PASSWD_LIMIT_TEST_BUF_LEN] = {0};
    char *argvBase[] = {"passwd", "-salt", "12345678", passwordBase};
    char *argvLong[] = {"passwd", "-salt", "12345678", passwordLong};
    char *argvStdin[] = {"passwd", "-salt", "12345678", "-stdin"};
    char *argvTerminal[] = {"passwd", "-salt", "12345678", "-noverify"};

    FillPassword(passwordBase, PASSWD_LIMIT_TEST_BASE_LEN);
    FillPassword(passwordLong, PASSWD_LIMIT_TEST_LONG_LEN);
    FillPassword(stdinLong, PASSWD_LIMIT_TEST_LONG_LEN);
    stdinLong[PASSWD_LIMIT_TEST_LONG_LEN] = '\n';

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    remove(inputFile);
    remove(outFile);
    remove(errFile);
    ASSERT_NE(savedStdinFd, -1);
    ASSERT_NE(savedStdoutFd, -1);
    ASSERT_NE(savedStderrFd, -1);
    warnLen = snprintf(expectWarn, sizeof(expectWarn),
        "passwd: Warning: truncating password to %u bytes.\n",
        (unsigned int)PASSWD_LIMIT_TEST_BASE_LEN);
    ASSERT_TRUE(warnLen > 0 && (uint32_t)warnLen < sizeof(expectWarn));

    ASSERT_EQ(RunPasswdWithStdout(4, argvBase, outFile, savedStdoutFd, expect, sizeof(expect)), HITLS_APP_SUCCESS);
    ASSERT_EQ(RunPasswdWithStdoutAndStderr(4, argvLong, outFile, errFile, savedStdoutFd, savedStderrFd,
        buf, sizeof(buf), errBuf, sizeof(errBuf)), HITLS_APP_SUCCESS);
    ASSERT_EQ(strcmp(buf, expect), 0);
    ASSERT_EQ(strcmp(errBuf, expectWarn), 0);

    ASSERT_EQ(WriteFile(inputFile, stdinLong), HITLS_APP_SUCCESS);
    ASSERT_NE(freopen(inputFile, "r", stdin), NULL);
    ASSERT_EQ(RunPasswdWithStdoutAndStderr(4, argvStdin, outFile, errFile, savedStdoutFd, savedStderrFd,
        buf, sizeof(buf), errBuf, sizeof(errBuf)), HITLS_APP_SUCCESS);
    RestoreStdinByFd(savedStdinFd);
    ASSERT_EQ(strcmp(buf, expect), 0);
    ASSERT_EQ(strcmp(errBuf, ""), 0);

    STUB_REPLACE(BSL_UI_ReadPwdUtil, StubReadPwdLong);
    ASSERT_EQ(RunPasswdWithStdoutAndStderr(4, argvTerminal, outFile, errFile, savedStdoutFd, savedStderrFd,
        buf, sizeof(buf), errBuf, sizeof(errBuf)), HITLS_APP_SUCCESS);
    STUB_RESTORE(BSL_UI_ReadPwdUtil);
    ASSERT_EQ(strcmp(buf, expect), 0);
    ASSERT_EQ(strcmp(errBuf, expectWarn), 0);

EXIT:
    STUB_RESTORE(BSL_UI_ReadPwdUtil);
    RestoreStdoutByFd(savedStdoutFd);
    RestoreStderrByFd(savedStderrFd);
    RestoreStdinByFd(savedStdinFd);
    if (savedStdinFd >= 0) {
        (void)close(savedStdinFd);
    }
    if (savedStdoutFd >= 0) {
        (void)close(savedStdoutFd);
    }
    if (savedStderrFd >= 0) {
        (void)close(savedStderrFd);
    }
    remove(inputFile);
    remove(outFile);
    remove(errFile);
    AppUninit();
    return;
}
/* END_CASE */
