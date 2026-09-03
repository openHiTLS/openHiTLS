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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "app_opt.h"
#include "app_print.h"
#include "sal_file.h"
#include "bsl_uio.h"
#include "bsl_ui.h"
#include "uio_abstraction.h"
#include "app_errno.h"
#include "crypt_errno.h"
#include "app_pkey.h"
#include "app_function.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "stub_utils.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET5(int32_t, BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdParam *, char *, uint32_t *, const BSL_UI_CheckDataCallBack, void *);
STUB_DEFINE_RET2(int32_t, CRYPT_EAL_PkeyPairCheck, CRYPT_EAL_PkeyCtx *, CRYPT_EAL_PkeyCtx *);


#define BAD_KEY_PATH "../testdata/apps/pkey/bad_rsa.pem"
#define PKEY_TEST_FILE_PATH "out_test.pem"
#define PKEY_RELOAD_FILE_PATH "out_reload.pem"
#define PKEY_TEST_DIR_PATH "./pkey_dir"

#define PKEY_MAX_ARGC 10

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

static void RestoreStdoutByFd(int savedStdoutFd)
{
    if (savedStdoutFd < 0) {
        return;
    }
    /*
     * Some command paths write to process stdout when no -out option is supplied.
     * Restore the original stdout fd before the next test iteration so subsequent
     * cases and framework logs do not inherit redirected output state.
     * Tests may run without a controlling tty, so recover by fd instead of /dev/tty.
     */
    fflush(stdout);
    (void)dup2(savedStdoutFd, STDOUT_FILENO);
    clearerr(stdout);
}

static void RestoreStdinByFd(int savedStdinFd)
{
    if (savedStdinFd < 0) {
        return;
    }
    /* Keep stdin recovery independent from terminal availability in CI. */
    (void)dup2(savedStdinFd, STDIN_FILENO);
    clearerr(stdin);
}

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

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_pkey.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */

/**
 * @test UT_HITLS_APP_PKEY_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_PKEY_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_TC001(char *encKeyPath)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    char *argv[][20] = {
        {"pkey", "-in", encKeyPath, "-passin", "pass:123456"},
        {"pkey", "-in", encKeyPath, "-passin", "pass:123456", "-out", PKEY_TEST_FILE_PATH},
        {"pkey", "-in", encKeyPath, "-passin", "pass:123456", "-aes256_cbc", "-passout", "pass:123456"},
        {"pkey", "-in", encKeyPath, "-passin", "pass:123456", "-aes256_cbc", "-passout", "pass:123456",
         "-out", PKEY_TEST_FILE_PATH},
        {"pkey", "-in", encKeyPath, "-passin", "pass:123456", "-pubout"},
        {"pkey", "-in", encKeyPath, "-passin", "pass:123456", "-out", PKEY_TEST_FILE_PATH},
    };

    OptTestData testData[] = {
        {5, argv[0], HITLS_APP_SUCCESS},
        {7, argv[1], HITLS_APP_SUCCESS},
        {8, argv[2], HITLS_APP_SUCCESS},
        {10, argv[3], HITLS_APP_SUCCESS},
        {6, argv[4], HITLS_APP_SUCCESS},
        {7, argv[5], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PkeyMain(testData[i].argc, testData[i].argv);
        RestoreStdoutByFd(savedStdoutFd);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    remove(PKEY_TEST_FILE_PATH);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_PKEY_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_TC002(char *keyPath)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    char *argv[][20] = {
        {"pkey", "-in", keyPath},
        {"pkey", "-in", keyPath, "-out", PKEY_TEST_FILE_PATH},
        {"pkey", "-in", keyPath, "-pubout"},
        {"pkey", "-in", keyPath, "-pubout", "-out", PKEY_TEST_FILE_PATH},
    };

    OptTestData testData[] = {
        {3, argv[0], HITLS_APP_SUCCESS},
        {5, argv[1], HITLS_APP_SUCCESS},
        {4, argv[2], HITLS_APP_SUCCESS},
        {6, argv[3], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PkeyMain(testData[i].argc, testData[i].argv);
        RestoreStdoutByFd(savedStdoutFd);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    remove(PKEY_TEST_FILE_PATH);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_TC003
 * @spec  -
 * @title   测试UT_HITLS_APP_PKEY_TC003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_TC003(char *encKeyPath, char *keyPath)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    mkdir(PKEY_TEST_DIR_PATH, 0775);
    char *argv[][20] = {
        {"pkey", "-ttt"},
        {"pkey", "-in", "no_exist.pem"},
        {"pkey", "-in", BAD_KEY_PATH},
        {"pkey", "-in", encKeyPath, "-passin", "err:12"},
        {"pkey", "-in", encKeyPath, "-passin", "pass:"},
        {"pkey", "-in", keyPath, "-passout", "err:12"},
        {"pkey", "-in", keyPath, "-aes256_cbc", "-passout", "pass:"},
        {"pkey", "-in", keyPath, "-out", PKEY_TEST_DIR_PATH},
        {"pkey", "-in", keyPath, "-pubout", "-out", PKEY_TEST_DIR_PATH},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_OPT_UNKOWN},
        {3, argv[1], HITLS_APP_LOAD_KEY_FAIL},
        {3, argv[2], HITLS_APP_LOAD_KEY_FAIL},
        {5, argv[3], HITLS_APP_PASSWD_FAIL},
        {5, argv[4], HITLS_APP_LOAD_KEY_FAIL},
        {5, argv[5], HITLS_APP_PASSWD_FAIL},
        {6, argv[6], HITLS_APP_PASSWD_FAIL},
        {5, argv[7], HITLS_APP_UIO_FAIL},
        {6, argv[8], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PkeyMain(testData[i].argc, testData[i].argv);
        RestoreStdoutByFd(savedStdoutFd);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    rmdir(PKEY_TEST_DIR_PATH);
    remove(PKEY_TEST_FILE_PATH);
    return;
}
/* END_CASE */

static int32_t BSL_UI_ReadPwdUtil_Mock(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    (void)buff;
    (void)buffLen;
    return HITLS_APP_PASSWD_FAIL;
}

/**
 * @test UT_HITLS_APP_PKEY_TC004
 * @spec  -
 * @title   测试UT_HITLS_APP_PKEY_TC004函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_TC004(char *encKeyPath, char *keyPath)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    STUB_REPLACE(BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdUtil_Mock);;
    char *argv[][20] = {
        {"pkey", "-in", keyPath, "-passin", "pass:"},
        {"pkey", "-in", keyPath, "-passin", "stdin"},
        {"pkey", "-in", keyPath, "-passout", "pass:"},
        {"pkey", "-in", keyPath, "-passout", "stdin"},
        {"pkey", "-in", encKeyPath, "-passin", "pass:"},
        {"pkey", "-in", encKeyPath, "-passin", "stdin"},
        {"pkey", "-in", encKeyPath},
        {"pkey", "-in", keyPath, "-aes256_cbc", "-passout", "pass:"},
        {"pkey", "-in", keyPath, "-aes256_cbc", "-passout", "stdin"},
        {"pkey", "-in", keyPath, "-aes256_cbc"},
    };

    OptTestData testData[] = {
        {5, argv[0], HITLS_APP_SUCCESS},
        {5, argv[1], HITLS_APP_PASSWD_FAIL},
        {5, argv[2], HITLS_APP_SUCCESS},
        {5, argv[3], HITLS_APP_PASSWD_FAIL},
        {5, argv[4], HITLS_APP_LOAD_KEY_FAIL},
        {5, argv[5], HITLS_APP_PASSWD_FAIL},
        {3, argv[6], HITLS_APP_LOAD_KEY_FAIL},
        {6, argv[7], HITLS_APP_PASSWD_FAIL},
        {6, argv[8], HITLS_APP_PASSWD_FAIL},
        {4, argv[9], HITLS_APP_PASSWD_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PkeyMain(testData[i].argc, testData[i].argv);
        RestoreStdoutByFd(savedStdoutFd);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    STUB_RESTORE(BSL_UI_ReadPwdUtil);
    remove(PKEY_TEST_FILE_PATH);
    return;
}
/* END_CASE */

/**
 * @test   UT_HITLS_APP_PKEY_IN_FILE_SIZE_TC001
 * @title  Test the limit size of input key file.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_IN_FILE_SIZE_TC001(char *opts, int ret, char *outFile, Hex *expectOut)
{
    int argc = 0;
    char *argv[PKEY_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    PreProcArgs(tmp, &argc, argv);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(argc, argv), ret);
    if (ret == 0) {
        ASSERT_EQ(CompareOutByData(outFile, expectOut), HITLS_APP_SUCCESS);
    }

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
    // remove(outFile);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_STDIN_TC001
 * @spec  -
 * @title  Read PEM from standard input (without -in), should succeed
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_STDIN_TC001(char *keyPath)
{
    int savedStdinFd = dup(STDIN_FILENO);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    /* Redirect stdin to specified PEM file, simulating stdin reading of `cat file | ./hitls pkey` */
    ASSERT_NE(freopen(keyPath, "r", stdin), NULL);

    char *argv[] = {"pkey", NULL};
    int argc = 1;

    int ret = HITLS_PkeyMain(argc, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    (void)fflush(stdout);
    RestoreStdinByFd(savedStdinFd);
    if (savedStdinFd >= 0) {
        close(savedStdinFd);
    }
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

static int32_t RunPkeyWithOpts(char *opts)
{
    int argc = 0;
    char *argv[PKEY_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    if (tmp == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    PreProcArgs(tmp, &argc, argv);
    int32_t ret = HITLS_PkeyMain(argc, argv);
    BSL_SAL_Free(tmp);
    return ret;
}

static void TestPkeyOption(char *opts, int expect)
{
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(RunPkeyWithOpts(opts), expect);
    if (expect == HITLS_APP_SUCCESS) {
        struct stat fileStat = {0};
        ASSERT_EQ(stat(PKEY_TEST_FILE_PATH, &fileStat), 0);
        ASSERT_TRUE(fileStat.st_size > 0);
    }

EXIT:
    AppPrintErrorUioUnInit();
    remove(PKEY_TEST_FILE_PATH);
}

/**
 * @test UT_HITLS_APP_PKEY_PUBIN_TC001
 * @spec  -
 * @title Read a PEM public key and reject incompatible input or options.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_PUBIN_TC001(char *opts, int expect)
{
    TestPkeyOption(opts, expect);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_INFORM_TC001
 * @spec  -
 * @title Accept PEM or DER input and reject invalid or mismatched formats.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_INFORM_TC001(char *opts, int expect)
{
    TestPkeyOption(opts, expect);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_CHECK_TC001
 * @spec  -
 * @title Check valid private keys in PEM and DER formats.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_CHECK_TC001(char *opts, int expect)
{
    TestPkeyOption(opts, expect);
}
/* END_CASE */

static int32_t CRYPT_EAL_PkeyPairCheck_Mock(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey)
{
    (void)pubKey;
    (void)prvKey;
    return CRYPT_PAIRWISE_CHECK_FAIL;
}

/**
 * @test UT_HITLS_APP_PKEY_CHECK_TC002
 * @spec  -
 * @title Return an error when private-key consistency checking fails.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_CHECK_TC002(char *keyPath)
{
    char *argv[] = {"pkey", "-in", keyPath, "-check", "-out", PKEY_TEST_FILE_PATH};
    STUB_REPLACE(CRYPT_EAL_PkeyPairCheck, CRYPT_EAL_PkeyPairCheck_Mock);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(6, argv), HITLS_APP_CRYPTO_FAIL);

EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(CRYPT_EAL_PkeyPairCheck);
    remove(PKEY_TEST_FILE_PATH);
}
/* END_CASE */

static int32_t CRYPT_EAL_PkeyPairCheckNotSupport_Mock(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey)
{
    (void)pubKey;
    (void)prvKey;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
}

/**
 * @test UT_HITLS_APP_PKEY_CHECK_TC003
 * @spec  -
 * @title Report an unsupported private-key check separately from an invalid key.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_CHECK_TC003(char *keyPath)
{
    char *argv[] = {"pkey", "-in", keyPath, "-check", "-out", PKEY_TEST_FILE_PATH};
    STUB_REPLACE(CRYPT_EAL_PkeyPairCheck, CRYPT_EAL_PkeyPairCheckNotSupport_Mock);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(6, argv), HITLS_APP_INVALID_ARG);

EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(CRYPT_EAL_PkeyPairCheck);
    remove(PKEY_TEST_FILE_PATH);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_PRV_CODEC_TC001
 * @spec  -
 * @title Check and decode an unencrypted private key, then encode it as a reloadable PEM private key.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_PRV_CODEC_TC001(char *opts)
{
    char *argv[] = {"pkey", "-in", PKEY_TEST_FILE_PATH, "-out", PKEY_RELOAD_FILE_PATH};
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(RunPkeyWithOpts(opts), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(5, argv), HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    remove(PKEY_TEST_FILE_PATH);
    remove(PKEY_RELOAD_FILE_PATH);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_PUB_CODEC_TC001
 * @spec  -
 * @title Decode a public key and encode it as a reloadable PEM SubjectPublicKeyInfo.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_PUB_CODEC_TC001(char *opts)
{
    char *argv[] = {"pkey", "-pubin", "-in", PKEY_TEST_FILE_PATH, "-out", PKEY_RELOAD_FILE_PATH};
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(RunPkeyWithOpts(opts), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(6, argv), HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    remove(PKEY_TEST_FILE_PATH);
    remove(PKEY_RELOAD_FILE_PATH);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_DSA_TRAD_TC001
 * @spec  -
 * @title Decode traditional DSA private keys in PEM and DER formats.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_DSA_TRAD_TC001(char *opts, int expect)
{
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(RunPkeyWithOpts(opts), expect);
    if (expect == HITLS_APP_SUCCESS) {
        ASSERT_EQ(RunPkeyWithOpts("pkey -in out_test.pem -noout"), HITLS_APP_SUCCESS);
    }

EXIT:
    AppPrintErrorUioUnInit();
    remove(PKEY_TEST_FILE_PATH);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_NOOUT_TC001
 * @spec  -
 * @title Do not modify an existing output file when -noout is specified without -text.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_NOOUT_TC001(char *opts)
{
    char output[4096] = {0};
    const char originalOutput[] = "existing output\n";
    FILE *fp = NULL;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    (void)remove(PKEY_TEST_FILE_PATH);
    fp = fopen(PKEY_TEST_FILE_PATH, "w");
    ASSERT_NE(fp, NULL);
    ASSERT_EQ(fwrite(originalOutput, 1, sizeof(originalOutput) - 1, fp), sizeof(originalOutput) - 1);
    fclose(fp);
    fp = NULL;
    ASSERT_EQ(RunPkeyWithOpts(opts), HITLS_APP_SUCCESS);
    fp = fopen(PKEY_TEST_FILE_PATH, "r");
    ASSERT_NE(fp, NULL);
    ASSERT_EQ(fread(output, 1, sizeof(output) - 1, fp), sizeof(originalOutput) - 1);
    ASSERT_TRUE(strcmp(output, originalOutput) == 0);

EXIT:
    if (fp != NULL) {
        fclose(fp);
    }
    (void)remove(PKEY_TEST_FILE_PATH);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKEY_PUB_OUTPUT_TC001
 * @spec  -
 * @title Honor -text and -noout when outputting a public key.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKEY_PUB_OUTPUT_TC001(char *opts, int expectPem)
{
    char output[4096] = {0};
    FILE *fp = NULL;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    (void)remove(PKEY_TEST_FILE_PATH);
    ASSERT_EQ(RunPkeyWithOpts(opts), HITLS_APP_SUCCESS);
    fp = fopen(PKEY_TEST_FILE_PATH, "r");
    ASSERT_NE(fp, NULL);
    ASSERT_TRUE(fread(output, 1, sizeof(output) - 1, fp) > 0);
    ASSERT_TRUE(strstr(output, "Public-Key:") != NULL);
    ASSERT_EQ(strstr(output, "-----BEGIN PUBLIC KEY-----") != NULL, expectPem);

EXIT:
    if (fp != NULL) {
        fclose(fp);
    }
    (void)remove(PKEY_TEST_FILE_PATH);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
