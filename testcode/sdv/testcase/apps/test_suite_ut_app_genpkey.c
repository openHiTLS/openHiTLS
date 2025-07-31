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
#include "app_opt.h"
#include "app_print.h"
#include "bsl_uio.h"
#include "uio_abstraction.h"
#include "app_errno.h"
#include "crypt_errno.h"
#include "app_genpkey.h"
#include "app_function.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "stub_replace.h"

/* END_HEADER */

#define GENPKEY_TEST_FILE_PATH "out_test.pem"
#define GENPKEY_TEST_DIR_PATH "./genpkey_dir"

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_genpkey.c
    ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */

/**
 * @test UT_HITLS_APP_GENPKEY_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_GENPKEY_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_GENPKEY_TC001()
{
    printf("UT_HITLS_APP_GENPKEY_TC001----start----------------------------------------------------------------------------------------------------------------------\n");
    char *argv[][20] = {
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-224"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolp256r1"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolp384r1"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolp512r1"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:sm2"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:sm2", "-out", GENPKEY_TEST_FILE_PATH},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:sm2", "-aes256-cbc", "-pass", "pass:123456"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:sm2", "-aes256-cbc", "-pass", "pass:123456", "-out", GENPKEY_TEST_FILE_PATH},
        {"genpkey", "-algorithm", "RSA"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", "out_test.pem"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-aes256-cbc", "-pass", "pass:123456"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-aes256-cbc", "-pass", "pass:123456", "-out", GENPKEY_TEST_FILE_PATH},
    };

    OptTestData testData[] = {
        {5, argv[0], HITLS_APP_SUCCESS},
        {5, argv[1], HITLS_APP_SUCCESS},
        {5, argv[2], HITLS_APP_SUCCESS},
        {5, argv[3], HITLS_APP_SUCCESS},
        {5, argv[4], HITLS_APP_SUCCESS},
        {5, argv[5], HITLS_APP_SUCCESS},
        {5, argv[6], HITLS_APP_SUCCESS},
        {5, argv[7], HITLS_APP_SUCCESS},
        {7, argv[8], HITLS_APP_SUCCESS},
        {8, argv[9], HITLS_APP_SUCCESS},
        {10, argv[10], HITLS_APP_SUCCESS},
        {3, argv[11], HITLS_APP_SUCCESS},
        {5, argv[12], HITLS_APP_SUCCESS},
        {5, argv[13], HITLS_APP_SUCCESS},
        {5, argv[14], HITLS_APP_SUCCESS},
        {5, argv[15], HITLS_APP_SUCCESS},
        {7, argv[16], HITLS_APP_SUCCESS},
        {8, argv[17], HITLS_APP_SUCCESS},
        {10, argv[18], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_GenPkeyMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        if (ret != testData[i].expect) {
            printf("ret: %d, i: %d ---------------------------------------------------------------------------------------------------------------------\n", ret, i);
        } else {
            printf("success, i: %d ---------------------------------------------------------------------------------------------------------------------\n", i);
        }
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    remove(GENPKEY_TEST_FILE_PATH);
    printf("UT_HITLS_APP_GENPKEY_TC001----end----------------------------------------------------------------------------------------------------------------------\n");
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_GENPKEY_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_GENPKEY_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_GENPKEY_TC002()
{
    printf("UT_HITLS_APP_GENPKEY_TC002----start----------------------------------------------------------------------------------------------------------------------\n");
    mkdir(GENPKEY_TEST_DIR_PATH, 0775);
    char *argv[][20] = {
        {"genpkey", "-ttt"},
        {"genpkey", "-algorithm", "ttt"},
        {"genpkey", "-algorithm", "RSA", "-pass", "err:12"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "ec_paramgen_curve:sm2"},
        {"genpkey", "-algorithm", "RSA", "-pkeyopt", "ttt"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "rsa_keygen_bits:1024"},
        {"genpkey", "-algorithm", "EC", "-pkeyopt", "ttt"},
        {"genpkey", "-algorithm", "RSA", "-aes256-cbc", "-pass", "pass:"},
        {"genpkey", "-algorithm", "RSA", "-out", GENPKEY_TEST_DIR_PATH},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_OPT_UNKOWN},
        {3, argv[1], HITLS_APP_INVALID_ARG},
        {5, argv[2], HITLS_APP_PASSWD_FAIL},
        {5, argv[3], HITLS_APP_INVALID_ARG},
        {5, argv[4], HITLS_APP_INVALID_ARG},
        {5, argv[5], HITLS_APP_INVALID_ARG},
        {5, argv[6], HITLS_APP_INVALID_ARG},
        {6, argv[7], HITLS_APP_PASSWD_FAIL},
        {5, argv[8], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_GenPkeyMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        if (ret != testData[i].expect) {
            printf("ret: %d, i: %d ---------------------------------------------------------------------------------------------------------------------\n", ret, i);
        } else {
            printf("success, i: %d ---------------------------------------------------------------------------------------------------------------------\n", i);
        }
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    rmdir(GENPKEY_TEST_DIR_PATH);
    remove(GENPKEY_TEST_FILE_PATH);
    printf("UT_HITLS_APP_GENPKEY_TC002----end----------------------------------------------------------------------------------------------------------------------\n");
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_GENPKEY_TC003
 * @spec  -
 * @title   测试UT_HITLS_APP_GENPKEY_TC003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_GENPKEY_TC003(char *cipherOpt)
{
    printf("UT_HITLS_APP_GENPKEY_TC003----start----------------------------------------------------------------------------------------------------------------------\n");
    mkdir(GENPKEY_TEST_DIR_PATH, 0775);
    char *argv[][20] = {
        {"genpkey", "-algorithm", "RSA", cipherOpt, "-pass", "pass:123456"},
    };

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_GenPkeyMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        if (ret != testData[i].expect) {
            printf("ret: %d, i: %d ---------------------------------------------------------------------------------------------------------------------\n", ret, i);
        } else {
            printf("success, i: %d ---------------------------------------------------------------------------------------------------------------------\n", i);
        }
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    rmdir(GENPKEY_TEST_DIR_PATH);
    remove(GENPKEY_TEST_FILE_PATH);
    printf("UT_HITLS_APP_GENPKEY_TC003----end----------------------------------------------------------------------------------------------------------------------\n");
    return;
}
/* END_CASE */