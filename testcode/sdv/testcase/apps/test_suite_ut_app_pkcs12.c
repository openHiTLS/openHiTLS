
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
#include "crypt_eal_rand.h"
#include "app_errno.h"
#include "bsl_base64.h"
#include "crypt_errno.h"
#include "app_pkcs12.h"
#include "app_function.h"
#include "securec.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "bsl_ui.h"
#include "stub_replace.h"

/* END_HEADER */

#define PRI_KEY "../testdata/apps/pkcs12/server.key"
#define CERT "../testdata/apps/pkcs12/server.crt"
#define CHAIN "../testdata/apps/pkcs12/chain.crt"
#define NO_EXIST_FILE "noexistfile"
#define LARGE_FILE "../testdata/apps/x509/257k.pem"
#define EMPTY_FILE "../testdata/apps/pkcs12/empty.pem"
#define PFX "../testdata/apps/pkcs12/out.pfx"
#define NO_MACP12 "../testdata/apps/pkcs12/nomac.p12"
#define MIN_PASSWD "pass:12345678"
#define MAX_PASSWD                                                                                                     \
    "pass:"                                                                                                            \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111"
#define SHORT_PASSWD "pass:"
#define LONG_PASSWD                                                                                                    \
    "pass:"                                                                                                            \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" \
    "11111111111111111"
#define FILE_PASSWD "file:../testdata/apps/pkcs12/pass.txt"
#define PARAM_PASSWD "pass:12345678"

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_pkcs12.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */

/**
 * @test UT_HITLS_APP_PKCS12_TC001
 * @spec  -
 * @title   test UT_HITLS_APP_PKCS12_TC001 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC001(void)
{
    char *argv[][16] = {
        {"pkcs12", "-help"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile", CHAIN,
            "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", "pass:12345678", "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", "pass:12345678", "-out", "decode_pfx.pem", "-clcerts", "-aes256-cbc"},
        {"pkcs12", "-in", NO_MACP12, "-passin", "pass:12345678", "-passout", "pass:12345678", "-out", "decode_pfx.pem", "-clcerts", "-aes256-cbc"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", FILE_PASSWD, "-chain", "-CAfile", CHAIN,
            "-passout", FILE_PASSWD, "-out", "out.pfx"},
        {"pkcs12", "-in", "out.pfx", "-passin", FILE_PASSWD, "-passout", FILE_PASSWD, "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", "out.pfx", "-passin", PARAM_PASSWD, "-passout", PARAM_PASSWD, "-out", "decode_pfx.pem"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
        {15, argv[1], HITLS_APP_SUCCESS},
        {9, argv[2], HITLS_APP_SUCCESS},
        {11, argv[3], HITLS_APP_SUCCESS},
        {11, argv[4], HITLS_APP_SUCCESS},
        {15, argv[5], HITLS_APP_SUCCESS},
        {9, argv[6], HITLS_APP_SUCCESS},
        {9, argv[7], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC002
 * @spec  -
 * @title   test UT_HITLS_APP_PKCS12_TC002 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC002(void)
{
    char *argv[][16] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", SHORT_PASSWD, "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", LONG_PASSWD, "-out", "out.pfx"},
        {"pkcs12", "-in", PFX, "-passin", SHORT_PASSWD, "-passout", "pass:12345678", "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", SHORT_PASSWD, "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", LONG_PASSWD, "-passout", "pass:12345678", "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", LONG_PASSWD, "-out", "decode_pfx.pem"},

        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", MIN_PASSWD, "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", MAX_PASSWD, "-out", "out.pfx"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", MIN_PASSWD, "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", MAX_PASSWD, "-out", "decode_pfx.pem"},
    };

    OptTestData testData[] = {
        {13, argv[0], HITLS_APP_SUCCESS},
        {13, argv[1], HITLS_APP_PASSWD_FAIL},
        {13, argv[2], HITLS_APP_SUCCESS},
        {13, argv[3], HITLS_APP_PASSWD_FAIL},
        {9, argv[4], HITLS_APP_PASSWD_FAIL},
        {9, argv[5], HITLS_APP_PASSWD_FAIL},
        {9, argv[6], HITLS_APP_PASSWD_FAIL},
        {9, argv[7], HITLS_APP_PASSWD_FAIL},
        {13, argv[8], HITLS_APP_SUCCESS},
        {13, argv[9], HITLS_APP_SUCCESS},
        {9, argv[10], HITLS_APP_SUCCESS},
        {9, argv[11], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC003
 * @spec  -
 * @title   Test UT_HITLS_APP_PKCS12_TC003 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC003(void)
{
    char *argv[][16] = {
        {"pkcs12", "-export", "-in", NO_EXIST_FILE, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", NO_EXIST_FILE, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            NO_EXIST_FILE, "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-in", NO_EXIST_FILE, "-passin", "pass:12345678", "-passout", "pass:12345678", "-out", "decode.pem"},

        {"pkcs12", "-export", "-in", EMPTY_FILE, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", EMPTY_FILE, "-passin", "pass:12345678", "-chain", "-CAfile", CHAIN,
            "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            EMPTY_FILE, "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-in", EMPTY_FILE, "-passin", "pass:12345678", "-passout", "pass:12345678", "-out", "decode.pem"},

        {"pkcs12", "-export", "-in", LARGE_FILE, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", LARGE_FILE, "-passin", "pass:12345678", "-chain", "-CAfile", CHAIN,
            "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            LARGE_FILE, "-passout", "pass:12345678", "-out", "out.pfx"},
    };

    OptTestData testData[] = {
        {15, argv[0], HITLS_APP_BSL_FAIL},
        {15, argv[1], HITLS_APP_BSL_FAIL},
        {15, argv[2], HITLS_APP_BSL_FAIL},
        {9, argv[3], HITLS_APP_BSL_FAIL},
        {15, argv[4], HITLS_APP_X509_FAIL},
        {15, argv[5], HITLS_APP_LOAD_KEY_FAIL},
        {15, argv[6], HITLS_APP_X509_FAIL},
        {9, argv[7], HITLS_APP_X509_FAIL},
        {15, argv[8], HITLS_APP_UIO_FAIL},
        {15, argv[9], HITLS_APP_UIO_FAIL},
        {15, argv[10], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC004
 * @spec  -
 * @title   Test UT_HITLS_APP_PKCS12_TC004 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC004(void)
{
    char *argv[][18] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-keypbe", "PBE-SHA1-RC4-128"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-keypbe", "PBE-SHA1-RC4-40"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-keypbe", "PBE-SHA1-RC2-128"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-keypbe", "PBE-SHA1-3DES"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-keypbe", "PBES2"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-keypbe", "INVALID_ALG"},
    };

    OptTestData testData[] = {
        {17, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[1], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[3], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[4], HITLS_APP_SUCCESS},
        {17, argv[5], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC005
 * @spec  -
 * @title   Test UT_HITLS_APP_PKCS12_TC005 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC005(void)
{
    char *argv[][18] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-certpbe", "PBE-SHA1-RC4-128"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-certpbe", "PBE-SHA1-RC4-40"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-certpbe", "PBE-SHA1-RC2-128"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-certpbe", "PBE-SHA1-3DES"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-certpbe", "PBES2"},
    };

    OptTestData testData[] = {
        {17, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[1], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[3], HITLS_APP_OPT_VALUE_INVALID},
        {17, argv[4], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC006
 * @spec  -
 * @title   Test UT_HITLS_APP_PKCS12_TC006 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC006(void)
{
    char *argv[][18] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-macalg", "sha224"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-macalg", "INVALID_ALG"},
    };

    OptTestData testData[] = {
        {17, argv[0], HITLS_APP_SUCCESS},
        {17, argv[1], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC007
 * @spec  -
 * @title   Test UT_HITLS_APP_PKCS12_TC007 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC007(void)
{
    char invalidName[2048] = {0};
    (void)memset_s(invalidName, sizeof(invalidName) - 1, 'a', sizeof(invalidName) - 1);
    char *argv[][18] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-name", "testname"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-name"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-name", invalidName},
    };

    OptTestData testData[] = {
        {17, argv[0], HITLS_APP_SUCCESS},
        {16, argv[1], HITLS_APP_OPT_UNKOWN},
        {17, argv[2], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC008
 * @spec  -
 * @title   Test UT_HITLS_APP_PKCS12_TC008 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC008(void)
{
    char *validPwd = "file:../testdata/apps/pass/size_1024_pass";
    char *invalidPwd = "file:../testdata/apps/pass/size_1025_pass";
    char *emptyPwd = "file:../testdata/apps/pass/empty_pass";
    char *argv[][18] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", validPwd, "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", invalidPwd, "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", emptyPwd, "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "file:noexistfile", "-out", "out.pfx"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", validPwd, "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", invalidPwd, "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", emptyPwd, "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", "file:noexistfile", "-out", "decode_pfx.pem"},
    };

    OptTestData testData[] = {
        {15, argv[0], HITLS_APP_SUCCESS},
        {15, argv[1], HITLS_APP_PASSWD_FAIL},
        {15, argv[2], HITLS_APP_PASSWD_FAIL},
        {15, argv[3], HITLS_APP_PASSWD_FAIL},
        {9, argv[4], HITLS_APP_SUCCESS},
        {9, argv[5], HITLS_APP_PASSWD_FAIL},
        {9, argv[6], HITLS_APP_PASSWD_FAIL},
        {9, argv[7], HITLS_APP_PASSWD_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

static int32_t BSL_UI_ReadPwdUtil_Mock(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    (void)memcpy_s(buff, *buffLen, "12345678", strlen("12345678"));
    *buffLen = strlen("12345678") + 1;
    return HITLS_APP_SUCCESS;
}

/**
 * @test UT_HITLS_APP_PKCS12_TC009
 * @spec  -
 * @title   Test UT_HITLS_APP_PKCS12_TC009 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC009(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdUtil_Mock);
    char *argv[][18] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-out", "out.pfx"},
        {"pkcs12", "-in", PFX, "-passout", "pass:12345678", "-out", "decode_pfx.pem"},
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-out", "decode_pfx.pem"},
    };

    OptTestData testData[] = {
        {13, argv[0], HITLS_APP_SUCCESS},
        {13, argv[1], HITLS_APP_SUCCESS},
        {7, argv[2], HITLS_APP_SUCCESS},
        {7, argv[3], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

static void SplitArgs(char *str, char **result, int *count) {
    char *token;
    token = strtok(str, " ");
    while (token != NULL) {
        result[*count] = token;
        (*count)++;
        token = strtok(NULL, " ");
    }
}

/**
 * @test UT_HITLS_APP_PKCS12_TC010
 * @spec  -
 * @title   Test HITLS_PKCS12Main function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC010(char *arg, int expect)
{
    char *argv[30] = {};
    int argc = 0;
    SplitArgs(arg, argv, &argc);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = HITLS_PKCS12Main(argc, argv);
    fflush(stdout);
    freopen("/dev/tty", "w", stdout);
    ASSERT_EQ(ret, expect);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_RandInit(
    CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    const uint8_t *pers, uint32_t persLen, BSL_Param *param)
{
    (void)libCtx;
    (void)algId;
    (void)attrName;
    (void)pers;
    (void)persLen;
    (void)param;
    return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
}

/**
 * @test UT_HITLS_APP_PKCS12_TC011
 * @spec  -
 * @title   Test HITLS_PKCS12Main function init rand failed
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC011(char *arg, int expect)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit);
    char *argv[30] = {};
    int argc = 0;
    SplitArgs(arg, argv, &argc);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = HITLS_PKCS12Main(argc, argv);
    fflush(stdout);
    freopen("/dev/tty", "w", stdout);
    ASSERT_EQ(ret, expect);

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */
 
/**
 * @test UT_HITLS_APP_PKCS12_TC012
 * @spec  -
 * @title   Test HITLS_PKCS12Main function file pass
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC012(char *passFile, char *passArg, int expect)
{
    char *argv[][16] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", passFile, "-out", "out.pfx"},
        {"pkcs12", "-in", "out.pfx", "-passin", passArg, "-passout", passArg, "-out", "decode_pfx.pem"},
    };
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int32_t ret = HITLS_PKCS12Main(13, argv[0]);
    ASSERT_EQ(ret, expect);
    if (expect == HITLS_APP_SUCCESS) {
        ASSERT_EQ(HITLS_PKCS12Main(9, argv[1]), expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */