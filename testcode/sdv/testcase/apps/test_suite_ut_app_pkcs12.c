
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
#include <string.h>
#include "bsl_err.h"
#include "bsl_sal.h"
#include "bsl_ui.h"
#include "stub_utils.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET5(int32_t, BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdParam *, char *, uint32_t *, const BSL_UI_CheckDataCallBack, void *);
STUB_DEFINE_RET6(int32_t, CRYPT_EAL_ProviderRandInitCtx, CRYPT_EAL_LibCtx *, int32_t, const char *, const uint8_t *, uint32_t, BSL_Param *);


#define PRI_KEY "../testdata/apps/pkcs12/server.key"
#define CERT "../testdata/apps/pkcs12/server.crt"
#define CHAIN "../testdata/apps/pkcs12/chain.crt"
#define NO_EXIST_FILE "noexistfile"
#define LARGE_FILE "../testdata/apps/x509/257k.pem"
#define EMPTY_FILE "../testdata/apps/pkcs12/empty.pem"
#define PFX "../testdata/apps/pkcs12/out.pfx"
#define NO_MACP12 "../testdata/apps/pkcs12/nomac.p12"
#define CERT_ONLY_P12 "../testdata/apps/pkcs12/cert_only.p12"
#define NOOUT_FILE "noout.pem"
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
        {"pkcs12", "-in", PFX, "-passin", "pass:12345678", "-passout", "pass:12345678", "-out", "decode_pfx.pem", "-clcerts", "-aes256_cbc"},
        {"pkcs12", "-in", NO_MACP12, "-passin", "pass:12345678", "-passout", "pass:12345678", "-out", "decode_pfx.pem", "-clcerts", "-aes256_cbc"},
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
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-macalg", "sha512"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passin", "pass:12345678", "-chain", "-CAfile",
            CHAIN, "-passout", "pass:12345678", "-out", "out.pfx", "-macalg", "INVALID_ALG"},
        {"pkcs12", "-in", "out.pfx", "-passin", "pass:12345678", "-passout", "pass:12345678", "-out",
            "decode_pfx.pem"},
    };

    OptTestData testData[] = {
        {17, argv[0], HITLS_APP_SUCCESS},
        {17, argv[1], HITLS_APP_SUCCESS},
        {17, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {9, argv[3], HITLS_APP_SUCCESS},
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
    memset(invalidName, 'a', sizeof(invalidName) - 1);
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
    memcpy(buff, "12345678", strlen("12345678"));
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
    STUB_REPLACE(BSL_UI_ReadPwdUtil, BSL_UI_ReadPwdUtil_Mock);;
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
#ifdef HITLS_CRYPTO_CMVP_SM_ARMV8_LE
    (void)arg;
    (void)expect;
    SKIP_TEST();
#else
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_RandInit);;
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
    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
    return;
#endif
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

/**
 * @test UT_HITLS_APP_PKCS12_TC013
 * @spec  -
 * @title   Test macsaltlen/iter export and nomacver/nokeys/nocerts/noout import options
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC013(void)
{
    char *argv[][18] = {
        /* export with custom macsaltlen/iter */
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-chain", "-CAfile", CHAIN,
            "-passout", MIN_PASSWD, "-out", "out_new.pfx", "-macsaltlen", "32", "-iter", "4096"},
        /* parse with the new import options */
        {"pkcs12", "-in", "out_new.pfx", "-passin", MIN_PASSWD, "-nomacver", "-noout"},
        {"pkcs12", "-in", "out_new.pfx", "-passin", MIN_PASSWD, "-nokeys", "-out", "nokeys.pem"},
        {"pkcs12", "-in", "out_new.pfx", "-passin", MIN_PASSWD, "-passout", MIN_PASSWD, "-nocerts",
            "-out", "nocerts.pem"},
        {"pkcs12", "-in", "out_new.pfx", "-passin", MIN_PASSWD, "-noout"},
        {"pkcs12", "-in", "out_new.pfx", "-passin", MIN_PASSWD, "-nodes", "-out", "nodes.pem"},
        /* options used in the wrong mode are ignored with a warning */
        {"pkcs12", "-in", "out_new.pfx", "-passin", MIN_PASSWD, "-noout", "-macsaltlen", "32"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_new.pfx", "-nokeys"},
    };

    OptTestData testData[] = {
        {17, argv[0], HITLS_APP_SUCCESS},
        {7, argv[1], HITLS_APP_SUCCESS},
        {8, argv[2], HITLS_APP_SUCCESS},
        {10, argv[3], HITLS_APP_SUCCESS},
        {6, argv[4], HITLS_APP_SUCCESS},
        {8, argv[5], HITLS_APP_SUCCESS},
        {8, argv[6], HITLS_APP_SUCCESS},
        {11, argv[7], HITLS_APP_SUCCESS},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    (void)remove("out_new.pfx");
    (void)remove("nokeys.pem");
    (void)remove("nocerts.pem");
    (void)remove("nodes.pem");

    ASSERT_EQ(HITLS_PKCS12Main(testData[0].argc, testData[0].argv), HITLS_APP_SUCCESS);

    for (int i = 1; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    (void)remove("out_new.pfx");
    (void)remove("nokeys.pem");
    (void)remove("nocerts.pem");
    (void)remove("nodes.pem");
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC014
 * @spec  -
 * @title   Test invalid macsaltlen and iter parameters
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC014(void)
{
    char *argv[][12] = {
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_err.pfx",
            "-macsaltlen", "0"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_err.pfx",
            "-macsaltlen", "1025"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_err.pfx",
            "-macsaltlen", "abc"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_err.pfx",
            "-iter", "0"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_err.pfx",
            "-iter", "999"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_err.pfx",
            "-iter", "2147483648"},
        {"pkcs12", "-export", "-in", CERT, "-inkey", PRI_KEY, "-passout", MIN_PASSWD, "-out", "out_err.pfx",
            "-iter", "abc"},
    };

    OptTestData testData[] = {
        {12, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[1], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[3], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[4], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[5], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[6], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_PKCS12Main(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    (void)remove("out_err.pfx");
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC015
 * @spec  -
 * @title   Test -nokeys with a certificate-only PKCS#12 file
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC015(void)
{
    char *argv[] = {"pkcs12", "-in", CERT_ONLY_P12, "-passin", MIN_PASSWD, "-nokeys", "-out", "cert_only.pem"};
    char output[2048] = {0};
    FILE *fp = NULL;

    (void)remove("cert_only.pem");
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12Main(8, argv), HITLS_APP_SUCCESS);
    fp = fopen("cert_only.pem", "r");
    ASSERT_NE(fp, NULL);
    ASSERT_TRUE(fread(output, 1, sizeof(output) - 1, fp) > 0);
    ASSERT_TRUE(strstr(output, "-----BEGIN CERTIFICATE-----") != NULL);

EXIT:
    if (fp != NULL) {
        fclose(fp);
    }
    (void)remove("cert_only.pem");
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_PKCS12_TC016
 * @spec  -
 * @title   Test -noout does not truncate an existing output file
 */
/* BEGIN_CASE */
void UT_HITLS_APP_PKCS12_TC016(void)
{
    char *argv[] = {"pkcs12", "-in", PFX, "-passin", MIN_PASSWD, "-noout", "-out", NOOUT_FILE};
    const char expected[] = "keep existing content";
    char output[sizeof(expected)] = {0};
    uint32_t writeLen = 0;
    size_t readLen = 0;
    BSL_UIO *wUio = NULL;
    FILE *fp = NULL;

    (void)remove(NOOUT_FILE);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    wUio = HITLS_APP_UioOpenPrivate(NOOUT_FILE, 'w');
    ASSERT_NE(wUio, NULL);
    ASSERT_EQ(BSL_UIO_Write(wUio, expected, sizeof(expected) - 1, &writeLen), BSL_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(expected) - 1);
    BSL_UIO_Free(wUio);
    wUio = NULL;

    ASSERT_EQ(HITLS_PKCS12Main(8, argv), HITLS_APP_SUCCESS);
    fp = fopen(NOOUT_FILE, "r");
    ASSERT_NE(fp, NULL);
    readLen = fread(output, 1, sizeof(output), fp);
    ASSERT_EQ(readLen, sizeof(expected) - 1);
    ASSERT_EQ(memcmp(output, expected, sizeof(expected) - 1), 0);

EXIT:
    if (fp != NULL) {
        fclose(fp);
    }
    BSL_UIO_Free(wUio);
    (void)remove(NOOUT_FILE);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
