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
#include "securec.h"
#include <stddef.h>
#include "app_genrsa.h"
#include "app_rsa.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_utils.h"
#include "bsl_uio.h"
#include "stub_utils.h"

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_genrsa.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_APP_Passwd, char *, int32_t, int32_t);


#define BSL_SUCCESS 0

typedef struct {
    int argc;
    char **argv;
    int expect;
} GenrsaTestData;

int32_t STUB_HITLS_APP_Passwd(char *buf, int32_t bufMaxLen, int32_t flag)
{
    (void)flag;
    (void)memcpy_s(buf, bufMaxLen, "12345678", 8);
    return 8;
}

/**
 * @test UT_HITLS_APP_genrsa_TC001
 * @spec  -
 * @title   test UT_HITLS_APP_genrsa_TC001 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_genrsa_TC001(void)
{
    STUB_REPLACE(HITLS_APP_Passwd, STUB_HITLS_APP_Passwd);;
    char *argv[][10] = {
        {"genrsa", "-help"},
        {"genrsa", "-cipher", "aes128_cbc", "1024"},
        {"genrsa", "-cipher", "aes128_ctr", "-out", "GenrsaOutFile_1", "2048"},
        {"genrsa", "-cipher", "aes128_xts", "-out", "GenrsaOutFile_2", "3072"},
        {"genrsa", "-cipher", "sm4_cfb", "-out", "GenrsaOutFile_3", "4096"},
        {"genrsa", "-cipher", "rc2_ofb", "-out", "GenrsaOutFile_4", "1024"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_5", "1024"},
        {"genrsa", "-cipher", "aes666_cbc", "3072"},
        {"genrsa", "-cipher", "aes128_cbc", "1234"}
    };

    GenrsaTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
        {4, argv[1], HITLS_APP_SUCCESS},
        {6, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {6, argv[3], HITLS_APP_SUCCESS},
        {6, argv[4], HITLS_APP_SUCCESS},
        {6, argv[5], HITLS_APP_OPT_VALUE_INVALID},
        {6, argv[6], HITLS_APP_SUCCESS},
        {4, argv[7], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[8], HITLS_APP_OPT_VALUE_INVALID}
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(GenrsaTestData)); ++i) {
        int ret = HITLS_GenRSAMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_Passwd);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_genrsa_TC002(void)
{
    STUB_REPLACE(HITLS_APP_Passwd, STUB_HITLS_APP_Passwd);;
    char *argv[][10] = {
        {"",       "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "2048"},
        {"genrsa", "",        "aes128_cbc", "-out", "GenrsaOutFile_1", "2048"},
        {"genrsa", "-cipher", "",           "-out", "GenrsaOutFile_1", "2048"},
        {"genrsa", "-cipher", "aes128_cbc", "",     "GenrsaOutFile_1", "2048"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "",                "2048"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", ""},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[0]), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[1]), HITLS_APP_OPT_UNKOWN);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[2]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[3]), HITLS_APP_OPT_UNKOWN);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[4]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[5]), HITLS_APP_OPT_VALUE_INVALID);
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_Passwd);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_genrsa_TC003(void)
{
    STUB_REPLACE(HITLS_APP_Passwd, STUB_HITLS_APP_Passwd);;
    char *argv[][10] = {
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "2048"},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_GenRSAMain(5, argv[0]), HITLS_APP_OPT_UNKOWN);
    ASSERT_EQ(HITLS_GenRSAMain(7, argv[0]), HITLS_APP_OPT_UNKOWN);
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_Passwd);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_genrsa_TC004(void)
{
    STUB_REPLACE(HITLS_APP_Passwd, STUB_HITLS_APP_Passwd);;
    char *argv[][10] = {
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "1023"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "1025"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "2047"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "2049"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "3071"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "3073"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "4095"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "4097"},
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile_1", "abcdefgh"},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[0]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[1]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[2]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[3]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[4]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[5]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[6]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[7]), HITLS_APP_OPT_VALUE_INVALID);
    ASSERT_EQ(HITLS_GenRSAMain(6, argv[8]), HITLS_APP_OPT_VALUE_INVALID);
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_Passwd);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_genrsa_TC005(void)
{
    STUB_REPLACE(HITLS_APP_Passwd, STUB_HITLS_APP_Passwd);;
    char *argv[][10] = {
        {"genrsa", "-cipher", "aes128_cbc", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes192_cbc", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes256_cbc", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes128_xts", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes256_xts", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "sm4_xts", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "sm4_cbc", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "sm4_ctr", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "sm4_cfb", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "sm4_ofb", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes128_cfb", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes192_cfb", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes256_cfb", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes128_ofb", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes192_ofb", "-out", "GenrsaOutFile", "1024"},
        {"genrsa", "-cipher", "aes256_ofb", "-out", "GenrsaOutFile", "1024"},
    };
    char *rsaArg[][10] = {
        {"rsa", "-in", "GenrsaOutFile", "-noout"},
    };
    int32_t ret;
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (uint32_t i = 0; i < sizeof(argv) / sizeof(argv[0]); i++) {
        ret = HITLS_GenRSAMain(6, argv[i]);
        ASSERT_EQ(ret, HITLS_APP_SUCCESS);
        ret = HITLS_RsaMain(4, rsaArg[0]);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_Passwd);
    return;
}
/* END_CASE */