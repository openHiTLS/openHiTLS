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
#include <stddef.h>
#include "app_enc.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_provider.h"
#include "bsl_uio.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "eal_cipher_local.h"
#include "bsl_errno.h"

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_enc.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */
/* END_HEADER */

typedef struct {
    uint16_t version;

} ResumeTestInfo;

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

static int32_t AppInit(void)
{
    int32_t ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (APP_Create_LibCtx() == NULL) {
        (void)AppPrintError("Create g_libCtx failed\n");
        return HITLS_APP_INVALID_ARG;
    }
    return HITLS_APP_SUCCESS;
}

static void AppUninit(void)
{
    AppPrintErrorUioUnInit();
    HITLS_APP_FreeLibCtx();
}

/**
 * @test UT_HITLS_APP_ENC_TC001
 * @spec  -
 * @title  测试命令行二级命令enc正常场景
 */

/* BEGIN_CASE */
void UT_HITLS_APP_ENC_TC001(void)
{
    char *argv[][13] = {
        {"enc", "-enc", "-cipher", "aes128_cbc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-enc", "-cipher", "aes128_cbc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "file:../testdata/apps/pass/size_1024_pass", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-enc", "-cipher", "aes128_cbc", "-md", "sha1", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-enc", "-cipher", "aes128_cbc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "file:../testdata/apps/enc/enter_pass_file", "-out", "../testdata/apps/enc/res_encfile"}
    };

    OptTestData testData[] = {
        {10, argv[0], HITLS_APP_SUCCESS},
        {10, argv[1], HITLS_APP_SUCCESS},
        {12, argv[2], HITLS_APP_SUCCESS},
        {10, argv[3], HITLS_APP_SUCCESS}
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_EncMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
    
EXIT:
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ENC_TC002
 * @spec  -
 * @title  测试命令行二级命令enc不同对称加解密算法的加解密流程
 */

/* BEGIN_CASE */
void UT_HITLS_APP_ENC_TC002(void)
{
    char *argv[][11] = {
        {"enc", "-enc", "-cipher", "aes128_cbc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "res_tmpfile"},
        {"enc", "-dec", "-cipher", "aes128_cbc", "-in", "res_tmpfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_decfile"},
        {"enc", "-enc", "-cipher", "aes128_ctr", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-dec", "-cipher", "aes128_ctr", "-in", "../testdata/apps/enc/res_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_decfile"},
        {"enc", "-enc", "-cipher", "aes128_ecb", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-dec", "-cipher", "aes128_ecb", "-in", "../testdata/apps/enc/res_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_decfile"},
        {"enc", "-enc", "-cipher", "aes128_xts", "-in", "../testdata/apps/enc/test_xts_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-dec", "-cipher", "aes128_xts", "-in", "../testdata/apps/enc/res_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_decfile"},
        {"enc", "-enc", "-cipher", "aes128_gcm", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-dec", "-cipher", "aes128_gcm", "-in", "../testdata/apps/enc/res_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_decfile"},
        {"enc", "-enc", "-cipher", "chacha20_poly1305", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-dec", "-cipher", "chacha20_poly1305", "-in", "../testdata/apps/enc/res_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_decfile"},
        {"enc", "-enc", "-cipher", "sm4_cfb", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-dec", "-cipher", "sm4_cfb", "-in", "../testdata/apps/enc/res_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_decfile"}
    };

    OptTestData testData[] = {
        {10, argv[0], HITLS_APP_SUCCESS},
        {10, argv[1], HITLS_APP_SUCCESS},
        {10, argv[2], HITLS_APP_SUCCESS},
        {10, argv[3], HITLS_APP_SUCCESS},
        {10, argv[4], HITLS_APP_SUCCESS},
        {10, argv[5], HITLS_APP_SUCCESS},
        {10, argv[6], HITLS_APP_SUCCESS},
        {10, argv[7], HITLS_APP_SUCCESS},
        {10, argv[8], HITLS_APP_SUCCESS},
        {10, argv[9], HITLS_APP_SUCCESS},
        {10, argv[10], HITLS_APP_SUCCESS},
        {10, argv[11], HITLS_APP_SUCCESS},
        {10, argv[12], HITLS_APP_SUCCESS},
        {10, argv[13], HITLS_APP_SUCCESS}
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_EncMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
    
EXIT:
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ENC_TC003
 * @spec  -
 * @title  测试命令行二级命令enc异常场景
 */

/* BEGIN_CASE */
void UT_HITLS_APP_ENC_TC003(void)
{
    char *argv[][13] = {
        {"enc", "-enc", "-cipher", "aes128_abc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-enc", "-cipher", "aes128_cbc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "file:../testdata/apps/pass/empty_pass", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-enc", "-cipher", "aes128_cbc", "-md", "md_abc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:12345678", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-enc", "-cipher", "aes128_cbc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "pass:", "-out", "../testdata/apps/enc/res_encfile"},
        {"enc", "-enc", "-cipher", "aes128_cbc", "-in", "../testdata/apps/enc/test_encfile", "-pass", "file:../testdata/apps/pass/size_1025_pass", "-out", "../testdata/apps/enc/res_encfile"}
    };

    OptTestData testData[] = {
        {10, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {10, argv[1], HITLS_APP_PASSWD_FAIL},
        {12, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {10, argv[3], HITLS_APP_PASSWD_FAIL},
        {10, argv[4], HITLS_APP_PASSWD_FAIL}
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_EncMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
    
EXIT:
    AppUninit();
    return;
}
/* END_CASE */