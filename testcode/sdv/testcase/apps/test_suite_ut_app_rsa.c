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
#include <termios.h>
#include <unistd.h>
#include "securec.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_utils.h"
#include "bsl_uio.h"
#include "app_errno.h"
#include "app_rsa.h"
#include "app_function.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "app_rsa.h"
#include "stub_utils.h"
#include "app_utils.h"
#include "bsl_types.h"
#include "crypt_eal_codecs.h"
#include "crypt_errno.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_APP_OptBegin, int32_t, char **, const HITLS_CmdOption *);
STUB_DEFINE_RET6(int32_t, CRYPT_EAL_DecodeBuffKey, int32_t, int32_t, BSL_Buffer *, const uint8_t *, uint32_t, CRYPT_EAL_PkeyCtx **);
STUB_DEFINE_RET1(BSL_UIO *, BSL_UIO_New, const BSL_UIO_Method *);
STUB_DEFINE_RET4(int32_t, BSL_UIO_Ctrl, BSL_UIO *, int32_t, int32_t, void *);
STUB_DEFINE_RET0(char *, HITLS_APP_OptGetValueStr);
STUB_DEFINE_RET4(int32_t, HITLS_APP_OptWriteUio, BSL_UIO *, uint8_t *, uint32_t, int32_t);
STUB_DEFINE_RET5(int32_t, CRYPT_EAL_EncodeBuffKey, CRYPT_EAL_PkeyCtx *, const CRYPT_EncodeParam *, int32_t, int32_t, BSL_Buffer *);
STUB_DEFINE_RET3(int32_t, HITLS_APP_Passwd, char *, int32_t, int32_t);

#define PRV_PATH "../testdata/certificate/rsa_key/prvKey.pem"
#define PRV_PASSWD_PATH "../testdata/cert/asn1/keypem/rsa-pri-key-p8-2048.pem"
#define PRV_DER_PATH "../testdata/cert/asn1/rsa2048key_pkcs1.der"
#define OUT_FILE_PATH "../testdata/certificate/rsa_key/out.pem"

typedef struct {
    int32_t outformat;
    bool text;
    bool noout;
    char *outfile;
} OutputInfo;

typedef struct {
    int argc;
    char **argv;
    int expect;
} RsaTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c  ${HITLS_ROOT_PATH}/apps/src/app_rsa.c  ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */

/**
 * @test UT_HITLS_APP_rsa_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_TC001(void)
{
    char *argv[][10] = {
        {"rsa", "-in", PRV_PATH, "-noout"},
        {"rsa", "-in", PRV_PATH, "-out", OUT_FILE_PATH},
        {"rsa", "-in", PRV_PATH, "-out", OUT_FILE_PATH, "-text"},
        {"rsa", "-in", PRV_PATH, "-out", OUT_FILE_PATH, "-text", "-noout"},
        {"rsa", "-in", PRV_PATH, "-out", "/test/noexist/out.pem"},
        {"rsa", "-in", "noexist.pem", "-text"}};

    RsaTestData testData[] = {{4, argv[0], HITLS_APP_SUCCESS},
        {5, argv[1], HITLS_APP_SUCCESS},
        {6, argv[2], HITLS_APP_SUCCESS},
        {7, argv[3], HITLS_APP_SUCCESS},
        {5, argv[4], HITLS_APP_UIO_FAIL},
        {4, argv[5], HITLS_APP_UIO_FAIL}

    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_rsa_T002
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_TC002(void)
{
    char *argv[][2] = {
        {"rsa", "-help"},
    };

    RsaTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_HITLS_APP_OptBegin(int32_t argc, char **argv, const HITLS_CmdOption *opts)
{
    (void)argc;
    (void)argv;
    (void)opts;
    return HITLS_APP_OPT_UNKOWN;
}

/**
 * @test UT_HITLS_APP_rsa_T003
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T003(void)
{
    STUB_REPLACE(HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin);;
    char *argv[][4] = {{"rsa", "-in", PRV_PATH, "-noout"}};

    RsaTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_OptBegin);
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_DecodeBuffKey(int32_t format, int32_t type, BSL_Buffer *encode,
    const uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey)
{
    (void)format;
    (void)type;
    (void)encode;
    (void)pwd;
    (void)pwdlen;
    (void)ealPKey;
    return HITLS_APP_DECODE_FAIL;
}

/**
 * @test UT_HITLS_APP_rsa_T004
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T004函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T004(void)
{
    STUB_REPLACE(CRYPT_EAL_DecodeBuffKey, STUB_CRYPT_EAL_DecodeBuffKey);;
    char *argv[][10] = {{"rsa", "-in", PRV_PATH, "-noout"}};

    RsaTestData testData[] = {
        {4, argv[0], HITLS_APP_DECODE_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(CRYPT_EAL_DecodeBuffKey);
    return;
}
/* END_CASE */

BSL_UIO *STUB_BSL_UIO_New(const BSL_UIO_Method *method)
{
    (void)method;
    return NULL;
}

/**
 * @test UT_HITLS_APP_rsa_T005
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T005函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T005(void)
{
    STUB_REPLACE(BSL_UIO_New, STUB_BSL_UIO_New);;
    char *argv[][10] = {{"rsa", "-in", PRV_PATH, "-noout"}};

    RsaTestData testData[] = {
        {4, argv[0], HITLS_APP_UIO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(BSL_UIO_New);
    return;
}
/* END_CASE */

int32_t STUB_BSL_UIO_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    (void)uio;
    (void)cmd;
    (void)larg;
    (void)parg;
    return BSL_NULL_INPUT;
}

/**
 * @test UT_HITLS_APP_rsa_T006
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T006函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T006(void)
{
    STUB_REPLACE(BSL_UIO_Ctrl, STUB_BSL_UIO_Ctrl);;
    char *argv[][10] = {{"rsa", "-in", PRV_PATH, "-noout"}};

    RsaTestData testData[] = {
        {4, argv[0], HITLS_APP_UIO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(BSL_UIO_Ctrl);
    return;
}
/* END_CASE */

char *STUB_HITLS_APP_OptGetValueStr(void)
{
    return NULL;
}

/**
 * @test UT_HITLS_APP_rsa_T007
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T007函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T007(void)
{
    STUB_REPLACE(HITLS_APP_OptGetValueStr, STUB_HITLS_APP_OptGetValueStr);;
    char *argv[][10] = {{"rsa", "-in", PRV_PATH, "-noout"}};

    RsaTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_OptGetValueStr);
    return;
}
/* END_CASE */

int32_t STUB_HITLS_APP_OptWriteUio(BSL_UIO *uio, uint8_t *buf, uint32_t outLen, int32_t format)
{
    (void)uio;
    (void)buf;
    (void)outLen;
    (void)format;
    return HITLS_APP_UIO_FAIL;
}

/**
 * @test UT_HITLS_APP_rsa_T008
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T008函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T008(void)
{
    STUB_REPLACE(HITLS_APP_OptWriteUio, STUB_HITLS_APP_OptWriteUio);;
    char *argv[][10] = {{"rsa", "-in", PRV_PATH, "-text"}};

    RsaTestData testData[] = {
        {4, argv[0], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_OptWriteUio);
    return;
}
/* END_CASE */


bool IsFileExist(const char *fileName)
{
    FILE *f = fopen(fileName, "r");
    if (f == NULL) {
        return false;
    }
    fclose(f);
    return true;
}

/**
 * @test UT_HITLS_APP_rsa_T009
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T009函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T009(void)
{
    char *filename = "_APP_rsa_T009.txt";
    char *argv[][10] = {{"rsa", "-in", PRV_PATH, "-out", filename}};

    RsaTestData testData[] = {{5, argv[0], HITLS_APP_SUCCESS}};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        ASSERT_TRUE(IsFileExist(filename) == false);
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
        ASSERT_TRUE(IsFileExist(filename));
        remove(filename);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_EncodeBuffKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, BSL_Buffer *encode)
{
    (void)ealPKey;
    (void)encodeParam;
    (void)format;
    (void)type;
    (void)encode;
    return HITLS_APP_UIO_FAIL;
}

/**
 * @test UT_HITLS_APP_rsa_T0010
 * @spec  -
 * @title   测试UT_HITLS_APP_rsa_T0010函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T0010(void)
{
    STUB_REPLACE(CRYPT_EAL_EncodeBuffKey, STUB_CRYPT_EAL_EncodeBuffKey);;
    char *argv[][10] = {{"rsa", "-in", PRV_PATH}};

    RsaTestData testData[] = {
        {3, argv[0], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(CRYPT_EAL_EncodeBuffKey);
    return;
}
/* END_CASE */

int32_t STUB_HITLS_APP_Passwd(char *buf, int32_t bufMaxLen, int32_t flag)
{
    (void)flag;
    (void)memcpy_s(buf, bufMaxLen, "123456", 6);
    return 6;
}

/* BEGIN_CASE */
void UT_HITLS_APP_rsa_T0011(void)
{
    STUB_REPLACE(HITLS_APP_Passwd, STUB_HITLS_APP_Passwd);;
    char *argv[][10] = {
        {"rsa", "-in", PRV_PASSWD_PATH, "-noout"},
        {"rsa", "-in", PRV_DER_PATH, "-noout"},
    };

    RsaTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_DECODE_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        int ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        if (ret != testData[i].expect) {
            printf("I is %d\n", i);
        }
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_Passwd);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_rsa_TC012(void)
{
    char *argv[][10] = {
        {"rsa", "-in", PRV_PATH},
        {"rsa", "-in", PRV_PATH, "-noout"},
        {"rsa", "-in", PRV_PATH, "-text"},
        {"rsa", "-in", PRV_PATH, "-noout", "-text"},
        {"rsa", "-in", PRV_PATH, "-out", "out4.pem"},
        {"rsa", "-in", PRV_PATH, "-noout", "-out", "out5.pem"},
        {"rsa", "-in", PRV_PATH, "-text", "-out", "out6.pem"},
        {"rsa", "-in", PRV_PATH, "-noout", "-text", "-out", "out7.pem"},
    };

    RsaTestData testData[] = {
        {3, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_SUCCESS},
        {4, argv[2], HITLS_APP_SUCCESS},
        {5, argv[3], HITLS_APP_SUCCESS},
        {5, argv[4], HITLS_APP_SUCCESS},
        {6, argv[5], HITLS_APP_SUCCESS},
        {6, argv[6], HITLS_APP_SUCCESS},
        {7, argv[7], HITLS_APP_SUCCESS},
    };
    int ret;
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(RsaTestData)); ++i) {
        ret = HITLS_RsaMain(testData[i].argc, testData[i].argv);
        fflush(stdout);
        freopen("/dev/tty", "w", stdout);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
