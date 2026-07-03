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
#include "app_verify.h"
#include "app_server.h"
#include <limits.h>
#include <stdbool.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "app_function.h"
#include "bsl_list.h"

#include "app_errno.h"
#include "app_opt.h"
#include "app_help.h"
#include "app_print.h"
#include "app_utils.h"
#include "stub_utils.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_APP_OptBegin, int32_t, char **, const HITLS_CmdOption *);
STUB_DEFINE_RET0(char *, HITLS_APP_OptGetValueStr);
STUB_DEFINE_RET3(int32_t, HITLS_X509_CertParseBundleFile, int32_t, const char *, HITLS_X509_List **);
STUB_DEFINE_RET4(int32_t, HITLS_X509_StoreCtxCtrl, HITLS_X509_StoreCtx *, int32_t, void *, uint32_t);
STUB_DEFINE_RET0(HITLS_X509_StoreCtx *, HITLS_X509_StoreCtxNew);
STUB_DEFINE_RET2(int32_t, HITLS_X509_CertVerify, HITLS_X509_StoreCtx *, HITLS_X509_List *);


#define MAX_CRLFILE_SIZE (256 * 1024)
#define CAFILE_PATH "../testdata/certificate/VerifyCAfile/root_trust.ca"
#define EMPTY_CAFILE_PATH "../testdata/certificate/VerifyCAfile/emptyRoot.ca"
#define ROOT256K_CAFILE_PATH "../testdata/certificate/VerifyCAfile/root256K.ca"
#define ROOT255K_CAFILE_PATH "../testdata/certificate/VerifyCAfile/root255k.ca"
#define MISTAKE_CA_FILEPATH "../testdata/certificate/VerifyCAfile/mistakeCA.ca"
#define MID_CA_FILEPATH "../testdata/certificate/VerifyCAfile/middle_ca.pem"
#define CERT_PATH "../testdata/certificate/VerifyCAfile/future.pem"
#define EMPTY_CERT_PATH "../testdata/certificate/VerifyCAfile/emptyCert.ca"
#define CERT_256K_FILEPATH "../testdata/certificate/VerifyCAfile/256kfuture.pem"
#define CERT_257K_FILEPATH "../testdata/certificate/VerifyCAfile/257kfuture.pem"
#define MISTAKE_CERT_PATH "../testdata/certificate/VerifyCAfile/mistakeCert.pem"
#define SM2_WITH_USERID_CA "../testdata/cert/sm2_with_userid/ca.crt"
#define SM2_WITH_USERID_INTER "../testdata/cert/sm2_with_userid/inter.crt"

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_verify.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/**
 * @test UT_HITLS_APP_Verify_TC001
 * @spec  -
 * @title   Test the UT_HITLS_APP_Verify_TC001 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC001(void)
{
    char *argv[][100] = {
        {"verify", "-CAfile", CAFILE_PATH, CERT_PATH},
        {"verify", "-CAfile", SM2_WITH_USERID_CA, "-nokeyusage", "-userid", "1234567812345678", SM2_WITH_USERID_INTER},
        {"verify", "-CAfile", SM2_WITH_USERID_CA, "-nokeyusage", "-userid", "1111111111111111", SM2_WITH_USERID_INTER},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {7, argv[1], HITLS_APP_SUCCESS},
        {7, argv[2], HITLS_APP_X509_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_verify_TC002
 * @spec  -
 * @title Test the UT_HITLS_APP_verify_TC002 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC002(void)
{
    char *argv[][2] = {
        {"verify", "-help"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
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
 * @test UT_HITLS_APP_verify_TC003
 * @spec  -
 * @title Test the UT_HITLS_APP_verify_TC003 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC003(void)
{
    STUB_REPLACE(HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin);;

    char *argv[][100] = {
        {"verify", "-CAfile", CAFILE_PATH, CERT_PATH},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_OptBegin);
    return;
}
/* END_CASE */

int32_t STUB_BSL_UIO_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    (void)uio;
    (void)cmd;
    (void)larg;
    (void)parg;
    return BSL_UIO_FAIL;
}

char *STUB_HITLS_APP_OptGetValueStr(void)
{
    return NULL;
}

/**
 * @test UT_HITLS_APP_verify_TC005
 * @spec  -
 * @title Test the UT_HITLS_APP_verify_TC005 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC005(void)
{
    STUB_REPLACE(HITLS_APP_OptGetValueStr, STUB_HITLS_APP_OptGetValueStr);;
    char *argv[][100] = {{"verify", "-CAfile", CAFILE_PATH, CERT_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_OptGetValueStr);
    return;
}
/* END_CASE */

int32_t STUB_HITLS_X509_CertMulParseFile(int32_t format, const char *path, HITLS_X509_List **certlist)
{
    (void)format;
    (void)path;
    (void)certlist;
    return HITLS_APP_DECODE_FAIL;
}

/* *
 * @test UT_HITLS_APP_verify_TC006
 * @spec  -
 * @title Test the UT_HITLS_APP_verify_TC006 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC006(void)
{
    STUB_REPLACE(HITLS_X509_CertParseBundleFile, STUB_HITLS_X509_CertMulParseFile);;
    char *argv[][100] = {{"verify", "-CAfile", CAFILE_PATH, CERT_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_X509_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_X509_CertParseBundleFile);
    return;
}
/* END_CASE */



int32_t STUB_HITLS_X509_StoreCtxCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (cmd == HITLS_X509_STORECTX_DEEP_COPY_SET_CA) {
        return HITLS_APP_DECODE_FAIL;
    }
    (void)storeCtx;
    (void)val;
    (void)valLen;
    return HITLS_APP_SUCCESS;
}

/**
 * @test UT_HITLS_APP_verify_TC008
 * @spec  -
 * @titleTest UT_HITLS_APP_verify_TC008 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC008(void)
{
    STUB_REPLACE(HITLS_X509_StoreCtxCtrl, STUB_HITLS_X509_StoreCtxCtrl);;
    char *argv[][100] = {{"verify", "-CAfile", CAFILE_PATH, CERT_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_X509_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_X509_StoreCtxCtrl);
    return;
}
/* END_CASE */

int32_t STUB_HITLS_X509_StoreCtxCtrlUserIdFail(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val,
    uint32_t valLen)
{
    (void)storeCtx;
    (void)val;
    (void)valLen;
    if (cmd == HITLS_X509_STORECTX_SET_VFY_SM2_USERID) {
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

/**
 * @test UT_HITLS_APP_verify_TC011
 * @spec  -
 * @title Test verify command failure when setting SM2 userid fails.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC011(void)
{
    STUB_REPLACE(HITLS_X509_StoreCtxCtrl, STUB_HITLS_X509_StoreCtxCtrlUserIdFail);
    char *argv[][100] = {
        {"verify", "-CAfile", CAFILE_PATH, "-userid", "1234567812345678", CERT_PATH},
    };

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_X509_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_X509_StoreCtxCtrl);
    return;
}
/* END_CASE */

HITLS_X509_StoreCtx *STUB_HITLS_X509_StoreCtxNew(void)
{
    return NULL;
}

/**
 * @test UT_HITLS_APP_verify_TC009
 * @spec  -
 * @titleTest UT_HITLS_APP_verify_TC009 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC009(void)
{
    STUB_REPLACE(HITLS_X509_StoreCtxNew, STUB_HITLS_X509_StoreCtxNew);;
    char *argv[][100] = {{"verify", "-CAfile", CAFILE_PATH, CERT_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_X509_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_X509_StoreCtxNew);
    return;
}
/* END_CASE */

int32_t STUB_HITLS_X509_CertVerify(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    (void)storeCtx;
    (void)chain;
    return HITLS_APP_X509_FAIL;
}
/**
 * @test UT_HITLS_APP_verify_TC0010
 * @spec  -
 * @titleTest UT_HITLS_APP_verify_TC0012 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_verify_TC0010(void)
{
    STUB_REPLACE(HITLS_X509_CertVerify, STUB_HITLS_X509_CertVerify);;
    char *argv[][50] = {{"verify", "-CAfile", CAFILE_PATH, CERT_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_X509_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_VerifyMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_X509_CertVerify);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ServerNoVerify_TC001
 * @spec  -
 * @title Test HITLS_ServerMain with -help, verify noverify option is present in option table
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ServerNoVerify_TC001(void)
{
    char *argv[] = {"s_server", "-help"};

    OptTestData testData[] = {
        {2, argv, HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_ServerMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ServerNoVerify_TC002
 * @spec  -
 * @title Test HITLS_ServerMain with -noverify and -help, verify noverify option is parsed correctly
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ServerNoVerify_TC002(void)
{
    char *argv[] = {"s_server", "-noverify", "-help"};

    OptTestData testData[] = {
        {3, argv, HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_ServerMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ServerNoVerify_TC003
 * @spec  -
 * @title Test HITLS_ServerMain option parsing failure via stubbed OptBegin
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ServerNoVerify_TC003(void)
{
    STUB_REPLACE(HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin);

    char *argv[] = {"s_server", "-noverify"};

    OptTestData testData[] = {
        {2, argv, HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_ServerMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(HITLS_APP_OptBegin);
    return;
}
/* END_CASE */
