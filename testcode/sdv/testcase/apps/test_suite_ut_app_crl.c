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
#include "app_crl.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#include "hitls_crl_local.h"
#include "bsl_errno.h"
#include "crypt_eal_pkey.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_utils.h"
#include "stub_replace.h"

#define MAX_CRLFILE_SIZE (256 * 1024)
#define DEFAULT_CERT_SIZE 1024U

/* END_HEADER */

#define CRL_PATH "../testdata/certificate/crlAndCert/crl.crt"
#define CRL_ASN1_PATH "../testdata/cert/asn1/sm2_crl/crl_v2.v1.der"
#define CERT_PATH "../testdata/certificate/crlAndCert/CA.crt"
#define ERR_CRL_PATH "../testdata/certificate/crlAndCert/emptyCRL.crt"
#define ERR_CERT_PATH "../testdata/certificate/crlAndCert/errCA.crt"
#define CRL_PEM_PATH "./crl.pem"
#define CRL_DER_PATH "./crl.der"

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_crl.c
    ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/**
 * @test UT_HITLS_APP_crl_TC001
 * @spec  -
 * @title   Test the UT_HITLS_APP_crl_TC001 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC001(void)
{
    char *argv[][10] = {
        {"crl", "-in", CRL_PATH, "-noout", "-CAfile", CERT_PATH},
        {"crl", "-in", CRL_PATH, "-noout"},
        {"crl", "-in", CRL_PATH, "-noout", "-nextupdate"},
        {"crl", "-in", CRL_PATH, "-noout", "-out", "tmp.txt", "-nextupdate"},
        {"crl", "-in", CRL_PATH, "-noout", "-CAfile", ERR_CRL_PATH},
        {"crl", "-in", ERR_CRL_PATH, "-noout", "-CAfile", CERT_PATH},
        {"crl", "-in", CRL_ASN1_PATH, "-inform", "DER", "-out", CRL_PEM_PATH, "-outform", "PEM"},
        {"crl", "-in", CRL_PATH, "-inform", "PEM", "-out", CRL_DER_PATH, "-outform", "DER"},
    };

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_SUCCESS},
        {4, argv[1], HITLS_APP_SUCCESS},
        {5, argv[2], HITLS_APP_SUCCESS},
        {7, argv[3], HITLS_APP_SUCCESS},
        {6, argv[4], HITLS_APP_UIO_FAIL},
        {6, argv[5], HITLS_APP_UIO_FAIL},
        {9, argv[6], HITLS_APP_SUCCESS},
        {9, argv[7], HITLS_APP_SUCCESS}
    };
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_crl_TC002
 * @spec  -
 * @title   Test the UT_HITLS_APP_crl_TC002 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC002(void)
{
    char *argv[][10] = {
        {"crl", "-in"},
        {"crl", "-in", ERR_CRL_PATH},
        {"crl", "-in", CRL_PATH, "-in", ERR_CRL_PATH},
        {"crl", "-in", ERR_CRL_PATH, "-noout", "-CAfile"},
        {"crl", "-in", CRL_PATH, "-noout", "-CAfile", ERR_CRL_PATH},
        {"crl", "-in", CRL_PATH, "-noout", "-CAfile", CERT_PATH, "-CAfile", ERR_CRL_PATH},
    };

    OptTestData testData[] = {{2, argv[0], HITLS_APP_OPT_UNKOWN},
        {3, argv[1], HITLS_APP_UIO_FAIL},
        {5, argv[2], HITLS_APP_UIO_FAIL},
        {5, argv[3], HITLS_APP_OPT_UNKOWN},
        {6, argv[4], HITLS_APP_UIO_FAIL},
        {8, argv[5], HITLS_APP_UIO_FAIL}};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_crl_TC003
 * @spec  -
 * @title Test the UT_HITLS_APP_crl_TC003 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC003(void)
{
    char *argv[][2] = {
        {"crl", "-help"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
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
 * @test UT_HITLS_APP_crl_TC004
 * @spec  -
 * @title Test the UT_HITLS_APP_crl_TC004 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC004(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin);

    char *argv[][10] = {
        {"crl", "-in", CRL_PATH, "-noout", "-CAfile", CERT_PATH},
    };

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
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

/**
 * @test UT_HITLS_APP_crl_TC005
 * @spec  -
 * @title Test the UT_HITLS_APP_crl_TC005 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC005(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, BSL_UIO_Ctrl, STUB_BSL_UIO_Ctrl);
    char *argv[][50] = {{"crl", "-in", CRL_PATH, "-noout", "-CAfile", CERT_PATH}};

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_UIO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

char *STUB_HITLS_APP_OptGetValueStr(void)
{
    return NULL;
}

/**
 * @test UT_HITLS_APP_crl_TC006
 * @spec  -
 * @title Test the UT_HITLS_APP_crl_TC006 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC006(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, HITLS_APP_OptGetValueStr, STUB_HITLS_APP_OptGetValueStr);
    char *argv[][50] = {{"crl", "-in", CRL_PATH, "-noout", "-CAfile", CERT_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
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
 * @test UT_HITLS_APP_crl_TC007
 * @spec  -
 * @title Test the UT_HITLS_APP_crl_TC007 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC007(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, HITLS_APP_OptWriteUio, STUB_HITLS_APP_OptWriteUio);
    char *argv[][50] = {{"crl", "-in", CRL_PATH, "-CAfile", CERT_PATH}};

    OptTestData testData[] = {
        {5, argv[0], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
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
 * @test UT_HITLS_APP_crl_TC008
 * @spec  -
 * @title Test the UT_HITLS_APP_crl_TC008 function.
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC008(void)
{
    char *filename = "_APP_crl_T008.txt";
    char *argv[][10] = {{"crl", "-in", CRL_PATH, "-out", filename, "-CAfile", CERT_PATH}};

    OptTestData testData[] = {{7, argv[0], HITLS_APP_SUCCESS}};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        ASSERT_TRUE(IsFileExist(filename) == false);
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
        ASSERT_TRUE(IsFileExist(filename));
        remove(filename);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

int32_t STUB_X509_extractPublicKey(HITLS_X509_Cert *cert, int32_t cmd, void *val, uint32_t valLen)
{
    (void)cert;
    (void)cmd;
    (void)val;
    (void)valLen;
    return HITLS_X509_ERR_INVALID_PARAM;
}

/**
 * @test UT_HITLS_APP_crl_TC0010
 * @spec  -
 * @titleTest UT_HITLS_APP_crl_TC0010 function
 */
/* BEGIN_CASE */
void UT_HITLS_APP_crl_TC0010(void)
{
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, HITLS_X509_CertCtrl, STUB_X509_extractPublicKey);
    char *argv[][50] = {{"crl", "-in", CRL_PATH, "-noout", "-CAfile", CERT_PATH}};

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_DECODE_FAIL},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_CrlMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    STUB_Reset(&stubInfo);
    return;
}
/* END_CASE */

int32_t STUB_PEM_encode(HITLS_X509_Crl *crl, uint8_t **encode, uint32_t *encodeLen)
{
    (void)crl;
    (void)encode;
    (void)encodeLen;
    return HITLS_APP_ENCODE_FAIL;
}