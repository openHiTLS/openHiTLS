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
#include <ctype.h>
#include "string.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_dgst.h"
#include "app_provider.h"
#include "app_print.h"
#include "crypt_eal_md.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include "bsl_params.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "stub_utils.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_APP_OptBegin, int32_t, char **, const HITLS_CmdOption *);
STUB_DEFINE_RET4(int32_t, BSL_UIO_Ctrl, BSL_UIO *, int32_t, int32_t, void *);
STUB_DEFINE_RET0(char *, HITLS_APP_OptGetValueStr);
STUB_DEFINE_RET4(int32_t, HITLS_APP_OptWriteUio, BSL_UIO *, uint8_t *, uint32_t, int32_t);
STUB_DEFINE_RET1(uint32_t, CRYPT_EAL_MdGetDigestSize, CRYPT_MD_AlgId);
STUB_DEFINE_RET3(CRYPT_EAL_MdCtx *, CRYPT_EAL_ProviderMdNewCtx, CRYPT_EAL_LibCtx *, int32_t, const char *);
STUB_DEFINE_RET1(int32_t, CRYPT_EAL_MdInit, CRYPT_EAL_MdCtx *);
STUB_DEFINE_RET3(int32_t, CRYPT_EAL_MdUpdate, CRYPT_EAL_MdCtx *, const uint8_t *, uint32_t);
STUB_DEFINE_RET3(int32_t, CRYPT_EAL_MdFinal, CRYPT_EAL_MdCtx *, uint8_t *, uint32_t *);


#define PRV_PATH "../testdata/certificate/rsa_key/prvKey.pem"
#define OUT_FILE_PATH "../testdata/certificate/rsa_key/out.pem"
#define SIGN_PRV_PATH "../testdata/apps/sm2/prv.pem"
#define SIGN_PUB_PATH "../testdata/apps/sm2/pub.pem"
#define BIN_SIGN_FILE_PATH "_APP_dgst_sign.bin"
#define RSA_SIGN_PRV_PATH "../testdata/cert/asn1/keypem/rsa-pri-key-p8.pem"
#define RSA_SIGN_PUB_PATH "../testdata/cert/asn1/keypem/rsa-pub-key-p8.pem"
#define RSA_SIGN_FILE_PATH "_APP_dgst_rsa_sign.bin"
#define RSA_PSS_MSG_FILE_PATH "_APP_dgst_rsa_pss_msg.bin"

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_dgst.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

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
    remove(OUT_FILE_PATH);
    AppPrintErrorUioUnInit();
    HITLS_APP_FreeLibCtx();
}

/**
 * @test UT_HITLS_APP_dgst_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC001(void)
{
    char *argv[][10] = {
        {"dgst", "-md", "md5", PRV_PATH},
        {"dgst", PRV_PATH},
        {"dgst", "-md", "md5", "-out", OUT_FILE_PATH, PRV_PATH},
    };

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_SUCCESS},
        {2, argv[1], HITLS_APP_SUCCESS},
        {6, argv[2], HITLS_APP_SUCCESS}
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC002(void)
{
    char *argv[][10] = {{"dgst", "-md"},
        {"dgst", "-md", "md10", PRV_PATH},
        {"dgst", "-md", "md5", "md5", PRV_PATH},
        {"dgst", "-md", "md5", "-out"},
        {"dgst", "-md", "md5", "/noexist/noexist.txt"},
        {"dgst", "-md", "md5", "-out", "/noexist/filepath/outfile.txt", PRV_PATH},
        {"dgst", "-md", "md5", "-out", "-out", "/noexist/filepath/outfile.txt", PRV_PATH},
        {"dgst", "-signfmt"},
        {"dgst", "-signfmt", "pem", PRV_PATH}
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_OPT_UNKOWN},
        {4, argv[1], HITLS_APP_OPT_VALUE_INVALID},
        {5, argv[2], HITLS_APP_UIO_FAIL},
        {4, argv[3], HITLS_APP_OPT_UNKOWN},
        {4, argv[4], HITLS_APP_UIO_FAIL},
        {6, argv[5], HITLS_APP_UIO_FAIL},
        {7, argv[6], HITLS_APP_UIO_FAIL},
        {2, argv[7], HITLS_APP_OPT_UNKOWN},
        {4, argv[8], HITLS_APP_OPT_VALUE_INVALID}
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_TC003
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC003(void)
{
    char *argv[][2] = {
        {"dgst", "-help"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
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
 * @test UT_HITLS_APP_dgst_TC004
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC004函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC004(void)
{
    STUB_REPLACE(HITLS_APP_OptBegin, STUB_HITLS_APP_OptBegin);;
    char *argv[][50] = {{"dgst", "-md", "md5", "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppUninit();
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

/**
 * @test UT_HITLS_APP_dgst_TC005
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC005函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC005(void)
{
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    STUB_REPLACE(BSL_UIO_Ctrl, STUB_BSL_UIO_Ctrl);;
    char *argv[][50] = {{"dgst", "-md", "md5", "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {6, argv[0], HITLS_APP_UIO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(BSL_UIO_Ctrl);
    AppUninit();
    return;
}
/* END_CASE */

char *STUB_HITLS_APP_OptGetValueStr(void)
{
    return NULL;
}

/**
 * @test UT_HITLS_APP_dgst_TC006
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC006函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC006(void)
{
    STUB_REPLACE(HITLS_APP_OptGetValueStr, STUB_HITLS_APP_OptGetValueStr);;
    char *argv[][50] = {{"dgst",  "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
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
 * @test UT_HITLS_APP_dgst_TC007
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC007函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC007(void)
{
    STUB_REPLACE(HITLS_APP_OptWriteUio, STUB_HITLS_APP_OptWriteUio);;
    char *argv[][50] = {{"dgst",  "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
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
 * @test UT_HITLS_APP_dgst_TC008
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC008函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC008(void)
{
    char *filename = "_APP_dgst_T008.txt";
    char *argv[][10] = {{"dgst", "-out", filename, PRV_PATH}};

    OptTestData testData[] = {{4, argv[0], HITLS_APP_SUCCESS}};

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
        ASSERT_TRUE(IsFileExist(filename));
        remove(filename);
    }

EXIT:
    AppUninit();
    return;
}
/* END_CASE */

uint32_t STUB_CRYPT_EAL_MdGetDigestSize(CRYPT_MD_AlgId id)
{
    (void)id;
    return 0;
}

/**
 * @test UT_HITLS_APP_dgst_TC009
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC009函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC009(void)
{
    STUB_REPLACE(CRYPT_EAL_MdGetDigestSize, STUB_CRYPT_EAL_MdGetDigestSize);;
    char *argv[][50] = {{"dgst", "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(CRYPT_EAL_MdGetDigestSize);
    return;
}
/* END_CASE */

CRYPT_EAL_MdCtx *STUB_CRYPT_EAL_ProviderMdNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
    (void)algId;
    (void)attrName;
    (void)libCtx;
    return NULL;
}

/**
 * @test UT_HITLS_APP_dgst_TC0010
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC0010函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC0010(void)
{
    STUB_REPLACE(CRYPT_EAL_ProviderMdNewCtx, STUB_CRYPT_EAL_ProviderMdNewCtx);;
    char *argv[][50] = {{"dgst", "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(CRYPT_EAL_ProviderMdNewCtx);
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_MdInit(CRYPT_EAL_MdCtx *ctx){
    (void)ctx;
    return HITLS_APP_CRYPTO_FAIL;
}

/**
 * @test UT_HITLS_APP_dgst_TC0011
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC0011函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC0011(void)
{
    STUB_REPLACE(CRYPT_EAL_MdInit, STUB_CRYPT_EAL_MdInit);;
    char *argv[][50] = {{"dgst", "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_CRYPTO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(CRYPT_EAL_MdInit);
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_MdUpdate(CRYPT_EAL_MdCtx *ctx, const uint8_t *data, uint32_t len){
    (void)ctx;
    (void)data;
    (void)len;
    return CRYPT_EAL_ERR_STATE;
}

/**
 * @test UT_HITLS_APP_dgst_TC0012
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC0012函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC0012(void)
{
    STUB_REPLACE(CRYPT_EAL_MdUpdate, STUB_CRYPT_EAL_MdUpdate);;
    char *argv[][50] = {{"dgst", "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {
        {4, argv[0], HITLS_APP_UIO_FAIL},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(CRYPT_EAL_MdUpdate);
    return;
}
/* END_CASE */

int32_t STUB_CRYPT_EAL_MdFinal(CRYPT_EAL_MdCtx *ctx, uint8_t *out, uint32_t *len){
    (void)ctx;
    (void)out;
    (void)len;
    return CRYPT_EAL_ERR_STATE;
}

/**
 * @test UT_HITLS_APP_dgst_TC0013
 * @spec  -
 * @title   测试UT_HITLS_APP_dgst_TC0013函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_TC0013(void)
{
    STUB_REPLACE(CRYPT_EAL_MdFinal, STUB_CRYPT_EAL_MdFinal);;
    char *argv[][50] = {{"dgst", "-out", OUT_FILE_PATH, PRV_PATH}};

    OptTestData testData[] = {{4, argv[0], HITLS_APP_CRYPTO_FAIL}};

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_DgstMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppUninit();
    STUB_RESTORE(CRYPT_EAL_MdFinal);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_STDIN_TC001
 * @spec  -
 * @title  Read message to be signed from standard input
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_STDIN_TC001(char *keyPath, char *md)
{
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);

    /* Redirect stdin to message file, simulating:
       cat message_file | ./hitls dgst -md <md> -sign <keyPath> -out <out> */
    ASSERT_NE(freopen(PRV_PATH, "r", stdin), NULL);

    /* dgst -md <md> -sign <keyPath> -out <OUT_FILE_PATH> */
    char *argv[] = {"dgst", "-md", md, "-sign", keyPath, "-out", OUT_FILE_PATH, NULL};
    int argc = 7;

    int ret = HITLS_DgstMain(argc, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    (void)fflush(stdout);
    /* Restore stdin to terminal to avoid affecting subsequent test cases */
    (void)freopen("/dev/tty", "r", stdin);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_COLON_TC001
 * @spec  -
 * @title Verify that -c separates every pair of digest hex digits with a colon
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_COLON_TC001(void)
{
    char *argv[] = {"dgst", "-md", "md5", "-out", OUT_FILE_PATH, "-c", PRV_PATH, NULL};
    const char *expected = "md5(" PRV_PATH ")= d6:55:65:70:ca:a4:39:3f:a5:73:33:45:29:3e:31:23\n";
    char output[256] = {0};
    FILE *file = NULL;

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_DgstMain(7, argv), HITLS_APP_SUCCESS);

    file = fopen(OUT_FILE_PATH, "r");
    ASSERT_NE(file, NULL);
    ASSERT_NE(fgets(output, sizeof(output), file), NULL);
    (void)fclose(file);
    file = NULL;

    ASSERT_EQ(strcmp(output, expected), 0);

EXIT:
    if (file != NULL) {
        (void)fclose(file);
    }
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_SIGNFMT_TC001
 * @spec  -
 * @title Sign, verify, and reject mismatched hexadecimal and binary signature formats
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_SIGNFMT_TC001(void)
{
    FILE *hexFile = NULL;
    FILE *binFile = NULL;
    uint8_t hexSign[1024] = {0};
    uint8_t binSign[1024] = {0};
    bool binHasNonHex = false;
    char *signHexArgv[] = {"dgst", "-md", "sm3", "-sign", SIGN_PRV_PATH, "-out", OUT_FILE_PATH,
        "-signfmt", "hex", PRV_PATH, NULL};
    char *signBinArgv[] = {"dgst", "-md", "sm3", "-sign", SIGN_PRV_PATH, "-out", BIN_SIGN_FILE_PATH,
        "-signfmt", "bin", PRV_PATH, NULL};
    char *verifyHexArgv[] = {"dgst", "-md", "sm3", "-verify", SIGN_PUB_PATH, "-signature", OUT_FILE_PATH,
        "-signfmt", "hex", PRV_PATH, NULL};
    char *verifyBinArgv[] = {"dgst", "-md", "sm3", "-verify", SIGN_PUB_PATH, "-signature", BIN_SIGN_FILE_PATH,
        "-signfmt", "bin", PRV_PATH, NULL};
    char *verifyHexAsBinArgv[] = {"dgst", "-md", "sm3", "-verify", SIGN_PUB_PATH, "-signature", OUT_FILE_PATH,
        "-signfmt", "bin", PRV_PATH, NULL};
    char *verifyBinAsHexArgv[] = {"dgst", "-md", "sm3", "-verify", SIGN_PUB_PATH, "-signature", BIN_SIGN_FILE_PATH,
        "-signfmt", "hex", PRV_PATH, NULL};

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_DgstMain(10, signHexArgv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_DgstMain(10, signBinArgv), HITLS_APP_SUCCESS);

    hexFile = fopen(OUT_FILE_PATH, "rb");
    binFile = fopen(BIN_SIGN_FILE_PATH, "rb");
    ASSERT_NE(hexFile, NULL);
    ASSERT_NE(binFile, NULL);
    size_t hexSignLen = fread(hexSign, 1, sizeof(hexSign), hexFile);
    size_t binSignLen = fread(binSign, 1, sizeof(binSign), binFile);
    ASSERT_TRUE(hexSignLen > 0);
    ASSERT_TRUE(binSignLen > 0);
    for (size_t i = 0; i < hexSignLen; i++) {
        ASSERT_TRUE(isxdigit(hexSign[i]) != 0);
    }
    for (size_t i = 0; i < binSignLen; i++) {
        if (isxdigit(binSign[i]) == 0) {
            binHasNonHex = true;
            break;
        }
    }
    ASSERT_TRUE(binHasNonHex);

    ASSERT_EQ(HITLS_DgstMain(10, verifyHexArgv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_DgstMain(10, verifyBinArgv), HITLS_APP_SUCCESS);
    ASSERT_NE(HITLS_DgstMain(10, verifyHexAsBinArgv), HITLS_APP_SUCCESS);
    ASSERT_NE(HITLS_DgstMain(10, verifyBinAsHexArgv), HITLS_APP_SUCCESS);

EXIT:
    if (hexFile != NULL) {
        (void)fclose(hexFile);
    }
    if (binFile != NULL) {
        (void)fclose(binFile);
    }
    (void)remove(BIN_SIGN_FILE_PATH);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_SIGN_VERIFY_TC001
 * @brief Sign and verify a message using the supplied algorithm, digest, keys, and expected results.
 * @expect Signing and verification return the supplied results.
 * @precon nan
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_SIGN_VERIFY_TC001(
    int algId, char *md, char *prvKey, char *pubKey, int expectSign, int expectVerify)
{
    char signFile[64] = {0};
    FILE *file = NULL;
    int ret = snprintf(signFile, sizeof(signFile), "_APP_dgst_sign_%d.bin", algId);
    ASSERT_TRUE(ret > 0 && (size_t)ret < sizeof(signFile));
    char *signArgv[] = {
        "dgst", "-md", md, "-sign", prvKey, "-out", signFile, "-signfmt", "bin", PRV_PATH, NULL};
    char *verifyArgv[] = {
        "dgst", "-md", md, "-verify", pubKey, "-signature", signFile, "-signfmt", "bin", PRV_PATH, NULL};

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    file = fopen(signFile, "wb");
    ASSERT_NE(file, NULL);
    ASSERT_EQ(fputc(0, file), 0);
    (void)fclose(file);
    file = NULL;

    ASSERT_EQ(HITLS_DgstMain(10, signArgv), expectSign);
    ASSERT_EQ(HITLS_DgstMain(10, verifyArgv), expectVerify);

EXIT:
    if (file != NULL) {
        (void)fclose(file);
    }
    (void)remove(signFile);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_RSA_SIGOPT_TC001
 * @brief Sign and verify with an explicitly selected RSA padding mode.
 * @expect RSA signing and verification succeed.
 * @precon nan
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_RSA_SIGOPT_TC001(char *paddingMode, char *otherPaddingMode)
{
    char sigOpt[64] = {0};
    char otherSigOpt[64] = {0};
    int ret = snprintf(sigOpt, sizeof(sigOpt), "rsa_padding_mode:%s", paddingMode);
    ASSERT_TRUE(ret > 0 && (size_t)ret < sizeof(sigOpt));
    ret = snprintf(otherSigOpt, sizeof(otherSigOpt), "rsa_padding_mode:%s", otherPaddingMode);
    ASSERT_TRUE(ret > 0 && (size_t)ret < sizeof(otherSigOpt));
    char *signArgv[] = {"dgst", "-md", "sha256", "-sign", RSA_SIGN_PRV_PATH, "-out", RSA_SIGN_FILE_PATH,
        "-signfmt", "bin", "-sigopt", sigOpt, PRV_PATH, NULL};
    char *verifyArgv[] = {"dgst", "-md", "sha256", "-verify", RSA_SIGN_PUB_PATH, "-signature",
        RSA_SIGN_FILE_PATH, "-signfmt", "bin", "-sigopt", sigOpt, PRV_PATH, NULL};
    char *verifyOtherArgv[] = {"dgst", "-md", "sha256", "-verify", RSA_SIGN_PUB_PATH, "-signature",
        RSA_SIGN_FILE_PATH, "-signfmt", "bin", "-sigopt", otherSigOpt, PRV_PATH, NULL};

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_DgstMain(12, signArgv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_DgstMain(12, verifyArgv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_DgstMain(12, verifyOtherArgv), HITLS_APP_CRYPTO_FAIL);

EXIT:
    (void)remove(RSA_SIGN_FILE_PATH);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_RSA_PSS_AUTOLEN_TC001
 * @brief Verify RSA-PSS signatures whose salt length is selected by the signer.
 * @expect Verification succeeds for every permitted salt length.
 * @precon nan
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_RSA_PSS_AUTOLEN_TC001(int saltLen)
{
    static const uint8_t msg[] = "RSA-PSS salt length test";
    uint8_t salt[222] = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *signature = NULL;
    FILE *file = NULL;
    uint32_t signatureLen = 0;
    int32_t mdId = CRYPT_MD_SHA256;
    BSL_Param params[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    char *verifyArgv[] = {"dgst", "-md", "sha256", "-verify", RSA_SIGN_PUB_PATH, "-signature",
        RSA_SIGN_FILE_PATH, "-signfmt", "bin", "-sigopt", "rsa_padding_mode:pss", RSA_PSS_MSG_FILE_PATH, NULL};

    ASSERT_TRUE(saltLen >= 0 && saltLen <= (int32_t)sizeof(salt));
    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        RSA_SIGN_PRV_PATH, NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, params, 0), CRYPT_SUCCESS);
    if (saltLen > 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, salt, (uint32_t)saltLen), CRYPT_SUCCESS);
    }
    signatureLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    ASSERT_TRUE(signatureLen > 0);
    signature = BSL_SAL_Malloc(signatureLen);
    ASSERT_NE(signature, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, msg, sizeof(msg) - 1, signature, &signatureLen),
        CRYPT_SUCCESS);

    file = fopen(RSA_PSS_MSG_FILE_PATH, "wb");
    ASSERT_NE(file, NULL);
    ASSERT_EQ(fwrite(msg, 1, sizeof(msg) - 1, file), sizeof(msg) - 1);
    (void)fclose(file);
    file = fopen(RSA_SIGN_FILE_PATH, "wb");
    ASSERT_NE(file, NULL);
    ASSERT_EQ(fwrite(signature, 1, signatureLen, file), signatureLen);
    (void)fclose(file);
    file = NULL;

    ASSERT_EQ(HITLS_DgstMain(12, verifyArgv), HITLS_APP_SUCCESS);

EXIT:
    if (file != NULL) {
        (void)fclose(file);
    }
    BSL_SAL_Free(signature);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    (void)remove(RSA_PSS_MSG_FILE_PATH);
    (void)remove(RSA_SIGN_FILE_PATH);
    AppUninit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_dgst_SIGOPT_INVALID_TC001
 * @brief Reject malformed, unsupported, duplicate, or inapplicable signature options.
 * @expect Every invalid command returns a parameter error.
 * @precon nan
 */
/* BEGIN_CASE */
void UT_HITLS_APP_dgst_SIGOPT_INVALID_TC001(void)
{
    char *argv[][16] = {
        {"dgst", "-md", "sha256", "-sign", RSA_SIGN_PRV_PATH, "-out", RSA_SIGN_FILE_PATH, "-sigopt",
            "rsa_padding_mode", PRV_PATH},
        {"dgst", "-md", "sha256", "-sign", RSA_SIGN_PRV_PATH, "-out", RSA_SIGN_FILE_PATH, "-sigopt",
            "rsa_padding_mode:oaep", PRV_PATH},
        {"dgst", "-md", "sha256", "-sign", RSA_SIGN_PRV_PATH, "-out", RSA_SIGN_FILE_PATH, "-sigopt",
            "rsa_mgf1_md:sha256", PRV_PATH},
        {"dgst", "-md", "sha256", "-sign", RSA_SIGN_PRV_PATH, "-out", RSA_SIGN_FILE_PATH, "-sigopt",
            "rsa_padding_mode:pss", "-sigopt", "rsa_padding_mode:pkcs1", PRV_PATH},
        {"dgst", "-md", "sm3", "-sign", SIGN_PRV_PATH, "-out", RSA_SIGN_FILE_PATH, "-sigopt",
            "rsa_padding_mode:pss", PRV_PATH},
        {"dgst", "-sigopt", "rsa_padding_mode:pkcs1", PRV_PATH},
    };
    OptTestData testData[] = {
        {10, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {10, argv[1], HITLS_APP_OPT_VALUE_INVALID},
        {10, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[3], HITLS_APP_OPT_VALUE_INVALID},
        {10, argv[4], HITLS_APP_OPT_VALUE_INVALID},
        {4, argv[5], HITLS_APP_OPT_VALUE_INVALID},
    };

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);
    for (size_t i = 0; i < sizeof(testData) / sizeof(testData[0]); i++) {
        ASSERT_EQ(HITLS_DgstMain(testData[i].argc, testData[i].argv), testData[i].expect);
    }

EXIT:
    (void)remove(RSA_SIGN_FILE_PATH);
    AppUninit();
    return;
}
/* END_CASE */
