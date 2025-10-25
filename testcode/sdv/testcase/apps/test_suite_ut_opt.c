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
#include "securec.h"
#include "app_errno.h"
#include "bsl_uio.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "app_print.h"
#include "stub_utils.h"
#include "bsl_base64.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, BSL_UIO_Ctrl, BSL_UIO *, int32_t, int32_t, void *);
STUB_DEFINE_RET1(BSL_UIO *, BSL_UIO_New, const BSL_UIO_Method *);
STUB_DEFINE_RET4(int32_t, BSL_UIO_Write, BSL_UIO *, const void *, uint32_t, uint32_t *);
STUB_DEFINE_RET4(int32_t, BSL_BASE64_Encode, const uint8_t *, const uint32_t, char *, uint32_t *);
STUB_DEFINE_RET4(int32_t, BSL_UIO_Read, BSL_UIO *, void *, uint32_t, uint32_t *);


typedef struct {
    int argc;
    char **argv;
    HITLS_CmdOption *opts;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

/**
 * @test UT_HITLS_APP_OptBegin_TC001
 * @spec  -
 * @title  测试HITLS_APP_OptBegine异常
 */
/* BEGIN_CASE */


void UT_HITLS_APP_OptBegin_TC001(void)
{
    HITLS_CmdOption opts[] = {{"test1", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "test1"}, {NULL, 0, 0, NULL}};
    OptTestData testData[] = {
        {0, NULL, NULL, HITLS_APP_OPT_UNKOWN}, // case1:invalid arg argc、argv、opt
        {0, NULL, opts, HITLS_APP_OPT_UNKOWN}  // case2:invalid argc and argv
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        ASSERT_EQ(HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts), testData[i].expect);
    }

EXIT:
    return;
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_OptBegin_TC002
 * @spec  -
 * @title  测试HITLS_APP_OptBegine异常
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptBegin_TC002(void)
{
    HITLS_CmdOption opts[] = {{"-test1", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "test1"}, {NULL, 0, 0, NULL}};
    char *argv[] = {"path", "help"};
    OptTestData testData[] = {
        {2, argv, opts, HITLS_APP_OPT_NAME_INVALID}, // case1： invald optname
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        ASSERT_EQ(HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_OptBegin_TC003
 * @spec  -
 * @title  测试HITLS_APP_OptBegine异常
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptBegin_TC003(void)
{
    HITLS_CmdOption opts[][4] = {
        {{"test1", 1, HITLS_APP_OPT_VALUETYPE_NONE, "test1"}, {NULL, 0, 0, NULL}},
        {{"test2", 1, HITLS_APP_OPT_VALUETYPE_NONE - 1, "test1"}, {NULL, 0, 0, NULL}},
        {{"test3", 1, HITLS_APP_OPT_VALUETYPE_MAX, "test1"}, {NULL, 0, 0, NULL}},
        {{"test4", 1, HITLS_APP_OPT_VALUETYPE_MAX + 1, "test1"}, {NULL, 0, 0, NULL}}
    };

    char *argv[] = {"path", "help"};
    OptTestData testData[] = {
        {2, argv, opts[0], HITLS_APP_OPT_VALUETYPE_INVALID}, // case1： invalid valuetype = 0
        {2, argv, opts[1], HITLS_APP_OPT_VALUETYPE_INVALID}, // case2： invalid valuetype < 0
        {2, argv, opts[2], HITLS_APP_OPT_VALUETYPE_INVALID}, // case3： invalid valuetype = max
        {2, argv, opts[3], HITLS_APP_OPT_VALUETYPE_INVALID}, // case4： invalid valuetype > max
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        ASSERT_EQ(HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_OptBegin_TC004
 * @spec  -
 * @title  测试HITLS_APP_OptBegine异常
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptBegin_TC004(void)
{
    HITLS_CmdOption opts[][4] = {
        {
            {"test1", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {"test1", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {NULL, 0, 0, NULL}
        },
        {
            {"test1", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {"test2", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {"test1", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {NULL, 0, 0, NULL}
        },
        {
            {"", 1, HITLS_APP_OPT_VALUETYPE_MAX - 1, "test1"},
            {"", 1, HITLS_APP_OPT_VALUETYPE_MAX - 1, "test1"},
            {NULL, 0, 0, NULL}
        },
        {
            {"", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {"test2", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {"", 1, HITLS_APP_OPT_VALUETYPE_NONE + 1, "test1"},
            {NULL, 0, 0, NULL}
        }
    };
    char *argv[] = {"path", "help"};
    OptTestData testData[] = {
        {2, argv, opts[0], HITLS_APP_OPT_NAME_INVALID}, // case1： optname(test1) dup (neighbour)
        {2, argv, opts[1], HITLS_APP_OPT_NAME_INVALID}, // case2： optname(test1) dup (separate)
        {2, argv, opts[2], HITLS_APP_OPT_NAME_INVALID}, // case3： optname("") dup  (neighbour)
        {2, argv, opts[3], HITLS_APP_OPT_NAME_INVALID}, // case4： optname("") dup  (separate)
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        ASSERT_EQ(HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_OptBegin_TC005
 * @spec  -
 * @title  测试HITLS_APP_OptBegine异常
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptBegin_TC005(void)
{
    HITLS_CmdOption opts[] = {{"", 1, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "test1"}, {NULL, 0, 0, NULL}};
    char *argv[] = {"path", "help"};
    OptTestData testData[] = {
        {2, argv, opts, HITLS_APP_OPT_NAME_INVALID} // case1： optname is "",but opttype is not  no value
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        ASSERT_EQ(HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_OptBegin_TC006
 * @spec  -
 * @title  测试HITLS_APP_OptBegine正常
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptBegin_TC006(void)
{
   HITLS_CmdOption opts[2][2] = {
        {{"", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "test1"},{NULL, 0, 0, NULL}},
        {{"test", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "test1"},{NULL, 0, 0, NULL}}
    };
    char *argv[] = {"test", "help"};
    OptTestData testData[] = {
        {2, argv, opts[0], HITLS_APP_SUCCESS}, // case1： HITLS_Optbegin success
        {2, argv, opts[1], HITLS_APP_SUCCESS} // case2： HITLS_Optbegin success
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        ASSERT_EQ(HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */


/**
 * @test HITLS_APP_OptNext_TC001
 * @spec  -
 * @title  测试HITLS_APP_OptNext异常
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptNext_TC001(void)
{
    HITLS_CmdOption opts[] = {
        {"", 1, HITLS_APP_OPT_VALUETYPE_STRING, "test1"},
        {"test", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "test1"},
        {NULL, 0, 0, NULL}
    };
    char *argv[3][2] = {{"help", "-"}, {"help", "--"}, {"help", NULL}};
    OptTestData testData[] = {
        {1, argv[0], opts, HITLS_APP_OPT_ERR}, // case1： input arg only contain "-"
        {2, argv[1], opts, HITLS_APP_OPT_ERR}, // case2： input arg only contain "--"
        {2, argv[2], opts, HITLS_APP_OPT_EOF}
    }; // case3： input arg is  NULL
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        (void)HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts);
        ASSERT_EQ(HITLS_APP_OptNext(), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test HITLS_OptNext_TC002
 * @spec  -
 * @title  测试HITLS_OptNext异常
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptNext_TC002(void)
{
    char testcmd[] = "-test=21";
    HITLS_CmdOption opts[] = {
        {"11", 1, HITLS_APP_OPT_VALUETYPE_STRING, "test1"},
        {"test", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "test1"},
        {"test2", 1, HITLS_APP_OPT_VALUETYPE_STRING, "test2"},
        {NULL, 0, 0, NULL},
        {NULL, 0, 0, NULL}
    };
    char *argv[][3] = {
        {"help", "-test"},        // case1:no opt value
        {"help", testcmd  },      // case2: -key=value not support
        {"help", "-test2", NULL}, // case3: opt should have value,but input isn't opt's value
        {"help", "-xxx"}          // case4: invalid opt
    };
    OptTestData testData[] = {
        {2, argv[0], opts, 1},
        {2, argv[1], opts, HITLS_APP_OPT_ERR},
        {3, argv[2], opts, HITLS_APP_OPT_ERR},
        {2, argv[3], opts, HITLS_APP_OPT_ERR},
    };
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        (void)HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts);
        ASSERT_EQ(HITLS_APP_OptNext(), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */
HITLS_CmdOption g_tc003Opts[] = {
    {"novalue", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "test"},
    {"infile", 1, HITLS_APP_OPT_VALUETYPE_IN_FILE, "test1"},
    {"outfile", 1, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "test2"},
    {"string", 1, HITLS_APP_OPT_VALUETYPE_STRING, "test2"},
    {"params", 1, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "test2"},
    {"dir", 1, HITLS_APP_OPT_VALUETYPE_DIR, "test2"},
    {"int", 1, HITLS_APP_OPT_VALUETYPE_INT, "test2"},
    {"uint", 1, HITLS_APP_OPT_VALUETYPE_UINT, "test2"},
    {"pint", 1, HITLS_APP_OPT_VALUETYPE_POSITIVE_INT, "test2"},
    {"long", 1, HITLS_APP_OPT_VALUETYPE_LONG, "test2"},
    {"ulong", 1, HITLS_APP_OPT_VALUETYPE_ULONG, "test2"},
    {"pemder", 1, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "test2"},
    {"any", 1, HITLS_APP_OPT_VALUETYPE_FMT_ANY, "test2"},
    {NULL, 0, 0, NULL}
};
char *g_tc003Argv[][3] = {
    {"help", "-novalue", NULL},      // 0 novalue tpye case
    {"help", "-infile", "1.txt"},    // 1 infiletype case
    {"help", "-outfile", "1.txt"},   // 2 outfiletype case
    {"help", "-string", "11111"},    // 3 string case
    {"help", "-params", "1211"},     // 4 params case
    {"help", "-dir", "."},           // 5 dir case
    {"help", "-int", "131231"},      // 6 int > 0 case
    {"help", "-int", "-131231"},     // 7 int < 0 case
    {"help", "-uint", "131231"},     // 8 uint > 0 case
    {"help", "-uint", "-131231"},    // 9 uint < 0 case
    {"help", "-uint", "3147483637"}, // 10 uint > max_uint case
    {"help", "-pint", "13123"},      // 11 positive int > 0 case
    {"help", "-pint", "0"},          // 12 positive int = 0 case
    {"help", "-long", "13123"},      // 13 long > 0 case
    {"help", "-ulong", "13123"},     // 14 ulong > 0 case
    {"help", "-ulong", "1312312"},   // 15 ulong > 0 case
    {"help", "-pemder", "PEM"},      // 16 pem case
    {"help", "-pemder", "DER"},      // 17 der case
    {"help", "-pemder", "xxx"},      // 18 any case
    {"help", "-any", "PEM"},         // 19 any case
    {"help", "-dir", NULL},          // 20 dir (value is NULL) case
    {"help", "-dir", "1"},           // 21 dir (not exist) case
};
OptTestData g_tc003TestData[] = {
    {3, g_tc003Argv[0], g_tc003Opts, 1},
    {3, g_tc003Argv[1], g_tc003Opts, 1},
    {3, g_tc003Argv[2], g_tc003Opts, 1},
    {3, g_tc003Argv[3], g_tc003Opts, 1},
    {3, g_tc003Argv[4], g_tc003Opts, 1},
    {3, g_tc003Argv[5], g_tc003Opts, 1},
    {3, g_tc003Argv[6], g_tc003Opts, 1},
    {3, g_tc003Argv[7], g_tc003Opts, 1},
    {3, g_tc003Argv[8], g_tc003Opts, 1},
    {3, g_tc003Argv[9], g_tc003Opts, -1},
    {3, g_tc003Argv[10], g_tc003Opts, -1},
    {3, g_tc003Argv[11], g_tc003Opts, 1},
    {3, g_tc003Argv[12], g_tc003Opts, 1},
    {3, g_tc003Argv[13], g_tc003Opts, 1},
    {3, g_tc003Argv[14], g_tc003Opts, 1},
    {3, g_tc003Argv[15], g_tc003Opts, 1},
    {3, g_tc003Argv[16], g_tc003Opts, 1},
    {3, g_tc003Argv[17], g_tc003Opts, 1},
    {3, g_tc003Argv[18], g_tc003Opts, -1},
    {3, g_tc003Argv[19], g_tc003Opts, 1},
    {3, g_tc003Argv[20], g_tc003Opts, -1},
    {3, g_tc003Argv[21], g_tc003Opts, -1},
    {3, g_tc003Argv[21], g_tc003Opts, -1},
};

/**
 * @test HITLS_APP_OptNext_TC003
 * @spec  -
 * @title  测试HITLS_APP_OptNext中各类值类型
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptNext_TC003(void)
{
    AppPrintErrorUioInit(stderr);
    for (int i = 0; i < (int)(sizeof(g_tc003TestData) / sizeof(OptTestData)); i++) {
        (void)HITLS_APP_OptBegin(g_tc003TestData[i].argc, g_tc003TestData[i].argv, g_tc003TestData[i].opts);
        ASSERT_EQ(HITLS_APP_OptNext(), g_tc003TestData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_OptNext_TC004
 * @spec  -
 * @title  测试HITLS_APP_OptNext函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptNext_TC004(void)
{
    enum OptType{param = 0,help,cipher};
    HITLS_CmdOption opts[] = {
        {"help",help , HITLS_APP_OPT_VALUETYPE_NO_VALUE, "print help"},
        {"",cipher,HITLS_APP_OPT_VALUETYPE_NO_VALUE,"cipher alg" },
        {"param", param, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "input paramters"},
        {NULL, 0, 0, NULL}
    };

    char *argv[][3] = {
        {"cmd", "-help", NULL},
        {"cmd", "-aes128-cbc", NULL},
        {"cmd", "a", "b"}
    };

    OptTestData testData[] = {
        {3, argv[0], opts, help},
        {3, argv[1], opts, cipher},
        {3, argv[2], opts, param},
    };
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        (void)HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts);
        ASSERT_EQ(HITLS_APP_OptNext(), testData[i].expect);
        HITLS_APP_OptEnd();
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_GetRestOptNum_TC001
 * @spec  -
 * @title  测试HITLS_APP_GetRestOptNum函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_GetRestOptNum_TC001(void)
{
    char *argv[] = {"help", "-infile", "1.txt"};
    HITLS_CmdOption opts[] = {
        {"infile", 1, HITLS_APP_OPT_VALUETYPE_IN_FILE, "test1"},
        {NULL, 0, 0, NULL}
    };
    OptTestData testData[] = {
        {3, argv, opts, 2} // case1: rest opt number
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        (void)HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts);
        ASSERT_EQ(HITLS_APP_GetRestOptNum(), testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_GetRestOpt_TC001
 * @spec  -
 * @title  测试UT_HITLS_APP_GetRestOpt函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_GetRestOpt_TC001(void)
{
    char *argv[] = {"help", "-infile", "1.txt"};
    HITLS_CmdOption opts[] = {
        {"infile", 1, HITLS_APP_OPT_VALUETYPE_IN_FILE, "test1"}, // case1: rest opt number
        {NULL, 0, 0, NULL}
    };
    OptTestData testData[] = {
        {3, argv, opts, 1}
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); i++) {
        (void)HITLS_APP_OptBegin(testData[i].argc, testData[i].argv, testData[i].opts);
        ASSERT_EQ(HITLS_APP_GetRestOpt() == &argv[1], testData[i].expect);
    }
EXIT:
    return;
}
/* END_CASE */

static bsl_sal_file_handle fileHandle = NULL;
static int32_t InitStderrUIOForFp(const char *filename, const char *mode)
{
    int32_t ret = BSL_SAL_FileOpen(&fileHandle, filename, mode);
    if (ret != BSL_SUCCESS) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    return AppPrintErrorUioInit(fileHandle);
}

#define MAX_BUF_SIZE (1024 * 2)
static int32_t CheckResult()
{
    char buf[MAX_BUF_SIZE] = {0};
    size_t len;
    int32_t ret = BSL_SAL_FileOpen(&fileHandle, "test.dat", "r");
    if (ret != BSL_SUCCESS) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    ret = BSL_SAL_FileRead(fileHandle, buf, sizeof(buf) / sizeof(char), sizeof(char), &len);
    if (ret != BSL_SUCCESS) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    (void)BSL_SAL_FileClose(fileHandle);
    fileHandle = NULL;
    /* check infile opt */
    if (strstr(buf, "-infile infile  input infile") == NULL) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }

    /* check inint opt */
    if (strstr(buf, "-inint int      input int") == NULL) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }

    /* check help opt */
    if (strstr(buf, "-help           print help") == NULL) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    /* check param opt */
    if (strstr(buf, "[param]         input paramters") == NULL) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }

    return HITLS_APP_SUCCESS;
}

static void *TestOptHelpPrint(void *args)
{
    (void)args;
    HITLS_CmdOption opts[] = {
        {"infile", 1, HITLS_APP_OPT_VALUETYPE_IN_FILE, "input infile"},     // case1: rest opt number
        {"inint", 1, HITLS_APP_OPT_VALUETYPE_INT, "input int"},             // case1: rest opt number
        {"help", 1, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "print help"},        // case1: rest opt number
        {"param", 1, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "input paramters"}, // case1: rest opt number
        {NULL, 0, 0, NULL}
    };
    char *argv[] = {"help"};
    ASSERT_TRUE(InitStderrUIOForFp("test.dat", "w+") == HITLS_APP_SUCCESS);
    HITLS_APP_OptBegin(1, argv, opts);
    HITLS_APP_OptHelpPrint(opts);
    AppPrintErrorUioUnInit();
    (void)BSL_SAL_FileClose(fileHandle);
    fileHandle = NULL;
    ASSERT_TRUE(CheckResult() == HITLS_APP_SUCCESS);
EXIT:
    return NULL;
}

/**
 * @test UT_HITLS_APP_OptHelpPrint_TC001
 * @spec  -
 * @title  测试HITLS_APP_OptHelpPrint函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptHelpPrint_TC001(void)
{
    TestOptHelpPrint(NULL);
}
/* END_CASE */

typedef struct{
    char* filename;
    char mode;
    int32_t flag;
}OptUioData;

/**
 * @test UT_HITLS_APP_OptUioOpen_TC001
 * @spec  -
 * @title   UT_HITLS_APP_OptUioOpen_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptUioOpen_TC001(void)
{
    OptUioData testData[] = {
        {NULL, 'w', 0},
        {NULL, 'r', 0},
        {"1.txt", 'w', 0},
        {"1.txt", 'r', 0},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptUioData)); ++i) {
        BSL_UIO *ret = HITLS_APP_UioOpen(testData[i].filename, testData[i].mode, testData[i].flag);
        ASSERT_TRUE(ret != NULL);
        BSL_UIO_Free(ret);
    }

EXIT:
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
 * @test UT_HITLS_APP_OptUioOpen_TC002
 * @spec  -
 * @title   UT_HITLS_APP_OptUioOpen_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptUioOpen_TC002(void)
{
    STUB_REPLACE(BSL_UIO_Ctrl, STUB_BSL_UIO_Ctrl);;

    OptUioData testData[] = {
        {NULL, 'w', 0},
        {NULL, 'a', 0},
        {NULL, 'b', 0},
        {NULL, 'r', 0},
        {"1.txt", 'w', 0},
        {"1.txt", 'a', 0},
        {"1.txt", 'b', 0},
        {"1.txt", 'r', 0},
        {"D:\\outfile\\1.txt", 'w', 0},
        {"D:\\outfile\\1.txt", 'r', 0},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptUioData)); ++i) {
        BSL_UIO *uio = HITLS_APP_UioOpen(testData[i].filename, testData[i].mode, testData[i].flag);
        ASSERT_TRUE(uio == NULL);
    }

EXIT:
    STUB_RESTORE(BSL_UIO_Ctrl);
    return;
}
/* END_CASE */

BSL_UIO *STUB_BSL_UIO_New(const BSL_UIO_Method *method)
{
    (void)method;
    return NULL;
}
/**
 * @test UT_HITLS_APP_OptUioOpen_TC003
 * @spec  -
 * @title   UT_HITLS_APP_OptUioOpen_TC003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptUioOpen_TC003(void)
{
    STUB_REPLACE(BSL_UIO_New, STUB_BSL_UIO_New);;

    OptUioData testData[] = {
        {NULL, 'w', 0},
        {NULL, 'r', 0},
        {"1.txt", 'w', 0},
        {"1.txt", 'r', 0}
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptUioData)); ++i) {
        BSL_UIO *uio = HITLS_APP_UioOpen(testData[i].filename, testData[i].mode, testData[i].flag);
        ASSERT_TRUE(uio == NULL);
    }

EXIT:
    STUB_RESTORE(BSL_UIO_New);
    return;
}
/* END_CASE */

typedef struct {
    BSL_UIO *uio;
    uint8_t *buf;
    uint32_t outLen;
    int32_t format;
    int32_t expect;
} OutputUioData;

/**
 * @test UT_HITLS_APP_OptUioOut_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_OptUioOut_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptUioOut_TC001(void)
{
    BSL_UIO *uio[] = {
        HITLS_APP_UioOpen(NULL, 'w', 0),
        HITLS_APP_UioOpen("D:\\outfile\\1.txt", 'w', 0),
        HITLS_APP_UioOpen("1.txt", 'w', 0),
        HITLS_APP_UioOpen(NULL, 'w', 0),
        HITLS_APP_UioOpen(NULL, 'w', 0),
        HITLS_APP_UioOpen(NULL, 'w', 0)
    };

    uint8_t buf[10] = {"123456789"};

    OutputUioData testData[] = {
        {uio[0], buf, 10, HITLS_APP_FORMAT_BASE64, HITLS_APP_SUCCESS},
        {uio[1], buf, 10, HITLS_APP_FORMAT_HEX, HITLS_APP_SUCCESS},
        {uio[2], buf, 10, HITLS_APP_FORMAT_BINARY, HITLS_APP_SUCCESS},
        {uio[3], NULL, 10, HITLS_APP_FORMAT_BASE64, HITLS_APP_INTERNAL_EXCEPTION},
        {uio[4], NULL, 10, HITLS_APP_FORMAT_HEX, HITLS_APP_INTERNAL_EXCEPTION},
        {uio[5], buf, 0, HITLS_APP_FORMAT_BINARY, HITLS_APP_INTERNAL_EXCEPTION},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OutputUioData)); ++i) {
        int ret = HITLS_APP_OptWriteUio(testData[i].uio, testData[i].buf, testData[i].outLen, testData[i].format);
        BSL_UIO_Free(testData[i].uio);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    return;
}
/* END_CASE */

int32_t STUB_BSL_UIO_Write(BSL_UIO *uio, const void *data, uint32_t len, uint32_t *writeLen)
{
    (void)uio;
    (void)data;
    (void)len;
    (void)writeLen;
    return BSL_INTERNAL_EXCEPTION;
}

/**
 * @test UT_HITLS_APP_OptUioOut_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_OptUioOut_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptUioOut_TC002(void)
{
    STUB_REPLACE(BSL_UIO_Write, STUB_BSL_UIO_Write);;

    BSL_UIO *uio[] = {
        HITLS_APP_UioOpen(NULL, 'w', 0),
        HITLS_APP_UioOpen(NULL, 'w', 0),
        HITLS_APP_UioOpen("1.txt", 'w', 0),
        HITLS_APP_UioOpen("1.txt", 'w', 0),
    };

    uint8_t buf[][1024] = {"123456789qweeeeeeqweqweqweqwasd12312", "1234567893123123123123123", "", "NULL"};
    OutputUioData testData[] = {
        {uio[0], buf[0], 1024, HITLS_APP_FORMAT_BASE64, HITLS_APP_UIO_FAIL},
        {uio[1], buf[1], 1024, HITLS_APP_FORMAT_HEX, HITLS_APP_UIO_FAIL},
        {uio[2], buf[1], 1024, HITLS_APP_FORMAT_BINARY, HITLS_APP_UIO_FAIL},
        {uio[3], buf[2], 1024, HITLS_APP_FORMAT_BASE64, HITLS_APP_UIO_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OutputUioData)); ++i) {
        int ret = HITLS_APP_OptWriteUio(testData[i].uio, testData[i].buf, testData[i].outLen, testData[i].format);
        BSL_UIO_Free(testData[i].uio);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(BSL_UIO_Write);
    return;
}
/* END_CASE */

int32_t STUB_BSL_Base64Encode(const uint8_t *srcBuf, const uint32_t srcBufLen, char *dstBuf, uint32_t *dstBufLen)
{
    (void)srcBuf;
    (void)srcBufLen;
    (void)dstBuf;
    (void)dstBufLen;
    return BSL_UIO_FAIL;
}

/**
 * @test UT_HITLS_APP_OptUioOut_TC003
 * @spec  -
 * @title   测试UT_HITLS_APP_OptUioOut_TC003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptUioOut_TC003(void)
{
    STUB_REPLACE(BSL_BASE64_Encode, STUB_BSL_Base64Encode);;

    BSL_UIO *uio[] = {
        HITLS_APP_UioOpen(NULL, 'w', 0),
        HITLS_APP_UioOpen(NULL, 'w', 0),
        HITLS_APP_UioOpen("1.txt", 'w', 0),
        HITLS_APP_UioOpen("1.txt", 'w', 0),
    };

    uint8_t buf[][1024] = {"123456789qweeeeeeqweqweqweqwasd12312", "1234567893123123123123123", "", "NULL"};
    OutputUioData testData[] = {
        {uio[0], buf[0], 1024, HITLS_APP_FORMAT_BASE64, HITLS_APP_ENCODE_FAIL},
        {uio[1], NULL, 1024, HITLS_APP_FORMAT_BASE64, HITLS_APP_INTERNAL_EXCEPTION},
        {uio[2], buf[2], 1024, HITLS_APP_FORMAT_BASE64, HITLS_APP_ENCODE_FAIL},
        {uio[3], buf[3], 1024, HITLS_APP_FORMAT_BASE64, HITLS_APP_ENCODE_FAIL},
    };

    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OutputUioData)); ++i) {
        int ret = HITLS_APP_OptWriteUio(testData[i].uio, testData[i].buf, testData[i].outLen, testData[i].format);
        BSL_UIO_Free(testData[i].uio);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    STUB_RESTORE(BSL_BASE64_Encode);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_OptToBase64_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_OptToBase64_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptToBase64_TC001(void)
{
    uint8_t str[] = "hello, world";
    char outBuf[1024] = {0};
    int ret = HITLS_APP_OptToBase64(str, 0, outBuf, 1024);
    ASSERT_EQ(ret, HITLS_APP_INTERNAL_EXCEPTION);
    int ret1 = HITLS_APP_OptToBase64(NULL, 12, outBuf, 1024);
    ASSERT_EQ(ret1, HITLS_APP_INTERNAL_EXCEPTION);
    int ret2 = HITLS_APP_OptToBase64(str, 12, NULL, 1024);
    ASSERT_EQ(ret2, HITLS_APP_INTERNAL_EXCEPTION);
    int ret3 = HITLS_APP_OptToBase64(str, 12, outBuf, 0);
    ASSERT_EQ(ret3, HITLS_APP_INTERNAL_EXCEPTION);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_OptToHex_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_OptToHex_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_OptToHex_TC001(void)
{
    uint8_t str[] = "hello, world";
    char outBuf[1024] = {0};
    int ret = HITLS_APP_OptToHex(str, 0, outBuf, 1024);
    ASSERT_EQ(ret, HITLS_APP_INTERNAL_EXCEPTION);
    int ret1 = HITLS_APP_OptToHex(NULL, 12, outBuf, 1024);
    ASSERT_EQ(ret1, HITLS_APP_INTERNAL_EXCEPTION);
    int ret2 = HITLS_APP_OptToHex(str, 12, NULL, 1024);
    ASSERT_EQ(ret2, HITLS_APP_INTERNAL_EXCEPTION);
    int ret3 = HITLS_APP_OptToHex(str, 12, outBuf, 0);
    ASSERT_EQ(ret3, HITLS_APP_INTERNAL_EXCEPTION);
    int ret4 = HITLS_APP_OptToHex(str, 12, outBuf, 4);
    ASSERT_EQ(ret4, HITLS_APP_INTERNAL_EXCEPTION);
EXIT:
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

int32_t CreateFile(const char *fileName, const char *data)
{
    size_t dataLen = strlen(data);
    FILE *f = fopen(fileName, "w");
    ASSERT_EQ(fwrite(data, dataLen, 1, f), 1);
    (void)fclose(f);
    return 1;
EXIT:
    return 0;
}

/* @
* @test  UT_HITLS_APP_Opt_Write_TC001
* @spec  -
* @title  file uio 测试: "w"模式打开文件，不存在则新建，存在则删除后再新建
@ */
/* BEGIN_CASE */
void UT_HITLS_APP_Opt_Write_TC001(void)
{
    const char *data = "1";
    uint32_t dataLen = strlen(data);
    BSL_UIO *uio = NULL;
    char *testFile = "uio.txt";
    ASSERT_TRUE(IsFileExist(testFile) == false);
    uio = HITLS_APP_UioOpen(testFile, 'w', 1);
    ASSERT_TRUE(uio != NULL);
    ASSERT_TRUE(IsFileExist(testFile));
    ASSERT_EQ(HITLS_APP_OptWriteUio(uio, (uint8_t *)data, dataLen, HITLS_APP_FORMAT_BINARY), HITLS_APP_SUCCESS);
EXIT:
    BSL_UIO_Free(uio);
    remove(testFile);
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_Opt_Uio_Read_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_Opt_Uio_Read_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_Opt_Uio_Read_TC001(void)
{
    char *testFile = "file_uio.txt";
    char data[] = "0123456789abcdef";
    uint32_t dataLen = strlen(data);
    BSL_UIO *uio = NULL;
    uint8_t *readBuf = NULL;
    uint64_t readBufLen = 0;
    ASSERT_TRUE(IsFileExist(testFile) == false);
    ASSERT_EQ(HITLS_APP_OptReadUio(uio, &readBuf, &readBufLen, 0), HITLS_APP_INTERNAL_EXCEPTION);
    ASSERT_EQ(CreateFile(testFile, data), 1);
    ASSERT_TRUE(IsFileExist(testFile));
    uio = HITLS_APP_UioOpen(testFile, 'r', 0);
    ASSERT_TRUE(uio != NULL);

    ASSERT_EQ(HITLS_APP_OptReadUio(uio, &readBuf, &readBufLen, 2048), HITLS_APP_SUCCESS);
    ASSERT_EQ(readBufLen, dataLen);
EXIT:
    BSL_UIO_Free(uio);
    BSL_SAL_FREE(readBuf);
    remove(testFile);
    return;
}
/* END_CASE */

int32_t STUB_BSL_UIO_Read(BSL_UIO *uio, void *data, uint32_t len, uint32_t *readLen)
{
    (void)uio;
    (void)data;
    (void)len;
    (void)readLen;
    return HITLS_APP_UIO_FAIL;
}

/**
 * @test UT_HITLS_APP_Opt_Uio_Read_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_Opt_Uio_Read_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_Opt_Uio_Read_TC002(void)
{
    char *testFile = "file_read_uio.txt";
    const char *data = "0123456789abcdef";
    BSL_UIO *uio = NULL;
    uint8_t *readBuf = NULL;
    uint64_t readBufLen = 0;
    ASSERT_EQ(CreateFile(testFile, data), 1);
    uio = HITLS_APP_UioOpen(testFile, 'r', 0);
    ASSERT_TRUE(uio != NULL);
    STUB_REPLACE(BSL_UIO_Read, STUB_BSL_UIO_Read);;
    ASSERT_EQ(HITLS_APP_OptReadUio(uio, &readBuf, &readBufLen, 0), HITLS_APP_UIO_FAIL);
    testFile = NULL;
    ASSERT_EQ(HITLS_APP_OptReadUio(uio, &readBuf, &readBufLen, 0), HITLS_APP_UIO_FAIL);

EXIT:
    BSL_UIO_Free(uio);
    BSL_SAL_FREE(readBuf);
    remove(testFile);
    STUB_RESTORE(BSL_UIO_Read);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_Opt_Uio_Read_TC003
 * @spec  -
 * @title   测试UT_HITLS_APP_Opt_Uio_Read_TC003函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_Opt_Uio_Read_TC003(void)
{
    STUB_REPLACE(BSL_UIO_Ctrl, STUB_BSL_UIO_Ctrl);;
    char *testFile = "file_read_uio.txt";
    const char *data = "0123456789abcdef";
    BSL_UIO *uio = NULL;
    uint8_t *readBuf = NULL;
    uint64_t readBufLen = 0;

    ASSERT_EQ(CreateFile(testFile, data), 1);
    uio = HITLS_APP_UioOpen(testFile, 'r', 0);
    ASSERT_TRUE(uio == NULL);
    ASSERT_EQ(HITLS_APP_OptReadUio(uio, &readBuf, &readBufLen, 0), HITLS_APP_INTERNAL_EXCEPTION);

EXIT:
    BSL_UIO_Free(uio);
    BSL_SAL_FREE(readBuf);
    remove(testFile);
    STUB_RESTORE(BSL_UIO_Ctrl);
    return;
}
/* END_CASE */