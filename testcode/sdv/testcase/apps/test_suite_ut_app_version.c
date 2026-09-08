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
#include <stdbool.h>
#include <string.h>
#include "app_errno.h"
#include "app_print.h"
#include "app_version.h"
#include "bsl_errno.h"
#include "bsl_version.h"
#include "stub_utils.h"
/* END_HEADER */

#define VERSION_OUTPUT_BUF_SIZE 128

STUB_DEFINE_RET4(int32_t, BSL_UIO_Write, BSL_UIO *, const void *, uint32_t, uint32_t *);

static uint8_t g_versionOutput[VERSION_OUTPUT_BUF_SIZE];
static uint32_t g_versionOutputLen;

static bool IsStdoutUio(BSL_UIO *uio)
{
    FILE *fp = NULL;
    return uio != NULL && BSL_UIO_Ctrl(uio, BSL_UIO_FILE_GET_PTR, 0, &fp) == BSL_SUCCESS && fp == stdout;
}

static int32_t STUB_BSL_UIO_Write(BSL_UIO *uio, const void *data, uint32_t len, uint32_t *writeLen)
{
    if (writeLen == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }
    if (!IsStdoutUio(uio)) {
        *writeLen = len;
        return BSL_SUCCESS;
    }
    if (data == NULL || len > VERSION_OUTPUT_BUF_SIZE - g_versionOutputLen) {
        return BSL_INTERNAL_EXCEPTION;
    }
    (void)memcpy(g_versionOutput + g_versionOutputLen, data, len);
    g_versionOutputLen += len;
    *writeLen = len;
    return BSL_SUCCESS;
}

typedef struct {
    int argc;
    char **argv;
    int expect;
} VersionTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_version.c
    ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

/**
 * @test UT_HITLS_APP_VERSION_TC001
 * @spec  -
 * @title   Test version command options
 */
/* BEGIN_CASE */
void UT_HITLS_APP_VERSION_TC001(void)
{
    char *argv[][3] = {
        {"version"},
        {"version", "-help"},
        {"version", "--help"},
        {"version", "extra"},
        {"version", "-unknown"}
    };

    VersionTestData testData[] = {
        {1, argv[0], HITLS_APP_SUCCESS},
        {2, argv[1], HITLS_APP_HELP},
        {2, argv[2], HITLS_APP_HELP},
        {2, argv[3], HITLS_APP_OPT_UNKOWN},
        {2, argv[4], HITLS_APP_OPT_UNKOWN}
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(VersionTestData)); ++i) {
        int ret = HITLS_VersionMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_VERSION_TC002
 * @spec  -
 * @title   Test version command output
 */
/* BEGIN_CASE */
void UT_HITLS_APP_VERSION_TC002(void)
{
    char *argv[] = {"version"};

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    const char *version = HITLS_Version();
    uint32_t versionLen = (uint32_t)strlen(version);
    ASSERT_LT(versionLen, VERSION_OUTPUT_BUF_SIZE);
    (void)memset(g_versionOutput, 0, sizeof(g_versionOutput));
    g_versionOutputLen = 0;
    STUB_REPLACE(BSL_UIO_Write, STUB_BSL_UIO_Write);
    int ret = HITLS_VersionMain(1, argv);
    STUB_RESTORE(BSL_UIO_Write);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    ASSERT_EQ(g_versionOutputLen, versionLen + 1);
    ASSERT_EQ(memcmp(g_versionOutput, version, versionLen), 0);
    ASSERT_EQ(g_versionOutput[versionLen], '\n');

EXIT:
    STUB_RESTORE(BSL_UIO_Write);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
