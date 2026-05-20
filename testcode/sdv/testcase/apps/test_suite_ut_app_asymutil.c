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
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* BEGIN_HEADER */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "app_opt.h"
#include "app_print.h"
#include "sal_file.h"
#include "bsl_uio.h"
#include "bsl_ui.h"
#include "uio_abstraction.h"
#include "app_errno.h"
#include "crypt_errno.h"
#include "app_asymutil.h"
#include "app_function.h"
#include "app_provider.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "stub_utils.h"
/* END_HEADER */

#define ASYMUTIL_ENC_OUT_FILE "asymutil_enc_out.bin"
#define ASYMUTIL_DEC_OUT_FILE "asymutil_dec_out.bin"

static int32_t CompareFileByPath(const char *file1, const char *file2)
{
    int32_t ret = 1;
    BSL_Buffer buf1 = {0};
    BSL_Buffer buf2 = {0};

    ASSERT_EQ(BSL_SAL_ReadFile(file1, &buf1.data, &buf1.dataLen), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(file2, &buf2.data, &buf2.dataLen), 0);
    ASSERT_EQ(buf1.dataLen, buf2.dataLen);
    ASSERT_COMPARE("Compare asymutil output",
                   buf1.data, buf1.dataLen,
                   buf2.data, buf2.dataLen);
    ret = 0;
EXIT:
    BSL_SAL_Free(buf1.data);
    BSL_SAL_Free(buf2.data);
    return ret;
}

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

/* BEGIN_CASE */
void UT_HITLS_APP_ASYMUTIL_TC001(char *pubKeyPath, char *priKeyPath, char *plainPath)
{
    char *encArgv[20] = {
        "asymutil",
        "-keylen", "1024",
        "-enc",
        "-in",  plainPath,
        "-out", ASYMUTIL_ENC_OUT_FILE,
        "-passfile", pubKeyPath,
        "-pkeyalg", "rsa",
        NULL,
    };
    int encArgc = 0;
    while (encArgv[encArgc] != NULL) {
        encArgc++;
    }

    char *decArgv[20] = {
        "asymutil",
        "-keylen", "1024",
        "-dec",
        "-in",  ASYMUTIL_ENC_OUT_FILE,
        "-out", ASYMUTIL_DEC_OUT_FILE,
        "-passfile", priKeyPath,
        "-pkeyalg", "rsa",
        NULL,
    };
    int decArgc = 0;
    while (decArgv[decArgc] != NULL) {
        decArgc++;
    }

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_AsymutilMain(encArgc, encArgv);
    (void)fflush(stdout);
    (void)freopen("/dev/tty", "w", stdout);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_AsymutilMain(decArgc, decArgv);
    (void)fflush(stdout);
    (void)freopen("/dev/tty", "w", stdout);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ASSERT_EQ(CompareFileByPath(ASYMUTIL_DEC_OUT_FILE, plainPath), 0);

EXIT:
    AppUninit();
    (void)remove(ASYMUTIL_ENC_OUT_FILE);
    (void)remove(ASYMUTIL_DEC_OUT_FILE);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_ASYMUTIL_TC002(char *priKeyPath, char *cipherPath, char *expectPlainPath)
{
    char *argv[20] = {
        "asymutil",
        "-keylen", "1024",
        "-dec",
        "-in",  cipherPath,
        "-out", ASYMUTIL_DEC_OUT_FILE,
        "-passfile", priKeyPath,
        "-pkeyalg", "rsa",
        NULL,
    };
    int argc = 0;
    while (argv[argc] != NULL) {
        argc++;
    }

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_AsymutilMain(argc, argv);
    (void)fflush(stdout);
    (void)freopen("/dev/tty", "w", stdout);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ASSERT_EQ(CompareFileByPath(ASYMUTIL_DEC_OUT_FILE, expectPlainPath), 0);

EXIT:
    AppUninit();
    (void)remove(ASYMUTIL_DEC_OUT_FILE);
    return;
}
/* END_CASE */