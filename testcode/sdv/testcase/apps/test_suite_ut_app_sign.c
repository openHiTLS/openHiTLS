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
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_provider.h"
#include "bsl_uio.h"
#include "bsl_errno.h"
/* END_HEADER */

#define SIGN_TMP_FILE "sign.sig"
#define SIGN_MAX_ARGC 32
#define SIGN_OPTS_MAX_LEN 4096

static void PreProcArgs(char *args, int *argc, char **argv)
{
    size_t len = strlen(args);
    argv[(*argc)++] = args;
    for (size_t i = 0; i < len; i++) {
        if (args[i] == ' ') {
            args[i] = '\0';
            argv[(*argc)++] = args + i + 1;
        }
    }
}

int32_t HITLS_SignMain(int argc, char *argv[]);

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

static int32_t RunSignVerifyCase(const char *msgPath,
                                 const char *prvKeyPath,
                                 const char *pubKeyPath,
                                 const char *pkeyAlg,
                                 const char *digestName)
{
    char *signArgv[20] = {
        "sign",
        "-in",     (char *)msgPath,
        "-out",    SIGN_TMP_FILE,
        "-key",    (char *)prvKeyPath,
        "-pkeyalg", (char *)pkeyAlg,
        "-digest", (char *)digestName,
        NULL
    };
    int signArgc = 0;
    while (signArgv[signArgc] != NULL) {
        signArgc++;
    }

    char *verifyArgv[20] = {
        "sign",
        "-verify",
        "-in",     (char *)msgPath,
        "-sig",    SIGN_TMP_FILE,
        "-pubkey", (char *)pubKeyPath,
        "-pkeyalg", (char *)pkeyAlg,
        "-digest", (char *)digestName,
        NULL
    };
    int verifyArgc = 0;
    while (verifyArgv[verifyArgc] != NULL) {
        verifyArgc++;
    }

    int32_t ret = HITLS_SignMain(signArgc, signArgv);
    if (ret != HITLS_APP_SUCCESS) {
        (void)remove(SIGN_TMP_FILE);
        return ret;
    }

    ret = HITLS_SignMain(verifyArgc, verifyArgv);
    (void)remove(SIGN_TMP_FILE);
    return ret;
}

/* BEGIN_CASE */
void UT_HITLS_APP_SIGN_TC001(void)
{
    const char *msgPath      = "../testdata/apps/sign/test.txt";
    const char *sm2PrvPath   = "../testdata/apps/sign/sm2_priv.pem";
    const char *sm2PubPath   = "../testdata/apps/sign/sm2_pub.pem";
    const char *ecdsaPrvPath = "../testdata/apps/sign/ecdsa_priv.pem";
    const char *ecdsaPubPath = "../testdata/apps/sign/ecdsa_pub.pem";

    ASSERT_EQ(AppInit(), HITLS_APP_SUCCESS);

    ASSERT_EQ(RunSignVerifyCase(msgPath, sm2PrvPath, sm2PubPath,
                                "sm2", "sm3"),
              HITLS_APP_SUCCESS);

    ASSERT_EQ(RunSignVerifyCase(msgPath, ecdsaPrvPath, ecdsaPubPath,
                                "ecdsa", "sm3"),
              HITLS_APP_SUCCESS);

    ASSERT_EQ(RunSignVerifyCase(msgPath, ecdsaPrvPath, ecdsaPubPath,
                                "ecdsa", "sha256"),
              HITLS_APP_SUCCESS);

    ASSERT_EQ(RunSignVerifyCase(msgPath, ecdsaPrvPath, ecdsaPubPath,
                                "ecdsa", "sha384"),
              HITLS_APP_SUCCESS);

    ASSERT_EQ(RunSignVerifyCase(msgPath, ecdsaPrvPath, ecdsaPubPath,
                                "ecdsa", "sha512"),
              HITLS_APP_SUCCESS);

    ASSERT_EQ(RunSignVerifyCase(msgPath, ecdsaPrvPath, ecdsaPubPath,
                                "ecdsa", "sha1"),
              HITLS_APP_SUCCESS);

EXIT:
    AppUninit();
    (void)remove(SIGN_TMP_FILE);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_SIGN_TC002(char *opts, int expectRet)
{
    int argc = 0;
    char *argv[SIGN_MAX_ARGC] = {0};
    size_t len = strlen(opts);
    if (len <= 0 || len > SIGN_OPTS_MAX_LEN) {
        return;
    }
    char *tmp = (char *)malloc(len + 1);
    ASSERT_NE(tmp, NULL);
    (void)memcpy(tmp, opts, len + 1);

    PreProcArgs(tmp, &argc, argv);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);

    ASSERT_EQ(HITLS_SignMain(argc, argv), expectRet);

EXIT:
    AppPrintErrorUioUnInit();
    if (tmp != NULL) {
        free(tmp);
    }
    (void)remove(SIGN_TMP_FILE);
    return;
}
/* END_CASE */