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

#include "app_pkey.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <securec.h>
#include <limits.h>
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_list.h"
#include "app_utils.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"

typedef enum {
    HITLS_APP_OPT_IN = 2,
    HITLS_APP_OPT_PASSIN,
    HITLS_APP_OPT_OUT,
    HITLS_APP_OPT_PUBOUT,
    HITLS_APP_OPT_CIPHER_ALG,
    HITLS_APP_OPT_PASSOUT,
    HITLS_APP_OPT_TEXT,
    HITLS_APP_OPT_NOOUT,
} HITLSOptType;

const HITLS_CmdOption g_pKeyOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"in", HITLS_APP_OPT_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input key"},
    {"passin", HITLS_APP_OPT_PASSIN, HITLS_APP_OPT_VALUETYPE_STRING, "Input file pass phrase source"},
    {"out", HITLS_APP_OPT_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"pubout", HITLS_APP_OPT_PUBOUT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Output public key, not private"},
    {"", HITLS_APP_OPT_CIPHER_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Any supported cipher"},
    {"passout", HITLS_APP_OPT_PASSOUT, HITLS_APP_OPT_VALUETYPE_STRING, "Output file pass phrase source"},
    {"text", HITLS_APP_OPT_TEXT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print key in text(only RSA is supported)"},
    {"noout", HITLS_APP_OPT_NOOUT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Do not output the key in encoded form"},
    {NULL, 0, 0, NULL},
};

typedef struct {
    char *inFilePath;
    BSL_ParseFormat inFormat;
    char *passInArg;
    bool pubin;
} InputKeyPara;

typedef struct {
    char *outFilePath;
    BSL_ParseFormat outFormat;
    char *passOutArg;
    bool pubout;
    bool text;
    bool noout;
} OutPutKeyPara;

typedef struct {
    CRYPT_EAL_PkeyCtx *pkey;
    char *passin;
    char *passout;
    BSL_UIO *wUio;
    int32_t cipherAlgCid;
    InputKeyPara inPara;
    OutPutKeyPara outPara;
} PkeyOptCtx;

typedef int32_t (*PkeyOptHandleFunc)(PkeyOptCtx *);

typedef struct {
    int optType;
    PkeyOptHandleFunc func;
} PkeyOptHandleTable;

static int32_t PkeyOptErr(PkeyOptCtx *optCtx)
{
    (void)optCtx;
    AppPrintError("pkey: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t PkeyOptHelp(PkeyOptCtx *optCtx)
{
    (void)optCtx;
    HITLS_APP_OptHelpPrint(g_pKeyOpts);
    return HITLS_APP_HELP;
}

static int32_t PkeyOptIn(PkeyOptCtx *optCtx)
{
    optCtx->inPara.inFilePath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t PkeyOptPassin(PkeyOptCtx *optCtx)
{
    optCtx->inPara.passInArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t PkeyOptOut(PkeyOptCtx *optCtx)
{
    optCtx->outPara.outFilePath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t PkeyOptPubout(PkeyOptCtx *optCtx)
{
    optCtx->outPara.pubout = true;
    return HITLS_APP_SUCCESS;
}

static int32_t PkeyOptCipher(PkeyOptCtx *optCtx)
{
    const char *name = HITLS_APP_OptGetUnKownOptName();
    return HITLS_APP_GetAndCheckCipherOpt(name, &optCtx->cipherAlgCid);
}

static int32_t PkeyOptPassout(PkeyOptCtx *optCtx)
{
    optCtx->outPara.passOutArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t PkeyOptText(PkeyOptCtx *optCtx)
{
    optCtx->outPara.text = true;
    return HITLS_APP_SUCCESS;
}

static int32_t PkeyOptNoout(PkeyOptCtx *optCtx)
{
    optCtx->outPara.noout = true;
    return HITLS_APP_SUCCESS;
}

static const PkeyOptHandleTable g_pkeyOptHandleTable[] = {
    {HITLS_APP_OPT_ERR, PkeyOptErr},
    {HITLS_APP_OPT_HELP, PkeyOptHelp},
    {HITLS_APP_OPT_IN, PkeyOptIn},
    {HITLS_APP_OPT_PASSIN, PkeyOptPassin},
    {HITLS_APP_OPT_OUT, PkeyOptOut},
    {HITLS_APP_OPT_PUBOUT, PkeyOptPubout},
    {HITLS_APP_OPT_CIPHER_ALG, PkeyOptCipher},
    {HITLS_APP_OPT_PASSOUT, PkeyOptPassout},
    {HITLS_APP_OPT_TEXT, PkeyOptText},
    {HITLS_APP_OPT_NOOUT, PkeyOptNoout},
};

static int32_t ParsePkeyOpt(int argc, char *argv[], PkeyOptCtx *optCtx)
{
    int32_t ret = HITLS_APP_OptBegin(argc, argv, g_pKeyOpts);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_APP_OptEnd();
        AppPrintError("error in opt begin.\n");
        return ret;
    }
    int optType = HITLS_APP_OPT_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF)) {
        for (size_t i = 0; i < (sizeof(g_pkeyOptHandleTable) / sizeof(g_pkeyOptHandleTable[0])); ++i) {
            if (optType == g_pkeyOptHandleTable[i].optType) {
                ret = g_pkeyOptHandleTable[i].func(optCtx);
                break;
            }
        }
    }
    // Obtain the number of parameters that cannot be parsed in the current version,
    // and print the error inFormation and help list.
    if ((ret == HITLS_APP_SUCCESS) && (HITLS_APP_GetRestOptNum() != 0)) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("pkey: Use -help for summary.\n");
        ret = HITLS_APP_OPT_UNKOWN;
    }
    HITLS_APP_OptEnd();
    return ret;
}

static int32_t HandlePkeyOpt(int argc, char *argv[], PkeyOptCtx *optCtx)
{
    int32_t ret = ParsePkeyOpt(argc, argv, optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    // 1. Read Password
    if ((optCtx->cipherAlgCid == CRYPT_CIPHER_MAX) && (optCtx->outPara.passOutArg != NULL)) {
        AppPrintError("Warning: The -passout option is ignored without a cipher option.\n");
    }
    if ((HITLS_APP_ParsePasswd(optCtx->inPara.passInArg, &optCtx->passin) != HITLS_APP_SUCCESS) ||
        (HITLS_APP_ParsePasswd(optCtx->outPara.passOutArg, &optCtx->passout) != HITLS_APP_SUCCESS)) {
        return HITLS_APP_PASSWD_FAIL;
    }

    // 2. Load the public or private key
    if (optCtx->inPara.pubin) {
        optCtx->pkey = HITLS_APP_LoadPubKey(optCtx->inPara.inFilePath, optCtx->inPara.inFormat);
    } else {
        optCtx->pkey = HITLS_APP_LoadPrvKey(optCtx->inPara.inFilePath, optCtx->inPara.inFormat, &optCtx->passin);
    }

    if (optCtx->pkey == NULL) {
        return HITLS_APP_LOAD_KEY_FAIL;
    }

    // 3. Output the public or private key.
    if (optCtx->outPara.pubout) {
        return HITLS_APP_PrintPubKey(optCtx->pkey, optCtx->outPara.outFilePath, optCtx->outPara.outFormat);
    }

    optCtx->wUio = HITLS_APP_UioOpen(optCtx->outPara.outFilePath, 'w', 0);
    if (optCtx->wUio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(optCtx->wUio, true);
    AppKeyPrintParam param = { optCtx->outPara.outFilePath, BSL_FORMAT_PEM, optCtx->cipherAlgCid,
                               optCtx->outPara.text, optCtx->outPara.noout};
    return HITLS_APP_PrintPrvKeyByUio(optCtx->wUio, optCtx->pkey, &param, &optCtx->passout);
}

static void InitPkeyOptCtx(PkeyOptCtx *optCtx)
{
    optCtx->pkey = NULL;
    optCtx->passin = NULL;
    optCtx->passout = NULL;
    optCtx->cipherAlgCid = CRYPT_CIPHER_MAX;

    optCtx->inPara.inFilePath = NULL;
    optCtx->inPara.inFormat = BSL_FORMAT_PEM;
    optCtx->inPara.passInArg = NULL;
    optCtx->inPara.pubin = false;

    optCtx->outPara.outFilePath = NULL;
    optCtx->outPara.outFormat = BSL_FORMAT_PEM;
    optCtx->outPara.passOutArg = NULL;
    optCtx->outPara.pubout = false;
    optCtx->outPara.text = false;
    optCtx->outPara.noout = false;
}

static void UnInitPkeyOptCtx(PkeyOptCtx *optCtx)
{
    CRYPT_EAL_PkeyFreeCtx(optCtx->pkey);
    optCtx->pkey = NULL;
    if (optCtx->passin != NULL) {
        BSL_SAL_ClearFree(optCtx->passin, strlen(optCtx->passin));
    }
    if (optCtx->passout != NULL) {
        BSL_SAL_ClearFree(optCtx->passout, strlen(optCtx->passout));
    }
    BSL_UIO_Free(optCtx->wUio);
    optCtx->wUio = NULL;
}

// pkey main function
int32_t HITLS_PkeyMain(int argc, char *argv[])
{
    PkeyOptCtx optCtx = {};
    InitPkeyOptCtx(&optCtx);
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR,
            "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = HandlePkeyOpt(argc, argv, &optCtx);
    } while (false);
    CRYPT_EAL_RandDeinitEx(NULL);
    UnInitPkeyOptCtx(&optCtx);
    return ret;
}