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

#include "app_rand.h"
#include <stddef.h>
#include <linux/limits.h>
#include "securec.h"
#include "bsl_uio.h"
#include "crypt_eal_rand.h"
#include "bsl_base64.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_function.h"

#define MAX_RANDOM_LEN 4096

typedef enum OptionChoice {
    HITLS_APP_OPT_RAND_ERR = -1,
    HITLS_APP_OPT_RAND_EOF = 0,
    HITLS_APP_OPT_RAND_NUMBITS = HITLS_APP_OPT_RAND_EOF,
    HITLS_APP_OPT_RAND_HELP = 1,  // The value of help type of each opt is 1. The following options can be customized.
    HITLS_APP_OPT_RAND_HEX = 2,
    HITLS_APP_OPT_RAND_BASE64,
    HITLS_APP_OPT_RAND_OUT,
} HITLSOptType;

HITLS_CmdOption g_randOpts[] = {
    {"help", HITLS_APP_OPT_RAND_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"hex", HITLS_APP_OPT_RAND_HEX, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Hex-encoded output"},
    {"base64", HITLS_APP_OPT_RAND_BASE64, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Base64-encoded output"},
    {"out", HITLS_APP_OPT_RAND_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"numbytes", HITLS_APP_OPT_RAND_NUMBITS, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Random byte length"},
    {NULL}};
static int32_t OptParse(char **outfile, int32_t *format);
static int32_t RandNumOut(int32_t randNumLen, char *outfile, int format);

int32_t HITLS_RandMain(int argc, char **argv)
{
    char *outfile = NULL;                      // output file name
    int32_t format = HITLS_APP_FORMAT_BINARY;  // default binary output
    int32_t randNumLen = 0;                    // length of the random number entered by the user
    int32_t mainRet = HITLS_APP_SUCCESS;       // return value of the main function
    mainRet = HITLS_APP_OptBegin(argc, argv, g_randOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = OptParse(&outfile, &format);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    // 获取用户输入即要生成的随机数长度
    int unParseParamNum = HITLS_APP_GetRestOptNum();
    char** unParseParam = HITLS_APP_GetRestOpt();
    if (unParseParamNum != 1) {
        (void)AppPrintError("Extra arguments given.\n");
        (void)AppPrintError("rand: Use -help for summary.\n");
        mainRet = HITLS_APP_OPT_UNKOWN;
        goto end;
    } else {
        mainRet = HITLS_APP_OptGetInt(unParseParam[0], &randNumLen);
        if (mainRet != HITLS_APP_SUCCESS || randNumLen <= 0) {
            mainRet = HITLS_APP_OPT_VALUE_INVALID;
            (void)AppPrintError("Valid Range[1, 2147483647]\n");
            goto end;
        }
    }
    if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR,
        "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
        mainRet = HITLS_APP_CRYPTO_FAIL;
        goto end;
    }
    mainRet = RandNumOut(randNumLen, outfile, format);
end:
    CRYPT_EAL_RandDeinitEx(NULL);
    HITLS_APP_OptEnd();
    return mainRet;
}

static int32_t OptParse(char **outfile, int32_t *format)
{
    HITLSOptType optType;
    int ret = HITLS_APP_SUCCESS;

    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_RAND_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_RAND_EOF:
            case HITLS_APP_OPT_RAND_ERR:
                ret = HITLS_APP_OPT_UNKOWN;
                (void)AppPrintError("rand: Use -help for summary.\n");
                return ret;
            case HITLS_APP_OPT_RAND_HELP:
                ret = HITLS_APP_HELP;
                (void)HITLS_APP_OptHelpPrint(g_randOpts);
                return ret;
            case HITLS_APP_OPT_RAND_OUT:
                *outfile = HITLS_APP_OptGetValueStr();
                if (*outfile == NULL || strlen(*outfile) >= PATH_MAX) {
                    AppPrintError("The length of outfile error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_RAND_BASE64:
                *format = HITLS_APP_FORMAT_BASE64;
                break;
            case HITLS_APP_OPT_RAND_HEX:
                *format = HITLS_APP_FORMAT_HEX;
                break;
            default:
                break;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t RandNumOut(int32_t randNumLen, char *outfile, int format)
{
    int ret = HITLS_APP_SUCCESS;
    BSL_UIO *uio;
    uio = HITLS_APP_UioOpen(outfile, 'w', 0);
    if (uio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    if (outfile != NULL) {
        BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);
    }
    while (randNumLen > 0) {
        uint8_t outBuf[MAX_RANDOM_LEN] = {0};
        uint32_t outLen = randNumLen;
        if (outLen > MAX_RANDOM_LEN) {
            outLen = MAX_RANDOM_LEN;
        }
        int32_t randRet = CRYPT_EAL_RandbytesEx(NULL, outBuf, outLen);
        if (randRet != CRYPT_SUCCESS) {
            BSL_UIO_Free(uio);
            (void)AppPrintError("Failed to generate a random number.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        ret = HITLS_APP_OptWriteUio(uio, outBuf, outLen, format);
        if (ret != HITLS_APP_SUCCESS) {
            BSL_UIO_Free(uio);
            return ret;
        }
        randNumLen -= outLen;
        if (format != HITLS_APP_FORMAT_BINARY && randNumLen == 0) {
            char buf[1] = {'\n'};  // Enter a newline character at the end.
            uint32_t bufLen = 1;
            uint32_t writeLen = 0;
            ret = BSL_UIO_Write(uio, buf, bufLen, &writeLen);
            if (ret != BSL_SUCCESS) {
                BSL_UIO_Free(uio);
                (void)AppPrintError("Failed to enter the newline character\n");
                return ret;
            }
        }
    }
    BSL_UIO_Free(uio);
    return HITLS_APP_SUCCESS;
}
