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
#include "app_rsa.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include "bsl_uio.h"
#include "bsl_ui.h"
#include "app_errno.h"
#include "app_function.h"
#include "bsl_sal.h"
#include "app_utils.h"
#include "app_opt.h"
#include "app_print.h"
#include "crypt_eal_codecs.h"
#include "crypt_codecskey.h"
#include "crypt_errno.h"

#define RSA_MIN_LEN 256
#define RSA_MAX_LEN 4096
#define DEFAULT_RSA_SIZE 512U

typedef enum OptionChoice {
    HITLS_APP_OPT_RSA_ERR = -1,
    HITLS_APP_OPT_RSA_ROF = 0,
    HITLS_APP_OPT_RSA_HELP = 1,  // first opt of each option is help = 1, following opt can be customized.
    HITLS_APP_OPT_RSA_IN,
    HITLS_APP_OPT_RSA_PASSIN,
    HITLS_APP_OPT_RSA_OUT,
    HITLS_APP_OPT_RSA_NOOUT,
    HITLS_APP_OPT_RSA_TEXT,
} HITLSOptType;

typedef struct {
    char *inFilePath;
    BSL_ParseFormat inFormat;
    char *passInArg;
} RsaInputOptions;

typedef struct {
    char *outFilePath;
    BSL_ParseFormat outFormat;
    bool text;
    bool noout;
} RsaOutputOptions;

typedef struct {
    RsaInputOptions input;
    RsaOutputOptions output;
    char *passin;
    CRYPT_EAL_PkeyCtx *pkey;
} RsaOptCtx;

static const HITLS_CmdOption g_rsaOpts[] = {
    {"help", HITLS_APP_OPT_RSA_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"in", HITLS_APP_OPT_RSA_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file"},
    {"passin", HITLS_APP_OPT_RSA_PASSIN, HITLS_APP_OPT_VALUETYPE_STRING, "Input file pass phrase source"},
    {"out", HITLS_APP_OPT_RSA_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"noout", HITLS_APP_OPT_RSA_NOOUT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "No RSA output "},
    {"text", HITLS_APP_OPT_RSA_TEXT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print RSA key in text"},
    {NULL, 0, 0, NULL}
};

static int32_t OutPemFormat(BSL_UIO *uio, void *encode)
{
    BSL_Buffer *outBuf = encode;  // Encode data into the PEM format.
    AppPrintError("writing RSA key\n");
    int32_t writeRet = HITLS_APP_OptWriteUio(uio, outBuf->data, outBuf->dataLen, HITLS_APP_FORMAT_PEM);
    if (writeRet != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to export data in PEM format\n");
    }
    return writeRet;
}

static int32_t BufWriteToUio(void *pkey, const RsaOutputOptions *output)
{
    int32_t writeRet = HITLS_APP_SUCCESS;
    BSL_UIO *uio = HITLS_APP_UioOpenPrivate(output->outFilePath, 'w');
    if (uio == NULL) {
        AppPrintError("Failed to open the file <%s> \n",
            output->outFilePath != NULL ? output->outFilePath : "stdout");
        return HITLS_APP_UIO_FAIL;
    }
    if (output->text == true) {
        writeRet = CRYPT_EAL_PrintPrikey(0, pkey, uio);
        if (writeRet != HITLS_APP_SUCCESS) {
            AppPrintError("Failed to export data in text format to a file <%s> \n", output->outFilePath);
            goto end;
        }
    }
    if (output->noout != true) {
        BSL_Buffer encodeBuffer = {0};
        writeRet = CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_RSA, &encodeBuffer);
        if (writeRet != CRYPT_SUCCESS) {
            AppPrintError("Failed to encode pem format data\n");
            goto end;
        }
        writeRet = OutPemFormat(uio, &encodeBuffer);
        BSL_SAL_FREE(encodeBuffer.data);
        if (writeRet != HITLS_APP_SUCCESS) {
            AppPrintError("Failed to export data in pem format to a file <%s> \n", output->outFilePath);
        }
    }
end:
    BSL_UIO_Free(uio);
    return writeRet;
}


static int32_t OptParse(RsaOptCtx *optCtx)
{
    HITLSOptType optType;
    int ret = HITLS_APP_SUCCESS;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_RSA_ROF) {
        switch (optType) {
            case HITLS_APP_OPT_RSA_ROF:
            case HITLS_APP_OPT_RSA_ERR:
                ret = HITLS_APP_OPT_UNKOWN;
                AppPrintError("rsa: Use -help for summary.\n");
                return ret;
            case HITLS_APP_OPT_RSA_HELP:
                ret = HITLS_APP_HELP;
                (void)HITLS_APP_OptHelpPrint(g_rsaOpts);
                return ret;
            case HITLS_APP_OPT_RSA_IN:
                optCtx->input.inFilePath = HITLS_APP_OptGetValueStr();
                if (optCtx->input.inFilePath == NULL || strlen(optCtx->input.inFilePath) >= PATH_MAX) {
                    AppPrintError("The length of infile error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_RSA_PASSIN:
                optCtx->input.passInArg = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_RSA_OUT:
                optCtx->output.outFilePath = HITLS_APP_OptGetValueStr();
                if (optCtx->output.outFilePath == NULL || strlen(optCtx->output.outFilePath) >= PATH_MAX) {
                    AppPrintError("The length of out file error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_RSA_NOOUT:
                optCtx->output.noout = true;
                break;
            case HITLS_APP_OPT_RSA_TEXT:
                optCtx->output.text = true;
                break;
            default:
                ret = HITLS_APP_OPT_UNKOWN;
                return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_RsaMain(int argc, char *argv[])
{
    RsaOptCtx optCtx = {
        .input.inFormat = BSL_FORMAT_PEM,
        .output.outFormat = BSL_FORMAT_PEM,
    };
    int32_t mainRet = HITLS_APP_SUCCESS;
    mainRet = HITLS_APP_OptBegin(argc, argv, g_rsaOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = OptParse(&optCtx);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    int unParseParamNum = HITLS_APP_GetRestOptNum();
    if (unParseParamNum != 0) {  // The input parameters are not completely parsed.
        AppPrintError("Extra arguments given.\n");
        AppPrintError("rsa: Use -help for summary.\n");
        mainRet = HITLS_APP_OPT_UNKOWN;
        goto end;
    }
    mainRet = HITLS_APP_ParsePasswd(optCtx.input.passInArg, &optCtx.passin);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    optCtx.pkey = HITLS_APP_LoadPrvKey(optCtx.input.inFilePath, optCtx.input.inFormat, &optCtx.passin);
    if (optCtx.pkey == NULL) {
        AppPrintError("Failed to load RSA private key.\n");
        mainRet = HITLS_APP_DECODE_FAIL;
        goto end;
    }
    mainRet = BufWriteToUio(optCtx.pkey, &optCtx.output);  // Selective output based on command line parameters.
end:
    CRYPT_EAL_PkeyFreeCtx(optCtx.pkey);
    if (optCtx.passin != NULL) {
        BSL_SAL_ClearFree(optCtx.passin, strlen(optCtx.passin));
    }
    HITLS_APP_OptEnd();
    return mainRet;
}
