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
#include <limits.h>
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
#include "app_provider.h"
#include "app_sm.h"
#include "app_list.h"
#include "app_utils.h"

#define MAX_RANDOM_LEN 4096

typedef enum OptionChoice {
    HITLS_APP_OPT_RAND_ERR = -1,
    HITLS_APP_OPT_RAND_EOF = 0,
    HITLS_APP_OPT_RAND_NUMBITS = HITLS_APP_OPT_RAND_EOF,
    HITLS_APP_OPT_RAND_HELP = 1,  // The value of help type of each opt is 1. The following options can be customized.
    HITLS_APP_OPT_RAND_HEX = 2,
    HITLS_APP_OPT_RAND_BASE64,
    HITLS_APP_OPT_RAND_OUT,
    HITLS_APP_OPT_RAND_ALGORITHM,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLSOptType;

typedef struct {
    int32_t randNumLen;
    char *outFile;
    int32_t format;
    int32_t algId;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} RandCmdOpt;

HITLS_CmdOption g_randOpts[] = {
    {"help", HITLS_APP_OPT_RAND_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"hex", HITLS_APP_OPT_RAND_HEX, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Hex-encoded output"},
    {"base64", HITLS_APP_OPT_RAND_BASE64, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Base64-encoded output"},
    {"out", HITLS_APP_OPT_RAND_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"numbytes", HITLS_APP_OPT_RAND_NUMBITS, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Random byte length"},
    {"algorithm", HITLS_APP_OPT_RAND_ALGORITHM, HITLS_APP_OPT_VALUETYPE_STRING, "Random algorithm"},
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {NULL, 0, 0, NULL}};

static int32_t OptParse(RandCmdOpt *randCmdOpt);
static int32_t RandNumOut(RandCmdOpt *randCmdOpt);

static int32_t GetRandNumLen(int32_t *randNumLen)
{
    int unParseParamNum = HITLS_APP_GetRestOptNum();
    char** unParseParam = HITLS_APP_GetRestOpt();
    if (unParseParamNum != 1) {
        (void)AppPrintError("rand: Extra arguments given.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    int32_t ret = HITLS_APP_OptGetInt(unParseParam[0], randNumLen);
    if (ret != HITLS_APP_SUCCESS || *randNumLen <= 0) {
        (void)AppPrintError("rand: Valid Range[1, 2147483647]\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_RandMain(int argc, char **argv)
{
    int32_t mainRet = HITLS_APP_SUCCESS;       // return value of the main function
    AppProvider appProvider = {NULL, NULL, NULL};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    RandCmdOpt randCmdOpt = {0, NULL, HITLS_APP_FORMAT_BINARY, CRYPT_RAND_SHA256, &appProvider, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
    RandCmdOpt randCmdOpt = {0, NULL, HITLS_APP_FORMAT_BINARY, CRYPT_RAND_SHA256, &appProvider};
#endif
    mainRet = HITLS_APP_OptBegin(argc, argv, g_randOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }

    mainRet = OptParse(&randCmdOpt);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    initParam.randAlgId = randCmdOpt.algId;
    // GET the length of the random number to be generated.
    mainRet = GetRandNumLen(&randCmdOpt.randNumLen);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = HITLS_APP_Init(&initParam);
    if (mainRet != HITLS_APP_SUCCESS) {
        (void)AppPrintError("rand: Failed to init, errCode: 0x%x.\n", mainRet);
        goto end;
    }
    mainRet = RandNumOut(&randCmdOpt);
end:
    HITLS_APP_Deinit(&initParam, mainRet);
    HITLS_APP_OptEnd();
    return mainRet;
}

static int32_t OptParse(RandCmdOpt *randCmdOpt)
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
                randCmdOpt->outFile = HITLS_APP_OptGetValueStr();
                if (randCmdOpt->outFile == NULL || strlen(randCmdOpt->outFile) >= PATH_MAX) {
                    AppPrintError("rand: The length of outfile error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_RAND_BASE64:
                randCmdOpt->format = HITLS_APP_FORMAT_BASE64;
                break;
            case HITLS_APP_OPT_RAND_HEX:
                randCmdOpt->format = HITLS_APP_FORMAT_HEX;
                break;
            case HITLS_APP_OPT_RAND_ALGORITHM:
                randCmdOpt->algId = HITLS_APP_GetCidByName(HITLS_APP_OptGetValueStr(), HITLS_APP_LIST_OPT_RAND_ALG);
                if (randCmdOpt->algId == BSL_CID_UNKNOWN) {
                    AppPrintError("rand: The algorithm is not supported.\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            default:
                break;
        }
        HITLS_APP_PROV_CASES(optType, randCmdOpt->provider);
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(optType, randCmdOpt->smParam);
#endif
    }
#ifdef HITLS_APP_SM_MODE
    if (randCmdOpt->smParam->smTag == 1 && randCmdOpt->smParam->workPath == NULL) {
        AppPrintError("rand: The workpath is not specified.\n");
        return HITLS_APP_INVALID_ARG;
    }
#endif
    return HITLS_APP_SUCCESS;
}

static int32_t RandNumOut(RandCmdOpt *randCmdOpt)
{
#ifdef HITLS_APP_SM_MODE
    if (randCmdOpt->smParam->smTag == 1) {
        randCmdOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    }
#endif
    int ret = HITLS_APP_SUCCESS;
    BSL_UIO *uio;
    uio = HITLS_APP_UioOpen(randCmdOpt->outFile, 'w', 0);
    if (uio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    if (randCmdOpt->outFile != NULL) {
        BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);
    }
    int32_t randNumLen = randCmdOpt->randNumLen;
    uint8_t outBuf[MAX_RANDOM_LEN] = {0};
    uint32_t outLen = 0;
    while (randNumLen > 0) {
        outLen = randNumLen > MAX_RANDOM_LEN ? MAX_RANDOM_LEN : randNumLen;
        int32_t randRet = CRYPT_EAL_RandbytesEx(APP_GetCurrent_LibCtx(), outBuf, outLen);
        if (randRet != CRYPT_SUCCESS) {
            BSL_UIO_Free(uio);
            BSL_SAL_CleanseData(outBuf, sizeof(outBuf));
            (void)AppPrintError("rand: Failed to generate random number, randRet: 0x%x\n", randRet);
            return HITLS_APP_CRYPTO_FAIL;
        }
        ret = HITLS_APP_OptWriteUio(uio, outBuf, outLen, randCmdOpt->format);
        if (ret != HITLS_APP_SUCCESS) {
            BSL_UIO_Free(uio);
            BSL_SAL_CleanseData(outBuf, outLen);
            return ret;
        }
        randNumLen -= outLen;
        if (randCmdOpt->format != HITLS_APP_FORMAT_BINARY && randNumLen == 0) {
            char buf[1] = {'\n'};  // Enter a newline character at the end.
            uint32_t bufLen = 1;
            uint32_t writeLen = 0;
            ret = BSL_UIO_Write(uio, buf, bufLen, &writeLen);
            if (ret != BSL_SUCCESS) {
                BSL_UIO_Free(uio);
                BSL_SAL_CleanseData(outBuf, outLen);
                (void)AppPrintError("rand: Failed to enter the newline character, errCode: 0x%x.\n", ret);
                return HITLS_APP_UIO_FAIL;
            }
        }
    }
    BSL_UIO_Free(uio);
    BSL_SAL_CleanseData(outBuf, outLen);
    return HITLS_APP_SUCCESS;
}
