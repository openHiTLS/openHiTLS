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

#include "app_mac.h"
#include <limits.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_mac.h"
#include "bsl_errno.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_provider.h"
#include "app_utils.h"
#include "app_sm.h"
#include "app_keymgmt.h"

#define MAX_BUFSIZE (1024 * 8)  // Indicates the length of a single mac during mac calculation.
#define IS_SUPPORT_GET_EOF 1
#define MAC_MAX_KEY_LEN 64

typedef enum OptionChoice {
    HITLS_APP_OPT_MAC_ERR = -1,
    HITLS_APP_OPT_MAC_EOF = 0,
    HITLS_APP_OPT_MAC_HELP = 1,  // The value of the help type of each opt option is 1. The following can be customized.
    HITLS_APP_OPT_MAC_ALG,
    HITLS_APP_OPT_MAC_IN,
    HITLS_APP_OPT_MAC_OUT,
    HITLS_APP_OPT_MAC_BINARY,
    HITLS_APP_OPT_MAC_KEY,
    HITLS_APP_OPT_MAC_HEXKEY,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLSOptType;

const HITLS_CmdOption g_macOpts[] = {
    {"help", HITLS_APP_OPT_MAC_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Show usage information for MAC command."},
    {"name", HITLS_APP_OPT_MAC_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Specify MAC algorithm (e.g., hmac-sha256)."},
    {"in", HITLS_APP_OPT_MAC_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE,
        "Set input file for MAC computation (default: stdin)."},
    {"out", HITLS_APP_OPT_MAC_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE,
        "Set output file for MAC result (default: stdout)."},
    {"binary", HITLS_APP_OPT_MAC_BINARY, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
        "Output MAC result in binary format."},
    {"key", HITLS_APP_OPT_MAC_KEY, HITLS_APP_OPT_VALUETYPE_STRING,
        "Input encryption key as a string."},
    {"hexkey", HITLS_APP_OPT_MAC_HEXKEY, HITLS_APP_OPT_VALUETYPE_STRING,
        "Input encryption key in hexadecimal format (e.g., 0x1234ABCD)."},
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {NULL, 0, 0, NULL}};

typedef struct {
    int32_t algId;
    uint32_t macSize;
    uint32_t isBinary;
    char *inFile;
    uint8_t readBuf[MAX_BUFSIZE];
    uint32_t readLen;
    char *outFile;
    char *key;
    char *hexKey;
    uint32_t keyLen;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} MacOpt;

typedef int32_t (*MacOptHandleFunc)(MacOpt *);
typedef struct {
    int32_t optType;
    MacOptHandleFunc func;
} MacOptHandleFuncMap;

static int32_t MacOptErr(MacOpt *macOpt)
{
    (void)macOpt;
    AppPrintError("mac: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t MacOptHelp(MacOpt *macOpt)
{
    (void)macOpt;
    HITLS_APP_OptHelpPrint(g_macOpts);
    return HITLS_APP_HELP;
}

static int32_t MacOptIn(MacOpt *macOpt)
{
    macOpt->inFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t MacOptOut(MacOpt *macOpt)
{
    macOpt->outFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t MacOptKey(MacOpt *macOpt)
{
    macOpt->key = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t MacOptHexKey(MacOpt *macOpt)
{
    macOpt->hexKey = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t MacOptBinary(MacOpt *macOpt)
{
    macOpt->isBinary = 1;
    return HITLS_APP_SUCCESS;
}

static int32_t MacOptAlg(MacOpt *macOpt)
{
    char *algName = HITLS_APP_OptGetValueStr();
    if (algName == NULL) {
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    macOpt->algId = HITLS_APP_GetCidByName(algName, HITLS_APP_LIST_OPT_MAC_ALG);
    if (macOpt->algId == BSL_CID_UNKNOWN) {
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static const MacOptHandleFuncMap g_macOptHandleFuncMap[] = {
    {HITLS_APP_OPT_MAC_ERR, MacOptErr},
    {HITLS_APP_OPT_MAC_HELP, MacOptHelp},
    {HITLS_APP_OPT_MAC_IN, MacOptIn},
    {HITLS_APP_OPT_MAC_OUT, MacOptOut},
    {HITLS_APP_OPT_MAC_KEY, MacOptKey},
    {HITLS_APP_OPT_MAC_HEXKEY, MacOptHexKey},
    {HITLS_APP_OPT_MAC_BINARY, MacOptBinary},
    {HITLS_APP_OPT_MAC_ALG, MacOptAlg},
};

static int32_t ParseMacOpt(MacOpt *macOpt)
{
    int ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_MAC_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_MAC_EOF)) {
        for (size_t i = 0; i < sizeof(g_macOptHandleFuncMap) / sizeof(g_macOptHandleFuncMap[0]); ++i) {
            if (optType == g_macOptHandleFuncMap[i].optType) {
                ret = g_macOptHandleFuncMap[i].func(macOpt);
                break;
            }
        }
        HITLS_APP_PROV_CASES(optType, macOpt->provider);
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(optType, macOpt->smParam);
#endif
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
    }
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("mac: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckKeyParam(MacOpt *macOpt)
{
#ifdef HITLS_APP_SM_MODE
    if (macOpt->smParam->smTag == 1) {
        if (macOpt->smParam->uuid == NULL) {
            AppPrintError("mac: The uuid is not specified.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (macOpt->smParam->workPath == NULL) {
            AppPrintError("mac: The workpath is not specified.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        return HITLS_APP_SUCCESS;
    }
#endif
    if (macOpt->key == NULL && macOpt->hexKey == NULL) {
        AppPrintError("mac: No key entered.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (macOpt->key != NULL && macOpt->hexKey != NULL) {
        AppPrintError("mac: Cannot specify both key and hexkey.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckParam(MacOpt *macOpt)
{
    int32_t ret = CheckKeyParam(macOpt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    if (macOpt->inFile != NULL && strlen((const char*)macOpt->inFile) > PATH_MAX) {
        AppPrintError("mac: The input file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (macOpt->outFile != NULL && strlen((const char*)macOpt->outFile) > PATH_MAX) {
        AppPrintError("mac: The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

#ifdef HITLS_APP_SM_MODE
static int32_t GetKeyFromP12(MacOpt *macOpt, uint8_t **key, uint32_t *keyLen)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    int32_t ret = HITLS_APP_FindKey(macOpt->provider, macOpt->smParam, macOpt->algId, &keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("mac: Failed to find key, errCode: 0x%x.\n", ret);
        return ret;
    }
    *key = (uint8_t*)BSL_SAL_Dump(keyInfo.key, keyInfo.keyLen);
    if (*key == NULL) {
        (void)BSL_SAL_CleanseData(keyInfo.key, keyInfo.keyLen);
        AppPrintError("mac: Failed to dump key, keyLen: %u.\n", keyInfo.keyLen);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    *keyLen = keyInfo.keyLen;
    (void)BSL_SAL_CleanseData(keyInfo.key, keyInfo.keyLen);
    return HITLS_APP_SUCCESS;
}
#endif

static int32_t GetMacKey(MacOpt *macOpt, uint8_t **key, uint32_t *keyLen)
{
#ifdef HITLS_APP_SM_MODE
    if (macOpt->smParam->smTag == 1) {
        return GetKeyFromP12(macOpt, key, keyLen);
    }
#endif
    size_t len;
    if (macOpt->key != NULL) {
        len = strlen((const char *)macOpt->key);
    } else {
        len = strlen((const char *)macOpt->hexKey);
    }
    if (len > UINT32_MAX) {
        AppPrintError("mac: key length overflow.\n");
        return HITLS_APP_INVALID_ARG;
    }
    if (macOpt->key != NULL) {
        *key = (uint8_t *)BSL_SAL_Dump(macOpt->key, strlen(macOpt->key));
        if (*key == NULL) {
            AppPrintError("mac: Failed to dump key, keyLen: %u.\n", strlen(macOpt->key));
            return HITLS_APP_MEM_ALLOC_FAIL;
        }
        *keyLen = strlen(macOpt->key);
        return HITLS_APP_SUCCESS;
    } else if (macOpt->hexKey != NULL) {
        int32_t ret = HITLS_APP_HexToByte(macOpt->hexKey, 1, key, keyLen);
        if (ret == HITLS_APP_OPT_VALUE_INVALID) {
            AppPrintError("mac: Get key from hexkey failed, errCode: 0x%x.\n", ret);
            return ret;
        }
        return HITLS_APP_SUCCESS;
    }
    return HITLS_APP_OPT_VALUE_INVALID;
}

static CRYPT_EAL_MacCtx *InitAlgMac(MacOpt *macOpt)
{
    uint8_t *key = NULL;
    uint32_t keyLen = 0;

    int32_t ret = GetMacKey(macOpt, &key, &keyLen);
    if (ret != HITLS_APP_SUCCESS) {
        return NULL;
    }
    CRYPT_EAL_MacCtx *ctx = NULL;
    do {
        ctx = CRYPT_EAL_ProviderMacNewCtx(APP_GetCurrent_LibCtx(), macOpt->algId,
            macOpt->provider->providerAttr);  // creating an MAC Context
        if (ctx == NULL) {
            (void)AppPrintError("mac:Failed to create the algorithm(%d) context\n", macOpt->algId);
            break;
        }
        ret = CRYPT_EAL_MacInit(ctx, key, keyLen);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("mac:Summary context creation failed, ret=%d\n", ret);
            CRYPT_EAL_MacFreeCtx(ctx);
            ctx = NULL;
            break;
        }
    } while (0);
    BSL_SAL_ClearFree(key, keyLen);
    return ctx;
}

static int32_t MacParamSet(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint32_t padding = CRYPT_PADDING_ZEROS;

    if (macOpt->algId == CRYPT_MAC_CBC_MAC_SM4) {
        ret = CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padding, sizeof(CRYPT_PaddingType));
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("mac:Failed to set CBC MAC padding, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
        }
    }
    return ret;
}

static int32_t GetReadBuf(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    int32_t ret;
    bool isEof = false;
    uint32_t readLen = 0;
    uint64_t readFileLen = 0;
    uint8_t *tmpBuf = (uint8_t *)BSL_SAL_Calloc(MAX_BUFSIZE, sizeof(uint8_t));
    if (tmpBuf == NULL) {
        AppPrintError("mac: Failed to allocate read buffer.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    BSL_UIO *readUio = HITLS_APP_UioOpen(macOpt->inFile, 'r', 0);
    BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
    if (readUio == NULL) {
        if (macOpt->inFile == NULL) {
            AppPrintError("mac: Failed to open stdin\n");
        } else {
            AppPrintError("mac: Failed to open the file <%s>, No such file or directory\n", macOpt->inFile);
        }
        BSL_SAL_FREE(tmpBuf);
        return HITLS_APP_UIO_FAIL;
    }

    if (macOpt->inFile == NULL) {
        while (BSL_UIO_Ctrl(readUio, BSL_UIO_FILE_GET_EOF, IS_SUPPORT_GET_EOF, &isEof) == BSL_SUCCESS && !isEof) {
            if (BSL_UIO_Read(readUio, tmpBuf, MAX_BUFSIZE, &readLen) != BSL_SUCCESS) {
                BSL_SAL_FREE(tmpBuf);
                BSL_UIO_Free(readUio);
                (void)AppPrintError("Failed to obtain the content from the STDIN\n");
                return HITLS_APP_STDIN_FAIL;
            }
            if (readLen == 0) {
                break;
            }
            ret = CRYPT_EAL_MacUpdate(ctx, tmpBuf, readLen);
            if (ret != CRYPT_SUCCESS) {
                BSL_SAL_FREE(tmpBuf);
                BSL_UIO_Free(readUio);
                (void)AppPrintError("Failed to continuously summarize the STDIN content\n");
                return HITLS_APP_CRYPTO_FAIL;
            }
        }
    } else {
        ret = BSL_UIO_Ctrl(readUio, BSL_UIO_PENDING, sizeof(readFileLen), &readFileLen);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_FREE(tmpBuf);
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to obtain the content length\n");
            return HITLS_APP_UIO_FAIL;
        }
        while (readFileLen > 0) {
            uint32_t bufLen = (readFileLen > MAX_BUFSIZE) ? MAX_BUFSIZE : (uint32_t)readFileLen;
            ret = BSL_UIO_Read(readUio, tmpBuf, bufLen, &readLen); // read content to memory
            if (ret != BSL_SUCCESS || bufLen != readLen) {
                BSL_SAL_FREE(tmpBuf);
                BSL_UIO_Free(readUio);
                (void)AppPrintError("Failed to read the input content\n");
                return HITLS_APP_UIO_FAIL;
            }
            ret = CRYPT_EAL_MacUpdate(ctx, tmpBuf, bufLen); // continuously enter summary content
            if (ret != CRYPT_SUCCESS) {
                BSL_SAL_FREE(tmpBuf);
                BSL_UIO_Free(readUio);
                (void)AppPrintError("mac: Failed to update MAC with file content, error code: %d\n", ret);
                return HITLS_APP_CRYPTO_FAIL;
            }
            readFileLen -= bufLen;
        }
    }
    BSL_UIO_Free(readUio);
    BSL_SAL_FREE(tmpBuf);
    return HITLS_APP_SUCCESS;
}

static int32_t MacResult(CRYPT_EAL_MacCtx *ctx, MacOpt *macOpt)
{
    uint8_t *outBuf = NULL;
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(macOpt->outFile, 'w', 0);  // overwrite the original content
    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    if (fileWriteUio == NULL) {
        (void)AppPrintError("Failed to open the outfile\n");
        return HITLS_APP_UIO_FAIL;
    }

    uint32_t macSize = CRYPT_EAL_GetMacLen(ctx);
    if (macSize <= 0) {
        AppPrintError("mac: Invalid MAC size: %u\n", macSize);
        BSL_UIO_Free(fileWriteUio);
        return HITLS_APP_CRYPTO_FAIL;
    }
    outBuf = (uint8_t *)BSL_SAL_Calloc(macSize, sizeof(uint8_t));
    if (outBuf == NULL) {
        AppPrintError("mac: Failed to allocate MAC buffer.\n");
        BSL_UIO_Free(fileWriteUio);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint32_t macBufLen = macSize;
    int32_t ret = CRYPT_EAL_MacFinal(ctx, outBuf, &macBufLen);
    if (ret != CRYPT_SUCCESS || macBufLen < macSize) {
        BSL_SAL_FREE(outBuf);
        (void)AppPrintError("mac: Failed to complete the final summary. ERR:%d\n", ret);
        BSL_UIO_Free(fileWriteUio);
        return HITLS_APP_CRYPTO_FAIL;
    }

    ret = HITLS_APP_OptWriteUio(fileWriteUio, outBuf, macBufLen,
        macOpt->isBinary == 1 ? HITLS_APP_FORMAT_TEXT: HITLS_APP_FORMAT_HEX);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("mac:Failed to export data to the outfile path\n");
    }
    BSL_UIO_Free(fileWriteUio);
    BSL_SAL_FREE(outBuf);
    return ret;
}

static int32_t HandleMac(MacOpt *macOpt)
{
    CRYPT_EAL_MacCtx *ctx = NULL;
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ctx = InitAlgMac(macOpt);
        if (ctx == NULL) {
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = MacParamSet(ctx, macOpt);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("mac: Failed to set mac params, errCode: 0x%x.\n", ret);
            break;
        }
#ifdef HITLS_APP_SM_MODE
        if (macOpt->smParam->smTag == 1) {
            macOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
        }
#endif
        ret = GetReadBuf(ctx, macOpt);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = MacResult(ctx, macOpt);
    } while (0);
    CRYPT_EAL_MacFreeCtx(ctx);
    return ret;
}

int32_t HITLS_MacMain(int argc, char *argv[])
{
    int32_t mainRet = HITLS_APP_SUCCESS;
    AppProvider appProvider = {NULL, NULL, NULL};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    MacOpt macOpt = {CRYPT_MAC_HMAC_SM3, 0, 0, NULL, {0}, 0, NULL, NULL, NULL, 0, &appProvider, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
    MacOpt macOpt = {CRYPT_MAC_HMAC_SHA256, 0, 0, NULL, {0}, 0, NULL, NULL, NULL, 0, &appProvider};
#endif
    do {
        mainRet = HITLS_APP_OptBegin(argc, argv, g_macOpts);
        if (mainRet != HITLS_APP_SUCCESS) {
            (void)AppPrintError("error in opt begin.\n");
            break;
        }
        mainRet = ParseMacOpt(&macOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            break;
        }
        mainRet = CheckParam(&macOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            break;
        }
        mainRet = HITLS_APP_Init(&initParam);
        if (mainRet != HITLS_APP_SUCCESS) {
            (void)AppPrintError("mac: Failed to init, errCode: 0x%x.\n", mainRet);
            break;
        }
        mainRet = HandleMac(&macOpt);
    } while (0);
    HITLS_APP_Deinit(&initParam, mainRet);
    HITLS_APP_OptEnd();
    return mainRet;
}
