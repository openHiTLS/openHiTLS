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
#include "app_opt.h"
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "securec.h"
#include "app_errno.h"
#include "bsl_sal.h"
#include "app_print.h"
#include "bsl_uio.h"
#include "bsl_errno.h"
#include "bsl_base64.h"

#define MAX_HITLS_APP_OPT_NAME_WIDTH 40
#define MAX_HITLS_APP_OPT_LINE_WIDTH 80
typedef struct {
    int32_t optIndex;
    int32_t argc;
    char *valueStr;
    char progName[128];
    char **argv;
    const HITLS_CmdOption *opts;
} HITLS_CmdOptState;

static HITLS_CmdOptState g_cmdOptState = {0};
static const HITLS_CmdOption *g_unKnownOpt = NULL;
static char *g_unKownName = NULL;

static int32_t AppIsDir(const char *path)
{
    struct stat st = {0};
    if (path == NULL) {
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (stat(path, &st) != 0) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    if (S_ISDIR(st.st_mode)) {
        return HITLS_APP_SUCCESS;
    }
    return HITLS_APP_OPT_VALUE_INVALID;
}

const char *HITLS_APP_OptGetUnKownOptName(void)
{
    return g_unKownName;
}

static void GetProgName(const char *filePath)
{
    const char *p = NULL;
    for (p = filePath + strlen(filePath); --p > filePath;) {
        if (*p == '/') {
            p++;
            break;
        }
    }

    // Avoid consistency between source and destination addresses.
    if (p != g_cmdOptState.progName) {
        (void)strncpy_s(
            g_cmdOptState.progName, sizeof(g_cmdOptState.progName) - 1, p, sizeof(g_cmdOptState.progName) - 1);
    }
    g_cmdOptState.progName[sizeof(g_cmdOptState.progName) - 1] = '\0';
}

static void CmdOptStateInit(int32_t index, int32_t argc, char **argv, const HITLS_CmdOption *opts)
{
    g_cmdOptState.optIndex = index;
    g_cmdOptState.argc = argc;
    g_cmdOptState.argv = argv;
    g_cmdOptState.opts = opts;
    (void)memset_s(g_cmdOptState.progName, sizeof(g_cmdOptState.progName), 0, sizeof(g_cmdOptState.progName));
}

static void CmdOptStateClear(void)
{
    g_cmdOptState.optIndex = 0;
    g_cmdOptState.argc = 0;
    g_cmdOptState.argv = NULL;
    g_cmdOptState.opts = NULL;
    (void)memset_s(g_cmdOptState.progName, sizeof(g_cmdOptState.progName), 0, sizeof(g_cmdOptState.progName));
}

char *HITLS_APP_GetProgName(void)
{
    return g_cmdOptState.progName;
}

int32_t HITLS_APP_OptBegin(int32_t argc, char **argv, const HITLS_CmdOption *opts)
{
    if (argc == 0 || argv == NULL || opts == NULL) {
        AppPrintError("incorrect command \n");
        return HITLS_APP_OPT_UNKOWN;
    }

    // init cmd option state
    CmdOptStateInit(1, argc, argv, opts);

    GetProgName(argv[0]);
    g_unKnownOpt = NULL;
    const HITLS_CmdOption *opt = opts;
    // Check all opts before using them
    for (; opt->name != NULL; ++opt) {
        if ((strlen(opt->name) == 0) && (opt->valueType == HITLS_APP_OPT_VALUETYPE_NO_VALUE)) {
            g_unKnownOpt = opt;
        } else if ((strlen(opt->name) == 0) || (opt->name[0] == '-')) {
            AppPrintError("Invalid optname %s \n", opt->name);
            return HITLS_APP_OPT_NAME_INVALID;
        }
        if (opt->valueType <= HITLS_APP_OPT_VALUETYPE_NONE || opt->valueType >= HITLS_APP_OPT_VALUETYPE_MAX) {
            return HITLS_APP_OPT_VALUETYPE_INVALID;
        }

        if (opt->valueType == HITLS_APP_OPT_VALUETYPE_PARAMTERS && opt->optType != HITLS_APP_OPT_PARAM) {
            return HITLS_APP_OPT_TYPE_INVALID;
        }

        for (const HITLS_CmdOption *nextOpt = opt + 1; nextOpt->name != NULL; ++nextOpt) {
            if (strcmp(opt->name, nextOpt->name) == 0) {
                AppPrintError("Invalid duplicate name : %s\n", opt->name);
                return HITLS_APP_OPT_NAME_INVALID;
            }
        }
    }

    return HITLS_APP_SUCCESS;
}

char *HITLS_APP_OptGetValueStr(void)
{
    return g_cmdOptState.valueStr;
}

int32_t HITLS_APP_OptGetLong(const char *valueS, long *valueL)
{
    char *endPtr = NULL;
    errno = 0;
    long l = strtol(valueS, &endPtr, 0);
    if (strlen(endPtr) > 0 || endPtr == valueS || (l == LONG_MAX || l == LONG_MIN) || errno == ERANGE ||
        (l == 0 && errno != 0)) {
        AppPrintError("The parameter: %s is not a number or out of range\n", valueS);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    *valueL = l;
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_OptGetInt(const char *valueS, int32_t *valueI)
{
    long valueL = 0;
    if (HITLS_APP_OptGetLong(valueS, &valueL) != HITLS_APP_SUCCESS) {
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    *valueI = (int32_t)valueL;
    // value outside integer range
    if ((long)(*valueI) != valueL) {
        AppPrintError("The number %ld out the int bound \n", valueL);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_OptGetUint32(const char *valueS, uint32_t *valueU)
{
    long valueL = 0;
    if (HITLS_APP_OptGetLong(valueS, &valueL) != HITLS_APP_SUCCESS) {
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    *valueU = (uint32_t)valueL;
    // value outside integer range
    if ((long)(*valueU) != valueL) {
        AppPrintError("The number %ld out the int bound \n", valueL);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_OptGetFormatType(const char *valueS, HITLS_ValueType type, BSL_ParseFormat *formatType)
{
    if (type != HITLS_APP_OPT_VALUETYPE_FMT_PEMDER && type != HITLS_APP_OPT_VALUETYPE_FMT_ANY) {
        AppPrintError("Invalid Format Type\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (strcasecmp(valueS, "DER") == 0) {
        *formatType = BSL_FORMAT_ASN1;
        return HITLS_APP_SUCCESS;
    } else if (strcasecmp(valueS, "PEM") == 0) {
        *formatType = BSL_FORMAT_PEM;
        return HITLS_APP_SUCCESS;
    }
    AppPrintError("Invalid format \"%s\".\n", valueS);
    return HITLS_APP_OPT_VALUE_INVALID;
}

int32_t HITLS_APP_GetRestOptNum(void)
{
    return g_cmdOptState.argc - g_cmdOptState.optIndex;
}

char **HITLS_APP_GetRestOpt(void)
{
    return &g_cmdOptState.argv[g_cmdOptState.optIndex];
}

static int32_t ClassifyByValue(HITLS_ValueType value)
{
    switch (value) {
        case HITLS_APP_OPT_VALUETYPE_IN_FILE:
        case HITLS_APP_OPT_VALUETYPE_OUT_FILE:
        case HITLS_APP_OPT_VALUETYPE_STRING:
        case HITLS_APP_OPT_VALUETYPE_PARAMTERS:
            return HITLS_APP_OPT_VALUECLASS_STR;
        case HITLS_APP_OPT_VALUETYPE_DIR:
            return HITLS_APP_OPT_VALUECLASS_DIR;
        case HITLS_APP_OPT_VALUETYPE_INT:
        case HITLS_APP_OPT_VALUETYPE_UINT:
        case HITLS_APP_OPT_VALUETYPE_POSITIVE_INT:
            return HITLS_APP_OPT_VALUECLASS_INT;
        case HITLS_APP_OPT_VALUETYPE_LONG:
        case HITLS_APP_OPT_VALUETYPE_ULONG:
            return HITLS_APP_OPT_VALUECLASS_LONG;
        case HITLS_APP_OPT_VALUETYPE_FMT_PEMDER:
        case HITLS_APP_OPT_VALUETYPE_FMT_ANY:
            return HITLS_APP_OPT_VALUECLASS_FMT;
        default:
            return HITLS_APP_OPT_VALUECLASS_NO_VALUE;
    }
    return HITLS_APP_OPT_VALUECLASS_NONE;
}

static int32_t CheckOptValueType(const HITLS_CmdOption *opt, const char *valStr)
{
    int32_t valueClass = ClassifyByValue(opt->valueType);
    switch (valueClass) {
        case HITLS_APP_OPT_VALUECLASS_STR:
            break;
        case HITLS_APP_OPT_VALUECLASS_DIR: {
            if (AppIsDir(valStr) != HITLS_APP_SUCCESS) {
                AppPrintError("%s: Invalid dir \"%s\" for -%s\n", g_cmdOptState.progName, valStr, opt->name);
                return HITLS_APP_OPT_VALUE_INVALID;
            }
            break;
        }
        case HITLS_APP_OPT_VALUECLASS_INT: {
            int32_t valueI = 0;
            if (HITLS_APP_OptGetInt(valStr, &valueI) != HITLS_APP_SUCCESS ||
                (opt->valueType == HITLS_APP_OPT_VALUETYPE_UINT && valueI < 0) ||
                (opt->valueType == HITLS_APP_OPT_VALUETYPE_POSITIVE_INT && valueI < 0)) {
                AppPrintError("%s: Invalid number \"%s\" for -%s\n", g_cmdOptState.progName, valStr, opt->name);
                return HITLS_APP_OPT_VALUE_INVALID;
            }
            break;
        }
        case HITLS_APP_OPT_VALUECLASS_LONG: {
            long valueL = 0;
            if (HITLS_APP_OptGetLong(valStr, &valueL) != HITLS_APP_SUCCESS ||
                (opt->valueType == HITLS_APP_OPT_VALUETYPE_LONG && valueL < 0)) {
                AppPrintError("%s: Invalid number \"%s\" for -%s\n", g_cmdOptState.progName, valStr, opt->name);
                return HITLS_APP_OPT_VALUE_INVALID;
            }
            break;
        }
        case HITLS_APP_OPT_VALUECLASS_FMT: {
            BSL_ParseFormat formatType = 0;
            if (HITLS_APP_OptGetFormatType(valStr, opt->valueType, &formatType) != HITLS_APP_SUCCESS) {
                AppPrintError("%s: Invalid format \"%s\" for -%s\n", g_cmdOptState.progName, valStr, opt->name);
                return HITLS_APP_OPT_VALUE_INVALID;
            }
            break;
        }
        default:
            AppPrintError("%s: Invalid arg \"%s\" for -%s\n", g_cmdOptState.progName, valStr, opt->name);
            return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_OptNext(void)
{
    if (g_cmdOptState.optIndex >= g_cmdOptState.argc) {
        return HITLS_APP_OPT_EOF;
    }

    char *optName = g_cmdOptState.argv[g_cmdOptState.optIndex];
    if (optName == NULL || *optName != '-') {
        return HITLS_APP_OPT_EOF;
    }

    g_cmdOptState.optIndex++;
    // optName only contain '-' or '--'
    if (strcmp(optName, "-") == 0 || strcmp(optName, "--") == 0) {
        return HITLS_APP_OPT_ERR;
    }

    if (*(++optName) == '-') {
        optName++;
    }

    // case: key=value do not support
    g_cmdOptState.valueStr = strchr(optName, '=');
    if (g_cmdOptState.valueStr != NULL) {
        return HITLS_APP_OPT_ERR;
    }

    for (const HITLS_CmdOption *opt = g_cmdOptState.opts; opt->name; ++opt) {
        if (strcmp(optName, opt->name) != 0) {
            continue;
        }

        // case: opt doesn't have value
        if (opt->valueType == HITLS_APP_OPT_VALUETYPE_NO_VALUE) {
            if (g_cmdOptState.valueStr != NULL) {
                AppPrintError("%s does not take a value\n", opt->name);
                return HITLS_APP_OPT_ERR;
            }
            return opt->optType;
        }

        // case: opt should has value
        if (g_cmdOptState.valueStr == NULL) {
            if (g_cmdOptState.optIndex > g_cmdOptState.argc || g_cmdOptState.argv[g_cmdOptState.optIndex] == NULL) {
                AppPrintError("%s needs a value\n", opt->name);
                return HITLS_APP_OPT_ERR;
            }
            g_cmdOptState.valueStr = g_cmdOptState.argv[g_cmdOptState.optIndex];
            g_cmdOptState.optIndex++;
        }

        if (CheckOptValueType(opt, g_cmdOptState.valueStr) != HITLS_APP_SUCCESS) {
            return HITLS_APP_OPT_ERR;
        }

        return opt->optType;
    }

    if (g_unKnownOpt != NULL) {
        g_unKownName = optName;
        return g_unKnownOpt->optType;
    }

    AppPrintError("%s: Unknown option: -%s\n", g_cmdOptState.progName, optName);
    return HITLS_APP_OPT_ERR;
}

struct {
    HITLS_ValueType type;
    char *param;
} g_valTypeParam[] = {
    {HITLS_APP_OPT_VALUETYPE_IN_FILE, "infile"},
    {HITLS_APP_OPT_VALUETYPE_OUT_FILE, "outfile"},
    {HITLS_APP_OPT_VALUETYPE_STRING, "val"},
    {HITLS_APP_OPT_VALUETYPE_PARAMTERS, ""},
    {HITLS_APP_OPT_VALUETYPE_DIR, "dir"},
    {HITLS_APP_OPT_VALUETYPE_INT, "int"},
    {HITLS_APP_OPT_VALUETYPE_UINT, "uint"},
    {HITLS_APP_OPT_VALUETYPE_POSITIVE_INT, "uint(>0)"},
    {HITLS_APP_OPT_VALUETYPE_LONG, "long"},
    {HITLS_APP_OPT_VALUETYPE_ULONG, "ulong"},
    {HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "PEM|DER"},
    {HITLS_APP_OPT_VALUETYPE_FMT_ANY, "format"}
};

/* Return a string describing the parameter type. */
static const char *ValueType2Param(HITLS_ValueType type)
{
    for (int i = 0; i <= (int)sizeof(g_valTypeParam); i++) {
        if (type == g_valTypeParam[i].type)
            return g_valTypeParam[i].param;
    }
    return "";
}

static void OptPrint(const HITLS_CmdOption *opt, int width)
{
    const char *help = opt->help ? opt->help : "";
    char start[MAX_HITLS_APP_OPT_LINE_WIDTH + 1] = {0};
    (void)memset_s(start, sizeof(start) - 1, ' ', sizeof(start) - 1);
    start[sizeof(start) - 1] = '\0';
    int pos = 0;
    start[pos++] = ' ';

    if (opt->valueType != HITLS_APP_OPT_VALUETYPE_PARAMTERS) {
        start[pos++] = '-';
    } else {
        start[pos++] = '[';
    }
    if (strlen(opt->name) > 0) {
        if (EOK == strncpy_s(&start[pos], sizeof(start) - pos - 1, opt->name, strlen(opt->name))) {
            pos += strlen(opt->name);
        }
        (void)memset_s(&start[pos + 1], sizeof(start) - 1 - pos - 1, ' ', sizeof(start) - 1 - pos - 1);
    } else {
        start[pos++] = '*';
    }

    if (opt->valueType == HITLS_APP_OPT_VALUETYPE_PARAMTERS) {
        start[pos++] = ']';
    }

    if (opt->valueType != HITLS_APP_OPT_VALUETYPE_NO_VALUE) {
        start[pos++] = ' ';
        const char *param = ValueType2Param(opt->valueType);
        if (strncpy_s(&start[pos], sizeof(start) - pos - 1, param, strlen(param)) == EOK) {
            pos += strlen(param);
        }
        (void)memset_s(&start[pos + 1], sizeof(start) - 1 - pos - 1, ' ', sizeof(start) - 1 - pos - 1);
    }
    start[pos++] = ' ';
    if (pos >= MAX_HITLS_APP_OPT_NAME_WIDTH) {
        start[pos] = '\0';
        AppPrintError("%s\n", start);
        (void)memset_s(start, sizeof(start) - 1, ' ', sizeof(start) - 1);
    }
    start[width] = '\0';
    AppPrintError("%s  %s\n", start, help);
}

void HITLS_APP_OptHelpPrint(const HITLS_CmdOption *opts)
{
    int width = 5;
    int len = 0;
    const HITLS_CmdOption *opt;
    for (opt = opts; opt->name != NULL; opt++) {
        len = 1 + (int)strlen(opt->name) + 1;  // '-' + name + space
        if (opt->valueType != HITLS_APP_OPT_VALUETYPE_NO_VALUE) {
            len += 1 + strlen(ValueType2Param(opt->valueType));
        }
        if (len < MAX_HITLS_APP_OPT_NAME_WIDTH && len > width) {
            width = len;
        }
    }
    AppPrintError("Usage: %s \n", g_cmdOptState.progName);

    for (opt = opts; opt->name != NULL; opt++) {
        (void)OptPrint(opt, width);
    }
}

void HITLS_APP_OptEnd(void)
{
    CmdOptStateClear();
}

BSL_UIO *HITLS_APP_UioOpen(const char *filename, char mode, int32_t flag)
{
    if (mode != 'w' && mode != 'r' && mode != 'a') {
        AppPrintError("Invalid mode, only support a/w/r\n");
        return NULL;
    }
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (uio == NULL) {
        return uio;
    }
    int32_t cmd = 0;
    int32_t larg = 0;
    void *parg = NULL;
    if (filename == NULL) {
        cmd = BSL_UIO_FILE_PTR;
        larg = flag;
        switch (mode) {
            case 'w': parg = (void *)stdout;
                break;
            case 'r': parg = (void *)stdin;
                break;
            default:
                BSL_UIO_Free(uio);
                AppPrintError("Only standard I/O is supported\n");
                return NULL;
        }
    } else {
        parg = (void *)(uintptr_t)filename;
        cmd = BSL_UIO_FILE_OPEN;
        switch (mode) {
            case 'w': larg = BSL_UIO_FILE_WRITE;
                break;
            case 'r': larg = BSL_UIO_FILE_READ;
                break;
            case 'a': larg = BSL_UIO_FILE_APPEND;
                break;
            default:
                BSL_UIO_Free(uio);
                AppPrintError("Only standard I/O is supported\n");
                return NULL;
        }
    }
    int32_t ctrlRet = BSL_UIO_Ctrl(uio, cmd, larg, parg);
    if (ctrlRet != BSL_SUCCESS) {
        AppPrintError("Failed to bind the filepath\n");
        BSL_UIO_Free(uio);
        uio = NULL;
    }
    return uio;
}

int32_t HITLS_APP_OptToBase64(uint8_t *inBuf, uint32_t inBufLen, char *outBuf, uint32_t outBufLen)
{
    if (inBuf == NULL || outBuf == NULL || inBufLen == 0 || outBufLen == 0) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    // encode conversion
    int32_t encodeRet = BSL_BASE64_Encode(inBuf, inBufLen, outBuf, &outBufLen);
    if (encodeRet != BSL_SUCCESS) {
        AppPrintError("Failed to convert to Base64 format\n");
        return HITLS_APP_ENCODE_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_OptToHex(uint8_t *inBuf, uint32_t inBufLen, char *outBuf, uint32_t outBufLen)
{
    // One byte is encoded into hex and becomes 2 bytes.
    int32_t hexCharSize = 2;
    if (inBuf == NULL || outBuf == NULL || inBufLen == 0 || outBufLen < hexCharSize * inBufLen + 1) {
        AppPrintError("opt: Invalid input buffer or output buffer.\n");
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    const char *hexChars = "0123456789abcdef";
    size_t pos = 0;

    for (size_t i = 0; i < inBufLen; ++i) {
        outBuf[pos++] = hexChars[(inBuf[i] >> 4) & 0xF]; // high 4 bits.
        outBuf[pos++] = hexChars[inBuf[i] & 0xF]; // low 4 bits.
    }

    outBuf[pos] = '\0';
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_OptWriteUio(BSL_UIO *uio, uint8_t *buf, uint32_t bufLen, int32_t format)
{
    if (buf == NULL || uio == NULL || bufLen == 0) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    uint32_t outBufLen = 0;
    uint32_t writeLen = 0;
    switch (format) {
        case HITLS_APP_FORMAT_BASE64:
            /* In the Base64 format, three 8-bit bytes are converted into four 6-bit bytes. Therefore, the length
               of the data in the Base64 format must be at least (Length of the original data + 2)/3 x 4.
               The original data length plus 2 is used to ensure that
               the remainder of buflen divided by 3 after rounding down is not lost. */
            outBufLen = (bufLen + 2) / 3 * 4;
            break;
        // One byte is encoded into hex and becomes 2 bytes.
        case HITLS_APP_FORMAT_HEX:
            outBufLen = bufLen * 2; // The length of the encoded data is 2 times the length of the original data.
            break;
        default: // The original length of bufLen is used by the default type.
            outBufLen = bufLen;
    }
    char *outBuf = (char *)BSL_SAL_Calloc(outBufLen + 1, 1);
    if (outBuf == NULL) {
        AppPrintError("Failed to read the UIO content to calloc space\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    int32_t outRet = HITLS_APP_SUCCESS;
    switch (format) {
        case HITLS_APP_FORMAT_BASE64:
            outRet = HITLS_APP_OptToBase64(buf, bufLen, outBuf, outBufLen + 1);
            break;
        case HITLS_APP_FORMAT_HEX:
            outRet = HITLS_APP_OptToHex(buf, bufLen, outBuf, outBufLen + 1);
            break;
        default:
            outRet = memcpy_s(outBuf, outBufLen, buf, bufLen);
            break;
    }
    if (outRet != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(outBuf);
        return outRet;
    }
    int32_t writeRet = BSL_UIO_Write(uio, outBuf, outBufLen, &writeLen);
    BSL_SAL_FREE(outBuf);
    if (writeRet != BSL_SUCCESS || outBufLen != writeLen) {
        AppPrintError("Failed to output the content.\n");
        return HITLS_APP_UIO_FAIL;
    }
    (void)BSL_UIO_Ctrl(uio, BSL_UIO_FLUSH, 0, NULL);
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_OptReadUio(BSL_UIO *uio, uint8_t **readBuf, uint64_t *readBufLen, uint64_t maxBufLen)
{
    if (uio == NULL) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    int32_t readRet = BSL_UIO_Ctrl(uio, BSL_UIO_PENDING, sizeof(*readBufLen), readBufLen);
    if (readRet != BSL_SUCCESS) {
        AppPrintError("Failed to obtain the content length\n");
        return HITLS_APP_UIO_FAIL;
    }
    if (*readBufLen == 0 || *readBufLen > maxBufLen) {
        AppPrintError("Invalid content length\n");
        return HITLS_APP_UIO_FAIL;
    }
    // obtain the length of the UIO content, the pointer of the input parameter points to the allocated memory
    uint8_t *buf = (uint8_t *)BSL_SAL_Calloc(*readBufLen + 1, 1);
    if (buf == NULL) {
        AppPrintError("Failed to create the space.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint32_t readLen = 0;
    readRet = BSL_UIO_Read(uio, buf, *readBufLen, &readLen); // read content to memory
    if (readRet != BSL_SUCCESS || *readBufLen != readLen) {
        BSL_SAL_FREE(buf);
        AppPrintError("Failed to read UIO content.\n");
        return HITLS_APP_UIO_FAIL;
    }
    buf[*readBufLen] = '\0';
    *readBuf = buf;
    return HITLS_APP_SUCCESS;
}
