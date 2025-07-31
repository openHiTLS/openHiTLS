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
#include "app_dgst.h"
#include <linux/limits.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"
#include "bsl_errno.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"

#define MAX_BUFSIZE (1024 * 8)  // Indicates the length of a single digest during digest calculation.
#define IS_SUPPORT_GET_EOF 1
#define DEFAULT_SHAKE256_SIZE 32
#define DEFAULT_SHAKE128_SIZE 16
typedef enum OptionChoice {
    HITLS_APP_OPT_DGST_ERR = -1,
    HITLS_APP_OPT_DGST_EOF = 0,
    HITLS_APP_OPT_DGST_FILE = HITLS_APP_OPT_DGST_EOF,
    HITLS_APP_OPT_DGST_HELP =
        1,  // The value of the help type of each opt option is 1. The following can be customized.
    HITLS_APP_OPT_DGST_ALG,
    HITLS_APP_OPT_DGST_OUT,
} HITLSOptType;

const HITLS_CmdOption g_dgstOpts[] = {
    {"help", HITLS_APP_OPT_DGST_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"md", HITLS_APP_OPT_DGST_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Digest algorithm"},
    {"out", HITLS_APP_OPT_DGST_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output the summary result to a file"},
    {"file...", HITLS_APP_OPT_DGST_FILE, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Files to be digested"},
    {NULL}};

typedef struct {
    char *algName;
    int32_t algId;
    uint32_t digestSize;  // the length of default hash value of the algorithm
} AlgInfo;

static AlgInfo g_dgstInfo = {"sha256", CRYPT_MD_SHA256, 0};
static int32_t g_argc = 0;
static char **g_argv;
static int32_t OptParse(char **outfile);
static CRYPT_EAL_MdCTX *InitAlgDigest(CRYPT_MD_AlgId id);
static int32_t ReadFileToBuf(CRYPT_EAL_MdCTX *ctx, const char *filename);
static int32_t HashValToFinal(
    uint8_t *hashBuf, uint32_t hashBufLen, uint8_t **buf, uint32_t *bufLen, const char *filename);
static int32_t MdFinalToBuf(CRYPT_EAL_MdCTX *ctx, uint8_t **buf, uint32_t *bufLen, const char *filename);
static int32_t BufOutToUio(const char *outfile, BSL_UIO *fileWriteUio, uint8_t *outBuf, uint32_t outBufLen);
static int32_t MultiFileSetCtx(CRYPT_EAL_MdCTX *ctx);
static int32_t StdSumAndOut(CRYPT_EAL_MdCTX *ctx, const char *outfile);
static int32_t FileSumOutFile(CRYPT_EAL_MdCTX *ctx, const char *outfile);
static int32_t FileSumOutStd(CRYPT_EAL_MdCTX *ctx);
static int32_t FileSumAndOut(CRYPT_EAL_MdCTX *ctx, const char *outfile);

int32_t HITLS_DgstMain(int argc, char *argv[])
{
    char *outfile = NULL;
    int32_t mainRet = HITLS_APP_SUCCESS;
    CRYPT_EAL_MdCTX *ctx = NULL;
    mainRet = HITLS_APP_OptBegin(argc, argv, g_dgstOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        (void)AppPrintError("error in opt begin.\n");
        goto end;
    }
    mainRet = OptParse(&outfile);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    g_argc = HITLS_APP_GetRestOptNum();
    g_argv = HITLS_APP_GetRestOpt();
    ctx = InitAlgDigest(g_dgstInfo.algId);
    if (ctx == NULL) {
        mainRet = HITLS_APP_CRYPTO_FAIL;
        goto end;
    }
    if (g_dgstInfo.algId == CRYPT_MD_SHAKE128) {
        g_dgstInfo.digestSize = DEFAULT_SHAKE128_SIZE;
    } else if (g_dgstInfo.algId == CRYPT_MD_SHAKE256) {
        g_dgstInfo.digestSize = DEFAULT_SHAKE256_SIZE;
    } else {
        g_dgstInfo.digestSize = CRYPT_EAL_MdGetDigestSize(g_dgstInfo.algId);
        if (g_dgstInfo.digestSize == 0) {
            mainRet = HITLS_APP_CRYPTO_FAIL;
            (void)AppPrintError("Failed to obtain the default length of the algorithm(%s)\n", g_dgstInfo.algName);
            goto end;
        }
    }
    mainRet = (g_argc == 0) ? StdSumAndOut(ctx, outfile) : FileSumAndOut(ctx, outfile);
    CRYPT_EAL_MdDeinit(ctx);  // algorithm release
end:
    CRYPT_EAL_MdFreeCtx(ctx);
    HITLS_APP_OptEnd();
    return mainRet;
}

static int32_t StdSumAndOut(CRYPT_EAL_MdCTX *ctx, const char *outfile)
{
    int32_t stdRet = HITLS_APP_SUCCESS;
    BSL_UIO *readUio = HITLS_APP_UioOpen(NULL, 'r', 1);
    if (readUio == NULL) {
        AppPrintError("Failed to open the stdin\n");
        return HITLS_APP_UIO_FAIL;
    }

    uint32_t readLen = MAX_BUFSIZE;
    uint8_t readBuf[MAX_BUFSIZE] = {0};

    bool isEof = false;
    while (BSL_UIO_Ctrl(readUio, BSL_UIO_FILE_GET_EOF, IS_SUPPORT_GET_EOF, &isEof) == BSL_SUCCESS && !isEof) {
        if (BSL_UIO_Read(readUio, readBuf, MAX_BUFSIZE, &readLen) != BSL_SUCCESS) {
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to obtain the content from the STDIN\n");
            return HITLS_APP_STDIN_FAIL;
        }
        if (readLen == 0) {
            break;
        }
        stdRet = CRYPT_EAL_MdUpdate(ctx, readBuf, readLen);
        if (stdRet != CRYPT_SUCCESS) {
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to continuously summarize the STDIN content\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    BSL_UIO_Free(readUio);
    uint8_t *outBuf = NULL;
    uint32_t outBufLen = 0;
    // reads the final hash value to the buffer
    stdRet = MdFinalToBuf(ctx, &outBuf, &outBufLen, "stdin");
    if (stdRet != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(outBuf);
        return stdRet;
    }
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(outfile, 'w', 1);
    if (fileWriteUio == NULL) {
        BSL_UIO_Free(fileWriteUio);
        BSL_SAL_FREE(outBuf);
        AppPrintError("Failed to open the <%s>\n", outfile);
        return HITLS_APP_UIO_FAIL;
    }
    // outputs the hash value to the UIO
    stdRet = BufOutToUio(outfile, fileWriteUio, (uint8_t *)outBuf, outBufLen);
    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    BSL_UIO_Free(fileWriteUio);
    BSL_SAL_FREE(outBuf);
    return stdRet;
}

static int32_t ReadFileToBuf(CRYPT_EAL_MdCTX *ctx, const char *filename)
{
    int32_t readRet = HITLS_APP_SUCCESS;
    BSL_UIO *readUio = HITLS_APP_UioOpen(filename, 'r', 0);
    if (readUio == NULL) {
        (void)AppPrintError("Failed to open the file <%s>, No such file or directory\n", filename);
        return HITLS_APP_UIO_FAIL;
    }
    uint64_t readFileLen = 0;
    readRet = BSL_UIO_Ctrl(readUio, BSL_UIO_PENDING, sizeof(readFileLen), &readFileLen);
    if (readRet != BSL_SUCCESS) {
        BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
        BSL_UIO_Free(readUio);
        (void)AppPrintError("Failed to obtain the content length\n");
        return HITLS_APP_UIO_FAIL;
    }

    while (readFileLen > 0) {
        uint8_t readBuf[MAX_BUFSIZE] = {0};
        uint32_t bufLen = (readFileLen > MAX_BUFSIZE) ? MAX_BUFSIZE : (uint32_t)readFileLen;
        uint32_t readLen = 0;
        readRet = BSL_UIO_Read(readUio, readBuf, bufLen, &readLen); // read content to memory
        if (readRet != BSL_SUCCESS || bufLen != readLen) {
            BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to read the input content\n");
            return HITLS_APP_UIO_FAIL;
        }
        readRet = CRYPT_EAL_MdUpdate(ctx, readBuf, bufLen); // continuously enter summary content
        if (readRet != CRYPT_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
            BSL_UIO_Free(readUio);
            (void)AppPrintError("Failed to continuously summarize the file content\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        readFileLen -= bufLen;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
    BSL_UIO_Free(readUio);
    return HITLS_APP_SUCCESS;
}

static int32_t BufOutToUio(const char *outfile, BSL_UIO *fileWriteUio, uint8_t *outBuf, uint32_t outBufLen)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    if (outfile == NULL) {
        BSL_UIO *stdOutUio = HITLS_APP_UioOpen(NULL, 'w', 0);
        if (stdOutUio == NULL) {
            return HITLS_APP_UIO_FAIL;
        }
        outRet = HITLS_APP_OptWriteUio(stdOutUio, outBuf, outBufLen, HITLS_APP_FORMAT_TEXT);
        BSL_UIO_Free(stdOutUio);
        if (outRet != HITLS_APP_SUCCESS) {
            (void)AppPrintError("Failed to output the content to the screen\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        outRet = HITLS_APP_OptWriteUio(fileWriteUio, outBuf, outBufLen, HITLS_APP_FORMAT_TEXT);
        if (outRet != HITLS_APP_SUCCESS) {
            (void)AppPrintError("Failed to export data to the file path: <%s>\n", outfile);
            return HITLS_APP_UIO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HashValToFinal(
    uint8_t *hashBuf, uint32_t hashBufLen, uint8_t **buf, uint32_t *bufLen, const char *filename)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    uint32_t hexBufLen = hashBufLen * 2 + 1;
    uint8_t *hexBuf = (uint8_t *)BSL_SAL_Calloc(hexBufLen, sizeof(uint8_t)); // save the hexadecimal hash value
    if (hexBuf == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    outRet = HITLS_APP_OptToHex(hashBuf, hashBufLen, (char *)hexBuf, hexBufLen);
    if (outRet != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(hexBuf);
        return HITLS_APP_ENCODE_FAIL;
    }
    uint32_t outBufLen;
    if (g_argc == 0) {
        // standard input(stdin) = hashValue,
        // 5 indicates " " + "()" + "=" + "\n"
        outBufLen = strlen("stdin") + hexBufLen + 5;
    } else {
        // 5: " " + "()" + "=" + "\n", and concatenate the string alg_name(filename1)=hash.
        outBufLen = strlen(g_dgstInfo.algName) + strlen(filename) + hexBufLen + 5;
    }
    char *outBuf = (char *)BSL_SAL_Calloc(outBufLen, sizeof(char));  // save the concatenated hash value
    if (outBuf == NULL) {
        (void)AppPrintError("Failed to open the format control content space\n");
        BSL_SAL_FREE(hexBuf);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    if (g_argc == 0) {  // standard input
        outRet = snprintf_s(outBuf, outBufLen, outBufLen - 1, "(%s)= %s\n", "stdin", (char *)hexBuf);
    } else {
        outRet = snprintf_s(
            outBuf, outBufLen, outBufLen - 1, "%s(%s)= %s\n", g_dgstInfo.algName, filename, (char *)hexBuf);
    }
    uint32_t len = strlen(outBuf);
    BSL_SAL_FREE(hexBuf);
    if (outRet == -1) {
        BSL_SAL_FREE(outBuf);
        (void)AppPrintError("Failed to combine the output content\n");
        return HITLS_APP_SECUREC_FAIL;
    }
    char *finalOutBuf = (char *)BSL_SAL_Calloc(len, sizeof(char));
    if (memcpy_s(finalOutBuf, len, outBuf, strlen(outBuf)) != EOK) {
        BSL_SAL_FREE(outBuf);
        BSL_SAL_FREE(finalOutBuf);
        return HITLS_APP_SECUREC_FAIL;
    }
    BSL_SAL_FREE(outBuf);
    *buf = (uint8_t *)finalOutBuf;
    *bufLen = len;
    return HITLS_APP_SUCCESS;
}

static int32_t MdFinalToBuf(CRYPT_EAL_MdCTX *ctx, uint8_t **buf, uint32_t *bufLen, const char *filename)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    // save the initial hash value
    uint8_t *hashBuf = (uint8_t *)BSL_SAL_Calloc(g_dgstInfo.digestSize + 1, sizeof(uint8_t));
    if (hashBuf == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint32_t hashBufLen = g_dgstInfo.digestSize;
    outRet = CRYPT_EAL_MdFinal(ctx, hashBuf, &hashBufLen); // complete the digest and output the final digest to the buf
    if (outRet != CRYPT_SUCCESS || hashBufLen < g_dgstInfo.digestSize) {
        BSL_SAL_FREE(hashBuf);
        (void)AppPrintError("filename: %s Failed to complete the final summary\n", filename);
        return HITLS_APP_CRYPTO_FAIL;
    }
    outRet = HashValToFinal(hashBuf, hashBufLen, buf, bufLen, filename);
    BSL_SAL_FREE(hashBuf);
    return outRet;
}

static int32_t FileSumOutStd(CRYPT_EAL_MdCTX *ctx)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    // Traverse the files that need to be digested, obtain the file content, calculate the file content digest,
    // and output the digest to the UIO.
    for (int i = 0; i < g_argc; ++i) {
        outRet = CRYPT_EAL_MdDeinit(ctx); // md release
        if (outRet != CRYPT_SUCCESS) {
            (void)AppPrintError("Summary context deinit failed.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        outRet = CRYPT_EAL_MdInit(ctx); // md initialization
        if (outRet != CRYPT_SUCCESS) {
            (void)AppPrintError("Summary context creation failed.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        outRet = ReadFileToBuf(ctx, g_argv[i]); // read the file content by block and calculate the hash value
        if (outRet != HITLS_APP_SUCCESS) {
            return HITLS_APP_UIO_FAIL;
        }
        uint8_t *outBuf = NULL;
        uint32_t outBufLen = 0;
        outRet = MdFinalToBuf(ctx, &outBuf, &outBufLen, g_argv[i]); // read the final hash value to the buffer
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(outBuf);
            (void)AppPrintError("Failed to output the final summary value\n");
            return outRet;
        }

        BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(NULL, 'w', 0); // the standard output is required for each file
        if (fileWriteUio == NULL) {
            BSL_SAL_FREE(outBuf);
            (void)AppPrintError("Failed to open the stdout\n");
            return HITLS_APP_UIO_FAIL;
        }
        outRet = BufOutToUio(NULL, fileWriteUio, (uint8_t *)outBuf, outBufLen); // output the hash value to the UIO
        BSL_SAL_FREE(outBuf);
        BSL_UIO_Free(fileWriteUio);
        if (outRet != HITLS_APP_SUCCESS) { // Released after the standard output is complete
            (void)AppPrintError("Failed to output the hash value\n");
            return outRet;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t MultiFileSetCtx(CRYPT_EAL_MdCTX *ctx)
{
    int32_t outRet = CRYPT_EAL_MdDeinit(ctx); // md release
    if (outRet != CRYPT_SUCCESS) {
        (void)AppPrintError("Summary context deinit failed.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    outRet = CRYPT_EAL_MdInit(ctx); // md initialization
    if (outRet != CRYPT_SUCCESS) {
        (void)AppPrintError("Summary context creation failed.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t FileSumOutFile(CRYPT_EAL_MdCTX *ctx, const char *outfile)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(outfile, 'w', 0);  // overwrite the original content
    if (fileWriteUio == NULL) {
        (void)AppPrintError("Failed to open the file path: %s\n", outfile);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    BSL_UIO_Free(fileWriteUio);
    fileWriteUio = HITLS_APP_UioOpen(outfile, 'a', 0);
    if (fileWriteUio == NULL) {
        (void)AppPrintError("Failed to open the file path: %s\n", outfile);
        return HITLS_APP_UIO_FAIL;
    }
    for (int i = 0; i < g_argc; ++i) {
        // Traverse the files that need to be digested, obtain the file content, calculate the file content digest,
        // and output the digest to the UIO.
        outRet = MultiFileSetCtx(ctx);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
            BSL_UIO_Free(fileWriteUio);
            return outRet;
        }
        outRet = ReadFileToBuf(ctx, g_argv[i]); // read the file content by block and calculate the hash value
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
            BSL_UIO_Free(fileWriteUio);
            (void)AppPrintError("Failed to read the file content by block and calculate the hash value\n");
            return HITLS_APP_UIO_FAIL;
        }
        uint8_t *outBuf = NULL;
        uint32_t outBufLen = 0;
        outRet = MdFinalToBuf(ctx, &outBuf, &outBufLen, g_argv[i]); // read the final hash value to the buffer
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(outBuf);
            BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
            BSL_UIO_Free(fileWriteUio);
            (void)AppPrintError("Failed to output the final summary value\n");
            return outRet;
        }
        outRet = BufOutToUio(outfile, fileWriteUio, (uint8_t *)outBuf, outBufLen); // output the hash value to the UIO
        BSL_SAL_FREE(outBuf);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
            BSL_UIO_Free(fileWriteUio);
            return outRet;
        }
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    BSL_UIO_Free(fileWriteUio);
    return HITLS_APP_SUCCESS;
}

static int32_t FileSumAndOut(CRYPT_EAL_MdCTX *ctx, const char *outfile)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    if (outfile == NULL) {
        // standard output, w overwriting mode
        outRet = FileSumOutStd(ctx);
    } else {
        // file output appending mode
        outRet = FileSumOutFile(ctx, outfile);
    }
    return outRet;
}

static CRYPT_EAL_MdCTX *InitAlgDigest(CRYPT_MD_AlgId id)
{
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, id, "provider=default"); // creating an MD Context
    if (ctx == NULL) {
        (void)AppPrintError("Failed to create the algorithm(%s) context\n", g_dgstInfo.algName);
        return NULL;
    }
    int32_t ret = CRYPT_EAL_MdInit(ctx); // md initialization
    if (ret != CRYPT_SUCCESS) {
        (void)AppPrintError("Summary context creation failed\n");
        CRYPT_EAL_MdFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static int32_t OptParse(char **outfile)
{
    HITLSOptType optType;
    int ret = HITLS_APP_SUCCESS;

    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_DGST_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_DGST_EOF:
            case HITLS_APP_OPT_DGST_ERR:
                ret = HITLS_APP_OPT_UNKOWN;
                (void)AppPrintError("dgst: Use -help for summary.\n");
                return ret;
            case HITLS_APP_OPT_DGST_HELP:
                ret = HITLS_APP_HELP;
                (void)HITLS_APP_OptHelpPrint(g_dgstOpts);
                return ret;
            case HITLS_APP_OPT_DGST_OUT:
                *outfile = HITLS_APP_OptGetValueStr();
                if (*outfile == NULL || strlen(*outfile) >= PATH_MAX) {
                    AppPrintError("The length of outfile error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_ALG:
                g_dgstInfo.algName = HITLS_APP_OptGetValueStr();
                if (g_dgstInfo.algName == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                g_dgstInfo.algId = HITLS_APP_GetCidByName(g_dgstInfo.algName, HITLS_APP_LIST_OPT_DGST_ALG);
                if (g_dgstInfo.algId == BSL_CID_UNKNOWN) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            default:
                return HITLS_APP_OPT_UNKOWN;
        }
    }
    return HITLS_APP_SUCCESS;
}
