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
#include <limits.h>
#include <string.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "bsl_errno.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_utils.h"
#include "app_sm.h"
#include "app_keymgmt.h"
#include "app_provider.h"

#define IS_SUPPORT_GET_EOF 1
#define MAX_CERT_KEY_SIZE (256 * 1024)

typedef enum OptionChoice {
    HITLS_APP_OPT_DGST_ERR = -1,
    HITLS_APP_OPT_DGST_EOF = 0,
    HITLS_APP_OPT_DGST_FILE = HITLS_APP_OPT_DGST_EOF,
    HITLS_APP_OPT_DGST_HELP =
        1,  // The value of the help type of each opt option is 1. The following can be customized.
    HITLS_APP_OPT_DGST_ALG,
    HITLS_APP_OPT_DGST_OUT,
    HITLS_APP_OPT_DGST_COLON,
    HITLS_APP_OPT_DGST_SIGN,
    HITLS_APP_OPT_DGST_VERIFY,
    HITLS_APP_OPT_DGST_SIGNATURE,
    HITLS_APP_OPT_DGST_SIGN_FORMAT,
    HITLS_APP_OPT_DGST_USERID,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLSOptType;

static const HITLS_CmdOption g_dgstOpts[] = {
    {"help", HITLS_APP_OPT_DGST_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"md", HITLS_APP_OPT_DGST_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Digest algorithm"},
    {"out", HITLS_APP_OPT_DGST_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output the summary result to a file"},
    {"c", HITLS_APP_OPT_DGST_COLON, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
        "In digest mode, print the hexadecimal digest with separating colons"},
    {"sign", HITLS_APP_OPT_DGST_SIGN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Private key for signature"},
    {"verify", HITLS_APP_OPT_DGST_VERIFY, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Public key for signature verification"},
    {"signature", HITLS_APP_OPT_DGST_SIGNATURE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Signature to be verified"},
    {"signfmt", HITLS_APP_OPT_DGST_SIGN_FORMAT, HITLS_APP_OPT_VALUETYPE_STRING,
        "Signature input/output format: hex or bin (default: hex)"},
    {"userid", HITLS_APP_OPT_DGST_USERID, HITLS_APP_OPT_VALUETYPE_STRING, "User ID for SM2"},
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {"file...", HITLS_APP_OPT_DGST_FILE, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Files to be digested"},
    {NULL, 0, 0, NULL}
};

typedef struct {
    char *algName;
    int32_t algId;
    uint32_t digestSize;  // the length of default hash value of the algorithm
} AlgInfo;

typedef struct {
    char *privateKeyFile;  // private key file for signing
    char *publicKeyFile;   // public key file for verification
    char *signatureFile;   // signature file for verification
    uint32_t signFormat;   // signature input/output format
    char *userid;          // user ID for SM2
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} SignInfo;

typedef struct {
    int32_t inputFileNum;
    char **inputFiles;
    char *outFile;
    bool colon;
    AlgInfo algInfo;
    SignInfo signInfo;
} DgstOptCtx;

static void InitDgstOptCtx(DgstOptCtx *optCtx)
{
    optCtx->algInfo.algName = "sha256";
    optCtx->algInfo.algId = CRYPT_MD_SHA256;
    optCtx->signInfo.signFormat = HITLS_APP_FORMAT_HEX;
    optCtx->signInfo.userid = "1234567812345678";
}

static CRYPT_EAL_MdCtx *InitAlgDigest(const DgstOptCtx *optCtx)
{
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_ProviderMdNewCtx(APP_GetCurrent_LibCtx(), optCtx->algInfo.algId,
        optCtx->signInfo.provider->providerAttr);
    if (ctx == NULL) {
        AppPrintError("dgst: Failed to create the algorithm(%s) context\n", optCtx->algInfo.algName);
        return NULL;
    }
    int32_t ret = CRYPT_EAL_MdInit(ctx); // md initialization
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("dgst: Summary context creation failed\n");
        CRYPT_EAL_MdFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static int32_t HashValToFinal(
    const DgstOptCtx *optCtx, uint8_t *hashBuf, uint32_t hashBufLen, uint8_t **buf, uint32_t *bufLen,
    const char *filename)
{
    int32_t outRet;
    uint32_t hexBufLen = hashBufLen * 2 + (optCtx->colon ? hashBufLen - 1 : 0);
    char *hexBuf = (char *)BSL_SAL_Calloc(hexBufLen + 1, 1); // save the hexadecimal hash value
    if (hexBuf == NULL) {
        AppPrintError("dgst: Failed to alloc memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    if (HITLS_APP_BytesToHex(hashBuf, hashBufLen, hexBuf, hexBufLen + 1) != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(hexBuf);
        return HITLS_APP_ENCODE_FAIL;
    }
    if (optCtx->colon) {
        hexBuf[hexBufLen] = '\0';
        for (uint32_t i = hashBufLen; i > 0; i--) {
            uint32_t index = i - 1;
            hexBuf[index * 3 + 1] = hexBuf[index * 2 + 1];
            hexBuf[index * 3] = hexBuf[index * 2];
            if (i < hashBufLen) {
                hexBuf[index * 3 + 2] = ':';
            }
        }
    }
    uint32_t outBufLen;
    if (optCtx->inputFileNum == 0) {
        // standard input(stdin) = hashValue,
        outBufLen = strlen("(stdin)= \n") + hexBufLen;
    } else {
        outBufLen = strlen(optCtx->algInfo.algName) + strlen("()= \n") + strlen(filename) + hexBufLen;
    }
    char *outBuf = (char *)BSL_SAL_Calloc(outBufLen + 1, 1);  // save the concatenated hash value
    if (outBuf == NULL) {
        AppPrintError("dgst: Failed to alloc memory.\n");
        BSL_SAL_FREE(hexBuf);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    if (optCtx->inputFileNum == 0) {  // standard input
        outRet = snprintf(outBuf, outBufLen + 1, "(stdin)= %s\n", hexBuf);
    } else {
        outRet = snprintf(outBuf, outBufLen + 1, "%s(%s)= %s\n", optCtx->algInfo.algName, filename, hexBuf);
    }
    BSL_SAL_FREE(hexBuf);
    if (outRet < 0) {
        BSL_SAL_FREE(outBuf);
        AppPrintError("dgst: Failed to combine the output content\n");
        return HITLS_APP_ENCODE_FAIL;
    }
    *buf = (uint8_t *)outBuf;
    *bufLen = outRet;
    return HITLS_APP_SUCCESS;
}

static int32_t MdFinalToBuf(
    const DgstOptCtx *optCtx, CRYPT_EAL_MdCtx *ctx, uint8_t **buf, uint32_t *bufLen, const char *filename)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    // save the initial hash value
    uint8_t *hashBuf = (uint8_t *)BSL_SAL_Calloc(optCtx->algInfo.digestSize + 1, 1);
    if (hashBuf == NULL) {
        AppPrintError("dgst: Failed to alloc memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint32_t hashBufLen = optCtx->algInfo.digestSize;
    outRet = CRYPT_EAL_MdFinal(ctx, hashBuf, &hashBufLen); // complete the digest and output the final digest to the buf
    if (outRet != CRYPT_SUCCESS || hashBufLen < optCtx->algInfo.digestSize) {
        BSL_SAL_FREE(hashBuf);
        AppPrintError("dgst: filename: %s Failed to complete the final summary\n", filename);
        return HITLS_APP_CRYPTO_FAIL;
    }
    outRet = HashValToFinal(optCtx, hashBuf, hashBufLen, buf, bufLen, filename);
    BSL_SAL_FREE(hashBuf);
    return outRet;
}

static int32_t BufOutToUio(const char *outfile, BSL_UIO *fileWriteUio, uint8_t *outBuf, uint32_t outBufLen)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    if (outfile == NULL) {
        BSL_UIO *stdOutUio = HITLS_APP_UioOpen(NULL, 'w', 0);
        if (stdOutUio == NULL) {
            AppPrintError("dgst: Failed to open the stdin\n");
            return HITLS_APP_UIO_FAIL;
        }
        outRet = HITLS_APP_OptWriteUio(stdOutUio, outBuf, outBufLen, HITLS_APP_FORMAT_TEXT);
        BSL_UIO_Free(stdOutUio);
        if (outRet != HITLS_APP_SUCCESS) {
            AppPrintError("dgst: Failed to output the content to the screen\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        outRet = HITLS_APP_OptWriteUio(fileWriteUio, outBuf, outBufLen, HITLS_APP_FORMAT_TEXT);
        if (outRet != HITLS_APP_SUCCESS) {
            AppPrintError("dgst: Failed to export data to the file path: <%s>\n", outfile);
            return HITLS_APP_UIO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t StdSumAndOut(const DgstOptCtx *optCtx, CRYPT_EAL_MdCtx *ctx)
{
    int32_t stdRet = HITLS_APP_SUCCESS;
    uint8_t *outBuf = NULL;
    uint32_t outBufLen = 0;
    BSL_UIO *readUio = HITLS_APP_UioOpen(NULL, 'r', 0);
    if (readUio == NULL) {
        AppPrintError("dgst: Failed to open the stdin\n");
        return HITLS_APP_UIO_FAIL;
    }
    uint32_t readLen = MAX_DIGEST_SIZE;
    uint8_t *readBuf = (uint8_t *)BSL_SAL_Calloc(MAX_DIGEST_SIZE + 1, 1);
    if (readBuf == NULL) {
        BSL_UIO_Free(readUio);
        AppPrintError("dgst: Failed to alloc memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    bool isEof = false;
    while (BSL_UIO_Ctrl(readUio, BSL_UIO_FILE_GET_EOF, IS_SUPPORT_GET_EOF, &isEof) == BSL_SUCCESS && !isEof) {
        if (BSL_UIO_Read(readUio, readBuf, MAX_DIGEST_SIZE, &readLen) != BSL_SUCCESS) {
            AppPrintError("dgst: Failed to obtain the content from the STDIN\n");
            stdRet = HITLS_APP_STDIN_FAIL;
            break;
        }
        if (readLen == 0) {
            break;
        }
        if (CRYPT_EAL_MdUpdate(ctx, readBuf, readLen) != CRYPT_SUCCESS) {
            AppPrintError("dgst: Failed to continuously summarize the STDIN content\n");
            stdRet = HITLS_APP_CRYPTO_FAIL;
            break;
        }
    }
    BSL_UIO_Free(readUio);
    BSL_SAL_FREE(readBuf);
    if (stdRet != HITLS_APP_SUCCESS) {
        return stdRet;
    }
    // reads the final hash value to the buffer
    stdRet = MdFinalToBuf(optCtx, ctx, &outBuf, &outBufLen, "stdin");
    if (stdRet != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(outBuf);
        return stdRet;
    }
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(optCtx->outFile, 'w', optCtx->outFile != NULL ? 1 : 0);
    if (fileWriteUio == NULL) {
        BSL_SAL_FREE(outBuf);
        AppPrintError("dgst: Failed to open the <%s>\n", optCtx->outFile != NULL ? optCtx->outFile : "stdout");
        return HITLS_APP_UIO_FAIL;
    }
    // outputs the hash value to the UIO
    stdRet = BufOutToUio(optCtx->outFile, fileWriteUio, (uint8_t *)outBuf, outBufLen);
    BSL_UIO_Free(fileWriteUio);
    BSL_SAL_FREE(outBuf);
    return stdRet;
}

static int32_t ReadFileToBuf(CRYPT_EAL_MdCtx *ctx, const char *filename)
{
    int32_t readRet = HITLS_APP_SUCCESS;
    BSL_UIO *readUio = HITLS_APP_UioOpen(filename, 'r', filename != NULL ? 1 : 0);
    if (readUio == NULL) {
        AppPrintError("dgst: Failed to open the file <%s>, No such file or directory\n", filename);
        return HITLS_APP_UIO_FAIL;
    }
    uint64_t readFileLen = 0;
    readRet = BSL_UIO_Ctrl(readUio, BSL_UIO_PENDING, sizeof(readFileLen), &readFileLen);
    if (readRet != BSL_SUCCESS) {
        BSL_UIO_Free(readUio);
        AppPrintError("dgst: Failed to obtain the content length\n");
        return HITLS_APP_UIO_FAIL;
    }
    uint8_t *readBuf = (uint8_t *)BSL_SAL_Calloc(MAX_DIGEST_SIZE + 1, 1);
    if (readBuf == NULL) {
        BSL_UIO_Free(readUio);
        AppPrintError("dgst: Failed to alloc memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    while (readFileLen > 0) {
        uint32_t bufLen = (readFileLen > MAX_DIGEST_SIZE) ? MAX_DIGEST_SIZE : (uint32_t)readFileLen;
        uint32_t readLen = 0;
        readRet = BSL_UIO_Read(readUio, readBuf, bufLen, &readLen); // read content to memory
        if (readRet != BSL_SUCCESS || bufLen != readLen) {
            AppPrintError("dgst: Failed to read the input content\n");
            readRet = HITLS_APP_UIO_FAIL;
            break;
        }
        readRet = CRYPT_EAL_MdUpdate(ctx, readBuf, bufLen); // continuously enter summary content
        if (readRet != CRYPT_SUCCESS) {
            AppPrintError("dgst: Failed to continuously summarize the file content\n");
            readRet = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        readFileLen -= bufLen;
    }
    BSL_UIO_Free(readUio);
    BSL_SAL_FREE(readBuf);
    return readRet;
}

static int32_t FileSumOutStd(const DgstOptCtx *optCtx, CRYPT_EAL_MdCtx *ctx)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    // Traverse the files that need to be digested, obtain the file content, calculate the file content digest,
    // and output the digest to the UIO.
    for (int32_t i = 0; i < optCtx->inputFileNum; ++i) {
        outRet = CRYPT_EAL_MdDeinit(ctx); // md release
        if (outRet != CRYPT_SUCCESS) {
            AppPrintError("dgst: Summary context deinit failed.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        outRet = CRYPT_EAL_MdInit(ctx); // md initialization
        if (outRet != CRYPT_SUCCESS) {
            AppPrintError("dgst: Summary context creation failed.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        // Read the file content by block and calculate the hash value.
        outRet = ReadFileToBuf(ctx, optCtx->inputFiles[i]);
        if (outRet != HITLS_APP_SUCCESS) {
            return HITLS_APP_UIO_FAIL;
        }
        uint8_t *outBuf = NULL;
        uint32_t outBufLen = 0;
        outRet = MdFinalToBuf(optCtx, ctx, &outBuf, &outBufLen, optCtx->inputFiles[i]);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(outBuf);
            AppPrintError("dgst: Failed to output the final summary value\n");
            return outRet;
        }

        BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(NULL, 'w', 0); // the standard output is required for each file
        if (fileWriteUio == NULL) {
            BSL_SAL_FREE(outBuf);
            AppPrintError("dgst: Failed to open the stdout\n");
            return HITLS_APP_UIO_FAIL;
        }
        outRet = BufOutToUio(NULL, fileWriteUio, (uint8_t *)outBuf, outBufLen); // output the hash value to the UIO
        BSL_SAL_FREE(outBuf);
        BSL_UIO_Free(fileWriteUio);
        if (outRet != HITLS_APP_SUCCESS) { // Released after the standard output is complete
            AppPrintError("dgst: Failed to output the hash value\n");
            return outRet;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t MultiFileSetCtx(CRYPT_EAL_MdCtx *ctx)
{
    int32_t outRet = CRYPT_EAL_MdDeinit(ctx); // md release
    if (outRet != CRYPT_SUCCESS) {
        AppPrintError("dgst: Summary context deinit failed.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    outRet = CRYPT_EAL_MdInit(ctx); // md initialization
    if (outRet != CRYPT_SUCCESS) {
        AppPrintError("dgst: Summary context creation failed.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t FileSumOutFile(const DgstOptCtx *optCtx, CRYPT_EAL_MdCtx *ctx)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(
        optCtx->outFile, 'w', optCtx->outFile != NULL ? 1 : 0);  // overwrite the original content
    if (fileWriteUio == NULL) {
        AppPrintError("dgst: Failed to open the file path: %s\n", optCtx->outFile);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_Free(fileWriteUio);
    fileWriteUio = HITLS_APP_UioOpen(optCtx->outFile, 'a', optCtx->outFile != NULL ? 1 : 0);
    if (fileWriteUio == NULL) {
        AppPrintError("dgst: Failed to open the file path: %s\n", optCtx->outFile);
        return HITLS_APP_UIO_FAIL;
    }
    for (int32_t i = 0; i < optCtx->inputFileNum; ++i) {
        // Traverse the files that need to be digested, obtain the file content, calculate the file content digest,
        // and output the digest to the UIO.
        outRet = MultiFileSetCtx(ctx);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_UIO_Free(fileWriteUio);
            return outRet;
        }
        outRet = ReadFileToBuf(ctx, optCtx->inputFiles[i]);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_UIO_Free(fileWriteUio);
            AppPrintError("dgst: Failed to read the file content by block and calculate the hash value\n");
            return HITLS_APP_UIO_FAIL;
        }
        uint8_t *outBuf = NULL;
        uint32_t outBufLen = 0;
        outRet = MdFinalToBuf(optCtx, ctx, &outBuf, &outBufLen, optCtx->inputFiles[i]);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(outBuf);
            BSL_UIO_Free(fileWriteUio);
            AppPrintError("dgst: Failed to output the final summary value\n");
            return outRet;
        }
        outRet = BufOutToUio(optCtx->outFile, fileWriteUio, (uint8_t *)outBuf, outBufLen);
        BSL_SAL_FREE(outBuf);
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_UIO_Free(fileWriteUio);
            return outRet;
        }
    }
    BSL_UIO_Free(fileWriteUio);
    return HITLS_APP_SUCCESS;
}

static int32_t FileSumAndOut(const DgstOptCtx *optCtx, CRYPT_EAL_MdCtx *ctx)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    if (optCtx->outFile == NULL) {
        // standard output, w overwriting mode
        outRet = FileSumOutStd(optCtx, ctx);
    } else {
        // file output appending mode
        outRet = FileSumOutFile(optCtx, ctx);
    }
    return outRet;
}

static int32_t CalculateDgst(DgstOptCtx *optCtx)
{
    int32_t ret = HITLS_APP_SUCCESS;
    CRYPT_EAL_MdCtx *ctx = InitAlgDigest(optCtx);
    if (ctx == NULL) {
        ret = HITLS_APP_CRYPTO_FAIL;
        return ret;
    }
#ifdef HITLS_APP_SM_MODE
    if (optCtx->signInfo.smParam->smTag == 1) {
        optCtx->signInfo.smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    }
#endif
    if (optCtx->algInfo.algId == CRYPT_MD_SHAKE128) {
        optCtx->algInfo.digestSize = HITLS_APP_SHAKE128_SIZE;
    } else if (optCtx->algInfo.algId == CRYPT_MD_SHAKE256) {
        optCtx->algInfo.digestSize = HITLS_APP_SHAKE256_SIZE;
    } else {
        optCtx->algInfo.digestSize = CRYPT_EAL_MdGetDigestSize(optCtx->algInfo.algId);
        if (optCtx->algInfo.digestSize == 0) {
            ret = HITLS_APP_CRYPTO_FAIL;
            AppPrintError("dgst: Failed to obtain the default length of the algorithm(%s)\n",
                optCtx->algInfo.algName);
            CRYPT_EAL_MdFreeCtx(ctx);
            return ret;
        }
    }
    ret = (optCtx->inputFileNum == 0) ? StdSumAndOut(optCtx, ctx) : FileSumAndOut(optCtx, ctx);
    CRYPT_EAL_MdDeinit(ctx);  // algorithm release
    CRYPT_EAL_MdFreeCtx(ctx);
    return ret;
}

#ifdef HITLS_APP_SM_MODE
static int32_t GetPkeyCtxFromUuid(SignInfo *signInfo, char *uuid, CRYPT_EAL_PkeyCtx **ctx)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    signInfo->smParam->uuid = uuid;
    int32_t ret = HITLS_APP_FindKey(signInfo->provider, signInfo->smParam, CRYPT_PKEY_SM2, &keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to find key, errCode: 0x%0x.\n", ret);
        return ret;
    }
    *ctx = keyInfo.pkeyCtx;
    return HITLS_APP_SUCCESS;
}
#endif

static int32_t CalculateSign(DgstOptCtx *optCtx, uint8_t *msgBuf, uint32_t msgBufLen)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *prvBuf = NULL;
    uint64_t bufLen = 0;
    uint8_t *signBuf = NULL;
    uint32_t signLen;
    BSL_Buffer prv = {0};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    do {
#ifdef HITLS_APP_SM_MODE
        if (optCtx->signInfo.smParam->smTag == 1) {
            ret = GetPkeyCtxFromUuid(&optCtx->signInfo, optCtx->signInfo.privateKeyFile, &ctx);
            if (ret != HITLS_APP_SUCCESS) {
                break;
            }
        } else {
#endif
            ret = HITLS_APP_ReadFileOrStdin(
                &prvBuf, &bufLen, optCtx->signInfo.privateKeyFile, MAX_CERT_KEY_SIZE, "dgst");
            if (ret != HITLS_APP_SUCCESS) {
                break;
            }
            prv.data = prvBuf;
            prv.dataLen = bufLen;
            ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(),
                optCtx->signInfo.provider->providerAttr, BSL_CID_UNKNOWN, "PEM", "PRIKEY_PKCS8_UNENCRYPT",
                &prv, NULL, &ctx);
            if (ret != CRYPT_SUCCESS) {
                AppPrintError("dgst: Failed to decode the private key, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
#ifdef HITLS_APP_SM_MODE
        }
#endif
        if (CRYPT_EAL_PkeyGetId(ctx) == CRYPT_PKEY_SM2) {
            ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, optCtx->signInfo.userid,
                strlen(optCtx->signInfo.userid));
            if (ret != CRYPT_SUCCESS) {
                AppPrintError("dgst: Failed to set the SM2 user ID, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
        }
#ifdef HITLS_APP_SM_MODE
        if (optCtx->signInfo.smParam->smTag == 1) {
            optCtx->signInfo.smParam->status = HITLS_APP_SM_STATUS_APPORVED;
        }
#endif
        signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
        if (signLen == 0) {
            AppPrintError("dgst: Failed to get the signature length.\n");
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        signBuf = BSL_SAL_Malloc(signLen);
        if (signBuf == NULL) {
            AppPrintError("dgst: Failed to allocate memory for the signature.\n");
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            break;
        }
        ret = CRYPT_EAL_PkeySign(ctx, optCtx->algInfo.algId, msgBuf, msgBufLen, signBuf, &signLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("dgst: Failed to sign the message, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }

        BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(
            optCtx->outFile, 'w', optCtx->outFile != NULL ? 1 : 0);  // overwrite the original content
        if (fileWriteUio == NULL) {
            AppPrintError("dgst: Failed to open the outfile\n");
            ret = HITLS_APP_UIO_FAIL;
            break;
        }
        ret = HITLS_APP_OptWriteUio(fileWriteUio, signBuf, signLen, optCtx->signInfo.signFormat);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("dgst:Failed to export data to the outfile path\n");
        }
        BSL_UIO_Free(fileWriteUio);
    } while (0);
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    BSL_SAL_ClearFree(prvBuf, bufLen);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(signBuf);
    return ret;
}

static int32_t GetPubKeyCtx(SignInfo *signInfo, CRYPT_EAL_PkeyCtx **ctx)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *pubBuf = NULL;
    uint64_t bufLen = 0;
    BSL_Buffer pub = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
#ifdef HITLS_APP_SM_MODE
    if (signInfo->smParam->smTag == 1) {
        ret = GetPkeyCtxFromUuid(signInfo, signInfo->publicKeyFile, &pkeyCtx);
        if (ret == HITLS_APP_SUCCESS) {
            *ctx = pkeyCtx;
            return HITLS_APP_SUCCESS;
        }
    }
#endif
    ret = HITLS_APP_ReadFileOrStdin(&pubBuf, &bufLen, signInfo->publicKeyFile, MAX_CERT_KEY_SIZE, "dgst");
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    pub.data = pubBuf;
    pub.dataLen = bufLen;
    ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(), signInfo->provider->providerAttr,
        BSL_CID_UNKNOWN, "PEM", "PUBKEY_SUBKEY", &pub, NULL, &pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("dgst: Failed to decode the public key, errCode: 0x%0x.\n", ret);
        BSL_SAL_ClearFree(pubBuf, bufLen);
        return HITLS_APP_CRYPTO_FAIL;
    }
    BSL_SAL_ClearFree(pubBuf, bufLen);
    *ctx = pkeyCtx;
    AppPrintInfo("dgst: Get pub key ctx success!\n");
    return HITLS_APP_SUCCESS;
}

static int32_t VerifySign(DgstOptCtx *optCtx, uint8_t *msgBuf, uint32_t msgBufLen)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *inputBuf = NULL;
    uint64_t inputLen = 0;
    uint8_t *signBuf = NULL;
    uint32_t signLen;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    do {
        ret = GetPubKeyCtx(&optCtx->signInfo, &ctx);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = HITLS_APP_ReadFileOrStdin(
            &inputBuf, &inputLen, optCtx->signInfo.signatureFile, UINT32_MAX, "dgst");
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        if (optCtx->signInfo.signFormat == HITLS_APP_FORMAT_BINARY) {
            signBuf = inputBuf;
            signLen = (uint32_t)inputLen;
        } else {
            signLen = inputLen / APP_HEX_TO_BYTE + 1;
            signBuf = (uint8_t *)BSL_SAL_Malloc(signLen);
            if (signBuf == NULL) {
                AppPrintError("dgst: Failed to alloc memory.\n");
                ret = HITLS_APP_MEM_ALLOC_FAIL;
                break;
            }
            ret = HITLS_APP_HexToBytes((const char *)inputBuf, signBuf, &signLen);
            if (ret != HITLS_APP_SUCCESS) {
                AppPrintError("dgst: Failed to convert signature from hex, ret=%d\n", ret);
                break;
            }
        }

        if (CRYPT_EAL_PkeyGetId(ctx) == CRYPT_PKEY_SM2) {
            ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, optCtx->signInfo.userid,
                strlen(optCtx->signInfo.userid));
            if (ret != CRYPT_SUCCESS) {
                AppPrintError("dgst: Failed to set the SM2 user ID, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
        }
#ifdef HITLS_APP_SM_MODE
        if (optCtx->signInfo.smParam->smTag == 1) {
            optCtx->signInfo.smParam->status = HITLS_APP_SM_STATUS_APPORVED;
        }
#endif
        ret = CRYPT_EAL_PkeyVerify(ctx, optCtx->algInfo.algId, msgBuf, msgBufLen, signBuf, signLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("dgst: Failed to verify the message, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        AppPrintError("verify success\n");
    } while (0);
    if (signBuf != inputBuf) {
        BSL_SAL_FREE(signBuf);
    }
    BSL_SAL_FREE(inputBuf);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

static int32_t CheckSmParam(SignInfo *signInfo)
{
#ifdef HITLS_APP_SM_MODE
    if (signInfo->smParam->smTag == 1 && signInfo->smParam->workPath == NULL) {
        AppPrintError("dgst: The workpath is not specified.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
#else
    (void) signInfo;
#endif
    return HITLS_APP_SUCCESS;
}

static int32_t ParseSignFormat(SignInfo *signInfo)
{
    const char *format = HITLS_APP_OptGetValueStr();
    if (format == NULL) {
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (strcmp(format, "hex") == 0) {
        signInfo->signFormat = HITLS_APP_FORMAT_HEX;
        return HITLS_APP_SUCCESS;
    }
    if (strcmp(format, "bin") == 0) {
        signInfo->signFormat = HITLS_APP_FORMAT_BINARY;
        return HITLS_APP_SUCCESS;
    }
    AppPrintError("dgst: Invalid signature format: %s. Use hex or bin.\n", format);
    return HITLS_APP_OPT_VALUE_INVALID;
}

static int32_t OptParse(DgstOptCtx *optCtx)
{
    HITLSOptType optType;
    int ret = HITLS_APP_SUCCESS;

    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_DGST_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_DGST_EOF:
            case HITLS_APP_OPT_DGST_ERR:
                ret = HITLS_APP_OPT_UNKOWN;
                AppPrintError("dgst: Use -help for summary.\n");
                return ret;
            case HITLS_APP_OPT_DGST_HELP:
                ret = HITLS_APP_HELP;
                (void)HITLS_APP_OptHelpPrint(g_dgstOpts);
                return ret;
            case HITLS_APP_OPT_DGST_COLON:
                optCtx->colon = true;
                break;
            case HITLS_APP_OPT_DGST_OUT:
                optCtx->outFile = HITLS_APP_OptGetValueStr();
                if (optCtx->outFile == NULL || strlen(optCtx->outFile) >= PATH_MAX) {
                    AppPrintError("dgst: The length of outfile error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_ALG:
                optCtx->algInfo.algName = HITLS_APP_OptGetValueStr();
                if (optCtx->algInfo.algName == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                optCtx->algInfo.algId =
                    HITLS_APP_GetCidByName(optCtx->algInfo.algName, HITLS_APP_LIST_OPT_DGST_ALG);
                if (optCtx->algInfo.algId == BSL_CID_UNKNOWN) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_SIGN:
                optCtx->signInfo.privateKeyFile = HITLS_APP_OptGetValueStr();
                if (optCtx->signInfo.privateKeyFile == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_VERIFY:
                optCtx->signInfo.publicKeyFile = HITLS_APP_OptGetValueStr();
                if (optCtx->signInfo.publicKeyFile == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_SIGNATURE:
                optCtx->signInfo.signatureFile = HITLS_APP_OptGetValueStr();
                if (optCtx->signInfo.signatureFile == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_SIGN_FORMAT:
                ret = ParseSignFormat(&optCtx->signInfo);
                if (ret != HITLS_APP_SUCCESS) {
                    return ret;
                }
                break;
            case HITLS_APP_OPT_DGST_USERID:
                optCtx->signInfo.userid = HITLS_APP_OptGetValueStr();
                if (optCtx->signInfo.userid == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
#ifdef HITLS_APP_SM_MODE
            case HITLS_SM_OPT_SM:
            case HITLS_SM_OPT_UUID:
            case HITLS_SM_OPT_WORKPATH:
#endif
            case HITLS_APP_OPT_PROVIDER:
            case HITLS_APP_OPT_PROVIDER_PATH:
            case HITLS_APP_OPT_PROVIDER_ATTR:
                break;
            default:
                return HITLS_APP_OPT_UNKOWN;
        }
        HITLS_APP_PROV_CASES(optType, optCtx->signInfo.provider);
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(optType, optCtx->signInfo.smParam);
#endif
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_DgstMain(int argc, char *argv[])
{
    AppProvider appProvider = {NULL, NULL, NULL};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
#endif
    DgstOptCtx optCtx = {0};
    InitDgstOptCtx(&optCtx);
    optCtx.signInfo.provider = &appProvider;
#ifdef HITLS_APP_SM_MODE
    optCtx.signInfo.smParam = &smParam;
#endif
    char *msgFile = NULL;
    uint8_t *msgBuf = NULL;
    uint64_t msgBufLen = 0;
    int32_t mainRet = HITLS_APP_SUCCESS;
    mainRet = HITLS_APP_OptBegin(argc, argv, g_dgstOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        AppPrintError("dgst: error in opt begin.\n");
        goto end;
    }
    mainRet = OptParse(&optCtx);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = CheckSmParam(&optCtx.signInfo);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = HITLS_APP_Init(&initParam);
    if (mainRet != HITLS_APP_SUCCESS) {
        AppPrintError("dgst: Failed to init the application, errCode: 0x%x.\n", mainRet);
        goto end;
    }

    optCtx.inputFileNum = HITLS_APP_GetRestOptNum();
    optCtx.inputFiles = HITLS_APP_GetRestOpt();
    if (optCtx.inputFileNum != 0) {
        msgFile = optCtx.inputFiles[0];
    }
    if (optCtx.signInfo.privateKeyFile == NULL && optCtx.signInfo.publicKeyFile == NULL) {
        mainRet = CalculateDgst(&optCtx);
    } else if (optCtx.signInfo.privateKeyFile != NULL && optCtx.signInfo.publicKeyFile == NULL) {
        mainRet = HITLS_APP_ReadFileOrStdin(&msgBuf, &msgBufLen, msgFile, UINT32_MAX, "dgst");
        if (mainRet != HITLS_APP_SUCCESS) {
            goto end;
        }
        mainRet = CalculateSign(&optCtx, msgBuf, (uint32_t)msgBufLen);
    } else if (optCtx.signInfo.publicKeyFile != NULL && optCtx.signInfo.signatureFile != NULL) {
        mainRet = HITLS_APP_ReadFileOrStdin(&msgBuf, &msgBufLen, msgFile, UINT32_MAX, "dgst");
        if (mainRet != HITLS_APP_SUCCESS) {
            goto end;
        }
        mainRet = VerifySign(&optCtx, msgBuf, (uint32_t)msgBufLen);
    } else {
        AppPrintError("dgst: Please add the signature file using the [-signature] option.\n");
        mainRet = HITLS_APP_INVALID_ARG;
    }
end:
    BSL_SAL_FREE(msgBuf);
    HITLS_APP_Deinit(&initParam, mainRet);
    HITLS_APP_OptEnd();
    return mainRet;
}
