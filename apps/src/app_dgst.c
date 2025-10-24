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

#define MAX_BUFSIZE (1024 * 8)  // Indicates the length of a single digest during digest calculation.
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
    HITLS_APP_OPT_DGST_SIGN,
    HITLS_APP_OPT_DGST_VERIFY,
    HITLS_APP_OPT_DGST_SIGNATURE,
    HITLS_APP_OPT_DGST_USERID,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLSOptType;

const HITLS_CmdOption g_dgstOpts[] = {
    {"help", HITLS_APP_OPT_DGST_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"md", HITLS_APP_OPT_DGST_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Digest algorithm"},
    {"out", HITLS_APP_OPT_DGST_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output the summary result to a file"},
    {"sign", HITLS_APP_OPT_DGST_SIGN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Private key for signature"},
    {"verify", HITLS_APP_OPT_DGST_VERIFY, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Public key for signature verification"},
    {"signature", HITLS_APP_OPT_DGST_SIGNATURE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Signature to be verified"},
    {"userid", HITLS_APP_OPT_DGST_USERID, HITLS_APP_OPT_VALUETYPE_STRING, "User ID for SM2"},
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {"file...", HITLS_APP_OPT_DGST_FILE, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Files to be digested"},
    {NULL}};

typedef struct {
    char *algName;
    int32_t algId;
    uint32_t digestSize;  // the length of default hash value of the algorithm
} AlgInfo;

typedef struct {
    char *privateKeyFile;  // private key file for signing
    char *publicKeyFile;   // public key file for verification
    char *signatureFile;   // signature file for verification
    char *userid;          // user ID for SM2
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} SignInfo;

static AlgInfo g_dgstInfo = {"sha256", CRYPT_MD_SHA256, 0};
#ifdef HITLS_APP_SM_MODE
    static SignInfo g_signInfo = {NULL, NULL, NULL, "1234567812345678", NULL, NULL};
#else
    static SignInfo g_signInfo = {NULL, NULL, NULL, "1234567812345678", NULL};
#endif
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

static int32_t CalculateDgst(char *outfile)
{
    int32_t ret = HITLS_APP_SUCCESS;
    CRYPT_EAL_MdCTX *ctx = InitAlgDigest(g_dgstInfo.algId);
    if (ctx == NULL) {
        ret = HITLS_APP_CRYPTO_FAIL;
        return ret;
    }
#ifdef HITLS_APP_SM_MODE
    if (g_signInfo.smParam->smTag == 1) {
        g_signInfo.smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    }
#endif
    if (g_dgstInfo.algId == CRYPT_MD_SHAKE128) {
        g_dgstInfo.digestSize = HITLS_APP_SHAKE128_SIZE;
    } else if (g_dgstInfo.algId == CRYPT_MD_SHAKE256) {
        g_dgstInfo.digestSize = HITLS_APP_SHAKE256_SIZE;
    } else {
        g_dgstInfo.digestSize = CRYPT_EAL_MdGetDigestSize(g_dgstInfo.algId);
        if (g_dgstInfo.digestSize == 0) {
            ret = HITLS_APP_CRYPTO_FAIL;
            (void)AppPrintError("dgst: Failed to obtain the default length of the algorithm(%s)\n", g_dgstInfo.algName);
            CRYPT_EAL_MdFreeCtx(ctx);
            return ret;
        }
    }
    ret = (g_argc == 0) ? StdSumAndOut(ctx, outfile) : FileSumAndOut(ctx, outfile);
    CRYPT_EAL_MdDeinit(ctx);  // algorithm release
    CRYPT_EAL_MdFreeCtx(ctx);
    return ret;
}

static int32_t GetReadBuf(uint8_t **buf, uint64_t *bufLen, char *inFile, uint32_t maxSize)
{
    if (buf == NULL || bufLen == NULL || *bufLen > UINT32_MAX) {
        AppPrintError("dgst: Invalid parameters for GetReadBuf\n");
        return HITLS_APP_INVALID_ARG;
    }
    BSL_UIO *readUio = HITLS_APP_UioOpen(inFile, 'r', 0);
    BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
    if (readUio == NULL) {
        if (inFile == NULL) {
            AppPrintError("dgst: Failed to open stdin\n");
        } else {
            AppPrintError("dgst: Failed to open the file <%s>, No such file or directory\n", inFile);
        }
        return HITLS_APP_UIO_FAIL;
    }
    int32_t ret = HITLS_APP_OptReadUio(readUio, buf, bufLen, maxSize);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("dgst: Failed to read the content from the file <%s>\n", inFile);
    }
    BSL_UIO_Free(readUio);
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

static int32_t CalculateSign(char *outfile, uint8_t *msgBuf, uint32_t msgBufLen)
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
        if (g_signInfo.smParam->smTag == 1) {
            ret = GetPkeyCtxFromUuid(&g_signInfo, g_signInfo.privateKeyFile, &ctx);
            if (ret != HITLS_APP_SUCCESS) {
                break;
            }
        } else {
#endif
            ret = GetReadBuf(&prvBuf, &bufLen, g_signInfo.privateKeyFile, MAX_CERT_KEY_SIZE);
            if (ret != HITLS_APP_SUCCESS) {
                (void)AppPrintError("dgst: Failed to read the private key file\n");
                break;
            }
            prv.data = prvBuf;
            prv.dataLen = bufLen;
            ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(), g_signInfo.provider->providerAttr,
                BSL_CID_UNKNOWN, "PEM", "PRIKEY_PKCS8_UNENCRYPT", &prv, NULL, &ctx);
            if (ret != CRYPT_SUCCESS) {
                (void)AppPrintError("dgst: Failed to decode the private key, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
#ifdef HITLS_APP_SM_MODE
        }
#endif
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, g_signInfo.userid, strlen(g_signInfo.userid));
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("dgst: Failed to set the SM2 user ID, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
#ifdef HITLS_APP_SM_MODE
        if (g_signInfo.smParam->smTag == 1) {
            g_signInfo.smParam->status = HITLS_APP_SM_STATUS_APPORVED;
        }
#endif
        signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
        if (signLen == 0) {
            (void)AppPrintError("dgst: Failed to get the signature length.\n");
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        signBuf = BSL_SAL_Malloc(signLen);
        if (signBuf == NULL) {
            (void)AppPrintError("dgst: Failed to allocate memory for the signature.\n");
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            break;
        }
        ret = CRYPT_EAL_PkeySign(ctx, g_dgstInfo.algId, msgBuf, msgBufLen, signBuf, &signLen);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("dgst: Failed to sign the message, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }

        BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(outfile, 'w', 0);  // overwrite the original content
        BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
        if (fileWriteUio == NULL) {
            (void)AppPrintError("dgst: Failed to open the outfile\n");
            ret = HITLS_APP_UIO_FAIL;
            break;
        }
        ret = HITLS_APP_OptWriteUio(fileWriteUio, signBuf, signLen, HITLS_APP_FORMAT_HEX);
        if (ret != HITLS_APP_SUCCESS) {
            (void)AppPrintError("dgst:Failed to export data to the outfile path\n");
        }
        BSL_UIO_Free(fileWriteUio);
    } while (0);
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    BSL_SAL_ClearFree(prvBuf, bufLen);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(signBuf);
    return ret;
}

static int32_t GetPubKeyCtx(CRYPT_EAL_PkeyCtx **ctx)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *pubBuf = NULL;
    uint64_t bufLen = 0;
    BSL_Buffer pub = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
#ifdef HITLS_APP_SM_MODE
    if (g_signInfo.smParam->smTag == 1) {
        ret = GetPkeyCtxFromUuid(&g_signInfo, g_signInfo.publicKeyFile, &pkeyCtx);
        if (ret == HITLS_APP_SUCCESS) {
            *ctx = pkeyCtx;
            return HITLS_APP_SUCCESS;
        }
    }
#endif
    ret = GetReadBuf(&pubBuf, &bufLen, g_signInfo.publicKeyFile, MAX_CERT_KEY_SIZE);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("dgst: Failed to read the public key file\n");
        return ret;
    }
    pub.data = pubBuf;
    pub.dataLen = bufLen;
    ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(), g_signInfo.provider->providerAttr,
        BSL_CID_UNKNOWN, "PEM", "PUBKEY_SUBKEY", &pub, NULL, &pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        (void)AppPrintError("dgst: Failed to decode the public key, errCode: 0x%0x.\n", ret);
        BSL_SAL_ClearFree(pubBuf, bufLen);
        return HITLS_APP_CRYPTO_FAIL;
    }
    BSL_SAL_ClearFree(pubBuf, bufLen);
    *ctx = pkeyCtx;
    (void)AppPrintError("dgst: Get pub key ctx success!\n");
    return HITLS_APP_SUCCESS;
}

static int32_t VerifySign(uint8_t *msgBuf, uint32_t msgBufLen)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *signBuf = NULL;
    uint64_t signLen = 0;
    uint8_t *hexBuf = NULL;
    uint32_t hexLen;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    do {
        ret = GetPubKeyCtx(&ctx);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = GetReadBuf(&signBuf, &signLen, g_signInfo.signatureFile, UINT32_MAX);
        if (ret != HITLS_APP_SUCCESS) {
            (void)AppPrintError("dgst: Failed to read the signature file\n");
            break;
        }
        hexBuf = BSL_SAL_Malloc(signLen * 2 + 1);
        hexLen = signLen * 2;
        ret = HITLS_APP_StrToHex((const char *)signBuf, hexBuf, &hexLen);
        if (ret != HITLS_APP_SUCCESS) {
            (void)AppPrintError("dgst: Failed to convert signature to hex, ret=%d\n", ret);
            break;
        }

        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, g_signInfo.userid, strlen(g_signInfo.userid));
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("dgst: Failed to set the SM2 user ID, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
#ifdef HITLS_APP_SM_MODE
        if (g_signInfo.smParam->smTag == 1) {
            g_signInfo.smParam->status = HITLS_APP_SM_STATUS_APPORVED;
        }
#endif
        ret = CRYPT_EAL_PkeyVerify(ctx, g_dgstInfo.algId, msgBuf, msgBufLen, hexBuf, hexLen);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("dgst: Failed to verify the message, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        (void)AppPrintError("verify success\n");
    } while (0);
    BSL_SAL_FREE(signBuf);
    BSL_SAL_FREE(hexBuf);
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

int32_t HITLS_DgstMain(int argc, char *argv[])
{
    AppProvider appProvider = {NULL, NULL, NULL};
    g_signInfo.provider = &appProvider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    g_signInfo.smParam = &smParam;
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
#endif
    char *outfile = NULL;
    char *msgFile = NULL;
    uint8_t *msgBuf = NULL;
    uint64_t msgBufLen = 0;
    int32_t mainRet = HITLS_APP_SUCCESS;
    mainRet = HITLS_APP_OptBegin(argc, argv, g_dgstOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        (void)AppPrintError("dgst: error in opt begin.\n");
        goto end;
    }
    mainRet = OptParse(&outfile);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = CheckSmParam(&g_signInfo);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = HITLS_APP_Init(&initParam);
    if (mainRet != HITLS_APP_SUCCESS) {
        (void)AppPrintError("dgst: Failed to init the application, errCode: 0x%x.\n", mainRet);
        goto end;
    }

    g_argc = HITLS_APP_GetRestOptNum();
    g_argv = HITLS_APP_GetRestOpt();
    if (g_argc !=0) {
        msgFile = g_argv[0];
    }
    if (g_signInfo.privateKeyFile == NULL && g_signInfo.publicKeyFile == NULL) {
        mainRet = CalculateDgst(outfile);
    } else if (g_signInfo.privateKeyFile != NULL && g_signInfo.publicKeyFile == NULL) {
        mainRet = GetReadBuf(&msgBuf, &msgBufLen, msgFile, UINT32_MAX);
        if (mainRet != HITLS_APP_SUCCESS) {
            goto end;
        }
        mainRet = CalculateSign(outfile, msgBuf, (uint32_t)msgBufLen);
    } else if (g_signInfo.publicKeyFile != NULL && g_signInfo.signatureFile != NULL) {
        mainRet = GetReadBuf(&msgBuf, &msgBufLen, msgFile, UINT32_MAX);
        if (mainRet != HITLS_APP_SUCCESS) {
            goto end;
        }
        mainRet = VerifySign(msgBuf, msgBufLen);
    } else {
        (void)AppPrintError("dgst: Please add the signature file using the [-signature] option.\n");
        mainRet = HITLS_APP_INVALID_ARG;
    }
end:
    BSL_SAL_FREE(msgBuf);
    HITLS_APP_Deinit(&initParam, mainRet);
    HITLS_APP_OptEnd();
    return mainRet;
}

static int32_t StdSumAndOut(CRYPT_EAL_MdCTX *ctx, const char *outfile)
{
    int32_t stdRet = HITLS_APP_SUCCESS;
    BSL_UIO *readUio = HITLS_APP_UioOpen(NULL, 'r', 1);
    if (readUio == NULL) {
        AppPrintError("dgst: Failed to open the stdin\n");
        return HITLS_APP_UIO_FAIL;
    }

    uint32_t readLen = MAX_BUFSIZE;
    uint8_t readBuf[MAX_BUFSIZE] = {0};

    bool isEof = false;
    while (BSL_UIO_Ctrl(readUio, BSL_UIO_FILE_GET_EOF, IS_SUPPORT_GET_EOF, &isEof) == BSL_SUCCESS && !isEof) {
        if (BSL_UIO_Read(readUio, readBuf, MAX_BUFSIZE, &readLen) != BSL_SUCCESS) {
            BSL_UIO_Free(readUio);
            (void)AppPrintError("dgst: Failed to obtain the content from the STDIN\n");
            return HITLS_APP_STDIN_FAIL;
        }
        if (readLen == 0) {
            break;
        }
        stdRet = CRYPT_EAL_MdUpdate(ctx, readBuf, readLen);
        if (stdRet != CRYPT_SUCCESS) {
            BSL_UIO_Free(readUio);
            (void)AppPrintError("dgst: Failed to continuously summarize the STDIN content\n");
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
        AppPrintError("dgst: Failed to open the <%s>\n", outfile);
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
        (void)AppPrintError("dgst: Failed to open the file <%s>, No such file or directory\n", filename);
        return HITLS_APP_UIO_FAIL;
    }
    uint64_t readFileLen = 0;
    readRet = BSL_UIO_Ctrl(readUio, BSL_UIO_PENDING, sizeof(readFileLen), &readFileLen);
    if (readRet != BSL_SUCCESS) {
        BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
        BSL_UIO_Free(readUio);
        (void)AppPrintError("dgst: Failed to obtain the content length\n");
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
            (void)AppPrintError("dgst: Failed to read the input content\n");
            return HITLS_APP_UIO_FAIL;
        }
        readRet = CRYPT_EAL_MdUpdate(ctx, readBuf, bufLen); // continuously enter summary content
        if (readRet != CRYPT_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
            BSL_UIO_Free(readUio);
            (void)AppPrintError("dgst: Failed to continuously summarize the file content\n");
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
            (void)AppPrintError("dgst: Failed to output the content to the screen\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        outRet = HITLS_APP_OptWriteUio(fileWriteUio, outBuf, outBufLen, HITLS_APP_FORMAT_TEXT);
        if (outRet != HITLS_APP_SUCCESS) {
            (void)AppPrintError("dgst: Failed to export data to the file path: <%s>\n", outfile);
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
        (void)AppPrintError("dgst: Failed to open the format control content space\n");
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
        (void)AppPrintError("dgst: Failed to combine the output content\n");
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
        (void)AppPrintError("dgst: filename: %s Failed to complete the final summary\n", filename);
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
            (void)AppPrintError("dgst: Summary context deinit failed.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        outRet = CRYPT_EAL_MdInit(ctx); // md initialization
        if (outRet != CRYPT_SUCCESS) {
            (void)AppPrintError("dgst: Summary context creation failed.\n");
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
            (void)AppPrintError("dgst: Failed to output the final summary value\n");
            return outRet;
        }

        BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(NULL, 'w', 0); // the standard output is required for each file
        if (fileWriteUio == NULL) {
            BSL_SAL_FREE(outBuf);
            (void)AppPrintError("dgst: Failed to open the stdout\n");
            return HITLS_APP_UIO_FAIL;
        }
        outRet = BufOutToUio(NULL, fileWriteUio, (uint8_t *)outBuf, outBufLen); // output the hash value to the UIO
        BSL_SAL_FREE(outBuf);
        BSL_UIO_Free(fileWriteUio);
        if (outRet != HITLS_APP_SUCCESS) { // Released after the standard output is complete
            (void)AppPrintError("dgst: Failed to output the hash value\n");
            return outRet;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t MultiFileSetCtx(CRYPT_EAL_MdCTX *ctx)
{
    int32_t outRet = CRYPT_EAL_MdDeinit(ctx); // md release
    if (outRet != CRYPT_SUCCESS) {
        (void)AppPrintError("dgst: Summary context deinit failed.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    outRet = CRYPT_EAL_MdInit(ctx); // md initialization
    if (outRet != CRYPT_SUCCESS) {
        (void)AppPrintError("dgst: Summary context creation failed.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t FileSumOutFile(CRYPT_EAL_MdCTX *ctx, const char *outfile)
{
    int32_t outRet = HITLS_APP_SUCCESS;
    BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(outfile, 'w', 0);  // overwrite the original content
    if (fileWriteUio == NULL) {
        (void)AppPrintError("dgst: Failed to open the file path: %s\n", outfile);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
    BSL_UIO_Free(fileWriteUio);
    fileWriteUio = HITLS_APP_UioOpen(outfile, 'a', 0);
    if (fileWriteUio == NULL) {
        (void)AppPrintError("dgst: Failed to open the file path: %s\n", outfile);
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
            (void)AppPrintError("dgst: Failed to read the file content by block and calculate the hash value\n");
            return HITLS_APP_UIO_FAIL;
        }
        uint8_t *outBuf = NULL;
        uint32_t outBufLen = 0;
        outRet = MdFinalToBuf(ctx, &outBuf, &outBufLen, g_argv[i]); // read the final hash value to the buffer
        if (outRet != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(outBuf);
            BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
            BSL_UIO_Free(fileWriteUio);
            (void)AppPrintError("dgst: Failed to output the final summary value\n");
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
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(APP_GetCurrent_LibCtx(), id, g_signInfo.provider->providerAttr);
    if (ctx == NULL) {
        (void)AppPrintError("dgst: Failed to create the algorithm(%s) context\n", g_dgstInfo.algName);
        return NULL;
    }
    int32_t ret = CRYPT_EAL_MdInit(ctx); // md initialization
    if (ret != CRYPT_SUCCESS) {
        (void)AppPrintError("dgst: Summary context creation failed\n");
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
                    AppPrintError("dgst: The length of outfile error, range is (0, 4096).\n");
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
            case HITLS_APP_OPT_DGST_SIGN:
                g_signInfo.privateKeyFile = HITLS_APP_OptGetValueStr();
                if (g_signInfo.privateKeyFile == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_VERIFY:
                g_signInfo.publicKeyFile = HITLS_APP_OptGetValueStr();
                if (g_signInfo.publicKeyFile == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_SIGNATURE:
                g_signInfo.signatureFile = HITLS_APP_OptGetValueStr();
                if (g_signInfo.signatureFile == NULL) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_DGST_USERID:
                g_signInfo.userid = HITLS_APP_OptGetValueStr();
                if (g_signInfo.userid == NULL) {
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
        HITLS_APP_PROV_CASES(optType, g_signInfo.provider);
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(optType, g_signInfo.smParam);
#endif
    }
    return HITLS_APP_SUCCESS;
}
