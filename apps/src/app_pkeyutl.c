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

#include "app_pkeyutl.h"
#include <limits.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_codecs.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "hitls_pki_errno.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_provider.h"
#include "app_utils.h"
#include "app_sm.h"
#include "app_keymgmt.h"

#define SM2_PUBKEY_LEN 65
#define SM2_PRVKEY_LEN 33
#define CIPHER_TEXT_BASE_LEN 112
#define MAX_CERT_KEY_SIZE (256 * 1024)

#define APP_PKEYUTL_PBKDF2_IT_CNT_MIN 1024
#define APP_PKEYUTL_PBKDF2_SALT_LEN_MIN 8
#define APP_PKEYUTL_SM2_EXCH_TEMP_KEY_LEN 32 // SM3_MD_SIZE

typedef enum OptionChoice {
    HITLS_APP_OPT_PKEYUTL_ERR = -1,
    HITLS_APP_OPT_PKEYUTL_EOF = 0,
    HITLS_APP_OPT_PKEYUTL_HELP = 1,
    HITLS_APP_OPT_PKEYUTL_ENCRYPT,
    HITLS_APP_OPT_PKEYUTL_DECRYPT,
    HITLS_APP_OPT_PKEYUTL_DERIVE,
    HITLS_APP_OPT_PKEYUTL_OUTR,
    HITLS_APP_OPT_PKEYUTL_OUTRAND,
    HITLS_APP_OPT_PKEYUTL_INR,
    HITLS_APP_OPT_PKEYUTL_SELFR,
    HITLS_APP_OPT_PKEYUTL_PUBIN,
    HITLS_APP_OPT_PKEYUTL_PRVIN,
    HITLS_APP_OPT_PKEYUTL_IN,
    HITLS_APP_OPT_PKEYUTL_OUT,
    HITLS_APP_OPT_PKEYUTL_INKEY,
    HITLS_APP_OPT_PKEYUTL_PEERKEY,
    HITLS_APP_OPT_PKEYUTL_USERID,
    HITLS_APP_OPT_PKEYUTL_RPASS,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLSOptType;

static const HITLS_CmdOption g_pkeyUtlOpts[] = {
    {"help", HITLS_APP_OPT_PKEYUTL_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Show usage information for command."},
    {"encrypt", HITLS_APP_OPT_PKEYUTL_ENCRYPT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Public key encryption."},
    {"decrypt", HITLS_APP_OPT_PKEYUTL_DECRYPT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Private key decryption."},
    {"derive", HITLS_APP_OPT_PKEYUTL_DERIVE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Key exchange."},
    {"outR", HITLS_APP_OPT_PKEYUTL_OUTR, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Key exchange output R."},
    {"outr", HITLS_APP_OPT_PKEYUTL_OUTRAND, HITLS_APP_OPT_VALUETYPE_OUT_FILE,
        "Key exchange output self r."},
    {"inR", HITLS_APP_OPT_PKEYUTL_INR, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Key exchange input R."},
    {"inr", HITLS_APP_OPT_PKEYUTL_SELFR, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Key exchange input r."},
    {"pubin", HITLS_APP_OPT_PKEYUTL_PUBIN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file for public key."},
    {"prvin", HITLS_APP_OPT_PKEYUTL_PRVIN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file for private key."},
    {"in", HITLS_APP_OPT_PKEYUTL_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file for data to be processed."},
    {"out", HITLS_APP_OPT_PKEYUTL_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file for result."},
    {"inkey", HITLS_APP_OPT_PKEYUTL_INKEY, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Key for this side in key exchange."},
    {"peerkey", HITLS_APP_OPT_PKEYUTL_PEERKEY, HITLS_APP_OPT_VALUETYPE_IN_FILE,
        "Key for the other side in key exchange."},
    {"userid", HITLS_APP_OPT_PKEYUTL_USERID, HITLS_APP_OPT_VALUETYPE_STRING, "User ID for SM2."},
    {"rpass", HITLS_APP_OPT_PKEYUTL_RPASS, HITLS_APP_OPT_VALUETYPE_STRING,
        "Password to encrypt or decrypt sm2 temp key when key exchange."},
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {NULL, 0, 0, NULL}
};

typedef struct {
        int32_t optEncrypt;   // Flag for encrypt
        int32_t optDecrypt;   // Flag for decrypt
        int32_t optDerive;    // Flag for derive
        char *outRFile;       // Output file for R
        char *outRandFile;   // Output file for self r
        char *inRFile;        // Input file for R
        char *inRandFile;      // Input file for self r
        char *pubinFile;      // Input file for public key
        char *prvinFile;      // Input file for private key
        char *inFile;         // Input file for data to be processed
        char *outFile;        // Output file for result
        char *inkeyFile;      // Key for this side in key exchange
        char *peerkeyFile;    // Key for the other side in key exchange
        char *rpass;
        char *userid;
        AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_Param *smParam;
#endif
} PkeyUtlOpt;

typedef int32_t (*PkeyUtlOptHandleFunc)(PkeyUtlOpt *);

typedef struct {
    int optType;
    PkeyUtlOptHandleFunc func;
} PkeyUtlOptHandleFuncMap;

static int32_t HandlePkeyUtlErr(PkeyUtlOpt *opt)
{
    (void)opt;
    AppPrintError("pkeyutl: Invalid option or error occurred.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t HandlePkeyUtlHelp(PkeyUtlOpt *opt)
{
    (void)opt;
    HITLS_APP_OptHelpPrint(g_pkeyUtlOpts);
    return HITLS_APP_HELP;
}

static int32_t HandlePkeyUtlEncrypt(PkeyUtlOpt *opt)
{
    opt->optEncrypt = 1;
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlDecrypt(PkeyUtlOpt *opt)
{
    opt->optDecrypt = 1;
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlDerive(PkeyUtlOpt *opt)
{
    opt->optDerive = 1;
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlPubin(PkeyUtlOpt *opt)
{
    opt->pubinFile = HITLS_APP_OptGetValueStr();
    if (opt->pubinFile == NULL) {
        AppPrintError("pkeyutl: Invalid public key file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlPrvin(PkeyUtlOpt *opt)
{
    opt->prvinFile = HITLS_APP_OptGetValueStr();
    if (opt->prvinFile == NULL) {
        AppPrintError("pkeyutl: Invalid private key file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlIn(PkeyUtlOpt *opt)
{
    opt->inFile = HITLS_APP_OptGetValueStr();
    if (opt->inFile == NULL) {
        AppPrintError("pkeyutl: Invalid input file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlOut(PkeyUtlOpt *opt)
{
    opt->outFile = HITLS_APP_OptGetValueStr();
    if (opt->outFile == NULL) {
        AppPrintError("pkeyutl: Invalid output file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlInkey(PkeyUtlOpt *opt)
{
    opt->inkeyFile = HITLS_APP_OptGetValueStr();
    if (opt->inkeyFile == NULL) {
        AppPrintError("pkeyutl: Invalid inkey file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlPeerkey(PkeyUtlOpt *opt)
{
    opt->peerkeyFile = HITLS_APP_OptGetValueStr();
    if (opt->peerkeyFile == NULL) {
        AppPrintError("pkeyutl: Invalid peerkey file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlR(PkeyUtlOpt *opt)
{
    opt->outRFile = HITLS_APP_OptGetValueStr();
    if (opt->outRFile == NULL) {
        AppPrintError("pkeyutl: Invalid outR file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlSelfOutr(PkeyUtlOpt *opt)
{
    opt->outRandFile = HITLS_APP_OptGetValueStr();
    if (opt->outRandFile == NULL) {
        AppPrintError("pkeyutl: Invalid out r file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlInR(PkeyUtlOpt *opt)
{
    opt->inRFile = HITLS_APP_OptGetValueStr();
    if (opt->inRFile == NULL) {
        AppPrintError("pkeyutl: Invalid inR file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlSelfr(PkeyUtlOpt *opt)
{
    opt->inRandFile = HITLS_APP_OptGetValueStr();
    if (opt->inRandFile == NULL) {
        AppPrintError("pkeyutl: Invalid in r file.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlUserid(PkeyUtlOpt *opt)
{
    opt->userid = HITLS_APP_OptGetValueStr();
    if (opt->userid == NULL) {
        AppPrintError("pkeyutl: Invalid user ID.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandlePkeyUtlrPass(PkeyUtlOpt *opt)
{
    opt->rpass = HITLS_APP_OptGetValueStr();
    if (opt->rpass == NULL) {
        AppPrintError("pkeyutl: Invalid rpass.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static const PkeyUtlOptHandleFuncMap g_ecOptHandleFuncMap[] = {
    {HITLS_APP_OPT_PKEYUTL_ERR, HandlePkeyUtlErr},
    {HITLS_APP_OPT_PKEYUTL_HELP, HandlePkeyUtlHelp},
    {HITLS_APP_OPT_PKEYUTL_ENCRYPT, HandlePkeyUtlEncrypt},
    {HITLS_APP_OPT_PKEYUTL_DECRYPT, HandlePkeyUtlDecrypt},
    {HITLS_APP_OPT_PKEYUTL_DERIVE, HandlePkeyUtlDerive},
    {HITLS_APP_OPT_PKEYUTL_OUTR, HandlePkeyUtlR},
    {HITLS_APP_OPT_PKEYUTL_OUTRAND, HandlePkeyUtlSelfOutr},
    {HITLS_APP_OPT_PKEYUTL_INR, HandlePkeyUtlInR},
    {HITLS_APP_OPT_PKEYUTL_SELFR, HandlePkeyUtlSelfr},
    {HITLS_APP_OPT_PKEYUTL_PUBIN, HandlePkeyUtlPubin},
    {HITLS_APP_OPT_PKEYUTL_PRVIN, HandlePkeyUtlPrvin},
    {HITLS_APP_OPT_PKEYUTL_IN, HandlePkeyUtlIn},
    {HITLS_APP_OPT_PKEYUTL_OUT, HandlePkeyUtlOut},
    {HITLS_APP_OPT_PKEYUTL_INKEY, HandlePkeyUtlInkey},
    {HITLS_APP_OPT_PKEYUTL_PEERKEY, HandlePkeyUtlPeerkey},
    {HITLS_APP_OPT_PKEYUTL_USERID, HandlePkeyUtlUserid},
    {HITLS_APP_OPT_PKEYUTL_RPASS, HandlePkeyUtlrPass},
};

static int32_t ParsepkeyUtlOpt(PkeyUtlOpt *pkeyUtlOpt)
{
    int ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_PKEYUTL_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_PKEYUTL_EOF)) {
        for (size_t i = 0; i < (sizeof(g_ecOptHandleFuncMap) / sizeof(g_ecOptHandleFuncMap[0])); ++i) {
            if (optType == g_ecOptHandleFuncMap[i].optType) {
                ret = g_ecOptHandleFuncMap[i].func(pkeyUtlOpt);
                break;
            }
        }
        HITLS_APP_PROV_CASES(optType, pkeyUtlOpt->provider)
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(optType, pkeyUtlOpt->smParam);
#endif
    }
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("pkeyutl: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return ret;
}

static int32_t GetReadBuf(uint8_t **buf, uint64_t *bufLen, char *inFile, uint32_t maxSize)
{
    if (buf == NULL || bufLen == NULL) {
        AppPrintError("pkeyutl: Invalid parameters for GetReadBuf\n");
        return HITLS_APP_INVALID_ARG;
    }
    BSL_UIO *readUio = HITLS_APP_UioOpen(inFile, 'r', 0);
    BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
    if (readUio == NULL) {
        if (inFile == NULL) {
            AppPrintError("pkeyutl: Failed to open stdin\n");
        } else {
            AppPrintError("pkeyutl: Failed to open the file <%s>, No such file or directory\n", inFile);
        }
        return HITLS_APP_UIO_FAIL;
    }
    int32_t ret = HITLS_APP_OptReadUio(readUio, buf, bufLen, maxSize);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkeyutl: Failed to read the content from the file <%s>\n", inFile);
    }
    BSL_UIO_Free(readUio);
    return ret;
}

static int32_t CheckFilePathLength(const PkeyUtlOpt *opt)
{
    // Check all file path length
    if (opt->inFile != NULL && strlen(opt->inFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The input file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->outFile != NULL && strlen(opt->outFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->pubinFile != NULL && strlen(opt->pubinFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The public key file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->prvinFile != NULL && strlen(opt->prvinFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The private key file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->inkeyFile != NULL && strlen(opt->inkeyFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The inkey file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->peerkeyFile != NULL && strlen(opt->peerkeyFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The peerkey file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->outRFile != NULL && strlen(opt->outRFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The outR file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->inRFile != NULL && strlen(opt->inRFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The inR file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->inRandFile != NULL && strlen(opt->inRandFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The r file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->outRandFile != NULL && strlen(opt->outRandFile) > PATH_MAX) {
        AppPrintError("pkeyutl: The out r file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetrPass(PkeyUtlOpt *opt, char **pass)
{
    char *tmpPass = NULL;
    int32_t ret = HITLS_APP_ParsePasswd(opt->rpass == NULL ? "stdin" : opt->rpass, &tmpPass);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkeyutl: Failed to parse the rpass, errCode: 0x%08x.\n", ret);
        return HITLS_APP_PASSWD_FAIL;
    }
    *pass = tmpPass;
    return HITLS_APP_SUCCESS;
}

static int32_t CheckParam(const PkeyUtlOpt *opt)
{
    int32_t count = opt->optEncrypt + opt->optDecrypt + opt->optDerive;
    if (count != 1) {
        AppPrintError("Must choose exactly one operation: encrypt, decrypt, or derive.\n");
        return HITLS_APP_INVALID_ARG;
    }

    if (opt->outFile == NULL && opt->optDerive == 0) {
        AppPrintError("Output file not specified.\n");
        return HITLS_APP_INVALID_ARG;
    }

    if (opt->optEncrypt == 1) {
        if (opt->inFile == NULL || opt->pubinFile == NULL) {
            AppPrintError("Encrypt: input file or public key file not specified.\n");
            return HITLS_APP_INVALID_ARG;
        }
    }

    if (opt->optDecrypt == 1) {
        if (opt->inFile == NULL || opt->prvinFile == NULL) {
            AppPrintError("Decrypt: input file or inkey file not specified.\n");
            return HITLS_APP_INVALID_ARG;
        }
    }

    if (opt->optDerive == 1) {
        if (opt->inkeyFile == NULL) {
            AppPrintError("Derive: inkey file or peerkey file not specified.\n");
            return HITLS_APP_INVALID_ARG;
        }
    }
#ifdef HITLS_APP_SM_MODE
    if (opt->smParam->smTag == 1 && opt->smParam->workPath == NULL) {
        AppPrintError(" The workpath is not specified.\n");
        return HITLS_APP_INVALID_ARG;
    }
#endif
    return CheckFilePathLength(opt);
}

#ifdef HITLS_APP_SM_MODE
static int32_t GetPkeyCtxFromUuid(PkeyUtlOpt *pkeyUtlOpt, char *uuid, CRYPT_EAL_PkeyCtx **ctx)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    pkeyUtlOpt->smParam->uuid = uuid;
    int32_t ret = HITLS_APP_FindKey(pkeyUtlOpt->provider, pkeyUtlOpt->smParam, CRYPT_PKEY_SM2, &keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to find key, ret: 0x%08x\n", ret);
        return ret;
    }
    *ctx = keyInfo.pkeyCtx;
    return HITLS_APP_SUCCESS;
}
#endif

static int32_t GetPubKeyCtx(PkeyUtlOpt *pkeyUtlOpt, CRYPT_EAL_PkeyCtx **ctx)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *pubBuf = NULL;
    uint64_t bufLen = 0;
    BSL_Buffer pub = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
#ifdef HITLS_APP_SM_MODE
    if (pkeyUtlOpt->smParam->smTag == 1) {
        ret = GetPkeyCtxFromUuid(pkeyUtlOpt, pkeyUtlOpt->pubinFile, &pkeyCtx);
        if (ret == HITLS_APP_SUCCESS) {
            *ctx = pkeyCtx;
            return HITLS_APP_SUCCESS;
        }
    }
#endif
    ret = GetReadBuf(&pubBuf, &bufLen, pkeyUtlOpt->pubinFile, MAX_CERT_KEY_SIZE);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkeyutl: Failed to read the public key file\n");
        return ret;
    }
    pub.data = pubBuf;
    pub.dataLen = bufLen;
    ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(), pkeyUtlOpt->provider->providerAttr,
        BSL_CID_UNKNOWN, "PEM", "PRIKEY_PKCS8_UNENCRYPT", &pub, NULL, &pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("pkeyutl: Failed to decode the private key, ret=%d\n", ret);
        BSL_SAL_ClearFree(pubBuf, bufLen);
        return HITLS_APP_CRYPTO_FAIL;
    }
    BSL_SAL_ClearFree(pubBuf, bufLen);
    *ctx = pkeyCtx;
    AppPrintInfo("pkeyutl: Get pub key ctx success!\n");
    return HITLS_APP_SUCCESS;
}

static int32_t PkeyEncrypt(PkeyUtlOpt *pkeyUtlOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *plainText = NULL;
    uint64_t plainTextLen = 0;
    uint8_t *cipherText = NULL;
    uint32_t outLen = CIPHER_TEXT_BASE_LEN;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    do {
        ret = GetPubKeyCtx(pkeyUtlOpt, &ctx);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
#ifdef HITLS_APP_SM_MODE
        if (pkeyUtlOpt->smParam->smTag == 1) {
            pkeyUtlOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
        }
#endif
        ret = GetReadBuf(&plainText, &plainTextLen, pkeyUtlOpt->inFile, MAX_CERT_KEY_SIZE);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        outLen += plainTextLen;
        cipherText = BSL_SAL_Malloc(outLen);
        if (cipherText == NULL) {
            AppPrintError("Failed to allocate memory for ciphertext\n");
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            break;
        }
        ret = CRYPT_EAL_PkeyEncrypt(ctx, plainText, plainTextLen, cipherText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("Failed to encrypt the plaintext, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }

        BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(pkeyUtlOpt->outFile, 'w', 0);  // overwrite the original content
        BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
        if (fileWriteUio == NULL) {
            AppPrintError("Failed to open the outfile\n");
            ret = HITLS_APP_UIO_FAIL;
            break;
        }
        ret = HITLS_APP_OptWriteUio(fileWriteUio, cipherText, outLen, HITLS_APP_FORMAT_HEX);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("dgst:Failed to export data to the outfile path\n");
        }
        BSL_UIO_Free(fileWriteUio);
    } while (0);
    BSL_SAL_FREE(cipherText);
    BSL_SAL_FREE(plainText);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

static int32_t PkeyDecrypt(PkeyUtlOpt *pkeyUtlOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *priBuf = NULL;
    uint64_t priLen = 0;
    uint8_t *cipherText = NULL;
    uint64_t cipherLen = 0;
    uint8_t *plainText = NULL;
    uint32_t outLen = 0;
    BSL_Buffer prv = {0};
    uint8_t *hexBuf = NULL;
    uint32_t hexLen;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    do {
#ifdef HITLS_APP_SM_MODE
        if (pkeyUtlOpt->smParam->smTag == 1) {
            ret = GetPkeyCtxFromUuid(pkeyUtlOpt, pkeyUtlOpt->prvinFile, &ctx);
            if (ret != HITLS_APP_SUCCESS) {
                break;
            }
        } else {
#endif
            ret = GetReadBuf(&priBuf, &priLen, pkeyUtlOpt->prvinFile, MAX_CERT_KEY_SIZE);
            if (ret != HITLS_APP_SUCCESS) {
                AppPrintError("pkeyutl: Failed to read private key file for decryption.\n");
                break;
            }
            prv.data = priBuf;
            prv.dataLen = priLen;
            ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(), pkeyUtlOpt->provider->providerAttr,
                BSL_CID_UNKNOWN, "PEM", "PRIKEY_PKCS8_UNENCRYPT", &prv, NULL, &ctx);
            if (ret != CRYPT_SUCCESS) {
                AppPrintError("pkeyutl: Failed to decode the private key, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
#ifdef HITLS_APP_SM_MODE
        }
        if (pkeyUtlOpt->smParam->smTag == 1) {
            pkeyUtlOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
        }
#endif
        ret = GetReadBuf(&cipherText, &cipherLen, pkeyUtlOpt->inFile, UINT32_MAX);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: Failed to read input ciphertext file.\n");
            break;
        }
        hexLen = cipherLen / APP_HEX_TO_BYTE + 1;
        hexBuf = (uint8_t *)BSL_SAL_Malloc(hexLen);
        if (hexBuf == NULL) {
            AppPrintError("pkeyutl: Failed to alloc memory.\n");
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            break;
        }
        ret = HITLS_APP_StrToHex((const char *)cipherText, hexBuf, &hexLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: Failed to convert signature to hex.");
            break;
        }
        outLen = cipherLen;
        plainText = BSL_SAL_Malloc(outLen);
        if (plainText == NULL) {
            AppPrintError("pkeyutl: Failed to allocate memory for plaintext\n");
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            break;
        }

        ret = CRYPT_EAL_PkeyDecrypt(ctx, hexBuf, hexLen, plainText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkeyutl: SM2 decryption failed, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }

        BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(pkeyUtlOpt->outFile, 'w', 0);
        BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
        if (fileWriteUio == NULL) {
            AppPrintError("pkeyutl: Failed to open the output file for plaintext.\n");
            ret = HITLS_APP_UIO_FAIL;
            break;
        }
        ret = HITLS_APP_OptWriteUio(fileWriteUio, plainText, outLen, HITLS_APP_FORMAT_TEXT);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: Failed to export plaintext to the output file.\n");
        }
        BSL_UIO_Free(fileWriteUio);
    } while (0);
    BSL_SAL_ClearFree(prv.data, prv.dataLen);
    BSL_SAL_FREE(hexBuf);
    BSL_SAL_FREE(cipherText);
    BSL_SAL_FREE(plainText);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

static int32_t GetPeerCtx(CRYPT_EAL_PkeyCtx **peerCtx, PkeyUtlOpt *pkeyUtlOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *pubBuf = NULL;
    uint64_t pubLen = 0;
    uint8_t *inRBuf = NULL;
    uint64_t inRLen = 0;
    uint8_t *hexBuf = NULL;
    uint32_t hexLen;
    BSL_Buffer pub = {0};
    do {
        ret = GetReadBuf(&pubBuf, &pubLen, pkeyUtlOpt->peerkeyFile, MAX_CERT_KEY_SIZE);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: Failed to read peer public key file for exchange.\n");
            break;
        }
        pub.data = pubBuf;
        pub.dataLen = pubLen;
        ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(), pkeyUtlOpt->provider->providerAttr,
            BSL_CID_UNKNOWN, "PEM", "PRIKEY_PKCS8_UNENCRYPT", &pub, NULL, peerCtx);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkeyutl: Failed to decode the peer public key, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = GetReadBuf(&inRBuf, &inRLen, pkeyUtlOpt->inRFile, MAX_CERT_KEY_SIZE);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: Failed to read R file for exchange.\n");
            break;
        }
        hexLen = inRLen / APP_HEX_TO_BYTE + 1;
        hexBuf = (uint8_t *)BSL_SAL_Malloc(hexLen);
        if (hexBuf == NULL) {
            AppPrintError("pkeyutl: Failed to alloc memory.\n");
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            break;
        }
        ret = HITLS_APP_StrToHex((const char *)inRBuf, hexBuf, &hexLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: Failed to convert R to hex.");
            break;
        }
        ret = CRYPT_EAL_PkeyCtrl(*peerCtx, CRYPT_CTRL_SET_SM2_USER_ID, pkeyUtlOpt->userid, strlen(pkeyUtlOpt->userid));
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkeyutl: Failed to set SM2 user ID, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        if (pkeyUtlOpt->inRFile != NULL) {
            ret = CRYPT_EAL_PkeyCtrl(*peerCtx, CRYPT_CTRL_SET_SM2_SERVER, &(int32_t){0}, sizeof(int32_t));
        } else {
            ret = CRYPT_EAL_PkeyCtrl(*peerCtx, CRYPT_CTRL_SET_SM2_SERVER, &(int32_t){1}, sizeof(int32_t));
        }
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkeyutl: Failed to set SM2 server/client, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = CRYPT_EAL_PkeyCtrl(*peerCtx, CRYPT_CTRL_SET_SM2_R, hexBuf, hexLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkeyutl: Failed to generate SM2 R, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
        }
    } while (0);
    BSL_SAL_FREE(hexBuf);
    BSL_SAL_FREE(inRBuf);
    BSL_SAL_ClearFree(pub.data, pub.dataLen);
    return ret;
}

static int32_t GetDataFromP12(AppProvider *provider, const char *file, uint8_t *password, uint32_t passwordLen,
    uint8_t *data, uint32_t *dataLen)
{
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer encPwd = {0};
    HITLS_PKCS12_PwdParam pwdParam = {0};
    encPwd.data = password;
    encPwd.dataLen = passwordLen;
    pwdParam.encPwd = &encPwd;
    pwdParam.macPwd = &encPwd;

    int32_t ret = HITLS_PKCS12_ProviderParseFile(APP_GetCurrent_LibCtx(), provider->providerAttr, "ASN1", file,
        &pwdParam, &p12, true);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkeyutl: Failed to read p12 file, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    BslList *bagList = NULL;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_SECRETBAGS, &bagList, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        AppPrintError("pkeyutl: Failed to get secret bags, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    HITLS_PKCS12_Bag *bag = BSL_LIST_GET_FIRST(bagList);
    BSL_Buffer value = {data, *dataLen};
    ret = HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_VALUE, &value, 0);
    HITLS_PKCS12_Free(p12);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkeyutl: Failed to get bag value, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    *dataLen = value.dataLen;
    return HITLS_APP_SUCCESS;
}

static int32_t GenP12File(AppProvider *provider, const char *file, HITLS_PKCS12_EncodeParam *encodeParam,
    uint8_t *data, uint32_t dataLen)
{
    HITLS_PKCS12 *p12 = HITLS_PKCS12_ProviderNew(APP_GetCurrent_LibCtx(), provider->providerAttr);
    if (p12 == NULL) {
        AppPrintError("pkeyutl: Failed to create the p12 ctx.\n");
        return HITLS_APP_X509_FAIL;
    }

    BSL_Buffer value = {0};
    value.data = data;
    value.dataLen = dataLen;

    HITLS_PKCS12_Bag *bag = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, BSL_CID_CE_KEYUSAGE, &value);
    if (bag == NULL) {
        AppPrintError("pkeyutl: Failed to create the secret bag.\n");
        HITLS_PKCS12_Free(p12);
        return HITLS_APP_X509_FAIL;
    }

    int32_t ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, bag, 0);
    HITLS_PKCS12_BagFree(bag);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        AppPrintError("pkeyutl: Failed to add the secret bag to p12, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, encodeParam, true, file);
    HITLS_PKCS12_Free(p12);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkeyutl: Failed to generate p12 file, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AddDataToP12(AppProvider *provider, const char *file, uint8_t *password, uint32_t passwordLen,
    uint8_t *data, uint32_t dataLen)
{
    CRYPT_Pbkdf2Param pbkdf2Param = {0};
    pbkdf2Param.pbesId = BSL_CID_PBES2;
    pbkdf2Param.pbkdfId = CRYPT_KDF_PBKDF2;
    pbkdf2Param.hmacId = CRYPT_MAC_HMAC_SM3;
    pbkdf2Param.symId = CRYPT_CIPHER_SM4_CBC;
    pbkdf2Param.saltLen = APP_PKEYUTL_PBKDF2_SALT_LEN_MIN;
    pbkdf2Param.pwd = password;
    pbkdf2Param.pwdLen = passwordLen;
    pbkdf2Param.itCnt = APP_PKEYUTL_PBKDF2_IT_CNT_MIN;

    CRYPT_EncodeParam encParam = {0};
    encParam.deriveMode = CRYPT_DERIVE_PBKDF2;
    encParam.param = &pbkdf2Param;

    HITLS_PKCS12_KdfParam kdfParam = {0};
    kdfParam.saltLen = APP_PKEYUTL_PBKDF2_SALT_LEN_MIN;
    kdfParam.itCnt = APP_PKEYUTL_PBKDF2_IT_CNT_MIN;
    kdfParam.macId = CRYPT_MD_SM3;
    kdfParam.pwd = password;
    kdfParam.pwdLen = passwordLen;

    HITLS_PKCS12_MacParam macParam = {0};
    macParam.algId = BSL_CID_PKCS12KDF;
    macParam.para = &kdfParam;

    HITLS_PKCS12_EncodeParam encodeParam = {0};
    encodeParam.encParam = encParam;
    encodeParam.macParam = macParam;

    return GenP12File(provider, file, &encodeParam, data, dataLen);
}

static int32_t GetTempKeyFromP12(PkeyUtlOpt *pkeyUtlOpt, CRYPT_EAL_PkeyCtx *ctx)
{
    char *pass = NULL;
    int32_t ret = GetrPass(pkeyUtlOpt, &pass);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkeyutl: Failed to get rpass, errCode: 0x%x.\n", ret);
        return ret;
    }
    uint8_t r[APP_PKEYUTL_SM2_EXCH_TEMP_KEY_LEN] = {0};
    uint32_t rLen = sizeof(r);
    ret = GetDataFromP12(pkeyUtlOpt->provider, pkeyUtlOpt->inRandFile, (uint8_t *)pass, strlen(pass), r, &rLen);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_ClearFree(pass, strlen(pass));
        AppPrintError("pkeyutl: Failed to get SM2 r from p12, errCode: 0x%x.\n", ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_RANDOM, r, rLen);
    BSL_SAL_CleanseData(r, rLen);
    BSL_SAL_ClearFree(pass, strlen(pass));
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("pkeyutl: Failed to set SM2 r, ret=%d\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t WriteTempKeyToP12(PkeyUtlOpt *pkeyUtlOpt, CRYPT_EAL_PkeyCtx *ctx)
{
    char *pass = NULL;
    int32_t ret = GetrPass(pkeyUtlOpt, &pass);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkeyutl: Failed to get rpass, errCode: 0x%x.\n", ret);
        return ret;
    }
    uint8_t r[APP_PKEYUTL_SM2_EXCH_TEMP_KEY_LEN] = {0};
    uint32_t rLen = sizeof(r);
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SM2_RANDOM, r, rLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(pass, strlen(pass));
        AppPrintError("pkeyutl: Failed to get SM2 r, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    ret = AddDataToP12(pkeyUtlOpt->provider, pkeyUtlOpt->outRandFile, (uint8_t *)pass, strlen(pass), r, rLen);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkeyutl: Failed to add SM2 r to p12, errCode: 0x%x.\n", ret);
    }
    BSL_SAL_ClearFree(pass, strlen(pass));
    BSL_SAL_CleanseData(r, sizeof(r));
    return ret;
}

static int32_t PkeyDerive(PkeyUtlOpt *pkeyUtlOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *priBuf = NULL;
    uint64_t priLen = 0;
    uint8_t localR[65];
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *peerCtx = NULL;
    uint8_t out[64];
    uint32_t outLen = sizeof(out);
    BSL_Buffer prv = {0};
    do {
#ifdef HITLS_APP_SM_MODE
        if (pkeyUtlOpt->smParam->smTag == 1) {
            ret = GetPkeyCtxFromUuid(pkeyUtlOpt, pkeyUtlOpt->inkeyFile, &ctx);
            if (ret != HITLS_APP_SUCCESS) {
                break;
            }
        } else {
#endif
            ret = GetReadBuf(&priBuf, &priLen, pkeyUtlOpt->inkeyFile, MAX_CERT_KEY_SIZE);
            if (ret != HITLS_APP_SUCCESS) {
                AppPrintError("pkeyutl: Failed to read private key file for exchange.\n");
                break;
            }
            prv.data = priBuf;
            prv.dataLen = priLen;
            ret = CRYPT_EAL_ProviderDecodeBuffKey(APP_GetCurrent_LibCtx(), pkeyUtlOpt->provider->providerAttr,
                BSL_CID_UNKNOWN, "PEM", "PRIKEY_PKCS8_UNENCRYPT", &prv, NULL, &ctx);
            if (ret != CRYPT_SUCCESS) {
                AppPrintError("pkeyutl: Failed to decode the private key, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
#ifdef HITLS_APP_SM_MODE
        }
#endif
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, pkeyUtlOpt->userid, strlen(pkeyUtlOpt->userid));
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkeyutl: Failed to set SM2 user ID, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        if (pkeyUtlOpt->inRandFile == NULL) {
            ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER, &(int32_t){1}, sizeof(int32_t));
        } else {
            ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER, &(int32_t){0}, sizeof(int32_t));
        }
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkeyutl: Failed to set SM2 server/client, ret=%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        if (pkeyUtlOpt->inRandFile == NULL) {
            ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR));
            if (ret != CRYPT_SUCCESS) {
                AppPrintError("pkeyutl: Failed to generate SM2 R, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
        } else {
            ret = GetTempKeyFromP12(pkeyUtlOpt, ctx);
            if (ret != HITLS_APP_SUCCESS) {
                break;
            }
        }

        if (pkeyUtlOpt->outRFile != NULL) {
            BSL_UIO *fileWriteUio = HITLS_APP_UioOpen(pkeyUtlOpt->outRFile, 'w', 0);
            BSL_UIO_SetIsUnderlyingClosedByUio(fileWriteUio, true);
            if (fileWriteUio == NULL) {
                AppPrintError("pkeyutl: Failed to open the output file for R.\n");
                ret = HITLS_APP_UIO_FAIL;
                break;
            }
            ret = HITLS_APP_OptWriteUio(fileWriteUio, localR, sizeof(localR), HITLS_APP_FORMAT_HEX);
            if (ret != HITLS_APP_SUCCESS) {
                AppPrintError("pkeyutl: Failed to export R to the output file.\n");
            }
            BSL_UIO_Free(fileWriteUio);
        }
        if (pkeyUtlOpt->outRandFile != NULL) {
            ret = WriteTempKeyToP12(pkeyUtlOpt, ctx);
            if (ret != HITLS_APP_SUCCESS) {
                break;
            }
        }
        if (pkeyUtlOpt->inRFile != NULL && pkeyUtlOpt->peerkeyFile != NULL) {
            ret = GetPeerCtx(&peerCtx, pkeyUtlOpt);
            if (ret != HITLS_APP_SUCCESS) {
                AppPrintError("pkeyutl: Failed to get peer context, ret=%d\n", ret);
                break;
            }
#ifdef HITLS_APP_SM_MODE
            if (pkeyUtlOpt->smParam->smTag == 1) {
                pkeyUtlOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
            }
#endif
            ret = CRYPT_EAL_PkeyComputeShareKey(ctx, peerCtx, out, &outLen);
            if (ret != CRYPT_SUCCESS) {
                AppPrintError("pkeyutl: Failed to compute shared key, ret=%d\n", ret);
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
            BSL_UIO *shareFileUio = HITLS_APP_UioOpen(pkeyUtlOpt->outFile, 'w', 0);
            BSL_UIO_SetIsUnderlyingClosedByUio(shareFileUio, true);
            if (shareFileUio == NULL) {
                AppPrintError("pkeyutl: Failed to open the output file for plaintext.\n");
                ret = HITLS_APP_UIO_FAIL;
                break;
            }
            ret = HITLS_APP_OptWriteUio(shareFileUio, out, outLen, HITLS_APP_FORMAT_TEXT);
            if (ret != HITLS_APP_SUCCESS) {
                AppPrintError("pkeyutl: Failed to export plaintext to the output file.\n");
            }

            BSL_UIO_Free(shareFileUio);
        }
    } while (0);
    pkeyUtlOpt->inRFile = NULL;
    BSL_SAL_ClearFree(prv.data, prv.dataLen);
    BSL_SAL_CleanseData(out, outLen);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    return ret;
}

int32_t HITLS_PkeyUtlMain(int argc, char *argv[])
{
    AppProvider appProvider = {NULL, NULL, NULL};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    PkeyUtlOpt pkeyUtlOpt = {0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        "1234567812345678", &appProvider, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
    PkeyUtlOpt pkeyUtlOpt = {0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        "1234567812345678", &appProvider};
#endif
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ret = HITLS_APP_OptBegin(argc, argv, g_pkeyUtlOpts);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: error in opt begin.\n");
            break;
        }
        ret = ParsepkeyUtlOpt(&pkeyUtlOpt);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }

        ret = CheckParam(&pkeyUtlOpt);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = HITLS_APP_Init(&initParam);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("pkeyutl: Failed to init app, errCode: 0x%x.\n", ret);
            break;
        }
        if (pkeyUtlOpt.optEncrypt) {
            ret = PkeyEncrypt(&pkeyUtlOpt);
        } else if (pkeyUtlOpt.optDecrypt) {
            ret = PkeyDecrypt(&pkeyUtlOpt);
        } else {
            ret = PkeyDerive(&pkeyUtlOpt);
        }
    } while (false);
    HITLS_APP_Deinit(&initParam, ret);
    HITLS_APP_OptEnd();
    return ret;
}