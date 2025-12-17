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

#include "app_kdf.h"
#include <limits.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_kdf.h"
#include "crypt_params_key.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_provider.h"
#include "app_sm.h"
#include "app_utils.h"

typedef enum OptionChoice {
    HITLS_APP_OPT_KDF_ERR = -1,
    HITLS_APP_OPT_KDF_EOF = 0,
    HITLS_APP_OPT_KDF_ALG = HITLS_APP_OPT_KDF_EOF,
    HITLS_APP_OPT_KDF_HELP = 1,  // The value of the help type of each opt option is 1. The following can be customized.
    HITLS_APP_OPT_KDF_KEYLEN,
    HITLS_APP_OPT_KDF_MAC_ALG,
    HITLS_APP_OPT_KDF_OUT,
    HITLS_APP_OPT_KDF_PASS,
    HITLS_APP_OPT_KDF_HEXPASS,
    HITLS_APP_OPT_KDF_SALT,
    HITLS_APP_OPT_KDF_HEXSALT,
    HITLS_APP_OPT_KDF_ITER,
    HITLS_APP_OPT_KDF_BINARY,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLSOptType;

static const HITLS_CmdOption g_kdfOpts[] = {
    {"help", HITLS_APP_OPT_KDF_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Show usage information for KDF command."},
    {"mac", HITLS_APP_OPT_KDF_MAC_ALG, HITLS_APP_OPT_VALUETYPE_STRING,
        "Specify MAC algorithm used in KDF (e.g.: hmac-sha256)."},
    {"out", HITLS_APP_OPT_KDF_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE,
        "Set output file for derived key (default: stdout, hex format)."},
    {"binary", HITLS_APP_OPT_KDF_BINARY, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
        "Output derived key in binary format."},
    {"keylen", HITLS_APP_OPT_KDF_KEYLEN, HITLS_APP_OPT_VALUETYPE_UINT, "Length of derived key in bytes."},
    {"pass", HITLS_APP_OPT_KDF_PASS, HITLS_APP_OPT_VALUETYPE_STRING, "Input password as a string."},
    {"hexpass", HITLS_APP_OPT_KDF_HEXPASS, HITLS_APP_OPT_VALUETYPE_STRING,
        "Input password in hexadecimal format (e.g.: 0x1234ABCD)."},
    {"salt", HITLS_APP_OPT_KDF_SALT, HITLS_APP_OPT_VALUETYPE_STRING, "Input salt as a string."},
    {"hexsalt", HITLS_APP_OPT_KDF_HEXSALT, HITLS_APP_OPT_VALUETYPE_STRING,
        "Input salt in hexadecimal format (e.g.: 0xAABBCCDD)."},
    {"iter", HITLS_APP_OPT_KDF_ITER, HITLS_APP_OPT_VALUETYPE_UINT, "Number of iterations for KDF computation."},
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {"kdfalg...", HITLS_APP_OPT_KDF_ALG, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Specify KDF algorithm (e.g.: pbkdf2)."},
    {NULL, 0, 0, NULL}
};

typedef struct {
    int32_t macId;
    char *kdfName;
    int32_t kdfId;
    uint32_t keyLen;
    char *outFile;
    char *pass;
    char *hexPass;
    char *salt;
    char *hexSalt;
    uint32_t iter;
    AppProvider *provider;
    uint32_t isBinary;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} KdfOpt;

typedef int32_t (*KdfOptHandleFunc)(KdfOpt *);

typedef struct {
    int optType;
    KdfOptHandleFunc func;
} KdfOptHandleFuncMap;

static int32_t HandleKdfErr(KdfOpt *kdfOpt)
{
    (void)kdfOpt;
    AppPrintError("kdf: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t HandleKdfHelp(KdfOpt *kdfOpt)
{
    (void)kdfOpt;
    HITLS_APP_OptHelpPrint(g_kdfOpts);
    return HITLS_APP_HELP;
}

static int32_t HandleKdfOut(KdfOpt *kdfOpt)
{
    kdfOpt->outFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int32_t HandleKdfPass(KdfOpt *kdfOpt)
{
    kdfOpt->pass = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfHexPass(KdfOpt *kdfOpt)
{
    kdfOpt->hexPass = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfSalt(KdfOpt *kdfOpt)
{
    kdfOpt->salt = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfHexSalt(KdfOpt *kdfOpt)
{
    kdfOpt->hexSalt = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfIter(KdfOpt *kdfOpt)
{
    int32_t ret = HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), &(kdfOpt->iter));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("kdf: Invalid iter value.\n");
    }
    return ret;
}

static int32_t HandleKdfKeyLen(KdfOpt *kdfOpt)
{
    int32_t ret = HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), &(kdfOpt->keyLen));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("kdf: Invalid keylen value.\n");
    }
    return ret;
}

static int32_t HandleKdfBinary(KdfOpt *kdfOpt)
{
    kdfOpt->isBinary = 1;
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfMacAlg(KdfOpt *kdfOpt)
{
    char *macName = HITLS_APP_OptGetValueStr();
    if (macName == NULL) {
        AppPrintError("kdf: MAC algorithm is NULL.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    kdfOpt->macId = HITLS_APP_GetCidByName(macName, HITLS_APP_LIST_OPT_MAC_ALG);
    if (kdfOpt->macId == BSL_CID_UNKNOWN) {
        AppPrintError("kdf: Unsupported MAC algorithm: %s\n", macName);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static const KdfOptHandleFuncMap g_kdfOptHandleFuncMap[] = {
    {HITLS_APP_OPT_KDF_ERR, HandleKdfErr},
    {HITLS_APP_OPT_KDF_HELP, HandleKdfHelp},
    {HITLS_APP_OPT_KDF_OUT, HandleKdfOut},
    {HITLS_APP_OPT_KDF_PASS, HandleKdfPass},
    {HITLS_APP_OPT_KDF_HEXPASS, HandleKdfHexPass},
    {HITLS_APP_OPT_KDF_SALT, HandleKdfSalt},
    {HITLS_APP_OPT_KDF_HEXSALT, HandleKdfHexSalt},
    {HITLS_APP_OPT_KDF_ITER, HandleKdfIter},
    {HITLS_APP_OPT_KDF_KEYLEN, HandleKdfKeyLen},
    {HITLS_APP_OPT_KDF_MAC_ALG, HandleKdfMacAlg},
    {HITLS_APP_OPT_KDF_BINARY, HandleKdfBinary},
};

static int32_t ParseKdfOpt(KdfOpt *kdfOpt)
{
    int ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_KDF_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_KDF_EOF)) {
        for (size_t i = 0; i < (sizeof(g_kdfOptHandleFuncMap) / sizeof(g_kdfOptHandleFuncMap[0])); ++i) {
            if (optType == g_kdfOptHandleFuncMap[i].optType) {
                ret = g_kdfOptHandleFuncMap[i].func(kdfOpt);
                break;
            }
        }
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        HITLS_APP_PROV_CASES(optType, kdfOpt->provider)
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(optType, kdfOpt->smParam);
#endif
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetKdfAlg(KdfOpt *kdfOpt)
{
    int32_t argc = HITLS_APP_GetRestOptNum();
    char **argv = HITLS_APP_GetRestOpt();
    if (argc == 0) {
        AppPrintError("Please input KDF algorithm.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    kdfOpt->kdfName = argv[0];
    kdfOpt->kdfId = HITLS_APP_GetCidByName(kdfOpt->kdfName, HITLS_APP_LIST_OPT_KDF_ALG);
    if (kdfOpt->kdfId == BSL_CID_UNKNOWN) {
        AppPrintError("Not support KDF algorithm.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (argc - 1 != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("kdf: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckSmParam(KdfOpt *kdfOpt)
{
#ifdef HITLS_APP_SM_MODE
    if (kdfOpt->smParam->smTag == 1 && kdfOpt->smParam->workPath == NULL) {
        AppPrintError("kdf: The workpath is not specified.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
#else
    (void)kdfOpt;
#endif
    return HITLS_APP_SUCCESS;
}

static int32_t CheckParam(KdfOpt *kdfOpt)
{
    int32_t ret = CheckSmParam(kdfOpt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (kdfOpt->kdfId == CRYPT_KDF_PBKDF2) {
        if (kdfOpt->pass == NULL && kdfOpt->hexPass == NULL) {
            AppPrintError("kdf: No pass entered.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (kdfOpt->pass != NULL && kdfOpt->hexPass != NULL) {
            AppPrintError("kdf: Cannot specify both pass and hexpass.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (kdfOpt->salt == NULL && kdfOpt->hexSalt == NULL) {
            AppPrintError("kdf: No salt entered.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (kdfOpt->salt != NULL && kdfOpt->hexSalt != NULL) {
            AppPrintError("kdf: Cannot specify both salt and hexsalt.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    }
    if (kdfOpt->keyLen == 0) {
        AppPrintError("kdf: Input keylen is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (kdfOpt->iter == 0) {
        AppPrintError("kdf: Input iter is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (kdfOpt->outFile != NULL && strlen((const char*)kdfOpt->outFile) > PATH_MAX) {
        AppPrintError("kdf: The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    
    return HITLS_APP_SUCCESS;
}

static CRYPT_EAL_KdfCTX *InitAlgKdf(KdfOpt *kdfOpt)
{
    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_ProviderKdfNewCtx(APP_GetCurrent_LibCtx(), kdfOpt->kdfId,
        kdfOpt->provider->providerAttr);
    if (ctx == NULL) {
        AppPrintError("Failed to create the algorithm(%s) context\n", kdfOpt->kdfName);
    }
    return ctx;
}

static int32_t KdfParsePass(KdfOpt *kdfOpt, uint8_t **pass, uint32_t *passLen)
{
    size_t len;
    if (kdfOpt->pass != NULL) {
        len = strlen((const char *)kdfOpt->pass);
    } else {
        len = strlen((const char *)kdfOpt->hexPass);
    }
    if (len > UINT32_MAX) {
        AppPrintError("kdf: pass length overflow.\n");
        return HITLS_APP_INVALID_ARG;
    }
    if (kdfOpt->pass != NULL) {
        *passLen = (uint32_t)len;
        *pass = (uint8_t *)kdfOpt->pass;
    } else {
        int32_t ret = HITLS_APP_HexToByte(kdfOpt->hexPass, 1, pass, passLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("kdf:Invalid pass: %s.\n", kdfOpt->hexPass);
            return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t KdfParseSalt(KdfOpt *kdfOpt, uint8_t **salt, uint32_t *saltLen)
{
    size_t len;
    if (kdfOpt->salt != NULL) {
        len = strlen((const char *)kdfOpt->salt);
    } else {
        len = strlen((const char *)kdfOpt->hexSalt);
    }
    if (len > UINT32_MAX) {
        AppPrintError("kdf: salt length overflow.\n");
        return HITLS_APP_INVALID_ARG;
    }
    if (kdfOpt->salt != NULL) {
        *saltLen = (uint32_t)len;
        *salt = (uint8_t *)kdfOpt->salt;
    } else {
        int32_t ret = HITLS_APP_HexToByte(kdfOpt->hexSalt, 1, salt, saltLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("kdf:Invalid salt: %s.\n", kdfOpt->hexSalt);
            return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t Pbkdf2Params(CRYPT_EAL_KdfCTX *ctx, BSL_Param *params, KdfOpt *kdfOpt)
{
    uint32_t index = 0;
    uint8_t *pass = NULL;
    uint32_t passLen = 0;
    uint8_t *salt = NULL;
    uint32_t saltLen = 0;
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ret = KdfParsePass(kdfOpt, &pass, &passLen);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = KdfParseSalt(kdfOpt, &salt, &saltLen);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
            &(kdfOpt->macId), sizeof(kdfOpt->macId));
        if (ret != BSL_SUCCESS) {
            AppPrintError("kdf:Init macId failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, pass, passLen);
        if (ret != BSL_SUCCESS) {
            AppPrintError("kdf:Init pass failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
        if (ret != BSL_SUCCESS) {
            AppPrintError("kdf:Init salt failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
            &kdfOpt->iter, sizeof(kdfOpt->iter));
        if (ret != BSL_SUCCESS) {
            AppPrintError("kdf:Init iter failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = CRYPT_EAL_KdfSetParam(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("kdf:KdfSetParam failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
        }
    } while (0);
    if (kdfOpt->salt == NULL) {
        BSL_SAL_FREE(salt);
    }
    if (kdfOpt->pass == NULL) {
        BSL_SAL_ClearFree(pass, passLen);
    }
    return ret;
}

static int32_t PbkdfParamSet(CRYPT_EAL_KdfCTX *ctx, KdfOpt *kdfOpt)
{
    if (kdfOpt->kdfId == CRYPT_KDF_PBKDF2) {
        BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
        return Pbkdf2Params(ctx, params, kdfOpt);
    }
    AppPrintError("kdf: Unsupported KDF algorithm: %s\n", kdfOpt->kdfName);
    return HITLS_APP_OPT_VALUE_INVALID;
}

static int32_t KdfResult(CRYPT_EAL_KdfCTX *ctx, KdfOpt *kdfOpt)
{
    uint8_t *out = NULL;
    uint32_t outLen = kdfOpt->keyLen;

    int32_t ret = PbkdfParamSet(ctx, kdfOpt);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("PbkdfParamSet failed. \n");
        return ret;
    }
#ifdef HITLS_APP_SM_MODE
    kdfOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
#endif
    out = BSL_SAL_Malloc(outLen);
    if (out == NULL) {
        AppPrintError("kdf: Allocate memory failed. \n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("KdfDeriv failed. ERROR:%d\n", ret);
        BSL_SAL_ClearFree(out, outLen);
        return HITLS_APP_CRYPTO_FAIL;
    }

    BSL_UIO *fileOutUio = HITLS_APP_UioOpen(kdfOpt->outFile, 'w', 0);
    if (fileOutUio == NULL) {
        BSL_SAL_ClearFree(out, outLen);
        AppPrintError("kdf:UioOpen failed\n");
        return HITLS_APP_UIO_FAIL;
    }
    if (kdfOpt->outFile != NULL) {
        BSL_UIO_SetIsUnderlyingClosedByUio(fileOutUio, true);
    }
    ret = HITLS_APP_OptWriteUio(fileOutUio, out, outLen,
        kdfOpt->isBinary == 1 ? HITLS_APP_FORMAT_TEXT: HITLS_APP_FORMAT_HEX);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("kdf:Failed to output the content to the screen\n");
    }

    BSL_UIO_Free(fileOutUio);
    BSL_SAL_ClearFree(out, outLen);
    return ret;
}

int32_t HITLS_KdfMain(int argc, char *argv[])
{
    int32_t mainRet = HITLS_APP_SUCCESS;
    AppProvider appProvider = {NULL, NULL, NULL};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    KdfOpt kdfOpt = {CRYPT_MAC_HMAC_SM3, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 1024, &appProvider, 0, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
    KdfOpt kdfOpt = {CRYPT_MAC_HMAC_SHA256, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 1000, &appProvider, 0};
#endif
    CRYPT_EAL_KdfCTX *ctx = NULL;
    do {
        mainRet = HITLS_APP_OptBegin(argc, argv, g_kdfOpts);
        if (mainRet != HITLS_APP_SUCCESS) {
            AppPrintError("error in opt begin.\n");
            break;
        }
        mainRet = ParseKdfOpt(&kdfOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            break;
        }
        mainRet = GetKdfAlg(&kdfOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            break;
        }
        mainRet = CheckParam(&kdfOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            break;
        }
        mainRet = HITLS_APP_Init(&initParam);
        if (mainRet != HITLS_APP_SUCCESS) {
            AppPrintError("kdf: Failed to init, errCode: 0x%x.\n", mainRet);
            break;
        }
        ctx = InitAlgKdf(&kdfOpt);
        if (ctx == NULL) {
            mainRet = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        mainRet = KdfResult(ctx, &kdfOpt);
    } while (0);
    CRYPT_EAL_KdfFreeCtx(ctx);
    HITLS_APP_Deinit(&initParam, mainRet);
    HITLS_APP_OptEnd();
    return mainRet;
}