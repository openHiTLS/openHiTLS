/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor: Xiaoran Dong, Enyu Liu, Boyu Lu, Haowei Wang, Jiayi Zhou
 * Instructor:  Weijia Wang
*/
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

#include "app_sign.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "app_utils.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_provider.h"
#include "crypt_eal_pkey.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_codecs.h"
#include "sal_file.h"

#define MAX_BUFSIZE (1024 * 8)

typedef enum {
    PKEY_ALG_UNKNOWN = 0,
    PKEY_ALG_SM2,
    PKEY_ALG_ECDSA
} PkeyAlgType;

typedef enum OptionChoice {
    HITLS_APP_OPT_SIGN_ERR = -1,
    HITLS_APP_OPT_SIGN_EOF = 0,
    HITLS_APP_OPT_SIGN_HELP = 1,
    HITLS_APP_OPT_SIGN_IN,
    HITLS_APP_OPT_SIGN_OUT,
    HITLS_APP_OPT_SIGN_KEY,
    HITLS_APP_OPT_SIGN_PUBKEY,
    HITLS_APP_OPT_SIGN_SIG,
    HITLS_APP_OPT_SIGN_VERIFY,
    HITLS_APP_OPT_SIGN_USERID,
    HITLS_APP_OPT_SIGN_DIGEST,
    HITLS_APP_OPT_SIGN_PKEYALG,
} HITLSOptSignType;

const HITLS_CmdOption g_signOpts[] = {
    {"help",   HITLS_APP_OPT_SIGN_HELP,    HITLS_APP_OPT_VALUETYPE_NO_VALUE,
        "Show usage information for sign command."},
    {"in",     HITLS_APP_OPT_SIGN_IN,      HITLS_APP_OPT_VALUETYPE_IN_FILE,
        "Set input file for signing/verifying (default: stdin)."},
    {"out",    HITLS_APP_OPT_SIGN_OUT,     HITLS_APP_OPT_VALUETYPE_OUT_FILE,
        "Set output file for signature (default: stdout)."},
    {"key",    HITLS_APP_OPT_SIGN_KEY,     HITLS_APP_OPT_VALUETYPE_IN_FILE,  "Private key file for signing."},
    {"pubkey", HITLS_APP_OPT_SIGN_PUBKEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE,  "Public key file for verifying."},
    {"sig",    HITLS_APP_OPT_SIGN_SIG,     HITLS_APP_OPT_VALUETYPE_IN_FILE,  "Signature file for verifying."},
    {"verify", HITLS_APP_OPT_SIGN_VERIFY,  HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Verify mode."},
    {"userid", HITLS_APP_OPT_SIGN_USERID,  HITLS_APP_OPT_VALUETYPE_STRING,
        "User ID for SM2 (default: 1234567812345678)."},
    {"digest", HITLS_APP_OPT_SIGN_DIGEST,  HITLS_APP_OPT_VALUETYPE_STRING,
        "Digest algorithm (default: sm3 for sm2; sha256 for ecdsa)."},
    {"pkeyalg", HITLS_APP_OPT_SIGN_PKEYALG, HITLS_APP_OPT_VALUETYPE_STRING,
        "Key algorithm: sm2 | ecdsa (required)."},
    {NULL}
};

typedef struct {
    char *inFile;
    char *outFile;
    char *keyFile;
    char *pubkeyFile;
    char *sigFile;
    int verifyMode;
    
    
    char *userId;
    char *digestAlg;
    char *pkeyAlgStr;
    PkeyAlgType pkeyAlg;
} SignOpt;

static int32_t SignOptHelp(SignOpt *opt)
{
    (void)opt;
    HITLS_APP_OptHelpPrint(g_signOpts);
    return HITLS_APP_HELP;
}

static int StrEqNoCase(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {return 0;}
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (tolower(ca) != tolower(cb)) {return 0;}
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

static PkeyAlgType ParsePkeyAlg(const char *s)
{
    if (s == NULL) {return PKEY_ALG_UNKNOWN;}
    if (StrEqNoCase(s, "sm2"))   {return PKEY_ALG_SM2;}
    if (StrEqNoCase(s, "ecdsa")) {return PKEY_ALG_ECDSA;}
    return PKEY_ALG_UNKNOWN;
}

static int32_t MapDigestId(const char *name)
{
    if (name == NULL) {return -1;}
    if (StrEqNoCase(name, "sm3"))    {return CRYPT_MD_SM3;}
    if (StrEqNoCase(name, "sha256")) {return CRYPT_MD_SHA256;}
    if (StrEqNoCase(name, "sha384")) {return CRYPT_MD_SHA384;}
    if (StrEqNoCase(name, "sha512")) {return CRYPT_MD_SHA512;}
    if (StrEqNoCase(name, "sha1"))   {return CRYPT_MD_SHA1;}
    return -1;
}

static char* DefaultDigestForAlg(PkeyAlgType alg)
{
    switch (alg) {
        case PKEY_ALG_SM2:   return "sm3";
        case PKEY_ALG_ECDSA: return "sha256";
        default:             return NULL;
    }
}

static int32_t ParseSignOpt(SignOpt *opt)
{
    int ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_SIGN_ERR;
    char *val = NULL;
    while ((ret == HITLS_APP_SUCCESS) &&
           ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_SIGN_EOF)) {
        switch (optType) {
            case HITLS_APP_OPT_SIGN_HELP:
                
                
                return SignOptHelp(opt);
            case HITLS_APP_OPT_SIGN_IN:
                opt->inFile = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_SIGN_OUT:
                opt->outFile = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_SIGN_KEY:
                opt->keyFile = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_SIGN_PUBKEY:
                opt->pubkeyFile = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_SIGN_SIG:
                opt->sigFile = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_SIGN_VERIFY:
                opt->verifyMode = 1; break;
            case HITLS_APP_OPT_SIGN_USERID:
                val = HITLS_APP_OptGetValueStr();
                
                if (val == NULL || strlen(val) == 0) {
                    AppPrintError("sign: -userid value must not be empty.\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                BSL_SAL_FREE(opt->userId);
                opt->userId = (char *)BSL_SAL_Calloc(strlen(val) + 1, sizeof(char));
                if (opt->userId == NULL) {
                    return HITLS_APP_MEM_ALLOC_FAIL;
                }
                memcpy(opt->userId, val, strlen(val));
                break;
            case HITLS_APP_OPT_SIGN_DIGEST:
                opt->digestAlg = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_SIGN_PKEYALG:
                opt->pkeyAlgStr = HITLS_APP_OptGetValueStr(); break;
            default:
                AppPrintError("sign: Unknown option. Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
        }
    }
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\nsign: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    opt->pkeyAlg = ParsePkeyAlg(opt->pkeyAlgStr);
    if (opt->pkeyAlg == PKEY_ALG_UNKNOWN) {
        AppPrintError("sign: Please specify -pkeyalg {sm2|ecdsa}.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (opt->digestAlg == NULL) {
        opt->digestAlg = DefaultDigestForAlg(opt->pkeyAlg);
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ReadInputFile(const char *file, uint8_t **buf, uint32_t *len)
{
    int32_t ret = 0;
    if (file == NULL) {
        
        
        uint64_t readLen = 0;
        ret = HITLS_APP_ReadFileOrStdin(buf, &readLen, file, UINT32_MAX, "sign");
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        if (readLen > UINT32_MAX) {
            BSL_SAL_FREE(*buf);
            *buf = NULL;
            return HITLS_APP_UIO_FAIL;
        }
        *len = (uint32_t)readLen;
        return HITLS_APP_SUCCESS;
    } else {
        ret = BSL_SAL_ReadFile(file, buf, len);
        return (ret == BSL_SUCCESS) ? HITLS_APP_SUCCESS : HITLS_APP_UIO_FAIL;
    }
}

static int32_t ExpectedPkeyIdSign(PkeyAlgType alg)
{
    switch (alg) {
        case PKEY_ALG_SM2:   return CRYPT_PKEY_SM2;
        case PKEY_ALG_ECDSA: return CRYPT_PKEY_ECDSA;
        default:             return -1;
    }
}

static int32_t HandleSignMode(SignOpt *opt, int32_t mdType)
{
    uint8_t *msg = NULL;
    uint32_t msgLen = 0;
    int32_t ret = ReadInputFile(opt->inFile, &msg, &msgLen);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    char *passin = NULL;
    CRYPT_EAL_PkeyCtx *prv = HITLS_APP_ProviderLoadPrvKey(
        APP_GetCurrent_LibCtx(), "provider=default", opt->keyFile, BSL_FORMAT_PEM, &passin);
    if (!prv) {
        BSL_SAL_FREE(msg);
        return HITLS_APP_UIO_FAIL;
    }

    
    int32_t expected = ExpectedPkeyId_Sign(opt->pkeyAlg);
    if (expected < 0 || CRYPT_EAL_PkeyGetId(prv) != (uint32_t)expected) {
        AppPrintError("sign: key type does not match -pkeyalg.\n");
        CRYPT_EAL_PkeyFreeCtx(prv);
        BSL_SAL_FREE(msg);
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (opt->pkeyAlg == PKEY_ALG_SM2) {
        ret = CRYPT_EAL_PkeyCtrl(prv, CRYPT_CTRL_SET_SM2_USER_ID, opt->userId, strlen(opt->userId));
    }

    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Failed to set SM2 User ID.\n", ret);
        CRYPT_EAL_PkeyFreeCtx(prv);
        BSL_SAL_FREE(msg);
        return HITLS_APP_CRYPTO_FAIL;
    }

    uint8_t signBuf[1024] = {0};
    uint32_t signLen = sizeof(signBuf);
    int32_t signRet = CRYPT_EAL_PkeySign(prv, mdType, msg, msgLen, signBuf, &signLen);
    if (signRet != CRYPT_SUCCESS) {
        AppPrintError("sign: Signing failed.\n");
        CRYPT_EAL_PkeyFreeCtx(prv);
        BSL_SAL_FREE(msg);
        return HITLS_APP_CRYPTO_FAIL;
    }

    
    
    BSL_UIO *outUio = HITLS_APP_UioOpen(opt->outFile, 'w', opt->outFile != NULL ? 1 : 0);
    if (!outUio) {
        AppPrintError("sign: Failed to open output file.\n");
        CRYPT_EAL_PkeyFreeCtx(prv);
        BSL_SAL_FREE(msg);
        return HITLS_APP_UIO_FAIL;
    }

    
    ret = HITLS_APP_OptWriteUio(outUio, signBuf, signLen, HITLS_APP_FORMAT_TEXT);
    BSL_UIO_Free(outUio);
    if (ret != HITLS_APP_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(prv);
        BSL_SAL_FREE(msg);
        return ret;
    }
    CRYPT_EAL_PkeyFreeCtx(prv);
    BSL_SAL_FREE(msg);
    return HITLS_APP_SUCCESS;
}

static int32_t HandleVerifyMode(SignOpt *opt, int32_t mdType)
{
    uint8_t *msg = NULL;
    uint8_t *sig = NULL;
    uint32_t msgLen = 0;
    uint32_t sigLen = 0;
    int32_t ret = ReadInputFile(opt->inFile, &msg, &msgLen);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = ReadInputFile(opt->sigFile, &sig, &sigLen);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_FREE(msg);
        return ret;
    }

    uint8_t *pubData = NULL;
    uint32_t pubDataLen = 0;
    if (BSL_SAL_ReadFile(opt->pubkeyFile, &pubData, &pubDataLen) != BSL_SUCCESS) {
        AppPrintError("sign: Failed to read public key file.\n");
        BSL_SAL_FREE(msg);
        BSL_SAL_FREE(sig);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_Buffer pubEncode = {pubData, pubDataLen};
    CRYPT_EAL_PkeyCtx *pub = NULL;
    ret = CRYPT_EAL_ProviderDecodeBuffKey(
        APP_GetCurrent_LibCtx(), "provider=default",
        BSL_CID_UNKNOWN, "PEM", NULL, &pubEncode, NULL, &pub);
    BSL_SAL_FREE(pubData);
    if (ret != CRYPT_SUCCESS || pub == NULL) {
        AppPrintError("sign: Failed to load public key.\n");
        BSL_SAL_FREE(msg);
        BSL_SAL_FREE(sig);
        return HITLS_APP_UIO_FAIL;
    }

    int32_t expectedPub = ExpectedPkeyId_Sign(opt->pkeyAlg);
    if (expectedPub < 0 || CRYPT_EAL_PkeyGetId(pub) != (uint32_t)expectedPub) {
        AppPrintError("sign: key type does not match -pkeyalg.\n");
        CRYPT_EAL_PkeyFreeCtx(pub);
        BSL_SAL_FREE(msg);
        BSL_SAL_FREE(sig);
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (opt->pkeyAlg == PKEY_ALG_SM2) {
        ret = CRYPT_EAL_PkeyCtrl(pub, CRYPT_CTRL_SET_SM2_USER_ID, opt->userId, strlen(opt->userId));
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("Failed to set SM2 User ID.\n", ret);
            CRYPT_EAL_PkeyFreeCtx(pub);
            BSL_SAL_FREE(msg);
            BSL_SAL_FREE(sig);
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    ret = CRYPT_EAL_PkeyVerify(pub, mdType, msg, msgLen, sig, sigLen);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("sign: Verification failed.\n");
        ret = HITLS_APP_CRYPTO_FAIL;
    } else {
        AppPrintError("sign: Verification OK.\n");
    }
    CRYPT_EAL_PkeyFreeCtx(pub);
    BSL_SAL_FREE(msg);
    BSL_SAL_FREE(sig);
    return ret;
}

int32_t HITLS_SignMain(int argc, char *argv[])
{
    int32_t mainRet = HITLS_APP_SUCCESS;
    SignOpt opt = {0};

    AppProvider appProvider = {"default", NULL, "provider=default"};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
#endif

    
    static const char *defaultUserId = "1234567812345678";
    opt.userId = (char *)BSL_SAL_Calloc(strlen(defaultUserId) + 1, sizeof(char));
    if (opt.userId == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    memcpy(opt.userId, defaultUserId, strlen(defaultUserId));

    opt.digestAlg = NULL;
    opt.pkeyAlg = PKEY_ALG_UNKNOWN;

    do {
        mainRet = HITLS_APP_OptBegin(argc, argv, g_signOpts);
        if (mainRet != HITLS_APP_SUCCESS) {
            HITLS_APP_OptEnd();
            AppPrintError("error in opt begin.\n");
            break;
        }
        mainRet = ParseSignOpt(&opt);
        if (mainRet != HITLS_APP_SUCCESS) {
            HITLS_APP_OptEnd();
            break;
        }
        HITLS_APP_OptEnd();

        int32_t mdType = MapDigestId(opt.digestAlg);
        if (mdType < 0) {
            AppPrintError("sign: Unsupported digest algorithm.\n");
            mainRet = HITLS_APP_OPT_VALUE_INVALID;
            break;
        }
        if (!opt.verifyMode) {
            if (!opt.keyFile) {
                AppPrintError("sign: No private key file specified.\n");
                mainRet = HITLS_APP_OPT_VALUE_INVALID;
                break;
            }
        } else {
            if (!opt.pubkeyFile || !opt.sigFile) {
                AppPrintError("sign: No public key or signature file specified.\n");
                mainRet = HITLS_APP_OPT_VALUE_INVALID;
                break;
            }
        }

        if (opt.inFile != NULL) {
            uint8_t *tmpBuf = NULL;
            uint32_t tmpLen = 0;
            if (BSL_SAL_ReadFile(opt.inFile, &tmpBuf, &tmpLen) != BSL_SUCCESS) {
                AppPrintError("sign: Failed to read input file.\n");
                mainRet = HITLS_APP_UIO_FAIL;
                break;
            }
            BSL_SAL_FREE(tmpBuf);
        }

        mainRet = HITLS_APP_Init(&initParam);
        if (mainRet != HITLS_APP_SUCCESS) {
            break;
        }

        mainRet = opt.verifyMode ?
            HandleVerifyMode(&opt, mdType) :
            HandleSignMode(&opt, mdType);
    } while (0);
    HITLS_APP_Deinit(&initParam, mainRet);
    BSL_SAL_FREE(opt.userId);
    return mainRet;
}
