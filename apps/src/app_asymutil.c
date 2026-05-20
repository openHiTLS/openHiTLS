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
#include "app_asymutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include "app_utils.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_provider.h"
#include "app_sm.h"
#include "app_keymgmt.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "bsl_ui.h"
#include "bsl_errno.h"
#include "bsl_pem_internal.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_codecs.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "sal_file.h"
#include "ui_type.h"

#define HITLS_APP_ENC_MAX_PARAM_NUM 5
#define ALG_NAME_WIDTH     19
#define ALG_PER_LINE        4
#define CIPHER_NAME_WIDTH  19
#define CIPHER_PER_LINE     4
#define MAX_BLOCK_SIZE 4096

typedef enum {
    HITLS_APP_OPT_PKEY_ALG = 2,
    HITLS_APP_OPT_PASSWORD,
    HITLS_APP_OPT_KEYLEN,
    HITLS_APP_OPT_CIPHER_ALG,
    HITLS_APP_OPT_IN_FILE,
    HITLS_APP_OPT_OUT_FILE,
    HITLS_APP_OPT_DEC,
    HITLS_APP_OPT_ENC,
    HITLS_APP_OPT_VERIFY,
    HITLS_APP_OPT_SIGN,
    HITLS_APP_OPT_MD,
    HITLS_APP_OPT_PASSFILE,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLS_OptType;

static const HITLS_CmdOption g_asymOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"pkeyalg", HITLS_APP_OPT_PKEY_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "pkey algorthm"},
    {"keylen", HITLS_APP_OPT_KEYLEN, HITLS_APP_OPT_VALUETYPE_STRING, "keylen"},

    {"cipher", HITLS_APP_OPT_CIPHER_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "cipher algorithm"},
    {"password", HITLS_APP_OPT_PASSWORD, HITLS_APP_OPT_VALUETYPE_STRING, "the key of private key"},
    
    {"in", HITLS_APP_OPT_IN_FILE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file"},
    {"out", HITLS_APP_OPT_OUT_FILE, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"passfile", HITLS_APP_OPT_PASSFILE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Passphrase source, such as stdin ,file etc"},

    {"dec", HITLS_APP_OPT_DEC, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Decryption operation"},
    {"enc", HITLS_APP_OPT_ENC, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Encryption operation"},
    {"verify", HITLS_APP_OPT_VERIFY, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Verify operation"},
    {"sign", HITLS_APP_OPT_SIGN, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Sign operation"},

    {"md", HITLS_APP_OPT_MD, HITLS_APP_OPT_VALUETYPE_STRING, "Specified hash algorthm"},
    
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {NULL}
};

static const HITLS_AsymAlgList g_pkeyAlgList[] = {
    {CRYPT_PKEY_DSA,       "dsa"},
    {CRYPT_PKEY_ED25519,   "ed25519"},
    {CRYPT_PKEY_X25519,    "x25519"},
    {CRYPT_PKEY_RSA,       "rsa"},
    {CRYPT_PKEY_DH,        "dh"},
    {CRYPT_PKEY_ECDSA,     "ecdsa"},
    {CRYPT_PKEY_ECDH,      "ecdh"},
    {CRYPT_PKEY_SM2,       "sm2"},
    {CRYPT_PKEY_PAILLIER,  "paillier"},
    {CRYPT_PKEY_ELGAMAL,   "elgamal"},
    {CRYPT_PKEY_SLH_DSA,   "slh_dsa"},
    {CRYPT_PKEY_ML_KEM,    "ml_kem"},
    {CRYPT_PKEY_ML_DSA,    "ml_dsa"},
    {CRYPT_PKEY_HYBRID_KEM, "hybrid_kem"},
    {CRYPT_PKEY_XMSS,      "xmss"},
};

static const HITLS_CipherAlgList1 g_cIdList[] = {
    {CRYPT_CIPHER_AES128_CBC, "aes128_cbc"},
    {CRYPT_CIPHER_AES192_CBC, "aes192_cbc"},
    {CRYPT_CIPHER_AES256_CBC, "aes256_cbc"},
    {CRYPT_CIPHER_AES128_CTR, "aes128_ctr"},
    {CRYPT_CIPHER_AES192_CTR, "aes192_ctr"},
    {CRYPT_CIPHER_AES256_CTR, "aes256_ctr"},
    {CRYPT_CIPHER_AES128_ECB, "aes128_ecb"},
    {CRYPT_CIPHER_AES192_ECB, "aes192_ecb"},
    {CRYPT_CIPHER_AES256_ECB, "aes256_ecb"},
    {CRYPT_CIPHER_AES128_XTS, "aes128_xts"},
    {CRYPT_CIPHER_AES256_XTS, "aes256_xts"},
    {CRYPT_CIPHER_AES128_GCM, "aes128_gcm"},
    {CRYPT_CIPHER_AES192_GCM, "aes192_gcm"},
    {CRYPT_CIPHER_AES256_GCM, "aes256_gcm"},
    {CRYPT_CIPHER_CHACHA20_POLY1305, "chacha20_poly1305"},
    {CRYPT_CIPHER_SM4_CBC, "sm4_cbc"},
    {CRYPT_CIPHER_SM4_ECB, "sm4_ecb"},
    {CRYPT_CIPHER_SM4_CTR, "sm4_ctr"},
    {CRYPT_CIPHER_SM4_GCM, "sm4_gcm"},
    {CRYPT_CIPHER_SM4_CFB, "sm4_cfb"},
    {CRYPT_CIPHER_SM4_OFB, "sm4_ofb"},
    {CRYPT_CIPHER_SM4_XTS, "sm4_xts"},
    {CRYPT_CIPHER_AES128_CFB, "aes128_cfb"},
    {CRYPT_CIPHER_AES192_CFB, "aes192_cfb"},
    {CRYPT_CIPHER_AES256_CFB, "aes256_cfb"},
    {CRYPT_CIPHER_AES128_OFB, "aes128_ofb"},
    {CRYPT_CIPHER_AES192_OFB, "aes192_ofb"},
    {CRYPT_CIPHER_AES256_OFB, "aes256_ofb"},
};

static const uint32_t CIPHER_IS_SIG[] = {
    CRYPT_PKEY_DSA,
    CRYPT_PKEY_ECDSA,
    CRYPT_PKEY_ED25519,
    CRYPT_PKEY_XMSS,
    CRYPT_PKEY_SLH_DSA,
    CRYPT_PKEY_ML_DSA,
    
};

static const uint32_t CIPHER_IS_ENC[] = {
    CRYPT_PKEY_RSA,
    
    
    
};

typedef struct {
    char *inFilePath;
    BSL_ParseFormat inFormat;
    char *passInArg;
    bool pubin;
} InputKeyPara;

typedef struct {
    long keyLen;

    char *pass;
    uint32_t passLen;
    unsigned char *salt;
    uint32_t saltLen;
    unsigned char *dKey;
    uint32_t dKeyLen;
    
    CRYPT_EAL_PkeyCtx *ctx;
    InputKeyPara inPara;
} AsymKeyParam;

typedef struct {
    BSL_UIO *rpUio;
    BSL_UIO *rUio;
    BSL_UIO *wUio;
} AsymUio;

typedef struct {
    uint32_t version;

    char *inFile;
    char *outFile;
    char *passFile;

    int32_t pkeyAlgId;
    int32_t cipherId;
    int32_t mdId;
    int32_t asymtag;

    uint32_t iter;

    AsymKeyParam *keySet;

    uint32_t MaxInputLen;
    AsymUio *asymUio;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} AsymCmdOpt;

typedef enum {
    HITLS_ASYM_TAG_DEC    = 0,
    HITLS_ASYM_TAG_ENC    = 1,
    HITLS_ASYM_TAG_VERIFY = 2,
    HITLS_ASYM_TAG_SIGN   = 3,
} HITLS_AsymOpTag;

static int32_t GetPwdFromFile(const char *fileArg, char *tmpPass) __attribute__((unused));
static int32_t Str2HexStr(
    const unsigned char *buf,
    uint32_t bufLen,
    char *hexBuf,
    uint32_t hexBufLen
) __attribute__((unused));
static int32_t HexToStr(const char *hexBuf, unsigned char *buf) __attribute__((unused));
static int32_t Int2Hex(uint32_t num, char *hexBuf);
static uint32_t Hex2Uint(char *hexBuf, int32_t *num);
static void PrintCipherAlgList(void);
static int32_t HexAndWrite(AsymCmdOpt *asymOpt, uint32_t decData, char *buf) __attribute__((unused));
static int32_t ReadAndDec(
    AsymCmdOpt *asymOpt,
    char *hexBuf,
    uint32_t hexBufLen,
    int32_t *decData
) __attribute__((unused));
static int32_t GetPkeyAlgId(const char *name);
static int32_t GetCipherAlgId(const char *name);
static int32_t CheckPasswd(const char *passwd) __attribute__((unused));
static int32_t EncryptFromFileLoop(AsymCmdOpt *opt, uint8_t *inBuf, uint8_t *outBuf,
                                   uint32_t maxInLen, uint32_t k, uint64_t readFileLen);

static int32_t EncryptFromStdinLoop(AsymCmdOpt *opt, uint8_t *inBuf, uint8_t *outBuf,
                                    uint32_t maxInLen, uint32_t k);

static int32_t HandleOpt(AsymCmdOpt *asymOpt)
{
    int32_t asymOptType;
    while ((asymOptType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        HITLS_APP_PROV_CASES(asymOptType, asymOpt->provider);
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(asymOptType, asymOpt->smParam);
#endif
        switch (asymOptType) {
            case HITLS_APP_OPT_EOF: break;
            case HITLS_APP_OPT_ERR:
                AppPrintError("asymutil: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_asymOpts);
                return HITLS_APP_HELP;
            case HITLS_APP_OPT_KEYLEN: asymOpt->keySet->keyLen = atoi(HITLS_APP_OptGetValueStr()); break;
            case HITLS_APP_OPT_SIGN: asymOpt->asymtag = HITLS_ASYM_TAG_SIGN; break;
            case HITLS_APP_OPT_VERIFY: asymOpt->asymtag = HITLS_ASYM_TAG_VERIFY; break;
            case HITLS_APP_OPT_ENC: asymOpt->asymtag = HITLS_ASYM_TAG_ENC; break;
            case HITLS_APP_OPT_DEC: asymOpt->asymtag = HITLS_ASYM_TAG_DEC; break;
            case HITLS_APP_OPT_IN_FILE: asymOpt->inFile = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_OUT_FILE: asymOpt->outFile = HITLS_APP_OptGetValueStr(); break;
            case HITLS_APP_OPT_PASSFILE:
                asymOpt->passFile = HITLS_APP_OptGetValueStr();
                asymOpt->keySet->inPara.inFilePath = asymOpt->passFile;
                break;
            case HITLS_APP_OPT_MD: break;
            case HITLS_APP_OPT_PKEY_ALG:
                if ((asymOpt->pkeyAlgId = GetPkeyAlgId(HITLS_APP_OptGetValueStr())) == -1) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_CIPHER_ALG:
                if (((asymOpt->cipherId = GetCipherAlgId(HITLS_APP_OptGetValueStr())) == -1) || asymOpt->asymtag != 0)
                    return HITLS_APP_OPT_VALUE_INVALID;
                break;
            case HITLS_APP_OPT_PASSWORD:
                if (asymOpt->asymtag != 0) {return HITLS_APP_OPT_VALUE_INVALID;}
                asymOpt->keySet->inPara.passInArg = HITLS_APP_OptGetValueStr();
                break;
            default:
                break;
        }
    }
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\nasymutil: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckSmParam(AsymCmdOpt *asymOpt)
{
#ifdef HITLS_APP_SM_MODE
    if (asymOpt->smParam->smTag == 1) {
        if (asymOpt->smParam->uuid == NULL) {
            AppPrintError("enc: The uuid is not specified.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (asymOpt->smParam->workPath == NULL) {
            AppPrintError("enc: The workpath is not specified.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    }
#else
    (void)asymOpt;
#endif
    return HITLS_APP_SUCCESS;
}

static int32_t CheckParam(AsymCmdOpt *asymOpt)
{
    int32_t ret = CheckSmParam(asymOpt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    
    if (asymOpt->pkeyAlgId < 0) {
        AppPrintError("The pkey algorithm is not specified.\n");
        AppPrintError("asym: Use -help for summary.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (asymOpt->keySet->keyLen <= 0) {
        AppPrintError("The keyLen is not specified.\n");
        AppPrintError("asym: Use -help for summary.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    
    
    if (asymOpt->asymtag != HITLS_ASYM_TAG_DEC && asymOpt->asymtag != HITLS_ASYM_TAG_ENC &&
        asymOpt->asymtag != HITLS_ASYM_TAG_VERIFY && asymOpt->asymtag != HITLS_ASYM_TAG_SIGN) {
        AppPrintError("You have not entered the -enc, -dec, -sign, -verify option.\n");
        AppPrintError("asym: Use -help for summary.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    
    if (asymOpt->iter == 0) {
        asymOpt->iter = REC_ITERATION_TIMES;
    }
    if (asymOpt->mdId < 0) {
        asymOpt->mdId = CRYPT_MAC_HMAC_SHA256;
    }

    if (asymOpt->inFile != NULL && strlen(asymOpt->inFile) > REC_MAX_FILENAME_LENGTH) {
        AppPrintError("The input file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (asymOpt->outFile != NULL && strlen(asymOpt->outFile) > REC_MAX_FILENAME_LENGTH) {
        AppPrintError("The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (asymOpt->passFile != NULL && strlen(asymOpt->passFile) > REC_MAX_FILENAME_LENGTH) {
        AppPrintError("The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    
    return HITLS_APP_SUCCESS;
}

static int32_t HandleIO(AsymCmdOpt *asymOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    if (asymOpt->inFile == NULL) {
        asymOpt->asymUio->rUio = HITLS_APP_UioOpen(NULL, 'r', 1);
        if (asymOpt->asymUio->rUio == NULL) {
            AppPrintError("Failed to open the stdin.\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        
        asymOpt->asymUio->rUio = BSL_UIO_New(BSL_UIO_FileMethod());
        if (BSL_UIO_Ctrl(asymOpt->asymUio->rUio,
            BSL_UIO_FILE_OPEN,
            BSL_UIO_FILE_READ,
            asymOpt->inFile) != BSL_SUCCESS) {
            AppPrintError("Failed to set infile mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
        if (asymOpt->asymUio->rUio == NULL) {
            AppPrintError("Sorry, the file content fails to be read. Please check the file path.\n");
            return HITLS_APP_UIO_FAIL;
        }
    }
    
    
    if (asymOpt->outFile == NULL) {
        asymOpt->asymUio->wUio = BSL_UIO_New(BSL_UIO_FileMethod());
        if (BSL_UIO_Ctrl(asymOpt->asymUio->wUio, BSL_UIO_FILE_PTR, 0, (void *)stdout) != BSL_SUCCESS) {
            AppPrintError("Failed to set stdout mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        
        asymOpt->asymUio->wUio = BSL_UIO_New(BSL_UIO_FileMethod());
        ret = BSL_UIO_Ctrl(asymOpt->asymUio->wUio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, asymOpt->outFile);
        if (ret != BSL_SUCCESS || chmod(asymOpt->outFile, S_IRUSR | S_IWUSR) != 0) {
            AppPrintError("Failed to set outfile mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    }
    if (asymOpt->asymUio->wUio == NULL) {
        AppPrintError("Failed to create the output pipeline.\n");
        return HITLS_APP_UIO_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static void FreeEnc(AsymCmdOpt *asymOpt)
{
    if (asymOpt->keySet->pass != NULL) {
        BSL_SAL_ClearFree(asymOpt->keySet->pass, asymOpt->keySet->passLen);
    }
    if (asymOpt->keySet->dKey != NULL) {
        BSL_SAL_ClearFree(asymOpt->keySet->dKey, asymOpt->keySet->dKeyLen);
    }
    if (asymOpt->keySet->salt != NULL) {
        BSL_SAL_ClearFree(asymOpt->keySet->salt, asymOpt->keySet->saltLen);
    }
    if (asymOpt->keySet->ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(asymOpt->keySet->ctx);
    }
    if (asymOpt->asymUio->rUio != NULL) {
        if (asymOpt->inFile != NULL) {
            BSL_UIO_SetIsUnderlyingClosedByUio(asymOpt->asymUio->rUio, true);
        }
        BSL_UIO_Free(asymOpt->asymUio->rUio);
    }
    if (asymOpt->asymUio->wUio != NULL) {
        if (asymOpt->outFile != NULL) {
            BSL_UIO_SetIsUnderlyingClosedByUio(asymOpt->asymUio->wUio, true);
        }
        BSL_UIO_Free(asymOpt->asymUio->wUio);
    }

    return;
}

static int32_t ApplyForSpace(AsymCmdOpt *asymOpt)
{
    if (asymOpt == NULL || asymOpt->keySet == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    asymOpt->keySet->pass = (char *)BSL_SAL_Calloc(APP_MAX_PASS_LENGTH + 1, sizeof(char));
    if (asymOpt->keySet->pass == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    asymOpt->keySet->salt = (unsigned char *)BSL_SAL_Calloc(REC_SALT_LEN + 1, sizeof(unsigned char));
    if (asymOpt->keySet->salt == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    asymOpt->keySet->saltLen = REC_SALT_LEN;
    asymOpt->keySet->dKey = (unsigned char *)BSL_SAL_Calloc(REC_MAX_MAC_KEY_LEN + 1, sizeof(unsigned char));
    if (asymOpt->keySet->dKey == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    
    return HITLS_APP_SUCCESS;
}

static CRYPT_EAL_PkeyCtx *AsymProviderLoadPubKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    const char *inFilePath)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    if (BSL_SAL_ReadFile(inFilePath, &data, &dataLen) != 0) {
        AppPrintError("Failed to read public key file: %s\n", inFilePath);
        return NULL;
    }
    BSL_Buffer encode = { data, dataLen };
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    if (CRYPT_EAL_ProviderDecodeBuffKey(libCtx, attrName, BSL_CID_UNKNOWN, "PEM", NULL,
        &encode, NULL, &pkey) != CRYPT_SUCCESS) {
        BSL_SAL_Free(data);
        return NULL;
    }
    BSL_SAL_Free(data);
    return pkey;
}

static CRYPT_EAL_PkeyCtx *AsymProviderLoadPrvKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    const char *inFilePath, char **passin)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    if (BSL_SAL_ReadFile(inFilePath, &data, &dataLen) != 0) {
        AppPrintError("Failed to read private key file: %s\n", inFilePath);
        return NULL;
    }
    BSL_Buffer encode = { data, dataLen };
    uint8_t *pass = (uint8_t *)(passin != NULL ? *passin : NULL);
    uint32_t passLen = (pass != NULL) ? (uint32_t)strlen((char *)pass) : 0;
    BSL_Buffer passBuf = { pass, passLen };
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    if (CRYPT_EAL_ProviderDecodeBuffKey(libCtx, attrName, BSL_CID_UNKNOWN, "PEM", NULL,
        &encode, (passLen > 0 ? &passBuf : NULL), &pkey) != CRYPT_SUCCESS) {
        BSL_SAL_Free(data);
        return NULL;
    }
    BSL_SAL_Free(data);
    return pkey;
}

static int32_t SetRsaOaepSha256(CRYPT_EAL_PkeyCtx *ctx)
{
    int32_t padType = CRYPT_RSAES_OAEP;
    if (CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType)) != CRYPT_SUCCESS) {
        AppPrintError("%s: Failed to set rsa padding (OAEP).\n", HITLS_APP_GetProgName());
        return HITLS_APP_CRYPTO_FAIL;
    }
    int32_t hashId = CRYPT_MD_SHA256;
    BSL_Param oaep[] = {
        { CRYPT_PARAM_RSA_MD_ID,   BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0 },
        { CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0 },
        BSL_PARAM_END
    };
    if (CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0) != CRYPT_SUCCESS) {
        AppPrintError("%s: Failed to set rsa OAEP params.\n", HITLS_APP_GetProgName());
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CipherIdIsValid(uint32_t id, const uint32_t *list, uint32_t num)
{
    for (uint32_t i = 0; i < num; i++) {
        if (id == list[i]) {
            return HITLS_APP_SUCCESS;
        }
    }
    return HITLS_APP_CRYPTO_FAIL;
}

static int32_t IsSigCipher(CRYPT_CIPHER_AlgId id)
{
    return CipherIdIsValid(id, CIPHER_IS_SIG, sizeof(CIPHER_IS_SIG) / sizeof(CIPHER_IS_SIG[0]));
}

static int32_t IsEncCipher(CRYPT_CIPHER_AlgId id)
{
    return CipherIdIsValid(id, CIPHER_IS_ENC, sizeof(CIPHER_IS_ENC) / sizeof(CIPHER_IS_ENC[0]));
}

static int32_t UpdateEncLoop(AsymCmdOpt *asymOpt, uint8_t *inBuf, uint8_t *outBuf,
                             uint32_t maxInLen, uint32_t k, uint64_t readFileLen)
{
    if (readFileLen > 0) {
        return EncryptFromFileLoop(asymOpt, inBuf, outBuf, maxInLen, k, readFileLen);
    } else {
        return EncryptFromStdinLoop(asymOpt, inBuf, outBuf, maxInLen, k);
    }
}

static int32_t EncryptFromFileLoop(AsymCmdOpt *opt, uint8_t *inBuf, uint8_t *outBuf,
                                   uint32_t maxInLen, uint32_t k, uint64_t readFileLen)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint64_t remain = readFileLen;

    while (remain > 0) {
        uint32_t want = (remain > maxInLen) ? maxInLen : (uint32_t)remain;
        uint32_t got = 0;

        
        
        ret = BSL_UIO_Read(opt->asymUio->rUio, inBuf, want, &got);
        if (ret != BSL_SUCCESS || got == 0) {
            AppPrintError("Failed to read input content.\n");
            return HITLS_APP_UIO_FAIL;
        }

        uint32_t outLen = k;
        if ((ret = CRYPT_EAL_PkeyEncrypt(opt->keySet->ctx, inBuf, got, outBuf, &outLen)) != CRYPT_SUCCESS) {
            AppPrintError("Failed to encrypt a chunk.\n");
            return ret;
        }

        uint32_t wrote = 0;
        ret = BSL_UIO_Write(opt->asymUio->wUio, outBuf, outLen, &wrote);
        if (ret != BSL_SUCCESS || wrote != outLen) {
            AppPrintError("Failed to write encrypted data.\n");
            return ret;
        }

        remain -= got;
    }

    return ret;
}

    static int32_t EncryptFromStdinLoop(AsymCmdOpt *opt, uint8_t *inBuf, uint8_t *outBuf,
                                        uint32_t maxInLen, uint32_t k)
    {
        int32_t ret = HITLS_APP_SUCCESS;

        for (;;) {
            uint32_t got = 0;
            if ((ret = BSL_UIO_Read(opt->asymUio->rUio, inBuf, maxInLen, &got)) != BSL_SUCCESS) {
                AppPrintError("Failed to read from STDIN.\n");
                return ret;
            }

            if (got == 0) {
                break; 
            }

            uint32_t outLen = k;
            if ((ret = CRYPT_EAL_PkeyEncrypt(opt->keySet->ctx, inBuf, got, outBuf, &outLen)) != CRYPT_SUCCESS) {
                AppPrintError("Failed to encrypt a STDIN chunk.\n");
                return ret;
            }

            uint32_t wrote = 0;
            if ((ret = BSL_UIO_Write(opt->asymUio->wUio, outBuf, outLen, &wrote)) != BSL_SUCCESS || wrote != outLen) {
                AppPrintError("Failed to write encrypted data.\n");
                return ret;
            }
        }

        return ret;
    }

static int32_t UpdateEncFile(AsymCmdOpt *asymOpt, uint64_t readFileLen)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint32_t k = (uint32_t)(asymOpt->keySet->keyLen / 8);
    static const uint32_t SHA256_LEN = 32;
    static const uint32_t OAEP_COEFF = 2;
    static const uint32_t OAEP_CONST_2  = 2;

    if (k <= OAEP_COEFF * SHA256_LEN + OAEP_CONST_2) {
        AppPrintError("Unsupported key length for OAEP(SHA-256).\n");
        return HITLS_APP_INVALID_ARG;
    }

    const uint32_t maxInLen = k - OAEP_COEFF * SHA256_LEN - OAEP_CONST_2;

    uint8_t *inBuf  = (uint8_t *)malloc(maxInLen);
    uint8_t *outBuf = (uint8_t *)malloc(k);

    if (!inBuf || !outBuf) {
        ret = HITLS_APP_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    ret = UpdateEncLoop(asymOpt, inBuf, outBuf, maxInLen, k, readFileLen);
    if (ret != HITLS_APP_SUCCESS) {
        goto EXIT;
    }

EXIT:
    free(inBuf);
    free(outBuf);
    return ret;
}

static int32_t DoPkeyUpdateEnc(AsymCmdOpt *asymOpt, uint64_t readFileLen)
{
    asymOpt->keySet->ctx = AsymProviderLoadPubKey(APP_GetCurrent_LibCtx(),
                                                  asymOpt->provider->providerAttr,
                                                  asymOpt->keySet->inPara.inFilePath);
    if (asymOpt->keySet->ctx == NULL) {
        return HITLS_APP_LOAD_KEY_FAIL;
    }
    int32_t ret = SetRsaOaepSha256(asymOpt->keySet->ctx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    return UpdateEncFile(asymOpt, readFileLen);
}

static int32_t PreparePrivateKey(AsymCmdOpt *asymOpt)
{
    
    if (asymOpt->keySet->pass != NULL) {
        BSL_SAL_ClearFree(asymOpt->keySet->pass, APP_MAX_PASS_LENGTH + 1);
        asymOpt->keySet->pass = NULL;
        asymOpt->keySet->passLen = 0;
    }
    if (asymOpt->keySet->inPara.passInArg != NULL) {
        if (HITLS_APP_ParsePasswd(asymOpt->keySet->inPara.passInArg,
                                  &asymOpt->keySet->pass) != HITLS_APP_SUCCESS) {
            return HITLS_APP_PASSWD_FAIL;
        }
        
        asymOpt->keySet->passLen = (uint32_t)strlen(asymOpt->keySet->pass);
    } else {
        asymOpt->keySet->pass = NULL;
    }

    asymOpt->keySet->ctx = AsymProviderLoadPrvKey(
        APP_GetCurrent_LibCtx(),
        asymOpt->provider->providerAttr,
        asymOpt->keySet->inPara.inFilePath,
        &asymOpt->keySet->pass);

    if (asymOpt->keySet->ctx == NULL) {
        return HITLS_APP_LOAD_KEY_FAIL;
    }

    int32_t ret = SetRsaOaepSha256(asymOpt->keySet->ctx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
        
    if (asymOpt->keySet->keyLen == 0) {
        return HITLS_APP_INVALID_ARG;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t DoPkeyUpdateDec(AsymCmdOpt *asymOpt, uint64_t readFileLen)
{
    int32_t ret = PreparePrivateKey(asymOpt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    uint32_t k = (uint32_t)(asymOpt->keySet->keyLen / 8);
    if (k == 0 || k > MAX_BLOCK_SIZE) {
        AppPrintError("Invalid block size: %u (must be >0 and <= %u)\n", k, MAX_BLOCK_SIZE);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint8_t *inBlk  = (uint8_t *)malloc(k);
    uint8_t *outBlk = (uint8_t *)malloc(k);
    if (!inBlk || !outBlk) {
        ret = HITLS_APP_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    uint64_t remain = readFileLen;
    while (readFileLen > 0 ? remain > 0 : 1) {
        uint32_t got = 0;
        
        ret = BSL_UIO_Read(asymOpt->asymUio->rUio, inBlk, k, &got);
        if (ret != BSL_SUCCESS) {
            AppPrintError("Failed to read ciphertext.\n");
            ret = HITLS_APP_UIO_FAIL;
            goto EXIT;
        }
        if (got == 0) {
            if (readFileLen > 0 && remain > 0) {
                AppPrintError("Ciphertext ended early.\n");
                ret = HITLS_APP_UIO_FAIL;
                goto EXIT;
            }
            break;
        }
        if (got != k) {
            AppPrintError("Ciphertext size not aligned (%u).\n", k);
            ret = HITLS_APP_INVALID_ARG;
            goto EXIT;
        }
        uint32_t outLen = k;
        if ((ret = CRYPT_EAL_PkeyDecrypt(asymOpt->keySet->ctx, inBlk, got, outBlk, &outLen))
             != CRYPT_SUCCESS) {
            AppPrintError("Decryption failed.\n");
            goto EXIT;
        }
        if (outLen > 0) {
            uint32_t wrote = 0;
            if ((ret = BSL_UIO_Write(asymOpt->asymUio->wUio, outBlk, outLen, &wrote)) != BSL_SUCCESS ||
                wrote != outLen) {
                goto EXIT;
            }
        }
        if (readFileLen > 0) {
            remain -= got;
        } else if (got == 0) {
            break;
        }
    }
    
    
EXIT:
    free(inBlk);
    free(outBlk);
    return ret;
}

static int32_t DoPkeyUpdate(AsymCmdOpt *asymOpt)
{
    uint64_t readFileLen = 0;
    if (asymOpt->inFile != NULL &&
        BSL_UIO_Ctrl(asymOpt->asymUio->rUio, BSL_UIO_PENDING, sizeof(readFileLen), &readFileLen) != BSL_SUCCESS) {
        (void)AppPrintError("Failed to obtain the content length\n");
        return HITLS_APP_UIO_FAIL;
    }

    if (asymOpt->inFile == NULL) {
        AppPrintError("You have not entered the -in option. Please directly enter the file content on the terminal.\n");
    }

    int32_t updateRet = (asymOpt->asymtag == 0) ? DoPkeyUpdateDec(asymOpt, readFileLen)
                                              : DoPkeyUpdateEnc(asymOpt, readFileLen);
    if (updateRet != HITLS_APP_SUCCESS) {
        return updateRet;
    }

    return HITLS_APP_SUCCESS;
}

static int32_t EncOrDecProc(AsymCmdOpt *asymOpt)
{
#ifdef HITLS_APP_SM_MODE
    if (asymOpt->smParam->smTag == 1) {
        asymOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    }
#endif

    int32_t ret = HITLS_APP_SUCCESS;

    if ((ret = DoPkeyUpdate(asymOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandleAsym(AsymCmdOpt *asymOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    if ((ret = HandleIO(asymOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    if ((ret = ApplyForSpace(asymOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }

    if (asymOpt->asymtag == HITLS_ASYM_TAG_VERIFY || asymOpt->asymtag == HITLS_ASYM_TAG_SIGN) {
        if ((ret = IsSigCipher(asymOpt->pkeyAlgId)) != HITLS_APP_SUCCESS) {
            return ret;
        }
        
        AppPrintError("asymutil: -sign/-verify are not implemented.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (asymOpt->asymtag == HITLS_ASYM_TAG_DEC || asymOpt->asymtag == HITLS_ASYM_TAG_ENC) {
        if ((ret = IsEncCipher(asymOpt->pkeyAlgId)) != HITLS_APP_SUCCESS) {
            return ret;
        }

        if ((ret = EncOrDecProc(asymOpt)) != HITLS_APP_SUCCESS) {
            return ret;
        }
    }

    return HITLS_APP_SUCCESS;
}

static void InitAsymKeyParam(AsymKeyParam *keySet)
{
    keySet->ctx = NULL;
    keySet->dKey = NULL;
    keySet->dKeyLen = 0;
    keySet->keyLen = 0;
    keySet->pass = NULL;
    keySet->passLen = 0;
    keySet->salt = NULL;
    keySet->saltLen = 0;

    keySet->inPara.inFilePath = NULL;
    keySet->inPara.inFormat = BSL_FORMAT_PEM;
    keySet->inPara.passInArg = NULL;
    keySet->inPara.pubin = false;
}

int32_t HITLS_AsymutilMain(int argc, char *argv[])
{
    int32_t asymRet = -1;
    AsymKeyParam keySet = { };
    InitAsymKeyParam(&keySet);

    AsymUio asymUio = {NULL, NULL, NULL};
    AppProvider appProvider = {"default", NULL, "provider=default"};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    
    
    AsymCmdOpt asymOpt = {1, NULL, NULL, NULL, -1, -1, -1, -1, 0, &keySet, 0, &asymUio, &appProvider, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
    AsymCmdOpt asymOpt = {1, NULL, NULL, NULL, -1, -1, -1, -1, 0, &keySet, 0, &asymUio, &appProvider};
#endif
    if ((asymRet = HITLS_APP_OptBegin(argc, argv, g_asymOpts)) != HITLS_APP_SUCCESS) {
        AppPrintError("error in opt begin.\n");
        goto EXIT;
    }
    if ((asymRet = HandleOpt(&asymOpt)) != HITLS_APP_SUCCESS) {
        goto EXIT;
    }
    if ((asymRet = CheckParam(&asymOpt)) != HITLS_APP_SUCCESS) {
        goto EXIT;
    }
    asymRet = HITLS_APP_Init(&initParam);
    if (asymRet != HITLS_APP_SUCCESS) {
        goto EXIT;
    }
    if ((asymRet = HandleAsym(&asymOpt)) != HITLS_APP_SUCCESS) {
        goto EXIT;
    }
    asymRet = HITLS_APP_SUCCESS;
EXIT:
    HITLS_APP_Deinit(&initParam, asymRet);
    FreeEnc(&asymOpt);
    return asymRet;
}

static void PrintPkeyAlgList(void)
{
    AppPrintError("The current version supports only the following pkey algorithms:\n");
    size_t algCount = sizeof(g_pkeyAlgList) / sizeof(g_pkeyAlgList[0]);
    for (size_t i = 0; i < algCount; i++) {
        AppPrintError("%-*s", ALG_NAME_WIDTH, g_pkeyAlgList[i].keyAlgName);

        if ((i + 1) % ALG_PER_LINE == 0 && i != algCount - 1) {
            AppPrintError("\n");
        }
    }
    AppPrintError("\n");
    return;
}

static void PrintCipherAlgList(void)
{
    AppPrintError("The current version supports only the following cipher algorithms:\n");
    size_t cipherCount = sizeof(g_cIdList) / sizeof(g_cIdList[0]);

    for (size_t i = 0; i < cipherCount; i++) {
        AppPrintError("%-*s", CIPHER_NAME_WIDTH, g_cIdList[i].cipherAlgName);

        if ((i + 1) % CIPHER_PER_LINE == 0 && i != cipherCount - 1) {
            AppPrintError("\n");
        }
    }

    AppPrintError("\n");
}

static int32_t GetPkeyAlgId(const char *name)
{
    for (size_t i = 0; i < sizeof(g_pkeyAlgList) / sizeof(g_pkeyAlgList[0]); i++) {
        if (strcmp(g_pkeyAlgList[i].keyAlgName, name) == 0) {
            return g_pkeyAlgList[i].keyAlgId;
        }
    }
    PrintPkeyAlgList();
    return -1;
}

static int32_t GetCipherAlgId(const char *name)
{
    for (size_t i = 0; i < sizeof(g_cIdList) / sizeof(g_cIdList[0]); i++) {
        if (strcmp(g_cIdList[i].cipherAlgName, name) == 0) {
            return g_cIdList[i].cipherId;
        }
    }
    PrintCipherAlgList();
    return -1;
}

static int32_t GetPwdFromFile(const char *fileArg, char *tmpPass)
{
    char tmpFileArg[REC_MAX_FILENAME_LENGTH + REC_MIN_PRE_LENGTH + 1] = {0};
    size_t fileArgLen = strlen(fileArg);
    if (fileArgLen > REC_MAX_FILENAME_LENGTH + REC_MIN_PRE_LENGTH) {
        return HITLS_APP_SECUREC_FAIL;
    }
    (void)memcpy(tmpFileArg, fileArg, fileArgLen + 1);

    char *filePath = strchr(tmpFileArg, ':');
    if (filePath == NULL || *(filePath + 1) == '\0') {
        return HITLS_APP_SECUREC_FAIL;
    }
    filePath++;
    char *nextColon = strchr(filePath, ':');
    if (nextColon != NULL) {
        *nextColon = '\0';
    }

    BSL_UIO *passUio = BSL_UIO_New(BSL_UIO_FileMethod());
    char tmpPassBuf[APP_MAX_PASS_LENGTH * REC_DOUBLE] = {0};
    if (BSL_UIO_Ctrl(passUio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_READ, filePath) != BSL_SUCCESS) {
        AppPrintError("Failed to set infile mode for passwd.\n");
        BSL_UIO_SetIsUnderlyingClosedByUio(passUio, true);
        BSL_UIO_Free(passUio);
        return HITLS_APP_UIO_FAIL;
    }
    uint32_t rPassLen = 0;
    if (BSL_UIO_Read(passUio, tmpPassBuf, sizeof(tmpPassBuf), &rPassLen) != BSL_SUCCESS || rPassLen <= 0) {
        AppPrintError("Failed to read passwd from file.\n");
        BSL_UIO_SetIsUnderlyingClosedByUio(passUio, true);
        BSL_UIO_Free(passUio);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(passUio, true);
    BSL_UIO_Free(passUio);
    if (tmpPassBuf[rPassLen - 1] == '\n') {
        tmpPassBuf[rPassLen - 1] = '\0';
        rPassLen -= 1;
    }
    if (rPassLen > APP_MAX_PASS_LENGTH) {
        HITLS_APP_PrintPassErrlog();
        return HITLS_APP_PASSWD_FAIL;
    }

    if (HITLS_APP_CheckPasswd((uint8_t *)tmpPassBuf, rPassLen) != HITLS_APP_SUCCESS) {
        return HITLS_APP_PASSWD_FAIL;
    }
    size_t passLen = strlen(tmpPassBuf);
    if (passLen >= APP_MAX_PASS_LENGTH) {
        return HITLS_APP_COPY_ARGS_FAILED;
    }
    (void)memcpy(tmpPass, tmpPassBuf, passLen + 1);
    return HITLS_APP_SUCCESS;
}

static int32_t CheckPasswd(const char *passwd)
{
    int32_t passLen = strlen(passwd);
    if (passLen > APP_MAX_PASS_LENGTH) {
        HITLS_APP_PrintPassErrlog();
        return HITLS_APP_PASSWD_FAIL;
    }
    return HITLS_APP_CheckPasswd((const uint8_t *)passwd, (uint32_t)passLen);
}

static int32_t Str2HexStr(const unsigned char *buf, uint32_t bufLen, char *hexBuf, uint32_t hexBufLen)
{
    if (hexBufLen < bufLen * REC_DOUBLE + 1) {
        return HITLS_APP_INVALID_ARG;
    }
    for (uint32_t i = 0; i < bufLen; i++) {
        int ret = snprintf(hexBuf + i * REC_DOUBLE, hexBufLen - i * REC_DOUBLE, "%02x", buf[i]);
        if (ret != REC_DOUBLE) {
            AppPrintError("BSL_SAL_Calloc Failed.\n");
            return HITLS_APP_ENCODE_FAIL;
        }
    }
    hexBuf[bufLen * REC_DOUBLE] = '\0';
    return HITLS_APP_SUCCESS;
}

static int32_t HexToStr(const char *hexBuf, unsigned char *buf)
{
    int len = strlen(hexBuf) / 2;
    for (int i = 0; i < len; i++) {
        uint32_t val;
        if (sscanf(hexBuf + i * REC_DOUBLE, "%2x", &val) != 1) {
            AppPrintError("error in converting hex str to str.\n");
            return HITLS_APP_ENCODE_FAIL;
        }
        buf[i] = (unsigned char)val;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t Int2Hex(uint32_t num, char *hexBuf)
{
    int ret = snprintf(hexBuf, REC_HEX_BUF_LENGTH + 1, "%08X", num);
    if (ret != REC_HEX_BUF_LENGTH) {
        AppPrintError("error in uint to hex.\n");
        return HITLS_APP_ENCODE_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static uint32_t Hex2Uint(char *hexBuf, int32_t *num)
{
    if (hexBuf == NULL) {
        AppPrintError("No hex buffer here.\n");
        return HITLS_APP_INVALID_ARG;
    }
    char *endptr = NULL;
    *num = strtoul(hexBuf, &endptr, REC_HEX_BASE);
    return HITLS_APP_SUCCESS;
}

static int32_t HexAndWrite(AsymCmdOpt *asymOpt, uint32_t decData, char *buf)
{
    uint32_t writeLen = 0;
    if (Int2Hex(decData, buf) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    if (BSL_UIO_Write(asymOpt->asymUio->wUio, buf, REC_HEX_BUF_LENGTH, &writeLen) != BSL_SUCCESS ||
        writeLen != REC_HEX_BUF_LENGTH) {
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}
static int32_t ReadAndDec(AsymCmdOpt *asymOpt, char *hexBuf, uint32_t hexBufLen, int32_t *decData)
{
    if (hexBufLen < REC_HEX_BUF_LENGTH + 1) {
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t readLen = 0;
    if (BSL_UIO_Read(asymOpt->asymUio->rUio, hexBuf, REC_HEX_BUF_LENGTH, &readLen) != BSL_SUCCESS ||
        readLen != REC_HEX_BUF_LENGTH) {
        return HITLS_APP_UIO_FAIL;
    }
    if (Hex2Uint(hexBuf, decData) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

