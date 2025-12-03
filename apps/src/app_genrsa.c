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
#include "app_genrsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <termios.h>
#include <unistd.h>
#include <securec.h>
#include <limits.h>
#include "bsl_ui.h"
#include "bsl_uio.h"
#include "app_utils.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_errno.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_eal_codecs.h"

typedef enum {
    HITLS_APP_OPT_NUMBITS = 0,
    HITLS_APP_OPT_CIPHER = 2,
    HITLS_APP_OPT_OUT_FILE,
} HITLSOptType;

typedef struct {
    char *outFile;
    long numBits; // Indicates the length of the private key entered by the user.
    int32_t cipherId; // Indicates the symmetric encryption algorithm ID entered by the user.
} GenrsaInOpt;

const HITLS_CmdOption g_genrsaOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"cipher", HITLS_APP_OPT_CIPHER, HITLS_APP_OPT_VALUETYPE_STRING, "Secret key cryptography"},
    {"out", HITLS_APP_OPT_OUT_FILE, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output the rsa key to specified file"},
    {"numbits", HITLS_APP_OPT_NUMBITS, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "RSA key length, command line tail value"},
    {NULL, 0, 0, NULL}
};

uint8_t g_e[] = {0x01, 0x00, 0x01}; // Default E value

const uint32_t g_numBitsArray[] = {1024, 2048, 3072, 4096};

const HITLS_APPAlgList g_IdList[] = {
    {CRYPT_CIPHER_AES128_CBC, "aes128-cbc"},
    {CRYPT_CIPHER_AES192_CBC, "aes192-cbc"},
    {CRYPT_CIPHER_AES256_CBC, "aes256-cbc"},
    {CRYPT_CIPHER_AES128_XTS, "aes128-xts"},
    {CRYPT_CIPHER_AES256_XTS, "aes256-xts"},
    {CRYPT_CIPHER_SM4_XTS, "sm4-xts"},
    {CRYPT_CIPHER_SM4_CBC, "sm4-cbc"},
    {CRYPT_CIPHER_SM4_CTR, "sm4-ctr"},
    {CRYPT_CIPHER_SM4_CFB, "sm4-cfb"},
    {CRYPT_CIPHER_SM4_OFB, "sm4-ofb"},
    {CRYPT_CIPHER_AES128_CFB, "aes128-cfb"},
    {CRYPT_CIPHER_AES192_CFB, "aes192-cfb"},
    {CRYPT_CIPHER_AES256_CFB, "aes256-cfb"},
    {CRYPT_CIPHER_AES128_OFB, "aes128-ofb"},
    {CRYPT_CIPHER_AES192_OFB, "aes192-ofb"},
    {CRYPT_CIPHER_AES256_OFB, "aes256-ofb"},
};

static void PrintAlgList(void)
{
    AppPrintError("The current version supports only the following Pkey algorithms:\n");
    for (size_t i = 0; i < sizeof(g_IdList) / sizeof(g_IdList[0]); i++) {
        AppPrintError("%-19s", g_IdList[i].algName);
        // Four algorithm names are displayed in each row.
        if ((i + 1) % REC_ALG_NUM_EACHLINE == 0 && i != sizeof(g_IdList) - 1) {
            AppPrintError("\n");
        }
    }
    AppPrintError("\n");
    return;
}

static int32_t GetAlgId(const char *name)
{
    for (size_t i = 0; i < sizeof(g_IdList) / sizeof(g_IdList[0]); i++) {
        if (strcmp(g_IdList[i].algName, name) == 0) {
            return g_IdList[i].id;
        }
    }
    (void)PrintAlgList();
    return -1;
}

int32_t HITLS_APP_Passwd(char *buf, int32_t bufMaxLen, int32_t flag, void *userdata)
{
    int32_t errLen = -1;
    if (buf == NULL) {
        return errLen;
    }
    int32_t cbRet = HITLS_APP_SUCCESS;
    uint32_t bufLen = bufMaxLen;
    BSL_UI_ReadPwdParam param = {"password", NULL, flag};
    if (userdata == NULL) {
        cbRet = BSL_UI_ReadPwdUtil(&param, buf, &bufLen, HITLS_APP_DefaultPassCB, NULL);
        if (cbRet == BSL_UI_READ_BUFF_TOO_LONG || cbRet == BSL_UI_READ_LEN_TOO_SHORT) {
            (void)memset_s(buf, bufMaxLen, 0, bufMaxLen);
            HITLS_APP_PrintPassErrlog();
            return errLen;
        }
        if (cbRet != BSL_SUCCESS) {
            (void)memset_s(buf, bufMaxLen, 0, bufMaxLen);
            return errLen;
        }
        bufLen -= 1;
        buf[bufLen] = '\0';
        cbRet = HITLS_APP_CheckPasswd((uint8_t *)buf, bufLen);
        if (cbRet != HITLS_APP_SUCCESS) {
            (void)memset_s(buf, bufMaxLen, 0, bufMaxLen);
            return errLen;
        }
    } else if (userdata != NULL) {
        bufLen = strlen(userdata);
        if (bufLen > APP_MAX_PASS_LENGTH) {
            HITLS_APP_PrintPassErrlog();
            return errLen;
        }
        cbRet = HITLS_APP_CheckPasswd((uint8_t *)userdata, bufLen);
        if (cbRet != HITLS_APP_SUCCESS) {
            return errLen;
        }
        if (strncpy_s(buf, bufMaxLen, (char *)userdata, bufLen) != EOK) {
            (void)memset_s(buf, bufMaxLen, 0, bufMaxLen);
            return errLen;
        }
    }
    return bufLen;
}

static int32_t HandleOpt(GenrsaInOpt *opt)
{
    int32_t optType;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_EOF:
                break;
            case HITLS_APP_OPT_ERR:
                AppPrintError("genrsa: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_genrsaOpts);
                return HITLS_APP_HELP;
            case HITLS_APP_OPT_CIPHER:
                if ((opt->cipherId = GetAlgId(HITLS_APP_OptGetValueStr())) == -1) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_OUT_FILE:
                opt->outFile = HITLS_APP_OptGetValueStr();
                break;
            default:
                break;
        }
    }
    // Obtains the value of the last digit numbits.
    int32_t restOptNum = HITLS_APP_GetRestOptNum();
    if (restOptNum == 1) {
        char **numbits = HITLS_APP_GetRestOpt();
        if (HITLS_APP_OptGetLong(numbits[0], &opt->numBits) != HITLS_APP_SUCCESS) {
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    } else {
        if (restOptNum > 1) {
            (void)AppPrintError("Extra arguments given.\n");
        } else {
            (void)AppPrintError("The command is incorrectly used.\n");
        }
        AppPrintError("genrsa: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static bool IsNumBitsValid(long num)
{
    for (size_t i = 0; i < sizeof(g_numBitsArray) / sizeof(g_numBitsArray[0]); i++) {
        if (num == g_numBitsArray[i]) {
            return true;
        }
    }
    return false;
}

static int32_t CheckPara(GenrsaInOpt *opt, BSL_UIO *outUio)
{
    if (opt->cipherId == -1) {
        AppPrintError("The command is incorrectly used.\n");
        AppPrintError("genrsa: Use -help for summary.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    // Check whether the RSA key length (in bits) of the private key complies with the specifications.
    // The length must be greater than or equal to 1024.
    if (!IsNumBitsValid(opt->numBits)) {
        AppPrintError("Your RSA key length is %ld.\n", opt->numBits);
        AppPrintError("The RSA key length is error, supporting 1024、2048、3072、4096.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    // Obtains the post-value of the OUT option. If there is no post-value or this option, stdout.
    if (opt->outFile == NULL) {
        if (BSL_UIO_Ctrl(outUio, BSL_UIO_FILE_PTR, 0, (void *)stdout) != BSL_SUCCESS) {
            AppPrintError("Failed to set stdout mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        // User input file path, which is bound to the output file.
        if (strlen(opt->outFile) >= PATH_MAX || strlen(opt->outFile) == 0) {
            AppPrintError("The length of outfile error, range is (0, 4096].\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (BSL_UIO_Ctrl(outUio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, opt->outFile) != BSL_SUCCESS) {
            AppPrintError("Failed to set outfile mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    }

    return HITLS_APP_SUCCESS;
}

static CRYPT_EAL_PkeyPara *PkeyNewRsaPara(uint8_t *e, uint32_t eLen, uint32_t bits)
{
    CRYPT_EAL_PkeyPara *para = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyPara));
    if (para == NULL) {
        return NULL;
    }

    para->id = CRYPT_PKEY_RSA;
    para->para.rsaPara.bits = bits;
    para->para.rsaPara.e = e;
    para->para.rsaPara.eLen = eLen;

    return para;
}

static int32_t HandlePkey(GenrsaInOpt *opt, char *resBuf, uint32_t bufLen)
{
    int32_t ret = HITLS_APP_SUCCESS;
    // Setting the Entropy Source
    (void)CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default");
    if (pkey == NULL) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_PkeyPara *pkeyParam = NULL;
    pkeyParam = PkeyNewRsaPara(g_e, sizeof(g_e), opt->numBits);
    if (pkeyParam == NULL) {
        ret = HITLS_APP_MEM_ALLOC_FAIL;
        goto hpEnd;
    }
    if (CRYPT_EAL_PkeySetPara(pkey, pkeyParam) != CRYPT_SUCCESS) {
        ret = HITLS_APP_CRYPTO_FAIL;
        goto hpEnd;
    }
    if (CRYPT_EAL_PkeyGen(pkey) != CRYPT_SUCCESS) {
        ret = HITLS_APP_CRYPTO_FAIL;
        goto hpEnd;
    }
    char pwd[APP_MAX_PASS_LENGTH + 1] = {0};
    int32_t pwdLen = HITLS_APP_Passwd(pwd, APP_MAX_PASS_LENGTH + 1, 1, NULL);
    if (pwdLen == -1) {
        ret = HITLS_APP_PASSWD_FAIL;
        goto hpEnd;
    }
    CRYPT_Pbkdf2Param pbkdfParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA1,
        opt->cipherId, 16, (uint8_t *)pwd, pwdLen, 2048};
    CRYPT_EncodeParam encodeParam = {CRYPT_DERIVE_PBKDF2, &pbkdfParam};
    BSL_Buffer encode = {0};
    ret = CRYPT_EAL_EncodeBuffKey(pkey, &encodeParam, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_ENCRYPT, &encode);
    (void)memset_s(pwd, APP_MAX_PASS_LENGTH, 0, APP_MAX_PASS_LENGTH);
    if (ret != CRYPT_SUCCESS) {
        (void)AppPrintError("Encode failed.\n");
        ret = HITLS_APP_ENCODE_FAIL;
        goto hpEnd;
    }
    if (memcpy_s(resBuf, bufLen, encode.data, encode.dataLen) != EOK) {
        ret = HITLS_APP_SECUREC_FAIL;
    }
    BSL_SAL_FREE(encode.data);
hpEnd:
    CRYPT_EAL_RandDeinitEx(NULL);
    BSL_SAL_ClearFree(pkeyParam, sizeof(CRYPT_EAL_PkeyPara));
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

int32_t HITLS_GenRSAMain(int argc, char *argv[])
{
    GenrsaInOpt opt = {NULL, -1, -1};
    BSL_UIO *outUio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (outUio == NULL) {
        AppPrintError("Failed to create the output UIO.\n");
        return HITLS_APP_UIO_FAIL;
    }
    int32_t ret = HITLS_APP_SUCCESS;
    if ((ret = HITLS_APP_OptBegin(argc, argv, g_genrsaOpts)) != HITLS_APP_SUCCESS) {
        AppPrintError("error in opt begin.\n");
        goto GenRsaEnd;
    }
    if ((ret = HandleOpt(&opt)) != HITLS_APP_SUCCESS) {
        goto GenRsaEnd;
    }
    if ((ret = CheckPara(&opt, outUio)) != HITLS_APP_SUCCESS) {
        goto GenRsaEnd;
    }
    char resBuf[REC_MAX_PEM_FILELEN] = {0};
    uint32_t bufLen = sizeof(resBuf);
    uint32_t writeLen = 0;
    if ((ret = HandlePkey(&opt, resBuf, bufLen)) != HITLS_APP_SUCCESS) {
        goto GenRsaEnd;
    }
    if (BSL_UIO_Write(outUio, resBuf, strlen(resBuf), &writeLen) != BSL_SUCCESS || writeLen == 0) {
        ret = HITLS_APP_UIO_FAIL;
        goto GenRsaEnd;
    }
    ret = HITLS_APP_SUCCESS;
GenRsaEnd:
    if (opt.outFile != NULL) {
        BSL_UIO_SetIsUnderlyingClosedByUio(outUio, true);
    }
    BSL_UIO_Free(outUio);
    HITLS_APP_OptEnd();
    return ret;
}
