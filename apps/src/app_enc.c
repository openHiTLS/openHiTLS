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
#include "app_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <securec.h>
#include "bsl_uio.h"
#include "app_utils.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_provider.h"
#include "app_sm.h"
#include "app_keymgmt.h"
#include "bsl_sal.h"
#include "bsl_ui.h"
#include "bsl_errno.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_kdf.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"

#define HITLS_APP_ENC_MAX_PARAM_NUM 5

typedef enum {
    HITLS_APP_OPT_CIPHER_ALG = 2,
    HITLS_APP_OPT_IN_FILE,
    HITLS_APP_OPT_OUT_FILE,
    HITLS_APP_OPT_DEC,
    HITLS_APP_OPT_ENC,
    HITLS_APP_OPT_MD,
    HITLS_APP_OPT_PASS,
    HITLS_APP_PROV_ENUM,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS_ENUM,
#endif
} HITLS_OptType;

static const HITLS_CmdOption g_encOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"cipher", HITLS_APP_OPT_CIPHER_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Cipher algorthm"},
    {"in", HITLS_APP_OPT_IN_FILE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file"},
    {"out", HITLS_APP_OPT_OUT_FILE, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"dec", HITLS_APP_OPT_DEC, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Encryption operation"},
    {"enc", HITLS_APP_OPT_ENC, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Decryption operation"},
    {"md", HITLS_APP_OPT_MD, HITLS_APP_OPT_VALUETYPE_STRING, "Specified digest to create a key"},
    {"pass", HITLS_APP_OPT_PASS, HITLS_APP_OPT_VALUETYPE_STRING, "Passphrase source, such as stdin ,file etc"},
    HITLS_APP_PROV_OPTIONS,
#ifdef HITLS_APP_SM_MODE
    HITLS_SM_OPTIONS,
#endif
    {NULL}
};

static const HITLS_CipherAlgList g_cIdList[] = {
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

static const HITLS_MacAlgList g_mIdList[] = {
    {CRYPT_MAC_HMAC_MD5, "md5"},
    {CRYPT_MAC_HMAC_SHA1, "sha1"},
    {CRYPT_MAC_HMAC_SHA224, "sha224"},
    {CRYPT_MAC_HMAC_SHA256, "sha256"},
    {CRYPT_MAC_HMAC_SHA384, "sha384"},
    {CRYPT_MAC_HMAC_SHA512, "sha512"},
    {CRYPT_MAC_HMAC_SM3, "sm3"},
    {CRYPT_MAC_HMAC_SHA3_224, "sha3_224"},
    {CRYPT_MAC_HMAC_SHA3_256, "sha3_256"},
    {CRYPT_MAC_HMAC_SHA3_384, "sha3_384"},
    {CRYPT_MAC_HMAC_SHA3_512, "sha3_512"}
};

static const uint32_t CIPHER_IS_BlOCK[] = {
    CRYPT_CIPHER_AES128_CBC,
    CRYPT_CIPHER_AES192_CBC,
    CRYPT_CIPHER_AES256_CBC,
    CRYPT_CIPHER_AES128_ECB,
    CRYPT_CIPHER_AES192_ECB,
    CRYPT_CIPHER_AES256_ECB,
    CRYPT_CIPHER_SM4_CBC,
    CRYPT_CIPHER_SM4_ECB,
};

static const uint32_t CIPHER_IS_XTS[] = {
    CRYPT_CIPHER_AES128_XTS,
    CRYPT_CIPHER_AES256_XTS,
    CRYPT_CIPHER_SM4_XTS,
};

typedef struct {
    char *pass;
    uint32_t passLen;
    unsigned char *salt;
    uint32_t saltLen;
    unsigned char *iv;
    uint32_t ivLen;
    unsigned char *dKey;
    uint32_t dKeyLen;
    CRYPT_EAL_CipherCtx *ctx;
    uint32_t blockSize;
} EncKeyParam;

typedef struct {
    BSL_UIO *rUio;
    BSL_UIO *wUio;
} EncUio;

typedef struct {
    uint32_t version;
    char *inFile;
    char *outFile;
    char *passOptStr; // Indicates the following value of the -pass option entered by the user.
    int32_t cipherId; // Indicates the symmetric encryption algorithm ID entered by the user.
    int32_t mdId; // Indicates the HMAC algorithm ID entered by the user.
    int32_t encTag; // Indicates the encryption/decryption flag entered by the user.
    uint32_t iter; // Indicates the number of iterations entered by the user.
    EncKeyParam *keySet;
    EncUio *encUio;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} EncCmdOpt;

static int32_t GetPwdFromFile(const char *fileArg, char *tmpPass);
static int32_t Str2HexStr(const unsigned char *buf, uint32_t bufLen, char *hexBuf, uint32_t hexBufLen);
static int32_t HexToStr(const char *hexBuf, unsigned char *buf);
static int32_t Int2Hex(uint32_t num, char *hexBuf);
static uint32_t Hex2Uint(char *hexBuf, int32_t *num);
static void PrintHMacAlgList(void);
static void PrintCipherAlgList(void);
static int32_t HexAndWrite(EncCmdOpt *encOpt, uint32_t decData, char *buf);
static int32_t ReadAndDec(EncCmdOpt *encOpt, char *hexBuf, uint32_t hexBufLen, int32_t *decData);
static int32_t GetCipherId(const char *name);
static int32_t GetHMacId(const char *mdName);
static int32_t GetPasswd(const char *arg, bool mode, char *resPass);
static int32_t CheckPasswd(const char *passwd);

// process for the ENC to receive subordinate options
static int32_t HandleOpt(EncCmdOpt *encOpt)
{
    int32_t encOptType;
    while ((encOptType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        HITLS_APP_PROV_CASES(encOptType, encOpt->provider);
#ifdef HITLS_APP_SM_MODE
        HITLS_APP_SM_CASES(encOptType, encOpt->smParam);
#endif
        switch (encOptType) {
            case HITLS_APP_OPT_EOF:
                break;
            case HITLS_APP_OPT_ERR:
                AppPrintError("enc: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_encOpts);
                return HITLS_APP_HELP;
            case HITLS_APP_OPT_ENC:
                encOpt->encTag = 1;
                break;
            case HITLS_APP_OPT_DEC:
                encOpt->encTag = 0;
                break;
            case HITLS_APP_OPT_IN_FILE:
                encOpt->inFile = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_OUT_FILE:
                encOpt->outFile = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_PASS:
                encOpt->passOptStr = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_MD:
                if ((encOpt->mdId = GetHMacId(HITLS_APP_OptGetValueStr())) == -1) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_CIPHER_ALG:
                if ((encOpt->cipherId = GetCipherId(HITLS_APP_OptGetValueStr())) == -1) {
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            default:
                break;
        }
    }
    // Obtain the number of parameters that cannot be parsed in the current version
    // and print the error information and help list.
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("enc: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckSmParam(EncCmdOpt *encOpt)
{
#ifdef HITLS_APP_SM_MODE
    if (encOpt->smParam->smTag == 1) {
        if (encOpt->smParam->uuid == NULL) {
            AppPrintError("enc: The uuid is not specified.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (encOpt->smParam->workPath == NULL) {
            AppPrintError("enc: The workpath is not specified.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    }
#else
    (void)encOpt;
#endif
    return HITLS_APP_SUCCESS;
}

// enc check the validity of option parameters
static int32_t CheckParam(EncCmdOpt *encOpt)
{
    int32_t ret = CheckSmParam(encOpt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    // if the -cipher option is not specified, an error is returned
    if (encOpt->cipherId < 0) {
        AppPrintError("The cipher algorithm is not specified.\n");
        AppPrintError("enc: Use -help for summary.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    // if the user does not specify the encryption or decryption mode,
    // an error is reported and the user is prompted to enter the following information
    if (encOpt->encTag != 1 && encOpt->encTag != 0) {
        AppPrintError("You have not entered the -enc or -dec option.\n");
        AppPrintError("enc: Use -help for summary.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    // if the number of iterations is not set, the default value is 10000
    if (encOpt->iter == 0) {
        encOpt->iter = REC_ITERATION_TIMES;
    }
    // if the user does not transfer the digest algorithm, SHA256 is used by default to generate the derived key Dkey
    if (encOpt->mdId < 0) {
        encOpt->mdId = CRYPT_MAC_HMAC_SHA256;
    }
    // determine an ivLen based on the cipher ID entered by the user
    if (CRYPT_EAL_CipherGetInfo(encOpt->cipherId, CRYPT_INFO_IV_LEN, &encOpt->keySet->ivLen) != CRYPT_SUCCESS) {
        AppPrintError("Failed to get the iv length from cipher ID.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }

    if (encOpt->inFile != NULL && strlen(encOpt->inFile) > REC_MAX_FILENAME_LENGTH) {
        AppPrintError("The input file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (encOpt->outFile != NULL && strlen(encOpt->outFile) > REC_MAX_FILENAME_LENGTH) {
        AppPrintError("The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

// enc determines the input and output paths
static int32_t HandleIO(EncCmdOpt *encOpt)
{
    // Obtain the last value of the IN option.
    // If there is no last value or this option does not exist, the standard input is used.
    // If the file fails to be read, the process ends.
    if (encOpt->inFile == NULL) {
        // User doesn't input file upload path. Read the content directly entered by the user from the standard input.
        encOpt->encUio->rUio = HITLS_APP_UioOpen(NULL, 'r', 1);
        if (encOpt->encUio->rUio == NULL) {
            AppPrintError("Failed to open the stdin.\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        // user inputs the file path and reads the content in the file from the file
        encOpt->encUio->rUio = BSL_UIO_New(BSL_UIO_FileMethod());
        if (BSL_UIO_Ctrl(encOpt->encUio->rUio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_READ, encOpt->inFile) != BSL_SUCCESS) {
            AppPrintError("Failed to set infile mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
        if (encOpt->encUio->rUio == NULL) {
            AppPrintError("Sorry, the file content fails to be read. Please check the file path.\n");
            return HITLS_APP_UIO_FAIL;
        }
    }
    // Obtain the post-value of the OUT option.
    // If there is no post-value or the option does not exist, the standard output is used.
    if (encOpt->outFile == NULL) {
        encOpt->encUio->wUio = BSL_UIO_New(BSL_UIO_FileMethod());
        if (BSL_UIO_Ctrl(encOpt->encUio->wUio, BSL_UIO_FILE_PTR, 0, (void *)stdout) != BSL_SUCCESS) {
            AppPrintError("Failed to set stdout mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        // The file path transferred by the user is bound to the output file.
        encOpt->encUio->wUio = BSL_UIO_New(BSL_UIO_FileMethod());
        if (BSL_UIO_Ctrl(encOpt->encUio->wUio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, encOpt->outFile) != BSL_SUCCESS ||
            chmod(encOpt->outFile, S_IRUSR | S_IWUSR) != 0) {
            AppPrintError("Failed to set outfile mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    }
    if (encOpt->encUio->wUio == NULL) {
        AppPrintError("Failed to create the output pipeline.\n");
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static void FreeEnc(EncCmdOpt *encOpt)
{
    if (encOpt->keySet->pass != NULL) {
        BSL_SAL_ClearFree(encOpt->keySet->pass, encOpt->keySet->passLen);
    }
    if (encOpt->keySet->dKey != NULL) {
        BSL_SAL_ClearFree(encOpt->keySet->dKey, encOpt->keySet->dKeyLen);
    }
    if (encOpt->keySet->salt != NULL) {
        BSL_SAL_ClearFree(encOpt->keySet->salt, encOpt->keySet->saltLen);
    }
    if (encOpt->keySet->iv != NULL) {
        BSL_SAL_ClearFree(encOpt->keySet->iv, encOpt->keySet->ivLen);
    }
    if (encOpt->keySet->ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(encOpt->keySet->ctx);
    }
    if (encOpt->encUio->rUio != NULL) {
        if (encOpt->inFile != NULL) {
            BSL_UIO_SetIsUnderlyingClosedByUio(encOpt->encUio->rUio, true);
        }
        BSL_UIO_Free(encOpt->encUio->rUio);
    }
    if (encOpt->encUio->wUio != NULL) {
        if (encOpt->outFile != NULL) {
            BSL_UIO_SetIsUnderlyingClosedByUio(encOpt->encUio->wUio, true);
        }
        BSL_UIO_Free(encOpt->encUio->wUio);
    }
    return;
}

static int32_t ApplyForSpace(EncCmdOpt *encOpt)
{
    if (encOpt == NULL || encOpt->keySet == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    encOpt->keySet->pass = (char *)BSL_SAL_Calloc(APP_MAX_PASS_LENGTH + 1, sizeof(char));
    if (encOpt->keySet->pass == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    encOpt->keySet->salt = (unsigned char *)BSL_SAL_Calloc(REC_SALT_LEN + 1, sizeof(unsigned char));
    if (encOpt->keySet->salt == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    encOpt->keySet->saltLen = REC_SALT_LEN;
    encOpt->keySet->iv = (unsigned char *)BSL_SAL_Calloc(REC_MAX_IV_LENGTH + 1, sizeof(unsigned char));
    if (encOpt->keySet->iv == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    encOpt->keySet->dKey = (unsigned char *)BSL_SAL_Calloc(REC_MAX_MAC_KEY_LEN + 1, sizeof(unsigned char));
    if (encOpt->keySet->dKey == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

// enc parses the password entered by the user
static int32_t HandlePasswd(EncCmdOpt *encOpt)
{
#ifdef HITLS_APP_SM_MODE
    if (encOpt->smParam->smTag == 1) {
        return HITLS_APP_SUCCESS;
    }
#endif
    // If the user enters the last value of -pass, the system parses the value directly.
    // If the user does not enter the value, the system reads the value from the standard input.
    if (encOpt->passOptStr != NULL) {
        // Parse the password, starting with "file:" or "pass:" can be parsed.
        // Others cannot be parsed and an error is reported.
        bool parsingMode = 1; // enable the parsing mode
        if (GetPasswd(encOpt->passOptStr, parsingMode, encOpt->keySet->pass) != HITLS_APP_SUCCESS) {
            AppPrintError("The password cannot be recognized. Enter '-pass file:filePath' or '-pass pass:passwd'.\n");
            return HITLS_APP_PASSWD_FAIL;
        }
    } else {
        AppPrintError("The password can contain the following characters:\n");
        AppPrintError("a~z A~Z 0~9 ! \" # $ %% & ' ( ) * + , - . / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\n");
        AppPrintError("The space is not supported.\n");

        char buf[APP_MAX_PASS_LENGTH + 1] = {0};
        uint32_t bufLen = APP_MAX_PASS_LENGTH + 1;
        BSL_UI_ReadPwdParam param = {"passwd", NULL, true};
        int32_t ret = BSL_UI_ReadPwdUtil(&param, buf, &bufLen, HITLS_APP_DefaultPassCB, NULL);
        if (ret == BSL_UI_READ_BUFF_TOO_LONG || ret == BSL_UI_READ_LEN_TOO_SHORT) {
            HITLS_APP_PrintPassErrlog();
            return HITLS_APP_PASSWD_FAIL;
        }
        if (ret != BSL_SUCCESS) {
            AppPrintError("Failed to read passwd from stdin.\n");
            return HITLS_APP_PASSWD_FAIL;
        }
        bufLen -= 1;
        buf[bufLen] = '\0';

        bool parsingMode = 0; // close the parsing mode
        if (GetPasswd(buf, parsingMode, encOpt->keySet->pass) != HITLS_APP_SUCCESS) {
            (void)memset_s(buf, APP_MAX_PASS_LENGTH, 0, APP_MAX_PASS_LENGTH);
            AppPrintError("The password cannot be recognized.Enter '-pass file:filePath' or '-pass pass:passwd'.\n");
            return HITLS_APP_PASSWD_FAIL;
        }
    }
    if (encOpt->keySet->pass == NULL) {
        AppPrintError("Failed to get the passwd.\n");
        return HITLS_APP_PASSWD_FAIL;
    }
    encOpt->keySet->passLen = strlen(encOpt->keySet->pass);
    return HITLS_APP_SUCCESS;
}

static int32_t GenSaltAndIv(EncCmdOpt *encOpt)
{
    // During encryption, salt and iv are randomly generated.
    // use the random number API to generate the salt value
    int32_t ret = CRYPT_EAL_RandbytesEx(APP_GetCurrent_LibCtx(), encOpt->keySet->salt, encOpt->keySet->saltLen);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("enc: Failed to generate the salt value, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    // use the random number API to generate the iv value
    if (encOpt->keySet->ivLen > 0) {
        ret = CRYPT_EAL_RandbytesEx(APP_GetCurrent_LibCtx(), encOpt->keySet->iv, encOpt->keySet->ivLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("enc: Failed to generate the iv value, errCode: 0x%x.\n", ret);
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

// The enc encryption mode writes information to the file header.
static int32_t WriteEncFileHeader(EncCmdOpt *encOpt)
{
    char hexDataBuf[REC_HEX_BUF_LENGTH + 1] = {0}; // Hexadecimal Data Generic Buffer
    // Write the version, derived algorithm ID, salt information, iteration times, and IV information to the output file
    // (Convert the character string to hexadecimal and eliminate '\0' after the character string.)
    // convert and write the version number
    int32_t ret;
    if ((ret = HexAndWrite(encOpt, encOpt->version, hexDataBuf)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    // convert and write the ID of the derived algorithm
    if ((ret = HexAndWrite(encOpt, encOpt->cipherId, hexDataBuf)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    // convert and write the saltlen
    if ((ret = HexAndWrite(encOpt, encOpt->keySet->saltLen, hexDataBuf)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    // convert and write the salt value
    char hSaltBuf[REC_SALT_LEN * REC_DOUBLE + 1] = {0}; // Hexadecimal salt buffer
    if (Str2HexStr(encOpt->keySet->salt, REC_HEX_BUF_LENGTH, hSaltBuf, sizeof(hSaltBuf)) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    uint32_t writeLen = 0;
    if (BSL_UIO_Write(encOpt->encUio->wUio, hSaltBuf, REC_SALT_LEN * REC_DOUBLE, &writeLen) != BSL_SUCCESS ||
        writeLen != REC_SALT_LEN * REC_DOUBLE) {
        return HITLS_APP_UIO_FAIL;
    }
    // convert and write the iteration times
    if ((ret = HexAndWrite(encOpt, encOpt->iter, hexDataBuf)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (encOpt->keySet->ivLen > 0) {
        // convert and write the ivlen
        if ((ret = HexAndWrite(encOpt, encOpt->keySet->ivLen, hexDataBuf)) != HITLS_APP_SUCCESS) {
            return ret;
        }
        // convert and write the iv
        char hIvBuf[REC_MAX_IV_LENGTH * REC_DOUBLE + 1] = {0}; // hexadecimal iv buffer
        if (Str2HexStr(encOpt->keySet->iv, encOpt->keySet->ivLen, hIvBuf, sizeof(hIvBuf)) != HITLS_APP_SUCCESS) {
            return HITLS_APP_ENCODE_FAIL;
        }
        if (BSL_UIO_Write(encOpt->encUio->wUio, hIvBuf, encOpt->keySet->ivLen * REC_DOUBLE, &writeLen) != BSL_SUCCESS ||
            writeLen != encOpt->keySet->ivLen * REC_DOUBLE) {
            return HITLS_APP_UIO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandleDecFileIv(EncCmdOpt *encOpt)
{
    char hexDataBuf[REC_HEX_BUF_LENGTH + 1] = {0}; // hexadecimal data buffer
    uint32_t hexBufLen = sizeof(hexDataBuf);
    int32_t ret = HITLS_APP_SUCCESS;
    // Read the length of the IV, convert it into decimal, and store it.
    uint32_t tmpIvLen = 0;
    if ((ret = ReadAndDec(encOpt, hexDataBuf, hexBufLen, (int32_t*)&tmpIvLen)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (tmpIvLen != encOpt->keySet->ivLen) {
        AppPrintError("Iv length is error, iv length read from file is %u.\n", tmpIvLen);
        return HITLS_APP_INFO_CMP_FAIL;
    }
    // Read iv based on ivLen, convert it into a decimal character string, and store it.
    uint32_t readLen = 0;
    char hIvBuf[REC_MAX_IV_LENGTH * REC_DOUBLE + 1] = {0}; // Hexadecimal iv buffer
    if (BSL_UIO_Read(encOpt->encUio->rUio, hIvBuf, encOpt->keySet->ivLen * REC_DOUBLE, &readLen) != BSL_SUCCESS ||
        readLen != encOpt->keySet->ivLen * REC_DOUBLE) {
        return HITLS_APP_UIO_FAIL;
    }
    if (HexToStr(hIvBuf, encOpt->keySet->iv) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    return ret;
}

// The ENC decryption mode parses the file header data and receives the ciphertext in the input file.
static int32_t HandleDecFileHeader(EncCmdOpt *encOpt)
{
    char hexDataBuf[REC_HEX_BUF_LENGTH + 1] = {0}; // hexadecimal data buffer
    uint32_t hexBufLen = sizeof(hexDataBuf);
    // Read the version, derived algorithm ID, salt information, iteration times, and IV information from the input file
    // convert them into decimal and store for later decryption.
    // The read data is in hexadecimal format and needs to be converted to decimal format.
    // Read the version number, convert it to decimal, and compare it.
    int32_t ret = HITLS_APP_SUCCESS;
    uint32_t rVersion = 0; // Version number in the ciphertext
    if ((ret = ReadAndDec(encOpt, hexDataBuf, hexBufLen, (int32_t *)&rVersion)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    // Compare the file version input by the user with the current ENC version.
    // If the file version does not match, an error is reported.
    if (rVersion != encOpt->version) {
        AppPrintError("Error version. The enc version is %u, the file version is %u.\n", encOpt->version, rVersion);
        return HITLS_APP_INFO_CMP_FAIL;
    }
    // Read the derived algorithm in the ciphertext, convert it to decimal and compare.
    int32_t rCipherId = -1; // Decimal cipherID read from the file
    if ((ret = ReadAndDec(encOpt, hexDataBuf, hexBufLen, &rCipherId)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    // Compare the algorithm entered by the user from the command line with the algorithm read.
    // If the algorithm is incorrect, an error is reported.
    if (encOpt->cipherId != rCipherId) {
        AppPrintError("Cipher ID is %d, cipher ID read from file is %d.\n", encOpt->cipherId, rCipherId);
        return HITLS_APP_INFO_CMP_FAIL;
    }
    // Read the salt length in the ciphertext, convert the salt length into decimal, and store the salt length.
    if ((ret = ReadAndDec(encOpt, hexDataBuf, hexBufLen, (int32_t *)&encOpt->keySet->saltLen)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (encOpt->keySet->saltLen != REC_SALT_LEN) {
        AppPrintError("Salt length is error, Salt length read from file is %u.\n", encOpt->keySet->saltLen);
        return HITLS_APP_INFO_CMP_FAIL;
    }
    // Read the salt value in the ciphertext, convert the salt value into a decimal string, and store the string.
    uint32_t readLen = 0;
    char hSaltBuf[REC_SALT_LEN * REC_DOUBLE + 1] = {0}; // Hexadecimal salt buffer
    if (BSL_UIO_Read(encOpt->encUio->rUio, hSaltBuf, REC_SALT_LEN * REC_DOUBLE, &readLen) != BSL_SUCCESS ||
        readLen != REC_SALT_LEN * REC_DOUBLE) {
        return HITLS_APP_UIO_FAIL;
    }
    if (HexToStr(hSaltBuf, encOpt->keySet->salt) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    // Read the times of iteration, convert the number to decimal, and store the number.
    if ((ret = ReadAndDec(encOpt, hexDataBuf, hexBufLen, (int32_t *)&encOpt->iter)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (encOpt->keySet->ivLen > 0) {
        if ((ret = HandleDecFileIv(encOpt)) != HITLS_APP_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

#ifdef HITLS_APP_SM_MODE
static int32_t GetKeyFromP12(EncCmdOpt *encOpt)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    int32_t ret = HITLS_APP_FindKey(encOpt->provider, encOpt->smParam, encOpt->cipherId, &keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("enc: Failed to find key, errCode: 0x%x\n", ret);
        return ret;
    }
    if (encOpt->keySet->dKeyLen != keyInfo.keyLen) {
        AppPrintError("enc: Key length is not equal, dKeyLen: %u, keyLen: %u.\n", encOpt->keySet->dKeyLen,
            keyInfo.keyLen);
        BSL_SAL_CleanseData(keyInfo.key, keyInfo.keyLen);
        return HITLS_APP_INVALID_ARG;
    }
    (void)memcpy_s(encOpt->keySet->dKey, encOpt->keySet->dKeyLen, keyInfo.key, keyInfo.keyLen);
    BSL_SAL_CleanseData(keyInfo.key, keyInfo.keyLen);
    return HITLS_APP_SUCCESS;
}
#endif

static int32_t GetCipherKey(EncCmdOpt *encOpt)
{
    if (CRYPT_EAL_CipherGetInfo(encOpt->cipherId, CRYPT_INFO_KEY_LEN, &encOpt->keySet->dKeyLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
#ifdef HITLS_APP_SM_MODE
    if (encOpt->smParam->smTag == 1) {
        return GetKeyFromP12(encOpt);
    }
#endif
    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_ProviderKdfNewCtx(APP_GetCurrent_LibCtx(), CRYPT_KDF_PBKDF2,
        encOpt->provider->providerAttr);
    if (ctx == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    int index = 0;
    BSL_Param params[HITLS_APP_ENC_MAX_PARAM_NUM] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &encOpt->mdId,
        sizeof(encOpt->mdId));
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        encOpt->keySet->pass, encOpt->keySet->passLen);
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        encOpt->keySet->salt, encOpt->keySet->saltLen);
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
        &encOpt->iter, sizeof(encOpt->iter));
    uint32_t ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, encOpt->keySet->dKey, encOpt->keySet->dKeyLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }
    // Delete sensitive information after the key is used.
    CRYPT_EAL_KdfFreeCtx(ctx);
    return BSL_SUCCESS;
}

static bool CipherIdIsValid(uint32_t id, const uint32_t *list, uint32_t num)
{
    for (uint32_t i = 0; i < num; i++) {
        if (id == list[i]) {
            return true;
        }
    }
    return false;
}

static bool IsBlockCipher(CRYPT_CIPHER_AlgId id)
{
    if (CipherIdIsValid(id, CIPHER_IS_BlOCK, sizeof(CIPHER_IS_BlOCK) / sizeof(CIPHER_IS_BlOCK[0]))) {
        return true;
    }
    return false;
}

static bool IsXtsCipher(CRYPT_CIPHER_AlgId id)
{
    if (CipherIdIsValid(id, CIPHER_IS_XTS, sizeof(CIPHER_IS_XTS) / sizeof(CIPHER_IS_XTS[0]))) {
        return true;
    }
    return false;
}

static int32_t XTSCipherUpdate(EncCmdOpt *encOpt, uint8_t *buf, uint32_t bufLen, uint8_t *res, uint32_t resLen)
{
    uint32_t updateLen = bufLen;
    if (CRYPT_EAL_CipherUpdate(encOpt->keySet->ctx, buf, bufLen, res, &updateLen) != CRYPT_SUCCESS) {
        AppPrintError("Failed to update the cipher.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (updateLen > resLen) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint32_t writeLen = 0;
    if (updateLen != 0 &&
        (BSL_UIO_Write(encOpt->encUio->wUio, res, updateLen, &writeLen) != BSL_SUCCESS || writeLen != updateLen)) {
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t StreamCipherUpdate(EncCmdOpt *encOpt, uint8_t *readBuf, uint32_t readLen, uint8_t *resBuf,
    uint32_t resLen)
{
    uint32_t updateLen = 0;
    uint32_t hBuffLen = readLen + encOpt->keySet->blockSize;
    uint32_t blockNum = readLen / encOpt->keySet->blockSize;
    uint32_t remainLen = readLen % encOpt->keySet->blockSize;
    for (uint32_t i = 0; i < blockNum; ++i) {
        hBuffLen = readLen + encOpt->keySet->blockSize - i * encOpt->keySet->blockSize;
        if (CRYPT_EAL_CipherUpdate(encOpt->keySet->ctx, readBuf + (i * encOpt->keySet->blockSize),
            encOpt->keySet->blockSize, resBuf + (i * encOpt->keySet->blockSize), &hBuffLen) != CRYPT_SUCCESS) {
            AppPrintError("Failed to update the cipher.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        updateLen += hBuffLen;
    }
    if (remainLen > 0) {
        hBuffLen = readLen + encOpt->keySet->blockSize - updateLen;
        if (CRYPT_EAL_CipherUpdate(encOpt->keySet->ctx, readBuf + updateLen, remainLen,
            resBuf + updateLen, &hBuffLen) != CRYPT_SUCCESS) {
            AppPrintError("Failed to update the cipher.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        updateLen += hBuffLen;
    }
    if (updateLen > resLen) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint32_t writeLen = 0;
    if (updateLen != 0 &&
        (BSL_UIO_Write(encOpt->encUio->wUio, resBuf, updateLen, &writeLen) != BSL_SUCCESS || writeLen != updateLen)) {
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t UpdateEncStdinEnd(EncCmdOpt *encOpt, uint8_t *cache, uint32_t cacheLen, uint8_t *resBuf, uint32_t resLen)
{
    if (IsXtsCipher(encOpt->cipherId)) {
        if (cacheLen < XTS_MIN_DATALEN) {
            AppPrintError("The XTS algorithm does not support data less than 16 bytes.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        return XTSCipherUpdate(encOpt, cache, cacheLen, resBuf, resLen);
    } else {
        return StreamCipherUpdate(encOpt, cache, cacheLen, resBuf, resLen);
    }
}

static int32_t UpdateEncStdin(EncCmdOpt *encOpt)
{
    // now readFileLen == 0
    int32_t ret = HITLS_APP_SUCCESS;
    // Because the standard input is read in each 4K, the data required by the XTS update cannot be less than 16.
    // Therefore, the remaining data cannot be less than 16 bytes. The buffer behavior is required.
    // In the common buffer logic, the remaining data may be less than 16. As a result, the XTS algorithm update fails.
    // Set the cacheArea, the size is maximum data length of each row (4 KB) plus the readable block size (32 bytes).
    // If the length of the read data exceeds 32 bytes, the length of the last 16-byte secure block is reserved,
    // the rest of the data is updated to avoid the failure of updating the rest and tail data.
    uint8_t cacheArea[MAX_BUFSIZE + BUF_READABLE_BLOCK] = {0};
    uint32_t cacheLen = 0;
    uint8_t readBuf[MAX_BUFSIZE] = {0};
    uint8_t resBuf[MAX_BUFSIZE + BUF_READABLE_BLOCK] = {0};
    uint32_t readLen = MAX_BUFSIZE;
    bool isEof = false;
    while (BSL_UIO_Ctrl(encOpt->encUio->rUio, BSL_UIO_FILE_GET_EOF, IS_SUPPORT_GET_EOF, &isEof) == BSL_SUCCESS) {
        readLen = MAX_BUFSIZE;
        if (isEof) {
            // End stdin. Update the remaining data. If the remaining data size is 16 ≤ dataLen < 32, the XTS is valid.
            ret = UpdateEncStdinEnd(encOpt, cacheArea, cacheLen, resBuf, sizeof(resBuf));
            if (ret != HITLS_APP_SUCCESS) {
                return ret;
            }
            break;
        }
        if (BSL_UIO_Read(encOpt->encUio->rUio, readBuf, MAX_BUFSIZE, &readLen) != BSL_SUCCESS) {
            (void)AppPrintError("Failed to obtain the content from the STDIN\n");
            return HITLS_APP_UIO_FAIL;
        }
        if (readLen == 0) {
            AppPrintError("Failed to read the input content\n");
            return HITLS_APP_STDIN_FAIL;
        }
        if (memcpy_s(cacheArea + cacheLen, MAX_BUFSIZE + BUF_READABLE_BLOCK - cacheLen, readBuf, readLen) != EOK) {
            return HITLS_APP_COPY_ARGS_FAILED;
        }
        cacheLen += readLen;
        if (cacheLen < BUF_READABLE_BLOCK) {
            continue;
        }
        uint32_t readableLen = cacheLen - BUF_SAFE_BLOCK;
        if (IsXtsCipher(encOpt->cipherId)) {
            ret = XTSCipherUpdate(encOpt, cacheArea, readableLen, resBuf, sizeof(resBuf));
        } else {
            ret = StreamCipherUpdate(encOpt, cacheArea, readableLen, resBuf, sizeof(resBuf));
        }
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        // Place the secure block data in the cacheArea at the top and reset cacheLen.
        if (memcpy_s(cacheArea, sizeof(cacheArea) - BUF_SAFE_BLOCK, cacheArea + readableLen, BUF_SAFE_BLOCK) != EOK) {
            return HITLS_APP_COPY_ARGS_FAILED;
        }
        cacheLen = BUF_SAFE_BLOCK;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t UpdateEncFile(EncCmdOpt *encOpt, uint64_t readFileLen)
{
    if (readFileLen < XTS_MIN_DATALEN && IsXtsCipher(encOpt->cipherId)) {
        AppPrintError("The XTS algorithm does not support data less than 16 bytes.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    // now readFileLen != 0
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t readBuf[MAX_BUFSIZE * REC_DOUBLE] = {0};
    uint8_t resBuf[MAX_BUFSIZE * REC_DOUBLE] = {0};
    uint32_t readLen = MAX_BUFSIZE * REC_DOUBLE;
    uint32_t bufLen = MAX_BUFSIZE * REC_DOUBLE;
    while (readFileLen > 0) {
        if (readFileLen < MAX_BUFSIZE * REC_DOUBLE) {
            bufLen = readFileLen;
            readLen = readFileLen;
        }
        if (readFileLen >= MAX_BUFSIZE * REC_DOUBLE) {
            bufLen = MAX_BUFSIZE;
            readLen = MAX_BUFSIZE;
        }
        if (!IsXtsCipher(encOpt->cipherId)) {
            bufLen = (readFileLen > MAX_BUFSIZE) ? MAX_BUFSIZE : readFileLen;
            readLen = bufLen;
        }
        if (BSL_UIO_Read(encOpt->encUio->rUio, readBuf, bufLen, &readLen) != BSL_SUCCESS || bufLen != readLen) {
            AppPrintError("Failed to read the input content\n");
            return HITLS_APP_UIO_FAIL;
        }
        readFileLen -= readLen;
        if (IsXtsCipher(encOpt->cipherId)) {
            ret = XTSCipherUpdate(encOpt, readBuf, readLen, resBuf, sizeof(resBuf));
        } else {
            ret = StreamCipherUpdate(encOpt, readBuf, readLen, resBuf, sizeof(resBuf));
        }
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t DoCipherUpdateEnc(EncCmdOpt *encOpt, uint64_t readFileLen)
{
    int32_t updateRet = HITLS_APP_SUCCESS;
    if (readFileLen > 0) {
        updateRet = UpdateEncFile(encOpt, readFileLen);
    } else {
        updateRet = UpdateEncStdin(encOpt);
    }
    if (updateRet != HITLS_APP_SUCCESS) {
        return updateRet;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t DoCipherUpdateDec(EncCmdOpt *encOpt, uint64_t readFileLen)
{
    if (readFileLen == 0 && encOpt->inFile == NULL) {
        AppPrintError("In decryption mode, the standard input cannot be used to obtain the ciphertext.\n");
        return HITLS_APP_STDIN_FAIL;
    }
    if (readFileLen < XTS_MIN_DATALEN && IsXtsCipher(encOpt->cipherId)) {
        AppPrintError("The XTS algorithm does not support ciphertext less than 16 bytes.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    // now readFileLen != 0
    uint8_t readBuf[MAX_BUFSIZE * REC_DOUBLE] = {0};
    uint8_t resBuf[MAX_BUFSIZE * REC_DOUBLE] = {0};
    uint32_t readLen = MAX_BUFSIZE * REC_DOUBLE;
    uint32_t bufLen = MAX_BUFSIZE * REC_DOUBLE;
    while (readFileLen > 0) {
        if (readFileLen < MAX_BUFSIZE * REC_DOUBLE) {
            bufLen = readFileLen;
        }
        if (readFileLen >= MAX_BUFSIZE * REC_DOUBLE) {
            bufLen = MAX_BUFSIZE;
        }
        if (!IsXtsCipher(encOpt->cipherId)) {
            bufLen = (readFileLen >= MAX_BUFSIZE) ? MAX_BUFSIZE : readFileLen;
        }
        readLen = 0;
        if (BSL_UIO_Read(encOpt->encUio->rUio, readBuf, bufLen, &readLen) != BSL_SUCCESS || bufLen != readLen) {
            AppPrintError("Failed to read the input content\n");
            return HITLS_APP_UIO_FAIL;
        }
        readFileLen -= readLen;
        uint32_t updateLen = readLen + encOpt->keySet->blockSize;
        if (CRYPT_EAL_CipherUpdate(encOpt->keySet->ctx, readBuf, readLen, resBuf, &updateLen) != CRYPT_SUCCESS) {
            AppPrintError("Failed to update the cipher.\n");
            return HITLS_APP_CRYPTO_FAIL;
        }
        uint32_t writeLen = 0;
        if (updateLen != 0 &&
            (BSL_UIO_Write(encOpt->encUio->wUio, resBuf, updateLen, &writeLen) != BSL_SUCCESS ||
            writeLen != updateLen)) {
            AppPrintError("Failed to write the cipher text.\n");
            return HITLS_APP_UIO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t DoCipherUpdate(EncCmdOpt *encOpt)
{
    const uint32_t AES_BLOCK_SIZE = 16;
    encOpt->keySet->blockSize = AES_BLOCK_SIZE;
    uint64_t readFileLen = 0;
    if (encOpt->inFile != NULL &&
        BSL_UIO_Ctrl(encOpt->encUio->rUio, BSL_UIO_PENDING, sizeof(readFileLen), &readFileLen) != BSL_SUCCESS) {
        (void)AppPrintError("Failed to obtain the content length\n");
        return HITLS_APP_UIO_FAIL;
    }
    if (encOpt->inFile == NULL) {
        AppPrintError("You have not entered the -in option. Please directly enter the file content on the terminal.\n");
    }
    int32_t updateRet = (encOpt->encTag == 0) ? DoCipherUpdateDec(encOpt, readFileLen)
                                              : DoCipherUpdateEnc(encOpt, readFileLen);
    if (updateRet != HITLS_APP_SUCCESS) {
        return updateRet;
    }

    // The Aead algorithm does not perform final processing.
    uint32_t isAeadId = 0;
    if (CRYPT_EAL_CipherGetInfo(encOpt->cipherId, CRYPT_INFO_IS_AEAD, &isAeadId) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (isAeadId == 1) {
        return HITLS_APP_SUCCESS;
    }
    uint32_t finLen = AES_BLOCK_SIZE;
    uint8_t resBuf[MAX_BUFSIZE] = {0};
    // Fill the data whose size is less than the block size and output the crypted data.
    if (CRYPT_EAL_CipherFinal(encOpt->keySet->ctx, resBuf, &finLen) != CRYPT_SUCCESS) {
        AppPrintError("Failed to final the cipher.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }

    uint32_t writeLen = 0;
    if (finLen != 0 && (BSL_UIO_Write(encOpt->encUio->wUio, resBuf, finLen, &writeLen) != BSL_SUCCESS ||
        writeLen != finLen)) {
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

// Enc encryption or decryption process
static int32_t EncOrDecProc(EncCmdOpt *encOpt)
{
    if (GetCipherKey(encOpt) != BSL_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    // Create a cipher context.
    encOpt->keySet->ctx = CRYPT_EAL_ProviderCipherNewCtx(APP_GetCurrent_LibCtx(), encOpt->cipherId,
        encOpt->provider->providerAttr);
    if (encOpt->keySet->ctx == NULL) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    // Initialize the symmetric encryption and decryption handle.
    if (CRYPT_EAL_CipherInit(encOpt->keySet->ctx, encOpt->keySet->dKey, encOpt->keySet->dKeyLen, encOpt->keySet->iv,
        encOpt->keySet->ivLen, encOpt->encTag) != CRYPT_SUCCESS) {
        AppPrintError("Failed to init the cipher.\n");
        (void)memset_s(encOpt->keySet->dKey, encOpt->keySet->dKeyLen, 0, encOpt->keySet->dKeyLen);
        return HITLS_APP_CRYPTO_FAIL;
    }
    (void)memset_s(encOpt->keySet->dKey, encOpt->keySet->dKeyLen, 0, encOpt->keySet->dKeyLen);
    if (IsBlockCipher(encOpt->cipherId)) {
        if (CRYPT_EAL_CipherSetPadding(encOpt->keySet->ctx, CRYPT_PADDING_PKCS7) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
#ifdef HITLS_APP_SM_MODE
    if (encOpt->smParam->smTag == 1) {
        encOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    }
#endif
    int32_t ret = HITLS_APP_SUCCESS;
    if (encOpt->encTag == 1) {
        if ((ret = WriteEncFileHeader(encOpt)) != HITLS_APP_SUCCESS) {
            return ret;
        }
    }
    if ((ret = DoCipherUpdate(encOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandleEnc(EncCmdOpt *encOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    if ((ret = HandleIO(encOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    if ((ret = ApplyForSpace(encOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    if ((ret = HandlePasswd(encOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    // The ciphertext format is
    // [g_version:uint32][derived algID:uint32][saltlen:uint32][salt][iter times:uint32][ivlen:uint32][iv][ciphertext]
    // If the user identifier is encrypted
    if (encOpt->encTag == 1 && (ret = GenSaltAndIv(encOpt)) != HITLS_APP_SUCCESS) {
        // Random salt and IV are generated in encryption mode.
        return ret;
    }
    // If the user identifier is decrypted
    if (encOpt->encTag == 0 && (ret = HandleDecFileHeader(encOpt)) != HITLS_APP_SUCCESS) {
        // Decryption mode: Parse the file header data and receive the ciphertext in the input file.
        return ret;
    }
    // Final encryption or decryption process
    if ((ret = EncOrDecProc(encOpt)) != HITLS_APP_SUCCESS) {
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

// enc main function
int32_t HITLS_EncMain(int argc, char *argv[])
{
    int32_t encRet = -1; // return value of enc
    EncKeyParam keySet = {NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0};
    EncUio encUio = {NULL, NULL};
    AppProvider appProvider = {NULL, NULL, NULL};
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    EncCmdOpt encOpt = {1, NULL, NULL, NULL, -1, -1, -1, 0, &keySet, &encUio, &appProvider, &smParam};
#else
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider};
    EncCmdOpt encOpt = {1, NULL, NULL, NULL, -1, -1, -1, 0, &keySet, &encUio, &appProvider};
#endif
    if ((encRet = HITLS_APP_OptBegin(argc, argv, g_encOpts)) != HITLS_APP_SUCCESS) {
        AppPrintError("error in opt begin.\n");
        goto End;
    }
    // Process of receiving the lower-level option of the ENC.
    if ((encRet = HandleOpt(&encOpt)) != HITLS_APP_SUCCESS) {
        goto End;
    }
    // Check the validity of the lower-level option receiving parameter.
    if ((encRet = CheckParam(&encOpt)) != HITLS_APP_SUCCESS) {
        goto End;
    }
    encRet = HITLS_APP_Init(&initParam);
    if (encRet != HITLS_APP_SUCCESS) {
        goto End;
    }
    if ((encRet = HandleEnc(&encOpt)) != HITLS_APP_SUCCESS) {
        goto End;
    }
    encRet = HITLS_APP_SUCCESS;
End:
    HITLS_APP_Deinit(&initParam, encRet);
    FreeEnc(&encOpt);
    return encRet;
}

static int32_t GetCipherId(const char *name)
{
    for (size_t i = 0; i < sizeof(g_cIdList) / sizeof(g_cIdList[0]); i++) {
        if (strcmp(g_cIdList[i].cipherAlgName, name) == 0) {
            return g_cIdList[i].cipherId;
        }
    }
    PrintCipherAlgList();
    return -1;
}

static int32_t GetHMacId(const char *mdName)
{
    for (size_t i = 0; i < sizeof(g_mIdList) / sizeof(g_mIdList[0]); i++) {
        if (strcmp(g_mIdList[i].macAlgName, mdName) == 0) {
            return g_mIdList[i].macId;
        }
    }
    PrintHMacAlgList();
    return -1;
}

static void PrintHMacAlgList(void)
{
    AppPrintError("The current version supports only the following digest algorithms:\n");
    for (size_t i = 0; i < sizeof(g_mIdList) / sizeof(g_mIdList[0]); i++) {
        AppPrintError("%-19s", g_mIdList[i].macAlgName);
        // 4 algorithm names are displayed in each row
        if ((i + 1) % 4 == 0 && i != sizeof(g_mIdList) - 1) {
            AppPrintError("\n");
        }
    }
    AppPrintError("\n");
    return;
}

static void PrintCipherAlgList(void)
{
    AppPrintError("The current version supports only the following cipher algorithms:\n");
    for (size_t i = 0; i < sizeof(g_cIdList) / sizeof(g_cIdList[0]); i++) {
        AppPrintError("%-19s", g_cIdList[i].cipherAlgName);
        // 4 algorithm names are displayed in each row
        if ((i + 1) % 4 == 0 && i != sizeof(g_cIdList) - 1) {
            AppPrintError("\n");
        }
    }
    AppPrintError("\n");
    return;
}

static int32_t GetPasswd(const char *arg, bool mode, char *resPass)
{
    const char filePrefix[] = "file:"; // Prefix of the file path
    const char passPrefix[] = "pass:"; // Prefix of password form
    if (mode) {
        // Parsing mode. The prefix needs to be parsed. The parseable format starts with "file:" or "pass:".
        // Other parameters cannot be parsed and an error is returned.
        // Apply for a new memory and copy the unprocessed character string.
        char tmpPassArg[APP_MAX_PASS_LENGTH * REC_DOUBLE] = {0};
        if (strlen(arg) < APP_MIN_PASS_LENGTH ||
            strcpy_s(tmpPassArg, sizeof(tmpPassArg) - 1, arg) != EOK) {
            return HITLS_APP_SECUREC_FAIL;
        }
        if (strncmp(tmpPassArg, filePrefix, REC_MIN_PRE_LENGTH - 1) == 0) {
            // In this case, the password mode is read from the file.
            int32_t res;
            if ((res = GetPwdFromFile(tmpPassArg, resPass)) != HITLS_APP_SUCCESS) {
                AppPrintError("Failed to obtain the password from the file.\n");
                return res;
            }
        } else if (strncmp(tmpPassArg, passPrefix, REC_MIN_PRE_LENGTH - 1) == 0) {
            // In this case, the password mode is read from the user input.
            // Obtain the password after the ':'.
            char *context = NULL;
            char *tmpPass = strtok_s(tmpPassArg, ":", &context);
            tmpPass = strtok_s(NULL, ":", &context);
            if (tmpPass == NULL) {
                return HITLS_APP_SECUREC_FAIL;
            }
            // Check whether the password is correct. Unsupported characters are not allowed.
            if (CheckPasswd(tmpPass) != HITLS_APP_SUCCESS) {
                return HITLS_APP_PASSWD_FAIL;
            }
            if (memcpy_s(resPass, APP_MAX_PASS_LENGTH, tmpPass, strlen(tmpPass)) != EOK) {
                return HITLS_APP_COPY_ARGS_FAILED;
            }
        } else {
            // The prefix format is invalid. An error is returned.
            AppPrintError("Invalid prefix format.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    } else {
        // In non-parse mode, the format is directly determined.
        // The value can be 1 byte ≤ password ≤ 1024 bytes, and only specified characters are supported.
        // If the operation is successful, the password is received. If the operation fails, an error is returned.
        if (CheckPasswd(arg) != HITLS_APP_SUCCESS) {
            return HITLS_APP_PASSWD_FAIL;
        }
        if (memcpy_s(resPass, APP_MAX_PASS_LENGTH, arg, strlen(arg)) != EOK) {
            return HITLS_APP_COPY_ARGS_FAILED;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetPwdFromFile(const char *fileArg, char *tmpPass)
{
    // Apply for a new memory and copy the unprocessed character string.
    char tmpFileArg[REC_MAX_FILENAME_LENGTH + REC_MIN_PRE_LENGTH + 1] = {0};
    if (strcpy_s(tmpFileArg, REC_MAX_FILENAME_LENGTH + REC_MIN_PRE_LENGTH, fileArg) != EOK) {
        return HITLS_APP_SECUREC_FAIL;
    }
    // Obtain the file path after the ':'.
    char *filePath = NULL;
    char *context = NULL;
    filePath = strtok_s(tmpFileArg, ":", &context);
    filePath = strtok_s(NULL, ":", &context);
    if (filePath == NULL) {
        return HITLS_APP_SECUREC_FAIL;
    }
    // Bind the password file UIO.
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
    // Check whether the password is correct. Unsupported characters are not allowed.
    if (HITLS_APP_CheckPasswd((uint8_t *)tmpPassBuf, rPassLen) != HITLS_APP_SUCCESS) {
        return HITLS_APP_PASSWD_FAIL;
    }
    if (memcpy_s(tmpPass, APP_MAX_PASS_LENGTH, tmpPassBuf, strlen(tmpPassBuf)) != EOK) {
        return HITLS_APP_COPY_ARGS_FAILED;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckPasswd(const char *passwd)
{
    // Check the key length. The key length must be greater than or equal to 1 byte and less than or equal to 1024
    // bytes.
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
        if (sprintf_s(hexBuf + i * REC_DOUBLE, bufLen * REC_DOUBLE + 1, "%02x", buf[i]) == -1) {
            AppPrintError("BSL_SAL_Calloc Failed.\n");
            return HITLS_APP_ENCODE_FAIL;
        }
    }
    hexBuf[bufLen * REC_DOUBLE] = '\0';
    return HITLS_APP_SUCCESS;
}

static int32_t HexToStr(const char *hexBuf, unsigned char *buf)
{
    // Convert hexadecimal character string data into ASCII character data.
    int len = strlen(hexBuf) / 2;
    for (int i = 0; i < len; i++) {
        uint32_t val;
        if (sscanf_s(hexBuf + i * REC_DOUBLE, "%2x", &val) == -1) {
            AppPrintError("error in converting hex str to str.\n");
            return HITLS_APP_ENCODE_FAIL;
        }
        buf[i] = (unsigned char)val;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t Int2Hex(uint32_t num, char *hexBuf)
{
    int ret = snprintf_s(hexBuf, REC_HEX_BUF_LENGTH + 1, REC_HEX_BUF_LENGTH, "%08X", num);
    if (strlen(hexBuf) != REC_HEX_BUF_LENGTH || ret == -1) {
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

static int32_t HexAndWrite(EncCmdOpt *encOpt, uint32_t decData, char *buf)
{
    uint32_t writeLen = 0;
    if (Int2Hex(decData, buf) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    if (BSL_UIO_Write(encOpt->encUio->wUio, buf, REC_HEX_BUF_LENGTH, &writeLen) != BSL_SUCCESS ||
        writeLen != REC_HEX_BUF_LENGTH) {
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}
static int32_t ReadAndDec(EncCmdOpt *encOpt, char *hexBuf, uint32_t hexBufLen, int32_t *decData)
{
    if (hexBufLen < REC_HEX_BUF_LENGTH + 1) {
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t readLen = 0;
    if (BSL_UIO_Read(encOpt->encUio->rUio, hexBuf, REC_HEX_BUF_LENGTH, &readLen) != BSL_SUCCESS ||
        readLen != REC_HEX_BUF_LENGTH) {
        return HITLS_APP_UIO_FAIL;
    }
    if (Hex2Uint(hexBuf, decData) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    return HITLS_APP_SUCCESS;
}
