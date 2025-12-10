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
#include "app_passwd.h"
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
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "app_opt.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_utils.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"

typedef enum {
    HITLS_APP_OPT_PASSWD_ERR = -1,
    HITLS_APP_OPT_PASSWD_EOF = 0,
    HITLS_APP_OPT_PASSWD_HELP = 1,
    HITLS_APP_OPT_PASSWD_OUTFILE = 2,
    HITLS_APP_OPT_PASSWD_SHA512,
} HITLSOptType;

const HITLS_CmdOption g_passwdOpts[] = {
    {"help", HITLS_APP_OPT_PASSWD_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"out", HITLS_APP_OPT_PASSWD_OUTFILE, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Outfile"},
    {"sha512",  HITLS_APP_OPT_PASSWD_SHA512, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "SHA512-based password algorithm"},
    {NULL, 0, 0, NULL}
};

typedef struct {
    char *outFile;
    int32_t algTag; // 6 indicates sha512, 5 indicates sha256, and 1 indicates md5.
    uint8_t *salt;
    int32_t saltLen;
    char *pass;
    uint32_t passwdLen;
    long iter;
} PasswdOpt;

typedef struct {
    uint8_t *buf;
    size_t bufLen;
} BufLen;

// List of visible characters also B64 coding table
static const char g_b64Table[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static int32_t HandleOpt(PasswdOpt *opt);
static int32_t GetSalt(PasswdOpt *opt);
static int32_t Sha512Crypt(PasswdOpt *opt, char *resBuf, uint32_t bufMaxLen);
static int32_t OutputResult(BSL_UIO *outUio, char *resBuf, uint32_t bufLen);
static bool IsSaltValid(char *salt);
static bool IsSaltArgValid(PasswdOpt *opt);
static bool IsDigit(char *str);
static long StrToDigit(char *str);
static bool ParseSalt(PasswdOpt *opt);
static char *SubStr(const char* srcStr, int32_t startPos, int32_t cutLen);
static CRYPT_EAL_MdCTX *InitSha512Ctx(void);
static int32_t B64EncToBuf(char *resBuf, uint32_t bufLen, uint32_t offset, uint8_t *hashBuf, uint32_t hashBufLen);
static int32_t ResToBuf(PasswdOpt *opt, char *resBuf, uint32_t bufMaxLen, uint8_t *hashBuf, uint32_t hashBufLen);
static int32_t Sha512Md2Hash(CRYPT_EAL_MdCTX *md2, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen);
static int32_t Sha512Md1HashWithMd2(CRYPT_EAL_MdCTX *md1, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen);
static int32_t Sha512MdPHash(CRYPT_EAL_MdCTX *mdP, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen);
static int32_t Sha512MdSHash(CRYPT_EAL_MdCTX *mdS, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen, uint8_t nForMdS);
static int32_t Sha512GetMdPBuf(PasswdOpt *opt, uint8_t *mdPBuf, uint32_t mdPBufLen);
static int32_t Sha512GetMdSBuf(PasswdOpt *opt, uint8_t *mdSBuf, uint32_t mdSBufLen, uint8_t nForMdS);
static int32_t Sha512IterHash(long rounds, BufLen *md1HashRes, BufLen *mdPBuf, BufLen *mdSBuf);
static int32_t Sha512MdCrypt(PasswdOpt *opt, char *resBuf, uint32_t bufLen);

static int32_t GetPasswd(PasswdOpt *opt)
{
    char *pwd = NULL;
    uint32_t pwdLen;
    int32_t ret = HITLS_APP_ParsePasswd("stdin", &pwd);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to read passwd from stdin.\n");
        return HITLS_APP_PASSWD_FAIL;
    }
    pwdLen = (uint32_t)strlen(pwd);
    if (pwdLen < APP_MIN_PASS_LENGTH || pwdLen > APP_MAX_PASS_LENGTH) {
        BSL_SAL_ClearFree(pwd, pwdLen);
        AppPrintError("Invalid passwd length.\n");
        return HITLS_APP_PASSWD_FAIL;
    }
    if (HITLS_APP_CheckPasswd((uint8_t *)pwd, pwdLen) != HITLS_APP_SUCCESS) {
        BSL_SAL_ClearFree(pwd, pwdLen);
        AppPrintError("Failed to check passwd.\n");
        return HITLS_APP_PASSWD_FAIL;
    }
    opt->pass = pwd;
    opt->passwdLen = pwdLen;
    return HITLS_APP_SUCCESS;
}

static int32_t CheckPara(PasswdOpt *passwdOpt, BSL_UIO *outUio)
{
    if (passwdOpt->algTag == -1 || passwdOpt->saltLen == -1) {
        AppPrintError("The hash algorithm is not specified.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (passwdOpt->iter != -1) {
        if (passwdOpt->iter < REC_MIN_ITER_TIMES || passwdOpt->iter > REC_MAX_ITER_TIMES) {
            AppPrintError("Invalid iterations number, valid range[1000, 999999999].\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    }
    int32_t checkRet = HITLS_APP_SUCCESS;
    if ((checkRet = GetSalt(passwdOpt)) != HITLS_APP_SUCCESS) {
        return checkRet;
    }
    if ((checkRet = GetPasswd(passwdOpt)) != HITLS_APP_SUCCESS) {
        return checkRet;
    }
    // Obtains the post-value of the OUT option. If there is no post-value or this option, stdout.
    if (passwdOpt->outFile == NULL) {
        if (BSL_UIO_Ctrl(outUio, BSL_UIO_FILE_PTR, 0, (void *)stdout) != BSL_SUCCESS) {
            AppPrintError("Failed to set stdout mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    } else {
        // User input file path, which is bound to the output file.
        if (strlen(passwdOpt->outFile) >= PATH_MAX || strlen(passwdOpt->outFile) == 0) {
            AppPrintError("The length of outfile error, range is (0, 4096].\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (BSL_UIO_Ctrl(outUio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, passwdOpt->outFile) != BSL_SUCCESS) {
            AppPrintError("Failed to set outfile mode.\n");
            return HITLS_APP_UIO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_PasswdMain(int argc, char *argv[])
{
    PasswdOpt opt = {NULL, -1, NULL, -1, NULL, 0, -1};
    int32_t ret = HITLS_APP_SUCCESS;
    BSL_UIO *outUio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (outUio == NULL) {
        AppPrintError("Failed to create the output UIO.\n");
        return HITLS_APP_UIO_FAIL;
    }
    if ((ret = HITLS_APP_OptBegin(argc, argv, g_passwdOpts)) != HITLS_APP_SUCCESS) {
        AppPrintError("error in opt begin.\n");
        goto passwdEnd;
    }
    if ((ret = HandleOpt(&opt)) != HITLS_APP_SUCCESS) {
        goto passwdEnd;
    }
    if ((ret = CheckPara(&opt, outUio)) != HITLS_APP_SUCCESS) {
        goto passwdEnd;
    }
    char res[REC_MAX_ARRAY_LEN] = {0};
    if ((ret = Sha512Crypt(&opt, res, REC_MAX_ARRAY_LEN)) != HITLS_APP_SUCCESS) {
        goto passwdEnd;
    }
    uint32_t resBufLen = strlen(res);
    if ((ret = OutputResult(outUio, res, resBufLen)) != HITLS_APP_SUCCESS) {
        goto passwdEnd;
    }
passwdEnd:
    BSL_SAL_FREE(opt.salt);
    if (opt.pass != NULL && opt.passwdLen > 0) {
        (void)memset_s(opt.pass, opt.passwdLen, 0, opt.passwdLen);
    }
    BSL_SAL_FREE(opt.pass);
    if (opt.outFile != NULL) {
        BSL_UIO_SetIsUnderlyingClosedByUio(outUio, true);
    }
    BSL_UIO_Free(outUio);
    return ret;
}

static int32_t HandleOpt(PasswdOpt *opt)
{
    int32_t optType;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_PASSWD_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_PASSWD_EOF:
                break;
            case HITLS_APP_OPT_PASSWD_ERR:
                AppPrintError("passwd: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_PASSWD_HELP:
                HITLS_APP_OptHelpPrint(g_passwdOpts);
                return HITLS_APP_HELP;
            case HITLS_APP_OPT_PASSWD_OUTFILE:
                opt->outFile = HITLS_APP_OptGetValueStr();
                break;
            case HITLS_APP_OPT_PASSWD_SHA512:
                opt->algTag = REC_SHA512_ALGTAG;
                opt->saltLen = REC_SHA512_SALTLEN;
                break;
            default:
                break;
        }
    }
    // Obtains the value of the last digit numbits.
    int32_t restOptNum = HITLS_APP_GetRestOptNum();
    if (restOptNum != 0) {
        (void)AppPrintError("Extra arguments given.\n");
        AppPrintError("passwd: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetSalt(PasswdOpt *opt)
{
    if (opt->salt == NULL && opt->saltLen != -1) {
        uint8_t *tmpSalt = (uint8_t *)BSL_SAL_Calloc(opt->saltLen + 1, sizeof(uint8_t));
        if (tmpSalt == NULL) {
            return HITLS_APP_MEM_ALLOC_FAIL;
        }
        opt->salt = tmpSalt;
        // Generate a salt value
        if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default",
                NULL, 0, NULL) != CRYPT_SUCCESS ||
            CRYPT_EAL_RandbytesEx(NULL, opt->salt, opt->saltLen) != CRYPT_SUCCESS) {
            AppPrintError("Failed to generate the salt value.\n");
            BSL_SAL_FREE(opt->salt);
            CRYPT_EAL_RandDeinitEx(NULL);
            return HITLS_APP_CRYPTO_FAIL;
        }
        // Convert salt value to visible code
        int32_t count = 0;
        for (; count < opt->saltLen; count++) {
            if ((opt->salt[count] & 0x3f) < strlen(g_b64Table)) {
                opt->salt[count] = g_b64Table[opt->salt[count] & 0x3f];
            }
        }
        opt->salt[count] = '\0';
        CRYPT_EAL_RandDeinitEx(NULL);
    }
    return HITLS_APP_SUCCESS;
}

static bool IsDigit(char *str)
{
    for (size_t i = 0; i < strlen(str); i++) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}

static long StrToDigit(char *str)
{
    long res = 0;
    for (size_t i = 0; i < strlen(str); i++) {
        res = res * REC_TEN + (str[i] - '0');
    }
    return res;
}

static char *SubStr(const char* srcStr, int32_t startPos, int32_t cutLen)
{
    if (srcStr == NULL || (size_t)startPos < 0 || cutLen < 0) {
        return NULL;
    }
    if (strlen(srcStr) < (size_t)startPos || strlen(srcStr) < (size_t)cutLen) {
        return NULL;
    }
    int32_t index = 0;
    static char destStr[REC_MAX_ARRAY_LEN] = {0};
    srcStr = srcStr + startPos;
    while (srcStr != NULL && index < cutLen) {
        destStr[index] = *srcStr++;
        if (*srcStr == '\0') {
            break;
        }
        index++;
    }
    return destStr;
}

// Parse the user salt value in the special format and obtain the core salt value.
// For example, "$6$rounds=100000$/q1Z/N8SXhnbS5p5$cipherText" or "$6$/q1Z/N8SXhnbS5p5$cipherText"
// This function parses a string and extracts a valid salt value as "/q1Z/N8SXhnbS5p5"
static bool ParseSalt(PasswdOpt *opt)
{
    if (strncmp((char *)opt->salt, "$6$", REC_PRE_TAG_LEN) != 0) {
        return false;
    }
    // cutting salt value head
    if (strlen((char *)opt->salt) < REC_PRE_TAG_LEN + 1) {
        return false;
    }
    uint8_t *restSalt = opt->salt + REC_PRE_TAG_LEN;
    // Check whether this part is the information about the number of iterations.
    if (strncmp((char *)restSalt, "rounds=", REC_PRE_ITER_LEN - 1) == 0) {
        // Check whether the number of iterations is valid and assign the value.
        if (strlen((char *)restSalt) < REC_PRE_ITER_LEN) {
            return false;
        }
        restSalt = restSalt + REC_PRE_ITER_LEN - 1;
        char *context = NULL;
        char *iterStr = strtok_s((char *)restSalt, "$", &context);
        if (iterStr == NULL || !IsDigit(iterStr)) {
            return false;
        }
        if (opt->iter != -1) {
            if (opt->iter != StrToDigit(iterStr)) {
                AppPrintError("Input iterations does not match the information in the salt string.\n");
                return false;
            }
        } else {
            long tmpIter = StrToDigit(iterStr);
            if (tmpIter < REC_MIN_ITER_TIMES || tmpIter > REC_MAX_ITER_TIMES) {
                AppPrintError("Invalid input iterations number, valid range[1000, 999999999].\n");
                return false;
            }
            opt->iter = tmpIter;
        }
        char *cipherText = NULL;
        char *tmpSalt = strtok_s(context, "$", &cipherText);
        if (tmpSalt == NULL || !IsSaltValid(tmpSalt)) {
            return false;
        }
        opt->salt = (uint8_t *)tmpSalt;
    } else {
        char *cipherText = NULL;
        char *tmpSalt = strtok_s((char *)restSalt, "$", &cipherText);
        if (tmpSalt == NULL || !IsSaltValid(tmpSalt)) {
            return false;
        }
        opt->salt = (uint8_t *)tmpSalt;
    }
    if (strlen((char *)opt->salt) > REC_MAX_SALTLEN) {
        opt->salt = (uint8_t *)SubStr((char *)opt->salt, 0, REC_MAX_SALTLEN);
    }
    return true;
}

static bool IsSaltValid(char *salt)
{
    if (salt == NULL || strlen(salt) == 0) {
        return false;
    }
    for (size_t i = 1; i < strlen(salt); i++) {
        if (salt[i] == '$') {
            return false;
        }
    }
    return true;
}

static bool IsSaltArgValid(PasswdOpt *opt)
{
    if (opt->salt[0] != '$') {
        // Salt value in non-encrypted format
        return IsSaltValid((char *)opt->salt);
    } else {
        // Salt value of the encryption format.
        return ParseSalt(opt);
    }
    return true;
}

static CRYPT_EAL_MdCTX *InitSha512Ctx(void)
{
    // Creating an MD Context
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, CRYPT_MD_SHA512, "provider=default");
    if (ctx == NULL) {
        return NULL;
    }
    if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

static int32_t B64EncToBuf(char *resBuf, uint32_t bufLen, uint32_t offset, uint8_t *hashBuf, uint32_t hashBufLen)
{
    if (resBuf == NULL || bufLen == 0 || hashBuf == NULL || hashBufLen < REC_HASH_BUF_LEN || offset > bufLen) {
        return HITLS_APP_INVALID_ARG;
    }
#define B64_FROM_24BIT(B3, B2, B1, N)                           \
    do {                                                        \
        uint32_t w = ((B3) << 16) | ((B2) << 8) | (B1);         \
        int32_t n = (N);                                        \
        while (n-- > 0 && bufLen > 0) {                         \
            *(resBuf + offset++) = g_b64Table[w & 0x3f];        \
            --bufLen;                                           \
            w >>= 6;                                            \
        }                                                       \
    } while (0)
    B64_FROM_24BIT (hashBuf[0], hashBuf[21], hashBuf[42], 4);
    B64_FROM_24BIT (hashBuf[22], hashBuf[43], hashBuf[1], 4);
    B64_FROM_24BIT (hashBuf[44], hashBuf[2], hashBuf[23], 4);
    B64_FROM_24BIT (hashBuf[3], hashBuf[24], hashBuf[45], 4);
    B64_FROM_24BIT (hashBuf[25], hashBuf[46], hashBuf[4], 4);
    B64_FROM_24BIT (hashBuf[47], hashBuf[5], hashBuf[26], 4);
    B64_FROM_24BIT (hashBuf[6], hashBuf[27], hashBuf[48], 4);
    B64_FROM_24BIT (hashBuf[28], hashBuf[49], hashBuf[7], 4);
    B64_FROM_24BIT (hashBuf[50], hashBuf[8], hashBuf[29], 4);
    B64_FROM_24BIT (hashBuf[9], hashBuf[30], hashBuf[51], 4);
    B64_FROM_24BIT (hashBuf[31], hashBuf[52], hashBuf[10], 4);
    B64_FROM_24BIT (hashBuf[53], hashBuf[11], hashBuf[32], 4);
    B64_FROM_24BIT (hashBuf[12], hashBuf[33], hashBuf[54], 4);
    B64_FROM_24BIT (hashBuf[34], hashBuf[55], hashBuf[13], 4);
    B64_FROM_24BIT (hashBuf[56], hashBuf[14], hashBuf[35], 4);
    B64_FROM_24BIT (hashBuf[15], hashBuf[36], hashBuf[57], 4);
    B64_FROM_24BIT (hashBuf[37], hashBuf[58], hashBuf[16], 4);
    B64_FROM_24BIT (hashBuf[59], hashBuf[17], hashBuf[38], 4);
    B64_FROM_24BIT (hashBuf[18], hashBuf[39], hashBuf[60], 4);
    B64_FROM_24BIT (hashBuf[40], hashBuf[61], hashBuf[19], 4);
    B64_FROM_24BIT (hashBuf[62], hashBuf[20], hashBuf[41], 4);
    B64_FROM_24BIT (0, 0, hashBuf[63], 2);
    if (bufLen <= 0) {
        return HITLS_APP_ENCODE_FAIL;
    } else {
        *(resBuf + offset) = '\0';
    }
    return CRYPT_SUCCESS;
}

static int32_t ResToBuf(PasswdOpt *opt, char *resBuf, uint32_t bufMaxLen, uint8_t *hashBuf, uint32_t hashBufLen)
{
    // construct the result string
    if (resBuf == NULL || bufMaxLen < REC_MIN_PREFIX_LEN) {
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t bufLen = bufMaxLen; // Remaining buffer size
    uint32_t offset = 0; // Number of characters in the prefix
    // algorithm identifier
    if (snprintf_s((char *)resBuf, bufLen, REC_PRE_TAG_LEN, "$%d$", opt->algTag) == -1) {
        return HITLS_APP_SECUREC_FAIL;
    }
    bufLen -= REC_PRE_TAG_LEN;
    offset += REC_PRE_TAG_LEN;
    // Determine whether to add the iteration times flag.
    if (opt->iter != -1) {
        uint32_t iterBit = 0;
        long tmpIter = opt->iter;
        while (tmpIter != 0) {
            tmpIter /= REC_TEN;
            iterBit++;
        }
        uint32_t totalLen = iterBit + REC_PRE_ITER_LEN;
        if (snprintf_s(resBuf + offset, bufLen, totalLen, "rounds=%ld$", opt->algTag) == -1) {
            return HITLS_APP_SECUREC_FAIL;
        }
        bufLen -= totalLen;
        offset += totalLen;
    }
    // Add Salt Value
    if (snprintf_s(resBuf + offset, bufLen, opt->saltLen + 1, "%s$", opt->salt) == -1) {
        return HITLS_APP_SECUREC_FAIL;
    }
    bufLen -= (opt->saltLen + 1);
    offset += (opt->saltLen + 1);
    if (B64EncToBuf(resBuf, bufLen, offset, hashBuf, hashBufLen) != CRYPT_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t Sha512Md2Hash(CRYPT_EAL_MdCTX *md2, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen)
{
    if (CRYPT_EAL_MdUpdate(md2, (uint8_t *)opt->pass, opt->passwdLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(md2, opt->salt, opt->saltLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(md2, (uint8_t *)opt->pass, opt->passwdLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdFinal(md2, resBuf, bufLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sha512Md1HashWithMd2(CRYPT_EAL_MdCTX *md1, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen)
{
    if (CRYPT_EAL_MdUpdate(md1, (uint8_t *)opt->pass, opt->passwdLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(md1, opt->salt, opt->saltLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_MdCTX *md2 = InitSha512Ctx();
    if (md2 == NULL) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint8_t md2_hash_res[REC_MAX_ARRAY_LEN] = {0};
    uint32_t md2_hash_len = REC_MAX_ARRAY_LEN;
    if (Sha512Md2Hash(md2, opt, md2_hash_res, &md2_hash_len) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(md2);
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_MdFreeCtx(md2);
    uint32_t times = opt->passwdLen / REC_SHA512_BLOCKSIZE;
    uint32_t restDataLen = opt->passwdLen % REC_SHA512_BLOCKSIZE;
    for (uint32_t i = 0; i < times; i++) {
        if (CRYPT_EAL_MdUpdate(md1, md2_hash_res, md2_hash_len) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    if (restDataLen != 0) {
        if (CRYPT_EAL_MdUpdate(md1, md2_hash_res, restDataLen) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    for (uint32_t count = opt->passwdLen; count > 0; count >>= 1) {
        if ((count & 1) != 0) {
            if (CRYPT_EAL_MdUpdate(md1, md2_hash_res, md2_hash_len) != CRYPT_SUCCESS) {
                return HITLS_APP_CRYPTO_FAIL;
            }
        } else {
            if (CRYPT_EAL_MdUpdate(md1, (uint8_t *)opt->pass, opt->passwdLen) != CRYPT_SUCCESS) {
                return HITLS_APP_CRYPTO_FAIL;
            }
        }
    }
    if (CRYPT_EAL_MdFinal(md1, resBuf, bufLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sha512MdPHash(CRYPT_EAL_MdCTX *mdP, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen)
{
    for (uint32_t i = opt->passwdLen; i > 0; i--) {
        if (CRYPT_EAL_MdUpdate(mdP, (uint8_t *)opt->pass, opt->passwdLen) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    if (CRYPT_EAL_MdFinal(mdP, resBuf, bufLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sha512MdSHash(CRYPT_EAL_MdCTX *mdS, PasswdOpt *opt, uint8_t *resBuf, uint32_t *bufLen, uint8_t nForMdS)
{
    for (int32_t count = 16 + nForMdS; count > 0; count--) {
        if (CRYPT_EAL_MdUpdate(mdS, opt->salt, opt->saltLen) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    if (CRYPT_EAL_MdFinal(mdS, resBuf, bufLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sha512GetMdPBuf(PasswdOpt *opt, uint8_t *mdPBuf, uint32_t mdPBufLen)
{
    CRYPT_EAL_MdCTX *mdP = InitSha512Ctx();
    if (mdP == NULL) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint32_t mdPBufMaxLen = REC_MAX_ARRAY_LEN;
    uint8_t mdP_hash_res[REC_MAX_ARRAY_LEN] = {0};
    uint32_t mdP_hash_len = REC_MAX_ARRAY_LEN; // The generated length is 64 characters.
    if (Sha512MdPHash(mdP, opt, mdP_hash_res, &mdP_hash_len) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(mdP);
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_MdFreeCtx(mdP);
    uint32_t cpyLen = 0;
    for (; mdPBufLen > REC_SHA512_BLOCKSIZE; mdPBufLen -= REC_SHA512_BLOCKSIZE) {
        if (strncpy_s((char *)(mdPBuf + cpyLen), mdPBufMaxLen, (char *)mdP_hash_res, mdP_hash_len) != EOK) {
            return HITLS_APP_SECUREC_FAIL;
        }
        cpyLen += mdP_hash_len;
        mdPBufMaxLen -= mdP_hash_len;
    }
    if (strncpy_s((char *)(mdPBuf + cpyLen), mdPBufMaxLen, (char *)mdP_hash_res, mdPBufLen) != EOK) {
        return HITLS_APP_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sha512GetMdSBuf(PasswdOpt *opt, uint8_t *mdSBuf, uint32_t mdSBufLen, uint8_t nForMdS)
{
    CRYPT_EAL_MdCTX *mdS = InitSha512Ctx();
    if (mdS == NULL) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint32_t mdSBufMaxLen = REC_MAX_ARRAY_LEN;
    uint8_t mdS_hash_res[REC_MAX_ARRAY_LEN] = {0};
    uint32_t mdS_hash_len = REC_MAX_ARRAY_LEN; // The generated length is 64 characters.
    if (Sha512MdSHash(mdS, opt, mdS_hash_res, &mdS_hash_len, nForMdS) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(mdS);
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_MdFreeCtx(mdS);
    uint32_t cpyLen = 0;
    for (; mdSBufLen > REC_SHA512_BLOCKSIZE; mdSBufLen -= REC_SHA512_BLOCKSIZE) {
        if (strncpy_s((char *)(mdSBuf + cpyLen), mdSBufMaxLen, (char *)mdS_hash_res, mdS_hash_len) != EOK) {
            return HITLS_APP_SECUREC_FAIL;
        }
        cpyLen += mdS_hash_len;
        mdSBufMaxLen -= mdS_hash_len;
    }
    if (strncpy_s((char *)(mdSBuf + cpyLen), mdSBufMaxLen, (char *)mdS_hash_res, mdSBufLen) != EOK) {
        return HITLS_APP_SECUREC_FAIL;
    }
    mdSBufLen = opt->saltLen;
    return CRYPT_SUCCESS;
}

static int32_t Sha512IterHash(long rounds, BufLen *md1HashRes, BufLen *mdPBuf, BufLen *mdSBuf)
{
    uint32_t md1HashLen = md1HashRes->bufLen;
    uint32_t mdPBufLen = mdPBuf->bufLen;
    uint32_t mdSBufLen = mdSBuf->bufLen;
    for (long round = 0; round < rounds; round++) {
        CRYPT_EAL_MdCTX *md_r = InitSha512Ctx();
        if (md_r == NULL) {
            return HITLS_APP_CRYPTO_FAIL;
        }
        uint32_t ret = CRYPT_SUCCESS;
        if (round % REC_TWO != 0) {
            if ((ret = CRYPT_EAL_MdUpdate(md_r, mdPBuf->buf, mdPBufLen)) != CRYPT_SUCCESS) {
                goto iterEnd;
            }
        } else {
            if ((ret = CRYPT_EAL_MdUpdate(md_r, md1HashRes->buf, md1HashLen)) != CRYPT_SUCCESS) {
                goto iterEnd;
            }
        }
        if (round % REC_THREE != 0) {
            if ((ret = CRYPT_EAL_MdUpdate(md_r, mdSBuf->buf, mdSBufLen)) != CRYPT_SUCCESS) {
                goto iterEnd;
            }
        }
        if (round % REC_SEVEN != 0) {
            if ((ret = CRYPT_EAL_MdUpdate(md_r, mdPBuf->buf, mdPBufLen)) != CRYPT_SUCCESS) {
                goto iterEnd;
            }
        }
        if (round % REC_TWO != 0) {
            if ((ret = CRYPT_EAL_MdUpdate(md_r, md1HashRes->buf, md1HashLen)) != CRYPT_SUCCESS) {
                goto iterEnd;
            }
        } else {
            if ((ret = CRYPT_EAL_MdUpdate(md_r, mdPBuf->buf, mdPBufLen)) != CRYPT_SUCCESS) {
                goto iterEnd;
            }
        }
        ret = CRYPT_EAL_MdFinal(md_r, md1HashRes->buf, &md1HashLen);
        iterEnd:
        CRYPT_EAL_MdFreeCtx(md_r);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t Sha512MdCrypt(PasswdOpt *opt, char *resBuf, uint32_t bufLen)
{
    CRYPT_EAL_MdCTX *md1 = InitSha512Ctx();
    if (md1 == NULL) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint8_t md1_hash_res[REC_MAX_ARRAY_LEN] = {0};
    uint32_t md1_hash_len = REC_MAX_ARRAY_LEN; // The generated length is 64 characters.
    if (Sha512Md1HashWithMd2(md1, opt, md1_hash_res, &md1_hash_len) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(md1);
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_MdFreeCtx(md1);
    uint8_t mdP_buf[REC_MAX_ARRAY_LEN] = {0};
    uint32_t mdP_buf_len = opt->passwdLen;
    if (Sha512GetMdPBuf(opt, mdP_buf, mdP_buf_len) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    uint8_t mdS_buf[REC_MAX_ARRAY_LEN] = {0};
    uint32_t mdS_buf_len = opt->saltLen;
    if (Sha512GetMdSBuf(opt, mdS_buf, mdS_buf_len, md1_hash_res[0]) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    long rounds = (opt->iter == -1) ? 5000 : opt->iter;
    BufLen md1HasnResBuf = {.buf = md1_hash_res, .bufLen = md1_hash_len};
    BufLen mdPBuf = {.buf = mdP_buf, .bufLen = mdP_buf_len};
    BufLen mdSBuf = {.buf = mdS_buf, .bufLen = mdS_buf_len};
    if (Sha512IterHash(rounds, &md1HasnResBuf, &mdPBuf, &mdSBuf) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (ResToBuf(opt, resBuf, bufLen, md1_hash_res, md1_hash_len) != HITLS_APP_SUCCESS) {
        return HITLS_APP_ENCODE_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sha512Crypt(PasswdOpt *opt, char *resBuf, uint32_t bufMaxLen)
{
    if (opt->pass == NULL || opt->salt == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    if (opt->algTag != REC_SHA512_ALGTAG && opt->algTag != REC_SHA256_ALGTAG && opt->algTag != REC_MD5_ALGTAG) {
        return HITLS_APP_INVALID_ARG;
    }
    if (!IsSaltArgValid(opt)) {
        return HITLS_APP_INVALID_ARG;
    }
    int32_t shaRet = HITLS_APP_SUCCESS;
    if ((shaRet = Sha512MdCrypt(opt, resBuf, bufMaxLen)) != HITLS_APP_SUCCESS) {
        return shaRet;
    }
    return shaRet;
}

static int32_t OutputResult(BSL_UIO *outUio, char *resBuf, uint32_t bufLen)
{
    uint32_t writeLen = 0;
    if (BSL_UIO_Write(outUio, resBuf, bufLen, &writeLen) != BSL_SUCCESS || writeLen == 0) {
        return HITLS_APP_UIO_FAIL;
    }
    if (BSL_UIO_Write(outUio, "\n", 1, &writeLen) != BSL_SUCCESS || writeLen == 0) {
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}
