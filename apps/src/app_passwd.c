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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "app_errno.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_utils.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_ui.h"
#include "bsl_uio.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"

#define PASSWD_SHA_CRYPT_DEFAULT_ROUNDS 5000
#define PASSWD_SHA_CRYPT_MIN_ROUNDS 1000
#define PASSWD_SHA_CRYPT_MAX_ROUNDS 999999999
#define PASSWD_SHA_CRYPT_ROUNDS_BUF_LEN sizeof("rounds=999999999$")
#define PASSWD_SHA_CRYPT_ROUNDS_PREFIX "rounds="
#define PASSWD_SHA_CRYPT_ROUNDS_PREFIX_LEN (sizeof(PASSWD_SHA_CRYPT_ROUNDS_PREFIX) - 1)
#define PASSWD_PASSWORD_MAX_LEN 256
#define PASSWD_PASSWORD_BUF_LEN (PASSWD_PASSWORD_MAX_LEN + 1)
#define PASSWD_SALT_MAX_LEN 16
#define PASSWD_SHA512_DIGEST_LEN 64
#define PASSWD_SHA512_CRYPT_B64_LEN 86
#define PASSWD_CRYPT_RESULT_BUF_LEN 128
#define PASSWD_STDIN_READ_BUF_LEN 128
#define PASSWD_CRYPT_B64_MASK 0x3f

typedef enum {
    HITLS_APP_OPT_PASSWD_ERR = HITLS_APP_OPT_ERR,
    HITLS_APP_OPT_PASSWD_EOF = HITLS_APP_OPT_EOF,
    HITLS_APP_OPT_PASSWD_PASSWORD = HITLS_APP_OPT_PARAM,
    HITLS_APP_OPT_PASSWD_HELP = HITLS_APP_OPT_HELP,
    HITLS_APP_OPT_PASSWD_SALT,
    HITLS_APP_OPT_PASSWD_ROUNDS,
    HITLS_APP_OPT_PASSWD_NOVERIFY,
    HITLS_APP_OPT_PASSWD_STDIN,
} HITLS_PasswdOptType;

typedef struct {
    uint32_t rounds;
    char salt[PASSWD_SALT_MAX_LEN + 1];
    char *password;
    bool useStdin;
    bool noVerify;
    bool saltSet;
    bool roundsSet;
} PasswdCmdOpt;

typedef int32_t (*OptHandleFunc)(PasswdCmdOpt *);

typedef struct {
    int32_t optType;
    OptHandleFunc func;
} OptHandleTable;

typedef struct {
    int32_t mdId;
    const char *prefix;
    uint32_t digestLen;
    uint32_t cryptB64Len;
} ShaCryptInfo;

typedef struct {
    const ShaCryptInfo *info;
    BSL_Buffer password;
    BSL_Buffer salt;
    uint32_t rounds;
    bool roundsSet;
} ShaCryptParam;

typedef struct {
    char data[PASSWD_PASSWORD_BUF_LEN];
    uint32_t len;
} PasswdLine;

static const HITLS_CmdOption g_passwdOpts[] = {
    {"help", HITLS_APP_OPT_PASSWD_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"salt", HITLS_APP_OPT_PASSWD_SALT, HITLS_APP_OPT_VALUETYPE_STRING,
        "Use the specified [rounds=N$]salt (salt must not be empty)"},
    {"rounds", HITLS_APP_OPT_PASSWD_ROUNDS, HITLS_APP_OPT_VALUETYPE_UINT, "Set SHA-crypt rounds"},
    {"noverify", HITLS_APP_OPT_PASSWD_NOVERIFY, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
        "Do not verify terminal password input"},
    {"stdin", HITLS_APP_OPT_PASSWD_STDIN, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Read passwords from stdin"},
    {"password", HITLS_APP_OPT_PASSWD_PASSWORD, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Password string"},
    {NULL, 0, 0, NULL}
};

static const char g_cryptBase64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static const ShaCryptInfo g_sha512CryptInfo = {CRYPT_MD_SHA512, "$6$", PASSWD_SHA512_DIGEST_LEN,
    PASSWD_SHA512_CRYPT_B64_LEN};

static bool ParseSaltRounds(const char *saltSetting, uint32_t *rounds, char *salt)
{
    const char *saltStart = saltSetting;
    bool roundsSet = false;
    if (strncmp(saltSetting, PASSWD_SHA_CRYPT_ROUNDS_PREFIX, PASSWD_SHA_CRYPT_ROUNDS_PREFIX_LEN) == 0) {
        const char *cur = saltSetting + PASSWD_SHA_CRYPT_ROUNDS_PREFIX_LEN;
        if (*cur >= '0' && *cur <= '9') {
            uint32_t value = 0;
            bool exceedsMax = false;
            for (; *cur >= '0' && *cur <= '9'; cur++) {
                uint32_t digit = (uint32_t)(*cur - '0');
                uint32_t maxRounds = PASSWD_SHA_CRYPT_MAX_ROUNDS;
                if (value > maxRounds / 10 || (value == maxRounds / 10 && digit > maxRounds % 10)) {
                    exceedsMax = true;
                    continue;
                }
                value = value * 10 + digit;
            }
            if (*cur == '$') {
                if (exceedsMax || value > PASSWD_SHA_CRYPT_MAX_ROUNDS) {
                    value = PASSWD_SHA_CRYPT_MAX_ROUNDS;
                } else if (value < PASSWD_SHA_CRYPT_MIN_ROUNDS) {
                    value = PASSWD_SHA_CRYPT_MIN_ROUNDS;
                }
                *rounds = value;
                saltStart = cur + 1;
                roundsSet = true;
            }
        }
    }

    uint32_t saltLen = 0;
    for (; saltStart[saltLen] != '\0' && saltStart[saltLen] != '$' && saltLen < PASSWD_SALT_MAX_LEN; saltLen++) {
        salt[saltLen] = saltStart[saltLen];
    }
    salt[saltLen] = '\0';
    return roundsSet;
}

static int32_t ParseSaltSetting(PasswdCmdOpt *passwdOpt)
{
    if (passwdOpt->saltSet) {
        AppPrintError("passwd: salt cannot be specified more than once.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    const char *saltStr = HITLS_APP_OptGetValueStr();
    uint32_t rounds = 0;
    char salt[PASSWD_SALT_MAX_LEN + 1] = {0};
    bool roundsInSalt = ParseSaltRounds(saltStr, &rounds, salt);
    if (roundsInSalt && passwdOpt->roundsSet) {
        AppPrintError("passwd: rounds cannot be specified more than once.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (salt[0] == '\0') {
        AppPrintError("passwd: Invalid salt.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (roundsInSalt) {
        passwdOpt->rounds = rounds;
        passwdOpt->roundsSet = true;
    }
    (void)memcpy(passwdOpt->salt, salt, sizeof(salt));
    passwdOpt->saltSet = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ParseRestArgs(PasswdCmdOpt *passwdOpt)
{
    int32_t restOptNum = HITLS_APP_GetRestOptNum();
    char **restOpt = HITLS_APP_GetRestOpt();

    if (restOptNum == 0) {
        return HITLS_APP_SUCCESS;
    }
    if (restOptNum != 1) {
        AppPrintError("passwd: Extra arguments given.\n");
        AppPrintError("passwd: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }

    passwdOpt->password = restOpt[0];
    return HITLS_APP_SUCCESS;
}

static int32_t CheckPasswdOptions(const PasswdCmdOpt *passwdOpt)
{
    if (passwdOpt->useStdin && passwdOpt->password != NULL) {
        AppPrintError("passwd: -stdin cannot be used with password argument.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    if (passwdOpt->roundsSet &&
        (passwdOpt->rounds < PASSWD_SHA_CRYPT_MIN_ROUNDS || passwdOpt->rounds > PASSWD_SHA_CRYPT_MAX_ROUNDS)) {
        AppPrintError("passwd: Invalid rounds.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandleOptErr(PasswdCmdOpt *passwdOpt)
{
    (void)passwdOpt;
    AppPrintError("passwd: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t DisplayHelp(PasswdCmdOpt *passwdOpt)
{
    (void)passwdOpt;
    HITLS_APP_OptHelpPrint(g_passwdOpts);
    return HITLS_APP_HELP;
}

static int32_t ParseRounds(PasswdCmdOpt *passwdOpt)
{
    uint32_t rounds = 0;
    if (HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), &rounds) != HITLS_APP_SUCCESS) {
        AppPrintError("passwd: Invalid rounds.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (passwdOpt->roundsSet) {
        AppPrintError("passwd: rounds cannot be specified more than once.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    passwdOpt->rounds = rounds;
    passwdOpt->roundsSet = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ParseNoVerify(PasswdCmdOpt *passwdOpt)
{
    passwdOpt->noVerify = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ParseStdin(PasswdCmdOpt *passwdOpt)
{
    passwdOpt->useStdin = true;
    return HITLS_APP_SUCCESS;
}

static const OptHandleTable OPT_HANDLE_TABLE[] = {
    {HITLS_APP_OPT_PASSWD_ERR,      HandleOptErr},
    {HITLS_APP_OPT_PASSWD_HELP,     DisplayHelp},
    {HITLS_APP_OPT_PASSWD_SALT,     ParseSaltSetting},
    {HITLS_APP_OPT_PASSWD_ROUNDS,   ParseRounds},
    {HITLS_APP_OPT_PASSWD_NOVERIFY, ParseNoVerify},
    {HITLS_APP_OPT_PASSWD_STDIN,    ParseStdin}
};

static int32_t OptParse(PasswdCmdOpt *passwdOpt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    int32_t optType = HITLS_APP_OPT_PASSWD_ERR;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_PASSWD_EOF) {
        for (size_t i = 0; i < (sizeof(OPT_HANDLE_TABLE) / sizeof(OPT_HANDLE_TABLE[0])); i++) {
            if (optType != OPT_HANDLE_TABLE[i].optType) {
                continue;
            }
            ret = OPT_HANDLE_TABLE[i].func(passwdOpt);
            if (ret != HITLS_APP_SUCCESS) {
                return ret;
            }
            break;
        }
    }

    ret = ParseRestArgs(passwdOpt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    return CheckPasswdOptions(passwdOpt);
}

static int32_t GenerateSalt(char *salt, uint32_t *saltLen)
{
    if (salt == NULL || saltLen == NULL || *saltLen < PASSWD_SALT_MAX_LEN + 1) {
        return HITLS_APP_INVALID_ARG;
    }
    uint8_t rnd[PASSWD_SALT_MAX_LEN] = {0};
    int32_t mainRet = HITLS_APP_CRYPTO_FAIL;
    int32_t ret = CRYPT_EAL_RandbytesEx(NULL, rnd, sizeof(rnd));
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }
    for (uint32_t i = 0; i < PASSWD_SALT_MAX_LEN; i++) {
        salt[i] = g_cryptBase64[rnd[i] & PASSWD_CRYPT_B64_MASK];
    }
    salt[PASSWD_SALT_MAX_LEN] = '\0';
    *saltLen = PASSWD_SALT_MAX_LEN;
    mainRet = HITLS_APP_SUCCESS;

end:
    BSL_SAL_CleanseData(rnd, sizeof(rnd));
    return mainRet;
}

static int32_t GenerateAltDigest(CRYPT_EAL_MdCtx *ctx, const BSL_Buffer *password,
    const BSL_Buffer *salt, BSL_Buffer *alt)
{
    uint32_t digestLen = alt->dataLen;
    if (CRYPT_EAL_MdDeinit(ctx) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(ctx, password->data, password->dataLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(ctx, salt->data, salt->dataLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(ctx, password->data, password->dataLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdFinal(ctx, alt->data, &digestLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GenerateRepeatedDigestBytes(CRYPT_EAL_MdCtx *ctx, const BSL_Buffer *data,
    uint32_t repeat, BSL_Buffer *out, uint32_t digestLen)
{
    uint8_t digest[PASSWD_SHA512_DIGEST_LEN] = {0};
    int32_t ret = HITLS_APP_CRYPTO_FAIL;
    uint32_t mdOutLen = digestLen;
    if (digestLen == 0 || digestLen > sizeof(digest)) {
        goto end;
    }
    if (CRYPT_EAL_MdDeinit(ctx) != CRYPT_SUCCESS) {
        goto end;
    }
    if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
        goto end;
    }
    for (uint32_t i = 0; i < repeat; i++) {
        if (CRYPT_EAL_MdUpdate(ctx, data->data, data->dataLen) != CRYPT_SUCCESS) {
            goto end;
        }
    }
    if (CRYPT_EAL_MdFinal(ctx, digest, &mdOutLen) != CRYPT_SUCCESS) {
        goto end;
    }
    for (uint32_t i = 0; i < out->dataLen; i++) {
        out->data[i] = digest[i % digestLen];
    }
    ret = HITLS_APP_SUCCESS;

end:
    BSL_SAL_CleanseData(digest, sizeof(digest));
    return ret;
}

static int32_t GenerateInitialDigest(CRYPT_EAL_MdCtx *ctx, const BSL_Buffer *password,
    const BSL_Buffer *salt, BSL_Buffer *alt)
{
    uint32_t digestLen = alt->dataLen;
    if (CRYPT_EAL_MdDeinit(ctx) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(ctx, password->data, password->dataLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (CRYPT_EAL_MdUpdate(ctx, salt->data, salt->dataLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }

    uint32_t cnt = password->dataLen;
    while (cnt > alt->dataLen) {
        if (CRYPT_EAL_MdUpdate(ctx, alt->data, alt->dataLen) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
        cnt -= alt->dataLen;
    }
    if (cnt != 0 && CRYPT_EAL_MdUpdate(ctx, alt->data, cnt) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }

    for (cnt = password->dataLen; cnt > 0; cnt >>= 1) {
        int32_t mdRet = (cnt & 1) ? CRYPT_EAL_MdUpdate(ctx, alt->data, alt->dataLen) :
            CRYPT_EAL_MdUpdate(ctx, password->data, password->dataLen);
        if (mdRet != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    if (CRYPT_EAL_MdFinal(ctx, alt->data, &digestLen) != CRYPT_SUCCESS) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t RunShaCryptRounds(CRYPT_EAL_MdCtx *ctx, const BSL_Buffer *pBytes,
    const BSL_Buffer *sBytes, BSL_Buffer *alt, uint32_t rounds)
{
    for (uint32_t i = 0; i < rounds; i++) {
        uint32_t digestLen = alt->dataLen;
        if (CRYPT_EAL_MdDeinit(ctx) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
        if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
        int32_t mdRet = (i & 1) ? CRYPT_EAL_MdUpdate(ctx, pBytes->data, pBytes->dataLen) :
            CRYPT_EAL_MdUpdate(ctx, alt->data, alt->dataLen);
        if (mdRet != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
        if ((i % 3) != 0) {
            if (CRYPT_EAL_MdUpdate(ctx, sBytes->data, sBytes->dataLen) != CRYPT_SUCCESS) {
                return HITLS_APP_CRYPTO_FAIL;
            }
        }
        if ((i % 7) != 0) {
            if (CRYPT_EAL_MdUpdate(ctx, pBytes->data, pBytes->dataLen) != CRYPT_SUCCESS) {
                return HITLS_APP_CRYPTO_FAIL;
            }
        }
        mdRet = (i & 1) ? CRYPT_EAL_MdUpdate(ctx, alt->data, alt->dataLen) :
            CRYPT_EAL_MdUpdate(ctx, pBytes->data, pBytes->dataLen);
        if (mdRet != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
        if (CRYPT_EAL_MdFinal(ctx, alt->data, &digestLen) != CRYPT_SUCCESS) {
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AppendData(char *out, uint32_t outLen, uint32_t *pos, const void *data, uint32_t dataLen)
{
    if (*pos >= outLen || dataLen >= outLen - *pos) {
        return HITLS_APP_UIO_FAIL;
    }
    (void)memcpy(out + *pos, data, dataLen);
    *pos += dataLen;
    out[*pos] = '\0';
    return HITLS_APP_SUCCESS;
}

static int32_t AppendStr(char *out, uint32_t outLen, uint32_t *pos, const char *str)
{
    return AppendData(out, outLen, pos, str, (uint32_t)strlen(str));
}

static int32_t AppendCryptB64Group(char *out, uint32_t outLen, uint32_t *pos,
    uint8_t b2, uint8_t b1, uint8_t b0, uint32_t charCount)
{
    uint32_t value = ((uint32_t)b2 << 16) | ((uint32_t)b1 << 8) | b0;
    while (charCount-- > 0) {
        if (*pos + 1 >= outLen) {
            return HITLS_APP_UIO_FAIL;
        }
        out[*pos] = g_cryptBase64[value & PASSWD_CRYPT_B64_MASK];
        (*pos)++;
        out[*pos] = '\0';
        value >>= 6;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CryptBase64EncodeSha512(char *out, uint32_t outLen, uint32_t *pos, const uint8_t *digest)
{
    static const uint8_t groups[][3] = {
        {0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26},
        {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
        {12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16},
        {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41},
    };
    for (uint32_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
        int32_t ret = AppendCryptB64Group(out, outLen, pos, digest[groups[i][0]], digest[groups[i][1]],
            digest[groups[i][2]], 4);
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
    }
    return AppendCryptB64Group(out, outLen, pos, 0, 0, digest[63], 2);
}

static int32_t FormatShaCryptOutput(const ShaCryptParam *param, const BSL_Buffer *digest, char *out, uint32_t outLen)
{
    const ShaCryptInfo *info = param->info;
    const BSL_Buffer *salt = &param->salt;
    char roundsBuf[PASSWD_SHA_CRYPT_ROUNDS_BUF_LEN] = {0};
    uint32_t roundsLen = 0;
    if (digest->dataLen != info->digestLen) {
        return HITLS_APP_INVALID_ARG;
    }

    uint32_t pos = 0;
    int32_t ret = AppendStr(out, outLen, &pos, info->prefix);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (param->roundsSet) {
        int32_t len = snprintf(roundsBuf, sizeof(roundsBuf), "rounds=%u$", (unsigned int)param->rounds);
        if (len <= 0 || (uint32_t)len >= sizeof(roundsBuf)) {
            return HITLS_APP_INVALID_ARG;
        }
        roundsLen = (uint32_t)len;
        ret = AppendStr(out, outLen, &pos, roundsBuf);
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
    }
    ret = AppendData(out, outLen, &pos, salt->data, salt->dataLen);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = AppendStr(out, outLen, &pos, "$");
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = CryptBase64EncodeSha512(out, outLen, &pos, digest->data);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (pos != strlen(info->prefix) + roundsLen + salt->dataLen + 1 + info->cryptB64Len) {
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ShaCrypt(const ShaCryptParam *param, char *out, uint32_t outLen)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *alt = NULL;
    uint8_t *pBytes = NULL;
    uint8_t *sBytes = NULL;
    CRYPT_EAL_MdCtx *ctx = NULL;
    uint32_t passLen = param->password.dataLen;
    uint32_t saltLen = param->salt.dataLen;
    const ShaCryptInfo *info = param->info;

    alt = (uint8_t *)BSL_SAL_Malloc(info->digestLen);
    pBytes = (uint8_t *)BSL_SAL_Malloc(passLen);
    sBytes = (uint8_t *)BSL_SAL_Malloc(saltLen);
    if (alt == NULL || pBytes == NULL || sBytes == NULL) {
        ret = HITLS_APP_MEM_ALLOC_FAIL;
        goto end;
    }
    BSL_Buffer altBuf = {alt, info->digestLen};
    BSL_Buffer pBytesBuf = {pBytes, passLen};
    BSL_Buffer sBytesBuf = {sBytes, saltLen};

    ctx = CRYPT_EAL_MdNewCtx(info->mdId);
    if (ctx == NULL) {
        ret = HITLS_APP_CRYPTO_FAIL;
        goto end;
    }

    ret = GenerateAltDigest(ctx, &param->password, &param->salt, &altBuf);
    if (ret != HITLS_APP_SUCCESS) {
        goto end;
    }
    ret = GenerateInitialDigest(ctx, &param->password, &param->salt, &altBuf);
    if (ret != HITLS_APP_SUCCESS) {
        goto end;
    }
    ret = GenerateRepeatedDigestBytes(ctx, &param->password, passLen, &pBytesBuf, info->digestLen);
    if (ret != HITLS_APP_SUCCESS) {
        goto end;
    }
    ret = GenerateRepeatedDigestBytes(ctx, &param->salt, 16 + altBuf.data[0], &sBytesBuf, info->digestLen);
    if (ret != HITLS_APP_SUCCESS) {
        goto end;
    }
    ret = RunShaCryptRounds(ctx, &pBytesBuf, &sBytesBuf, &altBuf, param->rounds);
    if (ret != HITLS_APP_SUCCESS) {
        goto end;
    }
    ret = FormatShaCryptOutput(param, &altBuf, out, outLen);

end:
    if (ret == HITLS_APP_CRYPTO_FAIL) {
        AppPrintError("passwd: Failed to generate password hash.\n");
    }
    if (ctx != NULL) {
        CRYPT_EAL_MdDeinit(ctx);
        CRYPT_EAL_MdFreeCtx(ctx);
    }
    BSL_SAL_ClearFree(alt, info->digestLen);
    BSL_SAL_ClearFree(pBytes, passLen);
    BSL_SAL_ClearFree(sBytes, saltLen);
    return ret;
}

static int32_t PrintPasswdResult(BSL_UIO *outUio, const PasswdCmdOpt *passwdOpt,
    const char *password, uint32_t passLen)
{
    if (passwdOpt == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    if (passLen == 0) {
        int32_t ret = AppPrint(outUio, "<NULL>\n");
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("passwd: Failed to print password hash.\n");
            return HITLS_APP_UIO_FAIL;
        }
        return HITLS_APP_SUCCESS;
    }

    char generatedSalt[PASSWD_SALT_MAX_LEN + 1] = {0};
    const char *cryptSalt = passwdOpt->salt;
    uint32_t cryptSaltLen = (uint32_t)strlen(cryptSalt);
    int32_t ret = HITLS_APP_SUCCESS;
    if (cryptSaltLen == 0) {
        cryptSaltLen = sizeof(generatedSalt);
        ret = GenerateSalt(generatedSalt, &cryptSaltLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("passwd: Failed to generate salt.\n");
        } else {
            cryptSalt = generatedSalt;
        }
    }
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    char cryptResult[PASSWD_CRYPT_RESULT_BUF_LEN] = {0};
    ShaCryptParam param = {
        .info = &g_sha512CryptInfo,
        .password = {(uint8_t *)(uintptr_t)password, passLen},
        .salt = {(uint8_t *)(uintptr_t)cryptSalt, cryptSaltLen},
        .rounds = passwdOpt->rounds,
        .roundsSet = passwdOpt->roundsSet,
    };
    ret = ShaCrypt(&param, cryptResult, sizeof(cryptResult));
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = AppPrint(outUio, "%s\n", cryptResult);
    BSL_SAL_CleanseData(cryptResult, sizeof(cryptResult));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("passwd: Failed to print password hash.\n");
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static void PrintPasswdTruncatedWarning(void)
{
    AppPrintError("passwd: Warning: truncating password to %u bytes.\n",
        (unsigned int)PASSWD_PASSWORD_MAX_LEN);
}

static int32_t ProcessPasswordArg(BSL_UIO *outUio, const PasswdCmdOpt *passwdOpt)
{
    const char *password = passwdOpt->password;
    uint32_t passwordLen = (uint32_t)strnlen(password, PASSWD_PASSWORD_BUF_LEN);
    if (passwordLen > PASSWD_PASSWORD_MAX_LEN) {
        PrintPasswdTruncatedWarning();
        passwordLen = PASSWD_PASSWORD_MAX_LEN;
    }
    return PrintPasswdResult(outUio, passwdOpt, password, passwordLen);
}

static void AppendLineData(PasswdLine *line, const char *data, uint32_t dataLen)
{
    uint32_t leftLen = line->len < PASSWD_PASSWORD_MAX_LEN ? PASSWD_PASSWORD_MAX_LEN - line->len : 0;
    if (dataLen > leftLen) {
        dataLen = leftLen;
    }
    if (dataLen != 0) {
        (void)memcpy(line->data + line->len, data, dataLen);
        line->len += dataLen;
    }
    line->data[line->len] = '\0';
}

static int32_t ReadPasswdFromStdin(BSL_UIO *readUio, PasswdLine *line, bool *hasLine)
{
    char buf[PASSWD_STDIN_READ_BUF_LEN] = {0};
    int32_t mainRet = HITLS_APP_SUCCESS;

    line->len = 0;
    line->data[0] = '\0';
    *hasLine = false;

    while (true) {
        uint32_t readLen = sizeof(buf);
        (void)memset(buf, 0, sizeof(buf));
        int32_t ret = BSL_UIO_Gets(readUio, buf, &readLen);
        if (ret != BSL_SUCCESS) {
            AppPrintError("passwd: Failed to read password.\n");
            mainRet = HITLS_APP_STDIN_FAIL;
            goto end;
        }
        if (readLen == 0) {
            goto end;
        }

        *hasLine = true;
        bool hasNewLine = (buf[readLen - 1] == '\n');
        uint32_t dataLen = hasNewLine ? readLen - 1 : readLen;
        AppendLineData(line, buf, dataLen);
        if (hasNewLine) {
            goto end;
        }
    }

end:
    BSL_SAL_CleanseData(buf, sizeof(buf));
    return mainRet;
}

static int32_t ProcessStdin(BSL_UIO *outUio, const PasswdCmdOpt *passwdOpt)
{
    PasswdLine line = {0};
    bool hasLine = false;
    BSL_UIO *readUio = HITLS_APP_UioOpen(NULL, 'r', 0);
    if (readUio == NULL) {
        AppPrintError("passwd: Failed to open stdin.\n");
        return HITLS_APP_UIO_FAIL;
    }

    int32_t ret = HITLS_APP_SUCCESS;
    while (true) {
        ret = ReadPasswdFromStdin(readUio, &line, &hasLine);
        if (ret != HITLS_APP_SUCCESS || !hasLine) {
            break;
        }
        ret = PrintPasswdResult(outUio, passwdOpt, line.data, line.len);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
    }

    BSL_UIO_Free(readUio);
    BSL_SAL_CleanseData(&line, sizeof(line));
    return ret;
}

static int32_t ProcessTerminal(BSL_UIO *outUio, const PasswdCmdOpt *passwdOpt)
{
    char password[APP_MAX_PASS_LENGTH + 1] = {0};
    uint32_t buffLen = sizeof(password);
    uint32_t passwordLen = 0;
    BSL_UI_ReadPwdParam passParam = {"password", NULL, !passwdOpt->noVerify};
    int32_t ret = HITLS_APP_SUCCESS;

    if (BSL_UI_ReadPwdUtil(&passParam, password, &buffLen, NULL, NULL) != BSL_SUCCESS) {
        AppPrintError("passwd: Failed to read password.\n");
        ret = HITLS_APP_STDIN_FAIL;
        goto end;
    }
    if (buffLen == 0) {
        AppPrintError("passwd: Failed to read password.\n");
        ret = HITLS_APP_STDIN_FAIL;
        goto end;
    }
    passwordLen = buffLen - 1;
    if (passwordLen > PASSWD_PASSWORD_MAX_LEN) {
        PrintPasswdTruncatedWarning();
        passwordLen = PASSWD_PASSWORD_MAX_LEN;
    }
    ret = PrintPasswdResult(outUio, passwdOpt, password, passwordLen);

end:
    BSL_SAL_CleanseData(password, sizeof(password));
    return ret;
}

static int32_t ProcessPasswords(PasswdCmdOpt *passwdOpt)
{
    BSL_UIO *outUio = HITLS_APP_UioOpen(NULL, 'w', 0);
    if (outUio == NULL) {
        AppPrintError("passwd: Failed to open output.\n");
        return HITLS_APP_UIO_FAIL;
    }

    int32_t ret;
    if (passwdOpt->password != NULL) {
        ret = ProcessPasswordArg(outUio, passwdOpt);
    } else if (passwdOpt->useStdin) {
        ret = ProcessStdin(outUio, passwdOpt);
    } else {
        ret = ProcessTerminal(outUio, passwdOpt);
    }

    BSL_UIO_Free(outUio);
    return ret;
}

int32_t HITLS_PasswdMain(int argc, char *argv[])
{
    int32_t mainRet = HITLS_APP_SUCCESS;
    PasswdCmdOpt passwdOpt = {
        .rounds = PASSWD_SHA_CRYPT_DEFAULT_ROUNDS,
    };

    mainRet = HITLS_APP_OptBegin(argc, argv, g_passwdOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }

    mainRet = OptParse(&passwdOpt);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }

    if (!passwdOpt.saltSet) {
        mainRet = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
        if (mainRet != CRYPT_SUCCESS) {
            AppPrintError("passwd: Failed to initialize the random number, errCode = 0x%x.\n", mainRet);
            mainRet = HITLS_APP_CRYPTO_FAIL;
            goto end;
        }
    }

    mainRet = ProcessPasswords(&passwdOpt);

end:
    if (!passwdOpt.saltSet) {
        CRYPT_EAL_RandDeinitEx(NULL);
    }
    HITLS_APP_OptEnd();
    return mainRet;
}
