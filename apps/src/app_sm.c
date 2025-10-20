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
#include "app_sm.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#ifdef HITLS_APP_SM_MODE
#include <unistd.h>
#endif
#include <securec.h>
#include "bsl_bytes.h"
#include "bsl_ui.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "sal_file.h"
#include "app_errno.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_utils.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_cmvp.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_cmvp_selftest.h"

#ifdef HITLS_APP_SM_MODE

#define HITLS_APP_SM_USER_FILE_NAME "openhitls_user"

#define HITLS_APP_SM_VERSION 1
#define HITLS_APP_SM_DERIVE_MAC_ID CRYPT_MAC_HMAC_SM3
#define HITLS_APP_SM_INTEGRITY_MAC_ID CRYPT_MAC_HMAC_SM3
#define HITLS_APP_SM_ITER 1024
#define HITLS_APP_SM_SALT_MAX_LEN 64
#define HITLS_APP_SM_SALT_LEN 8
#define HITLS_APP_SM_DKEY_LEN 32
#define HITLS_APP_SM_HMAC_LEN 32
#define HITLS_APP_SM_MAX_PARAM_NUM 5

#ifndef CMVP_INTEGRITYKEY
#define CMVP_INTEGRITYKEY ""
#endif

#define HITLS_APP_SM_SM4_SELFTEST_FAILED "SM4 selftest failed.\n"
#define HITLS_APP_SM_SM3_SELFTEST_FAILED "SM3 selftest failed.\n"
#define HITLS_APP_SM_MAC_SELFTEST_FAILED "Mac selftest failed.\n"
#define HITLS_APP_SM_DRBG_SELFTEST_FAILED "Drbg selftest failed.\n"
#define HITLS_APP_SM_KDF_SELFTEST_FAILED "Pbkdf2-hmac-sm3 selftest failed.\n"
#define HITLS_APP_SM_SM2_SELFTEST_FAILED "SM2 selftest failed.\n"
#define HITLS_APP_SM_INTEGRITY_SELFTEST_FAILED "Integrity selftest failed.\n"
#define HITLS_APP_SM_RANDOMNESS_SELFTEST_FAILED "Randomness selftest failed.\n"
#define HITLS_APP_SM_PAIRWISETEST_SELFTEST_FAILED "SM2 key pairwise test failed.\n"

typedef struct {
    int32_t version;
    int32_t deriveMacId;
    int32_t integrityMacId;
    int32_t iter;
    uint8_t salt[HITLS_APP_SM_SALT_MAX_LEN];
    uint32_t saltLen;
    uint8_t dKey[HITLS_APP_SM_DKEY_LEN];
    uint32_t dKeyLen;
} UserParam;

typedef struct {
    UserParam userParam;
    uint8_t hmac[HITLS_APP_SM_HMAC_LEN];
    uint32_t hmacLen;
} UserInfo;

static void UserParamOrderCvt(UserParam *userParam, bool toByte)
{
    if (toByte) {
        BSL_Uint32ToByte(userParam->version, (uint8_t *)&userParam->version);
        BSL_Uint32ToByte(userParam->deriveMacId, (uint8_t *)&userParam->deriveMacId);
        BSL_Uint32ToByte(userParam->integrityMacId, (uint8_t *)&userParam->integrityMacId);
        BSL_Uint32ToByte(userParam->iter, (uint8_t *)&userParam->iter);
        BSL_Uint32ToByte(userParam->saltLen, (uint8_t *)&userParam->saltLen);
        BSL_Uint32ToByte(userParam->dKeyLen, (uint8_t *)&userParam->dKeyLen);
    } else {
        userParam->version = BSL_ByteToUint32((uint8_t *)&userParam->version);
        userParam->deriveMacId = BSL_ByteToUint32((uint8_t *)&userParam->deriveMacId);
        userParam->integrityMacId = BSL_ByteToUint32((uint8_t *)&userParam->integrityMacId);
        userParam->iter = BSL_ByteToUint32((uint8_t *)&userParam->iter);
        userParam->saltLen = BSL_ByteToUint32((uint8_t *)&userParam->saltLen);
        userParam->dKeyLen = BSL_ByteToUint32((uint8_t *)&userParam->dKeyLen);
    }
}

static void UserInfoOrderCvt(UserInfo *userInfo, bool toByte)
{
    UserParamOrderCvt(&userInfo->userParam, toByte);
    if (toByte) {
        BSL_Uint32ToByte(userInfo->hmacLen, (uint8_t *)&userInfo->hmacLen);
    } else {
        userInfo->hmacLen = BSL_ByteToUint32((uint8_t *)&userInfo->hmacLen);
    }
}

int32_t HITLS_APP_SM_RootUserCheck(void)
{
    if (getuid() == 0) {
        AppPrintError("Root selftest failed.\n");
        return HITLS_APP_ROOT_CHECK_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static bool CheckFileExists(const char *filename)
{
    return access(filename, F_OK) == 0;
}

static int32_t CheckPassword(const uint8_t *password, const uint32_t passwordLen)
{
    const char specialStr[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    uint32_t hasLowercase = 0;
    uint32_t hasUppercase = 0;
    uint32_t hasDigit = 0;
    uint32_t hasSpecial = 0;
    if (passwordLen < 8) { // 8: minimum length of password
        AppPrintError("The password must be at least 8 characters long.\n");
        return HITLS_APP_PASSWD_FAIL;
    }
    for (uint32_t i = 0; i < passwordLen; i++) {
        if (password[i] < '!' || password[i] > '~') {
            AppPrintError("The password can contain only the following characters:\n");
            AppPrintError("a~z A~Z 0~9 ! \" # $ %% & ' ( ) * + , - . / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\n");
            return HITLS_APP_PASSWD_FAIL;
        }
        if (password[i] >= 'a' && password[i] <= 'z') {
            hasLowercase = 1;
        }
        if (password[i] >= 'A' && password[i] <= 'Z') {
            hasUppercase = 1;
        }
        if (password[i] >= '0' && password[i] <= '9') {
            hasDigit = 1;
        }
        if (strchr(specialStr, password[i]) != NULL) {
            hasSpecial = 1;
        }
    }
    if (hasLowercase + hasUppercase + hasDigit + hasSpecial < 2) { // 2: minimum number of different characters
        AppPrintError("The password must contain at least two of the following characters: lowercase letter, uppercase "
                      "letter, digit, or special character.\n");
        return HITLS_APP_PASSWD_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetPassword(char **password)
{
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
    buf[bufLen - 1] = '\0';
    ret = CheckPassword((const uint8_t *)buf, bufLen - 1);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_CleanseData(buf, bufLen);
        return ret;
    }

    *password = (char *)BSL_SAL_Dump(buf, bufLen);
    BSL_SAL_CleanseData(buf, bufLen);
    if (*password == NULL) {
        AppPrintError("Failed to allocate memory, bufLen: %u.\n", bufLen);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t DeriveKeyFromPassword(AppProvider *provider, char *password, UserParam *userParam, uint8_t *dKey,
    uint32_t dKeyLen)
{
    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(APP_GetCurrent_LibCtx(), CRYPT_KDF_PBKDF2,
        provider->providerAttr);
    if (kdfCtx == NULL) {
        AppPrintError("Failed to create kdf context.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }

    int index = 0;
    BSL_Param params[HITLS_APP_SM_MAX_PARAM_NUM] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &userParam->deriveMacId,
        sizeof(userParam->deriveMacId));
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, (uint8_t *)password,
        strlen(password));
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, userParam->salt,
        userParam->saltLen);
    (void)BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &userParam->iter,
        sizeof(userParam->iter));

    int32_t ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(kdfCtx);
        AppPrintError("Failed to set kdf params, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }

    ret = CRYPT_EAL_KdfDerive(kdfCtx, dKey, dKeyLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(kdfCtx);
        AppPrintError("Failed to derive key, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    return HITLS_APP_SUCCESS;
}

const char *GetIntegrityKey(void)
{
    return CMVP_INTEGRITYKEY;
}

static int32_t CalculateHMAC(AppProvider *provider, int32_t macId, const uint8_t *data, uint32_t dataLen, uint8_t *hmac,
    uint32_t *hmacLen)
{
    CRYPT_EAL_MacCtx *macCtx = CRYPT_EAL_ProviderMacNewCtx(APP_GetCurrent_LibCtx(), macId, provider->providerAttr);
    if (macCtx == NULL) {
        AppPrintError("Failed to create mac context, macId: %d.\n", macId);
        return HITLS_APP_CRYPTO_FAIL;
    }

    int32_t ret = CRYPT_EAL_MacInit(macCtx, (const uint8_t *)GetIntegrityKey(), (uint32_t)strlen(GetIntegrityKey()));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(macCtx);
        AppPrintError("Failed to init mac context, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }

    ret = CRYPT_EAL_MacUpdate(macCtx, data, dataLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(macCtx);
        AppPrintError("Failed to update mac context, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }

    ret = CRYPT_EAL_MacFinal(macCtx, hmac, hmacLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(macCtx);
        AppPrintError("Failed to final mac context, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_EAL_MacFreeCtx(macCtx);
    return HITLS_APP_SUCCESS;
}

static int32_t VerifyHMAC(AppProvider *provider, int32_t macId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *hmac, uint32_t hmacLen)
{
    uint8_t calculatedHmac[HITLS_APP_SM_HMAC_LEN];
    uint32_t calcHmacLen = sizeof(calculatedHmac);

    int32_t ret = CalculateHMAC(provider, macId, data, dataLen, calculatedHmac, &calcHmacLen);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    if (calcHmacLen != hmacLen || memcmp(calculatedHmac, hmac, hmacLen) != 0) {
        AppPrintError("HMAC verify failed.\n");
        return HITLS_APP_INTEGRITY_VERIFY_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t WriteUserFile(char *userFile, UserInfo *userInfo)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (uio == NULL) {
        AppPrintError("Failed to create uio.\n");
        return HITLS_APP_UIO_FAIL;
    }
    int32_t ret = BSL_UIO_Ctrl(uio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, userFile);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to open userFile, errCode: 0x%x.\n", ret);
        BSL_UIO_Free(uio);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);

    UserInfoOrderCvt(userInfo, true);
    uint32_t writeLen = 0;
    ret = BSL_UIO_Write(uio, userInfo, sizeof(UserInfo), &writeLen);
    if (ret != BSL_SUCCESS || writeLen != sizeof(UserInfo)) {
        BSL_UIO_Free(uio);
        AppPrintError("Failed to write userFile, errCode: 0x%x, writeLen: %u.\n", ret, writeLen);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_Free(uio);
    return HITLS_APP_SUCCESS;
}

static int32_t ReadUserFile(char *userFile, UserInfo *userInfo)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (uio == NULL) {
        AppPrintError("Failed to create uio.\n");
        return HITLS_APP_UIO_FAIL;
    }
    int32_t ret = BSL_UIO_Ctrl(uio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_READ, userFile);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to open userFile, errCode: 0x%x.\n", ret);
        BSL_UIO_Free(uio);
        return HITLS_APP_UIO_FAIL;
    }

    BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);

    uint32_t readLen = 0;
    ret = BSL_UIO_Read(uio, userInfo, sizeof(UserInfo), &readLen);
    if (ret != BSL_SUCCESS || readLen != sizeof(UserInfo)) {
        BSL_UIO_Free(uio);
        AppPrintError("Failed to read userFile, errCode: 0x%x, readLen: %u.\n", ret, readLen);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_Free(uio);

    UserInfoOrderCvt(userInfo, false);

    // check userInfo
    if (userInfo->userParam.version != HITLS_APP_SM_VERSION ||
        userInfo->userParam.saltLen > sizeof(userInfo->userParam.salt) ||
        userInfo->userParam.dKeyLen > sizeof(userInfo->userParam.dKey) ||
        userInfo->hmacLen > sizeof(userInfo->hmac)) {
        AppPrintError("User info check failed.\n");
        return HITLS_APP_INFO_CMP_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static int32_t SetUserInfo(AppProvider *provider, UserInfo *userInfo, char *password)
{
    userInfo->userParam.version = HITLS_APP_SM_VERSION;
    userInfo->userParam.deriveMacId = HITLS_APP_SM_DERIVE_MAC_ID;
    userInfo->userParam.integrityMacId = HITLS_APP_SM_INTEGRITY_MAC_ID;
    userInfo->userParam.iter = HITLS_APP_SM_ITER;
    userInfo->userParam.saltLen = HITLS_APP_SM_SALT_LEN;
    userInfo->userParam.dKeyLen = HITLS_APP_SM_DKEY_LEN;

    int32_t ret = CRYPT_EAL_RandbytesEx(APP_GetCurrent_LibCtx(), userInfo->userParam.salt, userInfo->userParam.saltLen);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Failed to generate the salt value, ret: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    return DeriveKeyFromPassword(provider, password, &userInfo->userParam, userInfo->userParam.dKey,
        userInfo->userParam.dKeyLen);
}

static int32_t FirstTimeLogin(AppProvider *provider, char *userFile, char **pwd)
{
    char *password = NULL;
    UserInfo userInfo = {0};
    userInfo.hmacLen = sizeof(userInfo.hmac);

    AppPrintError("This is your first login, please set your password.\n");
    int32_t ret = GetPassword(&password);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    ret = SetUserInfo(provider, &userInfo, password);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_ClearFree(password, strlen(password));
        return ret;
    }

    int32_t macId = userInfo.userParam.integrityMacId;
    UserParamOrderCvt(&userInfo.userParam, true);

    ret = CalculateHMAC(provider, macId, (const uint8_t *)&userInfo.userParam, sizeof(UserParam), userInfo.hmac,
        &userInfo.hmacLen);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_ClearFree(password, strlen(password));
        return ret;
    }

    UserParamOrderCvt(&userInfo.userParam, false);

    ret = WriteUserFile(userFile, &userInfo);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_ClearFree(password, strlen(password));
        return ret;
    }
    *pwd = password;
    return HITLS_APP_SUCCESS;
}

static int32_t VerifyPassword(AppProvider *provider, UserInfo *userInfo, char *password)
{
    uint8_t derivedKey[HITLS_APP_SM_DKEY_LEN];
    int32_t ret = DeriveKeyFromPassword(provider, password, &userInfo->userParam, derivedKey, sizeof(derivedKey));
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (userInfo->userParam.dKeyLen != sizeof(derivedKey)) {
        AppPrintError("Admin verification failed.\n");
        return HITLS_APP_INFO_CMP_FAIL;
    }

    if (memcmp(derivedKey, userInfo->userParam.dKey, userInfo->userParam.dKeyLen) != 0) {
        AppPrintError("Admin verification failed.\n");
        return HITLS_APP_PASSWD_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static int32_t ExistingUserLogin(AppProvider *provider, char *userFile, char **pwd)
{
    char *password = NULL;
    UserInfo userInfo = {0};
    int32_t ret;

    ret = ReadUserFile(userFile, &userInfo);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    int32_t macId = userInfo.userParam.integrityMacId;
    UserParamOrderCvt(&userInfo.userParam, true);

    ret = VerifyHMAC(provider, macId, (const uint8_t *)&userInfo.userParam, sizeof(UserParam),
        userInfo.hmac, userInfo.hmacLen);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("User file integrity check failed, errCode: 0x%x.\n", ret);
        return ret;
    }

    UserParamOrderCvt(&userInfo.userParam, false);

    ret = GetPassword(&password);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    ret = VerifyPassword(provider, &userInfo, password);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_ClearFree(password, strlen(password));
        return ret;
    }
    *pwd = password;
    return HITLS_APP_SUCCESS;
}

static char *GetUserFilePath(const char *workPath)
{
    char *path = BSL_SAL_Malloc(APP_MAX_PATH_LEN);
    if (path == NULL) {
        AppPrintError("Failed to allocate memory.\n");
        return NULL;
    }
    int32_t ret = sprintf_s(path, APP_MAX_PATH_LEN, "%s/%s", workPath, HITLS_APP_SM_USER_FILE_NAME);
    if (ret < 0) {
        AppPrintError("WorkPath is invalid.\n");
        BSL_SAL_Free(path);
        return NULL;
    }
    return path;
}

int32_t HITLS_APP_SM_Init(AppProvider *provider, const char *workPath, char **password, int32_t *status)
{
    if (provider == NULL || workPath == NULL || password == NULL || status == NULL) {
        return HITLS_APP_INVALID_ARG;
    }

    *status = HITLS_APP_SM_STATUS_SELFTEST;

    int32_t ret = HITLS_APP_SM_RootUserCheck();
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = HITLS_APP_SM_IntegrityCheck(provider);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    *status = HITLS_APP_SM_STATUS_MANAGER;

    char *path = GetUserFilePath(workPath);
    if (path == NULL) {
        AppPrintError("Failed to get user file path.\n");
        return HITLS_APP_INVALID_ARG;
    }

    ret = CheckFileExists(path) ? ExistingUserLogin(provider, path, password) :
        FirstTimeLogin(provider, path, password);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_Free(path);
        return ret;
    }

    BSL_SAL_Free(path);
    return HITLS_APP_SUCCESS;
}

char *HITLS_APP_GetAppPath(void)
{
    char *tempPath = BSL_SAL_Malloc(APP_MAX_PATH_LEN);
    if (tempPath == NULL) {
        (void)AppPrintError("Failed to allocate memory.\n");
        return NULL;
    }
    ssize_t count = readlink("/proc/self/exe", tempPath, APP_MAX_PATH_LEN);
    if (count < 0 || (size_t)count >= APP_MAX_PATH_LEN) {
        BSL_SAL_Free(tempPath);
        AppPrintError("Failed to readlink.\n");
        return NULL;
    }
    tempPath[count] = '\0';

    // realpath() need to use PATH_MAX.
    char *path = BSL_SAL_Malloc(PATH_MAX);
    if (path == NULL) {
        BSL_SAL_Free(tempPath);
        AppPrintError("Failed to allocate app path memory.\n");
        return NULL;
    }

    if (realpath(tempPath, path) == NULL) {
        BSL_SAL_Free(path);
        BSL_SAL_Free(tempPath);
        AppPrintError("Failed to get realpath.\n");
        return NULL;
    }
    BSL_SAL_Free(tempPath);
    return path;
}

static int32_t GetAppExpectHmac(const char *appPath, uint8_t *hmac, uint32_t *hmacLen)
{
    char *hmacPath = BSL_SAL_Malloc(APP_MAX_PATH_LEN);
    if (hmacPath == NULL) {
        AppPrintError("Failed to allocate memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    int32_t ret = sprintf_s(hmacPath, APP_MAX_PATH_LEN, "%s.hmac", appPath);
    if (ret < 0) {
        AppPrintError("AppPath is too long, ret: %d.\n", ret);
        BSL_SAL_Free(hmacPath);
        return HITLS_APP_SECUREC_FAIL;
    }

    BSL_Buffer data = { 0 };
    ret = BSL_SAL_ReadFile(hmacPath, &data.data, &data.dataLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Read file failed: %s, errCode: 0x%x.\n", hmacPath, ret);
        BSL_SAL_Free(hmacPath);
        return HITLS_APP_SAL_FAIL;
    }
    BSL_SAL_FREE(hmacPath);

    char seps[] = " \n";
    char *tmp = NULL;
    char *nextTmp = NULL;
    do {
        tmp = strtok_s((char *)data.data, seps, &nextTmp);
        if (tmp == NULL) {
            AppPrintError("Invalid hmac.\n");
            ret = HITLS_APP_INVALID_ARG;
            break;
        }
        tmp = strtok_s(NULL, seps, &nextTmp);
        if (tmp == NULL) {
            AppPrintError("Invalid hmac.\n");
            ret = HITLS_APP_INVALID_ARG;
            break;
        }
        ret = HITLS_APP_StrToHex(tmp, hmac, hmacLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("Failed to convert hmac, errCode: 0x%x.\n", ret);
            break;
        }
    } while (0);
    BSL_SAL_Free(data.data);
    return ret;
}

static int32_t VerifyAppHmac(AppProvider *provider, const char *appPath, const uint8_t *expectHmac,
    uint32_t expectHmacLen)
{
    BSL_Buffer data = {0};
    int32_t ret = BSL_SAL_ReadFile(appPath, &data.data, &data.dataLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Read file failed, appPath: %s, errCode: 0x%x.\n", appPath, ret);
        return HITLS_APP_SAL_FAIL;
    }
    ret = VerifyHMAC(provider, CRYPT_MAC_HMAC_SM3, data.data, data.dataLen, expectHmac, expectHmacLen);
    BSL_SAL_Free(data.data);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Calculate integrity hmac failed, appPath: %s, errCode: 0x%x.\n", appPath, ret);
        return ret;
    }
    return ret;
}

int32_t HITLS_APP_SM_IntegrityCheck(AppProvider *provider)
{
    if (provider == NULL) {
        return HITLS_APP_INVALID_ARG;
    }

    char *appPath = HITLS_APP_GetAppPath();
    if (appPath == NULL) {
        AppPrintError("Failed to get app path.\n");
        return HITLS_APP_INVALID_ARG;
    }
    uint8_t expectHmac[HITLS_APP_SM_HMAC_LEN];
    uint32_t expectHmacLen = sizeof(expectHmac);
    int32_t ret = GetAppExpectHmac(appPath, expectHmac, &expectHmacLen);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_Free(appPath);
        return ret;
    }

    ret = VerifyAppHmac(provider, appPath, expectHmac, expectHmacLen);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError(HITLS_APP_SM_INTEGRITY_SELFTEST_FAILED);
        BSL_SAL_Free(appPath);
        return ret;
    }

    BSL_SAL_Free(appPath);
    return HITLS_APP_SUCCESS;
}

static int32_t RandomnessTest(CRYPT_SelftestCtx *selftestCtx, uint8_t *data, uint32_t len)
{
    BSL_Param params[] = {{0}, {0}, BSL_PARAM_END};
    int32_t type = CRYPT_CMVP_RANDOMNESS_TEST;
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_CMVP_SELFTEST_TYPE, BSL_PARAM_TYPE_INT32, &type, sizeof(type));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_CMVP_RANDOM, BSL_PARAM_TYPE_OCTETS, data, len);

    int32_t ret = CRYPT_CMVP_Selftest(selftestCtx, params);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Random number randomness check failed, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t RandomSelftest(AppProvider *provider, uint32_t groups, uint32_t bitsPerGroup, uint32_t retry,
    uint32_t threshold)
{
    const uint32_t bytesPerGroup = (bitsPerGroup + 7) >> 3;
    const uint32_t totalLen = groups * bytesPerGroup;

    uint8_t *data = BSL_SAL_Malloc(totalLen);
    if (data == NULL) {
        AppPrintError("Failed to allocate memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    CRYPT_SelftestCtx *selftestCtx = CRYPT_CMVP_SelftestNewCtx(APP_GetCurrent_LibCtx(), provider->providerAttr);
    if (selftestCtx == NULL) {
        AppPrintError("Randomness test failed, selftestCtx is NULL.\n");
        BSL_SAL_Free(data);
        return HITLS_APP_CRYPTO_FAIL;
    }

    bool isSuccess = false;
    for (uint32_t attempt = 0; attempt < retry; attempt++) {
        int32_t ret = CRYPT_EAL_RandbytesEx(APP_GetCurrent_LibCtx(), data, totalLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("Failed to generate random data, errCode: 0x%x.\n", ret);
            continue;
        }
        uint32_t failCnt = 0;
        for (uint32_t i = 0; i < groups; i++) {
            ret = RandomnessTest(selftestCtx, data + i * bytesPerGroup, bytesPerGroup);
            if (ret == HITLS_APP_SUCCESS) {
                continue;
            }
            failCnt++;
            if (failCnt >= threshold) {
                break;
            }
        }
        if (failCnt < threshold) {
            isSuccess = true;
            break;
        }
    }
    BSL_SAL_Free(data);
    CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
    return isSuccess ? HITLS_APP_SUCCESS : HITLS_APP_CRYPTO_FAIL;
}

int32_t HITLS_APP_SM_PeriodicRandomCheck(AppProvider *provider)
{
    if (provider == NULL) {
        return HITLS_APP_INVALID_ARG;
    }

    /* GM/T 0062-2018:
     * Periodic random self-check (requirements a–d):
     * a) Test amount: 5 groups × 10^4 bits per group (total 5 × 10^4 bits).
     * b) Test item: Poker test, m = 2 (via CMVP selftest under the hood).
     * c) Decision: fail if ≥1 group fails; allow one repeat of collection and test.
     *    To allow one retry, set 'retry' to 2 (attempts). Default below is 1 (no retry).
     * d) Detection period: configurable; recommended interval ≤ 24 hours between checks.
     *    Invoke this API on a schedule according to product requirements.
     */
    uint32_t groups = 5;
    uint32_t bitsPerGroup = 10000;
    uint32_t retry = 2;
    uint32_t threshold = 1;

    return RandomSelftest(provider, groups, bitsPerGroup, retry, threshold);
}

void HITLS_APP_SM_PrintLog(int32_t ret)
{
    switch (ret) {
        case CRYPT_CMVP_ERR_CIPHER_SELFTEST:
            AppPrintError(HITLS_APP_SM_SM4_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_ERR_MD_SELFTEST:
            AppPrintError(HITLS_APP_SM_SM3_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_ERR_MAC_SELFTEST:
            AppPrintError(HITLS_APP_SM_MAC_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_ERR_DRBG_SELFTEST:
            AppPrintError(HITLS_APP_SM_DRBG_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_ERR_KDF_SELFTEST:
            AppPrintError(HITLS_APP_SM_KDF_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_ERR_PKEY_SELFTEST:
            AppPrintError(HITLS_APP_SM_SM2_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_ERR_INTEGRITY:
            AppPrintError(HITLS_APP_SM_INTEGRITY_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_RANDOMNESS_ERR:
            AppPrintError(HITLS_APP_SM_RANDOMNESS_SELFTEST_FAILED);
            return;
        case CRYPT_CMVP_ERR_PAIRWISETEST:
            AppPrintError(HITLS_APP_SM_PAIRWISETEST_SELFTEST_FAILED);
            return;
        default:
            return;
    }
}
#endif
