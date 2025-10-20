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

/* BEGIN_HEADER */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "app_enc.h"
#include "app_keymgmt.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "bsl_ui.h"
#include "bsl_uio.h"
#include "securec.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_cmvp.h"
#include "eal_cipher_local.h"
#include "stub_replace.h"
/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_enc.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */
/* END_HEADER */

#ifdef HITLS_APP_SM_MODE
#define WORK_PATH "./sm_workpath"
#define PASSWORD "a1234567"

#ifdef HITLS_CRYPTO_CMVP_SM_PURE_C
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/C/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_ARMV8_LE
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/armv8_le/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_X86_64
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/x86_64/lib"
#endif

#define HITLS_SM_LIB_NAME "libhitls_sm.so"
#define HITLS_SM_PROVIDER_ATTR "provider=sm"

static AppProvider g_appProvider = {HITLS_SM_LIB_NAME, HITLS_SM_PROVIDER_PATH, HITLS_SM_PROVIDER_ATTR};

CRYPT_SelftestCtx *STUB_CRYPT_CMVP_SelftestNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName)
{
    (void)libCtx;
    (void)attrName;
    return (CRYPT_SelftestCtx *)BSL_SAL_Malloc(1);
}

static int32_t AppTestInit(void)
{
    int32_t ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (APP_Create_LibCtx() == NULL) {
        AppPrintErrorUioUnInit();
        return HITLS_APP_INVALID_ARG;
    }
    ret = HITLS_APP_LoadProvider(g_appProvider.providerPath, g_appProvider.providerName);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_APP_FreeLibCtx();
        AppPrintErrorUioUnInit();
        return ret;
    }
    ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM4_CTR_DF, g_appProvider.providerAttr,
        NULL, 0, NULL);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_APP_FreeLibCtx();
        AppPrintErrorUioUnInit();
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

static void AppTestUninit(void)
{
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    HITLS_APP_FreeLibCtx();
    AppPrintErrorUioUnInit();
}

static int32_t STUB_BSL_UI_ReadPwdUtil(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    char result[] = PASSWORD;
    (void)strcpy_s(buff, *buffLen, result);
    *buffLen = (uint32_t)strlen(buff) + 1;
    return BSL_SUCCESS;
}

static int32_t STUB_BSL_UI_ReadPwdUtil_WrongPassword(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    char wrongPassword[] = "wrong_password_123";
    (void)strcpy_s(buff, *buffLen, wrongPassword);
    *buffLen = (uint32_t)strlen(buff) + 1;
    return BSL_SUCCESS;
}

static uid_t STUB_getuid(void)
{
    return 0;
}

static int32_t STUB_HITLS_APP_SM_RootUserCheck(void)
{
    return HITLS_APP_SUCCESS;
}

static int32_t STUB_HITLS_APP_SM_IntegrityCheck(void)
{
    return HITLS_APP_SUCCESS;
}
#endif

/**
 * @test UT_HITLS_APP_SM_TC001
 * @spec  -
 * @title  Test password retrieval of the command-line SM module
 */

/* BEGIN_CASE */
void UT_HITLS_APP_SM_TC001(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    char *password = NULL;

    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    system("rm -rf " WORK_PATH);
    system("mkdir -p " WORK_PATH);
    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int32_t status = 0;
    ASSERT_EQ(HITLS_APP_SM_Init(&g_appProvider, WORK_PATH, &password, &status), HITLS_APP_SUCCESS);
    ASSERT_EQ(strcmp(password, PASSWORD), 0);

    BSL_SAL_FREE(password);

    ASSERT_EQ(HITLS_APP_SM_Init(&g_appProvider, WORK_PATH, &password, &status), HITLS_APP_SUCCESS);
    ASSERT_EQ(strcmp(password, PASSWORD), 0);

EXIT:
    BSL_SAL_FREE(password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
    system("rm -rf " WORK_PATH);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_SM_TC002
 * @spec  -
 * @title  Test root user check of the command-line SM module
 */

/* BEGIN_CASE */
void UT_HITLS_APP_SM_TC002(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, getuid, STUB_getuid);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    char *password = NULL;
    int32_t status = 0;
    ASSERT_EQ(HITLS_APP_SM_Init(&g_appProvider, WORK_PATH, &password, &status), HITLS_APP_ROOT_CHECK_FAIL);
    ASSERT_EQ(password, NULL);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_SM_TC003
 * @spec  -
 * @title  Test file tamper detection of the command-line SM module; simulate file content corruption
 */

/* BEGIN_CASE */
void UT_HITLS_APP_SM_TC003(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    char *password = NULL;
    char userFilePath[1024] = {0};
    int fd = -1;

    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    system("rm -rf " WORK_PATH);
    system("mkdir -p " WORK_PATH);
    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // Normal initialization
    int32_t status = 0;
    ASSERT_EQ(HITLS_APP_SM_Init(&g_appProvider, WORK_PATH, &password, &status), HITLS_APP_SUCCESS);
    ASSERT_EQ(strcmp(password, PASSWORD), 0);
    BSL_SAL_FREE(password);

    // Build user file path
    snprintf(userFilePath, sizeof(userFilePath), "%s/openhitls_user", WORK_PATH);
    
    // Tamper user file content - modify salt; this passes version check but fails integrity check
    fd = open(userFilePath, O_RDWR);
    ASSERT_TRUE(fd >= 0);

    // Calculate the offset of the salt in the file
    // UserParam structure: version(4) + deriveMacId(4) + integrityMacId(4) + iter(4) + salt[64] + saltLen(4) + dKey[32] + dKeyLen(4)
    // Salt offset = 4 + 4 + 4 + 4 = 16 bytes
    off_t saltOffset = 16;
    
    // Seek to the salt position
    ASSERT_EQ(lseek(fd, saltOffset, SEEK_SET), saltOffset);
    
    // Corrupt the salt by filling with 0xFF
    uint8_t corruptedSalt[64];
    memset(corruptedSalt, 0xFF, sizeof(corruptedSalt));
    ASSERT_EQ(write(fd, corruptedSalt, sizeof(corruptedSalt)), sizeof(corruptedSalt));
    close(fd);
    fd = -1;

    // Initialization after tampering should fail (version check passes but integrity check fails)
    ASSERT_EQ(HITLS_APP_SM_Init(&g_appProvider, WORK_PATH, &password, &status), HITLS_APP_INTEGRITY_VERIFY_FAIL);
    ASSERT_EQ(password, NULL);

EXIT:
    if (fd >= 0) {
        close(fd);
    }
    BSL_SAL_FREE(password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
    system("rm -rf " WORK_PATH);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_SM_TC005
 * @spec  -
 * @title  Test wrong user password; second login fails in the command-line SM module
 */

/* BEGIN_CASE */
void UT_HITLS_APP_SM_TC005(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    char *password = NULL;

    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    
    // First login: use correct password
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);
    system("rm -rf " WORK_PATH);
    system("mkdir -p " WORK_PATH);
    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // First login should succeed
    int32_t status = 0;
    ASSERT_EQ(HITLS_APP_SM_Init(&g_appProvider, WORK_PATH, &password, &status), HITLS_APP_SUCCESS);
    ASSERT_EQ(strcmp(password, PASSWORD), 0);
    BSL_SAL_FREE(password);

    // Second login: use wrong password
    STUB_Reset(&stubInfo[0]);
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil_WrongPassword);

    // Second login with wrong password should fail
    ASSERT_EQ(HITLS_APP_SM_Init(&g_appProvider, WORK_PATH, &password, &status), HITLS_APP_PASSWD_FAIL);
    ASSERT_EQ(password, NULL);

EXIT:
    BSL_SAL_FREE(password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
    system("rm -rf " WORK_PATH);
#endif
}
/* END_CASE */
