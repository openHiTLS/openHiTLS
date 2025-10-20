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
#include "app_enc.h"
#include "app_keymgmt.h"
#include "app_dgst.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_mac.h"
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
#define WORK_PATH "./keymgmt_workpath"

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

#define SUFFIX ".p12"

#define SYNC_DATA_FILE "./keymgmt_workpath/sync_data.bin"

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

#define SM_PARAM \
    "-sm", "-workpath", WORK_PATH, \
    "-provider", HITLS_SM_LIB_NAME, \
    "-provider-path", HITLS_SM_PROVIDER_PATH, \
    "-provider-attr", HITLS_SM_PROVIDER_ATTR

static AppProvider g_appProvider = {HITLS_SM_LIB_NAME, HITLS_SM_PROVIDER_PATH, HITLS_SM_PROVIDER_ATTR};

static int32_t AppTestInit(void)
{
    system("rm -rf " WORK_PATH);
    system("mkdir -p " WORK_PATH);
    int32_t ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (APP_GetCurrent_LibCtx() == NULL) {
        if (APP_Create_LibCtx() == NULL) {
            AppPrintError("Create g_libCtx failed\n");
            return HITLS_APP_INVALID_ARG;
        }
    }
    return HITLS_APP_SUCCESS;
}

static void AppTestUninit(void)
{
    HITLS_APP_FreeLibCtx();
    AppPrintErrorUioUnInit();
    system("rm -rf " WORK_PATH);
}

static int32_t STUB_BSL_UI_ReadPwdUtil(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen, const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    char result[] = "a1234567";
    (void)strcpy_s(buff, *buffLen, result);
    *buffLen = (uint32_t)strlen(buff) + 1;
    return BSL_SUCCESS;
}

static int32_t STUB_HITLS_APP_SM_IntegrityCheck(void)
{
    return HITLS_APP_SUCCESS;
}

static int32_t STUB_HITLS_APP_SM_RootUserCheck(void)
{
    return HITLS_APP_SUCCESS;
}

static int has_suffix(const char *filename, const char *suffix)
{
    size_t len_filename = strlen(filename);
    size_t len_suffix = strlen(suffix);
    if (len_filename >= len_suffix) {
        return strcmp(filename + len_filename - len_suffix, suffix) == 0;
    }
    return 0;
}

static char *GetUuidFromP12(const char *directory)
{
    struct dirent *entry;
    DIR *dp = opendir(directory);
    if (dp == NULL) {
        return NULL;
    }
    bool found = false;
    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG && has_suffix(entry->d_name, SUFFIX)) {
            found = true;
            break;
        }
    }
    if (!found) {
        closedir(dp);
        return NULL;
    }
    uint32_t len = strlen(entry->d_name) - strlen(SUFFIX) + 1;
    char *uuid = BSL_SAL_Malloc(len);
    if (uuid == NULL) {
        closedir(dp);
        return NULL;
    }
    (void)memcpy_s(uuid, len, entry->d_name, len - 1);
    uuid[len - 1] = '\0';
    closedir(dp);
    return uuid;
}

// Get the list of all UUIDs in the directory
static int32_t GetAllUuidsFromDirectory(const char *directory, char **uuidList, int maxCount)
{
    struct dirent *entry;
    DIR *dp = opendir(directory);
    if (dp == NULL) {
        return 0;
    }
    
    int count = 0;
    while ((entry = readdir(dp)) && count < maxCount) {
        if (entry->d_type == DT_REG && has_suffix(entry->d_name, SUFFIX)) {
            uint32_t len = strlen(entry->d_name) - strlen(SUFFIX) + 1;
            uuidList[count] = BSL_SAL_Malloc(len);
            if (uuidList[count] == NULL) {
                for (int i = 0; i < count; i++) {
                    BSL_SAL_FREE(uuidList[i]);
                }
                closedir(dp);
                return -1;
            }
            (void)memcpy_s(uuidList[count], len, entry->d_name, len - 1);
            uuidList[count][len - 1] = '\0';
            count++;
        }
    }
    closedir(dp);
    return count;
}

static int32_t TEST_APP_SM_Init(AppProvider *provider, HITLS_APP_SM_Param *smParam)
{
    int32_t ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM4_CTR_DF, HITLS_SM_PROVIDER_ATTR,
        NULL, 0, NULL);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = HITLS_APP_SM_Init(provider, smParam->workPath, (char **)&smParam->password, &smParam->status);
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    smParam->passwordLen = strlen((char *)smParam->password);
    return HITLS_APP_SUCCESS;
}

typedef struct {
    int fd;
} TLCP_Context;

static int32_t TLCP_Send_Init(void *ctx)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    (void)memset_s(tlcpCtx, sizeof(TLCP_Context), 0, sizeof(TLCP_Context));
    int fd = open(SYNC_DATA_FILE, O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        AppPrintError("open %s failed, ret: 0x%08x\n", SYNC_DATA_FILE, fd);
        return HITLS_APP_UIO_FAIL;
    }
    tlcpCtx->fd = fd;
    return HITLS_APP_SUCCESS;
}

static int32_t TLCP_Receive_Init(void *ctx)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    (void)memset_s(tlcpCtx, sizeof(TLCP_Context), 0, sizeof(TLCP_Context));
    int fd = open(SYNC_DATA_FILE, O_RDONLY);
    if (fd == -1) {
        AppPrintError("open %s failed, ret: 0x%08x\n", SYNC_DATA_FILE, fd);
        return HITLS_APP_UIO_FAIL;
    }
    tlcpCtx->fd = fd;
    return HITLS_APP_SUCCESS;
}

// transport stubs (to be replaced by TLCP integration)
static int32_t TLCP_Send(void *ctx, const void *data, uint32_t len)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    int ret = write(tlcpCtx->fd, data, len);
    if (ret < 0 || (uint32_t)ret != len) {
        AppPrintError("write %s failed, ret: %d\n", SYNC_DATA_FILE, ret);
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t TLCP_Receive(void *ctx, void *data, uint32_t len)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    int ret = read(tlcpCtx->fd, data, len);
    if (ret < 0 || (uint32_t)ret != len) {
        AppPrintError("read %s failed, ret: %d\n", SYNC_DATA_FILE, ret);
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static void TLCP_Deinit(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    close(tlcpCtx->fd);
    (void)memset_s(tlcpCtx, sizeof(TLCP_Context), 0, sizeof(TLCP_Context));
}

static int32_t CreateFile(const char *file)
{
    FILE *fp = fopen(file, "w");
    if (fp == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    fprintf(fp, "01234567890123456789");
    fclose(fp);
    return HITLS_APP_SUCCESS;
}

static int32_t CompareFile(const char *file1, const char *file2)
{
    FILE *fp1 = fopen(file1, "rb");
    FILE *fp2 = fopen(file2, "rb");
    if (fp1 == NULL || fp2 == NULL) {
        if (fp1 != NULL) fclose(fp1);
        if (fp2 != NULL) fclose(fp2);
        return HITLS_APP_UIO_FAIL;
    }
    int result = HITLS_APP_SUCCESS;
    char buf1[1024];
    char buf2[1024];
    size_t bytesRead1, bytesRead2;
    do {
        bytesRead1 = fread(buf1, 1, sizeof(buf1), fp1);
        bytesRead2 = fread(buf2, 1, sizeof(buf2), fp2);
        if (bytesRead1 != bytesRead2 || memcmp(buf1, buf2, bytesRead1) != 0) {
            result = HITLS_APP_UIO_FAIL;
            break;
        }
    } while (bytesRead1 > 0 && bytesRead2 > 0);
    fclose(fp1);
    fclose(fp2);
    return result;
}

static int32_t EncryptAndDecrypt(char *uuid, char *cipher)
{
    char *inFile = WORK_PATH "/test.txt";
    char *outFile = WORK_PATH "/test.txt.cipher";
    char *outFile2 = WORK_PATH "/test.txt.out";

    char *argv[][20] = {
        {"enc", "-enc", "-cipher", cipher, "-uuid", uuid, "-in", inFile, "-out", outFile, SM_PARAM},
        {"enc", "-dec", "-cipher", cipher, "-uuid", uuid, "-in", outFile, "-out", outFile2, SM_PARAM},
    };

    int ret = CreateFile(inFile);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_EncMain(sizeof(argv[0]) / sizeof(argv[0][0]) - 1, argv[0]);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_EncMain(sizeof(argv[1]) / sizeof(argv[1][0]) - 1, argv[1]);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CompareFile(inFile, outFile2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    system("rm -f " WORK_PATH "/test.txt");
    system("rm -f " WORK_PATH "/test.txt.cipher");
    system("rm -f " WORK_PATH "/test.txt.out");

EXIT:
    return ret;
}

static int32_t CalculateMac(char *uuid, char *algId)
{
    char *inFile = WORK_PATH "/test.txt";
    char *outFile = WORK_PATH "/test.txt.mac";

    char *argv[][19] = {
        {"mac", "-name", algId, "-uuid", uuid, SM_PARAM, "-in", inFile, "-out", outFile},
    };

    int ret = CreateFile(inFile);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_MacMain(sizeof(argv[0]) / sizeof(argv[0][0]) - 1, argv[0]);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    system("rm -f " WORK_PATH "/test.txt");
    system("rm -f " WORK_PATH "/test.txt.mac");

EXIT:
    return ret;
}

static void DeleteKey(char *uuid)
{
    if (uuid == NULL) {
        return;
    }
    char *argv[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuid, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    return;
}
#endif

/**
 * @test UT_HITLS_APP_KEYMGMT_TC001
 * @spec  -
 * @title  Test keymgmt subcommand: create and find sm4 key
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC001(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *uuid = NULL;
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    ret = EncryptAndDecrypt(uuid, "sm4_cbc");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_ecb");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_ctr");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_cfb");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_ofb");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_gcm");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC002
 * @spec  -
 * @title  Test keymgmt subcommand: create and find sm4_xts key
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC002(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *uuid = NULL;
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4_xts", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    ret = EncryptAndDecrypt(uuid, "sm4_xts");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

#ifdef HITLS_APP_SM_MODE
static int32_t AsymSignAndVerify(CRYPT_EAL_PkeyCtx *pkeyCtx)
{
    uint8_t data[4] = {0, 1, 2, 3};
    uint32_t dataLen = sizeof(data);
    uint8_t sign[1024] = {0};
    uint32_t signLen = sizeof(sign);

    int32_t ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM4_CTR_DF, HITLS_SM_PROVIDER_ATTR,
        NULL, 0, NULL);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, &signLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, signLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    return ret;
}
#endif

/**
 * @test UT_HITLS_APP_KEYMGMT_TC003
 * @spec  -
 * @title  Test keymgmt subcommand: create and find sm2 key
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC003(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};
    HITLS_APP_KeyInfo keyInfo = {0};

    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = AsymSignAndVerify(keyInfo.pkeyCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_KEYMGMT_TC004
 * @spec  -
 * @title  Test keymgmt subcommand: unsupported algorithm id on create; expect failure
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC004(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *argv[] = {"keymgmt", "-create", "-algid", "aes128_cbc", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);
EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC005
 * @spec  -
 * @title  Test keymgmt subcommand: invalid parameter scenarios; expect failure
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC005(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // Case 1: Missing operation parameter (-create or -delete)
    char *argv1[] = {"keymgmt", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv1) / sizeof(argv1[0]) - 1, argv1);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // Case 2: Missing -sm parameter
    char *argv2[] = {"keymgmt", "-create", "-algid", "sm2", "-workpath", WORK_PATH, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // Case 3: Missing -workpath parameter
    char *argv3[] = {"keymgmt", "-create", "-algid", "sm2", "-sm", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv3) / sizeof(argv3[0]) - 1, argv3);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // Case 4: Missing -algid parameter (during key creation)
    char *argv4[] = {"keymgmt", "-create", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv4) / sizeof(argv4[0]) - 1, argv4);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // Case 5: Missing -uuid parameter (during key deletion)
    char *argv5[] = {"keymgmt", "-delete", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv5) / sizeof(argv5[0]) - 1, argv5);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // Case 6: Specify both -create and -delete (conflicting operations)
    char *argv6[] = {"keymgmt", "-create", "-delete", "-algid", "sm2", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv6) / sizeof(argv6[0]) - 1, argv6);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // Case 7: Empty argument list
    char *argv7[] = {"keymgmt", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv7) / sizeof(argv7[0]) - 1, argv7);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC006
 * @spec  -
 * @title  Test keymgmt subcommand: invalid derivation parameters; expect failure
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC006(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // Case 1: Invalid derivation parameters
    char *argv1[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-iter", "1023", NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv1) / sizeof(argv1[0]) - 1, argv1);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    char *argv2[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-iter", "-1024", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_OPT_UNKOWN);

    // Case 2: Invalid salt length
    char *argv3[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-saltlen", "7", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv3) / sizeof(argv3[0]) - 1, argv3);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    char *argv4[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-saltlen", "-8", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv4) / sizeof(argv4[0]) - 1, argv4);
    ASSERT_EQ(ret, HITLS_APP_OPT_UNKOWN);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC007
 * @spec  -
 * @title  Test keymgmt subcommand: delete key with single UUID; expect success
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC007(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *uuid = NULL;
    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // First create a key
    char *argv_create[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_create) / sizeof(argv_create[0]) - 1, argv_create);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Get the created key UUID
    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    // Verify the key file exists
    char keyPath[256];
    snprintf(keyPath, sizeof(keyPath), "%s/%s.p12", WORK_PATH, uuid);
    FILE *fp = fopen(keyPath, "r");
    ASSERT_TRUE(fp != NULL);
    fclose(fp);

    // Test deleting a key - pass a single UUID
    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuid, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Verify the key file has been deleted
    fp = fopen(keyPath, "r");
    ASSERT_TRUE(fp == NULL);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_KEYMGMT_TC008
 * @spec  -
 * @title  Test keymgmt subcommand: delete key with single UUID; key not found; expect failure
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC008(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // Test deleting a non-existent key - pass a randomly generated UUID
    char fakeUuid[] = "1234567890abcdef1234567890abcdef";
    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", fakeUuid, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);
    
    // Should return failure because the key does not exist
    ASSERT_NE(ret, HITLS_APP_SUCCESS);

    // Verify there is indeed no corresponding key file in the work directory
    char keyPath[256];
    snprintf(keyPath, sizeof(keyPath), "%s/%s.p12", WORK_PATH, fakeUuid);
    FILE *fp = fopen(keyPath, "r");
    ASSERT_TRUE(fp == NULL);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC009
 * @spec  -
 * @title  Test keymgmt subcommand: delete keys with multiple UUIDs; expect success
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC009(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *uuid1 = NULL;
    char *uuidArray[10] = {NULL};
    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // Create the first key
    char *argv_create1[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_create1) / sizeof(argv_create1[0]) - 1, argv_create1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Create the second key
    char *argv_create2[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_create2) / sizeof(argv_create2[0]) - 1, argv_create2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Get the list of created key UUIDs
    uuid1 = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid1 != NULL);
    
    // Get all UUIDs in the directory
    int uuidCount = GetAllUuidsFromDirectory(WORK_PATH, uuidArray, 10);
    ASSERT_EQ(uuidCount, 2); // There should be two keys
    
    // Find a UUID different from uuid1
    char *uuid2 = NULL;
    for (int i = 0; i < uuidCount; i++) {
        if (strcmp(uuidArray[i], uuid1) != 0) {
            uuid2 = uuidArray[i];
            break;
        }
    }
    ASSERT_TRUE(uuid2 != NULL);

    // Verify both key files exist
    char keyPath1[256], keyPath2[256];
    snprintf(keyPath1, sizeof(keyPath1), "%s/%s.p12", WORK_PATH, uuid1);
    snprintf(keyPath2, sizeof(keyPath2), "%s/%s.p12", WORK_PATH, uuid2);
    
    FILE *fp1 = fopen(keyPath1, "r");
    ASSERT_TRUE(fp1 != NULL);
    fclose(fp1);
    FILE *fp2 = fopen(keyPath2, "r");
    ASSERT_TRUE(fp2 != NULL);
    fclose(fp2);

    // Test deleting multiple keys - pass multiple UUIDs (comma-separated)
    char uuidList[256];
    snprintf(uuidList, sizeof(uuidList), "%s,%s", uuid1, uuid2);
    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuidList, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Verify both key files have been deleted
    fp1 = fopen(keyPath1, "r");
    fp2 = fopen(keyPath2, "r");
    ASSERT_TRUE(fp1 == NULL);
    ASSERT_TRUE(fp2 == NULL);

EXIT:
    BSL_SAL_FREE(uuid1);
    // Free memory allocated in uuidArray
    for (int i = 0; i < 10; i++) {
        if (uuidArray[i] != NULL) {
            BSL_SAL_FREE(uuidArray[i]);
        }
    }
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC010
 * @spec  -
 * @title  Test keymgmt subcommand: delete with multiple UUIDs; some missing; expect failure; earlier existing keys deleted in order
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC010(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // Create the first key
    char *argv_create1[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_create1) / sizeof(argv_create1[0]) - 1, argv_create1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Get the created key UUID
    char *uuid1 = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid1 != NULL);

    // Verify the key file exists
    char keyPath1[256];
    snprintf(keyPath1, sizeof(keyPath1), "%s/%s.p12", WORK_PATH, uuid1);
    FILE *fp1 = fopen(keyPath1, "r");
    ASSERT_TRUE(fp1 != NULL);
    fclose(fp1);

    // Construct a list containing existing and non-existing UUIDs
    char fakeUuid[] = "1234567890abcdef1234567890abcdef";
    char uuidList[256];
    // Note: Put the existing UUID first and the non-existing one after, to verify ordered deletion logic
    snprintf(uuidList, sizeof(uuidList), "%s,%s", uuid1, fakeUuid);

    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuidList, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);

    // Should return failure because some UUIDs do not have corresponding keys
    ASSERT_NE(ret, HITLS_APP_SUCCESS);

    // Verify the existing key file has been deleted (processed first due to order)
    fp1 = fopen(keyPath1, "r");
    ASSERT_TRUE(fp1 == NULL);

    // Verify the non-existent key file indeed does not exist
    char keyPath2[256];
    snprintf(keyPath2, sizeof(keyPath2), "%s/%s.p12", WORK_PATH, fakeUuid);
    FILE *fp2 = fopen(keyPath2, "r");
    ASSERT_TRUE(fp2 == NULL);

EXIT:
    BSL_SAL_FREE(uuid1);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_KEYMGMT_TC011
 * @spec  -
 * @title  Test keymgmt subcommand: find key API with UUID; find sm4-ofb key success (keyLen 16); sm4_xts returns failure
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC011(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // Create an sm4 key instead of an sm2 key
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Find sm4-ofb key
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_OFB, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Verify key info
    ASSERT_TRUE(keyInfo.key != NULL);
    ASSERT_EQ(keyInfo.keyLen, 16); // sm4 key length should be 16 bytes

    // Find sm4_xts key; expect failure
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_XTS, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC012
 * @spec  -
 * @title  Test keymgmt subcommand: find key API with UUID; find sm4_xts key success (keyLen 32); sm4-ofb returns failure
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC012(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // Create an sm4_xts key instead of an sm2 key
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4_xts", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Find sm4_xts key
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_XTS, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Verify key info
    ASSERT_TRUE(keyInfo.key != NULL);
    ASSERT_EQ(keyInfo.keyLen, 32); // sm4_xts key length should be 32 bytes

    // Find sm4-ofb key; expect failure
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_OFB, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC013
 * @spec  -
 * @title  Test keymgmt subcommand: create MAC key; compute MAC via CLI; expect success
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC013(char *macAlgId)
{
#ifndef HITLS_APP_SM_MODE
    (void)macAlgId;
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *uuid = NULL;
    char *argv[] = {"keymgmt", "-create", "-algid", macAlgId, SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    ret = CalculateMac(uuid, macAlgId);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC014
 * @spec  -
 * @title  Test keymgmt subcommand: find key API with UUID; find MAC key success; keyLen equals algorithm keyLen
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC014(int algId, char *macAlgId, int keyLen)
{
#ifndef HITLS_APP_SM_MODE
    (void)algId;
    (void)macAlgId;
    (void)keyLen;
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // Create a MAC key
    char *argv[] = {"keymgmt", "-create", "-algid", macAlgId, SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Find MAC key
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, algId, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Verify key info
    ASSERT_TRUE(keyInfo.key != NULL);
    ASSERT_EQ(keyInfo.keyLen, keyLen);
    ASSERT_EQ(keyInfo.attr.algId, algId);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC015
 * @spec  -
 * @title  Test keymgmt subcommand: find key API with UUID; find sm2 key success; pkeyCtx not NULL
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC015(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // Create an sm2 key
    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Find sm2 key
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Verify key info
    ASSERT_TRUE(keyInfo.pkeyCtx != NULL); // pkeyCtx is not NULL
    ASSERT_EQ(keyInfo.attr.algId, CRYPT_PKEY_SM2);

    // Test SM2 key signing and verification
    ret = AsymSignAndVerify(keyInfo.pkeyCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    char *argv2[] = {"keymgmt", "-getpub", "-uuid", smParam.uuid, SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC016
 * @spec  -
 * @title  Test keymgmt subcommand: find key API with UUID; find sm2 key with wrong password; PKCS12 decryption fails
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC016(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // Create an sm2 key
    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    HITLS_APP_KeyInfo keyInfo = {0};
    
    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // Attempt to decrypt PKCS12 with a wrong password: flip the first byte of the correct password
    smParam.password[0] = ~smParam.password[0];

    // Finding sm2 key should fail (PKCS12 decryption failure)
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_X509_FAIL);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC017(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    uint8_t data[4] = {0, 1, 2, 3};
    uint32_t dataLen = sizeof(data);
    uint8_t sign[1024] = {0};
    uint32_t signLen = sizeof(sign);
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};
    HITLS_APP_KeyInfo keyInfo = {0};
    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM4_CTR_DF, "provider=sm", NULL, 0, NULL);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeySign(keyInfo.pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, &signLen);
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    (void)memset_s(&keyInfo, sizeof(keyInfo), 0, sizeof(keyInfo));

    TLCP_Context tlcpCtx = {0};
    ret = TLCP_Send_Init(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    ret = HITLS_APP_SendKey(&g_appProvider, &smParam, TLCP_Send, &tlcpCtx);
    TLCP_Deinit(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    DeleteKey(smParam.uuid);

    ret = TLCP_Receive_Init(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM4_CTR_DF, "provider=sm", NULL, 0, NULL);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_ReceiveKey(&g_appProvider, &smParam, -1, -1, TLCP_Receive, &tlcpCtx);
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    TLCP_Deinit(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(keyInfo.pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, signLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC018
 * @spec  -
 * @title  Test keymgmt subcommand: erase all keys interface; expect success
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC018(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *argv[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    char *argv2[] = {"keymgmt", "-erasekey", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC019
 * @spec  -
 * @title  Test keymgmt subcommand: get status interface; expect success
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC019(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *argv[] = {"keymgmt", "-getstatus", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC020
 * @spec  -
 * @title  Test keymgmt subcommand: get version interface; expect success
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC020(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *argv[] = {"keymgmt", "-getversion", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC021
 * @spec  -
 * @title  Test keymgmt subcommand: self-test interface; expect success
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC021(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *argv[] = {"keymgmt", "-selftest", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */

#ifdef HITLS_APP_SM_MODE
static int32_t SM2SignAndVerify(char *uuid)
{
    char *inFile = WORK_PATH "/test.txt";
    char *outFile = WORK_PATH "/test.signature";
    char pubkey[256] = {0};
    (void)sprintf_s(pubkey, sizeof(pubkey), "%s/%s-pub.pem", WORK_PATH, uuid);

    char *argv[] = {"dgst", "-md", "sm3", "-sign", uuid, SM_PARAM, "-out", outFile, inFile, NULL};
    char *argv2[] = {"dgst", "-md", "sm3", "-verify", pubkey, SM_PARAM, "-signature", outFile, inFile, NULL};

    int ret = CreateFile(inFile);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_DgstMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_DgstMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    system("rm -f " WORK_PATH "/test.txt");
    system("rm -f " WORK_PATH "/test.signature");

EXIT:
    return ret;
}
#endif

/**
 * @test UT_HITLS_APP_KEYMGMT_SM2_SIGN_VERIFY_TEST
 * @spec  -
 * @title  Test sm mode sm2 sign and verify interface; expect success
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_SM2_SIGN_VERIFY_TEST(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[3] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    STUB_Replace(&stubInfo[2], HITLS_APP_SM_RootUserCheck, STUB_HITLS_APP_SM_RootUserCheck);

    char *uuid = NULL;
    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    char *argv2[] = {"keymgmt", "-getpub", "-uuid", uuid, SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = SM2SignAndVerify(uuid);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
    STUB_Reset(&stubInfo[2]);
#endif
}
/* END_CASE */
