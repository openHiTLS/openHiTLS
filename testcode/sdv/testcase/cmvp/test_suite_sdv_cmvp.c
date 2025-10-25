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

#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

/* BEGIN_HEADER */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "cmvp_common.h"
#include "crypt_cmvp.h"
#include "stub_utils.h"
#include "crypt_util_rand.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_entropy.h"
#include "securec.h"
#include "bsl_errno.h"
#include "crypt_params_key.h"
#include "crypt_hmac.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_VOID0(BSL_SAL_Malloc);


#define MAX_OUTPUT 200

extern const char *GetIntegrityKey(void);

static void *StdMalloc(uint32_t len)
{
    return malloc((size_t)len);
}

static void RegNormalMem(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
}

static void *STUB_Malloc(uint32_t size)
{
    (void)size;
    return NULL;
}

static char *Bin2Hex(const uint8_t *input, int length)
{
    const int perHexLen = 2;
    int rLen = length * perHexLen + 1;
    char *result = malloc(rLen);
    if (result == NULL) {
        return NULL;
    }
    (void)memset_s(result, rLen, 0, rLen);
    for (int i = 0; i < length; i++) {
        if (sprintf_s(result + perHexLen * i, rLen, "%02x", input[i]) <= 0) {
            free(result);
            return NULL;
        }
    }
    result[rLen - 1] = 0;
    return result;
}

#define HMAC_SHA256_SIZE 32

static int32_t CmvpHmacTest(const char *key, uint32_t id, uint8_t *buf, uint32_t bufLen, uint8_t *mac, uint32_t *macLen)
{
    CRYPT_HMAC_Ctx *hmacCtx = CRYPT_HMAC_NewCtx(id);
    if (hmacCtx == NULL) {
        return -1;
    }
    int32_t ret = CRYPT_HMAC_Init(hmacCtx, (uint8_t *)(uintptr_t)key, strlen(key), NULL);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_HMAC_FreeCtx(hmacCtx);
        return ret;
    }
    ret = CRYPT_HMAC_Update(hmacCtx, buf, bufLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_HMAC_FreeCtx(hmacCtx);
        return ret;
    }
    ret = CRYPT_HMAC_Final(hmacCtx, mac, macLen);
    CRYPT_HMAC_FreeCtx(hmacCtx);
    return ret;
}

static void CreatIntegrityFile(void)
{
    uint32_t bufLen;
    char *out = NULL;
    FILE *fp = NULL;
    uint8_t *buf = (uint8_t *)CMVP_ReadFile("test_suite_sdv_cmvp", "rb", &bufLen);
    ASSERT_TRUE(buf != NULL);
    uint32_t id;
    uint8_t mac[HMAC_SHA256_SIZE];
    uint32_t macLen = sizeof(mac);
    id = CRYPT_MAC_HMAC_SHA256;
    ASSERT_TRUE(CmvpHmacTest(GetIntegrityKey(), id, buf, bufLen, mac, &macLen) == CRYPT_SUCCESS);
    out = Bin2Hex(mac, HMAC_SHA256_SIZE);
    ASSERT_TRUE(out != NULL);
    fp = fopen("test_suite_sdv_cmvp.hmac", "w");
    ASSERT_TRUE(fp != NULL);
    ASSERT_TRUE(fprintf(fp, "%s%s\n", "HMAC-SHA256(test_suite_sdv_cmvp)= ", out) > 0);
    (void)fclose(fp);
EXIT:
    free(buf);
    free(out);
}

static int CreateFakeIntegrityFile(const char *key, uint32_t id)
{
    int ret = 1;
    uint32_t bufLen;
    char *out = NULL;
    FILE *fp = NULL;
    uint8_t *buf = (uint8_t *)CMVP_ReadFile("test_suite_sdv_cmvp", "rb", &bufLen);
    ASSERT_TRUE(buf != NULL);
    uint8_t mac[HMAC_SHA256_SIZE];
    uint32_t macLen = sizeof(mac);
    ASSERT_TRUE(CmvpHmacTest(key, id, buf, bufLen, mac, &macLen) == CRYPT_SUCCESS);
    out = Bin2Hex(mac, HMAC_SHA256_SIZE);
    ASSERT_TRUE(out != NULL);
    fp = fopen("test_suite_sdv_cmvp.hmac", "w");
    ASSERT_TRUE(fp != NULL);
    ASSERT_TRUE(fprintf(fp, "%s%s\n", "HMAC-SHA256(test_suite_sdv_cmvp)= ", out) > 0);
    (void)fclose(fp);
    ret = CRYPT_SUCCESS;
EXIT:
    free(buf);
    free(out);
    return ret;
}

static int FalsifyFile(const char *path)
{
    FILE *fp;
    char ch;
    int ret = 1;
    fp = fopen(path, "r+");
    ASSERT_TRUE(fp != NULL);
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fread(&ch, 1, 1, fp) != 0);
    ch++;
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fwrite(&ch, 1, 1, fp) != 0);  // 将文件最后一个字节修改
    (void)fclose(fp);
    ret = CRYPT_SUCCESS;
EXIT:
    return ret;
}

static int RecoverFile(const char *path)
{
    FILE *fp;
    char ch;
    int ret = 1;
    fp = fopen(path, "r+");
    ASSERT_TRUE(fp != NULL);
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fread(&ch, 1, 1, fp) != 0);
    ch--;
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fwrite(&ch, 1, 1, fp) != 0);  // 将文件最后一个字节修改
    (void)fclose(fp);
    ret = CRYPT_SUCCESS;
EXIT:
    return ret;
}

static int CopyFile(const char *src_path)
{
    FILE *src_file, *dst_file;
    int ret = 1;
    char *dst_path = "copy";
    char buffer[1024];
    size_t bytes_read;
    src_file = fopen(src_path, "rb");
    if (src_file == NULL) {
        return ret;
    }
    dst_file = fopen(dst_path, "wb");
    if (dst_file == NULL) {
        fclose(src_file);
        return ret;
    }
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        fwrite(buffer, 1, bytes_read, dst_file);
    }
    fclose(src_file);
    fclose(dst_file);
    ret = CRYPT_SUCCESS;
    return ret;
}

static void ResetStatus(void)
{
    CreatIntegrityFile(); // Generating an Integrity Verification File
    CRYPT_EAL_RegEventReport(NULL);
}

static void StartTest(void)
{
    RegNormalMem();
}

static void ResetStatusAndStartTest(void)
{
    ResetStatus();
    StartTest();
}

static void EndTest(void)
{
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC002
* @spec  -
* @title  Integrity verification file error_Integrity verification file missing
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC002(void)
{
    ResetStatus();
    ASSERT_TRUE(remove("test_suite_sdv_cmvp.hmac") == 0);
    StartTest();
    ASSERT_TRUE(CMVP_CheckIntegrity(NULL, NULL, CRYPT_MAC_HMAC_SHA256) == CRYPT_CMVP_ERR_INTEGRITY);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC003
* @spec  -
* @title  Integrity verification file error_Integrity verification file is falsified.
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC003(void)
{
    ResetStatus();
    ASSERT_TRUE(FalsifyFile("test_suite_sdv_cmvp.hmac") == 0);
    StartTest();
    ASSERT_TRUE(CMVP_CheckIntegrity(NULL, NULL, CRYPT_MAC_HMAC_SHA256) == CRYPT_CMVP_ERR_INTEGRITY);
EXIT:
    RecoverFile("test_suite_sdv_cmvp.hmac");
    EndTest();
}

/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC004
* @spec  -
* @title  Integrity verification file error_Integrity verification file is generated with incorrect Mac key
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC004(void)
{
    const char fake_key[] = "a8fc4931453af3285f0f";
    ResetStatus();
    ASSERT_TRUE(CreateFakeIntegrityFile(fake_key, CRYPT_MAC_HMAC_SHA256) == 0);
    StartTest();
    ASSERT_TRUE(CMVP_CheckIntegrity(NULL, NULL, CRYPT_MAC_HMAC_SHA256) == CRYPT_CMVP_ERR_INTEGRITY);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC005
* @spec  -
* @title  Integrity verification file error_Integrity verification file is generated using an incorrect algorithm
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC005(void)
{
    const char key[] = "b8fc4931453af3285f0f";
    ResetStatus();
    ASSERT_TRUE(CreateFakeIntegrityFile(key, CRYPT_MAC_HMAC_SHA3_256) == 0);
    StartTest();
    ASSERT_TRUE(CMVP_CheckIntegrity(NULL, NULL, CRYPT_MAC_HMAC_SHA256) == CRYPT_CMVP_ERR_INTEGRITY);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC006
* @spec  -
* @title  Integrity verification file error_"test_suite_sdv_cmvp" file missing
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC006(void)
{
    ResetStatus();
    ASSERT_TRUE(CopyFile("test_suite_sdv_cmvp") == 0);
    ASSERT_TRUE(remove("test_suite_sdv_cmvp") == 0);
    StartTest();
    ASSERT_TRUE(CMVP_CheckIntegrity(NULL, NULL, CRYPT_MAC_HMAC_SHA256) == CRYPT_CMVP_ERR_INTEGRITY);
EXIT:
    ASSERT_TRUE(rename("copy", "test_suite_sdv_cmvp") == 0);
    ASSERT_TRUE(chmod("test_suite_sdv_cmvp", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC001
* @spec  -
* @title  Integrity verification file is correct_Integrity verification file
* @precon  nan
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_SUCCESS
2.return no NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC001(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CMVP_CheckIntegrity(NULL, NULL, CRYPT_MAC_HMAC_SHA256) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC001
* @spec  -
* @title  MAC Algorithm self-check, Algorithm id
* @precon  nan
* @brief
1.Register Memory Management
2.Transfer CRYPT_MAC_HMAC_SHA1 to perform algorithm self-check. Expected result 2 is obtained.
3.Transfer CRYPT_MAC_HMAC_SHA224 to perform algorithm self-check. Expected result 3 is obtained.
4.Transfer CRYPT_MAC_HMAC_SHA256 to perform algorithm self-check. Expected result 4 is obtained.
5.Transfer CRYPT_MAC_HMAC_SHA384 to perform algorithm self-check. Expected result 5 is obtained.
6.Transfer CRYPT_MAC_HMAC_SHA512 to perform algorithm self-check. Expected result 6 is obtained.
7.Transfer CRYPT_MAC_MAX to perform algorithm self-check. Expected result 7 is obtained.
8.Transfer -1 to perform algorithm self-check. Expected result 8 is obtained.
* @expect
1.none 2.return true 3.return true
4.return true 5.return true 6.return true
7.return true 8.return true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC001(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES192) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES192) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC010
* @spec  -
* @title  MD Algorithm self-check. Indicates whether the ID is valid.
* @precon  nan
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
3.Transfer CRYPT_MD_MD5 to perform algorithm self-check. Expected result 2 is obtained.
3.Transfer CRYPT_MD_SHA1 to perform algorithm self-check. Expected result 3 is obtained.
4.Transfer CRYPT_MD_SHA224 to perform algorithm self-check. Expected result 4 is obtained.
5.Transfer CRYPT_MD_SHA256 to perform algorithm self-check. Expected result 5 is obtained.
6.Transfer CRYPT_MD_SHA384 to perform algorithm self-check. Expected result 6 is obtained.
7.Transfer CRYPT_MD_SHA512 to perform algorithm self-check. Expected result 7 is obtained.
8.Transfer CRYPT_MD_SHA3_224 to perform algorithm self-check. Expected result 8 is obtained.
9.Transfer CRYPT_MD_SHA3_256 to perform algorithm self-check. Expected result 9 is obtained.
10.Transfer CRYPT_MD_SHA3_384 to perform algorithm self-check. Expected result 10 is obtained.
11.Transfer CRYPT_MD_SHA3_512 to perform algorithm self-check. Expected result 111 is obtained.
12.Transfer CRYPT_MD_SM3 to perform algorithm self-check. Expected result 12 is obtained.
13.Transfer CRYPT_MD_MAX to perform algorithm self-check. Expected result 13 is obtained.
14.Transfer -1 to perform algorithm self-check. Expected result 14 is obtained.
* @expect
1.none 2.return false 3.return true
4.return true 5.return true 6.return true
7.return true 8.return true 9.return true
10.return true 11.return true 12.return false
13.return false 14.return false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC010(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_MD5) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHAKE128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHAKE256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC019
* @spec  -
* @title  DRBG Algorithm self-check. Indicates whether the ID is valid.
* @precon  Prepare the test environment.
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
2.Transfer CRYPT_RAND_AES128_CTR_DF to perform algorithm self-check. Expected result 2 is obtained.
3.Transfer CRYPT_RAND_AES192_CTR_DF to perform algorithm self-check. Expected result 3 is obtained.
4.Transfer CRYPT_RAND_AES256_CTR_DF to perform algorithm self-check. Expected result 4 is obtained.
5.Transfer CRYPT_RAND_AES128_CTR to perform algorithm self-check. Expected result 5 is obtained.
6.Transfer CRYPT_RAND_AES192_CTR to perform algorithm self-check. Expected result 6 is obtained.
7.Transfer CRYPT_RAND_AES256_CTR to perform algorithm self-check. Expected result 7 is obtained.
8.Transfer CRYPT_RAND_HMAC_SHA1 to perform algorithm self-check. Expected result 8 is obtained.
9.Transfer CRYPT_RAND_HMAC_SHA224 to perform algorithm self-check. Expected result 9 is obtained.
10.Transfer CRYPT_RAND_HMAC_SHA256 to perform algorithm self-check. Expected result 10 is obtained.
11.Transfer CRYPT_RAND_HMAC_SHA384 to perform algorithm self-check. Expected result 11 is obtained.
12.Transfer CRYPT_RAND_HMAC_SHA512 to perform algorithm self-check. Expected result 12 is obtained.
13.Transfer CRYPT_RAND_SHA1 to perform algorithm self-check. Expected result 13 is obtained.
14.Transfer CRYPT_RAND_SHA224 to perform algorithm self-check. Expected result 14 is obtained.
15.Transfer CRYPT_RAND_SHA256 to perform algorithm self-check. Expected result 15 is obtained.
16.Transfer CRYPT_RAND_SHA384 to perform algorithm self-check. Expected result 16 is obtained.
17.Transfer CRYPT_RAND_SHA512 to perform algorithm self-check. Expected result 17 is obtained.
18.Transfer CRYPT_RAND_ALGID_MAX to perform algorithm self-check. Expected result 18 is obtained.
19.Transfer -1 to perform algorithm self-check. Expected result 19 is obtained.
* @expect
1.none
2.return true 3.return true 4.return true 5.return true
6.return true 7.return true 8.return true 9.return true
10.return true 11.return true 12.return true 13.return true
14.return true 15.return true 16.return true 17.return true
18.return false 19.return false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC019(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES128_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES192_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM4_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES128_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES192_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_ALGID_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC035
* @spec  -
* @title  SM2 Algorithm self-check.
* @precon  nan
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
2.Perform SM2 algorithm self-check. Expected result 2 is obtained.
* @expect
1.none
2.return true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC035(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestSM2() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC036
* @spec  -
* @title  RSA Algorithm self-check.
* @precon  nan
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
2.Perform RSA algorithm self-check. Expected result 2 is obtained.
* @expect
1.none
2.return true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC036(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestRsa() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC037
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171150526
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC037(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_CHACHA20_POLY1305) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC038
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171311299
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC038(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestChacha20poly1305() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC039
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171322795
* @precon  准备好测试环境
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC039(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDh() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC040
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171331230
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC040(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDsa() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC041
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171347201
* @precon  准备好测试环境
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC041(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestEd25519() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC042
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171421887
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
* 2.执行Hkdf算法自检,有预期结果2
* 3.执行Pbkdf2算法自检,有预期结果3
* 4.执行Scrypt算法自检,有预期结果4
* @expect  1.返回BSL_SUCCESS
2.返回true 3.返回true 4.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC042(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestHkdf() == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestScrypt() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC043
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171421887
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
* 2.执行KdfTls12算法自检,有预期结果2
* @expect  1.无
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC043(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestKdfTls12() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC045
* @spec  -
* @title  X25519算法自检
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC045(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestX25519() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC046
* @spec  -
* @title  内存管理未注册_内存是否注册_20220523171100467
* @precon  nan
* @brief  1.传入CRYPT_RAND_AES256_CTR_DF执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC046(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR_DF) == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC047
* @spec  -
* @title  内存管理未注册_内存管理回调是否注册_20220523171144681
* @precon  准备好测试环境
* @brief  1.传入CRYPT_MD_SHA256执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC047(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA256) == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC048
* @spec  -
* @title  内存管理未注册_内存管理是否已注册_20220523171355210
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC048(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestRsa() == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC049
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171153018
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC049(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC050
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171318396
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC050(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestChacha20poly1305() == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC051
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171325201
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC051(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestDh() == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC052
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171333044
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC052(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestDsa() == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC053
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171349655
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC053(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestEd25519() == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC054
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171358066
* @precon  准备好测试环境
* @brief  1.执行Hkdf算法自检,有预期结果1
* 2.执行Pbkdf2算法自检,有预期结果2
* 3.执行Scrypt算法自检,有预期结果3
* @expect  1.返回false 2.返回false 3.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC054(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestHkdf() == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SHA1) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestScrypt() == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC057
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171435826
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC057(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestX25519() == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC058(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA256) == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC059
* @spec  -
* @title  ECDSA算法自检
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC059(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestEcdsa() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC060
* @spec  -
* @title  ECDH算法自检
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC060(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestEcdh() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC062
* @spec  -
* @title  内存管理未注册_内存管理是否注册
* @precon  nan
* @brief  1.执行TDES算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC062(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_Malloc);;
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == false);
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC063
* @spec  -
* @title  CMVP test for MLDSA
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC063(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMldsaSignVerify() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC064
* @spec  -
* @title  CMVP test for MLKEM
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC064(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMlkemEncapsDecaps() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC065
* @spec  -
* @title  CMVP test for SLHDSA
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC065(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestSlhdsaSignVerify() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */
#endif
