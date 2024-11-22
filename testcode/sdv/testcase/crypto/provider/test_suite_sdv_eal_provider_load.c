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
#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_provider_local.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_eal_mac.h"
#include "eal_mac_local.h"
#include "crypt_eal_kdf.h"
#include "eal_kdf_local.h"
#include "crypt_eal_md.h"
#include "eal_md_local.h"
#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
#include "test.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_errno.h"
/* END_HEADER */

#define PROVIDER_LOAD_SAIZE_2 2
#define PATH_EXCEED 4097

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_FUNC_TC001
 * @title Provider load and unload functionality test
 * @precon None
 * @brief
 *    1. Call CRYPT_EAL_LibCtxNew to create a library context. Expected result 1 is obtained.
 *    2. Call CRYPT_EAL_ProviderSetLoadPath to set the provider path. Expected result 2 is obtained.
 *    3. Call CRYPT_EAL_ProviderLoad to load providers. Expected result 3 is obtained.
 *    4. Call CRYPT_EAL_ProviderLoad with non-existent provider. Expected result 4 is obtained.
 *    5. Call CRYPT_EAL_ProviderLoad with provider lacking init function. Expected result 5 is obtained.
 *    6. Call CRYPT_EAL_ProviderLoad with provider lacking full functions. Expected result 6 is obtained.
 *    7. Call CRYPT_EAL_ProviderLoad to load the same provider again. Expected result 7 is obtained.
 *    8. Call CRYPT_EAL_ProviderLoad with different cmd for the same name. Expected result 8 is obtained.
 *    9. Call CRYPT_EAL_ProviderLoad with same cmd and name but different path. Expected result 9 is obtained.
 *    10. Call CRYPT_EAL_ProviderUnload to unload providers. Expected result 10 is obtained.
 *    11. Call CRYPT_EAL_ProviderUnload with non-existent provider. Expected result 11 is obtained.
 * @expect
 *    1. Library context is created successfully.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS for valid providers
 *    4. BSL_SAL_ERR_DL_NOT_FOUND
 *    5. CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL
 *    6. CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL
 *    7. CRYPT_SUCCESS, and only one EAL_ProviderMgrCtx structure for the provider in list with ref == 2
 *    8. CRYPT_SUCCESS
 *    9. CRYPT_SUCCESS
 *    10. CRYPT_SUCCESS
 *    11. CRYPT_SUCCESS
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_TC001(char *path, char *path2, char *test1, char *test2, char *testNoInit,
    char *testNoFullfunc, int cmd, int cmd2)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    int32_t ret;

    // Test CRYPT_EAL_LibCtxNew
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    // Test CRYPT_EAL_ProviderSetLoadPath
    ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, path);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test CRYPT_EAL_ProviderLoad
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test loading the same provider consecutively
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Verify only one EAL_ProviderMgrCtx structure for this provider in the providers list,and ref == 2
    ASSERT_EQ(BSL_LIST_COUNT(libCtx->providers), 1);
    CRYPT_EAL_ProvMgrCtx *providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_FIRST_ELMT(libCtx->providers);
    ASSERT_TRUE(providerMgr != NULL);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    // Test if loading the same name with different cmd is successful and not recognized as the same provider
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd2, test1, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    // Test if loading the same provider name with the same cmd from different paths is successful
    // and will recognized as the same provider。
    ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, path2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2+1);

    ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, path);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test2, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test loading a non-existent provider
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, "non_existent_provider", NULL, NULL);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NOT_FOUND);

    // Test loading a provider without initialization function
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, testNoInit, NULL, NULL);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NON_FUNCTION);

    // Test loading a provider without complete return methods
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, testNoFullfunc, NULL, NULL);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);

    setenv("LD_LIBRARY_PATH", path, 1);
    ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test CRYPT_EAL_ProviderUnload
    ret = CRYPT_EAL_ProviderUnload(libCtx, cmd, test1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_ProviderUnload(libCtx, cmd, test1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_ProviderUnload(libCtx, cmd, test2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test unloading a non-existent provider
    ret = CRYPT_EAL_ProviderUnload(libCtx, cmd, "non_existent_provider");
    ASSERT_EQ(ret, CRYPT_SUCCESS);

exit:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_FUNC_TC002
 * @title Test if an error occurs when the length of the set path exceeds
 * @precon None
 * @brief
 *    1. Test if an error is reported when the path length exceeds the maximum length in Linux.
 * @expect
 *    1. CRYPT_INVALID_ARG
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_TC002(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    int32_t ret;

    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    // Test if an error is reported when the path length exceeds the maximum length in Linux
    char *overpath = (char *)BSL_SAL_Calloc(1, PATH_EXCEED);
    ASSERT_TRUE(overpath != NULL);
    ret = memset_s(overpath, PATH_EXCEED, 'a', PATH_EXCEED - 1);
    ASSERT_EQ(ret, 0);
    ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, overpath);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    BSL_SAL_Free(overpath);

exit:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_COMPARE_TC001
 * @title Test the normal scenarios of provider lookup mechanism
 * @precon None
 * @brief
 *    1. Test if the corresponding funcs can be found based on the attribute
 * @expect
 *    1. CRYPT_SUCCESS for loading providers and getting functions
 *    2. The result of mdInitCtx matches the expected result
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_COMPARE_TC001(char *path, char *test1, char *test2, int cmd, char *attribute, int result)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    int32_t ret;

    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, path);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test2, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const CRYPT_EAL_Func *funcs;
    void *provCtx;
    // Test if the corresponding funcs can be found based on the attribute
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, attribute, &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(funcs != NULL);
    CRYPT_EAL_ImplMdInitCtx mdInitCtx = (CRYPT_EAL_ImplMdInitCtx)(funcs[1].func);
    ASSERT_TRUE(mdInitCtx != NULL);
    ret = mdInitCtx(provCtx, NULL);
    ASSERT_EQ(ret, result);

    ret = CRYPT_EAL_ProviderUnload(libCtx, cmd, test1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_ProviderUnload(libCtx, cmd, test2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

exit:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */

#define RIGHT_RESULT 1415926

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_COMPARE_TC002
 * @title Test special scenarios of provider lookup mechanism
 * @precon None
 * @brief
 *    1. Test when attribute is NULL
 *    2. Test when no provider can meet the attribute requirements
 *    3. Test when operaid and operaid are out of range
 * @expect
 *    1. CRYPT_SUCCESS for loading providers and getting functions
 *    2. CRYPT_NOT_SUPPORT when no provider meets the requirements or operaid is out of range
 *    3. The result of mdInitCtx matches the expected result
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_COMPARE_TC002(char *path, char *test1, char *test2, int cmd, int result)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    int32_t ret;

    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test2, NULL, NULL), CRYPT_SUCCESS);

    const CRYPT_EAL_Func *funcs;
    void *provCtx;
    // Demonstrate normal scenario
    ASSERT_EQ(CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider=test1",
        &funcs, &provCtx), CRYPT_SUCCESS);
    CRYPT_EAL_ImplMdInitCtx mdInitCtx = (CRYPT_EAL_ImplMdInitCtx)(funcs[1].func);
    ASSERT_EQ(mdInitCtx(provCtx, NULL), RIGHT_RESULT);
    ASSERT_EQ(CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5,
        "provider=test1,provider!=test2", &funcs, &provCtx), CRYPT_SUCCESS);
    mdInitCtx = (CRYPT_EAL_ImplMdInitCtx)(funcs[1].func);
    ASSERT_EQ(mdInitCtx(provCtx, NULL), RIGHT_RESULT);

    // Test 1: Test when attribute is NULL
    ASSERT_EQ(CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, NULL, &funcs, &provCtx),
        CRYPT_SUCCESS);
    mdInitCtx = (CRYPT_EAL_ImplMdInitCtx)(funcs[1].func);
    ASSERT_EQ(mdInitCtx(provCtx, NULL), result);
    funcs = provCtx = NULL;

    // Test 2: Test when no provider can meet the attribute requirements
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "n_atr=test3", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    // Test 3: Test when both operaid and operaid are out of range
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, 0, CRYPT_MD_MD5, "provider=test1", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, 0, "provider=test1", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    // Test 4: Test when attribute format is non-standard
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_ATTRIBUTE);
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider=test1provider!=test2",
        &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider!test2",
        &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_ATTRIBUTE);
    ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "!=tesst2", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_ATTRIBUTE);

exit:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_UNINSTALL_TC001
 * @title Test whether the external interface of each algorithm reports an error
 * when using the provider method provided by a third party that does not contain newctx
 * @precon None
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_UNINSTALL_TC001(char *path, char *providerNoInit, int cmd)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, providerNoInit, NULL, NULL), CRYPT_SUCCESS);

    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_SCRYPT, NULL);
    ASSERT_TRUE(kdfCtx == NULL);
    CRYPT_EAL_MacCtx *macCtx = CRYPT_EAL_ProviderMacNewCtx(libCtx, CRYPT_MAC_HMAC_MD5, NULL);
    ASSERT_TRUE(macCtx == NULL);
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, NULL);
    ASSERT_TRUE(mdCtx == NULL);
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_DSA, 0, NULL);
    ASSERT_TRUE(pkeyCtx == NULL);

exit:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_UNINSTALL_TC002
 * @title Test whether the external interfaces of each algorithm run normally
 * when using the provider method provided by a third party without freectx
 * @precon None
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_UNINSTALL_TC002(char *path, char *providerNoFree, int cmd)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, providerNoFree, NULL, NULL), CRYPT_SUCCESS);

    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_SCRYPT, NULL);
    ASSERT_TRUE(kdfCtx != NULL);
    void *tempData = kdfCtx->data;
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    BSL_SAL_FREE(tempData);
    CRYPT_EAL_MacCtx *macCtx = CRYPT_EAL_ProviderMacNewCtx(libCtx, CRYPT_MAC_HMAC_MD5, NULL);
    ASSERT_TRUE(macCtx != NULL);
    tempData = macCtx->ctx;
    CRYPT_EAL_MacFreeCtx(macCtx);
    BSL_SAL_FREE(tempData);
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, NULL);
    ASSERT_TRUE(mdCtx != NULL);
    tempData = mdCtx->data;
    CRYPT_EAL_MdFreeCtx(mdCtx);
    BSL_SAL_FREE(tempData);
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_DSA, 0, NULL);
    ASSERT_TRUE(pkeyCtx != NULL);
    tempData = pkeyCtx->key;
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(tempData);

exit:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */