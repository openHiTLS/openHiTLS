/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */
#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_provider_local.h"
#include "crypt_eal_implprovider.h"
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
 *    1. Call CRYPT_EAL_NewLibCtx to create a library context. Expected result 1 is obtained.
 *    2. Call CRYPT_EAL_SetLoadProviderPath to set the provider path. Expected result 2 is obtained.
 *    3. Call CRYPT_EAL_LoadProvider to load providers. Expected result 3 is obtained.
 *    4. Call CRYPT_EAL_LoadProvider with non-existent provider. Expected result 4 is obtained.
 *    5. Call CRYPT_EAL_LoadProvider with provider lacking init function. Expected result 5 is obtained.
 *    6. Call CRYPT_EAL_LoadProvider with provider lacking full functions. Expected result 6 is obtained.
 *    7. Call CRYPT_EAL_LoadProvider to load the same provider again. Expected result 7 is obtained.
 *    8. Call CRYPT_EAL_LoadProvider with different cmd for the same name. Expected result 8 is obtained.
 *    9. Call CRYPT_EAL_LoadProvider with same cmd and name but different path. Expected result 9 is obtained.
 *    10. Call CRYPT_EAL_UnloadProvider to unload providers. Expected result 10 is obtained.
 *    11. Call CRYPT_EAL_UnloadProvider with non-existent provider. Expected result 11 is obtained.
 * @expect
 *    1. Library context is created successfully.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS for valid providers
 *    4. BSL_SAL_ERR_DL_NOT_FOUND
 *    5. CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL
 *    6. CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL
 *    7. CRYPT_SUCCESS, and only one EalProviderMgrCtx structure for the provider in list with ref == 2
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

    // Test CRYPT_EAL_NewLibCtx
    libCtx = CRYPT_EAL_NewLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    // Test CRYPT_EAL_SetLoadProviderPath
    ret = CRYPT_EAL_SetLoadProviderPath(libCtx, path);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test CRYPT_EAL_LoadProvider
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd, test1, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test loading the same provider consecutively
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd, test1, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Verify only one EalProviderMgrCtx structure for this provider in the providers list,and ref == 2
    ASSERT_EQ(BSL_LIST_COUNT(libCtx->providers), 1);
    CRYPT_EAL_ProvMgrCtx *providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_FIRST_ELMT(libCtx->providers);
    ASSERT_TRUE(providerMgr != NULL);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    // Test if loading the same name with different cmd is successful and not recognized as the same provider
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd2, test1, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    // Test if loading the same provider name with the same cmd from different paths is successful
    // and not recognized as the same provider。
    ret = CRYPT_EAL_SetLoadProviderPath(libCtx, path2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd, test1, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    ret = CRYPT_EAL_SetLoadProviderPath(libCtx, path);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd, test2, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test loading a non-existent provider
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd, "non_existent_provider", NULL);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NOT_FOUND);

    // Test loading a provider without initialization function
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd, testNoInit, NULL);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NON_FUNCTION);

    // Test loading a provider without complete return methods
    ret = CRYPT_EAL_LoadProvider(libCtx, cmd, testNoFullfunc, NULL);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);

    // Test CRYPT_EAL_UnloadProvider
    ret = CRYPT_EAL_UnloadProvider(libCtx, cmd, test1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_UnloadProvider(libCtx, cmd, test1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_UnloadProvider(libCtx, cmd, test2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test unloading a non-existent provider
    ret = CRYPT_EAL_UnloadProvider(libCtx, cmd, "non_existent_provider");
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

    libCtx = CRYPT_EAL_NewLibCtx();
    ASSERT_TRUE(libCtx != NULL);

    // Test if an error is reported when the path length exceeds the maximum length in Linux
    char *overpath = (char *)BSL_SAL_Calloc(1, PATH_EXCEED);
    ASSERT_TRUE(overpath != NULL);
    ret = memset_s(overpath, PATH_EXCEED, 'a', PATH_EXCEED - 1);
    ASSERT_EQ(ret, 0);
    ret = CRYPT_EAL_SetLoadProviderPath(libCtx, overpath);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);
    BSL_SAL_Free(overpath);

exit:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */
