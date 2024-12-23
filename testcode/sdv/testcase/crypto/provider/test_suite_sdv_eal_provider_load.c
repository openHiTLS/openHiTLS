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
#include "crypt_eal_init.h"
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
#include "crypt_eal_md.h"
/* END_HEADER */

#define PROVIDER_LOAD_SAIZE_2 2
#define PATH_EXCEED 4097

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_FUNC_TC001
 * @title Provider load and unload functionality test
 * @precon None
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

    // Test CRYPT_EAL_ProviderLoad
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    // Test CRYPT_EAL_ProviderLoad
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test loading the same provider consecutively
    ret = CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Verify only one EAL_ProviderMgrCtx structure for this provider in the providers list,and ref == 2
    ASSERT_EQ(BSL_LIST_COUNT(libCtx->providers), 2);
    CRYPT_EAL_ProvMgrCtx *providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_FIRST_ELMT(libCtx->providers);
    ASSERT_TRUE(providerMgr != NULL);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_LAST_ELMT(libCtx->providers);
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
    providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_FIRST_ELMT(libCtx->providers);
    ASSERT_TRUE(providerMgr != NULL);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2 + 1);

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

EXIT:
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

EXIT:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */

#define RIGHT_RESULT 1415926

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_TC003
 * @title Test load provider into global libctx
 * @precon None
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_TC003(char *path, int cmd, char *test1, char *attrName)
{
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, cmd, test1, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(NULL, cmd, test1), CRYPT_SUCCESS);
    CRYPT_EAL_Cleanup(1);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, cmd, test1, NULL, NULL), CRYPT_PROVIDER_INVALID_LIB_CTX);
    ASSERT_EQ(CRYPT_EAL_Init(1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, cmd, test1, NULL, NULL), CRYPT_SUCCESS);
    mdCtx = CRYPT_EAL_ProviderMdNewCtx(NULL, CRYPT_MD_MD5, NULL);
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), CRYPT_SUCCESS);
    CRYPT_EAL_MdFreeCtx(mdCtx);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(NULL, CRYPT_MD_MD5, attrName);
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), RIGHT_RESULT);

EXIT:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    CRYPT_EAL_Cleanup(1);
    ASSERT_EQ(CRYPT_EAL_Init(1), CRYPT_SUCCESS);
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
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, attribute, &funcs, &provCtx);
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

EXIT:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */

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
    ASSERT_EQ(CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider=test1",
        &funcs, &provCtx), CRYPT_SUCCESS);
    CRYPT_EAL_ImplMdInitCtx mdInitCtx = (CRYPT_EAL_ImplMdInitCtx)(funcs[1].func);
    ASSERT_EQ(mdInitCtx(provCtx, NULL), RIGHT_RESULT);
    ASSERT_EQ(CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5,
        "provider=test1,provider!=test2", &funcs, &provCtx), CRYPT_SUCCESS);
    mdInitCtx = (CRYPT_EAL_ImplMdInitCtx)(funcs[1].func);
    ASSERT_EQ(mdInitCtx(provCtx, NULL), RIGHT_RESULT);

    // Test 1: Test when attribute is NULL
    ASSERT_EQ(CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, NULL, &funcs, &provCtx),
        CRYPT_SUCCESS);
    mdInitCtx = (CRYPT_EAL_ImplMdInitCtx)(funcs[1].func);
    ASSERT_EQ(mdInitCtx(provCtx, NULL), result);
    funcs = provCtx = NULL;

    // Test 2: Test when no provider can meet the attribute requirements
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "n_atr=test3", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    // Test 3: Test when both operaid and operaid are out of range
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, 0, CRYPT_MD_MD5, "provider=test1", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, 0, "provider=test1", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    // Test 4: Test when attribute format is non-standard
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_ATTRIBUTE);
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider=test1provider!=test2",
        &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "provider!test2",
        &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_ATTRIBUTE);
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "!=tesst2", &funcs, &provCtx);
    ASSERT_EQ(ret, CRYPT_PROVIDER_ERR_ATTRIBUTE);

EXIT:
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

EXIT:
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

EXIT:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
}
/* END_CASE */


/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_DEFAULT_TC001
 * Load two providers, one of which is the default provider,
 * query the algorithm from the default provider, and calculate the result
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_DEFAULT_TC001(char *path, char *test1, int cmd, Hex *msg, Hex *hash)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_MdCTX *ctx = NULL;
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

    // Test CRYPT_EAL_ProviderLoad
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    // Test CRYPT_EAL_ProviderLoad
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA224, "provider=default");
    ASSERT_TRUE(ctx != NULL);
    uint8_t output[32];
    uint32_t outLen = sizeof(output);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);
EXIT:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    if (ctx != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
    }
    return;
}
/* END_CASE */