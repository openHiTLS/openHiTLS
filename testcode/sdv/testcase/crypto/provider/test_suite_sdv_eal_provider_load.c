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
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
/* END_HEADER */

#define PROVIDER_LOAD_SAIZE_2 2
#define PATH_EXCEED 4097
#define NEW_PARA_ALGID (BSL_CID_MAX + 1)
#define NEW_PKEY_ALGID (BSL_CID_MAX + 2)
#define NEW_SIGN_HASH_ALGID (BSL_CID_MAX + 3)
#define NEW_HASH_ALGID (BSL_CID_MAX + 4)

/**
 * @test SDV_CRYPTO_PROVIDER_LOAD_FUNC_TC001
 * @title Provider load and unload functionality test
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_LOAD_TC001(char *path, char *path2, char *test1, char *test2, char *testNoInit,
    char *testNoFullfunc, int cmd, int cmd2)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)path2;
    (void)test1;
    (void)test2;
    (void)testNoInit;
    (void)testNoFullfunc;
    (void)cmd;
    (void)cmd2;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;

    // Test CRYPT_EAL_LibCtxNew
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    // Test CRYPT_EAL_ProviderSetLoadPath
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);

    // Test CRYPT_EAL_ProviderLoad
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL), CRYPT_SUCCESS);

    // Test CRYPT_EAL_ProviderLoad
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL), CRYPT_SUCCESS);
    // Test CRYPT_EAL_ProviderLoad
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL), CRYPT_SUCCESS);

    // Test loading the same provider consecutively
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL), CRYPT_SUCCESS);

    // Verify only one EAL_ProviderMgrCtx structure for this provider in the providers list,and ref == 2
    ASSERT_EQ(BSL_LIST_COUNT(libCtx->providers), 2);
    CRYPT_EAL_ProvMgrCtx *providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_FIRST_ELMT(libCtx->providers);
    ASSERT_TRUE(providerMgr != NULL);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_LAST_ELMT(libCtx->providers);
    ASSERT_TRUE(providerMgr != NULL);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    // Test if loading the same name with different cmd is successful and not recognized as the same provider
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd2, test1, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2);

    // Test if loading the same provider name with the same cmd from different paths is successful
    // and will recognized as the same provider。
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL), CRYPT_SUCCESS);
    providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_FIRST_ELMT(libCtx->providers);
    ASSERT_TRUE(providerMgr != NULL);
    ASSERT_EQ(providerMgr->ref.count, PROVIDER_LOAD_SAIZE_2 + 1);

    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test2, NULL, NULL), CRYPT_SUCCESS);

    // Test loading a non-existent provider
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, "non_existent_provider", NULL, NULL), BSL_SAL_ERR_DL_NOT_FOUND);

    // Test loading a provider without initialization function
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, testNoInit, NULL, NULL), BSL_SAL_ERR_DL_NON_FUNCTION);

    // Test loading a provider without complete return methods
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, testNoFullfunc, NULL, NULL), CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);

    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test2, NULL, NULL), CRYPT_SUCCESS);

    // Test CRYPT_EAL_ProviderUnload
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test2), CRYPT_SUCCESS);

    // Test unloading a non-existent provider
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, "non_existent_provider"), CRYPT_SUCCESS);

EXIT:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
#endif
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
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
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
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);
    BSL_SAL_Free(overpath);

EXIT:
    if (libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(libCtx);
    }
    return;
#endif
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
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)cmd;
    (void)test1;
    (void)attrName;
    SKIP_TEST();
#else
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, cmd, test1, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(NULL, cmd, test1), CRYPT_SUCCESS);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, cmd, test1, NULL, NULL), CRYPT_PROVIDER_INVALID_LIB_CTX);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND), CRYPT_SUCCESS);
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
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND), CRYPT_SUCCESS);
#endif
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
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)test1;
    (void)test2;
    (void)cmd;
    (void)attribute;
    (void)result;
    SKIP_TEST();
#else
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
#endif
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
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)test1;
    (void)test2;
    (void)cmd;
    (void)result;
    SKIP_TEST();
#else
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
#endif
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
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)providerNoInit;
    (void)cmd;
    SKIP_TEST();
#else
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
    CRYPT_EAL_LibCtxFree(libCtx);
    return;
#endif
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
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)providerNoFree;
    (void)cmd;
    SKIP_TEST();
#else
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
    CRYPT_EAL_LibCtxFree(libCtx);
    return;
#endif
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
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)test1;
    (void)cmd;
    (void)msg;
    (void)hash;
    SKIP_TEST();
#else
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
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_MdFreeCtx(ctx);
    return;
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t GroupCapsCallback(BSL_Param *param, void *args)
{
    int *count = (int *)args;
    (*count)++;

    BSL_Param *groupNameParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME);
    ASSERT_TRUE(groupNameParam != NULL);
    ASSERT_EQ(groupNameParam->valueType, BSL_PARAM_TYPE_OCTETS_PTR);
    ASSERT_TRUE(groupNameParam->value != NULL);
    BSL_Param *groupIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID);
    ASSERT_TRUE(groupIdParam != NULL);
    ASSERT_EQ(groupIdParam->valueType, BSL_PARAM_TYPE_UINT16);
    ASSERT_TRUE(groupIdParam->value != NULL);
    ASSERT_TRUE(groupIdParam->valueLen == sizeof(uint16_t));
    groupIdParam->useLen = sizeof(uint16_t);
    BSL_Param *paraIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID);
    ASSERT_TRUE(paraIdParam != NULL);
    ASSERT_EQ(paraIdParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(paraIdParam->value != NULL);
    ASSERT_TRUE(paraIdParam->valueLen == sizeof(int32_t));
    paraIdParam->useLen = sizeof(int32_t);
    BSL_Param *algIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID);
    ASSERT_TRUE(algIdParam != NULL);
    ASSERT_EQ(algIdParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(algIdParam->value != NULL);
    ASSERT_TRUE(algIdParam->valueLen == sizeof(int32_t));
    algIdParam->useLen = sizeof(int32_t);
    BSL_Param *secBitsParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS);
    ASSERT_TRUE(secBitsParam != NULL);
    ASSERT_EQ(secBitsParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(secBitsParam->value != NULL);
    ASSERT_TRUE(secBitsParam->valueLen == sizeof(int32_t));
    secBitsParam->useLen = sizeof(int32_t);
    BSL_Param *versionBitsParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS);
    ASSERT_TRUE(versionBitsParam != NULL);
    ASSERT_EQ(versionBitsParam->valueType, BSL_PARAM_TYPE_UINT32);
    ASSERT_TRUE(versionBitsParam->value != NULL);
    ASSERT_TRUE(versionBitsParam->valueLen == sizeof(uint32_t));
    versionBitsParam->useLen = sizeof(uint32_t);
    BSL_Param *isKemParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM);
    ASSERT_TRUE(isKemParam != NULL);
    ASSERT_EQ(isKemParam->valueType, BSL_PARAM_TYPE_BOOL);
    ASSERT_TRUE(isKemParam->valueLen == sizeof(bool));
    isKemParam->useLen = sizeof(bool);

    if (groupNameParam->value != NULL && strcmp((char *)groupNameParam->value, "secp256r1") == 0) {
        ASSERT_EQ(*((uint16_t *)groupIdParam->value), HITLS_EC_GROUP_SECP256R1);
        ASSERT_EQ(*((int32_t *)paraIdParam->value), CRYPT_ECC_NISTP256);
        ASSERT_EQ(*((int32_t *)algIdParam->value), CRYPT_PKEY_ECDH);
        ASSERT_EQ(*((int32_t *)secBitsParam->value), 128);
        ASSERT_EQ(*((uint32_t *)versionBitsParam->value), (TLS_VERSION_MASK | DTLS_VERSION_MASK));
        ASSERT_EQ(*((bool *)isKemParam->value), false);
    } else if (groupNameParam->value != NULL && strcmp((char *)groupNameParam->value, "test_new_group") == 0) {
        // Verify the custom group parameters from provider_get_cap_test1
        ASSERT_EQ(*((uint16_t *)groupIdParam->value), 477);
        ASSERT_EQ(*((int32_t *)paraIdParam->value), NEW_PARA_ALGID);
        ASSERT_EQ(*((int32_t *)algIdParam->value), NEW_PKEY_ALGID);
        ASSERT_EQ(*((int32_t *)secBitsParam->value), 1024);
        ASSERT_EQ(*((uint32_t *)versionBitsParam->value), (TLS12_VERSION_BIT | TLS13_VERSION_BIT));
        ASSERT_EQ(*((bool *)isKemParam->value), false);
    }

    return CRYPT_SUCCESS;
EXIT:
    return CRYPT_NOT_SUPPORT;
}

static int32_t SigAlgCapsCallback(BSL_Param *param, void *args)
{
    int *count = (int *)args;
    (*count)++;

    // 验证必要参数存在
    BSL_Param *sigNameParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME);
    ASSERT_TRUE(sigNameParam != NULL);
    ASSERT_EQ(sigNameParam->valueType, BSL_PARAM_TYPE_OCTETS_PTR);
    
    BSL_Param *sigIanaIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID);
    ASSERT_TRUE(sigIanaIdParam != NULL);
    ASSERT_EQ(sigIanaIdParam->valueType, BSL_PARAM_TYPE_UINT16);
    ASSERT_TRUE(sigIanaIdParam->valueLen == sizeof(uint16_t));
    sigIanaIdParam->useLen = sizeof(uint16_t);
    
    BSL_Param *keyTypeParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE);
    ASSERT_TRUE(keyTypeParam != NULL);
    ASSERT_EQ(keyTypeParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(keyTypeParam->valueLen == sizeof(int32_t));
    keyTypeParam->useLen = sizeof(int32_t);
    
    BSL_Param *paraIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID);
    ASSERT_TRUE(paraIdParam != NULL);
    ASSERT_EQ(paraIdParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(paraIdParam->valueLen == sizeof(int32_t));
    paraIdParam->useLen = sizeof(int32_t);

    BSL_Param *signHashAlgIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID);
    ASSERT_TRUE(signHashAlgIdParam != NULL);
    ASSERT_EQ(signHashAlgIdParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(signHashAlgIdParam->valueLen == sizeof(int32_t));
    signHashAlgIdParam->useLen = sizeof(int32_t);

    BSL_Param *signHashAlgOidParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID);
    BSL_Param *signHashAlgNameParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME);

    BSL_Param *signAlgIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID);
    ASSERT_TRUE(signAlgIdParam != NULL);
    ASSERT_EQ(signAlgIdParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(signAlgIdParam->valueLen == sizeof(int32_t));
    signAlgIdParam->useLen = sizeof(int32_t);

    BSL_Param *hashAlgIdParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID);
    ASSERT_TRUE(hashAlgIdParam != NULL);
    ASSERT_EQ(hashAlgIdParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(hashAlgIdParam->valueLen == sizeof(int32_t));
    hashAlgIdParam->useLen = sizeof(int32_t);
    BSL_Param *hashAlgOidParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID);
    BSL_Param *hashAlgNameParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME);
    BSL_Param *secBitsParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS);
    ASSERT_TRUE(secBitsParam != NULL);
    ASSERT_EQ(secBitsParam->valueType, BSL_PARAM_TYPE_INT32);
    ASSERT_TRUE(secBitsParam->valueLen == sizeof(int32_t));
    secBitsParam->useLen = sizeof(int32_t);

    BSL_Param *certVersionParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS);
    ASSERT_TRUE(certVersionParam != NULL);
    ASSERT_EQ(certVersionParam->valueType, BSL_PARAM_TYPE_UINT32);
    ASSERT_TRUE(certVersionParam->valueLen == sizeof(uint32_t));
    certVersionParam->useLen = sizeof(uint32_t);

    BSL_Param *chainVersionParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS);
    ASSERT_TRUE(chainVersionParam != NULL);
    ASSERT_EQ(chainVersionParam->valueType, BSL_PARAM_TYPE_UINT32);
    ASSERT_TRUE(chainVersionParam->valueLen == sizeof(uint32_t));
    chainVersionParam->useLen = sizeof(uint32_t);

    if (sigNameParam->value != NULL && strcmp((char *)sigNameParam->value, "ecdsa_secp256r1_sha256") == 0) {
        ASSERT_EQ(*((uint16_t *)sigIanaIdParam->value), CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256);
        ASSERT_EQ(*((int32_t *)keyTypeParam->value), TLS_CERT_KEY_TYPE_ECDSA);
        ASSERT_EQ(*((int32_t *)paraIdParam->value), CRYPT_ECC_NISTP256);
        ASSERT_EQ(*((int32_t *)signHashAlgIdParam->value), BSL_CID_ECDSAWITHSHA256);
        ASSERT_EQ(*((int32_t *)signAlgIdParam->value), CRYPT_PKEY_ECDSA);
        ASSERT_EQ(*((int32_t *)hashAlgIdParam->value), HITLS_HASH_SHA_256);
        ASSERT_EQ(*((int32_t *)secBitsParam->value), 128);
        ASSERT_EQ(*((uint32_t *)certVersionParam->value), (TLS_VERSION_MASK | DTLS_VERSION_MASK));
        ASSERT_EQ(*((uint32_t *)chainVersionParam->value), (TLS_VERSION_MASK | DTLS_VERSION_MASK));
    } else if (sigNameParam->value != NULL && strcmp((char *)sigNameParam->value, "test_new_sign_alg_name") == 0) {
        ASSERT_EQ(*((uint16_t *)sigIanaIdParam->value), 23333);
        ASSERT_EQ(*((int32_t *)keyTypeParam->value), CRYPT_PKEY_ECDSA);
        ASSERT_EQ(*((int32_t *)paraIdParam->value), BSL_CID_SECP384R1);
        if (signHashAlgOidParam != NULL) {
            char *signHashAlgOid = (char *)signHashAlgOidParam->value;
            ASSERT_EQ(strcmp(signHashAlgOid, "\150\40\66\77\55"), 0);
        }
        if (signHashAlgNameParam != NULL) {
            char *signHashAlgName = (char *)signHashAlgNameParam->value;
            ASSERT_EQ(strcmp(signHashAlgName, "test_new_sign_with_md_name"), 0);
        }
        ASSERT_EQ(*((int32_t *)signHashAlgIdParam->value), NEW_SIGN_HASH_ALGID);
        ASSERT_EQ(*((int32_t *)signAlgIdParam->value), CRYPT_PKEY_ECDSA);
        ASSERT_EQ(*((int32_t *)hashAlgIdParam->value), NEW_HASH_ALGID);
        if (hashAlgOidParam != NULL) {
            char *hashAlgOid = (char *)hashAlgOidParam->value;
            ASSERT_EQ(strcmp(hashAlgOid, "\150\40\66\71\55"), 0);
        }
        if (hashAlgNameParam != NULL) {
            char *hashAlgName = (char *)hashAlgNameParam->value;
            ASSERT_EQ(strcmp(hashAlgName, "test_new_md_name"), 0);
        }
        ASSERT_EQ(*((int32_t *)secBitsParam->value), 1024);
        ASSERT_EQ(*((uint32_t *)certVersionParam->value), (TLS12_VERSION_BIT | TLS13_VERSION_BIT));
        ASSERT_EQ(*((uint32_t *)chainVersionParam->value), (TLS12_VERSION_BIT | TLS13_VERSION_BIT));
    }

    return CRYPT_SUCCESS;
EXIT:
    return CRYPT_NOT_SUPPORT;
}
#endif

/**
 * @test SDV_CRYPTO_PROVIDER_GET_CAPS_TC002
 * @title Test CRYPT_EAL_ProviderGetCaps for default provider capabilities
 * @precon None
 * @brief
 *    1. Test getting group capabilities (curves)
 *    2. Test getting signature algorithm capabilities
 * @expect
 *    1. Successfully get and verify group parameters
 *    2. Successfully get and verify signature algorithm parameters
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_GET_CAPS_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    CRYPT_EAL_ProvMgrCtx provMgrWithGetCapCb = {0};
    int groupCount = 0;
    int sigAlgCount = 0;

    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    // Load default provider
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, &providerMgr), 0);
    ASSERT_TRUE(providerMgr != NULL);

    // Test getting group capabilities
    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(providerMgr, CRYPT_EAL_GET_GROUP_CAP, (CRYPT_EAL_ProcessFuncCb)GroupCapsCallback,
        &groupCount), CRYPT_SUCCESS);
    ASSERT_EQ(groupCount, 17);

    // Test getting signature algorithm capabilities
    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(providerMgr, CRYPT_EAL_GET_SIGALG_CAP, (CRYPT_EAL_ProcessFuncCb)SigAlgCapsCallback,
        &sigAlgCount), CRYPT_SUCCESS);
    ASSERT_EQ(sigAlgCount, 23);

    // Test invalid mgrCtx
    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(NULL, CRYPT_EAL_GET_GROUP_CAP, (CRYPT_EAL_ProcessFuncCb)GroupCapsCallback,
        &groupCount), CRYPT_NULL_INPUT);

    // Test invalid CRYPT_EAL_ProcessFuncCb
    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(providerMgr, CRYPT_EAL_GET_GROUP_CAP, NULL, &groupCount), CRYPT_NULL_INPUT);

    // Test invalid mgrCtx
    provMgrWithGetCapCb.provCtx = NULL;
    provMgrWithGetCapCb.provGetCap = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(&provMgrWithGetCapCb, CRYPT_EAL_GET_GROUP_CAP,
        (CRYPT_EAL_ProcessFuncCb)GroupCapsCallback, &groupCount), CRYPT_SUCCESS);

    // Test invalid command
    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(providerMgr, -1, (CRYPT_EAL_ProcessFuncCb)GroupCapsCallback, &groupCount),
        CRYPT_NOT_SUPPORT);

    // Cleanup
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_LIB_FMT_OFF, "default"), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    return;
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CountProvidersCallback(CRYPT_EAL_ProvMgrCtx *provMgr, void *args)
{
    (void)provMgr;
    int *count = (int *)args;
    if (count != NULL) {
        (*count)++;
    }
    return CRYPT_SUCCESS;
}

// Callback function that returns an error
static int32_t ErrorCallback(CRYPT_EAL_ProvMgrCtx *provMgr, void *args)
{
    (void)provMgr;
    int *count = (int *)args;
    if (count != NULL) {
        (*count)++;
    }
    return CRYPT_NOT_SUPPORT;
}
#endif

/**
 * @test SDV_CRYPTO_PROVIDER_PROC_ALL_TC001
 * @title Test CRYPT_EAL_ProviderProcessAll functionality
 * @precon None
 * @brief
 *    1. Test processing all loaded providers with a callback function
 *    2. Test error handling for NULL inputs
 *    3. Test error propagation from callback function
 * @expect
 *    1. Successfully process all providers
 *    2. Return CRYPT_NULL_INPUT for NULL inputs
 *    3. Properly propagate errors from callback function
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_PROC_ALL_TC001(char *path, char *test1, char *test2, int cmd)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)test1;
    (void)test2;
    (void)cmd;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    int providerCount = 0;
    int errorProviderCount = 0;

    // Initialize library context
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    
    // Set provider path
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    
    // Load multiple providers
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test2, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL), CRYPT_SUCCESS);
    
    // Test 1: Process all providers with a counting callback
    ASSERT_EQ(CRYPT_EAL_ProviderProcessAll(libCtx, CountProvidersCallback, &providerCount), CRYPT_SUCCESS);
    ASSERT_EQ(providerCount, 3); // Should have processed 3 providers

    // Test 2: Test NULL libCtx
    providerCount = 0;
    ASSERT_EQ(CRYPT_EAL_ProviderProcessAll(NULL, CountProvidersCallback, &providerCount), CRYPT_SUCCESS);
    ASSERT_EQ(providerCount, 1);

    // Test 3: Test NULL inputs
    ASSERT_EQ(CRYPT_EAL_ProviderProcessAll(libCtx, NULL, &providerCount), CRYPT_NULL_INPUT);
    
    // Test 4: Test error propagation from callback
    ASSERT_EQ(CRYPT_EAL_ProviderProcessAll(libCtx, ErrorCallback, &errorProviderCount), CRYPT_NOT_SUPPORT);
    ASSERT_EQ(errorProviderCount, 1); // Should have processed only the first provider before error
    
    // Cleanup
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_LIB_FMT_OFF, "default"), CRYPT_SUCCESS);
    
EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    return;
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_PROVIDER
typedef struct {
    int totalProviders;
    int providersWithMd5;
    int providersWithSha256;
} ProviderStats;

int32_t CheckAlgorithmsCallback(CRYPT_EAL_ProvMgrCtx *provMgr, void *args)
{
    ProviderStats *stats = (ProviderStats *)args;
    if (stats != NULL) {
        stats->totalProviders++;

        const CRYPT_EAL_Func *funcs;
        void *provCtx;
        int32_t ret = CRYPT_EAL_ProviderGetFuncs(provMgr->libCtx, CRYPT_EAL_OPERAID_HASH,
                                                CRYPT_MD_MD5, NULL, &funcs, &provCtx);
        if (ret == CRYPT_SUCCESS && funcs != NULL) {
            stats->providersWithMd5++;
        }

        ret = CRYPT_EAL_ProviderGetFuncs(provMgr->libCtx, CRYPT_EAL_OPERAID_HASH,
                                        CRYPT_MD_SHA256, NULL, &funcs, &provCtx);
        if (ret == CRYPT_SUCCESS && funcs != NULL) {
            stats->providersWithSha256++;
        }
    }
    return CRYPT_SUCCESS;
}
#endif
/**
 * @test SDV_CRYPTO_PROVIDER_PROC_ALL_TC002
 * @title Test CRYPT_EAL_ProviderProcessAll with specific provider operations
 * @precon None
 * @brief
 *    1. Test processing all providers to collect specific information
 *    2. Test processing all providers to perform specific operations
 * @expect
 *    1. Successfully collect information from all providers
 *    2. Successfully perform operations on all providers
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_PROC_ALL_TC002(char *path, char *test1, char *test2, int cmd)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)test1;
    (void)test2;
    (void)cmd;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    ProviderStats stats = {0};

    // Initialize library context
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    
    // Set provider path
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    
    // Load multiple providers
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test1, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, test2, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL), CRYPT_SUCCESS);
    
    // Process all providers to collect algorithm information
    ASSERT_EQ(CRYPT_EAL_ProviderProcessAll(libCtx, CheckAlgorithmsCallback, &stats), CRYPT_SUCCESS);
    
    // Verify results
    ASSERT_EQ(stats.totalProviders, 3);
    ASSERT_TRUE(stats.providersWithMd5 > 0); // At least one provider should support MD5
    ASSERT_TRUE(stats.providersWithSha256 > 0); // At least one provider should support SHA256
    
    // Test with empty provider list
    CRYPT_EAL_LibCtx *emptyLibCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(emptyLibCtx != NULL);
    
    ProviderStats emptyStats = {0};
    ASSERT_EQ(CRYPT_EAL_ProviderProcessAll(emptyLibCtx, CheckAlgorithmsCallback, &emptyStats), CRYPT_SUCCESS);
    ASSERT_EQ(emptyStats.totalProviders, 0); // No providers should be processed
    
    // Cleanup
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, cmd, test2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_LIB_FMT_OFF, "default"), CRYPT_SUCCESS);
    
EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_LibCtxFree(emptyLibCtx);
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_GET_CAP_TEST_TC001
 * @title Test provider_get_cap_test1 provider functionality
 * @precon None
 * @brief
 *    1. Load provider_get_cap_test1 provider
 *    2. Test key generation, shared key computation, signing and verification
 * @expect
 *    1. Successfully load the provider
 *    2. Successfully perform cryptographic operations
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_GET_CAP_TEST_TC001(char *path, char *get_cap_test1, int cmd)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)get_cap_test1;
    (void)cmd;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    CRYPT_EAL_PkeyCtx *keyCtx1 = NULL;
    CRYPT_EAL_PkeyCtx *keyCtx2 = NULL;
    uint8_t sharedKey1[256] = {0};
    uint32_t sharedKeyLen1 = sizeof(sharedKey1);
    uint8_t sharedKey2[256] = {0};
    uint32_t sharedKeyLen2 = sizeof(sharedKey2);
    
    // Initialize library context
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, get_cap_test1, NULL, &providerMgr), CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);

    int groupCount = 0;
    int sigAlgCount = 0;
    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(providerMgr, CRYPT_EAL_GET_GROUP_CAP,
        (CRYPT_EAL_ProcessFuncCb)GroupCapsCallback, &groupCount), CRYPT_SUCCESS);
    ASSERT_EQ(groupCount, 2);

    ASSERT_EQ(CRYPT_EAL_ProviderGetCaps(providerMgr, CRYPT_EAL_GET_SIGALG_CAP,
        (CRYPT_EAL_ProcessFuncCb)SigAlgCapsCallback, &sigAlgCount), CRYPT_SUCCESS);
    ASSERT_EQ(sigAlgCount, 1);

    keyCtx1 = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, NEW_PKEY_ALGID, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        "provider=provider_get_cap_test1");
    ASSERT_TRUE(keyCtx1 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(keyCtx1, NEW_PARA_ALGID), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(keyCtx1), CRYPT_SUCCESS);

    keyCtx2 = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, NEW_PKEY_ALGID, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        "provider=provider_get_cap_test1");
    ASSERT_TRUE(keyCtx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(keyCtx2, NEW_PARA_ALGID), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(keyCtx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(keyCtx1, keyCtx2, sharedKey1, &sharedKeyLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(keyCtx2, keyCtx1, sharedKey2, &sharedKeyLen2), CRYPT_SUCCESS);
    ASSERT_TRUE(sharedKeyLen1 > 0);
    ASSERT_TRUE(sharedKeyLen2 > 0);
    ASSERT_EQ(memcmp(sharedKey1, sharedKey2, sharedKeyLen1), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyCtx1);
    CRYPT_EAL_PkeyFreeCtx(keyCtx2);
    CRYPT_EAL_ProviderUnload(libCtx, cmd, get_cap_test1);
    CRYPT_EAL_LibCtxFree(libCtx);
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_GET_CAP_TEST_TC002
 * @title Test provider_get_cap_test1 provider signature and verification
 * @precon None
 * @brief
 *    1. Load provider_get_cap_test1 provider
 *    2. Test signature generation and verification with ECDSA
 * @expect
 *    1. Successfully load the provider
 *    2. Successfully sign and verify data
 *    3. Verification fails with modified signature
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_GET_CAP_TEST_TC002(char *path, char *get_cap_test1, int cmd)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)get_cap_test1;
    (void)cmd;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    CRYPT_EAL_PkeyCtx *keyCtx = NULL;
    uint8_t signature[128] = {0};
    uint32_t signatureLen = sizeof(signature);
    uint8_t testData[] = "Test data for signing and verification with ECDSA";
    uint32_t testDataLen = sizeof(testData) - 1;
    
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, get_cap_test1, NULL, &providerMgr), CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);
    
    keyCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDSA, 0, "provider=provider_get_cap_test1");
    ASSERT_TRUE(keyCtx != NULL);
    
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(keyCtx, NEW_PARA_ALGID), CRYPT_SUCCESS);
    
    ASSERT_EQ(CRYPT_EAL_PkeyGen(keyCtx), CRYPT_SUCCESS);
    
    ASSERT_EQ(CRYPT_EAL_PkeySign(keyCtx, CRYPT_MD_SHA256, testData, testDataLen, signature, &signatureLen), 0);
    ASSERT_TRUE(signatureLen > 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(keyCtx, CRYPT_MD_SHA256, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);
    
    // Test 4: Modify signature and verify it should fail
    signature[10] ^= 0xFF; // Flip bits in the signature
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(keyCtx, CRYPT_MD_SHA256, testData, testDataLen, signature, signatureLen),
        CRYPT_ECDSA_VERIFY_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyCtx);
    CRYPT_EAL_ProviderUnload(libCtx, cmd, get_cap_test1);
    CRYPT_EAL_LibCtxFree(libCtx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_GET_CAP_TEST_TC003(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, "default", NULL, NULL), CRYPT_SUCCESS);
    CRYPT_EAL_ProviderUnload(libCtx, 0, "default");
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, "default", NULL, NULL), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_ProviderUnload(libCtx, 0, "default");
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}

/* END_CASE */