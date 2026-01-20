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
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
/* END_HEADER */

#define PROVIDER_A_NAME "provider_a"
#define PROVIDER_B_NAME "provider_b"
#define PROVIDER_DEFAULT_NAME "default"

#define PROVIDER_A_ATTR "provider=a,md=sha256"
#define PROVIDER_B_ATTR "provider=b,md=md5"
#define PROVIDER_DEFAULT_ATTR "provider=default"

#define DEFAULT_SHA256_INIT_RET 0
#define DEFAULT_MD5_INIT_RET 0
#define PROVIDER_A_SHA256_INIT_RET (-1)
#define PROVIDER_B_MD5_INIT_RET (-2)

uint8_t md = 1;

static void *MdNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    (void)algId;
    return &md;
}

static int32_t MdInitA(void *ctx, BSL_Param *param)
{
    (void)ctx;
    (void)param;
    return PROVIDER_A_SHA256_INIT_RET;
}

static int32_t MdInitB(void *ctx, BSL_Param *param)
{
    (void)ctx;
    (void)param;
    return PROVIDER_B_MD5_INIT_RET;
}

static int32_t MdDeinit(void *ctx)
{
    (void)ctx;
    return 0;
}

static int32_t MdCopyCtx(void *dst, const void *src)
{
    (void)dst;
    (void)src;
    return 0;
}

static int32_t MdUpdate(void *ctx, const uint8_t *data, uint32_t nbytes)
{
    (void)ctx;
    (void)data;
    (void)nbytes;
    return 0;
}

static int32_t MdFinal(void *ctx, uint8_t *digest, uint32_t *outlen)
{
    (void)ctx;
    (void)digest;
    (void)outlen;
    return 0;
}

static void *MdDupCtx(const void *src)
{
    (void)src;
    return NULL;
}

static void MdFreeCtx(void *ctx)
{
    (void)ctx;
    return;
}

static int32_t MdGetParam(void *ctx, BSL_Param *param)
{
    (void)ctx;
    (void)param;
    return 0;
}

// SHA256 algorithm function table
const CRYPT_EAL_Func providerAMd[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, MdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, MdInitA},
    {CRYPT_EAL_IMPLMD_UPDATE, MdUpdate},
    {CRYPT_EAL_IMPLMD_FINAL, MdFinal},
    {CRYPT_EAL_IMPLMD_DEINITCTX, MdDeinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, MdDupCtx},
    {CRYPT_EAL_IMPLMD_COPYCTX, MdCopyCtx},
    {CRYPT_EAL_IMPLMD_GETPARAM, MdGetParam},
    {CRYPT_EAL_IMPLMD_FREECTX, MdFreeCtx},
    CRYPT_EAL_FUNC_END,
};

// Algorithm information table
static const CRYPT_EAL_AlgInfo providerAMds[] = {
    {CRYPT_MD_SHA256, providerAMd, PROVIDER_A_ATTR},
    CRYPT_EAL_ALGINFO_END
};

// SHA256 algorithm function table
const CRYPT_EAL_Func providerBMd[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, MdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, MdInitB},
    {CRYPT_EAL_IMPLMD_UPDATE, MdUpdate},
    {CRYPT_EAL_IMPLMD_FINAL, MdFinal},
    {CRYPT_EAL_IMPLMD_DEINITCTX, MdDeinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, MdDupCtx},
    {CRYPT_EAL_IMPLMD_COPYCTX, MdCopyCtx},
    {CRYPT_EAL_IMPLMD_GETPARAM, MdGetParam},
    {CRYPT_EAL_IMPLMD_FREECTX, MdFreeCtx},
    CRYPT_EAL_FUNC_END,
};

// Algorithm information table
static const CRYPT_EAL_AlgInfo providerBMds[] = {
    {CRYPT_MD_MD5, providerBMd, PROVIDER_B_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static void MdProvFree(void *provCtx)
{
    (void)provCtx;
    return;
}

static int32_t MdProvQueryA(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    
    switch (operaId) {
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = providerAMds;
            return 0;
        default:
            return 1;
    }
}
static int32_t MdProvQueryB(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    
    switch (operaId) {
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = providerBMds;
            return 0;
        default:
            return 1;
    }
}


// Provider output functions table
static CRYPT_EAL_Func providerAProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, MdProvQueryA},
    {CRYPT_EAL_PROVCB_FREE, MdProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

static CRYPT_EAL_Func providerBProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, MdProvQueryB},
    {CRYPT_EAL_PROVCB_FREE, MdProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

// Provider initialization function
int32_t ProviderAInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    BSL_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)mgrCtx;
    (void)param;
    (void)capFuncs;

    *outFuncs = providerAProvOutFuncs;
    *provCtx = NULL;
    return 0;
}

int32_t ProviderBInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    BSL_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)mgrCtx;
    (void)param;
    (void)capFuncs;

    *outFuncs = providerBProvOutFuncs;
    *provCtx = NULL;
    return 0;
}

/**
 * @test SDV_CRYPTO_PROVIDER_REG_FUNC_TC001
 * @title Register default provider first and then register custom provider
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_REG_FUNC_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_EAL_MdCTX *mdCtx = NULL;

    TestMemInit();
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    // 1st: default provider, 2nd: A provider, 3rd: B provider
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_DEFAULT_NAME, NULL, NULL, NULL), 0);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_A_NAME, ProviderAInit, NULL, NULL), 0);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_B_NAME, ProviderBInit, NULL, NULL), 0);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, "provider=default");
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), DEFAULT_SHA256_INIT_RET);
    CRYPT_EAL_MdFreeCtx(mdCtx);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, NULL);
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), DEFAULT_SHA256_INIT_RET);
    CRYPT_EAL_MdFreeCtx(mdCtx);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, "provider=a");
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), PROVIDER_A_SHA256_INIT_RET);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    mdCtx = NULL;

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, "provider=b");
    ASSERT_TRUE(mdCtx == NULL);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, "provider=a");
    ASSERT_TRUE(mdCtx == NULL);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, "md=sha256");
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), PROVIDER_A_SHA256_INIT_RET);
    CRYPT_EAL_MdFreeCtx(mdCtx);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, "provider=b");
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), PROVIDER_B_MD5_INIT_RET);

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_MdFreeCtx(mdCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_REG_FUNC_TC002
 * @title Register custom provider first and then register default provider
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_REG_FUNC_TC002(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    TestMemInit();
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    // 1st: A provider, 2nd: B provider, 3rd: default provider
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_A_NAME, ProviderAInit, NULL, NULL), 0);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_B_NAME, ProviderBInit, NULL, NULL), 0);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_DEFAULT_NAME, NULL, NULL, NULL), 0);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, NULL);
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), PROVIDER_A_SHA256_INIT_RET);
    CRYPT_EAL_MdFreeCtx(mdCtx);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, NULL);
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), PROVIDER_B_MD5_INIT_RET);
    CRYPT_EAL_MdFreeCtx(mdCtx);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA256, "provider?default");
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), DEFAULT_SHA256_INIT_RET);
    CRYPT_EAL_MdFreeCtx(mdCtx);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, "provider=default");
    ASSERT_TRUE(mdCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(mdCtx), DEFAULT_MD5_INIT_RET);

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_MdFreeCtx(mdCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_PROVIDER_REG_API_TC001
 * @title Api test for CRYPT_EAL_ProviderRegister
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PROVIDER_REG_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    /* Test case 1: libCtx test */
    // 1.1 Test with NULL libCtx and NULL providerName
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(NULL, NULL, ProviderAInit, NULL, NULL), CRYPT_INVALID_ARG);
    // 1.2 Test with NULL libCtx and valid providerName but NULL init for non-default
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(NULL, "non_default_null_init", NULL, NULL, NULL), CRYPT_NULL_INPUT);
    // 1.3 libCtx is NULL (should use global context)
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(NULL, PROVIDER_DEFAULT_NAME, NULL, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(NULL, PROVIDER_DEFAULT_NAME, ProviderAInit, NULL, NULL), CRYPT_SUCCESS);

    /* Test case 2: provider name test */
    // 2.1 Test with NULL provider name
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, NULL, ProviderAInit, NULL, NULL), CRYPT_INVALID_ARG);
    // 2.2 Test with empty provider name
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, "", ProviderAInit, NULL, NULL), CRYPT_INVALID_ARG);
    // 2.3 Test with very long provider name
    char longProviderName[4096];
    (void)memset_s(longProviderName, sizeof(longProviderName), 'a', sizeof(longProviderName) - 1);
    longProviderName[sizeof(longProviderName) - 1] = '\0';
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, longProviderName, ProviderAInit, NULL, NULL), CRYPT_INVALID_ARG);
    // 2.4 Test with special characters in provider name
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, "special_chars_!@#$%", ProviderAInit, NULL, NULL), CRYPT_SUCCESS);
    // 2.5 Register the same provider twice
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_A_NAME, ProviderAInit, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_A_NAME, ProviderAInit, NULL, NULL), CRYPT_SUCCESS);
    // 2.6 Test with different init function for same provider name
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, "same_name_different_init", ProviderAInit, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, "same_name_different_init", ProviderBInit, NULL, NULL), CRYPT_SUCCESS);
    // 2.7 Test that default provider can be registered multiple times
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_DEFAULT_NAME, NULL, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_DEFAULT_NAME, NULL, NULL, NULL), CRYPT_SUCCESS);

    /* Test case 3: Init function test */
    // 3.1 For non-predefined provider, init function is NULL
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, "non_default_provider", NULL, NULL, NULL), CRYPT_NULL_INPUT);
    // 3.2 For predefined provider (default), init function can be NULL
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_DEFAULT_NAME, NULL, NULL, NULL), CRYPT_SUCCESS);
    // 3.3 Test with valid param but NULL init function for non-default provider
    BSL_Param validParam[] = {{0}};
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, "provider_valid_param_null_init", NULL, validParam, NULL),
        CRYPT_NULL_INPUT);

    /* Test case 4: mgrCtx test */
    // 4.1 mgrCtx is not NULL but *mgrCtx is not NULL
    CRYPT_EAL_ProvMgrCtx *dummyCtx = (CRYPT_EAL_ProvMgrCtx *)0x12345678;
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_A_NAME, ProviderAInit, NULL, &dummyCtx), CRYPT_INVALID_ARG);
    // 4.2 Register provider with valid mgrCtx parameter
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderRegister(libCtx, PROVIDER_B_NAME, ProviderBInit, NULL, &mgrCtx), CRYPT_SUCCESS);
    ASSERT_TRUE(mgrCtx != NULL);

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}
/* END_CASE */
