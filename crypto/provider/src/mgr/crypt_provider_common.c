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

#ifdef HITLS_CRYPTO_PROVIDER

#include "securec.h"
#include "crypt_provider.h"
#include "bsl_list.h"
#include "crypt_provider_local.h"
#include "crypt_errno.h"
#include "crypt_eal_entropy.h"
#include "bsl_err_internal.h"
#include "eal_entropy.h"
#include "crypt_drbg_local.h"
#include "crypt_drbg.h"

static CRYPT_EAL_LibCtx *g_libCtx = NULL;

CRYPT_EAL_LibCtx *CRYPT_EAL_GetGlobalLibCtx(void)
{
    return g_libCtx;
}

int32_t CRYPT_EAL_ProviderGetFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attribute, const CRYPT_EAL_Func **funcs, void **provCtx)
{
    if (funcs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EAL_LibCtx *localCtx = libCtx;
    if (localCtx == NULL) {
        localCtx = g_libCtx;
    }

    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (attribute != NULL && strlen(attribute) > (INT32_MAX >> 1)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_ATTRIBUTE);
        return CRYPT_PROVIDER_ERR_ATTRIBUTE;
    }

    return CRYPT_EAL_CompareAlgAndAttr(localCtx, operaId, algId, attribute, funcs, provCtx);
}

int32_t CRYPT_EAL_ProvMgrCtrl(CRYPT_EAL_ProvMgrCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) valLen;
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    switch (cmd) {
        case CRYPT_EAL_MGR_GETSEEDCTX:
            *(void **) val = ctx->providerSeed.seed;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_MGR_GETLIBCTX:
            *(void **) val = ctx->libCtx;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_FOUND);
            return CRYPT_PROVIDER_NOT_FOUND;
    }
}

static void MountMgrMethod(CRYPT_EAL_Func *funcs, CRYPT_EAL_ProvMgrCtx *ctx)
{
    // Mount function addresses to corresponding positions in mgr according to method definition
    for (uint32_t i = 0; funcs[i].id != 0; i++) {
        switch (funcs[i].id) {
            case CRYPT_EAL_PROVCB_FREE:
                ctx->provFreeCb = (CRYPT_EAL_ProvFreeCb)funcs[i].func;
                break;
            case CRYPT_EAL_PROVCB_QUERY:
                ctx->provQueryCb = (CRYPT_EAL_ProvQueryCb)funcs[i].func;
                break;
            case CRYPT_EAL_PROVCB_CTRL:
                ctx->provCtrlCb = (CRYPT_EAL_ProvCtrlCb)funcs[i].func;
                break;
            case CRYPT_EAL_PROVCB_GETCAPS:
                ctx->provGetCap = (CRYPT_EAL_ProvGetCapsCb)funcs[i].func;
                break;
            default:
                break;
        }
    }
}

#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
static void ProviderSeedDeinit(EAL_SeedDrbg *seedDrbg)
{
    if (seedDrbg == NULL) {
        return;
    }
    if (seedDrbg->seed != NULL) {
        EAL_SeedDrbgRandDeinit(seedDrbg->seed);
        seedDrbg->seed = NULL;
        CRYPT_EAL_SeedPoolFree(seedDrbg->seedCtx);
        seedDrbg->seedCtx = NULL;
        BSL_SAL_ReferencesFree(&(seedDrbg->references));
        (void)memset_s(seedDrbg, sizeof(EAL_SeedDrbg), 0, sizeof(EAL_SeedDrbg));
    }
}
#endif

// Function to get provider methods
int32_t CRYPT_EAL_InitProviderMethod(CRYPT_EAL_ProvMgrCtx *ctx, BSL_Param *param,
    CRYPT_EAL_ImplProviderInit providerInit)
{
    int32_t ret;
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
    CRYPT_RandSeedMethod meth = {0};
    // The implementer of provider may not use the default entropy source
    (void)EAL_SeedDrbgEntropyMeth(&meth);
    ctx->providerSeed.id = HITLS_SEED_DRBG_INIT_RAND_ALG;
    ret = EAL_SeedDrbgInit(&(ctx->providerSeed));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
#endif
    // Construct input method structure array
    CRYPT_EAL_Func capFuncs[] = {
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
        {CRYPT_EAL_CAP_GETENTROPY, (CRYPT_EAL_GetEntropyCb)meth.getEntropy},
        {CRYPT_EAL_CAP_CLEANENTROPY, (CRYPT_EAL_CleanEntropyCb)meth.cleanEntropy},
        {CRYPT_EAL_CAP_GETNONCE, (CRYPT_EAL_GetNonceCb)meth.getNonce},
        {CRYPT_EAL_CAP_CLEANNONCE, (CRYPT_EAL_CleanNonceCb)meth.cleanNonce},
#endif
        {CRYPT_EAL_CAP_MGRCTXCTRL, (CRYPT_EAL_ProvMgrCtrlCb)CRYPT_EAL_ProvMgrCtrl},
        CRYPT_EAL_FUNC_END  // End marker
    };

    CRYPT_EAL_Func *outFuncs = NULL;
    // Call CRYPT_EAL_ImplProviderInit to get methods
    ret = providerInit(ctx, param, capFuncs, &outFuncs, &ctx->provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (outFuncs == NULL) {
        ret = CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
        goto ERR;
    }
    MountMgrMethod(outFuncs, ctx);

    if (ctx->provQueryCb == NULL) {
        if (ctx->provFreeCb != NULL) {
            ctx->provFreeCb(ctx->provCtx);
            ctx->provCtx = NULL;
        }
        ret = CRYPT_PROVIDER_ERR_IMPL_NULL;
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_IMPL_NULL);
        goto ERR;
    }

    return CRYPT_SUCCESS;
ERR:
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
    ProviderSeedDeinit(&(ctx->providerSeed));
#endif
    return ret;
}

CRYPT_EAL_LibCtx *CRYPT_EAL_LibCtxNewInternal(void)
{
    CRYPT_EAL_LibCtx *libCtx = (CRYPT_EAL_LibCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_LibCtx));
    if (libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    // Initialize providers list
    libCtx->providers = BSL_LIST_New(sizeof(struct EAL_ProviderMgrCtx *));
    if (libCtx->providers == NULL) {
        goto ERR;
    }

    // Initialize thread lock
    if (BSL_SAL_ThreadLockNew(&libCtx->lock) != BSL_SUCCESS) {
        BSL_LIST_FREE(libCtx->providers, NULL);
        goto ERR;
    }

    return libCtx;
ERR:
    BSL_SAL_Free(libCtx);
    libCtx = NULL;
    return NULL;
}

void CRYPT_EAL_ProviderMgrCtxFree(CRYPT_EAL_ProvMgrCtx  *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->provFreeCb != NULL) {
        ctx->provFreeCb(ctx->provCtx);
        ctx->provCtx = NULL;
    }
    BSL_SAL_FREE(ctx->providerName);
    BSL_SAL_FREE(ctx->providerPath);

    BSL_SAL_ReferencesFree(&(ctx->ref));
    
    if (ctx->handle != NULL) {
        BSL_SAL_UnLoadLib(ctx->handle);
        ctx->handle = NULL;
    }
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
    ProviderSeedDeinit(&(ctx->providerSeed));
#endif
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_EAL_LoadPreDefinedProvider(CRYPT_EAL_LibCtx *libCtx, const char* providerName,
    CRYPT_EAL_ProvMgrCtx **ctx)
{
    char *name = BSL_SAL_Dump(providerName, BSL_SAL_Strnlen(providerName, DEFAULT_PROVIDER_NAME_LEN_MAX) + 1);
    if (name == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_ProvMgrCtx *mgrCtx = (CRYPT_EAL_ProvMgrCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_ProvMgrCtx));
    if (mgrCtx == NULL) {
        BSL_SAL_Free(name);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BSL_SAL_ReferencesInit(&mgrCtx->ref);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(name);
        BSL_SAL_Free(mgrCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    mgrCtx->libCtx = libCtx;
    mgrCtx->providerName = name;
    ret = CRYPT_EAL_InitProviderMethod(mgrCtx, NULL, CRYPT_EAL_DefaultProvInit);
    if (ret == BSL_SUCCESS) {
        ret = BSL_LIST_AddElement(libCtx->providers, mgrCtx, BSL_LIST_POS_END);
        if (ctx != NULL) {
            *ctx = mgrCtx;
        }
    }
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(name);
        BSL_SAL_ReferencesFree(&mgrCtx->ref);
        BSL_SAL_Free(mgrCtx);
    }
    return ret;
}

int32_t CRYPT_EAL_InitPreDefinedProviders(void)
{
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNewInternal();
    if (libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_LoadPreDefinedProvider(libCtx, CRYPT_EAL_DEFAULT_PROVIDER, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_LIST_FREE(libCtx->providers, NULL);
        BSL_SAL_ThreadLockFree(libCtx->lock);
        BSL_SAL_FREE(libCtx);
        return ret;
    }
    g_libCtx = libCtx;
    return ret;
}

void CRYPT_EAL_FreePreDefinedProviders(void)
{
    CRYPT_EAL_LibCtx *libCtx = g_libCtx;
    if (libCtx == NULL) {
        return;
    }

    if (libCtx->drbg != NULL) {
        EAL_RandDeinit(libCtx->drbg);
        libCtx->drbg = NULL;
    }
    // Free the providers list and each EAL_ProviderMgrCtx in it
    if (libCtx->providers != NULL) {
        BSL_LIST_FREE(libCtx->providers, (BSL_LIST_PFUNC_FREE)CRYPT_EAL_ProviderMgrCtxFree);
    }

    BSL_SAL_FREE(libCtx->searchProviderPath);

    // Free thread lock
    if (libCtx->lock != NULL) {
        BSL_SAL_ThreadLockFree(libCtx->lock);
    }

    // Free the libctx structure itself
    BSL_SAL_Free(libCtx);
    g_libCtx = NULL;
}

#endif /* HITLS_CRYPTO_PROVIDER */