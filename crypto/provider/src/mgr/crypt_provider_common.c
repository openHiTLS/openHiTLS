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
#include <string.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "eal_drbg_local.h"
#include "crypt_eal_entropy.h"
#include "crypt_errno.h"
#include "crypt_drbg.h"
#include "crypt_provider_local.h"
#include "crypt_provider.h"
#include "crypt_utils.h"

static CRYPT_EAL_LibCtx *g_libCtx = NULL;

CRYPT_EAL_LibCtx *CRYPT_EAL_GetGlobalLibCtx(void)
{
    return g_libCtx;
}

int32_t CRYPT_EAL_ProviderGetFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attribute, const CRYPT_EAL_Func **funcs, void **provCtx)
{
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, operaId, algId, attribute, funcs, &mgrCtx, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_FOUND);
        return CRYPT_PROVIDER_NOT_FOUND;
    }
    if (provCtx != NULL) {
        *provCtx = mgrCtx->provCtx;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_ProviderGetFuncsAndMgrCtx(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attribute, const CRYPT_EAL_Func **funcs, CRYPT_EAL_ProvMgrCtx **mgrCtx, bool noPushError)
{
    if (funcs == NULL || mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EAL_LibCtx *localCtx = GetCurrentProviderLibCtx(libCtx);
    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (attribute != NULL && strlen(attribute) > (INT32_MAX >> 1)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_ATTRIBUTE);
        return CRYPT_PROVIDER_ERR_ATTRIBUTE;
    }

    return CRYPT_EAL_CompareAlgAndAttr(localCtx, operaId, algId, attribute, funcs, mgrCtx, noPushError);
}

int32_t CRYPT_EAL_ProvMgrCtrl(CRYPT_EAL_ProvMgrCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void)valLen;
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    switch (cmd) {
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
        case CRYPT_EAL_MGR_GETSEEDCTX:
            *(void **)val = ctx->providerSeed.seed;
            return CRYPT_SUCCESS;
#endif
        case CRYPT_EAL_MGR_GETLIBCTX:
            *(void **)val = ctx->libCtx;
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
    // The implementer of provider may not use the default entropy source
    CRYPT_RandSeedMethod method = {0};
    EAL_SeedDrbgEntropyMeth(&method);
    ctx->providerSeed.id = HITLS_SEED_DRBG_INIT_RAND_ALG;
    RETURN_RET_IF_ERR(EAL_SeedDrbgInit(&(ctx->providerSeed)), ret);
#endif
    // Construct input method structure array
    CRYPT_EAL_Func capFuncs[] = {
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
        {CRYPT_EAL_CAP_GETENTROPY, method.getEntropy},
        {CRYPT_EAL_CAP_CLEANENTROPY, method.cleanEntropy},
        {CRYPT_EAL_CAP_GETNONCE, method.getNonce},
        {CRYPT_EAL_CAP_CLEANNONCE, method.cleanNonce},
#endif
        {CRYPT_EAL_CAP_MGRCTXCTRL, CRYPT_EAL_ProvMgrCtrl},
        CRYPT_EAL_FUNC_END  // End marker
    };

    CRYPT_EAL_Func *outFuncs = NULL;
    // Call CRYPT_EAL_ImplProviderInit to get methods
    GOTO_ERR_IF(providerInit(ctx, param, capFuncs, &outFuncs, &ctx->provCtx), ret);
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

#ifdef HITLS_BSL_SAL_DL
    if (ctx->handle != NULL) {
        BSL_SAL_UnLoadLib(ctx->handle);
        ctx->handle = NULL;
    }
#endif
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
    ProviderSeedDeinit(&(ctx->providerSeed));
#endif
    BSL_SAL_Free(ctx);
}

// Add provider to the list
static int32_t AddProviderToList(CRYPT_EAL_LibCtx *libCtx, CRYPT_EAL_ProvMgrCtx *providerMgr)
{
    int32_t ret = BSL_SAL_ThreadWriteLock(libCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_LIST_AddElement(libCtx->providers, providerMgr, BSL_LIST_POS_END);
    (void)BSL_SAL_ThreadUnlock(libCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

int32_t CRYPT_EAL_AddNewProvMgrCtx(CRYPT_EAL_LibCtx *libCtx, const char *providerName, const char *providerPath,
    CRYPT_EAL_ImplProviderInit init, void *handle, BSL_Param *param, CRYPT_EAL_ProvMgrCtx **ctx)
{
    (void)handle;
    CRYPT_EAL_ProvMgrCtx *mgrCtx = (CRYPT_EAL_ProvMgrCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_ProvMgrCtx));
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    mgrCtx->libCtx = libCtx;
    mgrCtx->providerName = BSL_SAL_Dump(providerName, BSL_SAL_Strnlen(providerName, DEFAULT_PROVIDER_NAME_LEN_MAX) + 1);
    if (mgrCtx->providerName == NULL) {
        BSL_SAL_Free(mgrCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (providerPath != NULL) {
        mgrCtx->providerPath = BSL_SAL_Dump(providerPath,
            BSL_SAL_Strnlen(providerPath, DEFAULT_PROVIDER_PATH_LEN_MAX) + 1);
        if (mgrCtx->providerPath == NULL) {
            BSL_SAL_Free(mgrCtx->providerName);
            BSL_SAL_Free(mgrCtx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    int32_t ret = BSL_SAL_ReferencesInit(&mgrCtx->ref);
    if (ret != BSL_SUCCESS) {
        CRYPT_EAL_ProviderMgrCtxFree(mgrCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = AddProviderToList(libCtx, mgrCtx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_ProviderMgrCtxFree(mgrCtx);
        return ret;
    }
    ret = CRYPT_EAL_InitProviderMethod(mgrCtx, param, init);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteCurrent(libCtx->providers, (BSL_LIST_PFUNC_FREE)CRYPT_EAL_ProviderMgrCtxFree);
        return ret;
    }
    if (ctx != NULL) {
        *ctx = mgrCtx;
    }
#ifdef HITLS_BSL_SAL_DL
    mgrCtx->handle = handle;
#endif
    return ret;
}

int32_t CRYPT_EAL_InitPreDefinedProviders(void)
{
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNewInternal();
    if (libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    g_libCtx = libCtx;
    int32_t ret = CRYPT_EAL_AddNewProvMgrCtx(g_libCtx, CRYPT_EAL_DEFAULT_PROVIDER, NULL, CRYPT_EAL_DefaultProvInit,
        NULL, NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_LIST_FREE(g_libCtx->providers, NULL);
        BSL_SAL_ThreadLockFree(g_libCtx->lock);
        BSL_SAL_FREE(g_libCtx);
        return ret;
    }
    return ret;
}

void CRYPT_EAL_FreePreDefinedProviders(void)
{
    CRYPT_EAL_LibCtx *libCtx = g_libCtx;
    if (libCtx == NULL) {
        return;
    }

#ifdef HITLS_CRYPTO_DRBG
    if (libCtx->drbg != NULL) {
        EAL_RandDeinit(libCtx->drbg);
        libCtx->drbg = NULL;
    }
#endif
    // Free the providers list and each EAL_ProviderMgrCtx in it
    if (libCtx->providers != NULL) {
        BSL_LIST_FREE(libCtx->providers, (BSL_LIST_PFUNC_FREE)CRYPT_EAL_ProviderMgrCtxFree);
    }

#ifdef HITLS_BSL_SAL_DL
    BSL_SAL_FREE(libCtx->searchProviderPath);
#endif

    // Free thread lock
    if (libCtx->lock != NULL) {
        BSL_SAL_ThreadLockFree(libCtx->lock);
        libCtx->lock = NULL;
    }

    // Free the libctx structure itself
    BSL_SAL_Free(libCtx);
    g_libCtx = NULL;
}

#endif /* HITLS_CRYPTO_PROVIDER */