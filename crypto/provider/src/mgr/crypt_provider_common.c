/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "crypt_provider.h"
#include "bsl_list.h"
#include "crypt_provider_local.h"
#include "crypt_errno.h"
#include "string.h"
#include "bsl_err_internal.h"

static CRYPT_EAL_LibCtx *g_libCtx = NULL;

// The ability to parse and compare attributes in the subsequent upgrade
static const CRYPT_EAL_Func *CRYPT_EAL_CompareAlgAndAttr(int32_t algId, const char *attribute,
    CRYPT_EAL_AlgInfo *algInfos)
{
    int index = 0;
    while (algInfos[index].algId != 0) {
        if (attribute == NULL) { // No attribute is specified, any algorithm matching can be used
            if (algInfos[index].algId == algId) {
                return algInfos[index].implFunc;
            }
            index++;
            continue;
        }
        // attribute is not null
        if (algInfos[index].algId == algId && strcmp(attribute, algInfos[index].attr) == 0) {
            return algInfos[index].implFunc;
        }
        index++;
    }
    return NULL;
}

int32_t CRYPT_EAL_GetFuncsFromProvider(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attribute, const CRYPT_EAL_Func **funcs, void **provCtx)
{
    int32_t ret = CRYPT_NOT_SUPPORT;
    CRYPT_EAL_LibCtx *localCtx = libCtx;
    if (localCtx == NULL) {
        localCtx = g_libCtx;
    }
    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ret = BSL_SAL_ThreadWriteLock(localCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_EAL_ProvMgrCtx *node = BSL_LIST_GET_FIRST(localCtx->providers);
    while (node != NULL) {
        CRYPT_EAL_AlgInfo *algInfos = NULL;
        ret = node->provQueryCb(node->provCtx, operaId, &algInfos);
        if (ret != CRYPT_SUCCESS) {
            node = BSL_LIST_GET_NEXT(localCtx->providers);
            continue;
        }
        const CRYPT_EAL_Func *temp = CRYPT_EAL_CompareAlgAndAttr(algId, attribute, algInfos);
        if (temp != NULL) {
            *funcs = temp;
            *provCtx = node->provCtx;
            BSL_SAL_ThreadUnlock(localCtx->lock);
            return BSL_SUCCESS;
        }
        ret = CRYPT_NOT_SUPPORT;
        node = BSL_LIST_GET_NEXT(localCtx->providers);
    }
    BSL_SAL_ThreadUnlock(localCtx->lock);
    return ret;
}

// Function to get provider methods
int32_t CRYPT_EAL_InitProviderMethod(CRYPT_EAL_ProvMgrCtx *ctx, CRYPT_Param *param,
    CRYPT_EAL_ImplProviderInit providerInit)
{
    int32_t ret;

    // Construct input method structure array
    CRYPT_EAL_Func capFuncs[] = {
        {CRYPT_EAL_CAP_GETENTROPY, NULL},
        {CRYPT_EAL_CAP_CLEANENTROPY, NULL},
        {CRYPT_EAL_CAP_GETNONCE, NULL},
        {CRYPT_EAL_CAP_CLEANNONCE, NULL},
        {CRYPT_EAL_CAP_MGRCTXCTRL, NULL},
        CRYPT_EAL_FUNC_END  // End marker
    };

    CRYPT_EAL_Func *outFuncs = NULL;
    // Call CRYPT_EAL_ImplProviderInit to get methods
    ret = providerInit(ctx, param, capFuncs, &outFuncs, &ctx->provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (outFuncs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
        return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
    }
    // Mount function addresses to corresponding positions in mgr according to method definition
    for (int i = 0; ((outFuncs[i].id != 0) && (outFuncs[i].func != NULL)); i++) {
        switch (outFuncs[i].id) {
            case CRYPT_EAL_PROVCB_FREE:
                ctx->provFreeCb = (CRYPT_EAL_ProvFreeCb)outFuncs[i].func;
                break;
            case CRYPT_EAL_PROVCB_QUERY:
                ctx->provQueryCb = (CRYPT_EAL_ProvQueryCb)outFuncs[i].func;
                break;
            case CRYPT_EAL_PROVCB_CTRL:
                ctx->provCtrlCb = (CRYPT_EAL_ProvCtrlCb)outFuncs[i].func;
                break;
            default:
                break;
        }
    }
    if (ctx->provQueryCb == NULL) {
        if (ctx->provFreeCb != NULL) {
            ctx->provFreeCb(ctx->provCtx);
            ctx->provCtx = NULL;
        }
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_IMPL_NULL);
        return CRYPT_PROVIDER_ERR_IMPL_NULL;
    }

    return CRYPT_SUCCESS;
}

CRYPT_EAL_LibCtx *CRYPT_EAL_NewLibCtxInternal()
{
    CRYPT_EAL_LibCtx *libCtx = (CRYPT_EAL_LibCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_LibCtx));
    if (libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    // Initialize providers list
    libCtx->providers = BSL_LIST_New(sizeof(struct EalProviderMgrCtx *));
    if (libCtx->providers == NULL) {
        goto ERR;
    }

    // Initialize thread lock
    int32_t ret = BSL_SAL_ThreadLockNew(&libCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_FREE(libCtx->providers, NULL);
        goto ERR;
    }

    return libCtx;
ERR:
    BSL_SAL_Free(libCtx);
    libCtx = NULL;
    return NULL;
}

void EalFreeProviderMgrCtx(void *data)
{
    CRYPT_EAL_ProvMgrCtx *mgrCtx = (CRYPT_EAL_ProvMgrCtx *)data;
    if (mgrCtx->provFreeCb != NULL) {
        mgrCtx->provFreeCb(mgrCtx->provCtx);
    }

    BSL_SAL_ReferencesFree(&mgrCtx->ref);
    BSL_SAL_FREE(mgrCtx);
}

int32_t CRYPT_EAL_LoadPreDefinedProvider(CRYPT_EAL_LibCtx *libCtx)
{
    CRYPT_EAL_ProvMgrCtx *mgrCtx = (CRYPT_EAL_ProvMgrCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_ProvMgrCtx));
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BSL_SAL_ReferencesInit(&mgrCtx->ref);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(mgrCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_LIST_AddElement(libCtx->providers, mgrCtx, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_ReferencesFree(&mgrCtx->ref);
        BSL_SAL_FREE(mgrCtx);
        return ret;
    }
    mgrCtx->libCtx = libCtx;
    ret = CRYPT_EAL_InitProviderMethod(mgrCtx, NULL, CRYPT_EAL_DefaultProvInit);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_LIST_DeleteAll(libCtx->providers, EalFreeProviderMgrCtx);
    }

    return ret;
}

int32_t CRYPT_EAL_InitPreDefinedProviders()
{
    int32_t ret;
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_NewLibCtxInternal();
    if (libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_LoadPreDefinedProvider(libCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_LIST_FREE(libCtx->providers, NULL);
        BSL_SAL_ThreadLockFree(libCtx->lock);
        BSL_SAL_FREE(libCtx);
        return ret;
    }
    g_libCtx = libCtx;
    return ret;
}

void CRYPT_EAL_FreePreDefinedProviders()
{
    CRYPT_EAL_LibCtx *libCtx = g_libCtx;
    if (libCtx == NULL) {
        return;
    }
    // Free the providers list and each EalProviderMgrCtx in it
    if (libCtx->providers != NULL) {
        BSL_LIST_FREE(libCtx->providers, EalFreeProviderMgrCtx);
    }

    // Free thread lock
    if (libCtx->lock != NULL) {
        BSL_SAL_ThreadLockFree(libCtx->lock);
    }

    // Free the libctx structure itself
    BSL_SAL_Free(libCtx);
    g_libCtx = NULL;
}
