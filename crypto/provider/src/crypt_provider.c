/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PROVIDER

#include "securec.h"
#include "hitls_error.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"

#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider_local.h"

// Name of the dl initialization function
#define PROVIDER_INIT_FUNC "CRYPT_EAL_ProviderInitcb"
// Default path: current directory
#define DEFAULT_PROVIDER_PATH "."
// Maximum length of provider name
#define DEFAULT_PROVIDER_NAME_LEN_MAX 255
// Maximum length of search path
#define DEFAULT_PROVIDER_PATH_LEN_MAX 4095-DEFAULT_PROVIDER_NAME_LEN_MAX


CRYPT_EAL_LibCtx *CRYPT_EAL_NewLibCtx()
{
    CRYPT_EAL_LibCtx *libctx = (CRYPT_EAL_LibCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_LibCtx));
    if (libctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    libctx->providers = BSL_LIST_New(sizeof(CRYPT_EAL_ProvMgrCtx *));
    if (libctx->providers == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        goto ERR;
    }

    int32_t ret = BSL_SAL_ThreadLockNew(&libctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    libctx->searchProviderPath = BSL_SAL_Dump(DEFAULT_PROVIDER_PATH,
        BSL_SAL_Strnlen(DEFAULT_PROVIDER_PATH, DEFAULT_PROVIDER_PATH_LEN_MAX)+1);
    if (libctx->searchProviderPath == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        goto ERR;
    }

    return libctx;
ERR:
    BSL_SAL_ThreadLockFree(libctx->lock);
    BSL_LIST_FREE(libctx->providers, NULL);
    BSL_SAL_FREE(libctx);
    return NULL;
}


// Free EalProviderMgrCtx
static void EalProviderMgrCtxFree(CRYPT_EAL_ProvMgrCtx  *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->provCtx != NULL && ctx->provFreeCb != NULL) {
        ctx->provFreeCb(ctx->provCtx);
    }

    if (ctx->providerName != NULL) {
        BSL_SAL_Free(ctx->providerName);
    }
    if (ctx->providerPath != NULL) {
        BSL_SAL_Free(ctx->providerPath);
    }

    BSL_SAL_ReferencesFree(&(ctx->ref));
    
    if (ctx->handle != NULL) {
        BSL_SAL_UnLoadLib(ctx->handle);
    }

    BSL_SAL_FREE(ctx);
}


// Write a function to free EalProviderMgrCtx according to the requirements of BSL_LIST_FREE
static void ListEalProviderMgrCtxFree(void *data)
{
    if (data == NULL) {
        return;
    }
    CRYPT_EAL_ProvMgrCtx *ctx = (CRYPT_EAL_ProvMgrCtx *)data;
    EalProviderMgrCtxFree(ctx);
}


// Free EalLibCtx context
void CRYPT_EAL_LibCtxFree(CRYPT_EAL_LibCtx *libctx)
{
    if (libctx == NULL) {
        return;
    }

    if (libctx->providers != NULL) {
        BSL_LIST_FREE(libctx->providers, ListEalProviderMgrCtxFree);
    }

    if (libctx->lock != NULL) {
        BSL_SAL_ThreadLockFree(libctx->lock);
    }

    if (libctx->searchProviderPath != NULL) {
        BSL_SAL_FREE(libctx->searchProviderPath);
    }

    BSL_SAL_Free(libctx);
    libctx = NULL;
}


// Comparison function for searching provider in the list
static int32_t CompareProvider(const CRYPT_EAL_ProvMgrCtx *ctx, const char *providerName)
{
    int32_t result = strcmp(ctx->providerName, providerName);
    if (result == 0) {
        return 0;
    }
    result = result > 0 ? 1 : -1;
    return result;
}

// Write a function to search for provider according to BSL_LIST_Search requirements, comparing the input providerName
// with the providerName in EalProviderMgrCtx for exact match
static int32_t ListCompareProvider(const void *a, const void *b)
{
    const CRYPT_EAL_ProvMgrCtx *ctx = (const CRYPT_EAL_ProvMgrCtx *)a;
    const char *providerName = (const char *)b;

    return CompareProvider(ctx, providerName);
}

// Function to search for provider
static int32_t SearchProvider(CRYPT_EAL_LibCtx *libctx, const char *providerName, CRYPT_EAL_ProvMgrCtx **result)
{
    int32_t ret = BSL_SUCCESS;
    CRYPT_EAL_ProvMgrCtx *tempResult = NULL;

    tempResult = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_Search(libctx->providers, providerName, ListCompareProvider, &ret);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *result = tempResult;
    return BSL_SUCCESS;
}

// Function to get provider methods
static int32_t InitProviderMethods(CRYPT_EAL_ProvMgrCtx *ctx, CRYPT_Param *param)
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
    ret = ctx->provInitFunc(ctx, param, capFuncs, &outFuncs, &ctx->provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (outFuncs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NON_STANDARD);
        return CRYPT_PROVIDER_NON_STANDARD;
    }
    // Mount function addresses to corresponding positions in mgr according to method definition
    for (int i = 0; ((outFuncs[i].id != CRYPT_EAL_FUNCEND_ID) && (outFuncs[i].func != NULL)); i++) {
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

    return CRYPT_SUCCESS;
}

// Function to mount parameters of EalProviderMgrCtx structure
static int32_t MountEalProviderMgrCtxParams(void *handle, const char *providerName, const char *providerPath,
    CRYPT_Param *param, CRYPT_EAL_ProvMgrCtx *ctx)
{
    int32_t ret;

    ctx->handle = handle;

    ret = BSL_SAL_ReferencesInit(&(ctx->ref));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctx->providerName = BSL_SAL_Dump(providerName,
                                     BSL_SAL_Strnlen(providerName, DEFAULT_PROVIDER_NAME_LEN_MAX) + 1);
    if (ctx->providerName == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    ctx->providerPath = BSL_SAL_Dump(providerPath,
                                     BSL_SAL_Strnlen(providerPath, DEFAULT_PROVIDER_PATH_LEN_MAX) + 1);
    if (ctx->providerPath == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    // Get the address of the initialization function
    ret = BSL_SAL_GetFuncAddress(handle, PROVIDER_INIT_FUNC, (void **)&ctx->provInitFunc);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Call the initialization function
    ret = InitProviderMethods(ctx, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return CRYPT_SUCCESS;
}

static int32_t CheckProviderLoaded(CRYPT_EAL_LibCtx *libctx,
    const char *providerName, CRYPT_EAL_ProvMgrCtx **providerMgr)
{
    int32_t ret;
    CRYPT_EAL_ProvMgrCtx *tempProviderMgr = NULL;

    ret = BSL_SAL_ThreadReadLock(libctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = SearchProvider(libctx, providerName, &tempProviderMgr);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_ThreadUnlock(libctx->lock);
        return ret;
    }
    if (tempProviderMgr != NULL) {
        // Provider is already loaded, increase the reference count
        int32_t tempCount = 0;
        ret = BSL_SAL_AtomicUpReferences(&tempProviderMgr->ref, &tempCount);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_ThreadUnlock(libctx->lock);
            return ret;
        }
    }
    ret = BSL_SAL_ThreadUnlock(libctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *providerMgr = tempProviderMgr;
    return CRYPT_SUCCESS;
}

// Add provider to the list
static int32_t AddProviderToList(CRYPT_EAL_LibCtx *libctx, CRYPT_EAL_ProvMgrCtx *providerMgr)
{
    int32_t ret;

    ret = BSL_SAL_ThreadWriteLock(libctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_LIST_AddElement(libctx->providers, providerMgr, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_ThreadUnlock(libctx->lock);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_SAL_ThreadUnlock(libctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

// Create a new mgr context and initialize various parameters
static int32_t EalProviderMgrCtxNew(CRYPT_EAL_LibCtx *libctx, const char *providerName, CRYPT_Param *param,
    BSL_SAL_ConverterCmd cmd, CRYPT_EAL_ProvMgrCtx **ctx)
{
    int32_t ret;

    CRYPT_EAL_ProvMgrCtx *tempCtx = (CRYPT_EAL_ProvMgrCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_ProvMgrCtx));
    if (tempCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // Construct the full path of the provider
    char *providerPath = NULL;
    ret = BSL_SAL_ConverterName(cmd, providerName, libctx->searchProviderPath, &providerPath);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(tempCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Attempt to load the dynamic library
    void *handle = NULL;
    ret = BSL_SAL_LoadLib(providerPath, &handle);
    BSL_SAL_FREE(providerPath);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(tempCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // mount parameters of EalProviderMgrCtx structure
    ret = MountEalProviderMgrCtxParams(handle, providerName, libctx->searchProviderPath, param, tempCtx);
    if (ret != CRYPT_SUCCESS) {
        EalProviderMgrCtxFree(tempCtx);
        return ret;
    }

    *ctx = tempCtx;
    return CRYPT_SUCCESS;
}

// Load provider dynamic library
int32_t CRYPT_EAL_LoadProvider(CRYPT_EAL_LibCtx *libctx, BSL_SAL_ConverterCmd cmd,
    const char *providerName, CRYPT_Param *param)
{
    if (libctx == NULL || providerName == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;

    // Check if the provider is already loaded
    ret = CheckProviderLoaded(libctx, providerName, &providerMgr);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (providerMgr != NULL) {
        return CRYPT_SUCCESS;
    }

    // Create and initialize EalProviderMgrCtx
    ret = EalProviderMgrCtxNew(libctx, providerName, param, cmd, &providerMgr);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Add provider to the list
    ret = AddProviderToList(libctx, providerMgr);
    if (ret != CRYPT_SUCCESS) {
        EalProviderMgrCtxFree(providerMgr);
        providerMgr = NULL;
        return ret;
    }

    return CRYPT_SUCCESS;
}

// Remove provider from the list
static void RemoveAndFreeProvider(BslList *providers, CRYPT_EAL_ProvMgrCtx *providerMgr)
{
    BslListNode *node = BSL_LIST_FirstNode(providers);
    while (node != NULL) {
        if (BSL_LIST_GetData(node) == providerMgr) {
            BSL_LIST_DetachNode(providers, &node);
            break;
        }
        node = BSL_LIST_GetNextNode(providers, node);
    }
    EalProviderMgrCtxFree(providerMgr);
    providerMgr = NULL;
}

// Unload provider
int32_t CRYPT_EAL_UnloadProvider(CRYPT_EAL_LibCtx *libctx, const char *providerName)
{
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    if (libctx == NULL || providerName == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    // Search for the specified provider
    ret = BSL_SAL_ThreadReadLock(libctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = SearchProvider(libctx, providerName, &providerMgr);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadUnlock(libctx->lock);
        return ret;
    }
    if (providerMgr == NULL) {
        BSL_SAL_ThreadUnlock(libctx->lock);
        return CRYPT_SUCCESS;
    }
    // Decrease reference count
    int refCount = 0;
    ret = BSL_SAL_AtomicDownReferences(&providerMgr->ref, &refCount);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_ThreadUnlock(libctx->lock);
        return ret;
    }

    // If the reference count is reduced to 0, remove from the list and free the provider.
    // Use <= 0 as the condition because the reference count may be negative
    if (refCount <= 0) {
        RemoveAndFreeProvider(libctx->providers, providerMgr);
    }
    (void)BSL_SAL_ThreadUnlock(libctx->lock);
    return CRYPT_SUCCESS;
}

// Set the path for loading providers
int32_t CRYPT_EAL_SetLoadProviderPath(CRYPT_EAL_LibCtx *libctx, const char *searchPath)
{
    if (libctx == NULL || searchPath == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    BSL_SAL_Free(libctx->searchProviderPath);
    libctx->searchProviderPath = BSL_SAL_Dump(searchPath,
        BSL_SAL_Strnlen(searchPath, DEFAULT_PROVIDER_PATH_LEN_MAX) + 1);
    if (libctx->searchProviderPath == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}


#endif // HITLS_CRYPTO_PROVIDER
