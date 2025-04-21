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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PROVIDER

#include <stdlib.h>
#include "securec.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"

#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider_local.h"
#include "crypt_provider.h"
#include "crypt_drbg_local.h"

// Name of the dl initialization function
#define PROVIDER_INIT_FUNC "CRYPT_EAL_ProviderInit"

// Maximum length of search path
#define DEFAULT_PROVIDER_PATH_LEN_MAX 4095
static uint32_t g_threadRunOnce = 0;


CRYPT_EAL_LibCtx *CRYPT_EAL_LibCtxNew(void)
{
    return CRYPT_EAL_LibCtxNewInternal();
}

// Free EAL_LibCtx context
void CRYPT_EAL_LibCtxFree(CRYPT_EAL_LibCtx *libCtx)
{
    if (libCtx == NULL) {
        return;
    }

    if (libCtx->drbg != NULL) {
        EAL_RandDeinit(libCtx->drbg);
        libCtx->drbg = NULL;
    }
    if (libCtx->providers != NULL) {
        BSL_LIST_FREE(libCtx->providers, (BSL_LIST_PFUNC_FREE)CRYPT_EAL_ProviderMgrCtxFree);
    }

    if (libCtx->lock != NULL) {
        BSL_SAL_ThreadLockFree(libCtx->lock);
    }

    BSL_SAL_FREE(libCtx->searchProviderPath);

    BSL_SAL_Free(libCtx);
}

static void InitPreDefinedProviders(void)
{
    CRYPT_EAL_LibCtx *globalCtx = CRYPT_EAL_GetGlobalLibCtx();
    if (globalCtx == NULL) {
        int32_t ret = CRYPT_EAL_InitPreDefinedProviders();
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }
}

static CRYPT_EAL_LibCtx *GetCurrentProviderLibCtx(CRYPT_EAL_LibCtx *libCtx)
{
    CRYPT_EAL_LibCtx *curLibCtx = libCtx;
    if (curLibCtx == NULL) {
        int32_t ret = BSL_SAL_ThreadRunOnce(&g_threadRunOnce, InitPreDefinedProviders);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return NULL;
        }
        curLibCtx = CRYPT_EAL_GetGlobalLibCtx();
    }

    return curLibCtx;
}

// Write a function to search for providers according to BSL_LIST_Search requirements,
// comparing the input providerName with the providerName in EAL_ProviderMgrCtx for an exact match
static int32_t ListCompareProvider(const void *a, const void *b)
{
    const CRYPT_EAL_ProvMgrCtx *ctx = (const CRYPT_EAL_ProvMgrCtx *)a;
    const char *providerName = (const char *)b;
    return (strcmp(ctx->providerName, providerName) == 0) ? 0 : 1;
}

// Function to mount parameters of EAL_ProviderMgrCtx structure
static int32_t MountEalProviderMgrCtxParams(CRYPT_EAL_LibCtx *libCtx, void *handle, const char *providerName,
    const char *providerPath, BSL_Param *param, CRYPT_EAL_ProvMgrCtx *ctx)
{
    ctx->handle = handle;
    ctx->libCtx = libCtx;

    int32_t ret = BSL_SAL_ReferencesInit(&(ctx->ref));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctx->providerName = BSL_SAL_Dump(providerName,
                                     BSL_SAL_Strnlen(providerName, DEFAULT_PROVIDER_NAME_LEN_MAX) + 1);
    if (ctx->providerName == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    if (providerPath != NULL) {
        ctx->providerPath = BSL_SAL_Dump(providerPath,
                                        BSL_SAL_Strnlen(providerPath, DEFAULT_PROVIDER_PATH_LEN_MAX) + 1);
        if (ctx->providerPath == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }

    // Get the address of the initialization function
    ret = BSL_SAL_GetFuncAddress(handle, PROVIDER_INIT_FUNC, (void **)&ctx->provInitFunc);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Call the initialization function
    return CRYPT_EAL_InitProviderMethod(ctx, param, ctx->provInitFunc);
}

static int32_t CheckProviderLoaded(CRYPT_EAL_LibCtx *libCtx, const char *providerName,
    CRYPT_EAL_ProvMgrCtx **providerMgr)
{
    int32_t ret = BSL_SAL_ThreadReadLock(libCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CRYPT_EAL_ProvMgrCtx *tempProviderMgr =
        (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_Search(libCtx->providers, providerName, ListCompareProvider, NULL);
    if (tempProviderMgr != NULL) {
        // Provider is already loaded, increase the reference count
        int32_t tempCount = 0;
        ret = BSL_SAL_AtomicUpReferences(&tempProviderMgr->ref, &tempCount);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            (void)BSL_SAL_ThreadUnlock(libCtx->lock);
            return ret;
        }
    }
    (void)BSL_SAL_ThreadUnlock(libCtx->lock);

    *providerMgr = tempProviderMgr;
    return CRYPT_SUCCESS;
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

static bool IsEalPreDefinedProvider(const char *providerName)
{
    const char *preProvider[] = {CRYPT_EAL_DEFAULT_PROVIDER};
    for (size_t i = 0; i < sizeof(preProvider) / sizeof(preProvider[0]); i++) {
        if (strcmp(preProvider[i], providerName) == 0) {
            return true;
        }
    }
    return false;
}

// Create a new mgr context and initialize various parameters
static int32_t EalProviderMgrCtxNew(CRYPT_EAL_LibCtx *libCtx, char *providerName, BSL_Param *param,
    CRYPT_EAL_ProvMgrCtx **ctx)
{
    int32_t ret;
    uint32_t pathLen = BSL_SAL_Strnlen(providerName, DEFAULT_PROVIDER_NAME_LEN_MAX) +
        BSL_SAL_Strnlen(libCtx->searchProviderPath, DEFAULT_PROVIDER_PATH_LEN_MAX) + 1;
    if (pathLen > DEFAULT_PROVIDER_PATH_LEN_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    char *providerPath = providerName;
    // Construct the full path of the provider
    if (libCtx->searchProviderPath != NULL) {
        providerPath = (char *)BSL_SAL_Calloc(pathLen + 1, sizeof(char));
        if (providerPath == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = snprintf_s(providerPath, pathLen + 1, pathLen, "%s/%s", libCtx->searchProviderPath, providerName);
        if (ret < 0) {
            BSL_SAL_Free(providerPath);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    // Attempt to load the dynamic library
    void *handle = NULL;
    ret = BSL_SAL_LoadLib(providerPath, &handle);
    if (libCtx->searchProviderPath != NULL) {
        BSL_SAL_Free(providerPath);
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_EAL_ProvMgrCtx *tempCtx = (CRYPT_EAL_ProvMgrCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_ProvMgrCtx));
    if (tempCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // mount parameters of EAL_ProviderMgrCtx structure
    ret = MountEalProviderMgrCtxParams(libCtx, handle, providerName, libCtx->searchProviderPath, param, tempCtx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_ProviderMgrCtxFree(tempCtx);
        return ret;
    }

    *ctx = tempCtx;
    return CRYPT_SUCCESS;
}

// Load provider dynamic library
int32_t CRYPT_EAL_ProviderLoad(CRYPT_EAL_LibCtx *libCtx, BSL_SAL_LibFmtCmd cmd,
    const char *providerName, BSL_Param *param, CRYPT_EAL_ProvMgrCtx **mgrCtx)
{
    if (providerName == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EAL_LibCtx *localCtx = GetCurrentProviderLibCtx(libCtx);
    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }

    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;
    char *providerFullName = NULL;
    int32_t ret = BSL_SAL_LibNameFormat(cmd, providerName, &providerFullName);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Check if the provider is already loaded
    ret = CheckProviderLoaded(localCtx, providerFullName, &providerMgr);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(providerFullName);
        return ret;
    }
    if (providerMgr != NULL) {
        BSL_SAL_Free(providerFullName);
        if (mgrCtx != NULL) {
            *mgrCtx = providerMgr;
        }
        return CRYPT_SUCCESS;
    }
    if (IsEalPreDefinedProvider(providerFullName)) {
        ret = CRYPT_EAL_LoadPreDefinedProvider(libCtx, providerFullName, &providerMgr);
        BSL_SAL_Free(providerFullName);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (mgrCtx != NULL) {
            *mgrCtx = providerMgr;
        }
        return ret;
    }
    // Create and initialize EAL_ProviderMgrCtx
    ret = EalProviderMgrCtxNew(localCtx, providerFullName, param, &providerMgr);
    BSL_SAL_Free(providerFullName);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Add provider to the list
    ret = AddProviderToList(localCtx, providerMgr);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_ProviderMgrCtxFree(providerMgr);
        providerMgr = NULL;
        return ret;
    }

    if (mgrCtx != NULL) {
        *mgrCtx = providerMgr;
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
    CRYPT_EAL_ProviderMgrCtxFree(providerMgr);
}

// Unload provider
int32_t CRYPT_EAL_ProviderUnload(CRYPT_EAL_LibCtx *libCtx, BSL_SAL_LibFmtCmd cmd, const char *providerName)
{
    if (providerName == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_EAL_LibCtx *localCtx = libCtx;
    if (localCtx == NULL) {
        localCtx = CRYPT_EAL_GetGlobalLibCtx();
    }
    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    
    char *providerFullName = NULL;
    int32_t ret = BSL_SAL_LibNameFormat(cmd, providerName, &providerFullName);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Search for the specified provider
    ret = BSL_SAL_ThreadReadLock(localCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(providerFullName);
        return ret;
    }
    CRYPT_EAL_ProvMgrCtx *providerMgr =
        (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_Search(localCtx->providers, providerFullName, ListCompareProvider, NULL);
    BSL_SAL_FREE(providerFullName);
    if (providerMgr == NULL) {
        (void)BSL_SAL_ThreadUnlock(localCtx->lock);
        return CRYPT_SUCCESS;
    }
    // Decrease reference count
    int refCount = 0;
    ret = BSL_SAL_AtomicDownReferences(&providerMgr->ref, &refCount);
    if (ret != BSL_SUCCESS) {
        (void)BSL_SAL_ThreadUnlock(localCtx->lock);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (refCount <= 0) {
        RemoveAndFreeProvider(localCtx->providers, providerMgr);
    }
    (void)BSL_SAL_ThreadUnlock(localCtx->lock);
    return CRYPT_SUCCESS;
}

// Set the path for loading providers
int32_t CRYPT_EAL_ProviderSetLoadPath(CRYPT_EAL_LibCtx *libCtx, const char *searchPath)
{
    if (BSL_SAL_Strnlen(searchPath, DEFAULT_PROVIDER_PATH_LEN_MAX) >= DEFAULT_PROVIDER_PATH_LEN_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    CRYPT_EAL_LibCtx *localCtx = GetCurrentProviderLibCtx(libCtx);
    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    
    char *tempPath = NULL;
    if (searchPath != NULL) {
        tempPath = BSL_SAL_Dump(searchPath, BSL_SAL_Strnlen(searchPath, DEFAULT_PROVIDER_PATH_LEN_MAX) + 1);
        if (tempPath == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    BSL_SAL_FREE(localCtx->searchProviderPath);
    localCtx->searchProviderPath = tempPath;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_ProviderCtrl(CRYPT_EAL_ProvMgrCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || ctx->provCtrlCb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->provCtrlCb(ctx->provCtx, cmd, val, valLen);
}

int32_t CRYPT_EAL_ProviderGetCaps(CRYPT_EAL_ProvMgrCtx *ctx, int32_t cmd, CRYPT_EAL_ProcCapsCb cb, void *args)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->provGetCap == NULL) {
        return CRYPT_SUCCESS;
    }
    return ctx->provGetCap(ctx->provCtx, cmd, cb, args);
}

int32_t CRYPT_EAL_ProviderProcessAll(CRYPT_EAL_LibCtx *ctx, CRYPT_EAL_ProviderProcessCb cb, void *args)
{
    if (cb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EAL_LibCtx *localCtx = ctx;
    if (localCtx == NULL) {
        localCtx = CRYPT_EAL_GetGlobalLibCtx();
    }
    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    BslListNode *node = BSL_LIST_FirstNode(localCtx->providers);
    while (node != NULL) {
        CRYPT_EAL_ProvMgrCtx *providerMgr = (CRYPT_EAL_ProvMgrCtx *)BSL_LIST_GetData(node);
        int32_t ret = cb(providerMgr, args);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        node = BSL_LIST_GetNextNode(localCtx->providers, node);
    }
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_PROVIDER
