/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief Internal use of provider
 */

#ifndef CRYPT_EAL_PROVIDER_LOCAL_H
#define CRYPT_EAL_PROVIDER_LOCAL_H

#include <stdint.h>
#include "sal_atomic.h"
#include "crypt_eal_implprovider.h"
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct EalLibCtx {
    BslList *providers; // managing providers
    BSL_SAL_ThreadLockHandle lock;
    char *searchProviderPath;
};

struct EalProviderMgrCtx {
    void *handle; // so handle
    void *provCtx;
    BSL_SAL_RefCount ref;
    char *providerName;
    char *providerPath;
    void *seedCtx; // entropy ctx
    struct EalLibCtx *libCtx;
    CRYPT_EAL_ImplProviderInit provInitFunc;

    // out funcs
    CRYPT_EAL_ProvFreeCb provFreeCb;
    CRYPT_EAL_ProvQueryCb provQueryCb;
    CRYPT_EAL_ProvCtrlCb provCtrlCb;
};

int32_t CRYPT_EAL_InitProviderMethod(CRYPT_EAL_ProvMgrCtx *ctx, CRYPT_Param *param,
    CRYPT_EAL_ImplProviderInit providerInit);
CRYPT_EAL_LibCtx *CRYPT_EAL_NewLibCtxInternal();
int32_t CRYPT_EAL_CompareAlgAndAttr(CRYPT_EAL_LibCtx *localCtx, int32_t operaId,
    int32_t algId, const char *attribute, const CRYPT_EAL_Func **funcs, void **provCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_PROVIDER_LOCAL_H