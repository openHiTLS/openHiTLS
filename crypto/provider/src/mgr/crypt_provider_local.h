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

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief Internal use of provider
 */

#ifndef CRYPT_EAL_PROVIDER_LOCAL_H
#define CRYPT_EAL_PROVIDER_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include <stdint.h>
#include "sal_atomic.h"
#include "crypt_eal_implprovider.h"
#include "bsl_list.h"
#include "eal_drbg_local.h"
#include "crypt_provider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define DEFAULT_PROVIDER_PATH_LEN_MAX 4095

struct EAL_ProviderMgrCtx {
#ifdef HITLS_BSL_SAL_DL
    void *handle; // so handle
#endif
    void *provCtx;
    BSL_SAL_RefCount ref;
    char *providerName;
    char *providerPath;
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
    EAL_SeedDrbg providerSeed; // entropy ctx
#endif
    struct EAL_LibCtx *libCtx;
    CRYPT_EAL_ImplProviderInit provInitFunc;

    // out funcs
    CRYPT_EAL_ProvFreeCb provFreeCb;
    CRYPT_EAL_ProvQueryCb provQueryCb;
    CRYPT_EAL_ProvCtrlCb provCtrlCb;
    CRYPT_EAL_ProvGetCapsCb provGetCap;
};

int32_t CRYPT_EAL_InitProviderMethod(CRYPT_EAL_ProvMgrCtx *ctx, BSL_Param *param,
    CRYPT_EAL_ImplProviderInit providerInit);
CRYPT_EAL_LibCtx *CRYPT_EAL_LibCtxNewInternal(void);
int32_t CRYPT_EAL_CompareAlgAndAttr(CRYPT_EAL_LibCtx *localCtx, int32_t operaId,
    int32_t algId, const char *attribute, const CRYPT_EAL_Func **funcs, CRYPT_EAL_ProvMgrCtx **mgrCtx);

void CRYPT_EAL_ProviderMgrCtxFree(CRYPT_EAL_ProvMgrCtx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_PROVIDER */
#endif // CRYPT_EAL_PROVIDER_LOCAL_H