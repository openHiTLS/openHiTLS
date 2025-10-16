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
 * @brief sm provider header
 */

#ifndef CRYPT_EAL_SM_PROVIDER_H
#define CRYPT_EAL_SM_PROVIDER_H

#ifdef HITLS_CRYPTO_CMVP_SM

#include <stdint.h>
#include "crypt_eal_entropy.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_cmvp.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CRYPT_EAL_SM_ATTR "provider=sm"

typedef struct EalSmProvCtx {
    void *libCtx;
    void *mgrCtx;
    CRYPT_EAL_Es *es;
    CRYPT_EAL_SeedPoolCtx *pool;
} CRYPT_EAL_SmProvCtx;

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
    CRYPT_EAL_Func **outFuncs, void **provCtx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_CMVP_SM */
#endif /* CRYPT_EAL_SM_PROVIDER_H */