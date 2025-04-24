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

#ifndef CRYPT_PROVIDER_H
#define CRYPT_PROVIDER_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define CRYPT_EAL_DEFAULT_PROVIDER "default"

// Maximum length of provider name
#define DEFAULT_PROVIDER_NAME_LEN_MAX 255

struct EAL_LibCtx {
    BslList *providers; // managing providers
    BSL_SAL_ThreadLockHandle lock;
    char *searchProviderPath;
    void *drbg;
};

#if defined(HITLS_CRYPTO_ENTROPY) &&                                                        \
    (defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM) || \
    defined(HITLS_CRYPTO_ENTROPY_SYS) || defined(HITLS_CRYPTO_ENTROPY_HARDWARE))
#define HITLS_CRYPTO_ENTROPY_DEFAULT
#endif

int32_t CRYPT_EAL_InitPreDefinedProviders(void);
void CRYPT_EAL_FreePreDefinedProviders(void);

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx);

int32_t CRYPT_EAL_LoadPreDefinedProvider(CRYPT_EAL_LibCtx *libCtx, const char* providerName,
    CRYPT_EAL_ProvMgrCtx **ctx);


CRYPT_EAL_LibCtx* CRYPT_EAL_GetGlobalLibCtx(void);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* HITLS_CRYPTO_PROVIDER */
#endif // CRYPT_SHA1_H
