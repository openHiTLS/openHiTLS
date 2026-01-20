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
#endif /* __cplusplus */

#define CRYPT_EAL_DEFAULT_PROVIDER "default"

// Maximum length of provider name
#define DEFAULT_PROVIDER_NAME_LEN_MAX 255

#if defined(HITLS_CRYPTO_ENTROPY) &&                                                        \
    (defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM) || \
    defined(HITLS_CRYPTO_ENTROPY_SYS) || defined(HITLS_CRYPTO_ENTROPY_HARDWARE))
#define HITLS_CRYPTO_ENTROPY_DEFAULT
#endif

typedef enum {
    CRYPT_PROVIDER_GET_USER_CTX = 1,
    CRYPT_PROVIDER_CTRL_MAX,
} CRYPT_ProviderCtrlCmd;

struct EAL_LibCtx {
    BslList *providers; // managing providers
    BSL_SAL_ThreadLockHandle lock;
#ifdef HITLS_BSL_SAL_DL
    char *searchProviderPath;
#endif
#ifdef HITLS_CRYPTO_DRBG
    void *drbg;
#endif // drbg
};

int32_t CRYPT_EAL_InitPreDefinedProviders(void);
void CRYPT_EAL_FreePreDefinedProviders(void);

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx);

int32_t CRYPT_EAL_AddNewProvMgrCtx(CRYPT_EAL_LibCtx *libCtx, const char *providerName, const char *providerPath,
    CRYPT_EAL_ImplProviderInit init, void *handle, BSL_Param *param, CRYPT_EAL_ProvMgrCtx **ctx);

int32_t CRYPT_EAL_ProviderGetFuncsAndMgrCtx(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attribute, const CRYPT_EAL_Func **funcs, CRYPT_EAL_ProvMgrCtx **mgrCtx, bool noPushError);

CRYPT_EAL_LibCtx* CRYPT_EAL_GetGlobalLibCtx(void);
CRYPT_EAL_LibCtx *GetCurrentProviderLibCtx(CRYPT_EAL_LibCtx *libCtx);

int32_t CRYPT_EAL_ProviderQuery(CRYPT_EAL_ProvMgrCtx *ctx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos);
#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* HITLS_CRYPTO_PROVIDER */
#endif /* CRYPT_PROVIDER_H */
