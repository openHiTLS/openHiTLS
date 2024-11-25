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

#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

int32_t CRYPT_EAL_InitPreDefinedProviders();
void CRYPT_EAL_FreePreDefinedProviders();

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* HITLS_CRYPTO_PROVIDER */
#endif // CRYPT_SHA1_H
