/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_PROVIDER_H
#define CRYPT_PROVIDER_H

#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

int32_t CRYPT_EAL_GetFuncsFromProvider(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attribute, const CRYPT_EAL_Func **funcs, void **provCtx);

int32_t CRYPT_EAL_InitPreDefinedProviders();
void CRYPT_EAL_FreePreDefinedProviders();

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, CRYPT_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // CRYPT_SHA1_H
