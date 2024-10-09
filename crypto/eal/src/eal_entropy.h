/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef EAL_ENTROPY_H
#define EAL_ENTROPY_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_ENTROPY)

#include "crypt_types.h"
#include "entropy.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief Set the random number method that uses the default system entropy source.
 *
 * @param meth    meth method
 * @param seedCtx Handle of seedCtx
 * @return Success: CRYPT_SUCCESS
 */
int32_t EAL_SetDefaultEntropyMeth(CRYPT_RandSeedMethod *meth, void **seedCtx);

/**
 * @brief Obtain the conditioning function of the corresponding algorithm.
 *
 * @param  algId algId
 * @return ExternalConditioningFunction
 */
ExternalConditioningFunction EAL_EntropyGetECF(uint32_t algId);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_ENTROPY

#endif // EAL_ENTROPY_H
