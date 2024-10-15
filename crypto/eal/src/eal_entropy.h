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
