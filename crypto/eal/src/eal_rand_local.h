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

#ifndef EAL_RAND_LOCAL_H
#define EAL_RAND_LOCAL_H

#include "hitls_build.h"
#if (defined(HITLS_CRYPTO_EAL) || defined(HITLS_CRYPTO_PROVIDER)) && \
    (defined(HITLS_CRYPTO_DRBG) || defined(HITLS_CRYPTO_MULTI_DRBG))
#include <stdint.h>

#include "crypt_drbg.h"
#include "crypt_utils.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int32_t DRBG_InstantiateWrapper(DRBG_Ctx *ctx, const uint8_t *person, uint32_t persLen, const BSL_Param *params);

int32_t DRBG_ReSeedWrapper(DRBG_Ctx *ctx, const uint8_t *adin, uint32_t adinLen, const BSL_Param *params);

int32_t DRBG_GenerateBytesWrapper(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen, const BSL_Param *params);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif

#endif