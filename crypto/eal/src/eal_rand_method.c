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

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_DRBG)
#include "crypt_local_types.h"
#include "crypt_drbg.h"
#include "crypt_utils.h"
#include "crypt_params_key.h"
#include "eal_rand_local.h"

int32_t DRBG_InstantiateWrapper(DRBG_Ctx *ctx, const uint8_t *person, uint32_t persLen, const BSL_Param *params)
{
    (void)params;
    return DRBG_Instantiate(ctx, person, persLen);
}

int32_t DRBG_ReSeedWrapper(DRBG_Ctx *ctx, const uint8_t *adin, uint32_t adinLen, const BSL_Param *params)
{
    (void)params;
    return DRBG_Reseed(ctx, adin, adinLen);
}

int32_t DRBG_GenerateBytesWrapper(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen, const BSL_Param *params)
{
    (void)params;
    return DRBG_GenerateBytes(ctx, out, outLen, adin, adinLen);
}

static EAL_RandUnitaryMethod g_randMethod = {
    .newCtx = (RandNewCtx)DRBG_New,
    .inst = (RandDrbgInst)DRBG_InstantiateWrapper,
    .unInst = (RandDrbgUnInst)DRBG_Uninstantiate,
    .gen = (RandDrbgGen)DRBG_GenerateBytesWrapper,
    .reSeed = (RandDrbgReSeed)DRBG_ReSeedWrapper,
    .ctrl = (RandDrbgCtrl)DRBG_Ctrl,
    .freeCtx = (RandDrbgFreeCtx)DRBG_Free,
};

EAL_RandUnitaryMethod* EAL_RandGetMethod(void)
{
    return &g_randMethod;
}

#endif
