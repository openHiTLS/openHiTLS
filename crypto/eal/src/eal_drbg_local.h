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

#ifndef EAL_DRBG_LOCAL_H
#define EAL_DRBG_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_DRBG)

#include <stdint.h>
#include "bsl_sal.h"

#include "crypt_eal_rand.h"
#include "sal_atomic.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct EAL_RndCtx {
    bool isProvider;
    CRYPT_RAND_AlgId id;
    EAL_RandUnitaryMethod *meth;
    void *ctx;
    bool working; // whether the system is in the working state
    bool isDefaultSeed;
    BSL_SAL_ThreadLockHandle lock; // thread lock
};

typedef struct {
    CRYPT_RAND_AlgId id; // seed-drbg algorithm
    CRYPT_EAL_RndCtx *seed; // seed-drbg
    void *seedCtx; // seed-drbg entropy source handle
    CRYPT_RandSeedMethod seedMeth; // seed-drbg entropy source implementation function
    BSL_SAL_RefCount references;
} EAL_SeedDrbg;

int32_t EAL_SeedDrbgInit(EAL_SeedDrbg *seedDrbg);

void EAL_SeedDrbgEntropyMeth(CRYPT_RandSeedMethod *meth);

void EAL_SeedDrbgRandDeinit(CRYPT_EAL_RndCtx *rndCtx);

/**
 * @brief Global random deinitialization
 *
 * @param ctx handle of ctx
 */
void EAL_RandDeinit(CRYPT_EAL_RndCtx *ctx);

/**
 * @brief Get default method.
 *
 * @param void
 */
EAL_RandUnitaryMethod* EAL_RandGetMethod(void);

/**
 * @brief Get default seed method and ctx.
 *
 * @param seedMeth Seed method
 * @param seedCtx Seed context
 */
int32_t EAL_GetDefaultSeed(CRYPT_RandSeedMethod *seedMeth, void **seedCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_DRBG

#endif // EAL_DRBG_LOCAL_H
