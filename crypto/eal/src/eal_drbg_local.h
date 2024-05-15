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

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef union {
    uintptr_t ptr;
} CRYPT_RndParam;

typedef struct {
    /**
     * @brief Memory application and initialization of DRBG context. If it is not registered, the input ctx is null.
     */
    void* (*newCtx)(CRYPT_RndParam *param);
    /**
     * @brief Free the DRBG context memory. If it is not registered, this interface is not invoked in the deinit.
     */
    void (*freeCtx)(void *ctx);
    /**
     * @brief Generate random numbers.This hook must be implemented otherwise it will fail at initialization.
     *        (The internal initialization is specified by default.)
     */
    int32_t (*rand)(void *ctx, uint8_t *bytes, uint32_t len, const uint8_t *addin, uint32_t adinLen);
    /**
     * @brief DRBG seed interface. If it is not registered internally, the seed and seedwithAdin directly fail,
     *        but the DRBG generation is not affected because it's specified by default during internal initialization.
     */
    int32_t (*seed)(void *ctx, const uint8_t *addin, uint32_t adinLen);
} EalRndMeth;

struct EAL_RndCtx {
    CRYPT_RAND_AlgId id;
    EalRndMeth meth;
    void *ctx;
    bool working; // whether the system is in the working state
    BSL_SAL_ThreadLockHandle lock; // thread lock
};

/**
 * @brief Set the method for global random number
 *
 * @param meth meth method
 * @return Success: CRYPT_SUCCESS
 * For other error codes, see crypt_errno.h.
 */
int32_t EAL_RandSetMeth(EalRndMeth *meth, CRYPT_EAL_RndCtx *ctx);

/**
 * @brief Global DRBG initialization. After initialization is complete,
 * call CRYPT_RAND_Deinit before initialization is performed again.
 *
 * @return Success: CRYPT_SUCCESS
 * For other error codes, see crypt_errno.h.
 */
int32_t EAL_RandInit(CRYPT_RndParam *param, CRYPT_EAL_RndCtx *ctx);

/**
 * @brief Global random deinitialization
 *
 * @param ctx handle of ctx
 */
void CRYPT_RandDeinit(CRYPT_EAL_RndCtx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_DRBG

#endif // EAL_DRBG_LOCAL_H
