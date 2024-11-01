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
#include "crypt_algid.h"
#include "crypt_local_types.h"
#include "crypt_eal_rand.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define RAND_TYPE_MD 1
#define RAND_TYPE_MAC 2
#define RAND_TYPE_AES 3
#define RAND_TYPE_AES_DF 4

struct EAL_RndCtx {
    bool isProvider;
    CRYPT_RAND_AlgId id;
    EAL_RandUnitaryMethod *meth;
    void *ctx;
    bool working; // whether the system is in the working state
    BSL_SAL_ThreadLockHandle lock; // thread lock
};

typedef struct {
    CRYPT_RAND_AlgId  drbgId;
    uint32_t depId;
    uint32_t type;
} DrbgIdMap;

const DrbgIdMap *GetDrbgIdMap(CRYPT_RAND_AlgId id);

EAL_RandUnitaryMethod* EAL_RandGetMethod();

int32_t EAL_RandFindMethod(CRYPT_RAND_AlgId id, EAL_RandMethLookup *lu);

/**
 * @brief Set the method for global random number
 *
 * @param meth meth method
 * @return Success: CRYPT_SUCCESS
 * For other error codes, see crypt_errno.h.
 */
int32_t EAL_RandSetMeth(EAL_RandUnitaryMethod *meth, CRYPT_EAL_RndCtx *ctx);

/**
 * @brief Global DRBG initialization. After initialization is complete,
 * call CRYPT_RAND_Deinit before initialization is performed again.
 *
 * @return Success: CRYPT_SUCCESS
 * For other error codes, see crypt_errno.h.
 */
int32_t EAL_RandInit(CRYPT_RAND_AlgId id, CRYPT_Param *param, CRYPT_EAL_RndCtx *ctx, void *provCtx);

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
