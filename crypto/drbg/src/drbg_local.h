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

#ifndef DRBG_LOCAL_H
#define DRBG_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DRBG

#include <stdint.h>
#include "crypt_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

// Relationship between the number of NONCE and ENTROPY
#define DRBG_NONCE_FROM_ENTROPY (2)

typedef enum {
    DRBG_STATE_UNINITIALISED,
    DRBG_STATE_READY,
    DRBG_STATE_ERROR,
} DRBG_State;

typedef struct {
    int32_t (*instantiate)(DRBG_Ctx *ctx, const CRYPT_Data *entropy,
                           const CRYPT_Data *nonce, const CRYPT_Data *pers);
    int32_t (*generate)(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen, const CRYPT_Data *adin);
    int32_t (*reseed)(DRBG_Ctx *ctx, const CRYPT_Data *entropy, const CRYPT_Data *adin);
    void (*uninstantiate)(DRBG_Ctx *ctx);
    DRBG_Ctx* (*dup)(DRBG_Ctx *ctx);
    void (*free)(DRBG_Ctx *ctx);
} DRBG_Method;

struct DrbgCtx {
    DRBG_State state; /* DRBG state */

    uint32_t reseedCtr; /* reseed counter */
    uint32_t reseedInterval; /* reseed interval times */

    uint32_t strength; /* Algorithm strength */
    uint32_t maxRequest; /* Maximum number of bytes per request, which is determined by the algorithm. */

    CRYPT_Range entropyRange; /* entropy size range */
    CRYPT_Range nonceRange; /* nonce size range */

    uint32_t maxPersLen; /* Maximum private data length */
    uint32_t maxAdinLen; /* Maximum additional data length */

    DRBG_Method *meth; /* Internal different mode method */
    void *ctx; /* Mode Context */

    /* seed function, which is related to the entropy source and DRBG generation.
       When seedMeth and seedCtx are empty, the default entropy source is used. */
    CRYPT_RandSeedMethod seedMeth;
    void *seedCtx; /* Seed context */
};

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DRBG

#endif // DRBG_LOCAL_H
