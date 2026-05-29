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

#ifndef CRYPT_ASCONHASH_H
#define CRYPT_ASCONHASH_H

#include "hitls_build.h"

#ifdef HITLS_CRYPTO_ASCONHASH

#include <stdint.h>
#include "crypt_types.h"
#include "crypt_local_types.h"

#ifdef HITLS_CRYPTO_PROVIDER
#include "bsl_params.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


typedef struct CRYPT_ASCONHASH_Ctx CRYPT_ASCONHASH_Ctx;


/* ================= ASCON-HASH128 API Definition ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128

#define CRYPT_ASCON_HASH128_BLOCKSIZE  8
#define CRYPT_ASCON_HASH128_DIGESTSIZE 32

CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128_NewCtx(void);
CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128_NewCtxEx(void *libCtx, int32_t algId);
void CRYPT_ASCON_HASH128_FreeCtx(CRYPT_ASCONHASH_Ctx *ctx);

int32_t CRYPT_ASCON_HASH128_Init(CRYPT_ASCONHASH_Ctx *ctx);
int32_t CRYPT_ASCON_HASH128_InitEx(CRYPT_ASCONHASH_Ctx *ctx, void *param);
int32_t CRYPT_ASCON_HASH128_Deinit(CRYPT_ASCONHASH_Ctx *ctx);

int32_t CRYPT_ASCON_HASH128_Update(CRYPT_ASCONHASH_Ctx *ctx,
                                   const uint8_t *in, uint32_t len);
int32_t CRYPT_ASCON_HASH128_Final(CRYPT_ASCONHASH_Ctx *ctx,
                                  uint8_t *out, uint32_t *outLen);

int32_t CRYPT_ASCON_HASH128_CopyCtx(CRYPT_ASCONHASH_Ctx *dst,
                                    const CRYPT_ASCONHASH_Ctx *src);
CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128_DupCtx(const CRYPT_ASCONHASH_Ctx *src);

int32_t CRYPT_ASCON_HASH128_Squeeze(void *vctx, uint8_t *out, uint32_t outLen);
#endif /* HITLS_CRYPTO_ASCON_HASH128 */


/* ================= ASCON-HASH128A API Definition ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128A

#define CRYPT_ASCON_HASH128A_BLOCKSIZE  8
#define CRYPT_ASCON_HASH128A_DIGESTSIZE 32

CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128A_NewCtx(void);
CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128A_NewCtxEx(void *libCtx, int32_t algId);
void CRYPT_ASCON_HASH128A_FreeCtx(CRYPT_ASCONHASH_Ctx *ctx);

int32_t CRYPT_ASCON_HASH128A_Init(CRYPT_ASCONHASH_Ctx *ctx);
int32_t CRYPT_ASCON_HASH128A_InitEx(CRYPT_ASCONHASH_Ctx *ctx, void *param);
int32_t CRYPT_ASCON_HASH128A_Deinit(CRYPT_ASCONHASH_Ctx *ctx);

int32_t CRYPT_ASCON_HASH128A_Update(CRYPT_ASCONHASH_Ctx *ctx,
                                    const uint8_t *in, uint32_t len);
int32_t CRYPT_ASCON_HASH128A_Final(CRYPT_ASCONHASH_Ctx *ctx,
                                   uint8_t *out, uint32_t *outLen);

int32_t CRYPT_ASCON_HASH128A_CopyCtx(CRYPT_ASCONHASH_Ctx *dst,
                                     const CRYPT_ASCONHASH_Ctx *src);
CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128A_DupCtx(const CRYPT_ASCONHASH_Ctx *src);

int32_t CRYPT_ASCON_HASH128A_Squeeze(void *vctx, uint8_t *out, uint32_t outLen);
#endif /* HITLS_CRYPTO_ASCON_HASH128A */


#ifdef HITLS_CRYPTO_PROVIDER
#ifdef HITLS_CRYPTO_ASCON_HASH128
int32_t CRYPT_ASCON_HASH128_GetParam(CRYPT_ASCONHASH_Ctx *ctx, BSL_Param *param);
#else
#define CRYPT_ASCON_HASH128_GetParam NULL
#endif
#ifdef HITLS_CRYPTO_ASCON_HASH128A
int32_t CRYPT_ASCON_HASH128A_GetParam(CRYPT_ASCONHASH_Ctx *ctx, BSL_Param *param);
#else
#define CRYPT_ASCON_HASH128A_GetParam NULL
#endif
#else
#define CRYPT_ASCON_HASH128_GetParam NULL
#define CRYPT_ASCON_HASH128A_GetParam NULL
#endif


#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_ASCONHASH */

#endif /* CRYPT_ASCONHASH_H */
