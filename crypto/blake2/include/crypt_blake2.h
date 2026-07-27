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

#ifndef CRYPT_BLAKE2_H
#define CRYPT_BLAKE2_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BLAKE2

#include <stdint.h>
#include <stdlib.h>
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup LLF_BLAKE2 BLAKE2 Low level function */

#ifdef HITLS_CRYPTO_BLAKE2S256
#define CRYPT_BLAKE2S_BLOCKSIZE  64
#define CRYPT_BLAKE2S_MAX_DIGESTSIZE 32
#define CRYPT_BLAKE2S_STATE_SIZE 8

// blake2s public ctx
typedef struct CryptBlake2sCtx {
    uint32_t h[CRYPT_BLAKE2S_STATE_SIZE];
    uint8_t block[CRYPT_BLAKE2S_BLOCKSIZE];
    uint64_t t;
    uint32_t blockLen;
    uint32_t outLen;
} CRYPT_BLAKE2S_Ctx;

// blake2s public function
CRYPT_BLAKE2S_Ctx *CRYPT_BLAKE2S_NewCtx(void);
CRYPT_BLAKE2S_Ctx *CRYPT_BLAKE2S_NewCtxEx(void *libCtx, int32_t algId);
void CRYPT_BLAKE2S_FreeCtx(CRYPT_BLAKE2S_Ctx *ctx);
int32_t CRYPT_BLAKE2S_Update(CRYPT_BLAKE2S_Ctx *ctx, const uint8_t *data, uint32_t nbytes);
int32_t CRYPT_BLAKE2S_Final(CRYPT_BLAKE2S_Ctx *ctx, uint8_t *out, uint32_t *outLen);
int32_t CRYPT_BLAKE2S_Deinit(CRYPT_BLAKE2S_Ctx *ctx);
int32_t CRYPT_BLAKE2S_CopyCtx(CRYPT_BLAKE2S_Ctx *dst, const CRYPT_BLAKE2S_Ctx *src);
CRYPT_BLAKE2S_Ctx *CRYPT_BLAKE2S_DupCtx(const CRYPT_BLAKE2S_Ctx *src);

#ifdef HITLS_CRYPTO_BLAKE2S256
int32_t CRYPT_BLAKE2S256_Init(CRYPT_BLAKE2S_Ctx *ctx, uint32_t keyLen);
int32_t CRYPT_BLAKE2S256_InitEx(CRYPT_BLAKE2S_Ctx *ctx, void *param);
#define CRYPT_BLAKE2S256_BLOCKSIZE  CRYPT_BLAKE2S_BLOCKSIZE
#define CRYPT_BLAKE2S256_DIGESTSIZE CRYPT_BLAKE2S_MAX_DIGESTSIZE
#define CRYPT_BLAKE2S256_Squeeze    NULL
#define CRYPT_BLAKE2S256_NewCtxEx   CRYPT_BLAKE2S_NewCtxEx
#define CRYPT_BLAKE2S256_Update     CRYPT_BLAKE2S_Update
#define CRYPT_BLAKE2S256_Final      CRYPT_BLAKE2S_Final
#define CRYPT_BLAKE2S256_Deinit     CRYPT_BLAKE2S_Deinit
#define CRYPT_BLAKE2S256_CopyCtx    CRYPT_BLAKE2S_CopyCtx
#define CRYPT_BLAKE2S256_DupCtx     CRYPT_BLAKE2S_DupCtx
#define CRYPT_BLAKE2S256_FreeCtx    CRYPT_BLAKE2S_FreeCtx

#ifdef HITLS_CRYPTO_PROVIDER
    int32_t CRYPT_BLAKE2S256_GetParam(CRYPT_BLAKE2S_Ctx *ctx, BSL_Param *param);
#else
    #define CRYPT_BLAKE2S256_GetParam NULL
#endif
#endif

#endif // HITLS_CRYPTO_BLAKE2S256

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_BLAKE2

#endif // CRYPT_BLAKE2_H
