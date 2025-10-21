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

#ifndef CRYPT_SHA3_H
#define CRYPT_SHA3_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA3

#include <stdint.h>
#include <stdlib.h>
#include "crypt_types.h"

#ifdef HITLS_CRYPTO_PROVIDER
#include "bsl_params.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */


/** @defgroup LLF SHA3 Low level function */

/* SHA3-224 */
#define CRYPT_SHA3_224_BLOCKSIZE   144  // ((1600 - 224 * 2) / 8)
#define CRYPT_SHA3_224_DIGESTSIZE  28

/* SHA3-256 */
#define CRYPT_SHA3_256_BLOCKSIZE   136  // ((1600 - 256 * 2) / 8)
#define CRYPT_SHA3_256_DIGESTSIZE  32

/* SHA3-384 */
#define CRYPT_SHA3_384_BLOCKSIZE   104  // ((1600 - 384 * 2) / 8)
#define CRYPT_SHA3_384_DIGESTSIZE  48

/* SHA3-512 */
#define CRYPT_SHA3_512_BLOCKSIZE   72  // ((1600 - 512 * 2) / 8)
#define CRYPT_SHA3_512_DIGESTSIZE  64

/* SHAKE128 */
#define CRYPT_SHAKE128_BLOCKSIZE   168  // ((1600 - 128 * 2) / 8)
#define CRYPT_SHAKE128_DIGESTSIZE  0

/* SHAKE256 */
#define CRYPT_SHAKE256_BLOCKSIZE   136  // ((1600 - 256 * 2) / 8)
#define CRYPT_SHAKE256_DIGESTSIZE  0

typedef struct {
    uint8_t state[200];     // State array, 200bytes is 1600bits
    uint32_t num;           // Data length in the remaining buffer.
    uint32_t blockSize;     // For example, BlockSize(sha3-224) = ((1600 - 224 * 2) / 8) bytes
    uint32_t mdSize;     // sha3-224 corresponds to 28 bytes, sha3-256: 32 bytes, sha3-384: 48 bytes, sha3-512: 64 bytes
    // Non-integer multiple data cache. 168 = (1600 - 128 * 2) / 8, that is maximum block size used by shake_*
    uint8_t buf[168];
    uint8_t padChr;         // char for padding, sha3_* use 0x06 and shake_* use 0x1f
    bool squeeze;
} CRYPT_SHA3_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_224_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_256_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_384_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_512_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHAKE128_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHAKE256_Ctx;

CRYPT_SHA3_Ctx *CRYPT_SHA3_NewCtx(void);
#define CRYPT_SHA3_224_NewCtx CRYPT_SHA3_NewCtx
#define CRYPT_SHA3_256_NewCtx CRYPT_SHA3_NewCtx
#define CRYPT_SHA3_384_NewCtx CRYPT_SHA3_NewCtx
#define CRYPT_SHA3_512_NewCtx CRYPT_SHA3_NewCtx
#define CRYPT_SHAKE128_NewCtx CRYPT_SHA3_NewCtx
#define CRYPT_SHAKE256_NewCtx CRYPT_SHA3_NewCtx

CRYPT_SHA3_Ctx *CRYPT_SHA3_NewCtxEx(void *libCtx, int32_t algId);
#define CRYPT_SHA3_224_NewCtxEx CRYPT_SHA3_NewCtxEx
#define CRYPT_SHA3_256_NewCtxEx CRYPT_SHA3_NewCtxEx
#define CRYPT_SHA3_384_NewCtxEx CRYPT_SHA3_NewCtxEx
#define CRYPT_SHA3_512_NewCtxEx CRYPT_SHA3_NewCtxEx
#define CRYPT_SHAKE128_NewCtxEx CRYPT_SHA3_NewCtxEx
#define CRYPT_SHAKE256_NewCtxEx CRYPT_SHA3_NewCtxEx

void CRYPT_SHA3_FreeCtx(CRYPT_SHA3_Ctx *ctx);
#define CRYPT_SHA3_224_FreeCtx CRYPT_SHA3_FreeCtx
#define CRYPT_SHA3_256_FreeCtx CRYPT_SHA3_FreeCtx
#define CRYPT_SHA3_384_FreeCtx CRYPT_SHA3_FreeCtx
#define CRYPT_SHA3_512_FreeCtx CRYPT_SHA3_FreeCtx
#define CRYPT_SHAKE128_FreeCtx CRYPT_SHA3_FreeCtx
#define CRYPT_SHAKE256_FreeCtx CRYPT_SHA3_FreeCtx

// Initialize the context
int32_t CRYPT_SHA3_224_Init(CRYPT_SHA3_224_Ctx *ctx);
int32_t CRYPT_SHA3_224_InitEx(CRYPT_SHA3_224_Ctx *ctx, void *param);

int32_t CRYPT_SHA3_256_Init(CRYPT_SHA3_256_Ctx *ctx);
int32_t CRYPT_SHA3_256_InitEx(CRYPT_SHA3_256_Ctx *ctx, void *param);

int32_t CRYPT_SHA3_384_Init(CRYPT_SHA3_384_Ctx *ctx);
int32_t CRYPT_SHA3_384_InitEx(CRYPT_SHA3_384_Ctx *ctx, void *param);

int32_t CRYPT_SHA3_512_Init(CRYPT_SHA3_512_Ctx *ctx);
int32_t CRYPT_SHA3_512_InitEx(CRYPT_SHA3_512_Ctx *ctx, void *param);

int32_t CRYPT_SHAKE128_Init(CRYPT_SHAKE128_Ctx *ctx);
int32_t CRYPT_SHAKE128_InitEx(CRYPT_SHAKE128_Ctx *ctx, void *param);

int32_t CRYPT_SHAKE256_Init(CRYPT_SHAKE256_Ctx *ctx);
int32_t CRYPT_SHAKE256_InitEx(CRYPT_SHAKE256_Ctx *ctx, void *param);

// Data update API
int32_t CRYPT_SHA3_Update(CRYPT_SHA3_Ctx *ctx, const uint8_t *in, uint32_t len);
#define CRYPT_SHA3_224_Update CRYPT_SHA3_Update
#define CRYPT_SHA3_256_Update CRYPT_SHA3_Update
#define CRYPT_SHA3_384_Update CRYPT_SHA3_Update
#define CRYPT_SHA3_512_Update CRYPT_SHA3_Update
#define CRYPT_SHAKE128_Update CRYPT_SHA3_Update
#define CRYPT_SHAKE256_Update CRYPT_SHA3_Update

// Padding and output the digest value
int32_t CRYPT_SHA3_Final(CRYPT_SHA3_Ctx *ctx, uint8_t *out, uint32_t *len);
#define CRYPT_SHA3_224_Final CRYPT_SHA3_Final
#define CRYPT_SHA3_256_Final CRYPT_SHA3_Final
#define CRYPT_SHA3_384_Final CRYPT_SHA3_Final
#define CRYPT_SHA3_512_Final CRYPT_SHA3_Final
#define CRYPT_SHAKE128_Final CRYPT_SHA3_Final
#define CRYPT_SHAKE256_Final CRYPT_SHA3_Final

int32_t CRYPT_SHA3_Squeeze(CRYPT_SHA3_Ctx *ctx, uint8_t *out, uint32_t len);
#define CRYPT_SHA3_224_Squeeze NULL
#define CRYPT_SHA3_256_Squeeze NULL
#define CRYPT_SHA3_384_Squeeze NULL
#define CRYPT_SHA3_512_Squeeze NULL
#define CRYPT_SHAKE128_Squeeze CRYPT_SHA3_Squeeze
#define CRYPT_SHAKE256_Squeeze CRYPT_SHA3_Squeeze

// Clear the context
int32_t CRYPT_SHA3_Deinit(CRYPT_SHA3_Ctx *ctx);
#define CRYPT_SHA3_224_Deinit CRYPT_SHA3_Deinit
#define CRYPT_SHA3_256_Deinit CRYPT_SHA3_Deinit
#define CRYPT_SHA3_384_Deinit CRYPT_SHA3_Deinit
#define CRYPT_SHA3_512_Deinit CRYPT_SHA3_Deinit
#define CRYPT_SHAKE128_Deinit CRYPT_SHA3_Deinit
#define CRYPT_SHAKE256_Deinit CRYPT_SHA3_Deinit

// Copy the context
int32_t CRYPT_SHA3_CopyCtx(CRYPT_SHA3_Ctx *dst, const CRYPT_SHA3_Ctx *src);
#define CRYPT_SHA3_224_CopyCtx CRYPT_SHA3_CopyCtx
#define CRYPT_SHA3_256_CopyCtx CRYPT_SHA3_CopyCtx
#define CRYPT_SHA3_384_CopyCtx CRYPT_SHA3_CopyCtx
#define CRYPT_SHA3_512_CopyCtx CRYPT_SHA3_CopyCtx
#define CRYPT_SHAKE128_CopyCtx CRYPT_SHA3_CopyCtx
#define CRYPT_SHAKE256_CopyCtx CRYPT_SHA3_CopyCtx

// Dup the context
CRYPT_SHA3_Ctx *CRYPT_SHA3_DupCtx(const CRYPT_SHA3_Ctx *src);
#define CRYPT_SHA3_224_DupCtx CRYPT_SHA3_DupCtx
#define CRYPT_SHA3_256_DupCtx CRYPT_SHA3_DupCtx
#define CRYPT_SHA3_384_DupCtx CRYPT_SHA3_DupCtx
#define CRYPT_SHA3_512_DupCtx CRYPT_SHA3_DupCtx
#define CRYPT_SHAKE128_DupCtx CRYPT_SHA3_DupCtx
#define CRYPT_SHAKE256_DupCtx CRYPT_SHA3_DupCtx

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SHA3_224_GetParam(CRYPT_SHA3_224_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_SHA3_256_GetParam(CRYPT_SHA3_256_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_SHA3_384_GetParam(CRYPT_SHA3_384_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_SHA3_512_GetParam(CRYPT_SHA3_512_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_SHAKE128_GetParam(CRYPT_SHAKE128_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_SHAKE256_GetParam(CRYPT_SHAKE256_Ctx *ctx, BSL_Param *param);
#else
#define CRYPT_SHA3_224_GetParam NULL
#define CRYPT_SHA3_256_GetParam NULL
#define CRYPT_SHA3_384_GetParam NULL
#define CRYPT_SHA3_512_GetParam NULL
#define CRYPT_SHAKE128_GetParam NULL
#define CRYPT_SHAKE256_GetParam NULL
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3

#endif // CRYPT_SHA3_H
