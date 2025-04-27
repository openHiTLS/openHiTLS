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
#include "bsl_params.h"

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

typedef struct CryptSha3Ctx CRYPT_SHA3_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_224_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_256_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_384_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_512_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHAKE128_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHAKE256_Ctx;
// new context
CRYPT_SHA3_224_Ctx *CRYPT_SHA3_224_NewCtx(void);
CRYPT_SHA3_256_Ctx *CRYPT_SHA3_256_NewCtx(void);
CRYPT_SHA3_384_Ctx *CRYPT_SHA3_384_NewCtx(void);
CRYPT_SHA3_512_Ctx *CRYPT_SHA3_512_NewCtx(void);
CRYPT_SHAKE128_Ctx *CRYPT_SHAKE128_NewCtx(void);
CRYPT_SHAKE256_Ctx *CRYPT_SHAKE256_NewCtx(void);

// free context
void CRYPT_SHA3_224_FreeCtx(CRYPT_SHA3_224_Ctx* ctx);
void CRYPT_SHA3_256_FreeCtx(CRYPT_SHA3_256_Ctx* ctx);
void CRYPT_SHA3_384_FreeCtx(CRYPT_SHA3_384_Ctx* ctx);
void CRYPT_SHA3_512_FreeCtx(CRYPT_SHA3_512_Ctx* ctx);
void CRYPT_SHAKE128_FreeCtx(CRYPT_SHAKE128_Ctx* ctx);
void CRYPT_SHAKE256_FreeCtx(CRYPT_SHAKE256_Ctx* ctx);

// free context

// Initialize the context
int32_t CRYPT_SHA3_224_Init(CRYPT_SHA3_224_Ctx *ctx, BSL_Param *param);

int32_t CRYPT_SHA3_256_Init(CRYPT_SHA3_256_Ctx *ctx, BSL_Param *param);

int32_t CRYPT_SHA3_384_Init(CRYPT_SHA3_384_Ctx *ctx, BSL_Param *param);

int32_t CRYPT_SHA3_512_Init(CRYPT_SHA3_512_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_SHAKE128_Init(CRYPT_SHAKE128_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_SHAKE256_Init(CRYPT_SHAKE256_Ctx *ctx, BSL_Param *param);

// Data update API
int32_t CRYPT_SHA3_224_Update(CRYPT_SHA3_224_Ctx *ctx, const uint8_t *in, uint32_t len);

int32_t CRYPT_SHA3_256_Update(CRYPT_SHA3_256_Ctx *ctx, const uint8_t *in, uint32_t len);

int32_t CRYPT_SHA3_384_Update(CRYPT_SHA3_384_Ctx *ctx, const uint8_t *in, uint32_t len);

int32_t CRYPT_SHA3_512_Update(CRYPT_SHA3_512_Ctx *ctx, const uint8_t *in, uint32_t len);
int32_t CRYPT_SHAKE128_Update(CRYPT_SHAKE128_Ctx *ctx, const uint8_t *in, uint32_t len);
int32_t CRYPT_SHAKE256_Update(CRYPT_SHAKE256_Ctx *ctx, const uint8_t *in, uint32_t len);

// Padding and output the digest value
int32_t CRYPT_SHA3_224_Final(CRYPT_SHA3_224_Ctx *ctx, uint8_t *out, uint32_t *len);

int32_t CRYPT_SHA3_256_Final(CRYPT_SHA3_256_Ctx *ctx, uint8_t *out, uint32_t *len);

int32_t CRYPT_SHA3_384_Final(CRYPT_SHA3_384_Ctx *ctx, uint8_t *out, uint32_t *len);

int32_t CRYPT_SHA3_512_Final(CRYPT_SHA3_512_Ctx *ctx, uint8_t *out, uint32_t *len);
int32_t CRYPT_SHAKE128_Final(CRYPT_SHAKE128_Ctx *ctx, uint8_t *out, uint32_t *len);
int32_t CRYPT_SHAKE256_Final(CRYPT_SHAKE256_Ctx *ctx, uint8_t *out, uint32_t *len);

int32_t CRYPT_SHAKE128_Squeeze(CRYPT_SHAKE128_Ctx *ctx, uint8_t *out, uint32_t len);
int32_t CRYPT_SHAKE256_Squeeze(CRYPT_SHAKE256_Ctx *ctx, uint8_t *out, uint32_t len);

// Clear the context
void CRYPT_SHA3_224_Deinit(CRYPT_SHA3_224_Ctx *ctx);

void CRYPT_SHA3_256_Deinit(CRYPT_SHA3_256_Ctx *ctx);

void CRYPT_SHA3_384_Deinit(CRYPT_SHA3_384_Ctx *ctx);

void CRYPT_SHA3_512_Deinit(CRYPT_SHA3_512_Ctx *ctx);
void CRYPT_SHAKE128_Deinit(CRYPT_SHAKE128_Ctx *ctx);
void CRYPT_SHAKE256_Deinit(CRYPT_SHAKE256_Ctx *ctx);

// Copy the context
int32_t CRYPT_SHA3_224_CopyCtx(CRYPT_SHA3_224_Ctx *dst, const CRYPT_SHA3_224_Ctx *src);
int32_t CRYPT_SHA3_256_CopyCtx(CRYPT_SHA3_256_Ctx *dst, const CRYPT_SHA3_256_Ctx *src);
int32_t CRYPT_SHA3_384_CopyCtx(CRYPT_SHA3_384_Ctx *dst, const CRYPT_SHA3_384_Ctx *src);
int32_t CRYPT_SHA3_512_CopyCtx(CRYPT_SHA3_512_Ctx *dst, const CRYPT_SHA3_512_Ctx *src);
int32_t CRYPT_SHAKE128_CopyCtx(CRYPT_SHA3_384_Ctx *dst, const CRYPT_SHA3_384_Ctx *src);
int32_t CRYPT_SHAKE256_CopyCtx(CRYPT_SHA3_512_Ctx *dst, const CRYPT_SHA3_512_Ctx *src);

// Dup the context
CRYPT_SHA3_224_Ctx *CRYPT_SHA3_224_DupCtx(const CRYPT_SHA3_224_Ctx *src);
CRYPT_SHA3_256_Ctx *CRYPT_SHA3_256_DupCtx(const CRYPT_SHA3_256_Ctx *src);
CRYPT_SHA3_384_Ctx *CRYPT_SHA3_384_DupCtx(const CRYPT_SHA3_384_Ctx *src);
CRYPT_SHA3_512_Ctx *CRYPT_SHA3_512_DupCtx(const CRYPT_SHA3_512_Ctx *src);
CRYPT_SHA3_384_Ctx *CRYPT_SHAKE128_DupCtx(const CRYPT_SHA3_384_Ctx *src);
CRYPT_SHA3_512_Ctx *CRYPT_SHAKE256_DupCtx(const CRYPT_SHA3_512_Ctx *src);
#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3

#endif // CRYPT_SHA3_H
