/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_SHA3_H
#define CRYPT_SHA3_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA3

#include <stdint.h>
#include <stdlib.h>

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
} CRYPT_SHA3_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_224_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_256_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_384_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHA3_512_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHAKE128_Ctx;

typedef CRYPT_SHA3_Ctx CRYPT_SHAKE256_Ctx;

// Initialize the context
int32_t CRYPT_SHA3_224_Init(CRYPT_SHA3_224_Ctx *ctx);

int32_t CRYPT_SHA3_256_Init(CRYPT_SHA3_256_Ctx *ctx);

int32_t CRYPT_SHA3_384_Init(CRYPT_SHA3_384_Ctx *ctx);

int32_t CRYPT_SHA3_512_Init(CRYPT_SHA3_512_Ctx *ctx);
int32_t CRYPT_SHAKE128_Init(CRYPT_SHAKE128_Ctx *ctx);
int32_t CRYPT_SHAKE256_Init(CRYPT_SHAKE256_Ctx *ctx);

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

// Clear the context
void CRYPT_SHA3_224_Deinit(CRYPT_SHA3_224_Ctx *ctx);

void CRYPT_SHA3_256_Deinit(CRYPT_SHA3_256_Ctx *ctx);

void CRYPT_SHA3_384_Deinit(CRYPT_SHA3_384_Ctx *ctx);

void CRYPT_SHA3_512_Deinit(CRYPT_SHA3_512_Ctx *ctx);
void CRYPT_SHAKE128_Deinit(CRYPT_SHAKE128_Ctx *ctx);
void CRYPT_SHAKE256_Deinit(CRYPT_SHAKE256_Ctx *ctx);

// Copy the context
int32_t CRYPT_SHA3_224_CopyCtx(CRYPT_SHA3_224_Ctx *dst, CRYPT_SHA3_224_Ctx *src);

int32_t CRYPT_SHA3_256_CopyCtx(CRYPT_SHA3_256_Ctx *dst, CRYPT_SHA3_256_Ctx *src);

int32_t CRYPT_SHA3_384_CopyCtx(CRYPT_SHA3_384_Ctx *dst, CRYPT_SHA3_384_Ctx *src);

int32_t CRYPT_SHA3_512_CopyCtx(CRYPT_SHA3_512_Ctx *dst, CRYPT_SHA3_512_Ctx *src);

#define CRYPT_SHAKE128_CopyCtx NULL
#define CRYPT_SHAKE256_CopyCtx NULL

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3

#endif // CRYPT_SHA3_H
