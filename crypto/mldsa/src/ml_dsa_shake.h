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
#ifndef MLDSA_SHAKE_H
#define MLDSA_SHAKE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MLDSA

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "crypt_sha3.h"

typedef struct {
    uint64_t s[25];
    uint32_t rate;
} MldsaShakeCtx;

static inline void MldsaShake128_Init(MldsaShakeCtx *ctx)
{
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->rate = CRYPT_SHAKE128_BLOCKSIZE;
}

static inline void MldsaShake256_Init(MldsaShakeCtx *ctx)
{
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->rate = CRYPT_SHAKE256_BLOCKSIZE;
}

static inline void MldsaShake128_Absorb(MldsaShakeCtx *ctx, const uint8_t *in, size_t len)
{
    KeccakAbsorb(ctx->s, ctx->rate, in, len, 0x1F);
}

static inline void MldsaShake256_Absorb(MldsaShakeCtx *ctx, const uint8_t *in, size_t len)
{
    KeccakAbsorb(ctx->s, ctx->rate, in, len, 0x1F);
}

static inline void MldsaShake128_SqueezeBlocks(MldsaShakeCtx *ctx, uint8_t *out, size_t nblocks)
{
    KeccakSqueeze(out, nblocks, ctx->s, ctx->rate);
}

static inline void MldsaShake256_SqueezeBlocks(MldsaShakeCtx *ctx, uint8_t *out, size_t nblocks)
{
    KeccakSqueeze(out, nblocks, ctx->s, ctx->rate);
}

#endif
#endif
