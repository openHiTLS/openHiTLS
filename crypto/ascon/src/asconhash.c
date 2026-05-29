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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ASCONHASH

#include <stdlib.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "ascon_core.h"
#include "crypt_asconhash.h"

/* ================= Constant Definition ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128
#define CRYPTO_BYTES_HASH           32
#define ASCON_HASH_OUTLEN_HASH      32
#define ASCON_HASH_ROUNDS_HASH      12
#endif

#ifdef HITLS_CRYPTO_ASCON_HASH128A
#define CRYPTO_BYTES_HASHA          32
#define ASCON_HASH_OUTLEN_HASHA     32
#define ASCON_HASH_ROUNDS_HASHA     8
#endif

#define ASCON_HASH_RATE             8
#define ASCON_HASH_DIGESTSIZE       32

/* ================= Permutation Helper ================= */
static inline void ascon_permute(state_t *s, uint8_t rounds)
{
    if (rounds == 8) {
        P8(s);
    } else {
        P12(s);
    }
}

/* ================= ASCON Hash Context ================= */
struct CRYPT_ASCONHASH_Ctx {
    state_t  s;                      /* Ascon state (5 x 64-bit) */
    uint8_t  buf[ASCON_HASH_RATE];   /* Partial block buffer (rate=8) */
    uint32_t bufLen;                 /* Bytes buffered in buf[] */
    uint8_t  finalized;              /* Flag: 1 if Final() has been called */
    uint8_t  initialized;            /* Flag: 1 if Init() has been called */
    uint8_t  rounds;                 /* 8 for ascon_hash128a, 12 for ascon_hash128 */
};


/* ================= Unified Static Initialization ================= */
static int32_t ASCON_HASH_Init(CRYPT_ASCONHASH_Ctx *ctx, uint8_t rounds, uint64_t iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)BSL_SAL_CleanseData(ctx, sizeof(*ctx));
    
    ctx->rounds = rounds;
    ctx->initialized = 1;
    
    ctx->s.x0 = iv;
    ctx->s.x1 = 0;
    ctx->s.x2 = 0;
    ctx->s.x3 = 0;
    ctx->s.x4 = 0;
    
    P12(&ctx->s);
    
    return CRYPT_SUCCESS;
}


/* ================= Context allocation and free ================= */
CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_ASCONHASH_Ctx));
}

CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return CRYPT_ASCON_HASH128_NewCtx();
}

void CRYPT_ASCON_HASH128_FreeCtx(CRYPT_ASCONHASH_Ctx *ctx)
{
    if (ctx != NULL) {
        BSL_SAL_ClearFree(ctx, sizeof(CRYPT_ASCONHASH_Ctx));
    }
}

#ifdef HITLS_CRYPTO_ASCON_HASH128A
/* ================= ASCON-HASH128A Context allocation and free ================= */
CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128A_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_ASCONHASH_Ctx));
}

CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128A_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return CRYPT_ASCON_HASH128A_NewCtx();
}

void CRYPT_ASCON_HASH128A_FreeCtx(CRYPT_ASCONHASH_Ctx *ctx)
{
    if (ctx != NULL) {
        BSL_SAL_ClearFree(ctx, sizeof(CRYPT_ASCONHASH_Ctx));
    }
}
#endif


/* ================= Initialization / Deinitialization ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128
int32_t CRYPT_ASCON_HASH128_Init(CRYPT_ASCONHASH_Ctx *ctx)
{
    return ASCON_HASH_Init(ctx, 12, ASCON_HASH_IV);
}

int32_t CRYPT_ASCON_HASH128_InitEx(CRYPT_ASCONHASH_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_ASCON_HASH128_Init(ctx);
}

int32_t CRYPT_ASCON_HASH128_Deinit(CRYPT_ASCONHASH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)BSL_SAL_CleanseData(ctx, sizeof(*ctx));
    return CRYPT_SUCCESS;
}
#endif


#ifdef HITLS_CRYPTO_ASCON_HASH128A
int32_t CRYPT_ASCON_HASH128A_Init(CRYPT_ASCONHASH_Ctx *ctx)
{
    return ASCON_HASH_Init(ctx, 8, ASCON_HASHA_IV);
}

int32_t CRYPT_ASCON_HASH128A_InitEx(CRYPT_ASCONHASH_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_ASCON_HASH128A_Init(ctx);
}

int32_t CRYPT_ASCON_HASH128A_Deinit(CRYPT_ASCONHASH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)BSL_SAL_CleanseData(ctx, sizeof(*ctx));
    return CRYPT_SUCCESS;
}
#endif


/* ================= Update (absorb) ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128
int32_t CRYPT_ASCON_HASH128_Update(CRYPT_ASCONHASH_Ctx *ctx,
    const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || (in == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!ctx->initialized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->finalized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    while (len > 0) {
        uint32_t space = ASCON_HASH_RATE - ctx->bufLen;
        uint32_t take = (len < space) ? len : space;

        (void)memcpy(ctx->buf + ctx->bufLen, in, take);
        ctx->bufLen += take;
        in += take;
        len -= take;

        if (ctx->bufLen == ASCON_HASH_RATE) {
            ctx->s.x0 ^= LOADBYTES(ctx->buf, ASCON_HASH_RATE);
            ascon_permute(&ctx->s, ctx->rounds);  /* Dynamically select P8/P12 */
            ctx->bufLen = 0;
        }
    }

    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_ASCON_HASH128A
/* Hash128a reuses Hash128 Update implementation (same logic, different rounds) */
int32_t CRYPT_ASCON_HASH128A_Update(CRYPT_ASCONHASH_Ctx *ctx,
    const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || (in == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!ctx->initialized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->finalized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    while (len > 0) {
        uint32_t space = ASCON_HASH_RATE - ctx->bufLen;
        uint32_t take = (len < space) ? len : space;

        (void)memcpy(ctx->buf + ctx->bufLen, in, take);
        ctx->bufLen += take;
        in += take;
        len -= take;

        if (ctx->bufLen == ASCON_HASH_RATE) {
            ctx->s.x0 ^= LOADBYTES(ctx->buf, ASCON_HASH_RATE);
            ascon_permute(&ctx->s, ctx->rounds); 
            ctx->bufLen = 0;
        }
    }

    return CRYPT_SUCCESS;
}
#endif


/* ================= Final (pad + squeeze) ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128
int32_t CRYPT_ASCON_HASH128_Final(CRYPT_ASCONHASH_Ctx *ctx,
    uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!ctx->initialized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->finalized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (*outLen < CRYPT_ASCON_HASH128_DIGESTSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    /* 1. Absorb last block + padding */
    ctx->s.x0 ^= LOADBYTES(ctx->buf, ctx->bufLen);
    ctx->s.x0 ^= PAD(ctx->bufLen);
    P12(&ctx->s);  /* Standard specification: fixed P12 after final absorption */

    /* 2. Squeeze output 32 bytes (4 rate blocks) */
    for (uint32_t i = 0; i < 4; i++) {
        STOREBYTES(out, ctx->s.x0, 8);
        out += 8;
        /* Inter-block permutation: select P8/P12 based on rounds, no permutation after last block */
        if (i < 3) {
            ascon_permute(&ctx->s, ctx->rounds);
        }
    }

    *outLen = CRYPT_ASCON_HASH128_DIGESTSIZE;
    ctx->finalized = 1;

    BSL_SAL_CleanseData(ctx->buf, sizeof(ctx->buf));
    ctx->bufLen = 0;

    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_ASCON_HASH128A
int32_t CRYPT_ASCON_HASH128A_Final(CRYPT_ASCONHASH_Ctx *ctx,
    uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!ctx->initialized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->finalized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (*outLen < CRYPT_ASCON_HASH128A_DIGESTSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    /* 1. Absorb last block + padding */
    ctx->s.x0 ^= LOADBYTES(ctx->buf, ctx->bufLen);
    ctx->s.x0 ^= PAD(ctx->bufLen);
    P12(&ctx->s);  /* Standard specification: fixed P12 after final absorption */

    /* 2. Squeeze output 32 bytes (4 rate blocks) */
    for (uint32_t i = 0; i < 4; i++) {
        STOREBYTES(out, ctx->s.x0, 8);
        out += 8;
        /* Inter-block permutation: select P8/P12 based on rounds, no permutation after last block */
        if (i < 3) {
            ascon_permute(&ctx->s, ctx->rounds);
        }
    }

    *outLen = CRYPT_ASCON_HASH128A_DIGESTSIZE;
    ctx->finalized = 1;

    BSL_SAL_CleanseData(ctx->buf, sizeof(ctx->buf));
    ctx->bufLen = 0;

    return CRYPT_SUCCESS;
}
#endif


/* ================= Context copy/dup ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128
int32_t CRYPT_ASCON_HASH128_CopyCtx(CRYPT_ASCONHASH_Ctx *dst,
    const CRYPT_ASCONHASH_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memcpy(dst, src, sizeof(*src));
    return CRYPT_SUCCESS;
}

CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128_DupCtx(const CRYPT_ASCONHASH_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_ASCONHASH_Ctx *ctx = CRYPT_ASCON_HASH128_NewCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy(ctx, src, sizeof(*src));
    return ctx;
}
#endif

#ifdef HITLS_CRYPTO_ASCON_HASH128A
/* ================= ASCON-HASH128A Context copy/dup ================= */
int32_t CRYPT_ASCON_HASH128A_CopyCtx(CRYPT_ASCONHASH_Ctx *dst,
    const CRYPT_ASCONHASH_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memcpy(dst, src, sizeof(*src));
    return CRYPT_SUCCESS;
}

CRYPT_ASCONHASH_Ctx *CRYPT_ASCON_HASH128A_DupCtx(const CRYPT_ASCONHASH_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_ASCONHASH_Ctx *ctx = CRYPT_ASCON_HASH128A_NewCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy(ctx, src, sizeof(*src));
    return ctx;
}
#endif


#ifdef HITLS_CRYPTO_PROVIDER
/* ================= GetParam ================= */
#ifdef HITLS_CRYPTO_ASCON_HASH128
int32_t CRYPT_ASCON_HASH128_GetParam(CRYPT_ASCONHASH_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(
        CRYPT_ASCON_HASH128_DIGESTSIZE,
        CRYPT_ASCON_HASH128_BLOCKSIZE,
        param);
}
#endif /* HITLS_CRYPTO_ASCON_HASH128 */


#ifdef HITLS_CRYPTO_ASCON_HASH128A
int32_t CRYPT_ASCON_HASH128A_GetParam(CRYPT_ASCONHASH_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(
        CRYPT_ASCON_HASH128A_DIGESTSIZE,
        CRYPT_ASCON_HASH128A_BLOCKSIZE,
        param);
}
#endif /* HITLS_CRYPTO_ASCON_HASH128A */

#endif /* HITLS_CRYPTO_PROVIDER */ 


/* ================= Squeeze ================= */
static int32_t ASCON_HASH_Squeeze_Impl(CRYPT_ASCONHASH_Ctx *ctx,
    uint8_t *out, uint32_t outLen)
{
    (void)ctx;
    (void)out;
    (void)outLen;
    return CRYPT_NOT_SUPPORT;
}

#ifdef HITLS_CRYPTO_ASCON_HASH128
int32_t CRYPT_ASCON_HASH128_Squeeze(void *vctx, uint8_t *out, uint32_t outLen)
{
    return ASCON_HASH_Squeeze_Impl((CRYPT_ASCONHASH_Ctx *)vctx, out, outLen);
}
#endif


#ifdef HITLS_CRYPTO_ASCON_HASH128A
int32_t CRYPT_ASCON_HASH128A_Squeeze(void *vctx, uint8_t *out, uint32_t outLen)
{
    return ASCON_HASH_Squeeze_Impl((CRYPT_ASCONHASH_Ctx *)vctx, out, outLen);
}
#endif

#endif /* HITLS_CRYPTO_ASCONHASH */