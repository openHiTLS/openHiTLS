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
#ifdef HITLS_CRYPTO_BLAKE2S256

#include "crypt_blake2.h"
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "blake2s_core.h"

#define BLAKE2S_FINAL_BLOCK_FLAG 0xFFFFFFFFu
#define BLAKE2_PARAM_BLOCK 0x01010000u

static const uint32_t BLAKE2S_IV[CRYPT_BLAKE2S_STATE_SIZE] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

CRYPT_BLAKE2S_Ctx *CRYPT_BLAKE2S_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_BLAKE2S_Ctx));
}

CRYPT_BLAKE2S_Ctx *CRYPT_BLAKE2S_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return CRYPT_BLAKE2S_NewCtx();
}

void CRYPT_BLAKE2S_FreeCtx(CRYPT_BLAKE2S_Ctx *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_BLAKE2S_Ctx));
}

static int32_t BLAKE2S_Init(CRYPT_BLAKE2S_Ctx *ctx, uint32_t outLen, uint32_t keyLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (outLen == 0 || outLen > CRYPT_BLAKE2S_MAX_DIGESTSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    (void)memset(ctx, 0, sizeof(CRYPT_BLAKE2S_Ctx));
    (void)memcpy(ctx->h, BLAKE2S_IV, sizeof(BLAKE2S_IV));
    // parameter block, referenced https://datatracker.ietf.org/doc/html/rfc7693.html#section-2.6
    ctx->h[0] ^= (outLen | BLAKE2_PARAM_BLOCK | (keyLen << 8));
    ctx->outLen = outLen;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_BLAKE2S256
int32_t CRYPT_BLAKE2S256_Init(CRYPT_BLAKE2S_Ctx *ctx, uint32_t keyLen)
{
    return BLAKE2S_Init(ctx, CRYPT_BLAKE2S256_DIGESTSIZE, keyLen);
}

int32_t CRYPT_BLAKE2S256_InitEx(CRYPT_BLAKE2S_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_BLAKE2S256_Init(ctx, 0);
}
#endif

int32_t CRYPT_BLAKE2S_Deinit(CRYPT_BLAKE2S_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_CleanseData(ctx, sizeof(CRYPT_BLAKE2S_Ctx));
    return CRYPT_SUCCESS;
}

int32_t CRYPT_BLAKE2S_CopyCtx(CRYPT_BLAKE2S_Ctx *dst, const CRYPT_BLAKE2S_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy(dst, src, sizeof(CRYPT_BLAKE2S_Ctx));
    return CRYPT_SUCCESS;
}

CRYPT_BLAKE2S_Ctx *CRYPT_BLAKE2S_DupCtx(const CRYPT_BLAKE2S_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_BLAKE2S_Ctx *newCtx = CRYPT_BLAKE2S_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy(newCtx, src, sizeof(CRYPT_BLAKE2S_Ctx));
    return newCtx;
}

int32_t CRYPT_BLAKE2S_Update(CRYPT_BLAKE2S_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
{
    if (ctx == NULL || (data == NULL && nbytes != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (nbytes == 0) {
        return CRYPT_SUCCESS;
    }
    if (nbytes > UINT64_MAX - ctx->t) {
        BSL_ERR_PUSH_ERROR(CRYPT_MD_INPUT_OVERFLOW);
        return CRYPT_MD_INPUT_OVERFLOW;
    }
    const uint8_t *d = data;
    uint32_t left = nbytes;

    if (ctx->blockLen != 0) {
        uint32_t fillLen = CRYPT_BLAKE2S_BLOCKSIZE - ctx->blockLen;
        if (left <= fillLen) {
            (void)memcpy(ctx->block + ctx->blockLen, d, left);
            ctx->blockLen += left;
            return CRYPT_SUCCESS;
        }

        (void)memcpy(ctx->block + ctx->blockLen, d, fillLen);
        ctx->t += CRYPT_BLAKE2S256_BLOCKSIZE;
        BLAKE2S_Compress(ctx->h, ctx->block, ctx->t, 0);
        (void)memset(ctx->block, 0, CRYPT_BLAKE2S_BLOCKSIZE);
        ctx->blockLen = 0;
        d += fillLen;
        left -= fillLen;
    }

    while (left > CRYPT_BLAKE2S_BLOCKSIZE) {
        ctx->t += CRYPT_BLAKE2S256_BLOCKSIZE;
        BLAKE2S_Compress(ctx->h, d, ctx->t, 0);
        d += CRYPT_BLAKE2S_BLOCKSIZE;
        left -= CRYPT_BLAKE2S_BLOCKSIZE;
    }

    if (left != 0) {
        (void)memcpy(ctx->block, d, left);
        ctx->blockLen = left;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_BLAKE2S_Final(CRYPT_BLAKE2S_Ctx *ctx, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (*outLen < ctx->outLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH;
    }
    (void)memset(ctx->block + ctx->blockLen, 0, CRYPT_BLAKE2S_BLOCKSIZE - ctx->blockLen);
    ctx->t += ctx->blockLen;
    BLAKE2S_Compress(ctx->h, ctx->block, ctx->t, BLAKE2S_FINAL_BLOCK_FLAG);

    uint8_t fullDigest[CRYPT_BLAKE2S_MAX_DIGESTSIZE];
    for (uint32_t i = 0; i < CRYPT_BLAKE2S_STATE_SIZE; i++) {
        PUT_UINT32_LE(ctx->h[i], fullDigest, i * sizeof(uint32_t));
    }
    (void)memcpy(out, fullDigest, ctx->outLen);
    BSL_SAL_CleanseData(fullDigest, sizeof(fullDigest));
    *outLen = ctx->outLen;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_BLAKE2S256_GetParam(CRYPT_BLAKE2S_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_BLAKE2S256_DIGESTSIZE, CRYPT_BLAKE2S_BLOCKSIZE, param);
}
#endif

#endif // HITLS_CRYPTO_BLAKE2S256
