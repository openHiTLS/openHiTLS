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
#ifdef HITLS_CRYPTO_SHA256
#include "crypt_sha2.h"
#include <stdlib.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "sha2_core.h"
#include "bsl_sal.h"
#include "crypt_types.h"

#define SHA256_INIT_ARRAY {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

static const uint32_t SHA256_INIT_STATE[8] = SHA256_INIT_ARRAY;

struct CryptSha256Ctx {
    uint32_t h[CRYPT_SHA2_256_DIGESTSIZE / sizeof(uint32_t)]; /* 256 bits for SHA256 state */
    uint32_t block[CRYPT_SHA2_256_BLOCKSIZE / sizeof(uint32_t)]; /* 512 bits block cache */
    uint32_t lNum, hNum;                                           /* input bits counter, max 2^64 bits */
    uint32_t blocklen;                                     /* block length */
    uint32_t outlen;                                       /* digest output length */
    uint32_t errorCode; /* error Code */
};

CRYPT_SHA2_256_Ctx *CRYPT_SHA2_256_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA2_256_Ctx));
}

void CRYPT_SHA2_256_FreeCtx(CRYPT_SHA2_256_Ctx *ctx)
{
    CRYPT_SHA2_256_Ctx *mdCtx = ctx;
    if (mdCtx == NULL) {
        return;
    }
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_SHA2_256_Ctx));
}

int32_t CRYPT_SHA2_256_Init(CRYPT_SHA2_256_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void) param;
    (void)memset_s(ctx, sizeof(CRYPT_SHA2_256_Ctx), 0, sizeof(CRYPT_SHA2_256_Ctx));
    /**
     * @RFC 4634 6.1 SHA-224 and SHA-256 Initialization
     * SHA-256, the initial hash value, H(0):
     * H(0)0 = 6a09e667
     * H(0)1 = bb67ae85
     * H(0)2 = 3c6ef372
     * H(0)3 = a54ff53a
     * H(0)4 = 510e527f
     * H(0)5 = 9b05688c
     * H(0)6 = 1f83d9ab
     * H(0)7 = 5be0cd19
     */
    (void)memcpy_s(ctx->h, sizeof(SHA256_INIT_STATE), SHA256_INIT_STATE, sizeof(SHA256_INIT_STATE));
    ctx->outlen = CRYPT_SHA2_256_DIGESTSIZE;
    return CRYPT_SUCCESS;
}

void CRYPT_SHA2_256_Deinit(CRYPT_SHA2_256_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_CleanseData((void *)(ctx), sizeof(CRYPT_SHA2_256_Ctx));
}

int32_t CRYPT_SHA2_256_CopyCtx(CRYPT_SHA2_256_Ctx *dst, const CRYPT_SHA2_256_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy_s(dst, sizeof(CRYPT_SHA2_256_Ctx), src, sizeof(CRYPT_SHA2_256_Ctx));
    return CRYPT_SUCCESS;
}

CRYPT_SHA2_256_Ctx *CRYPT_SHA2_256_DupCtx(const CRYPT_SHA2_256_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_SHA2_256_Ctx *newCtx = CRYPT_SHA2_256_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy_s(newCtx, sizeof(CRYPT_SHA2_256_Ctx), src, sizeof(CRYPT_SHA2_256_Ctx));
    return newCtx;
}

static int32_t CheckIsCorrupted(CRYPT_SHA2_256_Ctx *ctx, uint32_t nbytes);
static int32_t UpdateParamIsValid(CRYPT_SHA2_256_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
{
    if ((ctx == NULL) || (data == NULL && nbytes != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->errorCode != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }

    if (CheckIsCorrupted(ctx, nbytes) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

static int32_t CheckIsCorrupted(CRYPT_SHA2_256_Ctx *ctx, uint32_t nbytes)
{
    uint32_t cnt0 = (ctx->lNum + (nbytes << SHIFTS_PER_BYTE)) & 0xffffffffUL;
    if (cnt0 < ctx->lNum) { /* overflow */
        if (++ctx->hNum == 0) {
            ctx->errorCode = CRYPT_SHA2_INPUT_OVERFLOW;
            BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
            return CRYPT_SHA2_INPUT_OVERFLOW;
        }
    }
    uint32_t cnt1 = ctx->hNum + (uint32_t)(nbytes >> (BITSIZE(uint32_t) - SHIFTS_PER_BYTE));
    if (cnt1 < ctx->hNum) { /* overflow */
        ctx->errorCode = CRYPT_SHA2_INPUT_OVERFLOW;
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }
    ctx->hNum = cnt1;
    ctx->lNum = cnt0;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA2_256_Update(CRYPT_SHA2_256_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
{
    int32_t ret = UpdateParamIsValid(ctx, data, nbytes);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (nbytes == 0) {
        return CRYPT_SUCCESS;
    }

    const uint8_t *d = data;
    uint32_t left = nbytes;
    uint32_t n = ctx->blocklen;
    uint8_t *p = (uint8_t *)ctx->block;

    if (left < CRYPT_SHA2_256_BLOCKSIZE - n) {
        (void)memcpy_s(p + n, CRYPT_SHA2_256_BLOCKSIZE - n, d, left);
        ctx->blocklen += (uint32_t)left;
        return CRYPT_SUCCESS;
    }
    if ((n != 0) && (left >= CRYPT_SHA2_256_BLOCKSIZE - n)) {
        (void)memcpy_s(p + n, CRYPT_SHA2_256_BLOCKSIZE - n, d, CRYPT_SHA2_256_BLOCKSIZE - n);
        SHA256CompressMultiBlocks(ctx->h, p, 1);
        n = CRYPT_SHA2_256_BLOCKSIZE - n;
        d += n;
        left -= n;
        ctx->blocklen = 0;
        (void)memset_s(p, CRYPT_SHA2_256_BLOCKSIZE, 0, CRYPT_SHA2_256_BLOCKSIZE);
    }

    n = (uint32_t)(left / CRYPT_SHA2_256_BLOCKSIZE);
    if (n > 0) {
        SHA256CompressMultiBlocks(ctx->h, d, n);
        n *= CRYPT_SHA2_256_BLOCKSIZE;
        d += n;
        left -= n;
    }

    if (left != 0) {
        ctx->blocklen = (uint32_t)left;
        (void)memcpy_s((uint8_t *)ctx->block, CRYPT_SHA2_256_BLOCKSIZE, d, left);
    }

    return CRYPT_SUCCESS;
}

static int32_t FinalParamIsValid(const CRYPT_SHA2_256_Ctx *ctx, const uint8_t *out, const uint32_t *outLen)
{
    if ((ctx == NULL) || (out == NULL) || (outLen == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*outLen < ctx->outlen) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    if (ctx->errorCode == CRYPT_SHA2_INPUT_OVERFLOW) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}
int32_t CRYPT_SHA2_256_Final(CRYPT_SHA2_256_Ctx *ctx, uint8_t *digest, uint32_t *outlen)
{
    int32_t ret = FinalParamIsValid(ctx, digest, outlen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint8_t *p = (uint8_t *)ctx->block;
    uint32_t n = ctx->blocklen;

    p[n++] = 0x80;
    if (n > (CRYPT_SHA2_256_BLOCKSIZE - 8)) { /* 8 bytes to save bits of input */
        (void)memset_s(p + n, CRYPT_SHA2_256_BLOCKSIZE - n, 0, CRYPT_SHA2_256_BLOCKSIZE - n);
        n = 0;
        SHA256CompressMultiBlocks(ctx->h, p, 1);
    }
    (void)memset_s(p + n, CRYPT_SHA2_256_BLOCKSIZE - n, 0,
        CRYPT_SHA2_256_BLOCKSIZE - 8 - n); /* 8 bytes to save bits of input */

    p += CRYPT_SHA2_256_BLOCKSIZE - 8; /* 8 bytes to save bits of input */
    PUT_UINT32_BE(ctx->hNum, p, 0);
    p += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->lNum, p, 0);
    p += sizeof(uint32_t);
    p -= CRYPT_SHA2_256_BLOCKSIZE;
    SHA256CompressMultiBlocks(ctx->h, p, 1);
    ctx->blocklen = 0;
    (void)memset_s(p, CRYPT_SHA2_256_BLOCKSIZE, 0, CRYPT_SHA2_256_BLOCKSIZE);

    n = ctx->outlen / sizeof(uint32_t);
    for (uint32_t nn = 0; nn < n; nn++) {
        PUT_UINT32_BE(ctx->h[nn], digest, sizeof(uint32_t) * nn);
    }
    *outlen = ctx->outlen;

    return CRYPT_SUCCESS;
}


#ifdef HITLS_CRYPTO_SHA2_MB

CRYPT_SHA2_256_MB_Ctx *CRYPT_SHA256_MBNewCtx(uint32_t num)
{
    if (num != 2) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return NULL;
    }

    CRYPT_SHA2_256_MB_Ctx *mbCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_SHA2_256_MB_Ctx));
    if (mbCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    mbCtx->ctxs = BSL_SAL_Calloc(num, sizeof(CRYPT_SHA2_256_Ctx));
    if (mbCtx->ctxs == NULL) {
        BSL_SAL_Free(mbCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    mbCtx->num = num;
    return mbCtx;
}

void CRYPT_SHA256_MBFreeCtx(CRYPT_SHA2_256_MB_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->ctxs != NULL) {
        for (uint32_t i = 0; i < ctx->num; i++) {
            (void)CRYPT_SHA2_256_Deinit(&ctx->ctxs[i]);
        }
        BSL_SAL_Free(ctx->ctxs);
    }
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_SHA256_MBInit(CRYPT_SHA2_256_MB_Ctx *ctx)
{
#if defined(__aarch64__)
    // currently only support sha256x2 in aarch64
    if (UNLIKELY(ctx == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (UNLIKELY(ctx->num != 2)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    (void)CRYPT_SHA2_256_Init(&ctx->ctxs[0], NULL);
    (void)CRYPT_SHA2_256_Init(&ctx->ctxs[1], NULL);
    return CRYPT_SUCCESS;
#else
    (void)ctx;
    return CRYPT_NOT_SUPPORT;
#endif
}

int32_t CRYPT_SHA256_MBUpdate(CRYPT_SHA2_256_MB_Ctx *ctx, const uint8_t *data[], uint32_t nbytes[], uint32_t num)
{
#if defined(__aarch64__) && defined(HITLS_CRYPTO_SHA2_ASM)
    // currently only support sha256x2 in aarch64
    if (UNLIKELY(ctx == NULL || data == NULL || nbytes == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (UNLIKELY(num != 2 || ctx->num != num || nbytes[0] != nbytes[1])) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    uint32_t commonBytes = nbytes[0];
    if (commonBytes == 0) {
        return CRYPT_SUCCESS;
    }
    CRYPT_SHA2_256_Ctx *ctx0 = &ctx->ctxs[0];
    CRYPT_SHA2_256_Ctx *ctx1 = &ctx->ctxs[1];

    int32_t ret = UpdateParamIsValid(ctx0, data[0], commonBytes);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = UpdateParamIsValid(ctx1, data[1], commonBytes);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint8_t *b0 = (uint8_t *)(uintptr_t)ctx0->block;
    uint8_t *b1 = (uint8_t *)(uintptr_t)ctx1->block;
    const uint8_t *d0 = data[0];
    const uint8_t *d1 = data[1];
    uint32_t caches = ctx0->blocklen;
    if (caches + commonBytes >= CRYPT_SHA2_256_BLOCKSIZE) {
        if (caches != 0) {
            uint32_t cpysize = CRYPT_SHA2_256_BLOCKSIZE - caches;
            (void)memcpy_s(b0 + caches, cpysize, d0, cpysize);
            d0 += cpysize;
            (void)memcpy_s(b1 + caches, cpysize, d1, cpysize);
            d1 += cpysize;
            commonBytes -= cpysize;
            CRYPT_SHA256x2_Compress(ctx0->h, ctx1->h, b0, b1, 1);
            ctx0->blocklen = 0;
            ctx1->blocklen = 0;
        }
        uint32_t nblocks = commonBytes / CRYPT_SHA2_256_BLOCKSIZE;
        commonBytes &= (CRYPT_SHA2_256_BLOCKSIZE - 1);
        if (nblocks > 0) {
            CRYPT_SHA256x2_Compress(ctx0->h, ctx1->h, d0, d1, nblocks);
            d0 += nblocks * CRYPT_SHA2_256_BLOCKSIZE;
            d1 += nblocks * CRYPT_SHA2_256_BLOCKSIZE;
        }
        caches = 0; 
    }
    if (commonBytes != 0) {
        (void)memcpy_s(b0 + caches, CRYPT_SHA2_256_BLOCKSIZE - caches, d0, commonBytes);
        (void)memcpy_s(b1 + caches, CRYPT_SHA2_256_BLOCKSIZE - caches, d1, commonBytes);
        ctx0->blocklen += commonBytes;
        ctx1->blocklen += commonBytes;
    }
    return CRYPT_SUCCESS;
#else
    (void)ctx;
    (void)data;
    (void)nbytes;
    (void)num;
    return CRYPT_NOT_SUPPORT;
#endif
}

int32_t CRYPT_SHA256_MBFinal(CRYPT_SHA2_256_MB_Ctx *ctx, uint8_t *digest[], uint32_t *outlen, uint32_t num)
{
#if defined(__aarch64__) && defined(HITLS_CRYPTO_SHA2_ASM)
    // currently only support sha256x2 in aarch64
    if (UNLIKELY(ctx == NULL || digest == NULL || outlen == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (UNLIKELY(num != 2 || ctx->num != num)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }

    if (UNLIKELY(digest[0] == NULL || digest[1] == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_SHA2_256_Ctx *ctx0 = &ctx->ctxs[0];
    CRYPT_SHA2_256_Ctx *ctx1 = &ctx->ctxs[1];
    int32_t ret = FinalParamIsValid(ctx0, digest[0], outlen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = FinalParamIsValid(ctx1, digest[1], outlen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t *b0 = (uint8_t *)(uintptr_t)ctx0->block;
    uint8_t *b1 = (uint8_t *)(uintptr_t)ctx1->block;
    uint32_t caches = ctx0->blocklen;
    b0[caches] = 0x80;
    b1[caches++] = 0x80;
    if (caches > (CRYPT_SHA2_256_BLOCKSIZE - 8)) {
        (void)memset_s(b0 + caches, CRYPT_SHA2_256_BLOCKSIZE - caches, 0, CRYPT_SHA2_256_BLOCKSIZE - caches);
        (void)memset_s(b1 + caches, CRYPT_SHA2_256_BLOCKSIZE - caches, 0, CRYPT_SHA2_256_BLOCKSIZE - caches);
        caches = 0;
        CRYPT_SHA256x2_Compress(ctx0->h, ctx1->h, b0, b1, 1);
    }
    (void)memset_s(b0 + caches, CRYPT_SHA2_256_BLOCKSIZE - caches, 0,
        CRYPT_SHA2_256_BLOCKSIZE - 8 - caches); /* 8 bytes to save bits of input */
    (void)memset_s(b1 + caches, CRYPT_SHA2_256_BLOCKSIZE - caches, 0,
        CRYPT_SHA2_256_BLOCKSIZE - 8 - caches); /* 8 bytes to save bits of input */
    PUT_UINT32_BE(ctx0->hNum, b0, CRYPT_SHA2_256_BLOCKSIZE - 8);
    PUT_UINT32_BE(ctx0->lNum, b0, CRYPT_SHA2_256_BLOCKSIZE - 4);
    PUT_UINT32_BE(ctx1->hNum, b1, CRYPT_SHA2_256_BLOCKSIZE - 8);
    PUT_UINT32_BE(ctx1->lNum, b1, CRYPT_SHA2_256_BLOCKSIZE - 4);
    CRYPT_SHA256x2_Compress(ctx0->h, ctx1->h, b0, b1, 1);
    ctx0->blocklen = 0;
    ctx1->blocklen = 0;
    for (uint32_t i = 0; i < ctx0->outlen / sizeof(uint32_t); i++) {
        PUT_UINT32_BE(ctx0->h[i], digest[0], sizeof(uint32_t) * i);
        PUT_UINT32_BE(ctx1->h[i], digest[1], sizeof(uint32_t) * i);
    }
    *outlen = ctx0->outlen;
    return CRYPT_SUCCESS;   
#else
    (void)ctx;
    (void)digest;
    (void)outlen;
    (void)num;
    return CRYPT_NOT_SUPPORT;
#endif
}

int32_t CRYPT_SHA256_MB(const uint8_t *data[], uint32_t nbytes, uint8_t *digest[], uint32_t *outlen, uint32_t num)
{
#if defined(__aarch64__) && defined(HITLS_CRYPTO_SHA2_ASM)
    // currently only support sha256x2 in aarch64
    if (num != 2) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    uint32_t state1[CRYPT_SHA256_STATE_SIZE] = SHA256_INIT_ARRAY;
    uint32_t state2[CRYPT_SHA256_STATE_SIZE] = SHA256_INIT_ARRAY;
    (void)CRYPT_SHA256x2(state1, state2, data[0], data[1], nbytes, digest[0], digest[1]);
    *outlen = CRYPT_SHA2_256_DIGESTSIZE;
    return CRYPT_SUCCESS;
#else
    (void)data;
    (void)nbytes;
    (void)digest;
    (void)outlen;
    (void)num;
    return CRYPT_NOT_SUPPORT;
#endif
}
#endif // HITLS_CRYPTO_SHA2_MB

#ifdef HITLS_CRYPTO_SHA224


CRYPT_SHA2_224_Ctx *CRYPT_SHA2_224_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA2_224_Ctx));
}

void CRYPT_SHA2_224_FreeCtx(CRYPT_SHA2_224_Ctx *ctx)
{
    CRYPT_SHA2_224_Ctx *mdCtx = ctx;
    if (mdCtx == NULL) {
        return;
    }
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_SHA2_224_Ctx));
}

int32_t CRYPT_SHA2_224_Init(CRYPT_SHA2_224_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void) param;
    (void)memset_s(ctx, sizeof(CRYPT_SHA2_224_Ctx), 0, sizeof(CRYPT_SHA2_224_Ctx));
    /**
     * @RFC 4634 6.1 SHA-224 and SHA-256 Initialization
     * SHA-224, the initial hash value, H(0):
     * H(0)0 = c1059ed8
     * H(0)1 = 367cd507
     * H(0)2 = 3070dd17
     * H(0)3 = f70e5939
     * H(0)4 = ffc00b31
     * H(0)5 = 68581511
     * H(0)6 = 64f98fa7
     * H(0)7 = befa4fa4
     */
    ctx->h[0] = 0xc1059ed8UL;
    ctx->h[1] = 0x367cd507UL;
    ctx->h[2] = 0x3070dd17UL;
    ctx->h[3] = 0xf70e5939UL;
    ctx->h[4] = 0xffc00b31UL;
    ctx->h[5] = 0x68581511UL;
    ctx->h[6] = 0x64f98fa7UL;
    ctx->h[7] = 0xbefa4fa4UL;
    ctx->outlen = CRYPT_SHA2_224_DIGESTSIZE;
    return CRYPT_SUCCESS;
}

void CRYPT_SHA2_224_Deinit(CRYPT_SHA2_224_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_CleanseData((void *)(ctx), sizeof(CRYPT_SHA2_224_Ctx));
}

int32_t CRYPT_SHA2_224_CopyCtx(CRYPT_SHA2_224_Ctx *dst, const CRYPT_SHA2_224_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy_s(dst, sizeof(CRYPT_SHA2_224_Ctx), src, sizeof(CRYPT_SHA2_224_Ctx));
    return CRYPT_SUCCESS;
}

CRYPT_SHA2_224_Ctx *CRYPT_SHA2_224_DupCtx(const CRYPT_SHA2_224_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_SHA2_224_Ctx *newCtx = CRYPT_SHA2_224_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy_s(newCtx, sizeof(CRYPT_SHA2_224_Ctx), src, sizeof(CRYPT_SHA2_224_Ctx));
    return newCtx;
}

int32_t CRYPT_SHA2_224_Update(CRYPT_SHA2_224_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
{
    return CRYPT_SHA2_256_Update((CRYPT_SHA2_256_Ctx *)ctx, data, nbytes);
}

int32_t CRYPT_SHA2_224_Final(CRYPT_SHA2_224_Ctx *ctx, uint8_t *digest, uint32_t *len)
{
    return CRYPT_SHA2_256_Final((CRYPT_SHA2_256_Ctx *)ctx, digest, len);
}
#endif // HITLS_CRYPTO_SHA224

#endif // HITLS_CRYPTO_SHA256
