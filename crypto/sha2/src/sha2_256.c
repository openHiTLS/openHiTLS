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

CRYPT_SHA2_256_Ctx *CRYPT_SHA2_256_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA2_256_Ctx));
}

CRYPT_SHA2_256_Ctx *CRYPT_SHA2_256_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA2_256_Ctx));
}

void CRYPT_SHA2_256_FreeCtx(CRYPT_SHA2_256_Ctx *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_SHA2_256_Ctx));
}

int32_t CRYPT_SHA2_256_Init(CRYPT_SHA2_256_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
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
    ctx->h[0] = 0x6a09e667UL;
    ctx->h[1] = 0xbb67ae85UL;
    ctx->h[2] = 0x3c6ef372UL;
    ctx->h[3] = 0xa54ff53aUL;
    ctx->h[4] = 0x510e527fUL;
    ctx->h[5] = 0x9b05688cUL;
    ctx->h[6] = 0x1f83d9abUL;
    ctx->h[7] = 0x5be0cd19UL;
    ctx->outlen = CRYPT_SHA2_256_DIGESTSIZE;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA2_256_InitEx(CRYPT_SHA2_256_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_SHA2_256_Init(ctx);
}

int32_t CRYPT_SHA2_256_Deinit(CRYPT_SHA2_256_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_CleanseData((void *)(ctx), sizeof(CRYPT_SHA2_256_Ctx));
    return CRYPT_SUCCESS;
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
        if (memcpy_s(p + n, CRYPT_SHA2_256_BLOCKSIZE - n, d, left) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        ctx->blocklen += (uint32_t)left;
        return CRYPT_SUCCESS;
    }
    if ((n != 0) && (left >= CRYPT_SHA2_256_BLOCKSIZE - n)) {
        if (memcpy_s(p + n, CRYPT_SHA2_256_BLOCKSIZE - n, d, CRYPT_SHA2_256_BLOCKSIZE - n) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
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
        if (memcpy_s((uint8_t *)ctx->block, CRYPT_SHA2_256_BLOCKSIZE, d, left) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
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

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SHA2_256_GetParam(CRYPT_SHA2_256_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_SHA2_256_DIGESTSIZE, CRYPT_SHA2_256_BLOCKSIZE, param);
}
#endif

#ifdef HITLS_CRYPTO_SHA224
int32_t CRYPT_SHA2_224_Init(CRYPT_SHA2_224_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
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

int32_t CRYPT_SHA2_224_InitEx(CRYPT_SHA2_224_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_SHA2_224_Init(ctx);
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SHA2_224_GetParam(CRYPT_SHA2_224_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_SHA2_224_DIGESTSIZE, CRYPT_SHA2_224_BLOCKSIZE, param);
}
#endif

#endif // HITLS_CRYPTO_SHA224

#endif // HITLS_CRYPTO_SHA256
