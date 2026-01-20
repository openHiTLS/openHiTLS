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
#ifdef HITLS_CRYPTO_SHA512
#include "crypt_sha2.h"
#include <stdlib.h>
#include "securec.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "sha2_core.h"
#include "bsl_sal.h"

#define SHA2_512_PADSIZE    112

// function : num1 += num2(num1 and num2 are 128bit int32_t)
static int32_t Add128Bit(uint64_t *num1h, uint64_t *num1l, uint64_t num2h, uint64_t num2l)
{
    uint64_t num1hTemp = *num1h;
    uint64_t num1lTemp = *num1l;
    uint64_t sumh = num1hTemp;
    uint64_t suml = num1lTemp + num2l;
    uint64_t carry = 0;
    if (suml < num1lTemp) {
        carry = 1;
        sumh += carry;
    }
    sumh += num2h;
    // num2h + carry >= 1, thus sumh shoud > num1hTemp; otherwise overflow
    if ((carry > 0 || num2h > 0) && sumh <= num1hTemp) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }
    *num1h = sumh;
    *num1l = suml;
    return 0;
}

static int32_t CheckIsCorrupted(CRYPT_SHA2_512_Ctx *ctx, uint32_t nbytes)
{
    // bit len of data = len << 3, which may be 2^67, thus need to 2 uint64 to represent
    uint64_t bitLenl = (uint64_t)nbytes << 3; // low 64 bit
    // high 64 bit, right shift 61 to get higest 3 bit
    uint64_t bitLenh = sizeof(nbytes) >= sizeof(uint64_t) ? (uint64_t)nbytes >> 61 : 0;
    if (Add128Bit(&ctx->hNum, &ctx->lNum, bitLenh, bitLenl) != 0) {
        // overflow, the len of msg over 2 ^ 128;
        ctx->errorCode = CRYPT_SHA2_INPUT_OVERFLOW;
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }
    return CRYPT_SUCCESS;
}

CRYPT_SHA2_512_Ctx *CRYPT_SHA2_512_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA2_512_Ctx));
}

CRYPT_SHA2_512_Ctx *CRYPT_SHA2_512_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA2_512_Ctx));
}

void CRYPT_SHA2_512_FreeCtx(CRYPT_SHA2_512_Ctx *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_SHA2_512_Ctx));
}

int32_t CRYPT_SHA2_512_Init(CRYPT_SHA2_512_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memset_s(ctx, sizeof(CRYPT_SHA2_512_Ctx), 0, sizeof(CRYPT_SHA2_512_Ctx));

    // see RFC6234 chapter 6.3
    ctx->h[0] = U64(0x6a09e667f3bcc908);
    ctx->h[1] = U64(0xbb67ae8584caa73b);
    ctx->h[2] = U64(0x3c6ef372fe94f82b);
    ctx->h[3] = U64(0xa54ff53a5f1d36f1);
    ctx->h[4] = U64(0x510e527fade682d1);
    ctx->h[5] = U64(0x9b05688c2b3e6c1f);
    ctx->h[6] = U64(0x1f83d9abfb41bd6b);
    ctx->h[7] = U64(0x5be0cd19137e2179);
    ctx->mdlen = CRYPT_SHA2_512_DIGESTSIZE;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA2_512_InitEx(CRYPT_SHA2_512_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_SHA2_512_Init(ctx);
}

int32_t CRYPT_SHA2_512_Deinit(CRYPT_SHA2_512_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_CleanseData((void *)(ctx), sizeof(CRYPT_SHA2_512_Ctx));
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA2_512_CopyCtx(CRYPT_SHA2_512_Ctx *dst, const CRYPT_SHA2_512_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy_s(dst, sizeof(CRYPT_SHA2_512_Ctx), src, sizeof(CRYPT_SHA2_512_Ctx));
    return CRYPT_SUCCESS;
}

CRYPT_SHA2_512_Ctx *CRYPT_SHA2_512_DupCtx(const CRYPT_SHA2_512_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_SHA2_512_Ctx *newCtx = CRYPT_SHA2_512_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy_s(newCtx, sizeof(CRYPT_SHA2_512_Ctx), src, sizeof(CRYPT_SHA2_512_Ctx));
    return newCtx;
}

static int32_t UpdateParamIsValid(CRYPT_SHA2_512_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
{
    if ((ctx == NULL) || (data == NULL && nbytes != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->errorCode == CRYPT_SHA2_INPUT_OVERFLOW) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }

    return CheckIsCorrupted(ctx, nbytes);
}

int32_t CRYPT_SHA2_512_Update(CRYPT_SHA2_512_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
{
    int32_t ret = UpdateParamIsValid(ctx, data, nbytes);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (nbytes == 0) {
        return CRYPT_SUCCESS;
    }

    const uint32_t n = CRYPT_SHA2_512_BLOCKSIZE - ctx->num;
    if (nbytes < n) {
        // if the data can't fill block, just copy data to block
        (void)memcpy_s(ctx->block + ctx->num, n, data, nbytes);
        ctx->num += (uint32_t)nbytes;
        return CRYPT_SUCCESS;
    }

    const uint8_t *d = data;
    uint32_t dataLen = nbytes;
    if (ctx->num != 0) {
        // fill the block first and compute
        (void)memcpy_s(ctx->block + ctx->num, n, data, n);
        ctx->num = 0;
        dataLen -= n;
        d += n;
        SHA512CompressMultiBlocks(ctx->h, ctx->block, 1);
    }

    SHA512CompressMultiBlocks(ctx->h, d, dataLen / CRYPT_SHA2_512_BLOCKSIZE);
    d += dataLen;
    dataLen &= (CRYPT_SHA2_512_BLOCKSIZE - 1);
    d -= dataLen;

    if (dataLen != 0) {
        // copy rest data to blcok
        if (memcpy_s(ctx->block, CRYPT_SHA2_512_BLOCKSIZE, d, dataLen) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        ctx->num = (uint32_t)dataLen;
    }

    return CRYPT_SUCCESS;
}

static int32_t FinalParamIsValid(const CRYPT_SHA2_512_Ctx *ctx, const uint8_t *out, const uint32_t *outLen)
{
    if ((ctx == NULL) || (out == NULL) || (outLen == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*outLen < ctx->mdlen) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    if (ctx->errorCode == CRYPT_SHA2_INPUT_OVERFLOW) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA2_INPUT_OVERFLOW);
        return CRYPT_SHA2_INPUT_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA2_512_Final(CRYPT_SHA2_512_Ctx *ctx, uint8_t *digest, uint32_t *len)
{
    int32_t ret = FinalParamIsValid(ctx, digest, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t pad;
    uint32_t n = ctx->num;
    uint8_t *block = ctx->block;

    block[n++] = 0x80;

    if (n > SHA2_512_PADSIZE) {
        pad = CRYPT_SHA2_512_BLOCKSIZE - n;
        (void)memset_s(block + n, pad, 0, pad);
        SHA512CompressMultiBlocks(ctx->h, block, 1);
        n = 0;
        pad = SHA2_512_PADSIZE;
    } else {
        pad = SHA2_512_PADSIZE - n;
    }

    (void)memset_s(block + n, pad, 0, pad);
    Uint64ToBeBytes(ctx->hNum, block + SHA2_512_PADSIZE);
    Uint64ToBeBytes(ctx->lNum, block + SHA2_512_PADSIZE + sizeof(uint64_t));
    SHA512CompressMultiBlocks(ctx->h, block, 1);

    uint8_t *out = digest;
    uint32_t ncnt = ctx->mdlen >> 3; // MDSize / 8, calculate the number of times that values need to be assigned to out
    for (n = 0; n < ncnt; n++) {
        Uint64ToBeBytes(ctx->h[n], out);
        out += sizeof(uint64_t);
    }
    *len = ctx->mdlen;

    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SHA2_512_GetParam(CRYPT_SHA2_512_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_SHA2_512_DIGESTSIZE, CRYPT_SHA2_512_BLOCKSIZE, param);
}
#endif

#ifdef HITLS_CRYPTO_SHA384
int32_t CRYPT_SHA2_384_Init(CRYPT_SHA2_384_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memset_s(ctx, sizeof(CRYPT_SHA2_384_Ctx), 0, sizeof(CRYPT_SHA2_384_Ctx));
    ctx->h[0] = U64(0xcbbb9d5dc1059ed8);
    ctx->h[1] = U64(0x629a292a367cd507);
    ctx->h[2] = U64(0x9159015a3070dd17);
    ctx->h[3] = U64(0x152fecd8f70e5939);
    ctx->h[4] = U64(0x67332667ffc00b31);
    ctx->h[5] = U64(0x8eb44a8768581511);
    ctx->h[6] = U64(0xdb0c2e0d64f98fa7);
    ctx->h[7] = U64(0x47b5481dbefa4fa4);
    ctx->mdlen = CRYPT_SHA2_384_DIGESTSIZE;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA2_384_InitEx(CRYPT_SHA2_384_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_SHA2_384_Init(ctx);
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SHA2_384_GetParam(CRYPT_SHA2_384_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_SHA2_384_DIGESTSIZE, CRYPT_SHA2_384_BLOCKSIZE, param);
}
#endif
#endif // HITLS_CRYPTO_SHA384

#endif // HITLS_CRYPTO_SHA512
