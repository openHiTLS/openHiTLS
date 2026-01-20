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
#ifdef HITLS_CRYPTO_SM3

#include <stdlib.h>
#include <stdint.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_sm3.h"
#include "sm3_local.h"

CRYPT_SM3_Ctx *CRYPT_SM3_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SM3_Ctx));
}

CRYPT_SM3_Ctx *CRYPT_SM3_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SM3_Ctx));
}

void CRYPT_SM3_FreeCtx(CRYPT_SM3_Ctx *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_SM3_Ctx));
}

int32_t CRYPT_SM3_Init(CRYPT_SM3_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memset_s(ctx, sizeof(CRYPT_SM3_Ctx), 0, sizeof(CRYPT_SM3_Ctx));
    /* GM/T 0004-2012 chapter 4.1 */
    ctx->h[0] = 0x7380166F;
    ctx->h[1] = 0x4914B2B9;
    ctx->h[2] = 0x172442D7;
    ctx->h[3] = 0xDA8A0600;
    ctx->h[4] = 0xA96F30BC;
    ctx->h[5] = 0x163138AA;
    ctx->h[6] = 0xE38DEE4D;
    ctx->h[7] = 0xB0FB0E4E;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM3_InitEx(CRYPT_SM3_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_SM3_Init(ctx);
}

int32_t CRYPT_SM3_Deinit(CRYPT_SM3_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)memset_s(ctx, sizeof(CRYPT_SM3_Ctx), 0, sizeof(CRYPT_SM3_Ctx));
    return CRYPT_SUCCESS;
}

static uint32_t IsInputOverflow(CRYPT_SM3_Ctx *ctx, uint32_t nbytes)
{
    uint32_t cnt0 = ctx->lNum + (nbytes << SHIFTS_PER_BYTE);
    if (cnt0 < ctx->lNum) {
        if (++ctx->hNum == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_SM3_INPUT_OVERFLOW);
            return CRYPT_SM3_INPUT_OVERFLOW;
        }
    }
    uint32_t cnt1 = ctx->hNum + (uint32_t)(nbytes >> (BITSIZE(uint32_t) - SHIFTS_PER_BYTE));
    if (cnt1 < ctx->hNum) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM3_INPUT_OVERFLOW);
        return CRYPT_SM3_INPUT_OVERFLOW;
    }
    ctx->hNum = cnt1;
    ctx->lNum = cnt0;
    return CRYPT_SUCCESS;
}

static int32_t IsUpdateParamValid(CRYPT_SM3_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if ((ctx == NULL) || (in == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (IsInputOverflow(ctx, len) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM3_INPUT_OVERFLOW);
        return CRYPT_SM3_INPUT_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM3_Update(CRYPT_SM3_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    int32_t ret = IsUpdateParamValid(ctx, in, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (len == 0) {
        return CRYPT_SUCCESS;
    }

    const uint8_t *data = in;
    uint32_t dataLen = len;
    uint32_t left = CRYPT_SM3_BLOCKSIZE - ctx->num;

    if (ctx->num != 0) {
        if (dataLen < left) {
            (void)memcpy_s(ctx->block + ctx->num, left, data, dataLen);
            ctx->num += dataLen;
            return CRYPT_SUCCESS;
        }
        // When the external input data is greater than the remaining space of the block,
        // copy the data which is the same length as the remaining space.
        (void)memcpy_s(ctx->block + ctx->num, left, data, left);
        SM3_Compress(ctx->h, ctx->block, 1);
        dataLen -= left;
        data += left;
        ctx->num = 0;
    }

    uint32_t blockCnt = dataLen / CRYPT_SM3_BLOCKSIZE;
    if (blockCnt > 0) {
        SM3_Compress(ctx->h, data, blockCnt);
        blockCnt *= CRYPT_SM3_BLOCKSIZE;
        data += blockCnt;
        dataLen -= blockCnt;
    }

    if (dataLen != 0) {
        // copy the remaining data to the cache array
        (void)memcpy_s(ctx->block, CRYPT_SM3_BLOCKSIZE, data, dataLen);
        ctx->num = dataLen;
    }

    return CRYPT_SUCCESS;
}

static int32_t IsFinalParamValid(const CRYPT_SM3_Ctx *ctx, const uint8_t *out, const uint32_t *outLen)
{
    if ((ctx == NULL) || (out == NULL) || (outLen == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*outLen < CRYPT_SM3_DIGESTSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM3_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SM3_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM3_Final(CRYPT_SM3_Ctx *ctx, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = IsFinalParamValid(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->block[ctx->num++] = 0x80;  /* 0x80 means add '1' to the end of the message */
    uint8_t *block = ctx->block;
    uint32_t num = ctx->num;
    uint32_t left = CRYPT_SM3_BLOCKSIZE - num;
    if (left < 8) { /* less than 8 bytes which insufficient for storing data length data */
        (void)memset_s(block + num, left, 0, left);
        SM3_Compress(ctx->h, ctx->block, 1);
        num = 0;
        left = CRYPT_SM3_BLOCKSIZE;
    }
    (void)memset_s(block + num, left - 8, 0, left - 8);
    block += CRYPT_SM3_BLOCKSIZE - 8;
    PUT_UINT32_BE(ctx->hNum, block, 0);
    block += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->lNum, block, 0);
    SM3_Compress(ctx->h, ctx->block, 1);
    ctx->num = 0;

    PUT_UINT32_BE(ctx->h[0], out, 0);
    PUT_UINT32_BE(ctx->h[1], out, 4);
    PUT_UINT32_BE(ctx->h[2], out, 8);
    PUT_UINT32_BE(ctx->h[3], out, 12);
    PUT_UINT32_BE(ctx->h[4], out, 16);
    PUT_UINT32_BE(ctx->h[5], out, 20);
    PUT_UINT32_BE(ctx->h[6], out, 24);
    PUT_UINT32_BE(ctx->h[7], out, 28);
    *outLen = CRYPT_SM3_DIGESTSIZE;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM3_CopyCtx(CRYPT_SM3_Ctx *dst, const CRYPT_SM3_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy_s(dst, sizeof(CRYPT_SM3_Ctx), src, sizeof(CRYPT_SM3_Ctx));
    return CRYPT_SUCCESS;
}

CRYPT_SM3_Ctx *CRYPT_SM3_DupCtx(const CRYPT_SM3_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_SM3_Ctx *newCtx = CRYPT_SM3_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy_s(newCtx, sizeof(CRYPT_SM3_Ctx), src, sizeof(CRYPT_SM3_Ctx));
    return newCtx;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SM3_GetParam(CRYPT_SM3_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_SM3_DIGESTSIZE, CRYPT_SM3_BLOCKSIZE, param);
}
#endif // HITLS_CRYPTO_PROVIDER

#endif /* HITLS_CRYPTO_SM3 */
