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
#ifdef HITLS_CRYPTO_MD5

#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "md5_core.h"
#include "crypt_md5.h"
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

CRYPT_MD5_Ctx *CRYPT_MD5_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_MD5_Ctx));
}

CRYPT_MD5_Ctx *CRYPT_MD5_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return BSL_SAL_Calloc(1, sizeof(CRYPT_MD5_Ctx));
}

void CRYPT_MD5_FreeCtx(CRYPT_MD5_Ctx *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_MD5_Ctx));
}

int32_t CRYPT_MD5_Init(CRYPT_MD5_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memset_s(ctx, sizeof(CRYPT_MD5_Ctx), 0, sizeof(CRYPT_MD5_Ctx));
    /* Set the initial values of A, B, C, and D according to step 3 in section 3.3 of RFC1321. */
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe;
    ctx->h[3] = 0x10325476;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_MD5_InitEx(CRYPT_MD5_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_MD5_Init(ctx);
}

int32_t CRYPT_MD5_Deinit(CRYPT_MD5_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)memset_s(ctx, sizeof(CRYPT_MD5_Ctx), 0, sizeof(CRYPT_MD5_Ctx));
    return CRYPT_SUCCESS;
}

static uint32_t IsInputOverflow(CRYPT_MD5_Ctx *ctx, uint32_t nbytes)
{
    uint32_t cnt0 = ctx->lNum + (nbytes << SHIFTS_PER_BYTE);
    if (cnt0 < ctx->lNum) {
        if (++ctx->hNum == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_MD_INPUT_OVERFLOW);
            return CRYPT_MD_INPUT_OVERFLOW;
        }
    }
    uint32_t cnt1 = ctx->hNum + (uint32_t)(nbytes >> (BITSIZE(uint32_t) - SHIFTS_PER_BYTE));
    if (cnt1 < ctx->hNum) {
        BSL_ERR_PUSH_ERROR(CRYPT_MD_INPUT_OVERFLOW);
        return CRYPT_MD_INPUT_OVERFLOW;
    }
    ctx->hNum = cnt1;
    ctx->lNum = cnt0;
    return CRYPT_SUCCESS;
}

static int32_t IsUpdateParamValid(CRYPT_MD5_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if ((ctx == NULL) || (in == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (IsInputOverflow(ctx, len) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MD_INPUT_OVERFLOW);
        return CRYPT_MD_INPUT_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_MD5_Update(CRYPT_MD5_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    int32_t ret = IsUpdateParamValid(ctx, in, len);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    if (len == 0) {
        return CRYPT_SUCCESS;
    }

    const uint8_t *data = in;
    uint32_t dataLen = len;
    uint32_t left = CRYPT_MD5_BLOCKSIZE - ctx->num;

    if (ctx->num != 0) {
        if (dataLen < left) {
            (void)memcpy_s(ctx->block + ctx->num, left, data, dataLen);
            ctx->num += dataLen;
            return CRYPT_SUCCESS;
        }
        // When the external input data is greater than the remaining space of the block,
        // copy the data which is the same length as the remaining space.
        (void)memcpy_s(ctx->block + ctx->num, left, data, left);
        MD5_Compress(ctx->h, ctx->block, 1);
        dataLen -= left;
        data += left;
        ctx->num = 0;
    }

    uint32_t blockCnt = dataLen / CRYPT_MD5_BLOCKSIZE;
    if (blockCnt > 0) {
        MD5_Compress(ctx->h, data, blockCnt);
        blockCnt *= CRYPT_MD5_BLOCKSIZE;
        data += blockCnt;
        dataLen -= blockCnt;
    }

    if (dataLen != 0) {
        // Copy the remaining data to the cache array.
        (void)memcpy_s(ctx->block, CRYPT_MD5_BLOCKSIZE, data, dataLen);
        ctx->num = dataLen;
    }

    return CRYPT_SUCCESS;
}

static int32_t IsFinalParamValid(const CRYPT_MD5_Ctx *ctx, const uint8_t *out, const uint32_t *outLen)
{
    if ((ctx == NULL) || (out == NULL) || (outLen == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*outLen < CRYPT_MD5_DIGESTSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    return CRYPT_SUCCESS;
}


int32_t CRYPT_MD5_Final(CRYPT_MD5_Ctx *ctx, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = IsFinalParamValid(ctx, out, outLen);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    ctx->block[ctx->num++] = 0x80;  /* 0x80 indicates that '1' is appended to the end of a message. */
    uint8_t *block = ctx->block;
    uint32_t num = ctx->num;
    uint32_t left = CRYPT_MD5_BLOCKSIZE - num;
    if (left < 8) { /* Less than 8 bytes, insufficient for storing data of the accumulated data length(lNum&hNum). */
        (void)memset_s(block + num, left, 0, left);
        MD5_Compress(ctx->h, ctx->block, 1);
        num = 0;
        left = CRYPT_MD5_BLOCKSIZE;
    }
    (void)memset_s(block + num, left - 8, 0, left - 8); /* 8 byte is used to store data of accumulated data length. */
    block += CRYPT_MD5_BLOCKSIZE - 8; /* 8 byte is used to store data of the accumulated data length(lNum&hNum). */
    PUT_UINT32_LE(ctx->lNum, block, 0);
    block += sizeof(uint32_t);
    PUT_UINT32_LE(ctx->hNum, block, 0);
    MD5_Compress(ctx->h, ctx->block, 1);
    ctx->num = 0;

    PUT_UINT32_LE(ctx->h[0], out, 0);
    PUT_UINT32_LE(ctx->h[1], out, 4);
    PUT_UINT32_LE(ctx->h[2], out, 8);
    PUT_UINT32_LE(ctx->h[3], out, 12);
    *outLen = CRYPT_MD5_DIGESTSIZE;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_MD5_CopyCtx(CRYPT_MD5_Ctx *dst, const CRYPT_MD5_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy_s(dst, sizeof(CRYPT_MD5_Ctx), src, sizeof(CRYPT_MD5_Ctx));
    return CRYPT_SUCCESS;
}

CRYPT_MD5_Ctx *CRYPT_MD5_DupCtx(const CRYPT_MD5_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_MD5_Ctx *newCtx = CRYPT_MD5_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy_s(newCtx, sizeof(CRYPT_MD5_Ctx), src, sizeof(CRYPT_MD5_Ctx));
    return newCtx;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_MD5_GetParam(CRYPT_MD5_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_MD5_DIGESTSIZE, CRYPT_MD5_BLOCKSIZE, param);
}
#endif

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // HITLS_CRYPTO_MD5
