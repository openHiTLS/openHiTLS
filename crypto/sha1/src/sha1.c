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
#ifdef HITLS_CRYPTO_SHA1

#include <stdlib.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "sha1_core.h"
#include "bsl_sal.h"
#include "crypt_sha1.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

CRYPT_SHA1_Ctx *CRYPT_SHA1_NewCtx(void)
{
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA1_Ctx));
}

CRYPT_SHA1_Ctx *CRYPT_SHA1_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    return BSL_SAL_Calloc(1, sizeof(CRYPT_SHA1_Ctx));
}

void CRYPT_SHA1_FreeCtx(CRYPT_SHA1_Ctx *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_SHA1_Ctx));
}

/* e767 is because H is defined in SHA1 and MD5.
But the both the macros are different. So masked
this error */

int32_t CRYPT_SHA1_Init(CRYPT_SHA1_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memset_s(ctx, sizeof(CRYPT_SHA1_Ctx), 0, sizeof(CRYPT_SHA1_Ctx));

    /**
     *  RFC3174 6.1 Initialize the H constants of the input ctx
     *  These constants are provided by the standard
     */
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xc3d2e1f0;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA1_InitEx(CRYPT_SHA1_Ctx *ctx, void *param)
{
    (void)param;
    return CRYPT_SHA1_Init(ctx);
}

int32_t CRYPT_SHA1_Deinit(CRYPT_SHA1_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_CleanseData((void *)(ctx), sizeof(CRYPT_SHA1_Ctx));
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA1_CopyCtx(CRYPT_SHA1_Ctx *dst, const CRYPT_SHA1_Ctx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memcpy_s(dst, sizeof(CRYPT_SHA1_Ctx), src, sizeof(CRYPT_SHA1_Ctx));
    return CRYPT_SUCCESS;
}

CRYPT_SHA1_Ctx *CRYPT_SHA1_DupCtx(const CRYPT_SHA1_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_SHA1_Ctx *newCtx = CRYPT_SHA1_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memcpy_s(newCtx, sizeof(CRYPT_SHA1_Ctx), src, sizeof(CRYPT_SHA1_Ctx));
    return newCtx;
}

static int32_t SHA1_CheckIsCorrupted(CRYPT_SHA1_Ctx *ctx, uint32_t textLen)
{
    uint32_t low = (ctx->lNum + (textLen << 3)) & 0xffffffffUL;
    if (low < ctx->lNum) { /* overflow */
        if (++ctx->hNum == 0) {
            ctx->errorCode = CRYPT_SHA1_INPUT_OVERFLOW;
            BSL_ERR_PUSH_ERROR(CRYPT_SHA1_INPUT_OVERFLOW);
            return CRYPT_SHA1_INPUT_OVERFLOW;
        }
    }
    uint32_t high = ctx->hNum + (uint32_t)(textLen >> (32 - 3));
    if (high < ctx->hNum) { /* overflow */
        ctx->errorCode = CRYPT_SHA1_INPUT_OVERFLOW;
        BSL_ERR_PUSH_ERROR(CRYPT_SHA1_INPUT_OVERFLOW);
        return CRYPT_SHA1_INPUT_OVERFLOW;
    }
    ctx->hNum = high;
    ctx->lNum = low;

    return CRYPT_SUCCESS;
}

static int32_t SHA1_UpdateParamIsValid(CRYPT_SHA1_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
{
    if ((ctx == NULL) || (data == NULL && nbytes != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->errorCode != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ctx->errorCode);
        return ctx->errorCode;
    }

    if (SHA1_CheckIsCorrupted(ctx, nbytes) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA1_INPUT_OVERFLOW);
        return CRYPT_SHA1_INPUT_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA1_Update(CRYPT_SHA1_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    int32_t ret = SHA1_UpdateParamIsValid(ctx, in, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const uint8_t *data = in;
    uint32_t dataLen = len;
    uint32_t start = ctx->count;
    uint32_t left = CRYPT_SHA1_BLOCKSIZE - start;

    /* Check whether the user input data and cached data can form a block. */
    if (dataLen < left) {
        (void)memcpy_s(&ctx->m[start], left, data, dataLen);
        ctx->count += dataLen;
        return CRYPT_SUCCESS;
    }

    /* Preferentially process the buf data and form a block with the user input data. */
    if (start != 0) {
        (void)memcpy_s(&ctx->m[start], left, data, left);
        (void)SHA1_Step(ctx->m, CRYPT_SHA1_BLOCKSIZE, ctx->h);
        dataLen -= left;
        data += left;
        ctx->count = 0;
    }

    /* Cyclically process the input data */
    data = SHA1_Step(data, dataLen, ctx->h);
    dataLen = len - (data - in);

    /* The remaining data is less than one block and stored in the buf. */
    if (dataLen != 0) {
        (void)memcpy_s(ctx->m, CRYPT_SHA1_BLOCKSIZE, data, dataLen);
        ctx->count = dataLen;
    }
    return CRYPT_SUCCESS;
}

static int32_t SHA1_FinalParamIsValid(const CRYPT_SHA1_Ctx *ctx, const uint8_t *out, const uint32_t *outLen)
{
    if ((ctx == NULL) || (out == NULL) || (outLen == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*outLen < CRYPT_SHA1_DIGESTSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SHA1_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SHA1_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    if (ctx->errorCode != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ctx->errorCode);
        return ctx->errorCode;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SHA1_Final(CRYPT_SHA1_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    int32_t ret = SHA1_FinalParamIsValid(ctx, out, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t padLen;
    uint32_t padPos;
    /* Add "1" to the end of the user data */
    ctx->m[ctx->count] = 0x80;
    ctx->count++;

    /* If here is one complete data block, one complete data block is processed first. */
    if (ctx->count == CRYPT_SHA1_BLOCKSIZE) {
        (void)SHA1_Step(ctx->m, CRYPT_SHA1_BLOCKSIZE, ctx->h);
        ctx->count = 0;
    }

    /* Calculate the padding position. */
    padPos = ctx->count;
    padLen = CRYPT_SHA1_BLOCKSIZE - padPos;

    if (padLen < 8) {   /* 64 bits (8 bytes) of 512 bits are reserved to pad "0" */
        (void)memset_s(&ctx->m[padPos], padLen, 0, padLen);
        padPos = 0;
        padLen = CRYPT_SHA1_BLOCKSIZE;
        (void)SHA1_Step(ctx->m, CRYPT_SHA1_BLOCKSIZE, ctx->h);
    }
    /* offset 8 bytes, reserved for storing the data length */
    (void)memset_s(&ctx->m[padPos], (padLen - 8), 0, (padLen - 8));
    PUT_UINT32_BE(ctx->hNum, ctx->m, 56);    /* The 56th byte starts to store the upper 32-bit data. */
    PUT_UINT32_BE(ctx->lNum, ctx->m, 60);    /* The 60th byte starts to store the lower 32-bit data. */
    (void)SHA1_Step(ctx->m, CRYPT_SHA1_BLOCKSIZE, ctx->h);

    PUT_UINT32_BE(ctx->h[0], out, 0);
    PUT_UINT32_BE(ctx->h[1], out, 4);
    PUT_UINT32_BE(ctx->h[2], out, 8);
    PUT_UINT32_BE(ctx->h[3], out, 12);
    PUT_UINT32_BE(ctx->h[4], out, 16);
    *len = CRYPT_SHA1_DIGESTSIZE;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SHA1_GetParam(CRYPT_SHA1_Ctx *ctx, BSL_Param *param)
{
    (void)ctx;
    return CRYPT_MdCommonGetParam(CRYPT_SHA1_DIGESTSIZE, CRYPT_SHA1_BLOCKSIZE, param);
}
#endif

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA1
