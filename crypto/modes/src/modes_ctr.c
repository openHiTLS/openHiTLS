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
#ifdef HITLS_CRYPTO_CTR

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes.h"
#include "crypt_modes_ctr.h"

void MODE_CTR_Clean(MODE_CipherCtx *ctx)
{
    MODE_Clean(ctx);
}

uint32_t MODE_CTR_LastHandle(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    uint32_t left = len;
    uint32_t blockSize = ctx->blockSize;
    const uint8_t *tmpIn = in;
    uint8_t *tmpOut = out;
    // buf[0, ctx->offset, blockSize)
    // The data from st to blockSize - 1 is the data obtained after the last encryption and is not used up.
    while ((ctx->offset != 0) && (left > 0)) {
        *(tmpOut++) = ((*(tmpIn++)) ^ (ctx->buf[ctx->offset++]));
        --left;
        // & (blockSize - 1) is equivalent to mod blockSize.
        ctx->offset &= (uint8_t)(blockSize - 1);
    }
    // Return the calculated length.
    return (len - left);
}

void MODE_CTR_RemHandle(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (len == 0) {
        return;
    }
    uint32_t left = len;
    uint32_t blockSize = ctx->blockSize;
    const uint8_t *tmpIn = in;
    uint8_t *tmpOut = out;
    // Ensure that the length of IV is 16 when setting it, which will not cause encryption failures.
    // To optimize performance, the function does not determine the length of the IV.
    (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->iv, ctx->buf, blockSize);
    MODE_IncCounter(ctx->iv, ctx->blockSize);
    ctx->offset = 0;
    while ((left) > 0) {
        tmpOut[ctx->offset] = (tmpIn[ctx->offset]) ^ (ctx->buf[ctx->offset]);
        --left;
        ++ctx->offset;
    }
}

int32_t MODE_CTR_Crypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    // The ctx, in, and out pointers have been determined at the EAL layer and are not determined again.
    if (len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t offset = MODE_CTR_LastHandle(ctx, in, out, len);
    uint32_t left = len - offset;
    const uint8_t *tmpIn = in + offset;
    uint8_t *tmpOut = out + offset;
    uint32_t blockSize = ctx->blockSize;

    while (left >= blockSize) {
        // Ensure that the length of IV is 16 when setting it, which will not cause encryption failures.
        // To optimize performance, the function does not determine the length of the IV.
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->iv, ctx->buf, blockSize);
        MODE_IncCounter(ctx->iv, ctx->blockSize);
        DATA64_XOR(tmpIn, ctx->buf, tmpOut, blockSize);
        left -= blockSize;
        tmpOut += blockSize;
        tmpIn += blockSize;
    }

    MODE_CTR_RemHandle(ctx, tmpIn, tmpOut, left);

    return CRYPT_SUCCESS;
}
#endif