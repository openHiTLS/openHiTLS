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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CTR)

#include "bsl_err_internal.h"
#include "crypt_aes.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_modes_ctr.h"
#include "modes_local.h"

int32_t AES_CTR_EncryptBlock(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    // The ctx, in, and out pointers have been determined at the EAL layer and are not determined again.
    if (ctx->ciphCtx == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t left = len;
    const uint8_t *tmpIn = in;
    uint8_t *tmpOut = out;
    while ((ctx->offset != 0) && (left > 0)) {
        *(tmpOut++) = ((*(tmpIn++)) ^ (ctx->buf[ctx->offset++]));
        --left;
        ctx->offset &= (uint8_t)(ctx->blockSize - 1);
    }

    uint32_t blockSize = ctx->blockSize; // ctr supports only 16-byte block size
    uint32_t blocks, beCtr32;
    while (left >= blockSize) {
        blocks = left >> 4; // Shift rightwards by 4 bytes to obtain the number of blocks.
        beCtr32 = GET_UINT32_BE(ctx->iv, 12); // offset of 12 bytes, it is used to obtain the lower 32 bits of IV
        beCtr32 += blocks;
        if (beCtr32 < blocks) {
            blocks -= beCtr32;
            beCtr32 = 0;
        }
        // Shift leftwards by 4 bytes to obtain the length of the data involved in the calculation.
        uint32_t calLen = blocks << 4;
        (void)CRYPT_AES_CTR_Encrypt(ctx->ciphCtx, tmpIn, tmpOut, calLen, ctx->iv);
        left -= calLen;
        tmpIn += calLen;
        tmpOut += calLen;
        if (beCtr32 == 0) {
            // 16 - 4, the lower 32 bits are carried, and the upper 12 bytes are increased by 1.
            MODE_IncCounter(ctx->iv, blockSize - 4);
        }
    }
    if (left > 0) {
        (void)ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->buf, blockSize);
        MODE_IncCounter(ctx->iv, ctx->blockSize);
        ctx->offset = 0;
        while ((left) > 0) {
            tmpOut[ctx->offset] = (tmpIn[ctx->offset]) ^ (ctx->buf[ctx->offset]);
            --left;
            ++ctx->offset;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t AES_CTR_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(AES_CTR_EncryptBlock, &modeCtx->commonCtx, in, inLen, out, outLen);
}
#endif