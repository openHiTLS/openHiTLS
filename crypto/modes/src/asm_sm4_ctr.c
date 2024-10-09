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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_CTR)

#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_sm4.h"
#include "crypt_modes_ctr.h"

int32_t MODE_SM4_CTR_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t offset = MODE_CTR_LastHandle(ctx, in, out, len);
    uint32_t left = len - offset;
    const uint8_t *tmpIn = in + offset;
    uint8_t *tmpOut = out + offset;

    uint32_t blockSize = ctx->blockSize;
    uint32_t blocks, beCtr32;
    while (left >= blockSize) {
        blocks = left >> 4;
        beCtr32 = GET_UINT32_BE(ctx->iv, 12);
        beCtr32 += blocks;
        if (beCtr32 < blocks) {
            blocks -= beCtr32;
            beCtr32 = 0;
        }

        uint32_t calLen = blocks << 4;
        (void)CRYPT_SM4_CTR_Encrypt(ctx->ciphCtx, tmpIn, tmpOut, calLen / ctx->blockSize, ctx->iv);
        left -= calLen;
        tmpIn += calLen;
        tmpOut += calLen;
        if (beCtr32 == 0) {
            // 16 - 4, The lower 32 bits are carried, and the upper 12 bytes are increased by 1.
            MODE_IncCounter(ctx->iv, blockSize - 4);
        }
    }
    MODE_CTR_RemHandle(ctx, tmpIn, tmpOut, left);
    return CRYPT_SUCCESS;
}

int32_t MODE_SM4_CTR_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_SM4_CTR_Encrypt(ctx, in, out, len);
}
#endif