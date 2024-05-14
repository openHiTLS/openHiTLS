/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CTR)

#include "bsl_err_internal.h"
#include "crypt_aes.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_modes_ctr.h"

int32_t AES_CTR_EncryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    // The ctx, in, and out pointers have been determined at the EAL layer and are not determined again.
    if (ctx->ciphCtx == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t offset = MODE_CTR_LastHandle(ctx, in, out, len);
    uint32_t left = len - offset;
    const uint8_t *tmpIn = in + offset;
    uint8_t *tmpOut = out + offset;

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
    MODE_CTR_RemHandle(ctx, tmpIn, tmpOut, left);
    return CRYPT_SUCCESS;
}

int32_t AES_CTR_DecryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return AES_CTR_EncryptBlock(ctx, in, out, len);
}
#endif