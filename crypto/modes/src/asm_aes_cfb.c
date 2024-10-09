/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CFB)

#include "bsl_err_internal.h"
#include "crypt_aes.h"
#include "crypt_errno.h"
#include "crypt_modes_cfb.h"

/* Decrypt the 128-bit CFB. Here, len indicates the number of bytes to be processed. */
static int32_t CRYPT_AES_CFB16_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx->modeCtx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const uint8_t *input = in;
    uint8_t *output = out;
    uint8_t *tmp = ctx->modeCtx->buf;
    uint32_t blockSize = ctx->modeCtx->blockSize;
    uint32_t left = len;
    uint32_t i, k;

    // If the remaining encryption iv is not used up last time, use the part to perform exclusive OR.
    while (left > 0 && ctx->modeCtx->offset > 0) {
        uint8_t tmpInput = *input; // To support the same address in and out
        *(output++) = ctx->modeCtx->iv[ctx->modeCtx->offset] ^ *(input++);
        // Write the iv to ciphertext to prepare for the next round of encryption.
        ctx->modeCtx->iv[ctx->modeCtx->offset] = tmpInput;
        ctx->modeCtx->offset = (ctx->modeCtx->offset + 1) % blockSize;
        left--;
    }

    if (left >= blockSize) {
        uint32_t processedLen = left - (left % blockSize);
        (void)CRYPT_AES_CFB_Decrypt(ctx->modeCtx->ciphCtx, input, output, processedLen, ctx->modeCtx->iv);
        UPDATE_VALUES(left, input, output, processedLen);
    }
    
    if (left > 0) {
        // encrypt the IV
        int32_t ret = ctx->modeCtx->ciphMeth->encrypt(ctx->modeCtx->ciphCtx, ctx->modeCtx->iv, tmp, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        for (i = 0, k = 0; k < left; k++, i++) {
            // Write the iv to ciphertext to prepare for the next round of encryption.
            ctx->modeCtx->iv[i] = input[k];
            output[k] = input[k] ^ tmp[k];
        }

        while (i < blockSize) {
            ctx->modeCtx->iv[i++] = tmp[k++];
        }
        ctx->modeCtx->offset = (uint8_t)left;
    }
    return CRYPT_SUCCESS;
}

int32_t MODE_AES_CFB_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || ctx->modeCtx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->feedbackBits == 128) { // feedbackBits 128 has assembly optimization
        return CRYPT_AES_CFB16_Decrypt(ctx, in, out, len);
    } else { // no optimization
        return MODE_CFB_Decrypt(ctx, in, out, len);
    }
}
#endif