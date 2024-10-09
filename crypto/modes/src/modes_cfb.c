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
#ifdef HITLS_CRYPTO_CFB

#include <stdbool.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_modes.h"
#include "crypt_errno.h"
#include "crypt_modes_cfb.h"

int32_t MODE_CFB_InitCtx(MODE_CFB_Ctx *ctx, const EAL_CipherMethod *method)
{
    if (ctx == NULL || method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->modeCtx = BSL_SAL_Malloc(sizeof(MODE_CipherCtx));
    if (ctx->modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = MODE_InitCtx(ctx->modeCtx, method);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(ctx->modeCtx);
        return ret;
    }

    uint8_t blockBits = ctx->modeCtx->blockSize * 8;
    if (blockBits <= 128) {
        ctx->feedbackBits = blockBits;
    } else {
        ctx->feedbackBits = 128;
    }
    return CRYPT_SUCCESS;
}

void MODE_CFB_Clean(MODE_CFB_Ctx *ctx)
{
    if (ctx == NULL || ctx->modeCtx == NULL) {
        return;
    }
    MODE_Clean(ctx->modeCtx);
}

/* 8-bit | 64-bit | 128-bit CFB encryption. Here, len indicates the number of bytes to be processed. */
static int32_t MODE_CFB_BytesEncrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    const uint8_t *input = in;
    uint8_t *output = out;
    uint8_t *tmp = ctx->modeCtx->buf;
    uint32_t blockSize = ctx->modeCtx->blockSize;
    uint32_t feedbackBytes = ctx->feedbackBits >> 3;
    uint32_t left = len;
    uint32_t i, k;

    // If the remaining encryption iv is not used up last time, use that part to perform XOR.
    while (left > 0 && ctx->modeCtx->offset > 0) {
        ctx->modeCtx->iv[ctx->modeCtx->offset] ^= *(input++);
        *(output++) = ctx->modeCtx->iv[ctx->modeCtx->offset];
        left--;
        ctx->modeCtx->offset = (ctx->modeCtx->offset + 1) % blockSize;
    }

    while (left > 0) {
        // Encrypt the IV.
        int32_t ret = ctx->modeCtx->ciphMeth->encrypt(ctx->modeCtx->ciphCtx, ctx->modeCtx->iv, tmp, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        i = 0;

        // The first (blockSize - feedbackBytes) bytes are filled with the least significant bytes of the previous IV.
        if (blockSize - feedbackBytes > 0) {
            (void)memmove_s(&ctx->modeCtx->iv[0], blockSize, &ctx->modeCtx->iv[feedbackBytes],
                blockSize - feedbackBytes);
            i = blockSize - feedbackBytes;
        }

        // The input data is XORed with the encrypted IV, and the current ciphertext is sent to the next IV.
        if (left >= feedbackBytes) {
            // Enter the last feedbackBytes in ciphertext.
            for (k = 0; i < blockSize; i++, k++) {
                output[k] = input[k] ^ tmp[k];
                ctx->modeCtx->iv[i] = output[k];
            }
            UPDATE_VALUES(left, input, output, feedbackBytes);
        } else {
            // Enter the last feedbackBytes in ciphertext.
            // The cache with insufficient feedbackBytes is used to encrypt the IV.
            for (k = 0; k < left; k++) {
                output[k] = input[k] ^ tmp[k];
                ctx->modeCtx->iv[i++] = output[k];
            }

            while (i < blockSize) {
                ctx->modeCtx->iv[i++] = tmp[k++];
            }
            ctx->modeCtx->offset = (uint8_t)(blockSize - feedbackBytes + left);
            left = 0;
        }
    }

    return CRYPT_SUCCESS;
}

/* 8-bit | 64-bit | 128-bit CFB decryption. Here, len indicates the number of bytes to be processed. */
static int32_t MODE_CFB_BytesDecrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    const uint8_t *input = in;
    uint8_t *output = out;
    uint8_t *tmp = ctx->modeCtx->buf;
    uint32_t blockSize = ctx->modeCtx->blockSize;
    uint32_t feedbackBytes = ctx->feedbackBits >> 3;
    uint32_t left = len;
    uint32_t i, k;

    // If the remaining encryption iv is not used up last time, use that part to perform XOR.
    while (left > 0 && ctx->modeCtx->offset > 0) {
        uint8_t tmpInput = *input;      // To support the same address in and out
        *(output++) = ctx->modeCtx->iv[ctx->modeCtx->offset] ^ *(input++);
        ctx->modeCtx->iv[ctx->modeCtx->offset] = tmpInput;
        left--;
        ctx->modeCtx->offset = (ctx->modeCtx->offset + 1) % blockSize;
    }

    while (left > 0) {
        // Encrypt the IV.
        int32_t ret = ctx->modeCtx->ciphMeth->encrypt(ctx->modeCtx->ciphCtx, ctx->modeCtx->iv, tmp, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        i = 0;

        // The first (blockSize - feedbackBytes) bytes are filled with the least significant bytes of the previous IV.
        if (blockSize - feedbackBytes > 0) {
            (void)memmove_s(&ctx->modeCtx->iv[0], blockSize, &ctx->modeCtx->iv[feedbackBytes],
                blockSize - feedbackBytes);
            i = blockSize - feedbackBytes;
        }

        // The input data is XORed with the encrypted IV, and the current ciphertext is sent to the next IV.
        if (left >= feedbackBytes) {
            // Enter the last feedbackBytes in ciphertext.
            for (k = 0; i < blockSize; i++, k++) {
                ctx->modeCtx->iv[i] = input[k];
                output[k] = input[k] ^ tmp[k];
            }
            UPDATE_VALUES(left, input, output, feedbackBytes);
        } else {
            // Enter the last feedbackBytes in ciphertext.
            // The cache with insufficient feedbackBytes is used to encrypt the IV.
            for (k = 0; k < left; k++) {
                ctx->modeCtx->iv[i++] = input[k];
                output[k] = input[k] ^ tmp[k];
            }

            while (i < blockSize) {
                ctx->modeCtx->iv[i++] = tmp[k++];
            }
            ctx->modeCtx->offset = (uint8_t)(blockSize - feedbackBytes + left);
            left = 0;
        }
    }

    return CRYPT_SUCCESS;
}

static int32_t Cfb1Crypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, bool enc)
{
    int32_t ret;
    uint8_t *tmp = ctx->modeCtx->buf;
    uint32_t blockSize = ctx->modeCtx->blockSize;
    uint32_t i;

    // Encrypt the IV.
    ret = ctx->modeCtx->ciphMeth->encrypt(ctx->modeCtx->ciphCtx, ctx->modeCtx->iv, tmp, blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (i = 0; i < blockSize - 1; i++) {
        // All bytes are shifted left by one bit,
        // and the least significant bits are obtained by shifting right by 7 bits from the next byte.
        ctx->modeCtx->iv[i] = (ctx->modeCtx->iv[i] << 1) | (ctx->modeCtx->iv[i + 1] >> 7);
    }

    if (enc) {
        *out = tmp[0] ^ *in;
        // The last byte is shifted to the left by one bit and then filled in the ciphertext.
        // Shifted to the right by 7 bits to obtain the first bit of the byte.
        ctx->modeCtx->iv[i] = (ctx->modeCtx->iv[i] << 1) | (*out >> 7);
    } else {
        // The last byte is shifted to the left by one bit and then filled in the ciphertext.
        // Shifted to the right by 7 bits to obtain the first bit of the byte.
        ctx->modeCtx->iv[i] = (ctx->modeCtx->iv[i] << 1) | (*in >> 7);
        *out = tmp[0] ^ *in;
    }

    return CRYPT_SUCCESS;
}

/* 1-bit CFB. Here, len indicates the number of bits to be processed. */
int32_t MODE_CFB_BitCrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    int32_t ret;
    uint8_t tmp[2];
    uint32_t pos;
    for (uint32_t i = 0; i < len; i++) {
        // 7 - i % 8 is used to obtain the number of bits in the byte stream (high bit -> low bit).
        pos = 7 - i % 8;
        // Obtain the bits to be encrypted. 0x80 indicates a byte whose most significant bit is 1.
        tmp[0] = ((in[i / 8] & (1 << pos)) > 0) ? 0x80 : 0;
        ret = Cfb1Crypt(ctx, &tmp[0], &tmp[1], enc);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        // Divide by 8 to obtain the current byte position. Assign the out encryption bit to 0.
        out[i / 8] = out[i / 8] & ~(1u << pos);
        // Divide by 8 to obtain the current byte position. tmpOut[0] >> 7 to obtain the most significant bit.
        out[i / 8] |= (tmp[1] >> 7) << pos; // Assign the out encryption bit to the encrypted/decrypted value.
    }
    (void)memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
    return CRYPT_SUCCESS;
}

static int32_t CFB_Crypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    if (ctx == NULL || in == NULL || out == NULL || len == 0 || ctx->modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    switch (ctx->feedbackBits) {
        case 1:
            return MODE_CFB_BitCrypt(ctx, in, out, len * 8, enc);
        case 8:
        case 64:
        case 128:
            return enc ? MODE_CFB_BytesEncrypt(ctx, in, out, len) : MODE_CFB_BytesDecrypt(ctx, in, out, len);

        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_FEEDBACKSIZE);
            return CRYPT_MODES_ERR_FEEDBACKSIZE;
    }
}

int32_t MODE_CFB_Encrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CFB_Crypt(ctx, in, out, len, true);
}

int32_t MODE_CFB_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CFB_Crypt(ctx, in, out, len, false);
}

static int32_t SetIv(MODE_CFB_Ctx *ctx, uint8_t *val, uint32_t len)
{
    int32_t ret = MODE_SetIv(ctx->modeCtx, val, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

static int32_t SetFeedbackSize(MODE_CFB_Ctx *ctx, const uint32_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    if (ctx->modeCtx->algId == CRYPT_SYM_SM4 && *val != 128) { // sm4 set 128 feedbackbits only
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_FEEDBACKSIZE_NOT_SUPPORT);
        return CRYPT_MODES_FEEDBACKSIZE_NOT_SUPPORT;
    }
    if (*val != 1 && *val != 8 && *val != 128) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_FEEDBACKSIZE);
        return CRYPT_MODES_ERR_FEEDBACKSIZE;
    }

    if (*val > (uint32_t)(ctx->modeCtx->blockSize * 8)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_FEEDBACKSIZE);
        return CRYPT_MODES_ERR_FEEDBACKSIZE;
    }
    ctx->feedbackBits = (uint8_t)*val;
    return CRYPT_SUCCESS;
}

static int32_t GetFeedbackSize(MODE_CFB_Ctx *ctx, uint32_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    *val = ctx->feedbackBits;
    return CRYPT_SUCCESS;
}

int32_t MODE_CFB_Ctrl(MODE_CFB_Ctx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL || ctx->modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    switch (opt) {
        case CRYPT_CTRL_SET_IV:
            return SetIv(ctx, (uint8_t *)val, len);
        case CRYPT_CTRL_GET_IV:
            return MODE_GetIv(ctx->modeCtx, (uint8_t *)val, len);
        case CRYPT_CTRL_SET_FEEDBACKSIZE:
            return SetFeedbackSize(ctx, (uint32_t *)val, len);
        case CRYPT_CTRL_GET_FEEDBACKSIZE:
            return GetFeedbackSize(ctx, (uint32_t *)val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_METHODS_NOT_SUPPORT);
            return CRYPT_MODES_METHODS_NOT_SUPPORT;
    }
}

int32_t MODE_CFB_SetEncryptKey(MODE_CFB_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || ctx->modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODE_SetEncryptKey(ctx->modeCtx, key, len);
}

void MODE_CFB_DeInitCtx(MODE_CFB_Ctx *ctx)
{
    if (ctx == NULL || ctx->modeCtx == NULL) {
        return;
    }
    MODE_DeInitCtx(ctx->modeCtx);
    BSL_SAL_FREE(ctx->modeCtx);
}
#endif