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
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_ctr.h"
#include "modes_local.h"

uint32_t MODES_CTR_LastHandle(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
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

void MODES_CTR_RemHandle(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
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
    (void)ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->buf, blockSize);
    MODE_IncCounter(ctx->iv, ctx->blockSize);
    ctx->offset = 0;
    while ((left) > 0) {
        tmpOut[ctx->offset] = (tmpIn[ctx->offset]) ^ (ctx->buf[ctx->offset]);
        --left;
        ++ctx->offset;
    }
}

int32_t MODES_CTR_Crypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    uint32_t offset = MODES_CTR_LastHandle(ctx, in, out, len);
    uint32_t left = len - offset;
    const uint8_t *tmpIn = in + offset;
    uint8_t *tmpOut = out + offset;
    uint32_t blockSize = ctx->blockSize;

    while (left >= blockSize) {
        // Ensure that the length of IV is 16 when setting it, which will not cause encryption failures.
        // To optimize performance, the function does not determine the length of the IV.
        (void)ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->buf, blockSize);
        MODE_IncCounter(ctx->iv, ctx->blockSize);
        DATA64_XOR(tmpIn, ctx->buf, tmpOut, blockSize);
        left -= blockSize;
        tmpOut += blockSize;
        tmpIn += blockSize;
    }

    MODES_CTR_RemHandle(ctx, tmpIn, tmpOut, left);

    return CRYPT_SUCCESS;
}

int32_t MODES_CTR_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    return MODES_CipherInitCtx(modeCtx, modeCtx->commonCtx.ciphMeth->setEncryptKey,
        modeCtx->commonCtx.ciphCtx, key, keyLen, iv, ivLen, enc);
}

int32_t MODES_CTR_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(MODES_CTR_Crypt, &modeCtx->commonCtx, in, inLen, out, outLen);
}

int32_t MODES_CTR_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    (void) modeCtx;
    (void) out;
    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_CTR_DeInitCtx(MODES_CipherCtx *modeCtx)
{
    return MODES_CipherDeInitCtx(modeCtx);
}

int32_t MODES_CTR_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || valLen != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = 1;
            return CRYPT_SUCCESS;
        default:
            return MODES_CipherCtrl(modeCtx, cmd, val, valLen);;
    }
}


void MODES_CTR_FreeCtx(MODES_CipherCtx *modeCtx)
{
    MODES_CipherFreeCtx(modeCtx);
}

int32_t MODES_CTR_InitCtxEx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_SM4_CTR:
#ifdef HITLS_CRYPTO_SM4
            return SM4_CTR_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_CTR_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
    }
}

int32_t MODES_CTR_UpdateEx(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES192_CTR:
        case CRYPT_CIPHER_AES256_CTR:
#ifdef HITLS_CRYPTO_AES
            return AES_CTR_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        case CRYPT_CIPHER_SM4_CTR:
#ifdef HITLS_CRYPTO_SM4
            return SM4_CTR_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_CTR_Update(modeCtx, in, inLen, out, outLen);
    }
}

#endif