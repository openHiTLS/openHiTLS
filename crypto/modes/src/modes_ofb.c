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
#ifdef HITLS_CRYPTO_OFB

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "modes_local.h"
#include "crypt_modes_ofb.h"

int32_t MODES_OFB_Crypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret;
    const uint8_t *input = in;
    uint32_t blockSize = ctx->blockSize;
    uint32_t left = len;
    uint8_t *output = out;
    uint32_t i;

    // If the remaining encrypted iv is not used up last time, use that part to perform XOR.
    while (left > 0 && ctx->offset > 0) {
        *(output++) = ctx->iv[ctx->offset] ^ *(input++);
        left--;
        ctx->offset = (ctx->offset + 1) % blockSize;
    }

    while (left > 0) {
        // Encrypt the IV.
        ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->iv, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (left >= blockSize) {
            DATA32_XOR(input, ctx->iv, output, blockSize);
            UPDATE_VALUES(left, input, output, blockSize);
        } else {
            for (i = 0; i < left; i++) {
                output[i] = input[i] ^ ctx->iv[i];
            }
            ctx->offset = (uint8_t)left;
            left = 0;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t MODES_OFB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    return MODES_CipherInitCtx(modeCtx, modeCtx->commonCtx.ciphMeth->setEncryptKey,
        modeCtx->commonCtx.ciphCtx, key, keyLen, iv, ivLen, enc);
}

int32_t MODES_OFB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(MODES_OFB_Crypt, &modeCtx->commonCtx,
        in, inLen, out, outLen);
}

int32_t MODES_OFB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    (void) modeCtx;
    (void) out;
    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_OFB_DeInitCtx(MODES_CipherCtx *modeCtx)
{
    return MODES_CipherDeInitCtx(modeCtx);
}

int32_t MODES_OFB_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen)
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

void MODES_OFB_FreeCtx(MODES_CipherCtx *modeCtx)
{
    MODES_CipherFreeCtx(modeCtx);
}

int32_t MODES_OFB_InitCtxEx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void) param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_SM4_OFB:
#ifdef HITLS_CRYPTO_SM4
            return SM4_OFB_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_OFB_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
    }
}

int32_t MODES_OFB_UpdateEx(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_SM4_OFB:
#ifdef HITLS_CRYPTO_SM4
            return SM4_OFB_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_OFB_Update(modeCtx, in, inLen, out, outLen);
    }
}

#endif // HITLS_CRYPTO_OFB