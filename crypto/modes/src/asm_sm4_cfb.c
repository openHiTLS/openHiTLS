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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_CFB)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_errno.h"
#include "crypt_modes_cfb.h"
#include "modes_local.h"
#include "securec.h"

int32_t MODE_SM4_CFB_Encrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->feedbackBits == 128) { // feedbackBits value of 128 has assembly optimizations
        return CRYPT_SM4_CFB_Encrypt(ctx->modeCtx.ciphCtx, in, out, len, ctx->modeCtx.iv, &ctx->modeCtx.offset);
    } else { // no assembly optimization
        return MODES_CFB_Encrypt(ctx, in, out, len);
    }
}

int32_t MODE_SM4_CFB_Decrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->feedbackBits == 128) { // feedbackBits value of 128 has assembly optimizations
        return CRYPT_SM4_CFB_Decrypt(ctx->modeCtx.ciphCtx, in, out, len, ctx->modeCtx.iv, &ctx->modeCtx.offset);
    } else { // no assembly optimization
        return MODES_CFB_Decrypt(ctx, in, out, len);
    }
}

int32_t SM4_CFB_InitCtx(MODES_CFB_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    int32_t ret;
    if (ivLen != modeCtx->cfbCtx.modeCtx.blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }

    ret = CRYPT_SM4_SetEncryptKey(modeCtx->cfbCtx.modeCtx.ciphCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    (void)memcpy_s(modeCtx->cfbCtx.modeCtx.iv, MODES_MAX_IV_LENGTH, iv, ivLen);
    modeCtx->enc = enc;
    return ret;
}

int32_t SM4_CFB_Update(MODES_CFB_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODE_SM4_CFB_Encrypt : MODE_SM4_CFB_Decrypt, &modeCtx->cfbCtx,
        in, inLen, out, outLen);
}
#endif