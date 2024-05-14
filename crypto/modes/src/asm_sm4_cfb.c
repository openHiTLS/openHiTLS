/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_CFB)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_errno.h"
#include "crypt_modes_cfb.h"

int32_t MODES_SM4_CFB_SetEncryptKey(MODE_CFB_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODES_SM4_SetEncryptKey(ctx->modeCtx, key, len);
}

int32_t MODES_SM4_CFB_SetDecryptKey(MODE_CFB_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODES_SM4_SetDecryptKey(ctx->modeCtx, key, len);
}

int32_t MODE_SM4_CFB_Encrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || ctx->modeCtx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->feedbackBits == 128) { // feedbackBits value of 128 has assembly optimizations
        return CRYPT_SM4_CFB_Encrypt(ctx->modeCtx->ciphCtx, in, out, len, ctx->modeCtx->iv, &ctx->modeCtx->offset);
    } else { // no assembly optimization
        return MODE_CFB_Encrypt(ctx, in, out, len);
    }
}

int32_t MODE_SM4_CFB_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || ctx->modeCtx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->feedbackBits == 128) { // feedbackBits value of 128 has assembly optimizations
        return CRYPT_SM4_CFB_Decrypt(ctx->modeCtx->ciphCtx, in, out, len, ctx->modeCtx->iv, &ctx->modeCtx->offset);
    } else { // no assembly optimization
        return MODE_CFB_Decrypt(ctx, in, out, len);
    }
}
#endif