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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_CBC)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_errno.h"
#include "crypt_modes_cbc.h"
#include "modes_local.h"

int32_t MODE_SM4_CBC_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SM4_CBC_Encrypt(ctx->ciphCtx, in, out, len, ctx->iv);
}

int32_t MODE_SM4_CBC_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SM4_CBC_Decrypt(ctx->ciphCtx, in, out, len, ctx->iv);
}

int32_t SM4_CBC_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherUpdate(modeCtx, modeCtx->enc ? MODE_SM4_CBC_Encrypt : MODE_SM4_CBC_Decrypt,
        in, inLen, out, outLen);
}

int32_t SM4_CBC_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherFinal(modeCtx, modeCtx->enc ? MODE_SM4_CBC_Encrypt : MODE_SM4_CBC_Decrypt, out, outLen);
}

int32_t SM4_CBC_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    void *setKey = enc ? MODES_SM4_SetEncryptKey : MODES_SM4_SetDecryptKey;
    return MODES_CipherInitCtx(modeCtx, setKey, &modeCtx->commonCtx, key, keyLen, iv, ivLen, enc);
}

#endif