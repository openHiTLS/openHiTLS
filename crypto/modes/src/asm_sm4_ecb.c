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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_ECB)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_errno.h"
#include "crypt_modes_ecb.h"
#include "modes_local.h"

int32_t MODE_SM4_ECB_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SM4_ECB_Encrypt(ctx->ciphCtx, in, out, len);
}

int32_t MODE_SM4_ECB_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SM4_ECB_Decrypt(ctx->ciphCtx, in, out, len);
}

int32_t SM4_ECB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    (void) iv;
    (void) ivLen;
    int32_t ret = enc ? MODES_SM4_SetEncryptKey(&modeCtx->commonCtx, key, keyLen) :
        MODES_SM4_SetDecryptKey(&modeCtx->commonCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    modeCtx->enc = enc;
    return ret;
}

int32_t SM4_ECB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherUpdate(modeCtx, modeCtx->enc ? MODE_SM4_ECB_Encrypt : MODE_SM4_ECB_Decrypt,
        in, inLen, out, outLen);
}

int32_t SM4_ECB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherFinal(modeCtx, modeCtx->enc ? MODE_SM4_ECB_Encrypt : MODE_SM4_ECB_Decrypt, out, outLen);
}

#endif