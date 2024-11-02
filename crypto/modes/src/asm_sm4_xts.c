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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_XTS)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_errno.h"
#include "modes_local.h"
#include "crypt_modes_xts.h"

int32_t MODES_SM4_XTS_SetEncryptKey(MODES_CipherXTSCtx *ctx, const uint8_t *key, uint32_t len)
{
    return CRYPT_SM4_XTS_SetEncryptKey(ctx->ciphCtx, key, len);
}

int32_t MODES_SM4_XTS_SetDecryptKey(MODES_CipherXTSCtx *ctx, const uint8_t *key, uint32_t len)
{
    return CRYPT_SM4_XTS_SetDecryptKey(ctx->ciphCtx, key, len);
}

int32_t MODES_SM4_XTS_Encrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CRYPT_SM4_XTS_Encrypt(ctx->ciphCtx, in, out, len, ctx->tweak);
}

int32_t MODES_SM4_XTS_Decrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CRYPT_SM4_XTS_Decrypt(ctx->ciphCtx, in, out, len, ctx->tweak);
}

int32_t SM4_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODES_SM4_XTS_Encrypt : MODES_SM4_XTS_Decrypt, &modeCtx->xtsCtx,
        in, inLen, out, outLen);
}

int32_t SM4_XTS_InitCtx(MODES_XTS_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    int32_t ret;
    ret = MODES_XTS_CheckPara(key, keyLen, iv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (enc) {
        ret = MODES_SM4_XTS_SetEncryptKey(&modeCtx->xtsCtx, key, keyLen);
    } else {
        ret = MODES_SM4_XTS_SetDecryptKey(&modeCtx->xtsCtx, key, keyLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = MODES_XTS_SetIv(&modeCtx->xtsCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        MODES_XTS_DeInitCtx(modeCtx);
        return ret;
    }
    
    modeCtx->enc = enc;
    return ret;
}
#endif