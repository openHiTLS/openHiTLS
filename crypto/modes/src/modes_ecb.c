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
#ifdef HITLS_CRYPTO_ECB

#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_ecb.h"
#include "modes_local.h"
#include "securec.h"

static int32_t MODES_ECB_Crypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    // ctx, in, out, these pointer have been judged at the EAL layer and is not judged again here.
    if (ctx == NULL || ctx->ciphCtx == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    uint32_t left = len;
    const uint8_t *input = in;
    uint8_t *output = out;
    uint32_t blockSize = ctx->blockSize;

    while (left >= blockSize) {
        if (enc) {
            ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, input, output, blockSize);
        } else {
            ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, input, output, blockSize);
        }
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        input += blockSize;
        output += blockSize;
        left -= blockSize;
    }
    if (left > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_ECB_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_ECB_Crypt(ctx, in, out, len, true);
}

int32_t MODES_ECB_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_ECB_Crypt(ctx, in, out, len, false);
}

int32_t MODES_ECB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    (void)iv;
    (void)ivLen;
    int32_t ret = enc ? modeCtx->commonCtx.ciphMeth->setEncryptKey(modeCtx->commonCtx.ciphCtx, key, keyLen) :
        modeCtx->commonCtx.ciphMeth->setDecryptKey(modeCtx->commonCtx.ciphCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    modeCtx->enc = enc;
    return ret;
}

int32_t MODES_ECB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherUpdate(modeCtx, modeCtx->enc ? MODES_ECB_Encrypt : MODES_ECB_Decrypt,
        in, inLen, out, outLen);
}

int32_t MODES_ECB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherFinal(modeCtx, modeCtx->enc ? MODES_ECB_Encrypt : MODES_ECB_Decrypt, out, outLen);
}

int32_t MODES_ECB_DeinitCtx(MODES_CipherCtx *modeCtx)
{
    return MODES_CipherDeInitCtx(modeCtx);
}

int32_t MODES_ECB_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    int ret;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_REINIT_STATUS:
            (void)memset_s(modeCtx->data, EAL_MAX_BLOCK_LENGTH, 0, EAL_MAX_BLOCK_LENGTH);
            modeCtx->dataLen = 0;
            modeCtx->pad = CRYPT_PADDING_NONE;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_PADDING:
            if (modeCtx->commonCtx.blockSize == 1) {
                BSL_ERR_PUSH_ERROR(CRYPT_EAL_PADDING_NOT_SUPPORT);
                return CRYPT_EAL_PADDING_NOT_SUPPORT;
            }
            if (val == NULL || valLen != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ret = MODES_SetPaddingCheck(*(int32_t *)val);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            modeCtx->pad = *(int32_t *)val;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_PADDING:
            if (val == NULL || valLen != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = modeCtx->pad;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || valLen != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = modeCtx->commonCtx.ciphMeth->blockSize;
            return CRYPT_SUCCESS;
        default:
            return MODES_CipherCtrl(modeCtx, cmd, val, valLen);
    }
}

void MODES_ECB_FreeCtx(MODES_CipherCtx *modeCtx)
{
    MODES_CipherFreeCtx(modeCtx);
}

int32_t MODES_ECB_InitCtxEx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_SM4_ECB:
#ifdef HITLS_CRYPTO_SM4
            return SM4_ECB_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_ECB_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
    }
}

int32_t MODES_ECB_UpdateEx(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_AES128_ECB:
        case CRYPT_CIPHER_AES192_ECB:
        case CRYPT_CIPHER_AES256_ECB:
#ifdef HITLS_CRYPTO_AES
            return AES_ECB_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        case CRYPT_CIPHER_SM4_ECB:
#ifdef HITLS_CRYPTO_SM4
            return SM4_ECB_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_ECB_Update(modeCtx, in, inLen, out, outLen);
    }
}

int32_t MODES_ECB_FinalEx(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_AES128_ECB:
        case CRYPT_CIPHER_AES192_ECB:
        case CRYPT_CIPHER_AES256_ECB:
#ifdef HITLS_CRYPTO_AES
            return AES_ECB_Final(modeCtx, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        case CRYPT_CIPHER_SM4_ECB:
#ifdef HITLS_CRYPTO_SM4
            return SM4_ECB_Final(modeCtx, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_ECB_Final(modeCtx, out, outLen);
    }
}

#endif  // end HITLS_CRYPTO_ECB
