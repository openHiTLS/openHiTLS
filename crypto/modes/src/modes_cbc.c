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
#ifdef HITLS_CRYPTO_CBC

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_cbc.h"
#include "modes_local.h"

#define CBC_UPDATE_VALUES(l, i, o, len) \
    do { \
        (l) -= (len); \
        (i) += (len); \
        (o) += (len); \
    } while (false)


int32_t MODES_CBC_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    uint32_t blockSize = ctx->blockSize;
    int32_t ret;
    uint8_t *iv = ctx->iv;
    uint8_t *tmp = ctx->buf;
    uint32_t left = len;
    const uint8_t *input = in;
    uint8_t *output = out;
    // The ctx, in, and out pointers have been determined at the EAL layer and are not determined again.
    if ((left % blockSize) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }

    while (left >= blockSize) {
        /* Plaintext XOR IV. BlockSize must be an integer multiple of 4 bytes. */
        DATA32_XOR(input, iv, tmp, blockSize);

        ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, tmp, output, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        /* The current encryption result is used as the next IV value. */
        iv = output;

        /* Offset length is the size of integer multiple blocks */
        CBC_UPDATE_VALUES(left, input, output, blockSize);
    }

    if (memcpy_s(ctx->iv, MODES_MAX_IV_LENGTH, iv, blockSize) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }

    return CRYPT_SUCCESS;
}

int32_t MODES_CBC_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const uint8_t *iv = ctx->iv;
    uint8_t *tmp = ctx->buf;
    uint32_t blockSize = ctx->blockSize;
    uint32_t left = len;
    uint8_t *output = out;
    uint8_t tmpChar;
    const uint8_t *input = in;

    // The ctx, in, and out pointers have been determined at the EAL layer and are not determined again.
    RETURN_RET_IF((left % blockSize) != 0, CRYPT_MODE_ERR_INPUT_LEN);

    // In the case where the input and output are at the same address,
    // the judgment should be placed outside the while loop. Otherwise, the performance will be affected.
    if (in != out) {
        while (left >= blockSize) {
            int32_t ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, input, tmp, blockSize);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            /* The ciphertext is used as the next IV value. BlockSize must be an integer multiple of 4 bytes. */
            DATA32_XOR(iv, tmp, output, blockSize);
            iv = input;

            CBC_UPDATE_VALUES(left, input, output, blockSize);
        }
        if (iv != ctx->iv) {
            (void)memcpy_s(ctx->iv, MODES_MAX_IV_LENGTH, iv, blockSize);
        }
    } else {
        while (left >= blockSize) {
            int32_t ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, input, tmp, blockSize);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }

            for (uint32_t i = 0; i < blockSize; i++) {
                tmpChar = input[i];
                output[i] = tmp[i] ^ ctx->iv[i];
                ctx->iv[i] = tmpChar;
            }

            CBC_UPDATE_VALUES(left, input, output, blockSize);
        }
    }

    return CRYPT_SUCCESS;
}

int32_t MODES_CBC_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    void *setKeyFuncs = enc ? modeCtx->commonCtx.ciphMeth->setEncryptKey : modeCtx->commonCtx.ciphMeth->setDecryptKey;
    return MODES_CipherInitCtx(modeCtx, setKeyFuncs, modeCtx->commonCtx.ciphCtx, key, keyLen, iv, ivLen, enc);
}

int32_t MODES_CBC_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherUpdate(modeCtx, modeCtx->enc ? MODES_CBC_Encrypt : MODES_CBC_Decrypt,
        in, inLen, out, outLen);
}

int32_t MODES_CBC_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherFinal(modeCtx, modeCtx->enc ? MODES_CBC_Encrypt : MODES_CBC_Decrypt, out, outLen);
}

int32_t MODES_CBC_DeInitCtx(MODES_CipherCtx *modeCtx)
{
    return MODES_CipherDeInitCtx(modeCtx);
}

int32_t MODES_CBC_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    int32_t ret;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    switch (cmd) {
        case CRYPT_CTRL_SET_PADDING:
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
                BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
                return CRYPT_MODE_ERR_INPUT_LEN;
            }
            *(int32_t *)val = modeCtx->commonCtx.ciphMeth->blockSize;
            return CRYPT_SUCCESS;
        default:
            return MODES_CipherCtrl(modeCtx, cmd, val, valLen);
    }
}

void MODES_CBC_FreeCtx(MODES_CipherCtx *modeCtx)
{
    MODES_CipherFreeCtx(modeCtx);
}

int32_t MODES_CBC_UpdateEx(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES256_CBC:
#ifdef HITLS_CRYPTO_AES
            return AES_CBC_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        case CRYPT_CIPHER_SM4_CBC:
#ifdef HITLS_CRYPTO_SM4
            return SM4_CBC_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_CBC_Update(modeCtx, in, inLen, out, outLen);
    }
}
int32_t MODES_CBC_InitCtxEx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_SM4_CBC:
#ifdef HITLS_CRYPTO_SM4
            return SM4_CBC_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_CBC_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
    }
}

int32_t MODES_CBC_FinalEx(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES256_CBC:
#ifdef HITLS_CRYPTO_AES
            return AES_CBC_Final(modeCtx, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        case CRYPT_CIPHER_SM4_CBC:
#ifdef HITLS_CRYPTO_SM4
            return SM4_CBC_Final(modeCtx, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_CBC_Final(modeCtx, out, outLen);
    }
}

#endif // HITLS_CRYPTO_CBC
