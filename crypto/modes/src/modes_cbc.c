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
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes.h"
#include "crypt_modes_cbc.h"

#define CBC_UPDATE_VALUES(l, i, o, len) \
    do { \
        (l) -= (len); \
        (i) += (len); \
        (o) += (len); \
    } while (false)

int32_t MODE_CBC_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
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

        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, tmp, output, blockSize);
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
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_SECUREC_FAIL;
    }

    return CRYPT_SUCCESS;
}

int32_t MODE_CBC_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    const uint8_t *iv = ctx->iv;
    uint8_t *tmp = ctx->buf;
    uint32_t blockSize = ctx->blockSize;
    uint32_t left = len;
    uint8_t *output = out;
    uint8_t tmpChar;
    const uint8_t *input = in;

    // The ctx, in, and out pointers have been determined at the EAL layer and are not determined again.
    if ((left % blockSize) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }

    // In the case where the input and output are at the same address,
    // the judgment should be placed outside the while loop. Otherwise, the performance will be affected.
    if (in != out) {
        while (left >= blockSize) {
            int32_t ret = ctx->ciphMeth->decrypt(ctx->ciphCtx, input, tmp, blockSize);
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
            int32_t ret = ctx->ciphMeth->decrypt(ctx->ciphCtx, input, tmp, blockSize);
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

void MODE_CBC_Clean(MODE_CipherCtx *ctx)
{
    MODE_Clean(ctx);
}
#endif // HITLS_CRYPTO_CBC
