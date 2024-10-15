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
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes.h"
#include "crypt_modes_ofb.h"

int32_t MODE_OFB_Crypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret;
    const uint8_t *input = in;
    uint8_t *tmp = ctx->buf;
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
        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->iv, tmp, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        // Update the IV.
        if (memcpy_s(ctx->iv, MODES_MAX_IV_LENGTH, tmp, blockSize) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }

        if (left >= blockSize) {
            /* Plaintext XOR IV. BlockSize must be an integer multiple of 4 bytes. */
            DATA32_XOR(input, tmp, output, blockSize);
            UPDATE_VALUES(left, input, output, blockSize);
        } else {
            for (i = 0; i < left; i++) {
                output[i] = input[i] ^ tmp[i];
            }
            ctx->offset = (uint8_t)left;
            left = 0;
        }
    }

    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_OFB