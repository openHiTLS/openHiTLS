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


int32_t MODE_ECB_Crypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    // ctx, in, out, these pointer have been judged at the EAL layer and is not judged again here.
    if (ctx->ciphCtx == NULL || len == 0) {
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
            ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, input, output, blockSize);
        } else {
            ret = ctx->ciphMeth->decrypt(ctx->ciphCtx, input, output, blockSize);
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

int32_t MODE_ECB_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_ECB_Crypt(ctx, in, out, len, true);
}

int32_t MODE_ECB_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_ECB_Crypt(ctx, in, out, len, false);
}

void MODE_ECB_Clean(MODE_CipherCtx *ctx)
{
    if (ctx != NULL && ctx->ciphMeth != NULL && ctx->ciphMeth->clean != NULL) {
        ctx->ciphMeth->clean(ctx->ciphCtx);
    }
}

int32_t MODE_ECB_Ctrl(MODE_CipherCtx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return MODE_DefaultCtrl(ctx, opt, val, len);
}
#endif  // end HITLS_CRYPTO_ECB
