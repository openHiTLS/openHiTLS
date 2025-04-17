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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_XTS)
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_aes.h"
#include "crypt_modes_xts.h"
#include "modes_local.h"

int32_t MODES_AES_XTS_Encrypt(MODES_CipherXTSCtx *xtsCtx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (xtsCtx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len < xtsCtx->blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }

    (void)CRYPT_AES_XTS_Encrypt(xtsCtx->ciphCtx, in, out, len, xtsCtx->tweak);
    return CRYPT_SUCCESS;
}

int32_t MODES_AES_XTS_Decrypt(MODES_CipherXTSCtx *xtsCtx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (xtsCtx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len < xtsCtx->blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    (void)CRYPT_AES_XTS_Decrypt(xtsCtx->ciphCtx, in, out, len, xtsCtx->tweak);
    return CRYPT_SUCCESS;
}

int32_t AES_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODES_AES_XTS_Encrypt : MODES_AES_XTS_Decrypt, &modeCtx->xtsCtx,
        in, inLen, out, outLen);
}


#endif