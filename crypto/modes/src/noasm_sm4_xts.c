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
#include "crypt_modes_xts.h"

void MODES_SM4_XTS_Clean(MODE_XTS_Ctx *ctx)
{
    MODE_XTS_Clean(ctx);
}

int32_t MODES_SM4_XTS_SetEncryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    return MODE_XTS_SetEncryptKey(ctx, key, len);
}

int32_t MODES_SM4_XTS_SetDecryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    return MODE_XTS_SetDecryptKey(ctx, key, len);
}

int32_t MODES_SM4_XTS_Encrypt(MODE_XTS_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODE_XTS_Encrypt(ctx, in, out, len);
}

int32_t MODES_SM4_XTS_Decrypt(MODE_XTS_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODE_XTS_Decrypt(ctx, in, out, len);
}
#endif