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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_CFB)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_modes.h"
#include "crypt_modes_cfb.h"

int32_t MODES_SM4_CFB_SetEncryptKey(MODE_CFB_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    return MODE_SetEncryptKey(ctx->modeCtx, key, len);
}

int32_t MODE_SM4_CFB_Encrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_CFB_Encrypt(ctx, in, out, len);
}

int32_t MODE_SM4_CFB_Decrypt(MODE_CFB_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_CFB_Decrypt(ctx, in, out, len);
}
#endif
