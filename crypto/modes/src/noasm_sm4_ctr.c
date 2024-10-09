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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_CTR)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_modes.h"
#include "crypt_modes_ctr.h"

int32_t MODE_SM4_CTR_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_CTR_Crypt(ctx, in, out, len);
}

int32_t MODE_SM4_CTR_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_CTR_Crypt(ctx, in, out, len);
}
#endif
