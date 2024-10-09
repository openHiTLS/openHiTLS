/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_OFB)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_modes.h"
#include "crypt_modes_ofb.h"

int32_t MODE_SM4_OFB_Encrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_OFB_Crypt(ctx, in, out, len);
}

int32_t MODE_SM4_OFB_Decrypt(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODE_OFB_Crypt(ctx, in, out, len);
}

#endif
