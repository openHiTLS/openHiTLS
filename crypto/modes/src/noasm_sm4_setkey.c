/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_modes.h"

int32_t MODES_SM4_SetEncryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len)
{
    return MODE_SetEncryptKey(ctx, key, len);
}

int32_t MODES_SM4_SetDecryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len)
{
    return MODE_SetDecryptKey(ctx, key, len);
}

#endif // HITLS_CRYPTO_SM4
