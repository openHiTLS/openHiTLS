/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_GCM)

#include "crypt_sm4.h"
#include "crypt_modes.h"
#include "crypt_modes_gcm.h"

int32_t MODES_SM4_GCM_SetKey(MODES_GCM_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    return MODES_GCM_SetKey(ctx, key, len);
}

int32_t MODES_SM4_GCM_EncryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_GCM_Encrypt(ctx, in, out, len);
}

int32_t MODES_SM4_GCM_DecryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_GCM_Decrypt(ctx, in, out, len);
}

#endif