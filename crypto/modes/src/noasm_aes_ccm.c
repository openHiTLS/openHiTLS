/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CCM)

#include "crypt_modes.h"
#include "crypt_modes_ccm.h"

int32_t MODES_AES_CCM_Encrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_CCM_Encrypt(ctx, in, out, len);
}

int32_t MODES_AES_CCM_Decrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_CCM_Decrypt(ctx, in, out, len);
}
#endif