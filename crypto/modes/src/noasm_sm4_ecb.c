/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_ECB)

#include "crypt_modes_ecb.h"

int32_t SM4_ECB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    return MODES_ECB_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
}

int32_t SM4_ECB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_ECB_Update(modeCtx, in, inLen, out, outLen);
}

int32_t SM4_ECB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    return MODES_ECB_Final(modeCtx, out, outLen);
}

#endif
