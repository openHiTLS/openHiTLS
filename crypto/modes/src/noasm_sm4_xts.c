/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_XTS)

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_errno.h"
#include "crypt_modes_xts.h"

void MODES_SM4_XTS_Clean(MODE_XTS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    MODE_XTS_Clean(ctx);
}

int32_t MODES_SM4_XTS_SetEncryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODE_XTS_SetEncryptKey(ctx, key, len);
}

int32_t MODES_SM4_XTS_SetDecryptKey(MODE_XTS_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
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