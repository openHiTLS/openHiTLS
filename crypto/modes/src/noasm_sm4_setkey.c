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
#ifdef HITLS_CRYPTO_SM4

#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_sm4.h"
#include "modes_local.h"

int32_t MODES_SetEncryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len)
{
    // The ctx and key have been checked at the EAL layer and will not be checked again here.
    // The keyMethod will support registration in the future. Therefore, this check is added.
    if (ctx->ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->ciphMeth->setEncryptKey(ctx->ciphCtx, key, len);
}

int32_t MODES_SetDecryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len)
{
    // The ctx and key have been checked at the EAL layer and will not be checked again here.
    // The keyMethod will support registration in the future. Therefore, this check is added.
    if (ctx->ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->ciphMeth->setDecryptKey(ctx->ciphCtx, key, len);
}

int32_t MODES_SM4_SetEncryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len)
{
    return MODES_SetEncryptKey(ctx, key, len);
}

int32_t MODES_SM4_SetDecryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len)
{
    return MODES_SetDecryptKey(ctx, key, len);
}

#endif // HITLS_CRYPTO_SM4
