/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MODES

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_modes.h"


int32_t MODE_InitCtx(MODE_CipherCtx *ctx, const EAL_CipherMethod *method)
{
    if (ctx == NULL || method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->ciphCtx = BSL_SAL_Malloc(method->ctxSize);
    if (ctx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(ctx->ciphCtx, method->ctxSize, 0, method->ctxSize);

    ctx->blockSize = method->blockSize;
    ctx->ciphMeth = method;
    ctx->algId = method->algId;
    ctx->offset = 0;

    return CRYPT_SUCCESS;
}

void MODE_DeInitCtx(MODE_CipherCtx *ctx)
{
    if (ctx == NULL || ctx->ciphMeth == NULL || ctx->ciphMeth->clean == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }

    ctx->ciphMeth->clean(ctx->ciphCtx);
    BSL_SAL_FREE(ctx->ciphCtx);
    ctx->ciphMeth = NULL;
}

int32_t MODE_SetEncryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len)
{
    // The ctx and key have been checked at the EAL layer and will not be checked again here.
    // The keyMethod will support registration in the future. Therefore, this check is added.
    if (ctx->ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->ciphMeth->setEncryptKey(ctx->ciphCtx, key, len);
}

int32_t MODE_SetDecryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len)
{
    // The ctx and key have been checked at the EAL layer and will not be checked again here.
    // The keyMethod will support registration in the future. Therefore, this check is added.
    if (ctx->ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->ciphMeth->setDecryptKey(ctx->ciphCtx, key, len);
}

int32_t MODE_SetIv(MODE_CipherCtx *ctx, uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len != ctx->blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }

    if (memcpy_s(ctx->iv, MODES_MAX_IV_LENGTH, (uint8_t*)val, len) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    ctx->offset = 0;    // If the IV value is changed, the original offset is useless.
    return CRYPT_SUCCESS;
}

int32_t MODE_GetIv(MODE_CipherCtx *ctx, uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t ivLen = ctx->blockSize;

    if (len != ivLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }

    if (memcpy_s(val, len, ctx->iv, ivLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t MODE_DefaultCtrl(MODE_CipherCtx *ctx, CRYPT_CipherCtrl opt, uint32_t *val, uint32_t len)
{
    if (ctx->ciphMeth == NULL || ctx->ciphMeth->ctrl == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TYPE_ERROR);
        return CRYPT_MODES_CTRL_TYPE_ERROR;
    }
    return ctx->ciphMeth->ctrl(ctx->ciphCtx, opt, val, len);
}

// support: finally do the MODE_DefaultCtrl, but not all MODEs have assembly optimizations
int32_t MODE_Ctrl(MODE_CipherCtx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    switch (opt) {
        case CRYPT_CTRL_SET_IV:
            return MODE_SetIv(ctx, (uint8_t *)val, len);
        case CRYPT_CTRL_GET_IV:
            return MODE_GetIv(ctx, (uint8_t *)val, len);
        default:
            return MODE_DefaultCtrl(ctx, opt, val, len);
    }
}

void MODE_Clean(MODE_CipherCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_CleanseData((void *)(ctx->buf), MODES_MAX_IV_LENGTH);
    BSL_SAL_CleanseData((void *)(ctx->iv), MODES_MAX_IV_LENGTH);
    ctx->ciphMeth->clean(ctx->ciphCtx);
    ctx->offset = 0;
}
#endif // HITLS_CRYPTO_MODES
