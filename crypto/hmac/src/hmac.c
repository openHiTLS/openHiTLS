/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HMAC

#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_hmac.h"

uint32_t CRYPT_HMAC_GetMacLen(const CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return ctx->method->mdSize;
}

int32_t CRYPT_HMAC_InitCtx(CRYPT_HMAC_Ctx *ctx, const EAL_MdMethod *m)
{
    if (ctx == NULL || m == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    void *mdCtx = (void *)BSL_SAL_Malloc(m->ctxSize * 3); // 3 contexts including mdCtx, iCtx, oCtx
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // clear 3 contexts including mdCtx, iCtx, oCtx
    (void)memset_s(mdCtx, m->ctxSize * 3, 0, m->ctxSize * 3);

    ctx->mdCtx = mdCtx;
    ctx->iCtx = (void *)((uint8_t *)mdCtx + m->ctxSize);
    // offset 2 ctxSize: (mdCtx, iCtx)
    ctx->oCtx = (void *)((uint8_t *)mdCtx + m->ctxSize * 2);
    ctx->method = m;

    return CRYPT_SUCCESS;
}

void CRYPT_HMAC_DeinitCtx(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    const EAL_MdMethod *method = ctx->method;
    // clear 3 contexts including mdCtx, iCtx, oCtx
    BSL_SAL_CleanseData((void *)(ctx->mdCtx), method->ctxSize * 3);
    BSL_SAL_FREE(ctx->mdCtx);
}

static void HmacCleanseData(uint8_t *tmp, uint32_t tmpLen, uint8_t *ipad, uint32_t ipadLen,
    uint8_t *opad, uint32_t opadLen)
{
    BSL_SAL_CleanseData(tmp, tmpLen);
    BSL_SAL_CleanseData(ipad, ipadLen);
    BSL_SAL_CleanseData(opad, opadLen);
}

int32_t CRYPT_HMAC_Init(CRYPT_HMAC_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || ctx->method == NULL || (key == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_MdMethod *method = ctx->method;
    uint32_t blockSize = method->blockSize;
    uint8_t tmp[HMAC_MAXBLOCKSIZE];
    uint32_t tmpLen = HMAC_MAXBLOCKSIZE;
    const uint8_t *keyTmp = key;
    uint32_t i, keyLen = len;
    uint8_t ipad[HMAC_MAXBLOCKSIZE];
    uint8_t opad[HMAC_MAXBLOCKSIZE];
    int32_t ret;

    if (keyLen > blockSize) {
        keyTmp = tmp;
        GOTO_ERR_IF(method->init(ctx->mdCtx), ret);
        GOTO_ERR_IF(method->update(ctx->mdCtx, key, keyLen), ret);
        GOTO_ERR_IF(method->final(ctx->mdCtx, tmp, &tmpLen), ret);
        keyLen = method->mdSize;
    }
    for (i = 0; i < keyLen; i++) {
        ipad[i] = 0x36 ^ keyTmp[i];
        opad[i] = 0x5c ^ keyTmp[i];
    }
    for (i = keyLen; i < blockSize; i++) {
        ipad[i] = 0x36;
        opad[i] = 0x5c;
    }
    GOTO_ERR_IF(method->init(ctx->iCtx), ret);
    GOTO_ERR_IF(method->update(ctx->iCtx, ipad, method->blockSize), ret);
    GOTO_ERR_IF(method->init(ctx->oCtx), ret);
    GOTO_ERR_IF(method->update(ctx->oCtx, opad, method->blockSize), ret);
    GOTO_ERR_IF(method->copyCtx(ctx->mdCtx, ctx->iCtx), ret);

    HmacCleanseData(tmp, HMAC_MAXBLOCKSIZE, ipad, HMAC_MAXBLOCKSIZE, opad, HMAC_MAXBLOCKSIZE);
    return CRYPT_SUCCESS;

ERR:
    HmacCleanseData(tmp, HMAC_MAXBLOCKSIZE, ipad, HMAC_MAXBLOCKSIZE, opad, HMAC_MAXBLOCKSIZE);
    method->deinit(ctx->mdCtx);
    method->deinit(ctx->iCtx);
    method->deinit(ctx->oCtx);
    return ret;
}

int32_t CRYPT_HMAC_Update(CRYPT_HMAC_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->method->update(ctx->mdCtx, in, len);
}

int32_t CRYPT_HMAC_Final(CRYPT_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || ctx->method == NULL || out == NULL || len == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_MdMethod *method = ctx->method;
    if (*len < method->mdSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_HMAC_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_HMAC_OUT_BUFF_LEN_NOT_ENOUGH;
    }
    *len = method->mdSize;
    uint8_t tmp[HMAC_MAXOUTSIZE];
    uint32_t tmpLen = sizeof(tmp);
    int32_t ret;
    GOTO_ERR_IF(method->final(ctx->mdCtx, tmp, &tmpLen), ret);
    GOTO_ERR_IF(method->copyCtx(ctx->mdCtx, ctx->oCtx), ret);
    GOTO_ERR_IF(method->update(ctx->mdCtx, tmp, tmpLen), ret);
    return method->final(ctx->mdCtx, out, len);
ERR:
    return ret;
}

void CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    const EAL_MdMethod *method = ctx->method;
    method->copyCtx(ctx->mdCtx, ctx->iCtx);
}

void CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    const EAL_MdMethod *method = ctx->method;
    method->deinit(ctx->mdCtx);
    method->deinit(ctx->iCtx);
    method->deinit(ctx->oCtx);
}
#endif // HITLS_CRYPTO_HMAC
