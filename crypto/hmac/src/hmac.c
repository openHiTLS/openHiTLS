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
#ifdef HITLS_CRYPTO_HMAC

#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_hmac.h"
#include "eal_mac_local.h"

struct HMAC_Ctx {
    const EAL_MdMethod *method;
    void *mdCtx;            /* md ctx */
    void *oCtx;             /* opad ctx */
    void *iCtx;             /* ipad ctx */
};

CRYPT_HMAC_Ctx *CRYPT_HMAC_NewCtx(CRYPT_MAC_AlgId id)
{
    int32_t ret;
    EAL_MacMethLookup method;
    ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    CRYPT_HMAC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_HMAC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->method = method.md;

    ret = CRYPT_MD_ERR_NEWCTX;
    if (ctx->method->newCtx == NULL || ctx->method->freeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->mdCtx = ctx->method->newCtx();
    if (ctx->mdCtx == NULL) {
        goto ERR;
    }
    ctx->iCtx = ctx->method->newCtx();
    if (ctx->iCtx == NULL) {
        goto ERR;
    }
    ctx->oCtx = ctx->method->newCtx();
    if (ctx->oCtx == NULL) {
        goto ERR;
    }

    return ctx;
ERR:
    BSL_ERR_PUSH_ERROR(ret);
    ctx->method->freeCtx(ctx->mdCtx);
    ctx->method->freeCtx(ctx->iCtx);
    ctx->method->freeCtx(ctx->oCtx);
    BSL_SAL_Free(ctx);
    return NULL;
}

static int32_t CRYPT_HMAC_GetMacLen(const CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return ctx->method->mdSize;
}

static void HmacCleanseData(uint8_t *tmp, uint32_t tmpLen, uint8_t *ipad, uint32_t ipadLen,
    uint8_t *opad, uint32_t opadLen)
{
    BSL_SAL_CleanseData(tmp, tmpLen);
    BSL_SAL_CleanseData(ipad, ipadLen);
    BSL_SAL_CleanseData(opad, opadLen);
}

int32_t CRYPT_HMAC_Init(CRYPT_HMAC_Ctx *ctx, const uint8_t *key, uint32_t len, BSL_Param *param)
{
    if (ctx == NULL || ctx->method == NULL || (key == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void) param;
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
        GOTO_ERR_IF(method->init(ctx->mdCtx, NULL), ret);
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
    GOTO_ERR_IF(method->init(ctx->iCtx, NULL), ret);
    GOTO_ERR_IF(method->update(ctx->iCtx, ipad, method->blockSize), ret);
    GOTO_ERR_IF(method->init(ctx->oCtx, NULL), ret);
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
    int32_t ret = method->final(ctx->mdCtx, tmp, &tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = method->copyCtx(ctx->mdCtx, ctx->oCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = method->update(ctx->mdCtx, tmp, tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return method->final(ctx->mdCtx, out, len);
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

static int32_t CRYPT_HMAC_GetLen(const CRYPT_HMAC_Ctx *ctx, GetLenFunc func, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *(uint32_t *)val = func(ctx);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HMAC_Ctrl(CRYPT_HMAC_Ctx *ctx, CRYPT_MacCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_MACLEN:
            return CRYPT_HMAC_GetLen(ctx, (GetLenFunc)CRYPT_HMAC_GetMacLen, val, len);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_HMAC_ERR_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_HMAC_ERR_UNSUPPORTED_CTRL_OPTION;
}

void CRYPT_HMAC_FreeCtx(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->method == NULL || ctx->method->freeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    const EAL_MdMethod *method = ctx->method;
    // clear 3 contexts including mdCtx, iCtx, oCtx
    method->freeCtx(ctx->mdCtx);
    ctx->mdCtx = NULL;
    method->freeCtx(ctx->iCtx);
    ctx->iCtx = NULL;
    method->freeCtx(ctx->oCtx);
    ctx->oCtx = NULL;

    BSL_SAL_FREE(ctx);
}

CRYPT_HMAC_Ctx *CRYPT_HMAC_DupCtx(const CRYPT_HMAC_Ctx *macCtx)
{
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    if (macCtx->method == NULL || macCtx->method->freeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_HMAC_Ctx *ctx = BSL_SAL_Dump(macCtx, sizeof(CRYPT_HMAC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    void *mdCtx = macCtx->method->dupCtx(macCtx->mdCtx);
    void *oCtx = macCtx->method->dupCtx(macCtx->oCtx);
    void *iCtx = macCtx->method->dupCtx(macCtx->iCtx);
    if (mdCtx == NULL || oCtx == NULL || iCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(ctx);
        macCtx->method->freeCtx(mdCtx);
        macCtx->method->freeCtx(iCtx);
        macCtx->method->freeCtx(oCtx);
        return NULL;
    }
    ctx->mdCtx = mdCtx;
    ctx->oCtx = oCtx;
    ctx->iCtx = iCtx;
    return ctx;
}

#endif // HITLS_CRYPTO_HMAC
