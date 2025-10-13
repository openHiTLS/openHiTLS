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
#include "eal_mac_local.h"
#include "crypt_local_types.h"
#include "crypt_hmac.h"

struct HMAC_Ctx {
    CRYPT_MAC_AlgId hmacId;
    EAL_MdMethod method;
    void *mdCtx;            /* md ctx */
    void *oCtx;             /* opad ctx */
    void *iCtx;             /* ipad ctx */
#ifdef HITLS_CRYPTO_PROVIDER
    void *libCtx;           /* library context for external provider */
#endif
};

CRYPT_HMAC_Ctx *CRYPT_HMAC_NewCtx(CRYPT_MAC_AlgId id)
{
    CRYPT_HMAC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_HMAC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ctx->hmacId = id;
    return ctx;
}

CRYPT_HMAC_Ctx *CRYPT_HMAC_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id)
{
    CRYPT_HMAC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_HMAC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->hmacId = id;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx->libCtx = libCtx;
#else
    (void)libCtx;
#endif
    return ctx;
}

static inline void HmacCleanseData(uint8_t *tmp, uint32_t tmpLen, uint8_t *ipad, uint32_t ipadLen,
    uint8_t *opad, uint32_t opadLen)
{
    BSL_SAL_CleanseData(tmp, tmpLen);
    BSL_SAL_CleanseData(ipad, ipadLen);
    BSL_SAL_CleanseData(opad, opadLen);
}

static int32_t HmacInitMdCtx(CRYPT_HMAC_Ctx *ctx, const char *attr)
{
    if (ctx->mdCtx != NULL) { // already initialized at ctrl or init
        return CRYPT_SUCCESS;
    }

#ifdef HITLS_CRYPTO_PROVIDER
    void *libCtx = ctx->libCtx;
#else
    void *libCtx = NULL;
#endif
    void *provCtx = NULL;
    EAL_MacDepMethod depMeth = {.method = {.md = &ctx->method}};
    int32_t ret = EAL_MacFindDepMethod(ctx->hmacId, libCtx, attr, &depMeth, &provCtx, libCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->method.newCtx == NULL || ctx->method.freeCtx == NULL) { // Check the method will be used.
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->mdCtx = ctx->method.newCtx(provCtx, depMeth.id.mdId);
    ctx->iCtx = ctx->method.newCtx(provCtx, depMeth.id.mdId);
    ctx->oCtx = ctx->method.newCtx(provCtx, depMeth.id.mdId);
    if (ctx->mdCtx == NULL || ctx->iCtx == NULL || ctx->oCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    return CRYPT_SUCCESS;
ERR:
    ctx->method.freeCtx(ctx->mdCtx);
    ctx->mdCtx = NULL;
    ctx->method.freeCtx(ctx->iCtx);
    ctx->iCtx = NULL;
    ctx->method.freeCtx(ctx->oCtx);
    ctx->oCtx = NULL;
    return CRYPT_MEM_ALLOC_FAIL;
}

static inline bool IsMdMethodValid(const EAL_MdMethod *method)
{
    return method->init != NULL && method->update != NULL && method->final != NULL &&
        method->deinit != NULL && method->copyCtx != NULL;
}

int32_t CRYPT_HMAC_Init(CRYPT_HMAC_Ctx *ctx, const uint8_t *key, uint32_t len, BSL_Param *param)
{
    (void)param;
    if (ctx == NULL || (key == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint8_t tmp[HMAC_MAXBLOCKSIZE];
    uint32_t tmpLen = HMAC_MAXBLOCKSIZE;
    const uint8_t *keyTmp = key;
    uint32_t i, keyLen = len;
    uint8_t ipad[HMAC_MAXBLOCKSIZE];
    uint8_t opad[HMAC_MAXBLOCKSIZE];

    int32_t ret = HmacInitMdCtx(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (IsMdMethodValid(&ctx->method) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (keyLen > ctx->method.blockSize) {
        keyTmp = tmp;
        GOTO_ERR_IF(ctx->method.init(ctx->mdCtx, NULL), ret);
        GOTO_ERR_IF(ctx->method.update(ctx->mdCtx, key, keyLen), ret);
        GOTO_ERR_IF(ctx->method.final(ctx->mdCtx, tmp, &tmpLen), ret);
        keyLen = ctx->method.mdSize;
    }
    for (i = 0; i < keyLen; i++) {
        ipad[i] = 0x36 ^ keyTmp[i];
        opad[i] = 0x5c ^ keyTmp[i];
    }
    for (i = keyLen; i < ctx->method.blockSize; i++) {
        ipad[i] = 0x36;
        opad[i] = 0x5c;
    }
    GOTO_ERR_IF(ctx->method.init(ctx->iCtx, NULL), ret);
    GOTO_ERR_IF(ctx->method.update(ctx->iCtx, ipad, ctx->method.blockSize), ret);
    GOTO_ERR_IF(ctx->method.init(ctx->oCtx, NULL), ret);
    GOTO_ERR_IF(ctx->method.update(ctx->oCtx, opad, ctx->method.blockSize), ret);
    GOTO_ERR_IF(ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx), ret);

ERR:
    HmacCleanseData(tmp, HMAC_MAXBLOCKSIZE, ipad, HMAC_MAXBLOCKSIZE, opad, HMAC_MAXBLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        ctx->method.deinit(ctx->mdCtx);
        ctx->method.deinit(ctx->iCtx);
        ctx->method.deinit(ctx->oCtx);
    }
    return ret;
}

int32_t CRYPT_HMAC_Update(CRYPT_HMAC_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || ctx->method.update == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->method.update(ctx->mdCtx, in, len);
}

int32_t CRYPT_HMAC_Final(CRYPT_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    bool nullInput = ctx == NULL || ctx->method.final == NULL || ctx->method.copyCtx == NULL ||
                     ctx->method.update == NULL || out == NULL || len == NULL;
    if (nullInput == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_MdMethod *method = &ctx->method;
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

int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.deinit == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)ctx->method.deinit(ctx->mdCtx);
    (void)ctx->method.deinit(ctx->iCtx);
    (void)ctx->method.deinit(ctx->oCtx);
    return CRYPT_SUCCESS;
}

static int32_t HMAC_GetMacLen(CRYPT_HMAC_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = HmacInitMdCtx(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *(uint32_t *)val = ctx->method.mdSize;
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
            return HMAC_GetMacLen(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HMAC_ERR_UNSUPPORTED_CTRL_OPTION);
            return CRYPT_HMAC_ERR_UNSUPPORTED_CTRL_OPTION;
    }
}

static void HmacFreeMdCtx(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx->method.freeCtx == NULL) {
        return;
    }
    ctx->method.freeCtx(ctx->mdCtx);
    ctx->mdCtx = NULL;
    ctx->method.freeCtx(ctx->iCtx);
    ctx->iCtx = NULL;
    ctx->method.freeCtx(ctx->oCtx);
    ctx->oCtx = NULL;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_HMAC_SetParam(CRYPT_HMAC_Ctx *ctx, const BSL_Param *param)
{
    const BSL_Param *temp = NULL;
    int32_t ret = CRYPT_HMAC_PARAM_ERROR;
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_MD_ATTR)) != NULL) {
        if (temp->valueLen == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_HMAC_PARAM_ERROR);
            return CRYPT_HMAC_PARAM_ERROR;
        }
        HmacFreeMdCtx(ctx);
        GOTO_ERR_IF(HmacInitMdCtx(ctx, (const char *)temp->value), ret);
    }
ERR:
    return ret;
}
#endif // HITLS_CRYPTO_PROVIDER

void CRYPT_HMAC_FreeCtx(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    HmacFreeMdCtx(ctx);
    BSL_SAL_Free(ctx);
}
#endif // HITLS_CRYPTO_HMAC
