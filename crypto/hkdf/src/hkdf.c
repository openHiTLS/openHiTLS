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
#ifdef HITLS_CRYPTO_HKDF

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_util_ctrl.h"
#include "crypt_utils.h"
#include "crypt_hkdf.h"
#include "eal_mac_local.h"
#include "crypt_eal_kdf.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#define HKDF_MAX_HMACSIZE 64

static const uint32_t HKDF_ID_LIST[] = {
    CRYPT_MAC_HMAC_MD5,
    CRYPT_MAC_HMAC_SHA1,
    CRYPT_MAC_HMAC_SHA224,
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
    CRYPT_MAC_HMAC_SM3,
};

bool CRYPT_HKDF_IsValidAlgId(CRYPT_MAC_AlgId id)
{
    return ParamIdIsValid(id, HKDF_ID_LIST, sizeof(HKDF_ID_LIST) / sizeof(HKDF_ID_LIST[0]));
}

struct CryptHkdfCtx {
    CRYPT_MAC_AlgId macId;
    EAL_MacMethod macMeth;
    uint16_t mdSize;
    CRYPT_HKDF_MODE mode;
    void *macCtx;
    uint8_t *key;
    uint32_t keyLen;
    uint8_t *salt;
    uint32_t saltLen;
    uint8_t *prk;
    uint32_t prkLen;
    uint8_t *info;
    uint32_t infoLen;
    uint32_t *outLen;
#ifdef HITLS_CRYPTO_PROVIDER
    void *libCtx;
#endif
    bool hasGetMdSize;
};

static bool CheckMacMethod(const EAL_MacMethod *macMeth)
{
    return macMeth->freeCtx != NULL && macMeth->init != NULL &&
        macMeth->update != NULL && macMeth->final != NULL && macMeth->deinit != NULL &&
        macMeth->reinit != NULL;
}

int32_t CRYPT_HKDF_Extract(void *macCtx, const EAL_MacMethod *macMeth, const uint8_t *key,
    uint32_t keyLen, const uint8_t *salt, uint32_t saltLen, uint8_t *prk, uint32_t *prkLen)
{
    int32_t ret;
    if (macCtx == NULL || macMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (CheckMacMethod(macMeth) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_ERR_MAC_METH);
        return CRYPT_HKDF_ERR_MAC_METH;
    }

    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)macMeth->deinit(macCtx);
    GOTO_ERR_IF(macMeth->init(macCtx, salt, saltLen, NULL), ret);
    GOTO_ERR_IF(macMeth->update(macCtx, key, keyLen), ret);
    GOTO_ERR_IF(macMeth->final(macCtx, prk, prkLen), ret);

ERR:
    (void)macMeth->deinit(macCtx);
    return ret;
}

static int32_t HKDF_ExpandParamCheck(void *macCtx, const EAL_MacMethod *macMeth, uint16_t mdSize, const uint8_t *prk,
    uint32_t prkLen, const uint8_t *info, uint32_t infoLen, const uint8_t *out, uint32_t outLen)
{
    if (macCtx == NULL || macMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (CheckMacMethod(macMeth) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_ERR_MAC_METH);
        return CRYPT_HKDF_ERR_MAC_METH;
    }
    if (prk == NULL && prkLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (info == NULL && infoLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((out == NULL) || (outLen == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (mdSize == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_PARAM_ERROR);
        return CRYPT_HKDF_PARAM_ERROR;
    }
    /* len cannot be larger than 255 * hashLen */
    if (outLen > mdSize * 255) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_DKLEN_OVERFLOW);
        return CRYPT_HKDF_DKLEN_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_Expand(void *macCtx, const EAL_MacMethod *macMeth, uint16_t mdSize,
    const uint8_t *prk, uint32_t prkLen, const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t outLen)
{
    int32_t ret = HKDF_ExpandParamCheck(macCtx, macMeth, mdSize, prk, prkLen, info, infoLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t hash[HKDF_MAX_HMACSIZE];
    uint32_t hashLen = mdSize;
    uint8_t counter = 1;
    uint32_t totalLen = 0;
    uint32_t n;

    (void)macMeth->deinit(macCtx);
    GOTO_ERR_IF(macMeth->init(macCtx, prk, prkLen, NULL), ret);

    /* ceil(a / b) = (a + b - 1) / b */
    n = (outLen + hashLen - 1) / hashLen;
    for (uint32_t i = 1; i <= n; i++, counter++) {
        if (i > 1) {
            macMeth->reinit(macCtx);
            GOTO_ERR_IF(macMeth->update(macCtx, hash, hashLen), ret);
        }
        GOTO_ERR_IF(macMeth->update(macCtx, info, infoLen), ret);
        GOTO_ERR_IF(macMeth->update(macCtx, &counter, 1), ret);
        GOTO_ERR_IF(macMeth->final(macCtx, hash, &hashLen), ret);
        hashLen = hashLen > (outLen - totalLen) ? (outLen - totalLen) : hashLen;
        (void)memcpy_s(out + totalLen, outLen - totalLen, hash, hashLen);
        totalLen += hashLen;
    }

ERR:
    (void)macMeth->deinit(macCtx);
    return ret;
}

int32_t CRYPT_HKDF(void *macCtx, const EAL_MacMethod *macMeth, uint16_t mdSize,
    const uint8_t *key, uint32_t keyLen, const uint8_t *salt, uint32_t saltLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len)
{
    int ret;
    uint8_t prk[HKDF_MAX_HMACSIZE];
    uint32_t prkLen = HKDF_MAX_HMACSIZE;
    ret = CRYPT_HKDF_Extract(macCtx, macMeth, key, keyLen, salt, saltLen, prk, &prkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_HKDF_Expand(macCtx, macMeth, mdSize, prk, prkLen, info, infoLen, out, len);
}

CRYPT_HKDF_Ctx *CRYPT_HKDF_NewCtx(void)
{
    CRYPT_HKDF_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_HKDF_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

CRYPT_HKDF_Ctx *CRYPT_HKDF_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    CRYPT_HKDF_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_HKDF_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    ctx->libCtx = libCtx;
#endif
    return ctx;
}

static int32_t HkdfGetMdSize(CRYPT_HKDF_Ctx *ctx, const char *mdAttr)
{
    if (ctx->hasGetMdSize) {
        return CRYPT_SUCCESS;
    }
    void *libCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    libCtx = ctx->libCtx;
#endif

    EAL_MdMethod mdMeth = {0};
    EAL_MacDepMethod depMeth = {.method = {.md = &mdMeth}};
    int32_t ret = EAL_MacFindDepMethod(ctx->macId, libCtx, mdAttr, &depMeth, NULL, libCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->hasGetMdSize = true;
    ctx->mdSize = mdMeth.mdSize;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_SetMacMethod(CRYPT_HKDF_Ctx *ctx, const CRYPT_MAC_AlgId id)
{
    if (!CRYPT_HKDF_IsValidAlgId(id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_PARAM_ERROR);
        return CRYPT_HKDF_PARAM_ERROR;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_CTRL_SetMacMethod(ctx->libCtx, id, CRYPT_HKDF_ERR_MAC_METH, &ctx->macCtx, &ctx->macMeth, &ctx->macId);
#else
    return CRYPT_CTRL_SetMacMethod(NULL, id, CRYPT_HKDF_ERR_MAC_METH, &ctx->macCtx, &ctx->macMeth, &ctx->macId);
#endif
}

int32_t CRYPT_HKDF_SetOutLen(CRYPT_HKDF_Ctx *ctx, uint32_t *outLen)
{
    if (outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->outLen = outLen;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CRYPT_HKDF_SetMdAttr(CRYPT_HKDF_Ctx *ctx, const char *mdAttr, uint32_t valLen)
{
    int32_t ret = CRYPT_CTRL_SetMdAttrToHmac(mdAttr, valLen, ctx->macMeth.setParam, ctx->macCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HkdfGetMdSize(ctx, mdAttr);
}
#endif

int32_t CRYPT_HKDF_SetParam(CRYPT_HKDF_Ctx *ctx, const BSL_Param *param)
{
    uint32_t val = 0;
    void *ptrVal = NULL;
    uint32_t len = 0;
    const BSL_Param *temp = NULL;
    int32_t ret = CRYPT_HKDF_PARAM_ERROR;
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_MAC_ID)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_MAC_ID,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_HKDF_SetMacMethod(ctx, val), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_MODE)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_MODE,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        ctx->mode = val;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_KEY)) != NULL) {
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->key, &ctx->keyLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SALT)) != NULL) {
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->salt, &ctx->saltLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_PRK)) != NULL) {
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->prk, &ctx->prkLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_INFO)) != NULL) {
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->info, &ctx->infoLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_EXLEN)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR, &ptrVal, &len), ret);
        GOTO_ERR_IF(CRYPT_HKDF_SetOutLen(ctx, ptrVal), ret);
    }
#ifdef HITLS_CRYPTO_PROVIDER
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_MD_ATTR)) != NULL) {
        GOTO_ERR_IF(CRYPT_HKDF_SetMdAttr(ctx, temp->value, temp->valueLen), ret);
    }
#endif
ERR:
    return ret;
}

int32_t CRYPT_HKDF_Derive(CRYPT_HKDF_Ctx *ctx, uint8_t *out, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    void *macCtx = ctx->macCtx;
    const EAL_MacMethod *macMeth = &ctx->macMeth;
    const uint8_t *key = ctx->key;
    uint32_t keyLen = ctx->keyLen;
    const uint8_t *salt = ctx->salt;
    uint32_t saltLen = ctx->saltLen;
    const uint8_t *prk = ctx->prk;
    uint32_t prkLen = ctx->prkLen;
    const uint8_t *info = ctx->info;
    uint32_t infoLen = ctx->infoLen;
    uint32_t *outLen = ctx->outLen;

    int32_t ret = HkdfGetMdSize(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    switch (ctx->mode) {
        case CRYPT_KDF_HKDF_MODE_FULL:
            return CRYPT_HKDF(macCtx, macMeth, ctx->mdSize, key, keyLen, salt, saltLen, info, infoLen, out, len);
        case CRYPT_KDF_HKDF_MODE_EXTRACT:
            return CRYPT_HKDF_Extract(macCtx, macMeth, key, keyLen, salt, saltLen, out, outLen);
        case CRYPT_KDF_HKDF_MODE_EXPAND:
            return CRYPT_HKDF_Expand(macCtx, macMeth, ctx->mdSize, prk, prkLen, info, infoLen, out, len);
        default:
            return CRYPT_HKDF_PARAM_ERROR;
    }
}

static void DeinitCtx(CRYPT_HKDF_Ctx *ctx)
{
    if (ctx->macMeth.freeCtx != NULL) {
        ctx->macMeth.freeCtx(ctx->macCtx);
        ctx->macCtx = NULL;
    }
    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);
    BSL_SAL_FREE(ctx->salt);
    BSL_SAL_ClearFree((void *)ctx->prk, ctx->prkLen);
    BSL_SAL_ClearFree((void *)ctx->info, ctx->infoLen);
}

int32_t CRYPT_HKDF_Deinit(CRYPT_HKDF_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    DeinitCtx(ctx);
    (void)memset_s(ctx, sizeof(CRYPT_HKDF_Ctx), 0, sizeof(CRYPT_HKDF_Ctx));
    return CRYPT_SUCCESS;
}

void CRYPT_HKDF_FreeCtx(CRYPT_HKDF_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    DeinitCtx(ctx);
    BSL_SAL_Free(ctx);
}

CRYPT_HKDF_Ctx *CRYPT_HKDF_DupCtx(const CRYPT_HKDF_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    uint8_t *key = NULL;
    uint8_t *salt = NULL;
    uint8_t *prk = NULL;
    uint8_t *info = NULL;

    CRYPT_HKDF_Ctx *newCtx = BSL_SAL_Dump(ctx, sizeof(CRYPT_HKDF_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    void *macCtx = NULL;
    if (ctx->macCtx != NULL) {
        macCtx = ctx->macMeth.dupCtx(ctx->macCtx);
        GOTO_ERR_IF_TRUE((macCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
    }

    if (ctx->key != NULL) {
        key = BSL_SAL_Dump(ctx->key, ctx->keyLen);
        GOTO_ERR_IF_TRUE((key == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->salt != NULL) {
        salt = BSL_SAL_Dump(ctx->salt, ctx->saltLen);
        GOTO_ERR_IF_TRUE((salt == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->prk != NULL) {
        prk = BSL_SAL_Dump(ctx->prk, ctx->prkLen);
        GOTO_ERR_IF_TRUE((prk == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->info != NULL) {
        info = BSL_SAL_Dump(ctx->info, ctx->infoLen);
        GOTO_ERR_IF_TRUE((info == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    newCtx->macCtx = macCtx;
    newCtx->key = key;
    newCtx->salt = salt;
    newCtx->prk = prk;
    newCtx->info = info;
    newCtx->outLen = NULL;
    return newCtx;
ERR:
    if (macCtx != NULL) {
        ctx->macMeth.freeCtx(macCtx);
    }
    BSL_SAL_ClearFree(key, ctx->keyLen);
    BSL_SAL_ClearFree(prk, ctx->prkLen);
    BSL_SAL_ClearFree(info, ctx->infoLen);
    BSL_SAL_Free(salt);
    BSL_SAL_Free(newCtx);
    return NULL;
}

#endif // HITLS_CRYPTO_HKDF
