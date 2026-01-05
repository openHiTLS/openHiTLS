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
#include "crypt_utils.h"
#include "crypt_hkdf.h"
#include "eal_mac_local.h"
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
};

bool CRYPT_HKDF_IsValidAlgId(CRYPT_MAC_AlgId id)
{
    return ParamIdIsValid(id, HKDF_ID_LIST, sizeof(HKDF_ID_LIST) / sizeof(HKDF_ID_LIST[0]));
}

struct CryptHkdfCtx {
    CRYPT_MAC_AlgId macId;
    const EAL_MacMethod *macMeth;
    const EAL_MdMethod *mdMeth;
    CRYPT_HKDF_MODE mode;
    uint8_t *key;
    uint32_t keyLen;
    uint8_t *salt;
    uint32_t saltLen;
    uint8_t *prk;
    uint32_t prkLen;
    uint8_t *info;
    uint32_t infoLen;
    uint32_t *outLen;
};

int32_t CRYPT_HKDF_Extract(const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId, const uint8_t *key,
    uint32_t keyLen, const uint8_t *salt, uint32_t saltLen, uint8_t *prk, uint32_t *prkLen)
{
    int32_t ret;
    if (macMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    void *macCtx = macMeth->newCtx(macId);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    GOTO_ERR_IF(macMeth->init(macCtx, salt, saltLen, NULL), ret);
    GOTO_ERR_IF(macMeth->update(macCtx, key, keyLen), ret);
    GOTO_ERR_IF(macMeth->final(macCtx, prk, prkLen), ret);

ERR:
    macMeth->deinit(macCtx);
    macMeth->freeCtx(macCtx);
    macCtx = NULL;
    return ret;
}

static int32_t HKDF_ExpandParamCheck(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *prk,
    uint32_t prkLen, const uint8_t *info, uint32_t infoLen, const uint8_t *out, uint32_t outLen)
{
    if (macMeth == NULL || mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
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
    if (mdMeth->mdSize == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_PARAM_ERROR);
        return CRYPT_HKDF_PARAM_ERROR;
    }
    /* len cannot be larger than 255 * hashLen */
    if (outLen > (uint32_t)mdMeth->mdSize * 255) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_DKLEN_OVERFLOW);
        return CRYPT_HKDF_DKLEN_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_Expand(const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId, const EAL_MdMethod *mdMeth,
    const uint8_t *prk, uint32_t prkLen, const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t outLen)
{
    int32_t ret = HKDF_ExpandParamCheck(macMeth, mdMeth, prk, prkLen, info, infoLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t hash[HKDF_MAX_HMACSIZE];
    uint32_t hashLen = mdMeth->mdSize;
    uint8_t counter = 1;
    uint32_t totalLen = 0;
    uint32_t n;

    void *macCtx = macMeth->newCtx(macId);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

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
    macMeth->deinit(macCtx);
    macMeth->freeCtx(macCtx);
    macCtx = NULL;
    return ret;
}

int32_t CRYPT_HKDF(const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId, const EAL_MdMethod *mdMeth,
    const uint8_t *key, uint32_t keyLen, const uint8_t *salt, uint32_t saltLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len)
{
    int ret;
    uint8_t prk[HKDF_MAX_HMACSIZE];
    uint32_t prkLen = HKDF_MAX_HMACSIZE;
    ret = CRYPT_HKDF_Extract(macMeth, macId, key, keyLen, salt, saltLen, prk, &prkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_HKDF_Expand(macMeth, macId, mdMeth, prk, prkLen, info, infoLen, out, len);
}

CRYPT_HKDF_Ctx* CRYPT_HKDF_NewCtx(void)
{
    CRYPT_HKDF_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_HKDF_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

int32_t CRYPT_HKDF_SetMacMethod(CRYPT_HKDF_Ctx *ctx, const CRYPT_MAC_AlgId id)
{
    EAL_MacMethLookup method;
    if (!CRYPT_HKDF_IsValidAlgId(id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_PARAM_ERROR);
        return CRYPT_HKDF_PARAM_ERROR;
    }
    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }
    ctx->macMeth = method.macMethod;
    ctx->macId = id;
    ctx->mdMeth = method.md;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_SetKey(CRYPT_HKDF_Ctx *ctx, const uint8_t *key, uint32_t keyLen)
{
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);

    ctx->key = BSL_SAL_Dump(key, keyLen);
    if (ctx->key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->keyLen = keyLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_SetSalt(CRYPT_HKDF_Ctx *ctx, const uint8_t *salt, uint32_t saltLen)
{
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_FREE(ctx->salt);

    ctx->salt = BSL_SAL_Dump(salt, saltLen);
    if (ctx->salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->saltLen = saltLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_SetPRK(CRYPT_HKDF_Ctx *ctx, const uint8_t *prk, uint32_t prkLen)
{
    if (prk == NULL && prkLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->prk, ctx->prkLen);

    ctx->prk = BSL_SAL_Dump(prk, prkLen);
    if (ctx->prk == NULL && prkLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->prkLen = prkLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_SetInfo(CRYPT_HKDF_Ctx *ctx, const uint8_t *info, uint32_t infoLen)
{
    if (info == NULL && infoLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->info, ctx->infoLen);

    ctx->info = BSL_SAL_Dump(info, infoLen);
    if (ctx->info == NULL && infoLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->infoLen = infoLen;
    return CRYPT_SUCCESS;
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
        GOTO_ERR_IF(CRYPT_HKDF_SetKey(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SALT)) != NULL) {
        GOTO_ERR_IF(CRYPT_HKDF_SetSalt(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_PRK)) != NULL) {
        GOTO_ERR_IF(CRYPT_HKDF_SetPRK(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_INFO)) != NULL) {
        GOTO_ERR_IF(CRYPT_HKDF_SetInfo(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_EXLEN)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR, &ptrVal, &len), ret);
        GOTO_ERR_IF(CRYPT_HKDF_SetOutLen(ctx, ptrVal), ret);
    }
ERR:
    return ret;
}

int32_t CRYPT_HKDF_Derive(CRYPT_HKDF_Ctx *ctx, uint8_t *out, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const EAL_MacMethod *macMeth = ctx->macMeth;
    CRYPT_MAC_AlgId macId = ctx->macId;
    const EAL_MdMethod *mdMeth = ctx->mdMeth;
    const uint8_t *key = ctx->key;
    uint32_t keyLen = ctx->keyLen;
    const uint8_t *salt = ctx->salt;
    uint32_t saltLen = ctx->saltLen;
    const uint8_t *prk = ctx->prk;
    uint32_t prkLen = ctx->prkLen;
    const uint8_t *info = ctx->info;
    uint32_t infoLen = ctx->infoLen;
    uint32_t *outLen = ctx->outLen;

    switch (ctx->mode) {
        case CRYPT_KDF_HKDF_MODE_FULL:
            return CRYPT_HKDF(macMeth, macId, mdMeth, key, keyLen, salt, saltLen, info, infoLen, out, len);
        case CRYPT_KDF_HKDF_MODE_EXTRACT:
            return CRYPT_HKDF_Extract(macMeth, macId, key, keyLen, salt, saltLen, out, outLen);
        case CRYPT_KDF_HKDF_MODE_EXPAND:
            return CRYPT_HKDF_Expand(macMeth, macId, mdMeth, prk, prkLen, info, infoLen, out, len);
        default:
            return CRYPT_HKDF_PARAM_ERROR;
    }
}

int32_t CRYPT_HKDF_Deinit(CRYPT_HKDF_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);
    BSL_SAL_FREE(ctx->salt);
    BSL_SAL_ClearFree((void *)ctx->prk, ctx->prkLen);
    BSL_SAL_ClearFree((void *)ctx->info, ctx->infoLen);
    (void)memset_s(ctx, sizeof(CRYPT_HKDF_Ctx), 0, sizeof(CRYPT_HKDF_Ctx));
    return CRYPT_SUCCESS;
}

void CRYPT_HKDF_FreeCtx(CRYPT_HKDF_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);
    BSL_SAL_FREE(ctx->salt);
    BSL_SAL_ClearFree((void *)ctx->prk, ctx->prkLen);
    BSL_SAL_ClearFree((void *)ctx->info, ctx->infoLen);
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
    if (ctx->key != NULL) {
        key = BSL_SAL_Dump(ctx->key, ctx->keyLen);
        GOTO_EXIT_IF((key == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->salt != NULL) {
        salt = BSL_SAL_Dump(ctx->salt, ctx->saltLen);
        GOTO_EXIT_IF((salt == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->prk != NULL) {
        prk = BSL_SAL_Dump(ctx->prk, ctx->prkLen);
        GOTO_EXIT_IF((prk == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->info != NULL) {
        info = BSL_SAL_Dump(ctx->info, ctx->infoLen);
        GOTO_EXIT_IF((info == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    newCtx->key = key;
    newCtx->salt = salt;
    newCtx->prk = prk;
    newCtx->info = info;
    newCtx->outLen = NULL;
    return newCtx;
EXIT:
    BSL_SAL_ClearFree(key, ctx->keyLen);
    BSL_SAL_ClearFree(prk, ctx->prkLen);
    BSL_SAL_ClearFree(info, ctx->infoLen);
    BSL_SAL_Free(salt);
    BSL_SAL_Free(newCtx);
    return NULL;
}

#endif // HITLS_CRYPTO_HKDF
