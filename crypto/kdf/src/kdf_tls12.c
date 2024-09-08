/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_KDFTLS12

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_kdf_tls12.h"
#include "eal_mac_local.h"

#define KDFTLS12_MAX_BLOCKSIZE 64

static const uint32_t KDFTLS12_ID_LIST[] = {
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
};

struct CryptKdfTls12Ctx {
    const EAL_MacMethod *macMeth;
    const EAL_MdMethod *mdMeth;
    void *macCtx;
    const uint8_t *key;
    uint32_t keyLen;
    const uint8_t *label;
    uint32_t labelLen;
    const uint8_t *seed;
    uint32_t seedLen;
};

bool CRYPT_KDFTLS12_IsValidAlgId(CRYPT_MAC_AlgId id)
{
    return ParamIdIsValid(id, KDFTLS12_ID_LIST, sizeof(KDFTLS12_ID_LIST) / sizeof(KDFTLS12_ID_LIST[0]));
}

int32_t KDF_Hmac(const EAL_MacMethod *macMeth, void *macCtx, uint8_t *data, uint32_t *len)
{
    int32_t ret;
    macMeth->reinit(macCtx);
    ret = macMeth->update(macCtx, data, *len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = macMeth->final(macCtx, data, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

// algorithm implementation see https://datatracker.ietf.org/doc/pdf/rfc5246.pdf, chapter 5, p_hash function
int32_t KDF_PHASH(CRYPT_KDFTLS12_Ctx *ctx, uint8_t *out, uint32_t len)
{
    int32_t ret;
    const EAL_MacMethod *macMeth = ctx->macMeth;
    const EAL_MdMethod *mdMeth = ctx->mdMeth;
    uint32_t totalLen = 0;
    uint8_t nextIn[KDFTLS12_MAX_BLOCKSIZE];
    uint32_t nextInLen = KDFTLS12_MAX_BLOCKSIZE;
    uint8_t outTmp[KDFTLS12_MAX_BLOCKSIZE];
    uint32_t outTmpLen = KDFTLS12_MAX_BLOCKSIZE;

    ctx->macCtx = BSL_SAL_Malloc(macMeth->ctxSize);
    if (ctx->macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(ctx->macCtx, macMeth->ctxSize, 0, macMeth->ctxSize);
    GOTO_ERR_IF(macMeth->initCtx(ctx->macCtx, mdMeth), ret);

    while (len > totalLen) {
        if (totalLen == 0) {
            GOTO_ERR_IF(macMeth->init(ctx->macCtx, ctx->key, ctx->keyLen), ret);
            GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->label, ctx->labelLen), ret);
            GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->seed, ctx->seedLen), ret);
            GOTO_ERR_IF(macMeth->final(ctx->macCtx, nextIn, &nextInLen), ret);
        } else {
            GOTO_ERR_IF(KDF_Hmac(macMeth, ctx->macCtx, nextIn, &nextInLen), ret);
        }

        macMeth->reinit(ctx->macCtx);
        GOTO_ERR_IF(macMeth->update(ctx->macCtx, nextIn, nextInLen), ret);
        GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->label, ctx->labelLen), ret);
        GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->seed, ctx->seedLen), ret);
        GOTO_ERR_IF(macMeth->final(ctx->macCtx, outTmp, &outTmpLen), ret);

        uint32_t cpyLen = outTmpLen > (len - totalLen) ? (len - totalLen) : outTmpLen;
        (void)memcpy_s(out + totalLen, len - totalLen, outTmp, cpyLen);
        totalLen += cpyLen;
    }

ERR:
    macMeth->deinit(ctx->macCtx);
    macMeth->deinitCtx(ctx->macCtx);
    BSL_SAL_FREE(ctx->macCtx);
    return ret;
}

int32_t CRYPT_KDF_TLS12(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *label, uint32_t labelLen, const uint8_t *seed, uint32_t seedLen, uint8_t *out, uint32_t len)
{
    if (macMeth == NULL || mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (label == NULL && labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (seed == NULL && seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((out == NULL) || (len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_KDFTLS12_Ctx ctx;
    ctx.macMeth = macMeth;
    ctx.mdMeth = mdMeth;
    ctx.key = key;
    ctx.keyLen = keyLen;
    ctx.label = label;
    ctx.labelLen = labelLen;
    ctx.seed = seed;
    ctx.seedLen = seedLen;

    return KDF_PHASH(&ctx, out, len);
}

CRYPT_KDFTLS12_Ctx* CRYPT_KDFTLS12_NewCtx(void)
{
    CRYPT_KDFTLS12_Ctx* ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_KDFTLS12_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

int32_t CRYPT_KDFTLS12_SetMacMethod(CRYPT_KDFTLS12_Ctx *ctx, const CRYPT_MAC_AlgId id)
{
    EAL_MacMethLookup method;
    if (!CRYPT_KDFTLS12_IsValidAlgId(id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_KDFTLS12_PARAM_ERROR);
        return CRYPT_KDFTLS12_PARAM_ERROR;
    }
    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }
    ctx->macMeth = method.macMethod;
    ctx->mdMeth = method.md;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_KDFTLS12_SetKey(CRYPT_KDFTLS12_Ctx *ctx, const uint8_t *key, uint32_t keyLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

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

int32_t CRYPT_KDFTLS12_SetLabel(CRYPT_KDFTLS12_Ctx *ctx, const uint8_t *label, uint32_t labelLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (label == NULL && labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->label, ctx->labelLen);

    ctx->label = BSL_SAL_Dump(label, labelLen);
    if (ctx->label == NULL && labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->labelLen = labelLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_KDFTLS12_SetSeed(CRYPT_KDFTLS12_Ctx *ctx, const uint8_t *seed, uint32_t seedLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (seed == NULL && seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->seed, ctx->seedLen);

    ctx->seed = BSL_SAL_Dump(seed, seedLen);
    if (ctx->seed == NULL && seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->seedLen = seedLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_KDFTLS12_SetParam(CRYPT_KDFTLS12_Ctx *ctx, const CRYPT_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    switch (param->type) {
        case CRYPT_KDF_PARAM_MAC_ALG_ID:
            return CRYPT_KDFTLS12_SetMacMethod(ctx, *(CRYPT_MAC_AlgId *)(param->param));
        case CRYPT_KDF_PARAM_KEY:
            return CRYPT_KDFTLS12_SetKey(ctx, param->param, param->paramLen);
        case CRYPT_KDF_PARAM_LABEL:
            return CRYPT_KDFTLS12_SetLabel(ctx, param->param, param->paramLen);
        case CRYPT_KDF_PARAM_SEED:
            return CRYPT_KDFTLS12_SetSeed(ctx, param->param, param->paramLen);
        default:
            return CRYPT_KDFTLS12_PARAM_ERROR;
    }
}

int32_t CRYPT_KDFTLS12_Derive(CRYPT_KDFTLS12_Ctx *ctx, uint8_t *out, uint32_t len)
{
    if (ctx->macMeth == NULL || ctx->mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->key == NULL && ctx->keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->label == NULL && ctx->labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->seed == NULL && ctx->seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((out == NULL) || (len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return KDF_PHASH(ctx, out, len);
}

int32_t CRYPT_KDFTLS12_Deinit(CRYPT_KDFTLS12_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);
    BSL_SAL_ClearFree((void *)ctx->label, ctx->labelLen);
    BSL_SAL_ClearFree((void *)ctx->seed, ctx->seedLen);
    (void)memset_s(ctx, sizeof(CRYPT_KDFTLS12_Ctx), 0, sizeof(CRYPT_KDFTLS12_Ctx));
    return CRYPT_SUCCESS;
}

void CRYPT_KDFTLS12_FreeCtx(CRYPT_KDFTLS12_Ctx *ctx)
{
    CRYPT_KDFTLS12_Ctx *kdfCtx = ctx;
    if (kdfCtx == NULL) {
        return;
    }
    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);
    BSL_SAL_ClearFree((void *)ctx->label, ctx->labelLen);
    BSL_SAL_ClearFree((void *)ctx->seed, ctx->seedLen);
    BSL_SAL_FREE(kdfCtx);
}

#endif // HITLS_CRYPTO_KDFTLS12
