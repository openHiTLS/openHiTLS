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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_CIPHER)

#include "securec.h"
#include "crypt_algid.h"
#include "crypt_eal_cipher.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "eal_cipher_local.h"
#include "eal_common.h"
#include "crypt_utils.h"
#include "crypt_ealinit.h"
#include "crypt_types.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_provider.h"
#endif

static CRYPT_EAL_CipherCtx *CipherNewCtxInner(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    bool isProvider)
{
    (void)libCtx;
    (void)attrName;
    (void)isProvider;
    CRYPT_EAL_CipherCtx *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_CipherCtx));
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, algId, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    int32_t ret;
    void *provCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == true) {
        ret = EAL_ProviderCipherFindMethod(algId, libCtx, attrName, &ctx->method, &provCtx);
    } else
#endif
    {
        ret = EAL_CipherFindMethod(algId, &ctx->method);
    }
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, algId, ret);
        goto ERR;
    }

    if (ctx->method.newCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, algId, CRYPT_PROVIDER_ERR_IMPL_NULL);
        goto ERR;
    }
    ctx->ctx = ctx->method.newCtx(provCtx, algId);
    if (ctx->ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, algId, CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    ctx->id = algId;
    ctx->states = EAL_CIPHER_STATE_NEW;
    return ctx;
ERR:
    BSL_SAL_Free(ctx);
    return NULL;
}

CRYPT_EAL_CipherCtx *CRYPT_EAL_ProviderCipherNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CipherNewCtxInner(libCtx, algId, attrName, true);
#else
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_CipherNewCtx(algId);
#endif
}

CRYPT_EAL_CipherCtx *CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AlgId id)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Cipher(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    return CipherNewCtxInner(NULL, id, NULL, false);
}

void CRYPT_EAL_CipherFreeCtx(CRYPT_EAL_CipherCtx *ctx)
{
    if (ctx == NULL) {
        // If the input parameter is NULL, it is not considered as an error.
        return;
    }
    if (ctx->method.freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
    } else {
        (void)ctx->method.freeCtx(ctx->ctx);
    }

    // Free the memory eal ctx and mode ctx at the EAL layer.
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_EAL_CipherInit(CRYPT_EAL_CipherCtx *ctx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method.initCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    CRYPT_EAL_CipherDeinit(ctx);
    if (ctx->states != EAL_CIPHER_STATE_NEW) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    int32_t ret = ctx->method.initCtx(ctx->ctx, key, keyLen, iv, ivLen, NULL, enc);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return ret;
    }

    ctx->states = EAL_CIPHER_STATE_INIT;
    return CRYPT_SUCCESS;
}

void CRYPT_EAL_CipherDeinit(CRYPT_EAL_CipherCtx *ctx)
{
    if (ctx == NULL) {
        // If the ctx is NULL during deinit, it is not considered as an error.
        return;
    }
    if (ctx->method.deinitCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return;
    }

    int32_t ret = ctx->method.deinitCtx(ctx->ctx);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
    }
    
    // Restore the state to the state after the new is successful.
    ctx->states = EAL_CIPHER_STATE_NEW;
}

// no need for IV, the value can be set to NULL
int32_t CRYPT_EAL_CipherReinit(CRYPT_EAL_CipherCtx *ctx, uint8_t *iv, uint32_t ivLen)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // Without init, reinit cannot be invoked directly.
    if (ctx->states == EAL_CIPHER_STATE_NEW) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    // Reset the IV. In this case, reset the IV is not restricted by the states.
    if (ctx->method.ctrl == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = ctx->method.ctrl(ctx->ctx, CRYPT_CTRL_REINIT_STATUS, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return ret;
    }
    
    // Reset the states.
    ctx->states = EAL_CIPHER_STATE_INIT;
    return CRYPT_SUCCESS;
}

static bool IsPartialOverLap(const void *out, const void *in, uint32_t len)
{
    uintptr_t diff;
    if ((uintptr_t)out > (uintptr_t)in) {
        diff = (uintptr_t)out - (uintptr_t)in;
        return diff < (uintptr_t)len;
    }
    // If in >= out, this case is valid.
    return false;
}

static int32_t CheckUpdateParam(const CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, const uint8_t *out,
    const uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL || (in == NULL && inLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((in != NULL && inLen != 0) && IsPartialOverLap(out, in, inLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_PART_OVERLAP);
        return CRYPT_EAL_ERR_PART_OVERLAP;
    }
    // If the state is not init or update, the state is regarded as an error.
    // If the state is final or new, update cannot be directly invoked.
    if (!(ctx->states == EAL_CIPHER_STATE_INIT || ctx->states == EAL_CIPHER_STATE_UPDATE)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->method.update == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_CipherUpdate(CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen)
{
    int32_t ret = CheckUpdateParam(ctx, in, inLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        // The push error in CheckUpdateParam can be locate the only error location. No need to add the push error here.
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, (ctx == NULL) ? CRYPT_CIPHER_MAX : ctx->id, ret);
        return ret;
    }

    ret = ctx->method.update(ctx->ctx, in, inLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return ret;
    }
    ctx->states = EAL_CIPHER_STATE_UPDATE;
    return CRYPT_SUCCESS;
}

int32_t CheckFinalParam(const CRYPT_EAL_CipherCtx *ctx, const uint8_t *out, const uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // If the state is not init or update, the state is regarded as an error.
    // If the state is final or new, update cannot be directly invoked.
    if (!(ctx->states == EAL_CIPHER_STATE_UPDATE || ctx->states == EAL_CIPHER_STATE_INIT)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    if (ctx->method.final == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_CipherFinal(CRYPT_EAL_CipherCtx *ctx, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = CheckFinalParam(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, (ctx == NULL) ? CRYPT_CIPHER_MAX : ctx->id, ret);
        return ret;
    }

    ret = ctx->method.final(ctx->ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return ret;
    }

    ctx->states = EAL_CIPHER_STATE_FINAL;
    return CRYPT_SUCCESS;
}

static bool CipherCtrlIsCanSet(const CRYPT_EAL_CipherCtx *ctx, int32_t type)
{
    if (ctx->states == EAL_CIPHER_STATE_NEW) {
        return false;
    }
    if (ctx->states == EAL_CIPHER_STATE_FINAL) {
        return false;
    }
    if ((ctx->states == EAL_CIPHER_STATE_UPDATE) &&
        (type == CRYPT_CTRL_SET_COUNT || type == CRYPT_CTRL_SET_TAGLEN ||
        type == CRYPT_CTRL_SET_MSGLEN || type == CRYPT_CTRL_SET_AAD)) {
        return false;
    }
    return true;
}

int32_t CRYPT_EAL_CipherCtrl(CRYPT_EAL_CipherCtx *ctx, int32_t type, void *data, uint32_t len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // The IV cannot be set through the Ctrl. You need to set the IV through the init and reinit.
    if (type == CRYPT_CTRL_SET_IV || type == CRYPT_CTRL_REINIT_STATUS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_CIPHER_CTRL_ERROR);
        return CRYPT_EAL_CIPHER_CTRL_ERROR;
    }

    // If the algorithm is running in the intermediate state, write operations are not allowed.
    if (!CipherCtrlIsCanSet(ctx, type)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    // Setting AAD indicates that the encryption operation has started and no more write operations are allowed.
    if (type == CRYPT_CTRL_SET_AAD) {
        ctx->states = EAL_CIPHER_STATE_UPDATE;
    } else if (type == CRYPT_CTRL_GET_TAG) {
        // After getTag the system enters the final state.
        ctx->states = EAL_CIPHER_STATE_FINAL;
    }
    if (ctx->method.ctrl == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = ctx->method.ctrl(ctx->ctx, type, data, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return ret;
    }
    return ret;
}

int32_t CRYPT_EAL_CipherSetPadding(CRYPT_EAL_CipherCtx *ctx, CRYPT_PaddingType type)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->method.ctrl == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = ctx->method.ctrl(ctx->ctx, CRYPT_CTRL_SET_PADDING, (void *)&type, sizeof(type));
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_CipherGetPadding(CRYPT_EAL_CipherCtx *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_PADDING_MAX_COUNT;
    }

    if (ctx->method.ctrl == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_PADDING_MAX_COUNT;
    }
    int32_t type;
    int32_t ret = ctx->method.ctrl(ctx->ctx, CRYPT_CTRL_GET_PADDING, (void *)&type, sizeof(type));
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return CRYPT_PADDING_MAX_COUNT;
    }
    return type;
}

bool CRYPT_EAL_CipherIsValidAlgId(CRYPT_CIPHER_AlgId id)
{
    EAL_CipherMethod method = {0};
    return EAL_CipherFindMethod(id, &method) == CRYPT_SUCCESS;
}

static const uint32_t CIPHER_IS_AEAD[] = {
    CRYPT_CIPHER_AES128_CCM,
    CRYPT_CIPHER_AES192_CCM,
    CRYPT_CIPHER_AES256_CCM,
    CRYPT_CIPHER_AES128_GCM,
    CRYPT_CIPHER_AES192_GCM,
    CRYPT_CIPHER_AES256_GCM,
    CRYPT_CIPHER_CHACHA20_POLY1305,
    CRYPT_CIPHER_SM4_GCM,
};

// Check whether the algorithm is the AEAD algorithm. If yes, true is returned. Otherwise, false is returned.
static bool IsAeadAlg(CRYPT_CIPHER_AlgId id)
{
    if (ParamIdIsValid(id, CIPHER_IS_AEAD, sizeof(CIPHER_IS_AEAD) / sizeof(CIPHER_IS_AEAD[0]))) {
        return true;
    }
    return false;
}

int32_t CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AlgId id, int32_t type, uint32_t *infoValue)
{
    if (infoValue == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    CRYPT_CipherInfo info = {0};
    if (EAL_GetCipherInfo(id, &info) != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }

    switch (type) {
        case CRYPT_INFO_IS_AEAD:
            (*infoValue) = IsAeadAlg(id) ? 1 : 0;
            break;
        case CRYPT_INFO_IS_STREAM:
            (*infoValue) = (uint32_t)!((info.blockSize) != 1);
            break;
        case CRYPT_INFO_IV_LEN:
            (*infoValue) = info.ivLen;
            break;
        case CRYPT_INFO_KEY_LEN:
            (*infoValue) = info.keyLen;
            break;
        case CRYPT_INFO_BLOCK_LEN:
            (*infoValue) = (uint32_t)info.blockSize;
            break;
        default:
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_EAL_INTO_TYPE_NOT_SUPPORT);
            return CRYPT_EAL_INTO_TYPE_NOT_SUPPORT;
    }

    return CRYPT_SUCCESS;
}

#endif
