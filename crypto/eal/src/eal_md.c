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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MD)

#include <stdio.h>
#include <stdlib.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "eal_md_local.h"
#include "eal_common.h"
#include "crypt_utils.h"
#include "crypt_ealinit.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#endif

static CRYPT_EAL_MdCTX *MdAllocCtx(CRYPT_MD_AlgId id, const EAL_MdUnitaryMethod *method)
{
    CRYPT_EAL_MdCTX *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MdCTX));
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    void *data = NULL;
    if (method->newCtx != NULL) {
        data = method->newCtx();
    } else {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NULL_INPUT);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    if (data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->data = data;
    return ctx;
}

static void EalMdCopyMethod(const EAL_MdMethod *method, EAL_MdUnitaryMethod *dest)
{
    dest->blockSize = method->blockSize;
    dest->mdSize = method->mdSize;
    dest->newCtx = method->newCtx;
    dest->init = method->init;
    dest->update = method->update;
    dest->final = method->final;
    dest->deinit = method->deinit;
    dest->dupCtx = method->dupCtx;
    dest->freeCtx = method->freeCtx;
    dest->ctrl = method->ctrl;
    dest->squeeze = method->squeeze;
}

static CRYPT_EAL_MdCTX *MdNewDefaultCtx(CRYPT_MD_AlgId id)
{
    const EAL_MdMethod *method = EAL_MdFindMethod(id);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }

    EAL_MdUnitaryMethod *temp = BSL_SAL_Calloc(1, sizeof(EAL_MdUnitaryMethod));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    EalMdCopyMethod(method, temp);
    CRYPT_EAL_MdCTX *ctx = MdAllocCtx(id, temp);
    if (ctx == NULL) {
        BSL_SAL_FREE(temp);
        return NULL;
    }

    ctx->id = id;
    ctx->state = CRYPT_MD_STATE_NEW;
    ctx->method = temp;
    return ctx;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CRYPT_EAL_SetMdMethod(CRYPT_EAL_MdCTX *ctx, const CRYPT_EAL_Func *funcs)
{
    int32_t index = 0;
    EAL_MdUnitaryMethod *method = BSL_SAL_Calloc(1, sizeof(EAL_MdUnitaryMethod));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLMD_NEWCTX:
                method->provNewCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_INITCTX:
                method->init = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_UPDATE:
                method->update = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_FINAL:
                method->final = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_DEINITCTX:
                method->deinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_DUPCTX:
                method->dupCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_CTRL:
                method->ctrl = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_FREECTX:
                method->freeCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_SQUEEZE:
                method->squeeze = funcs[index].func;
                break;
            default:
                BSL_SAL_FREE(method);
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    ctx->method = method;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_MdCTX *CRYPT_EAL_ProviderMdNewCtxInner(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
    const CRYPT_EAL_Func *funcs = NULL;
    void *provCtx = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, algId, attrName,
        &funcs, &provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    CRYPT_EAL_MdCTX *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MdCTX));
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, algId, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    ret = CRYPT_EAL_SetMdMethod(ctx, funcs);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    if (ctx->method->provNewCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_IMPL_NULL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->data = ctx->method->provNewCtx(provCtx, algId);
    if (ctx->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->id = algId;
    ctx->state = CRYPT_MD_STATE_NEW;
    ctx->isProvider = true;
    return ctx;
}
#endif // HITLS_CRYPTO_PROVIDER

CRYPT_EAL_MdCTX *CRYPT_EAL_ProviderMdNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderMdNewCtxInner(libCtx, algId, attrName);
#else
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_MdNewCtx(algId);
#endif
}

CRYPT_EAL_MdCTX *CRYPT_EAL_MdNewCtx(CRYPT_MD_AlgId id)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Md(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    return MdNewDefaultCtx(id);
}

bool CRYPT_EAL_MdIsValidAlgId(CRYPT_MD_AlgId id)
{
    return EAL_MdFindMethod(id) != NULL;
}

int32_t CRYPT_EAL_MdGetId(CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        return CRYPT_MD_MAX;
    }
    return ctx->id;
}

int32_t CRYPT_EAL_MdCopyCtx(CRYPT_EAL_MdCTX *to, const CRYPT_EAL_MdCTX *from)
{
    if (to == NULL || to->method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (from == NULL || from->method == NULL || from->method->dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (to->isProvider != from->isProvider) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_INCONSISTENT_OPERATION);
        return CRYPT_INCONSISTENT_OPERATION;
    }

    if (to->data != NULL) {
        if (to->method->freeCtx == NULL) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        to->method->freeCtx(to->data);
        to->data = NULL;
    }
    void *data = from->method->dupCtx(from->data);
    if (data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, from->id, CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *(EAL_MdUnitaryMethod *)to->method = *from->method;
    to->data = data;
    to->state = from->state;
    to->id = from->id;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_MdCTX *CRYPT_EAL_MdDupCtx(const CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return NULL;
    }
    if (ctx->method == NULL || ctx->method->dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_EAL_MdCTX *newCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MdCTX));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    EAL_MdUnitaryMethod *method = BSL_SAL_Calloc(1u, sizeof(EAL_MdUnitaryMethod));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_FREE(newCtx);
        return NULL;
    }
    *method = *ctx->method;
    newCtx->data = ctx->method->dupCtx(ctx->data);
    if (newCtx->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_FREE(method);
        BSL_SAL_FREE(newCtx);
        return NULL;
    }
    newCtx->method = method;
    newCtx->state = ctx->state;
    newCtx->id = ctx->id;
    return newCtx;
}

void CRYPT_EAL_MdFreeCtx(CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->method == NULL || ctx->method->freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return;
    }
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_MD, ctx->id, CRYPT_SUCCESS);
    ctx->method->freeCtx(ctx->data);
    BSL_SAL_FREE(ctx->method);
    BSL_SAL_FREE(ctx);
    return;
}

int32_t CRYPT_EAL_MdInit(CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->init == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->method->init(ctx->data, NULL);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, ret);
        return ret;
    }
    ctx->state = CRYPT_MD_STATE_INIT;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MdUpdate(CRYPT_EAL_MdCTX *ctx, const uint8_t *data, uint32_t len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->update == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    if ((ctx->state == CRYPT_MD_STATE_FINAL) || (ctx->state == CRYPT_MD_STATE_NEW)
        || (ctx->state == CRYPT_MD_STATE_SQUEEZE)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    int32_t ret = ctx->method->update(ctx->data, data, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, ret);
        return ret;
    }
    ctx->state = CRYPT_MD_STATE_UPDATE;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MdFinal(CRYPT_EAL_MdCTX *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->final == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    if ((ctx->state == CRYPT_MD_STATE_NEW) || (ctx->state == CRYPT_MD_STATE_FINAL) ||
        (ctx->state == CRYPT_MD_STATE_SQUEEZE)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    // The validity of the buffer length that carries the output result (len > ctx->method->mdSize)
    // is determined by the algorithm bottom layer and is not verified here.
    int32_t ret = ctx->method->final(ctx->data, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, ret);
        return ret;
    }
    ctx->state = CRYPT_MD_STATE_FINAL;
    EAL_EventReport(CRYPT_EVENT_MD, CRYPT_ALGO_MD, ctx->id, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MdSqueeze(CRYPT_EAL_MdCTX *ctx, uint8_t *out, uint32_t len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->squeeze == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    if ((ctx->state == CRYPT_MD_STATE_NEW) || (ctx->state == CRYPT_MD_STATE_FINAL)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    int32_t ret = ctx->method->squeeze(ctx->data, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, ret);
        return ret;
    }
    ctx->state = CRYPT_MD_STATE_SQUEEZE;
    EAL_EventReport(CRYPT_EVENT_MD, CRYPT_ALGO_MD, ctx->id, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MdDeinit(CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL || ctx->method == NULL || ctx->method->deinit == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->method->deinit(ctx->data);
    ctx->state = CRYPT_MD_STATE_NEW;
    return CRYPT_SUCCESS;
}

uint32_t CRYPT_EAL_MdGetDigestSize(CRYPT_MD_AlgId id)
{
    const EAL_MdMethod *method = EAL_MdFindMethod(id);
    if (method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_EAL_ERR_ALGID);
        return 0;
    }

    return method->mdSize;
}

int32_t CRYPT_EAL_Md(CRYPT_MD_AlgId id, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return EAL_Md(id, in, inLen, out, outLen);
}

#ifdef HITLS_CRYPTO_MD_MB

CRYPT_EAL_MdCTX *CRYPT_EAL_MdMBNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t id, uint32_t num)
{
    (void)libCtx;
    if (UNLIKELY(num == 0)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NULL_INPUT);
        return NULL;
    }

    EAL_MdMBMethod mbMethod = {0};
    if (EAL_MdFindMbMethod(id, &mbMethod) == NULL ||
        mbMethod.newCtx == NULL || mbMethod.freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NOT_SUPPORT);
        return NULL;
    }

    void *mbData = mbMethod.newCtx(num);
    if (mbData == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    CRYPT_EAL_MdCTX *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_MdCTX));
    if (ctx == NULL) {
        mbMethod.freeCtx(mbData);
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ctx->mbMethod = mbMethod;
    ctx->data = mbData;
    ctx->id = id;
    ctx->state = CRYPT_MD_STATE_NEW;
    return ctx;
}

void CRYPT_EAL_MdMBFreeCtx(CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->mbMethod.freeCtx != NULL) {
        ctx->mbMethod.freeCtx(ctx->data);
    }
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_EAL_MdMBInit(CRYPT_EAL_MdCTX *ctx)
{
    if (UNLIKELY(ctx == NULL)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_MD_AlgId id = ctx->id;
    if (ctx->mbMethod.init == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    int32_t ret = ctx->mbMethod.init(ctx->data);
    
    if (ret == CRYPT_SUCCESS) {
        ctx->state = CRYPT_MD_STATE_INIT;
    }

    return ret;
}

int32_t CRYPT_EAL_MdMBUpdate(CRYPT_EAL_MdCTX *ctx, const uint8_t *data[], uint32_t nbytes[], uint32_t num)
{
    if (UNLIKELY(ctx == NULL || data == NULL || nbytes == NULL || num == 0)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (UNLIKELY(nbytes[0] == 0)) {
        return CRYPT_SUCCESS;
    }

    CRYPT_MD_AlgId id = ctx->id;
    if (ctx->mbMethod.update == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }

    int32_t ret = ctx->mbMethod.update(ctx->data, data, nbytes, num);
    if (ret == CRYPT_SUCCESS) {
        ctx->state = CRYPT_MD_STATE_UPDATE;
    }

    return ret;
}

int32_t CRYPT_EAL_MdMBFinal(CRYPT_EAL_MdCTX *ctx, uint8_t *digest[], uint32_t *outlen, uint32_t num)
{
    if (UNLIKELY(ctx == NULL || digest == NULL || outlen == NULL || num == 0)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_MD_AlgId id = ctx->id;
    if (ctx->mbMethod.final == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }

    int32_t ret = ctx->mbMethod.final(ctx->data, digest, outlen, num);
    if (ret == CRYPT_SUCCESS) {
        ctx->state = CRYPT_MD_STATE_FINAL;
    }

    return ret;
}

#endif // HITLS_CRYPTO_MD_MB

#endif
