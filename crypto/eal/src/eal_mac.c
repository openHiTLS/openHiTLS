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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MAC)

#include <stdio.h>
#include <stdlib.h>
#include "crypt_eal_mac.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_eal_mac.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_ealinit.h"
#include "eal_mac_local.h"
#include "eal_common.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#endif

#define MAC_TYPE_INVALID 0

static void EalMacCopyMethod(const EAL_MacMethod *src, EAL_MacUnitaryMethod *dst)
{
    dst->init = src->init;
    dst->update = src->update;
    dst->final = src->final;
    dst->deinit = src->deinit;
    dst->reinit = src->reinit;
    dst->newCtx = src->newCtx;
    dst->ctrl = src->ctrl;
    dst->freeCtx = src->freeCtx;
    dst->dupCtx = src->dupCtx;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CRYPT_EAL_SetMacMethod(CRYPT_EAL_MacCtx *ctx, const CRYPT_EAL_Func *funcs)
{
    int32_t index = 0;
    EAL_MacUnitaryMethod *method = BSL_SAL_Calloc(1, sizeof(EAL_MacUnitaryMethod));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLMAC_NEWCTX:
                method->provNewCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_INIT:
                method->init = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_UPDATE:
                method->update = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_FINAL:
                method->final = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_REINITCTX:
                method->reinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_DEINITCTX:
                method->deinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_CTRL:
                method->ctrl = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_FREECTX:
                method->freeCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_DUPCTX:
                method->dupCtx = funcs[index].func;
                break;
            default:
                BSL_SAL_Free(method);
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    ctx->macMeth = method;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_MacCtx *CRYPT_EAL_ProviderMacNewCtxInner(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
    const CRYPT_EAL_Func *funcs = NULL;
    void *provCtx = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_MAC, algId, attrName,
        &funcs, &provCtx);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, algId, ret);
        return NULL;
    }
    CRYPT_EAL_MacCtx *macCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MacCtx));
    if (macCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, algId, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ret = CRYPT_EAL_SetMacMethod(macCtx, funcs);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(macCtx);
        return NULL;
    }
    if (macCtx->macMeth->provNewCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, algId, CRYPT_PROVIDER_ERR_IMPL_NULL);
        BSL_SAL_FREE(macCtx->macMeth);
        BSL_SAL_FREE(macCtx);
        return NULL;
    }
    macCtx->ctx = macCtx->macMeth->provNewCtx(provCtx, algId);
    if (macCtx->ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, algId, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(macCtx->macMeth);
        BSL_SAL_FREE(macCtx);
        return NULL;
    }

    macCtx->id = algId;
    macCtx->state = CRYPT_MAC_STATE_NEW;
    macCtx->isProvider = true;

    return macCtx;
}
#endif

CRYPT_EAL_MacCtx *CRYPT_EAL_ProviderMacNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderMacNewCtxInner(libCtx, algId, attrName);
#else
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_MacNewCtx(algId);
#endif
}

CRYPT_EAL_MacCtx *MacNewDefaultCtx(CRYPT_MAC_AlgId id)
{
    EAL_MacMethLookup method;
    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, ret);
        return NULL;
    }

    CRYPT_EAL_MacCtx *macCtx = NULL;

    macCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MacCtx));
    if (macCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    macCtx->id = id;
    macCtx->state = CRYPT_MAC_STATE_NEW;

    EAL_MacUnitaryMethod *temp = BSL_SAL_Calloc(1, sizeof(EAL_MacUnitaryMethod));
    if (temp == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(macCtx);
        return NULL;
    }
    EalMacCopyMethod(method.macMethod, temp);
    macCtx->macMeth = temp;

    if (method.macMethod->newCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, CRYPT_PROVIDER_ERR_IMPL_NULL);
        BSL_SAL_FREE(macCtx->macMeth);
        BSL_SAL_FREE(macCtx);
        return NULL;
    }
    macCtx->ctx = method.macMethod->newCtx(id);
    if (macCtx->ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(macCtx->macMeth);
        BSL_SAL_FREE(macCtx);
        return NULL;
    }

    return macCtx;
}

CRYPT_EAL_MacCtx *CRYPT_EAL_MacNewCtx(CRYPT_MAC_AlgId id)
{
#if defined(HITLS_CRYPTO_ASM_CHECK)
    if (CRYPT_ASMCAP_Mac(id) != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    return MacNewDefaultCtx(id);
}

void CRYPT_EAL_MacFreeCtx(CRYPT_EAL_MacCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->macMeth == NULL || ctx->macMeth->freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        BSL_SAL_FREE(ctx->macMeth);
        BSL_SAL_FREE(ctx);
        return;
    }
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_MAC, ctx->id, CRYPT_SUCCESS);
    ctx->macMeth->freeCtx(ctx->ctx);
    BSL_SAL_FREE(ctx->macMeth);
    BSL_SAL_FREE(ctx);
    return;
}

int32_t CRYPT_EAL_MacInit(CRYPT_EAL_MacCtx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->macMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->macMeth == NULL || ctx->macMeth->init == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->macMeth->init(ctx->ctx, key, len, NULL);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_SETSSP, CRYPT_ALGO_MAC, ctx->id, ret);
    ctx->state = CRYPT_MAC_STATE_INIT;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MacUpdate(CRYPT_EAL_MacCtx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->macMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((ctx->state == CRYPT_MAC_STATE_FINAL) || (ctx->state == CRYPT_MAC_STATE_NEW)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    if (ctx->macMeth == NULL || ctx->macMeth->update == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->macMeth->update(ctx->ctx, in, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, ret);
        return ret;
    }
    ctx->state = CRYPT_MAC_STATE_UPDATE;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MacFinal(CRYPT_EAL_MacCtx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->macMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((ctx->state == CRYPT_MAC_STATE_NEW) || (ctx->state == CRYPT_MAC_STATE_FINAL)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    if (ctx->macMeth == NULL || ctx->macMeth->final == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->macMeth->final(ctx->ctx, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, ret);
        return ret;
    }
    ctx->state = CRYPT_MAC_STATE_FINAL;
    EAL_EventReport(CRYPT_EVENT_MAC, CRYPT_ALGO_MAC, ctx->id, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
}

void CRYPT_EAL_MacDeinit(CRYPT_EAL_MacCtx *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return;
    }
    if (ctx->macMeth == NULL || ctx->macMeth->deinit == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return;
    }
    ctx->macMeth->deinit(ctx->ctx);

    ctx->state = CRYPT_MAC_STATE_NEW;
    return;
}

int32_t CRYPT_EAL_MacReinit(CRYPT_EAL_MacCtx *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->state == CRYPT_MAC_STATE_NEW) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    if (ctx->macMeth == NULL || ctx->macMeth->reinit == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    ctx->macMeth->reinit(ctx->ctx);
    ctx->state = CRYPT_MAC_STATE_INIT;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MacCtrl(CRYPT_EAL_MacCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || ctx->macMeth == NULL || ctx->macMeth->ctrl== NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (cmd == CRYPT_CTRL_GET_MACLEN) {
        return ctx->macMeth->ctrl(ctx->ctx, cmd, val, valLen);
    }

    if (ctx->state != CRYPT_MAC_STATE_INIT) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    return ctx->macMeth->ctrl(ctx->ctx, cmd, val, valLen);
}

uint32_t CRYPT_EAL_GetMacLen(const CRYPT_EAL_MacCtx *ctx)
{
    uint32_t result = 0;
    int32_t ret = CRYPT_EAL_MacCtrl((CRYPT_EAL_MacCtx *)(uintptr_t)ctx,
        CRYPT_CTRL_GET_MACLEN, &result, sizeof(uint32_t));
    return (ret == CRYPT_SUCCESS) ? result : 0;
}

bool CRYPT_EAL_MacIsValidAlgId(CRYPT_MAC_AlgId id)
{
    EAL_MacMethLookup method;
    return EAL_MacFindMethod(id, &method) == CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_MacCopyCtx(CRYPT_EAL_MacCtx *to, const CRYPT_EAL_MacCtx *from)
{
    if (to == NULL || from == NULL || from->macMeth == NULL || from->macMeth->dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (to->ctx != NULL) {
        if (to->macMeth->freeCtx == NULL) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, from->id, CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        to->macMeth->freeCtx(to->ctx);
        to->ctx = NULL;
    }

    if (to->macMeth != NULL) {
        BSL_SAL_FREE(to->macMeth);
    }

    EAL_MacUnitaryMethod *tmpMethod = BSL_SAL_Dump(from->macMeth, sizeof(EAL_MacUnitaryMethod));
    if (tmpMethod == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, from->id, CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    void *ctx = from->macMeth->dupCtx(from->ctx);
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, from->id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(tmpMethod);
        return CRYPT_INVALID_ARG;
    }
    (void)memcpy_s(to, sizeof(CRYPT_EAL_MacCtx), from, sizeof(CRYPT_EAL_MacCtx));
    to->ctx = ctx;
    to->macMeth = tmpMethod;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_MacCtx *CRYPT_EAL_MacDupCtx(const CRYPT_EAL_MacCtx *from)
{
    if (from == NULL || from->macMeth == NULL || from->macMeth->dupCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_EAL_MacCtx *newCtx = BSL_SAL_Dump(from, sizeof(CRYPT_EAL_MacCtx));
    if (newCtx == NULL ) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, from->id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->macMeth = BSL_SAL_Dump(from->macMeth, sizeof(EAL_MacUnitaryMethod));
    if (newCtx->macMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, from->id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(newCtx);
        return NULL;
    }
    newCtx->ctx = from->macMeth->dupCtx(from->ctx);
    if (newCtx->ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, from->id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(newCtx->macMeth);
        BSL_SAL_Free(newCtx);
        return NULL;
    }
    return newCtx;
}

#endif
