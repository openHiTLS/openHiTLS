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

#define NOT_CHECK_PARAM 0xff
#define MAC_TYPE_INVALID 0

CRYPT_EAL_MacCtx *MacNewDefaultCtx(CRYPT_MAC_AlgId id)
{
    int32_t ret;
    EAL_MacMethLookup method;
    ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, CRYPT_EAL_ERR_ALGID);
        return NULL;
    }

    CRYPT_EAL_MacCtx *macCtx = NULL;

    macCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MacCtx) + method.macMethod->ctxSize);
    if (macCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    macCtx->id = id;
    macCtx->state = CRYPT_MAC_STATE_NEW;
    macCtx->macMeth = method.macMethod;
    macCtx->ctx = (void *)(macCtx + 1);

    ret = method.macMethod->initCtx(macCtx->ctx, method.depMeth);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, id, ret);
        BSL_SAL_FREE(macCtx);
        return NULL;
    }

    return macCtx;
}

CRYPT_EAL_MacCtx *CRYPT_EAL_MacNewCtx(CRYPT_MAC_AlgId id)
{
#if defined(HITLS_CRYPTO_ASM_CHECK)
    if (CRYPT_ASMCAP_Mac(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
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

    if (ctx->masMeth == NULL) {
        BSL_SAL_FREE(ctx);
        return;
    }

    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_MAC, ctx->id, CRYPT_SUCCESS);

    if (ctx->macMeth == NULL || ctx->macMeth->deinitCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        BSL_SAL_FREE(ctx);
        return;
    }
    ctx->macMeth->deinitCtx(ctx->ctx);

    BSL_SAL_FREE(ctx);
    return;
}

int32_t CRYPT_EAL_MacInit(CRYPT_EAL_MacCtx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->masMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_EAL_ALG_NOT_SUPPORT;

    if (ctx->macMeth == NULL || ctx->macMeth->init == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    ret = ctx->macMeth->init(ctx->ctx, key, len);
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
    if (ctx->masMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((ctx->state == CRYPT_MAC_STATE_FINAL) || (ctx->state == CRYPT_MAC_STATE_NEW)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    int32_t ret = CRYPT_EAL_ALG_NOT_SUPPORT;

    if (ctx->macMeth == NULL || ctx->macMeth->update == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    ret = ctx->macMeth->update(ctx->ctx, in, len);
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
    if (ctx->masMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((ctx->state == CRYPT_MAC_STATE_NEW) || (ctx->state == CRYPT_MAC_STATE_FINAL)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    int32_t ret = CRYPT_EAL_ALG_NOT_SUPPORT;

    if (ctx->macMeth == NULL || ctx->macMeth->final == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    ret = ctx->macMeth->final(ctx->ctx, out, len);
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
    if (ctx->masMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return;
    }

    if (ctx->macMeth == NULL || ctx->macMeth->deinit == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return;
    }
    ctx->macMeth->deinit(ctx->ctx);

    ctx->state = CRYPT_MAC_STATE_NEW;
}

int32_t CRYPT_EAL_MacReinit(CRYPT_EAL_MacCtx *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->masMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
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

uint32_t CRYPT_EAL_GetMacLen(const CRYPT_EAL_MacCtx *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, CRYPT_MAC_MAX, CRYPT_NULL_INPUT);
        return 0;
    }
    if (ctx->masMeth == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_NULL_INPUT);
        return 0;
    }

    if (ctx->macMeth == NULL || ctx->macMeth->getLen == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return 0;
    }
    return ctx->macMeth->getLen(ctx->ctx);
}

bool CRYPT_EAL_MacIsValidAlgId(CRYPT_MAC_AlgId id)
{
    EAL_MacMethLookup method;
    return EAL_MacFindMethod(id, &method) == CRYPT_SUCCESS;
}
#endif
