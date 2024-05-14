/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MD)

#include <stdio.h>
#include <stdlib.h>
#include "crypt_eal_md.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "eal_md_local.h"
#include "eal_common.h"

static CRYPT_EAL_MdCTX *MdAllocCtx(CRYPT_MD_AlgId id, const EAL_MdMethod *method)
{
    CRYPT_EAL_MdCTX *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MdCTX));
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    void *data = BSL_SAL_Calloc(1u, method->ctxSize);
    if (data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->data = data;
    return ctx;
}

static CRYPT_EAL_MdCTX *MdNewDefaultCtx(CRYPT_MD_AlgId id)
{
    const EAL_MdMethod *method = EAL_MdFindMethod(id);
    if (method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_EAL_ERR_ALGID);
        return NULL;
    }

    CRYPT_EAL_MdCTX *ctx = MdAllocCtx(id, method);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->id = id;
    ctx->state = CRYPT_MD_STATE_NEW;
    ctx->method = method;
    return ctx;
}

CRYPT_EAL_MdCTX *CRYPT_EAL_MdNewCtx(CRYPT_MD_AlgId id)
{
    return MdNewDefaultCtx(id);
}

bool CRYPT_EAL_MdIsValidAlgId(CRYPT_MD_AlgId id)
{
    return EAL_MdFindMethod(id) != NULL;
}

CRYPT_MD_AlgId CRYPT_EAL_MdGetId(CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        return CRYPT_MD_MAX;
    }
    return ctx->id;
}

static void EalMdCopyCtx(CRYPT_EAL_MdCTX *to, const CRYPT_EAL_MdCTX *from)
{
    void *tmpData = to->data;
    (void)memcpy_s(to, sizeof(CRYPT_EAL_MdCTX), from, sizeof(CRYPT_EAL_MdCTX));
    to->data = tmpData;
    (void)memcpy_s(to->data, from->method->ctxSize, from->data, from->method->ctxSize);
}

int32_t CRYPT_EAL_MdCopyCtx(CRYPT_EAL_MdCTX *to, const CRYPT_EAL_MdCTX *from)
{
    if (to == NULL || from == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (to->data != NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    if (from->method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    void *data = BSL_SAL_Calloc(1u, from->method->ctxSize);
    if (data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, from->id, CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    to->data = data;

    EalMdCopyCtx(to, from);
    return CRYPT_SUCCESS;
}

CRYPT_EAL_MdCTX *CRYPT_EAL_MdDupCtx(const CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, CRYPT_MD_MAX, CRYPT_NULL_INPUT);
        return NULL;
    }
    if (ctx->method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, ctx->id, CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_EAL_MdCTX *newCtx = MdAllocCtx(ctx->id, ctx->method);
    if (newCtx == NULL) {
        return NULL;
    }
    EalMdCopyCtx(newCtx, ctx);
    return newCtx;
}

void CRYPT_EAL_MdFreeCtx(CRYPT_EAL_MdCTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_MD, ctx->id, CRYPT_SUCCESS);
    ctx->method->deinit(ctx->data);
    BSL_SAL_FREE(ctx->data);
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
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->method->init(ctx->data);
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
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    if ((ctx->state == CRYPT_MD_STATE_FINAL) || (ctx->state == CRYPT_MD_STATE_NEW)) {
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
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MAC, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    if ((ctx->state == CRYPT_MD_STATE_NEW) || (ctx->state == CRYPT_MD_STATE_FINAL)) {
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

uint32_t CRYPT_EAL_MdDeinit(CRYPT_EAL_MdCTX *ctx)
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
    int32_t ret;
    if (out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (in == NULL && inLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_MdMethod *method = EAL_MdFindMethod(id);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    void *data = BSL_SAL_Malloc(method->ctxSize);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(data, method->ctxSize, 0, method->ctxSize);

    ret = method->init(data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(data);
        return ret;
    }
    if (inLen != 0) {
        ret = method->update(data, in, inLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    }

    ret = method->final(data, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *outLen = method->mdSize;

ERR:
    method->deinit(data);
    BSL_SAL_FREE(data);
    return ret;
}
#endif
