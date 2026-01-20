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

#if defined(HITLS_CRYPTO_CODECS) && defined(HITLS_CRYPTO_PROVIDER)
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "bsl_types.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "decode_local.h"

int32_t CRYPT_DECODE_ParseDecoderAttr(const char *attrName, DECODER_AttrInfo *info)
{
    char *rest = NULL;
    info->inFormat = NULL;
    info->inType = NULL;
    info->outFormat = NULL;
    info->outType = NULL;
    info->attrName = (char *)BSL_SAL_Dump(attrName, (uint32_t)strlen(attrName) + 1);
    if (info->attrName == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    char *token = strtok_s(info->attrName, ",", &rest);
    while (token != NULL) {
        while (*token == ' ') {
            token++;
        }

        if (strstr(token, "inFormat=") == token) {
            info->inFormat = token + strlen("inFormat=");
        } else if (strstr(token, "inType=") == token) {
            info->inType = token + strlen("inType=");
        } else if (strstr(token, "outFormat=") == token) {
            info->outFormat = token + strlen("outFormat=");
        } else if (strstr(token, "outType=") == token) {
            info->outType = token + strlen("outType=");
        }

        token = strtok_s(NULL, ",", &rest);
    }

    return CRYPT_SUCCESS;
}

static int32_t SetDecoderMethod(CRYPT_DECODER_Ctx *ctx, const CRYPT_EAL_Func *funcs)
{
    int32_t index = 0;
    CRYPT_DECODER_Method *method = BSL_SAL_Calloc(1, sizeof(CRYPT_DECODER_Method));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    while (funcs[index].func != NULL) {
        switch (funcs[index].id) {
            case CRYPT_DECODER_IMPL_NEWCTX:
                method->newCtx = (CRYPT_DECODER_IMPL_NewCtx)funcs[index].func;
                break;
            case CRYPT_DECODER_IMPL_SETPARAM:
                method->setParam = (CRYPT_DECODER_IMPL_SetParam)funcs[index].func;
                break;
            case CRYPT_DECODER_IMPL_GETPARAM:
                method->getParam = (CRYPT_DECODER_IMPL_GetParam)funcs[index].func;
                break;
            case CRYPT_DECODER_IMPL_DECODE:
                method->decode = (CRYPT_DECODER_IMPL_Decode)funcs[index].func;
                break;
            case CRYPT_DECODER_IMPL_FREEOUTDATA:
                method->freeOutData = (CRYPT_DECODER_IMPL_FreeOutData)funcs[index].func;
                break;
            case CRYPT_DECODER_IMPL_FREECTX:
                method->freeCtx = (CRYPT_DECODER_IMPL_FreeCtx)funcs[index].func;
                break;
            default:
                BSL_SAL_Free(method);
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    ctx->method = method;
    return CRYPT_SUCCESS;
}

CRYPT_DECODER_Ctx *CRYPT_DECODE_NewDecoderCtxByMethod(const CRYPT_EAL_Func *funcs, CRYPT_EAL_ProvMgrCtx *mgrCtx,
    const char *attrName)
{
    void *provCtx = NULL;
    DECODER_AttrInfo attrInfo = {0};
    CRYPT_DECODER_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_DECODER_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    int32_t ret = CRYPT_EAL_ProviderCtrl(mgrCtx, CRYPT_PROVIDER_GET_USER_CTX, &provCtx, sizeof(provCtx));
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    ret = SetDecoderMethod(ctx, funcs);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    if (ctx->method->newCtx == NULL || ctx->method->setParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        goto ERR;
    }
    ctx->decoderCtx = ctx->method->newCtx(provCtx);
    if (ctx->decoderCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    BSL_Param param[2] = {{CRYPT_PARAM_DECODE_PROVIDER_CTX, BSL_PARAM_TYPE_CTX_PTR, mgrCtx, 0, 0},
        BSL_PARAM_END};
    ret = ctx->method->setParam(ctx->decoderCtx, param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (attrName != NULL) {
        ret = CRYPT_DECODE_ParseDecoderAttr(attrName, &attrInfo);
        if (ret != CRYPT_SUCCESS) {
            goto ERR;
        }
    }
    ctx->providerMgrCtx = mgrCtx;
    ctx->inFormat = attrInfo.inFormat;
    ctx->inType = attrInfo.inType;
    ctx->outFormat = attrInfo.outFormat;
    ctx->outType = attrInfo.outType;
    ctx->attrName = attrName != NULL ? attrInfo.attrName : NULL;
    ctx->decoderState = CRYPT_DECODER_STATE_UNTRIED;
    return ctx;
ERR:
    CRYPT_DECODE_Free(ctx);
    return NULL;
}

CRYPT_DECODER_Ctx *CRYPT_DECODE_ProviderNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t pkeyAlgId, const char *attrName)
{
    const CRYPT_EAL_Func *funcsDecoder = NULL;
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncsAndMgrCtx(libCtx, CRYPT_EAL_OPERAID_DECODER, pkeyAlgId, attrName,
        &funcsDecoder, &mgrCtx, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    return CRYPT_DECODE_NewDecoderCtxByMethod(funcsDecoder, mgrCtx, attrName);
}

/* Free decoder context */
void CRYPT_DECODE_Free(CRYPT_DECODER_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    if (ctx->method != NULL && ctx->method->freeCtx != NULL) {
        ctx->method->freeCtx(ctx->decoderCtx);
    }
    BSL_SAL_Free(ctx->method);
    BSL_SAL_Free(ctx->attrName);
    BSL_SAL_Free(ctx);
}

/* Set decoder parameters */
int32_t CRYPT_DECODE_SetParam(CRYPT_DECODER_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->method == NULL || ctx->method->setParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    
    return ctx->method->setParam(ctx->decoderCtx, param);
}

/* Get decoder parameters */
int32_t CRYPT_DECODE_GetParam(CRYPT_DECODER_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->method == NULL || ctx->method->getParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    
    return ctx->method->getParam(ctx->decoderCtx, param);
}

/* Execute decode operation */
int32_t CRYPT_DECODE_Decode(CRYPT_DECODER_Ctx *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->method == NULL || ctx->method->decode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }

    int32_t ret = ctx->method->decode(ctx->decoderCtx, inParam, outParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    
    return ret;
}

void CRYPT_DECODE_FreeOutData(CRYPT_DECODER_Ctx *ctx, BSL_Param *outData)
{
    if (ctx == NULL || outData == NULL || ctx->method == NULL || ctx->method->freeOutData == NULL) {
        return;
    }
    ctx->method->freeOutData(ctx->decoderCtx, outData);
}

#endif /* HITLS_CRYPTO_CODECS && HITLS_CRYPTO_PROVIDER */
