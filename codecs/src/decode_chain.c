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
#include <stdint.h>
#include <string.h>
#include "securec.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_params_key.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "decode_local.h"
#include "bsl_list.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"

static CRYPT_DECODER_Node *CreateDecoderNode(const char *format, const char *type, const char *targetFormat,
    const char *targetType, const BSL_Param *input)
{
    CRYPT_DECODER_Node *decoderNode = BSL_SAL_Calloc(1, sizeof(CRYPT_DECODER_Node));
    if (decoderNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    decoderNode->inData.format = format;
    decoderNode->inData.type = type;
    decoderNode->inData.data = (BSL_Param *)(uintptr_t)input;
    decoderNode->outData.format = targetFormat;
    decoderNode->outData.type = targetType;
    return decoderNode;
}

static void FreeDecoderNode(CRYPT_DECODER_Node *decoderNode)
{
    if (decoderNode == NULL) {
        return;
    }
    CRYPT_DECODE_FreeOutData(decoderNode->decoderCtx, decoderNode->outData.data);
    BSL_SAL_Free(decoderNode);
}

CRYPT_DECODER_PoolCtx *CRYPT_DECODE_PoolNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    int32_t pkeyAlgId, const char *format, const char *type)
{
    CRYPT_DECODER_PoolCtx *poolCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_DECODER_PoolCtx));
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    poolCtx->libCtx = libCtx;
    poolCtx->attrName = attrName;
    poolCtx->decoders = BSL_LIST_New(sizeof(CRYPT_DECODER_Ctx));
    if (poolCtx->decoders == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(poolCtx);
        return NULL;
    }

    poolCtx->decoderPath = BSL_LIST_New(sizeof(CRYPT_DECODER_Node));
    if (poolCtx->decoderPath == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    poolCtx->inputFormat = format;
    poolCtx->inputType = type;
    poolCtx->inputPkeyAlgId = pkeyAlgId;
    poolCtx->targetFormat = NULL;
    poolCtx->targetType = NULL;
    return poolCtx;
ERR:
    BSL_LIST_FREE(poolCtx->decoders, NULL);
    BSL_SAL_Free(poolCtx);
    return NULL;
}

void CRYPT_DECODE_PoolFreeCtx(CRYPT_DECODER_PoolCtx *poolCtx)
{
    if (poolCtx == NULL) {
        return;
    }
    
    /* Free decoder path list and all decoder nodes */
    if (poolCtx->decoderPath != NULL) {
        BSL_LIST_FREE(poolCtx->decoderPath, (BSL_LIST_PFUNC_FREE)FreeDecoderNode);
    }
    /* Free decoder list and all decoder contexts */
    if (poolCtx->decoders != NULL) {
        BSL_LIST_FREE(poolCtx->decoders, (BSL_LIST_PFUNC_FREE)CRYPT_DECODE_Free);
    }

    BSL_SAL_Free(poolCtx);
}

static int32_t SetDecodeType(void *val, int32_t valLen, const char **targetValue)
{
    if (valLen == 0 || valLen > MAX_CRYPT_DECODE_FORMAT_TYPE_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *targetValue = val;
    return CRYPT_SUCCESS;
}

static int32_t SetFlagFreeOutData(CRYPT_DECODER_PoolCtx *poolCtx, void *val, int32_t valLen)
{
    if (valLen != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (poolCtx->decoderPath == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    CRYPT_DECODER_Node *prevNode = BSL_LIST_GET_PREV(poolCtx->decoderPath);
    if (prevNode == NULL) {
        return CRYPT_SUCCESS;
    }
    bool isFreeOutData = *(bool *)val;
    if (!isFreeOutData) {
        prevNode->outData.data = NULL;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DECODE_PoolCtrl(CRYPT_DECODER_PoolCtx *poolCtx, int32_t cmd, void *val, int32_t valLen)
{
    if (poolCtx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    switch (cmd) {
        case CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE:
            return SetDecodeType(val, valLen, &poolCtx->targetType);
        case CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT:
            return SetDecodeType(val, valLen, &poolCtx->targetFormat);
        case CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA:
            return SetFlagFreeOutData(poolCtx, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

static int32_t CollectDecoder(CRYPT_DECODER_Ctx *decoderCtx, void *args)
{
    int32_t ret;
    CRYPT_DECODER_PoolCtx *poolCtx = (CRYPT_DECODER_PoolCtx *)args;
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // TODO: Filter the decoder by input format and type According to poolCtx
    BSL_Param param[3] = {
        {CRYPT_PARAM_DECODE_LIB_CTX, BSL_PARAM_TYPE_CTX_PTR, poolCtx->libCtx, 0, 0},
        {CRYPT_PARAM_DECODE_TARGET_ATTR_NAME, BSL_PARAM_TYPE_OCTETS_PTR, (void *)(uintptr_t)poolCtx->attrName, 0, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_DECODE_SetParam(decoderCtx, param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_LIST_AddElement(poolCtx->decoders, decoderCtx, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

static CRYPT_DECODER_Ctx* GetUsableDecoderFromPool(CRYPT_DECODER_PoolCtx *poolCtx, CRYPT_DECODER_Node *currNode)
{
    CRYPT_DECODER_Ctx *decoderCtx = NULL;
    const char *curFormat = currNode->inData.format;
    const char *curType = currNode->inData.type;
    CRYPT_DECODER_Ctx *node = BSL_LIST_GET_FIRST(poolCtx->decoders);
    while (node != NULL) {
        decoderCtx = node;
        if (decoderCtx == NULL || decoderCtx->decoderState != CRYPT_DECODER_STATE_UNTRIED) {
            node = BSL_LIST_GET_NEXT(poolCtx->decoders);
            continue;
        }
        /* Check if decoder matches the current node's input format and type */
        if (curFormat != NULL && curType != NULL) {
            if ((decoderCtx->inFormat != NULL && BSL_SAL_StrcaseCmp(decoderCtx->inFormat, curFormat) == 0) &&
                (decoderCtx->inType == NULL || BSL_SAL_StrcaseCmp(decoderCtx->inType, curType) == 0)) {
                break;
            }
        } else if (curFormat == NULL && curType != NULL) {
            if (decoderCtx->inType == NULL || BSL_SAL_StrcaseCmp(decoderCtx->inType, curType) == 0) {
                break;
            }
        } else if (curFormat != NULL && curType == NULL) {
            if (decoderCtx->inFormat != NULL && BSL_SAL_StrcaseCmp(decoderCtx->inFormat, curFormat) == 0) {
                break;
            }
        } else {
            break;
        }
        node = BSL_LIST_GET_NEXT(poolCtx->decoders);
    }
    if (node != NULL) {
        decoderCtx = node;
        decoderCtx->decoderState = CRYPT_DECODER_STATE_TRING;
        return decoderCtx;
    }
    return NULL;
}

static int32_t UpdateDecoderPath(CRYPT_DECODER_PoolCtx *poolCtx, CRYPT_DECODER_Node *currNode)
{
    /* Create new node */
    CRYPT_DECODER_Node *newNode = CreateDecoderNode(currNode->outData.format, currNode->outData.type,
        poolCtx->targetFormat, poolCtx->targetType, currNode->outData.data);
    if (newNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BSL_LIST_AddElement(poolCtx->decoderPath, newNode, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(newNode);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t TryDecodeWithDecoder(CRYPT_DECODER_PoolCtx *poolCtx, CRYPT_DECODER_Node *currNode)
{
    /* Convert password buffer to parameter if provided */
    BSL_Param *decoderParam = NULL;
    int32_t ret = CRYPT_DECODE_Decode(currNode->decoderCtx, currNode->inData.data, &decoderParam);
    if (ret == CRYPT_SUCCESS) {
        /* Get output format and type from decoder */
        BSL_Param outParam[3] = {
            {CRYPT_PARAM_DECODE_OUTPUT_FORMAT, BSL_PARAM_TYPE_OCTETS_PTR, NULL, 0, 0},
            {CRYPT_PARAM_DECODE_OUTPUT_TYPE, BSL_PARAM_TYPE_OCTETS_PTR, NULL, 0, 0},
            BSL_PARAM_END
        };
        ret = CRYPT_DECODE_GetParam(currNode->decoderCtx, outParam);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        
        currNode->outData.data = decoderParam;
        currNode->outData.format = outParam[0].value;
        currNode->outData.type = outParam[1].value;
        currNode->decoderCtx->decoderState = CRYPT_DECODER_STATE_SUCCESS;
        ret = UpdateDecoderPath(poolCtx, currNode);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        return CRYPT_SUCCESS;
    } else {
        /* Mark the node as tried */
        currNode->decoderCtx->decoderState = CRYPT_DECODER_STATE_TRIED;
        return CRYPT_DECODE_RETRY;
    }
}

static void ResetLastNode(CRYPT_DECODER_PoolCtx *poolCtx, CRYPT_DECODER_Node *currNode)
{
    (void)currNode;
    CRYPT_DECODER_Node *prevNode = BSL_LIST_GET_PREV(poolCtx->decoderPath);
    /* Reset the out data of previous node if found */
    if (prevNode != NULL) {
        CRYPT_DECODE_FreeOutData(prevNode->decoderCtx, prevNode->outData.data);
        prevNode->outData.data = NULL;
        prevNode->decoderCtx = NULL;
        prevNode->outData.format = poolCtx->targetFormat;
        prevNode->outData.type = poolCtx->targetType;
        (void)BSL_LIST_GET_NEXT(poolCtx->decoderPath);
    } else {
        (void)BSL_LIST_GET_FIRST(poolCtx->decoderPath);
    }
    BSL_LIST_DeleteCurrent(poolCtx->decoderPath, (BSL_LIST_PFUNC_FREE)FreeDecoderNode);
    (void)BSL_LIST_GET_LAST(poolCtx->decoderPath);
}

static int32_t BackToLastLayerDecodeNode(CRYPT_DECODER_PoolCtx *poolCtx, CRYPT_DECODER_Node *currNode)
{
    if (poolCtx == NULL || currNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ResetLastNode(poolCtx, currNode);
    /* Reset all decoders marked as tried to untried state */
    CRYPT_DECODER_Ctx *decoderCtx = BSL_LIST_GET_FIRST(poolCtx->decoders);
    while (decoderCtx != NULL) {
        if (decoderCtx->decoderState == CRYPT_DECODER_STATE_TRIED) {
            decoderCtx->decoderState = CRYPT_DECODER_STATE_UNTRIED;
        }
        decoderCtx = BSL_LIST_GET_NEXT(poolCtx->decoders);
    }

    return CRYPT_SUCCESS;
}

static bool IsStrMatch(const char *source, const char *target)
{
    if (source == NULL && target == NULL) {
        return true;
    }
    if (source == NULL || target == NULL) {
        return false;
    }
    return BSL_SAL_StrcaseCmp(source, target) == 0;
}

static int32_t DecodeWithKeyChain(CRYPT_DECODER_PoolCtx *poolCtx, BSL_Param **outParam)
{
    int32_t ret;
    CRYPT_DECODER_Ctx *decoderCtx = NULL;
    CRYPT_DECODER_Node *currNode = BSL_LIST_GET_FIRST(poolCtx->decoderPath);
    while (!BSL_LIST_EMPTY(poolCtx->decoderPath)) {
        if (IsStrMatch(currNode->inData.format, poolCtx->targetFormat) &&
            IsStrMatch(currNode->inData.type, poolCtx->targetType)) {
            *outParam = currNode->inData.data;
            return CRYPT_SUCCESS;
        }
        /* Get the usable decoder from the pool */
        decoderCtx = GetUsableDecoderFromPool(poolCtx, currNode);
        /* If the decoder is found, try to decode */
        if (decoderCtx != NULL) {
            currNode->decoderCtx = decoderCtx;
            ret = TryDecodeWithDecoder(poolCtx, currNode);
            if (ret == CRYPT_DECODE_RETRY) {
                continue;
            }
        } else {
            ret = BackToLastLayerDecodeNode(poolCtx, currNode);
        }
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        CRYPT_DECODER_Node **curNodePtr = (CRYPT_DECODER_Node **)BSL_LIST_Curr(poolCtx->decoderPath);
        currNode = curNodePtr == NULL ? NULL : *curNodePtr;
    }

    BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_NO_USABLE_DECODER);
    return CRYPT_DECODE_ERR_NO_USABLE_DECODER;
}

typedef int32_t (*CRYPT_DECODE_ProviderProcessCb)(CRYPT_DECODER_Ctx *decoderCtx, void *args);
typedef struct {
    CRYPT_DECODE_ProviderProcessCb cb;
    void *args;
} CRYPT_DECODE_ProviderProcessArgs;

static int32_t ProcessEachProviderDecoder(CRYPT_EAL_ProvMgrCtx *ctx, void *args)
{
    CRYPT_DECODE_ProviderProcessArgs *processArgs = (CRYPT_DECODE_ProviderProcessArgs *)args;
    CRYPT_DECODER_Ctx *decoderCtx = NULL;
    CRYPT_EAL_AlgInfo *algInfos = NULL;
    int32_t ret;

    if (ctx == NULL || args == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ret = CRYPT_EAL_ProviderQuery(ctx, CRYPT_EAL_OPERAID_DECODER, &algInfos);
    if (ret == CRYPT_NOT_SUPPORT) {
        return CRYPT_SUCCESS;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (int32_t i = 0; algInfos != NULL && algInfos[i].algId != 0; i++) {
        decoderCtx = CRYPT_DECODE_NewDecoderCtxByMethod(algInfos[i].implFunc, ctx, algInfos[i].attr);
        if (decoderCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = processArgs->cb(decoderCtx, processArgs->args);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_DECODE_Free(decoderCtx);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_DECODE_ProviderProcessAll(CRYPT_EAL_LibCtx *ctx, CRYPT_DECODE_ProviderProcessCb cb, void *args)
{
    if (cb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DECODE_ProviderProcessArgs processArgs = {
        .cb = cb,
        .args = args
    };
    int32_t ret = CRYPT_EAL_ProviderProcessAll(ctx, ProcessEachProviderDecoder, &processArgs);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DECODE_PoolDecode(CRYPT_DECODER_PoolCtx *poolCtx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (poolCtx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (*outParam != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = CRYPT_DECODE_ProviderProcessAll(poolCtx->libCtx, CollectDecoder, poolCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BSL_LIST_COUNT(poolCtx->decoders) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_NO_DECODER);
        return CRYPT_DECODE_ERR_NO_DECODER;
    }
    CRYPT_DECODER_Node *initialNode = CreateDecoderNode(poolCtx->inputFormat, poolCtx->inputType,
        poolCtx->targetFormat, poolCtx->targetType, inParam);
    if (initialNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = BSL_LIST_AddElement(poolCtx->decoderPath, initialNode, BSL_LIST_POS_END);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(initialNode);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return DecodeWithKeyChain(poolCtx, outParam);
}

#endif /* HITLS_CRYPTO_CODECS && HITLS_CRYPTO_PROVIDER */
