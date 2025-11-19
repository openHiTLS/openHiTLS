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
#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) && defined(HITLS_CRYPTO_PROVIDER)
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#include "crypt_provider.h"
#include "crypt_params_key.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "eal_pkey.h"
#include "crypt_decoder.h"
#include "bsl_err_internal.h"

typedef struct {
    CRYPT_EAL_LibCtx *libCtx;
    const char *targetAttrName;
    const char *outFormat;
    const char *outType;
} DECODER_Lowkey2PkeyCtx;

void *DECODER_LowKeyObject2PkeyObjectNewCtx(void *provCtx)
{
    (void)provCtx;
    DECODER_Lowkey2PkeyCtx *ctx = (DECODER_Lowkey2PkeyCtx *)BSL_SAL_Calloc(1, sizeof(DECODER_Lowkey2PkeyCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ctx->outFormat = "OBJECT";
    ctx->outType = "HIGH_KEY";
    return (void *)ctx;
}

int32_t DECODER_LowKeyObject2PkeyObjectSetParam(void *ctx, const BSL_Param *param)
{
    DECODER_Lowkey2PkeyCtx *decoderCtx = (DECODER_Lowkey2PkeyCtx *)ctx;
    if (decoderCtx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *libCtxParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_LIB_CTX);
    if (libCtxParam != NULL) {
        if (libCtxParam->valueType != BSL_PARAM_TYPE_CTX_PTR) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        decoderCtx->libCtx = (CRYPT_EAL_LibCtx *)(uintptr_t)libCtxParam->value;
    }
    const BSL_Param *targetAttrNameParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_TARGET_ATTR_NAME);
    if (targetAttrNameParam != NULL) {
        if (targetAttrNameParam->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        decoderCtx->targetAttrName = (const char *)(uintptr_t)targetAttrNameParam->value;
    }

    return CRYPT_SUCCESS;
}

int32_t DECODER_LowKeyObject2PkeyObjectGetParam(void *ctx, BSL_Param *param)
{
    DECODER_Lowkey2PkeyCtx *decoderCtx = (DECODER_Lowkey2PkeyCtx *)ctx;
    if (decoderCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    DECODER_CommonCtx commonCtx = {
        .outFormat = decoderCtx->outFormat,
        .outType = decoderCtx->outType
    };
    return DECODER_CommonGetParam(&commonCtx, param);
}
typedef struct LowKeyObjectMethodInfo {
    CRYPT_EAL_ImplPkeyMgmtExport export;
    CRYPT_EAL_ImplPkeyMgmtDupCtx dupCtx;
    CRYPT_EAL_ImplPkeyMgmtFreeCtx freeCtx;
} LowKeyObjectMethodInfo;

static int32_t GetLowKeyObjectInfo(const BSL_Param *inParam, void **object, int32_t *objectType,
    LowKeyObjectMethodInfo *method)
{
    const BSL_Param *lowObjectRef = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_OBJECT_DATA);
    if (lowObjectRef == NULL || lowObjectRef->valueType != BSL_PARAM_TYPE_CTX_PTR) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const BSL_Param *lowObjectRefType = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_OBJECT_TYPE);
    if (lowObjectRefType == NULL || lowObjectRefType->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const BSL_Param *exportFunc = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_PKEY_EXPORT_METHOD_FUNC);
    if (exportFunc == NULL || exportFunc->valueType != BSL_PARAM_TYPE_FUNC_PTR) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const BSL_Param *dupFunc = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_PKEY_DUP_METHOD_FUNC);
    if (dupFunc == NULL || dupFunc->valueType != BSL_PARAM_TYPE_FUNC_PTR) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const BSL_Param *freeFunc = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_PKEY_FREE_METHOD_FUNC);
    if (freeFunc == NULL || freeFunc->valueType != BSL_PARAM_TYPE_FUNC_PTR) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (lowObjectRef->value == NULL || lowObjectRefType->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    *object = (void *)(uintptr_t)lowObjectRef->value;
    *objectType = *((int32_t *)(uintptr_t)lowObjectRefType->value);
    method->export = (CRYPT_EAL_ImplPkeyMgmtExport)(uintptr_t)exportFunc->value;
    method->dupCtx = (CRYPT_EAL_ImplPkeyMgmtDupCtx)(uintptr_t)dupFunc->value;
    method->freeCtx = (CRYPT_EAL_ImplPkeyMgmtFreeCtx)(uintptr_t)freeFunc->value;
    return CRYPT_SUCCESS;
}

static int32_t GetProviderInfo(const BSL_Param *inParam, CRYPT_EAL_ProvMgrCtx **lastDecoderProviderCtx)
{
    const BSL_Param *lastDecoderProvCtxParam = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_PROVIDER_CTX);
    if (lastDecoderProvCtxParam != NULL) {
        if (lastDecoderProvCtxParam->valueType != BSL_PARAM_TYPE_CTX_PTR) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        *lastDecoderProviderCtx = (CRYPT_EAL_ProvMgrCtx *)(uintptr_t)lastDecoderProvCtxParam->value;
    }
    return CRYPT_SUCCESS;
}

typedef struct {
    CRYPT_EAL_PkeyMgmtInfo *pkeyAlgInfo;
    void *targetKeyRef;
} ImportTargetPkeyArgs;

static int32_t ImportTargetPkey(const BSL_Param *param, void *args)
{
    if (param == NULL || args == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ImportTargetPkeyArgs *importTargetPkeyArgs = (ImportTargetPkeyArgs *)args;
    void *provCtx = NULL;
    CRYPT_EAL_PkeyMgmtInfo *pkeyAlgInfo = importTargetPkeyArgs->pkeyAlgInfo;
    if (pkeyAlgInfo == NULL || pkeyAlgInfo->keyMgmtMethod.provNewCtx == NULL ||
        pkeyAlgInfo->keyMgmtMethod.import == NULL || pkeyAlgInfo->keyMgmtMethod.freeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_EAL_ProviderCtrl(pkeyAlgInfo->mgrCtx, CRYPT_PROVIDER_GET_USER_CTX, &provCtx, sizeof(provCtx));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    void *keyRef = pkeyAlgInfo->keyMgmtMethod.provNewCtx(provCtx, pkeyAlgInfo->algId);
    if (keyRef == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = pkeyAlgInfo->keyMgmtMethod.import(keyRef, param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        pkeyAlgInfo->keyMgmtMethod.freeCtx(keyRef);
        return ret;
    }
    importTargetPkeyArgs->targetKeyRef = keyRef;
    return CRYPT_SUCCESS;
}

static int32_t TransLowKeyToTargetLowKey(CRYPT_EAL_PkeyMgmtInfo *pkeyAlgInfo, const LowKeyObjectMethodInfo *method,
    void *lowObjectRef, void **targetKeyRef)
{
    ImportTargetPkeyArgs importTargetPkeyArgs = {0};
    importTargetPkeyArgs.pkeyAlgInfo = pkeyAlgInfo;
    
    if (method->export == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param param[3] = {
        {CRYPT_PARAM_PKEY_PROCESS_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ImportTargetPkey, 0, 0},
        {CRYPT_PARAM_PKEY_PROCESS_ARGS, BSL_PARAM_TYPE_CTX_PTR, &importTargetPkeyArgs, 0, 0},
        BSL_PARAM_END
    };
    int32_t ret = method->export(lowObjectRef, param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *targetKeyRef = importTargetPkeyArgs.targetKeyRef;
    return CRYPT_SUCCESS;
}

static int32_t DupLowKey(const LowKeyObjectMethodInfo *method, void *lowObjectRef, void **targetKeyRef)
{
    if (method->dupCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *targetKeyRef = method->dupCtx(lowObjectRef);
    if (*targetKeyRef == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t ConstructOutObjectParam(BSL_Param **outParam, void *object)
{
    BSL_Param *result = BSL_SAL_Calloc(2, sizeof(BSL_Param));
    if (result == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BSL_PARAM_InitValue(&result[0], CRYPT_PARAM_DECODE_OBJECT_DATA, BSL_PARAM_TYPE_CTX_PTR,
        object, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(result);
        BSL_ERR_PUSH_ERROR(ret);
    }
    *outParam = result;
    return ret;
}

/* input is pem format buffer, output is der format buffer */
int32_t DECODER_LowKeyObject2PkeyObjectDecode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    DECODER_Lowkey2PkeyCtx *decoderCtx = (DECODER_Lowkey2PkeyCtx *)ctx;
    void *lowObjectRef = NULL;
    int32_t lowObjectRefType = 0;
    CRYPT_EAL_ProvMgrCtx *lastDecoderProviderCtx = NULL;
    LowKeyObjectMethodInfo method = {0};
    void *targetKeyRef = NULL;
    CRYPT_EAL_PkeyMgmtInfo pkeyAlgInfo = {0};
    int32_t ret = 0;
    RETURN_RET_IF_ERR(GetLowKeyObjectInfo(inParam, &lowObjectRef, &lowObjectRefType, &method), ret);
    if (method.freeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    RETURN_RET_IF_ERR(GetProviderInfo(inParam, &lastDecoderProviderCtx), ret);
    RETURN_RET_IF_ERR(CRYPT_EAL_GetPkeyAlgInfo(decoderCtx->libCtx, lowObjectRefType, decoderCtx->targetAttrName,
        &pkeyAlgInfo), ret);
    if (pkeyAlgInfo.mgrCtx != lastDecoderProviderCtx) {
        ret = TransLowKeyToTargetLowKey(&pkeyAlgInfo, &method, lowObjectRef, &targetKeyRef);
    } else {
        ret = DupLowKey(&method, lowObjectRef, &targetKeyRef);
    }
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    CRYPT_EAL_PkeyCtx *ealPKey = CRYPT_EAL_MakeKeyByPkeyAlgInfo(&pkeyAlgInfo, targetKeyRef);
    if (ealPKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto EXIT;
    }
    ret = ConstructOutObjectParam(outParam, ealPKey);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ealPKey);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;

EXIT:
    if (targetKeyRef != NULL) {
        method.freeCtx(targetKeyRef);
    }
    return ret;
}

void DECODER_LowKeyObject2PkeyObjectFreeOutData(void *ctx, BSL_Param *outParam)
{
    DECODER_Lowkey2PkeyCtx *decoderCtx = (DECODER_Lowkey2PkeyCtx *)ctx;
    if (outParam == NULL || decoderCtx == NULL) {
        return;
    }
    BSL_Param *objectDataParam = BSL_PARAM_FindParam(outParam, CRYPT_PARAM_DECODE_OBJECT_DATA);
    if (objectDataParam == NULL || objectDataParam->valueType != BSL_PARAM_TYPE_CTX_PTR ||
        objectDataParam->value == NULL) {
        return;
    }
    CRYPT_EAL_PkeyCtx *ealPKey = (CRYPT_EAL_PkeyCtx *)objectDataParam->value;
    CRYPT_EAL_PkeyFreeCtx(ealPKey);
    BSL_SAL_Free(outParam);
}

void DECODER_LowKeyObject2PkeyObjectFreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx);
}

#endif /* HITLS_CRYPTO_KEY_DECODE_CHAIN && HITLS_CRYPTO_PROVIDER */