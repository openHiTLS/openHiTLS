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

#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) && defined(HITLS_CRYPTO_KEY_EPKI)
#include <string.h>
#include "crypt_eal_implprovider.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "bsl_types.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "crypt_codecskey_local.h"
#include "crypt_decoder.h"

typedef struct DECODER_EPki2PkiCtx {
    CRYPT_EAL_LibCtx *libCtx;
    const char *attrName;
    const char *outFormat;
    const char *outType;
} DECODER_EPki2PkiCtx;

void *DECODER_EPKI2PKI_NewCtx(void *provCtx)
{
    (void)provCtx;
    DECODER_EPki2PkiCtx *ctx = (DECODER_EPki2PkiCtx *)BSL_SAL_Calloc(1, sizeof(DECODER_EPki2PkiCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->outFormat = "ASN1";
    ctx->outType = "PRIKEY_PKCS8_UNENCRYPT";
    return ctx;
}

int32_t DECODER_EPKI2PKI_GetParam(void *ctx, BSL_Param *param)
{
    DECODER_EPki2PkiCtx *decoderCtx = (DECODER_EPki2PkiCtx *)ctx;
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

int32_t DECODER_EPKI2PKI_SetParam(void *ctx, const BSL_Param *param)
{
    DECODER_EPki2PkiCtx *decoderCtx = (DECODER_EPki2PkiCtx *)ctx;
    if (decoderCtx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *attrNameParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_TARGET_ATTR_NAME);
    if (attrNameParam != NULL) {
        if (attrNameParam->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        decoderCtx->attrName = (const char *)attrNameParam->value;
    }
    const BSL_Param *libCtxParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_LIB_CTX);
    if (libCtxParam != NULL) {
        if (libCtxParam->valueType != BSL_PARAM_TYPE_CTX_PTR) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        decoderCtx->libCtx = (CRYPT_EAL_LibCtx *)(uintptr_t)libCtxParam->value;
    }
    return CRYPT_SUCCESS;
}

int32_t DECODER_EPKI2PKI_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    DECODER_EPki2PkiCtx *decoderCtx = (DECODER_EPki2PkiCtx *)ctx;
    if (decoderCtx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *inputParam = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (inputParam == NULL || inputParam->value == NULL || inputParam->valueType != BSL_PARAM_TYPE_OCTETS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const BSL_Param *passParam = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_PASSWORD);
    if (passParam == NULL || passParam->valueType != BSL_PARAM_TYPE_OCTETS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    BSL_Buffer input = {(uint8_t *)(uintptr_t)inputParam->value, inputParam->valueLen};
    BSL_Buffer pwdBuff = {(uint8_t *)(uintptr_t)passParam->value, passParam->valueLen};
    BSL_Buffer decode = {NULL, 0};
    int32_t ret = CRYPT_DECODE_Pkcs8PrvDecrypt(decoderCtx->libCtx, decoderCtx->attrName, &input,
        &pwdBuff, NULL, &decode);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_DECODE_ConstructBufferOutParam(NULL, outParam, decode.data, decode.dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(decode.data, decode.dataLen);
    }
    return ret;
}

void DECODER_EPKI2PKI_FreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx);
}

void DECODER_EPKI2PKI_FreeOutData(void *ctx, BSL_Param *outParam)
{
    (void)ctx;
    if (outParam == NULL) {
        return;
    }
    BSL_Param *dataParam = BSL_PARAM_FindParam(outParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (dataParam == NULL) {
        return;
    }
    BSL_SAL_ClearFree(dataParam->value, dataParam->valueLen);
    BSL_SAL_Free(outParam);
}

#endif /* HITLS_CRYPTO_KEY_DECODE_CHAIN && HITLS_CRYPTO_EPKI2PKI */
