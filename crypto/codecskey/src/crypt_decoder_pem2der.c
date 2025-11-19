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

#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) && defined(HITLS_BSL_PEM)
#include <stdint.h>
#include <string.h>
#include "crypt_eal_implprovider.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_pem_internal.h"
#include "crypt_codecskey_local.h"
#include "crypt_decoder.h"

typedef struct {
    void *provCtx;
    const char *outFormat;
    const char *outType;
} DECODER_Pem2DerCtx;

void *DECODER_Pem2DerNewCtx(void *provCtx)
{
    (void)provCtx;
    DECODER_Pem2DerCtx *ctx = (DECODER_Pem2DerCtx *)BSL_SAL_Calloc(1, sizeof(DECODER_Pem2DerCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->provCtx = provCtx;
    ctx->outFormat = "ASN1";
    ctx->outType = NULL;
    return ctx;
}

int32_t DECODER_Pem2DerGetParam(void *ctx, BSL_Param *param)
{
    DECODER_Pem2DerCtx *decoderCtx = (DECODER_Pem2DerCtx *)ctx;
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

int32_t DECODER_Pem2DerSetParam(void *ctx, const BSL_Param *param)
{
    (void)ctx;
    (void)param;
    return CRYPT_SUCCESS;
}

/* input is pem format buffer, output is der format buffer */
int32_t DECODER_Pem2DerDecode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_PEM_Symbol symbol = {0};
    char *dataType = NULL;
    DECODER_Pem2DerCtx *decoderCtx = (DECODER_Pem2DerCtx *)ctx;
    const BSL_Param *input = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (input == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (input->value == NULL || input->valueLen == 0 || input->valueType != BSL_PARAM_TYPE_OCTETS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    BSL_Buffer encode = {(uint8_t *)(uintptr_t)input->value, input->valueLen};
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    int32_t ret = BSL_PEM_GetSymbolAndType((char *)encode.data, encode.dataLen, &symbol, &dataType);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_PEM_DecodePemToAsn1((char **)&encode.data, &encode.dataLen, &symbol, &asn1Encode, &asn1Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    decoderCtx->outType = dataType;
    ret = CRYPT_DECODE_ConstructBufferOutParam(inParam, outParam, asn1Encode, asn1Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(asn1Encode);
    }
    return ret;
}

void DECODER_Pem2DerFreeOutData(void *ctx, BSL_Param *outParam)
{
    (void)ctx;
    if (outParam == NULL) {
        return;
    }
    BSL_Param *asn1DataParam = BSL_PARAM_FindParam(outParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (asn1DataParam == NULL) {
        return;
    }
    BSL_SAL_Free(asn1DataParam->value);
    asn1DataParam->value = NULL;
    asn1DataParam->valueLen = 0;
    BSL_SAL_Free(outParam);
}

void DECODER_Pem2DerFreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx);
}
#endif /* HITLS_CRYPTO_KEY_DECODE_CHAIN && HITLS_BSL_PEM */
