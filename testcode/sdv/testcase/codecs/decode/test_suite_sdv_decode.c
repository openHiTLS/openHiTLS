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

/* BEGIN_HEADER */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "sal_file.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "bsl_types.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "decode_local.h"
#include "test.h"
#include "stub_utils.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);


void *malloc_fail(uint32_t size)
{
    (void)size;
    return NULL;
}

/**
 * @test SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC001
 * @brief Test CRYPT_DECODE_ProviderNewCtx API
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_DECODER_Ctx *ctx = NULL;

    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, BSL_CID_DECODE_UNKNOWN, "provider=default, inFormat=PEM, outFormat=ASN1");
    ASSERT_TRUE(ctx != NULL);

    CRYPT_DECODE_Free(ctx);
    ctx = NULL;

    CRYPT_DECODE_Free(NULL);
    /* Test with NULL libCtx */
    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, CRYPT_PKEY_RSA, NULL);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_DECODE_Free(ctx);
    ctx = NULL;

    /* Test with invalid key type */
    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, -1, NULL);
    ASSERT_TRUE(ctx == NULL);
    
    /* Test with valid parameters */
    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, BSL_CID_DECODE_UNKNOWN, "provider=default, inFormat=PEM, outFormat=ASN1");
    ASSERT_TRUE(ctx != NULL);
    CRYPT_DECODE_Free(ctx);
    ctx = NULL;

    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, BSL_CID_DECODE_UNKNOWN, "provider?default, inFormat?PEM");
    ASSERT_TRUE(ctx != NULL);
    CRYPT_DECODE_Free(ctx);
    ctx = NULL;

    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, CRYPT_PKEY_RSA, "provider=default, inFormat=PEM, outFormat=ASN1");
    ASSERT_TRUE(ctx == NULL);

    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, CRYPT_PKEY_RSA, "provider=default, inFormat=ASN1, inType=PRIKEY_RSA");
    ASSERT_TRUE(ctx != NULL);
    CRYPT_DECODE_Free(ctx);
    ctx = NULL;
EXIT:
    CRYPT_DECODE_Free(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC002
 * @brief When no provider is loaded, CRYPT_DECODE_ProviderNewCtx should return NULL
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC002(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_DECODER_Ctx *ctx = NULL;
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, CRYPT_PKEY_RSA, "provider=default, inFormat=ASN1, inType=PRIKEY_RSA");
    ASSERT_TRUE(ctx == NULL);
EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC002
 * @brief When user provider no decoder implement, CRYPT_DECODE_ProviderNewCtx should return NULL
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC003(char *providerPath, char *providerName, int cmd, int keyType)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)providerPath;
    (void)providerName;
    (void)cmd;
    (void)keyType;
    SKIP_TEST();
#else
    CRYPT_DECODER_Ctx *ctx = NULL;
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, providerPath), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, providerName, NULL, NULL), CRYPT_SUCCESS);

    ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, keyType, NULL);
    ASSERT_TRUE(ctx == NULL);
    
EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_SET_PARAM_API_TC001
 * @brief Test CRYPT_DECODE_SetParam API
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_SET_PARAM_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_DECODER_Ctx *ctx = NULL;
    /* Test with NULL ctx */
    BSL_Param param = {0};
    ASSERT_EQ(CRYPT_DECODE_SetParam(NULL, &param), CRYPT_NULL_INPUT);

    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, CRYPT_PKEY_RSA, "provider=default, inFormat=ASN1, inType=PRIKEY_RSA");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_DECODE_SetParam(ctx, NULL), CRYPT_NULL_INPUT);

    ctx->method->setParam = NULL;
    ASSERT_EQ(CRYPT_DECODE_SetParam(ctx, &param), CRYPT_NOT_SUPPORT);
EXIT:
    CRYPT_DECODE_Free(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_GET_PARAM_API_TC001
 * @brief Test CRYPT_DECODE_GetParam API
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_GET_PARAM_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(NULL, CRYPT_PKEY_RSA, "provider=default, inFormat=ASN1, inType=PRIKEY_RSA");
    ASSERT_TRUE(ctx != NULL);

    /* Test with NULL ctx */
    BSL_Param param = {0};
    int32_t ret = CRYPT_DECODE_GetParam(NULL, &param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_DECODE_GetParam(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ctx->method->getParam = NULL;
    ret = CRYPT_DECODE_GetParam(ctx, &param);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);

EXIT:
    CRYPT_DECODE_Free(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_DECODE_API_TC001
 * @title Test CRYPT_DECODE_Decode API
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_DECODE_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(NULL, BSL_CID_DECODE_UNKNOWN, "provider=default, inFormat=PEM, outFormat=ASN1");
    ASSERT_TRUE(ctx != NULL);
    
    /* Test with NULL ctx */
    BSL_Param inParam[2] = {0};
    BSL_Param *outParam = NULL;
    int32_t ret = CRYPT_DECODE_Decode(NULL, inParam, &outParam);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    
    /* Test with NULL inParam */
    ret = CRYPT_DECODE_Decode(ctx, NULL, &outParam);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
        
    /* Test with NULL outParam */
    ret = CRYPT_DECODE_Decode(ctx, inParam, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    /* Test with NULL decode function */
    ctx->method->decode = NULL;
    ret = CRYPT_DECODE_Decode(ctx, inParam, &outParam);
    ASSERT_EQ(ret, CRYPT_NOT_SUPPORT);

EXIT:
    CRYPT_DECODE_Free(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_DECODE_API_TC002
 * @title Test CRYPT_DECODE_Decode API with valid parameters,
 *        Test with valid PEM to ASN1 conversion
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_DECODE_API_TC002(char *pemPath, char *asn1Path)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)pemPath;
    (void)asn1Path;
    SKIP_TEST();
#else
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(NULL, BSL_CID_DECODE_UNKNOWN, "provider=default, inFormat=PEM, outFormat=ASN1");
    ASSERT_TRUE(ctx != NULL);
    
    /* Test with valid PEM to ASN1 conversion */
    uint8_t *pemData = NULL;
    uint32_t pemDataLen = 0;
    uint8_t *asn1Data = NULL;
    uint32_t asn1DataLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(pemPath, &pemData, &pemDataLen), BSL_SUCCESS);

    BSL_Param inParam[2] = {
        {CRYPT_PARAM_DECODE_BUFFER_DATA, BSL_PARAM_TYPE_OCTETS, pemData, pemDataLen, 0},
        BSL_PARAM_END
        };
    BSL_Param *outParam = NULL;
    ASSERT_EQ(CRYPT_DECODE_Decode(ctx, inParam, &outParam), CRYPT_SUCCESS);
    ASSERT_TRUE(outParam != NULL);
    ASSERT_TRUE(outParam->value != NULL);
    ASSERT_TRUE(outParam->valueLen > 0);
    ASSERT_EQ(BSL_SAL_ReadFile(asn1Path, &asn1Data, &asn1DataLen), BSL_SUCCESS);
    ASSERT_EQ(outParam->valueLen, asn1DataLen);
    ASSERT_EQ(memcmp(outParam->value, asn1Data, asn1DataLen), 0);

EXIT:
    BSL_SAL_Free(pemData);
    BSL_SAL_Free(asn1Data);
    if (outParam != NULL) {
        CRYPT_DECODE_FreeOutData(ctx, outParam);
    }
    CRYPT_DECODE_Free(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_FREE_OUT_DATA_API_TC001
 * @title Test CRYPT_DECODE_FreeOutData API
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_FREE_OUT_DATA_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    /* Test with NULL ctx */
    BSL_Param outData = {0};
    CRYPT_DECODE_FreeOutData(NULL, &outData);

    /* Test with NULL outData */
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(NULL, BSL_CID_DECODE_UNKNOWN, "provider=default, inFormat=PEM, outFormat=ASN1");
    ASSERT_TRUE(ctx != NULL);
    CRYPT_DECODE_FreeOutData(ctx, NULL);

    ctx->method->freeOutData = NULL;
    CRYPT_DECODE_FreeOutData(ctx, &outData);

EXIT:
    CRYPT_DECODE_Free(ctx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_NEW_CTX_API_TC001
 * @title Test CRYPT_DECODE_PoolNewCtx API
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_NEW_CTX_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_PKEY_RSA, "PEM", "PRIKEY_RSA");
    ASSERT_TRUE(poolCtx != NULL);

    CRYPT_DECODE_PoolFreeCtx(poolCtx);
    poolCtx = NULL;

    CRYPT_DECODE_PoolFreeCtx(NULL);

    /* Test with malloc failed */
    STUB_REPLACE(BSL_SAL_Malloc, malloc_fail);

    TestMemInit();

    poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_PKEY_RSA, "PEM", "PRIKEY_RSA");
    ASSERT_TRUE(poolCtx == NULL);

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_DECODE_PoolFreeCtx(poolCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_DECODE_API_TC001
 * @title Test CRYPT_DECODE_PoolDecode API with invalid parameters
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_DECODE_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_PKEY_RSA, "PEM", "PRIKEY_RSA");
    ASSERT_TRUE(poolCtx != NULL);
    
    /* Test with NULL poolCtx */
    BSL_Param inParam[2] = {0};
    BSL_Param *outParam = NULL;
    ASSERT_EQ(CRYPT_DECODE_PoolDecode(NULL, inParam, &outParam), CRYPT_NULL_INPUT);
    
    /* Test with NULL inParam */
    ASSERT_EQ(CRYPT_DECODE_PoolDecode(poolCtx, NULL, &outParam), CRYPT_NULL_INPUT);
    
    /* Test with NULL outParam */
    ASSERT_EQ(CRYPT_DECODE_PoolDecode(poolCtx, inParam, NULL), CRYPT_NULL_INPUT);

    /* Test with invalid outParam */
    outParam = inParam;
    ASSERT_EQ(CRYPT_DECODE_PoolDecode(poolCtx, inParam, &outParam), CRYPT_INVALID_ARG);

    /* Test with invalid input data */
    uint8_t invalidData[] = "Invalid PEM data";
    inParam[0].valueType = BSL_PARAM_TYPE_OCTETS;
    inParam[0].value = invalidData;
    inParam[0].valueLen = sizeof(invalidData);
    ASSERT_EQ(CRYPT_DECODE_PoolDecode(poolCtx, inParam, &outParam), CRYPT_DECODE_ERR_NO_USABLE_DECODER);

    

EXIT:
    CRYPT_DECODE_PoolFreeCtx(poolCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_DECODE_API_TC002
 * @title Test CRYPT_DECODE_PoolDecode API with valid parameters
 * @precon None
 * @brief
 *    1. Test with valid parameters
 *    2. Test with valid PEM to ASN1 conversion
 * @expect
 *    1. Return CRYPT_SUCCESS
 *    2. Return CRYPT_SUCCESS and output data matches expected
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_DECODE_API_TC002(char *inputFormat, char *inputType, char *path, char *targetFormat,
    char *targetType, char *targetPath)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)inputFormat;
    (void)inputType;
    (void)path;
    (void)targetFormat;
    (void)targetType;
    (void)targetPath;
    SKIP_TEST();
#else
    if (strcmp(inputFormat, "NULL") == 0) {
        inputFormat = NULL;
    }
    if (strcmp(inputType, "NULL") == 0) {
        inputType = NULL;
    }
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, BSL_CID_DECODE_UNKNOWN, inputFormat, inputType);
    ASSERT_TRUE(poolCtx != NULL);
    
    /* Test with valid PEM to ASN1 conversion */
    uint8_t *inputData = NULL;
    uint32_t inputDataLen = 0;
    uint8_t *outputData = NULL;
    uint32_t outputDataLen = 0;
    bool isFreeOutData = true;
    ASSERT_EQ(BSL_SAL_ReadFile(path, &inputData, &inputDataLen), BSL_SUCCESS);

    BSL_Param inParam[2] = {
        {CRYPT_PARAM_DECODE_BUFFER_DATA, BSL_PARAM_TYPE_OCTETS, inputData, inputDataLen, 0},
        BSL_PARAM_END
    };
    BSL_Param *outParam = NULL;
    
    /* Set target format and type */
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT, targetFormat,
        strlen(targetFormat)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE, targetType,
        strlen(targetType)), CRYPT_SUCCESS);
    
    ASSERT_EQ(CRYPT_DECODE_PoolDecode(poolCtx, inParam, &outParam), CRYPT_SUCCESS);
    ASSERT_TRUE(outParam != NULL);
    ASSERT_TRUE(outParam->value != NULL);
    ASSERT_TRUE(outParam->valueLen > 0);
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA, &isFreeOutData,
        sizeof(bool)), CRYPT_SUCCESS);

    if (outParam->key == CRYPT_PARAM_DECODE_BUFFER_DATA) {
        ASSERT_EQ(BSL_SAL_ReadFile(targetPath, &outputData, &outputDataLen), BSL_SUCCESS);
        ASSERT_EQ(outParam->valueLen, outputDataLen);
        ASSERT_EQ(memcmp(outParam->value, outputData, outputDataLen), 0);
    } else if (outParam->key == CRYPT_PARAM_DECODE_OBJECT_DATA) {
        ASSERT_NE(outParam->value, NULL);
    }
EXIT:
    BSL_SAL_Free(inputData);
    BSL_SAL_Free(outputData);
    CRYPT_DECODE_PoolFreeCtx(poolCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_CTRL_API_TC001
 * @title Test CRYPT_DECODE_PoolCtrl API with valid parameters and boundary conditions
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_CTRL_API_TC001(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_PKEY_RSA, "PEM", "PRIKEY_RSA");
    ASSERT_TRUE(poolCtx != NULL);

    /* Test setting target format */
    const char *targetFormat = "ASN1";
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT, (void *)targetFormat,
        strlen(targetFormat)), CRYPT_SUCCESS);
    ASSERT_EQ(poolCtx->targetFormat, targetFormat);

    /* Test setting target type */
    const char *targetType = "PRIKEY_RSA";
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE, (void *)targetType,
        strlen(targetType)), CRYPT_SUCCESS);
    ASSERT_EQ(poolCtx->targetType, targetType);

    /* Test setting free output data flag */
    bool isFreeOutData = true;
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA, &isFreeOutData,
        sizeof(bool)), CRYPT_SUCCESS);

    /* Test with invalid format length */
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT, (void *)targetFormat,
        MAX_CRYPT_DECODE_FORMAT_TYPE_SIZE + 1), CRYPT_INVALID_ARG);

    /* Test with invalid type length */
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE, (void *)targetType,
        MAX_CRYPT_DECODE_FORMAT_TYPE_SIZE + 1), CRYPT_INVALID_ARG);

    /* Test with invalid flag size */
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA, &isFreeOutData,
        sizeof(bool) + 1), CRYPT_INVALID_ARG);
    
    /* Test with invalid command */
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, 0xFFFFFFFF, &isFreeOutData, sizeof(bool)), CRYPT_INVALID_ARG);

EXIT:
    CRYPT_DECODE_PoolFreeCtx(poolCtx);
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_PROVIDER
static void FreeDecoderNode(CRYPT_DECODER_Node *decoderNode)
{
    if (decoderNode == NULL) {
        return;
    }
    CRYPT_DECODE_FreeOutData(decoderNode->decoderCtx, decoderNode->outData.data);
    BSL_SAL_Free(decoderNode);
}
#endif

/**
 * @test SDV_CRYPT_DECODE_POOL_CTRL_API_TC002
 * @title Test CRYPT_DECODE_PoolCtrl CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA with valid parameters and boundary
 *  conditions
 * @precon None
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_CTRL_API_TC002(void)
{
#ifndef HITLS_CRYPTO_PROVIDER
    SKIP_TEST();
#else
    BSL_Param *outParam = NULL;
    bool isFreeOutData = true;
    uint8_t *inputData = NULL;
    uint32_t inputDataLen = 0;
    CRYPT_DECODER_PoolCtx *poolCtx = NULL;
    ASSERT_EQ(BSL_SAL_ReadFile("../testdata/cert/asn1/rsa2048key_pkcs1.pem", &inputData, &inputDataLen), BSL_SUCCESS);
    BSL_Param inParam[2] = {
        {CRYPT_PARAM_DECODE_BUFFER_DATA, BSL_PARAM_TYPE_OCTETS, inputData, inputDataLen, 0},
        BSL_PARAM_END
    };
    poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_PKEY_RSA, "PEM", "PRIKEY_RSA");
    ASSERT_TRUE(poolCtx != NULL);

    /* Manually clear the decoder path to simulate no nodes condition */
    if (poolCtx->decoderPath != NULL) {
        BSL_LIST_FREE(poolCtx->decoderPath, (BSL_LIST_PFUNC_FREE)FreeDecoderNode);
    }
    
    /* Now test the control operation with empty decoder path */
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA, 
        &isFreeOutData, sizeof(bool)), CRYPT_INVALID_ARG);

    CRYPT_DECODE_PoolFreeCtx(poolCtx);
    poolCtx = NULL;
    /* Test when decoderPath has only one node (input equals output) */
    poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_PKEY_RSA, "PEM", "PRIKEY_RSA");
    ASSERT_TRUE(poolCtx != NULL);
    const char *targetFormat = "PEM";
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT, (void *)targetFormat,
        strlen(targetFormat)), CRYPT_SUCCESS);
    ASSERT_EQ(poolCtx->targetFormat, targetFormat);

    const char *targetType = "PRIKEY_RSA";
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE, (void *)targetType,
        strlen(targetType)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_DECODE_PoolDecode(poolCtx, inParam, &outParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA, 
        &isFreeOutData, sizeof(bool)), CRYPT_SUCCESS);

    CRYPT_DECODE_PoolFreeCtx(poolCtx);
    poolCtx = NULL;
    outParam = NULL;

    /* Test isFreeOutData is false */
    poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_PKEY_RSA, "PEM", "PRIKEY_RSA");
    ASSERT_TRUE(poolCtx != NULL);
    targetFormat = "ASN1";
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT, (void *)targetFormat,
        strlen(targetFormat)), CRYPT_SUCCESS);
    targetType = "PRIKEY_RSA";
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE, (void *)targetType,
        strlen(targetType)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_DECODE_PoolDecode(poolCtx, inParam, &outParam), CRYPT_SUCCESS);
    isFreeOutData = false;
    ASSERT_EQ(CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA, 
        &isFreeOutData, sizeof(bool)), CRYPT_SUCCESS);
    BSL_SAL_FREE(outParam->value);
    BSL_SAL_FREE(outParam);

EXIT:
    BSL_SAL_Free(inputData);
    CRYPT_DECODE_PoolFreeCtx(poolCtx);
#endif
}
/* END_CASE */
