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
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_eal_pkey.h"
#include "crypt_decode.h"
#include "bsl_types.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "decode_local.h"
/* END_HEADER */

/**
 * @test SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC001
 * @title Test CRYPT_DECODE_ProviderNewCtx API
 * @precon None
 * @brief
 *    1. Test with NULL libCtx
 *    2. Test with invalid key type
 *    3. Test with valid parameters
 * @expect
 *    1. Return NULL
 *    2. Return NULL
 *    3. Return valid context
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_PROVIDER_NEW_CTX_API_TC001(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_Ctx *ctx = NULL;
    
    /* Test with NULL libCtx */
    ctx = CRYPT_DECODE_ProviderNewCtx(NULL, CRYPT_ALG_ID_RSA, NULL);
    ASSERT_TRUE(ctx == NULL);
    
    /* Test with invalid key type */
    ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, -1, NULL);
    ASSERT_TRUE(ctx == NULL);
    
    /* Test with valid parameters */
    ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, CRYPT_ALG_ID_RSA, "test_attr");
    ASSERT_TRUE(ctx != NULL);
    CRYPT_DECODE_Free(ctx);
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_FREE_API_TC001
 * @title Test CRYPT_DECODE_Free API
 * @precon None
 * @brief
 *    1. Test with NULL ctx
 *    2. Test with valid ctx
 * @expect
 *    1. No crash
 *    2. No crash
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_FREE_API_TC001(void)
{
    /* Test with NULL ctx */
    CRYPT_DECODE_Free(NULL);
    
    /* Test with valid ctx */
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, CRYPT_ALG_ID_RSA, "test_attr");
    if (ctx != NULL) {
        CRYPT_DECODE_Free(ctx);
    }
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_SET_PARAM_API_TC001
 * @title Test CRYPT_DECODE_SetParam API
 * @precon None
 * @brief
 *    1. Test with NULL ctx
 *    2. Test with NULL param
 * @expect
 *    1. Return CRYPT_NULL_INPUT
 *    2. Return CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_SET_PARAM_API_TC001(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, CRYPT_ALG_ID_RSA, "test_attr");
    
    /* Test with NULL ctx */
    BSL_Param param = {0};
    int32_t ret = CRYPT_DECODE_SetParam(NULL, &param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    
    /* Test with NULL param */
    if (ctx != NULL) {
        ret = CRYPT_DECODE_SetParam(ctx, NULL);
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
        CRYPT_DECODE_Free(ctx);
    }
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_GET_PARAM_API_TC001
 * @title Test CRYPT_DECODE_GetParam API
 * @precon None
 * @brief
 *    1. Test with NULL ctx
 *    2. Test with NULL param
 * @expect
 *    1. Return CRYPT_NULL_INPUT
 *    2. Return CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_GET_PARAM_API_TC001(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, CRYPT_ALG_ID_RSA, "test_attr");
    
    /* Test with NULL ctx */
    BSL_Param param = {0};
    int32_t ret = CRYPT_DECODE_GetParam(NULL, &param);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    
    /* Test with NULL param */
    if (ctx != NULL) {
        ret = CRYPT_DECODE_GetParam(ctx, NULL);
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
        CRYPT_DECODE_Free(ctx);
    }
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_DECODE_API_TC001
 * @title Test CRYPT_DECODE_Decode API
 * @precon None
 * @brief
 *    1. Test with NULL ctx
 *    2. Test with NULL inParam
 *    3. Test with NULL outParam
 * @expect
 *    1. Return CRYPT_NULL_INPUT
 *    2. Return CRYPT_NULL_INPUT
 *    3. Return CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_DECODE_API_TC001(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, CRYPT_ALG_ID_RSA, "test_attr");
    
    /* Test with NULL ctx */
    BSL_Param inParam = {0};
    BSL_Param *outParam = NULL;
    int32_t ret = CRYPT_DECODE_Decode(NULL, &inParam, &outParam);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    
    /* Test with NULL inParam */
    if (ctx != NULL) {
        ret = CRYPT_DECODE_Decode(ctx, NULL, &outParam);
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
        
        /* Test with NULL outParam */
        ret = CRYPT_DECODE_Decode(ctx, &inParam, NULL);
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
        
        CRYPT_DECODE_Free(ctx);
    }
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_FREE_OUT_DATA_API_TC001
 * @title Test CRYPT_DECODE_FreeOutData API
 * @precon None
 * @brief
 *    1. Test with NULL ctx
 *    2. Test with NULL outData
 * @expect
 *    1. No crash
 *    2. No crash
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_FREE_OUT_DATA_API_TC001(void)
{
    /* Test with NULL ctx */
    BSL_Param outData = {0};
    CRYPT_DECODE_FreeOutData(NULL, &outData);
    
    /* Test with NULL outData */
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_Ctx *ctx = CRYPT_DECODE_ProviderNewCtx(libCtx, CRYPT_ALG_ID_RSA, "test_attr");
    if (ctx != NULL) {
        CRYPT_DECODE_FreeOutData(ctx, NULL);
        CRYPT_DECODE_Free(ctx);
    }
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_NEW_CTX_API_TC001
 * @title Test CRYPT_DECODE_PoolNewCtx API
 * @precon None
 * @brief
 *    1. Test with NULL libCtx
 *    2. Test with invalid key type
 *    3. Test with valid parameters
 * @expect
 *    1. Return NULL
 *    2. Return NULL
 *    3. Return valid context
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_NEW_CTX_API_TC001(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    
    /* Test with NULL libCtx */
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(NULL, NULL, CRYPT_ALG_ID_RSA, "PEM", "RSA");
    ASSERT_TRUE(poolCtx == NULL);
    
    /* Test with invalid key type */
    poolCtx = CRYPT_DECODE_PoolNewCtx(libCtx, NULL, -1, "PEM", "RSA");
    ASSERT_TRUE(poolCtx == NULL);
    
    /* Test with valid parameters */
    poolCtx = CRYPT_DECODE_PoolNewCtx(libCtx, "test_attr", CRYPT_ALG_ID_RSA, "PEM", "RSA");
    ASSERT_TRUE(poolCtx != NULL);
    CRYPT_DECODE_PoolFreeCtx(poolCtx);
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_FREE_CTX_API_TC001
 * @title Test CRYPT_DECODE_PoolFreeCtx API
 * @precon None
 * @brief
 *    1. Test with NULL poolCtx
 *    2. Test with valid poolCtx
 * @expect
 *    1. No crash
 *    2. No crash
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_FREE_CTX_API_TC001(void)
{
    /* Test with NULL poolCtx */
    CRYPT_DECODE_PoolFreeCtx(NULL);
    
    /* Test with valid poolCtx */
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(libCtx, "test_attr", CRYPT_ALG_ID_RSA, "PEM", "RSA");
    if (poolCtx != NULL) {
        CRYPT_DECODE_PoolFreeCtx(poolCtx);
    }
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_DECODE_API_TC001
 * @title Test CRYPT_DECODE_PoolDecode API
 * @precon None
 * @brief
 *    1. Test with NULL poolCtx
 *    2. Test with NULL outParam
 * @expect
 *    1. Return CRYPT_NULL_INPUT
 *    2. Return CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_DECODE_API_TC001(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(libCtx, "test_attr", CRYPT_ALG_ID_RSA, "PEM", "RSA");
    
    /* Test with NULL poolCtx */
    BSL_Param *outParam = NULL;
    int32_t ret = CRYPT_DECODE_PoolDecode(NULL, &outParam);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    
    /* Test with NULL outParam */
    if (poolCtx != NULL) {
        ret = CRYPT_DECODE_PoolDecode(poolCtx, NULL);
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
        CRYPT_DECODE_PoolFreeCtx(poolCtx);
    }
}
/* END_CASE */

/**
 * @test SDV_CRYPT_DECODE_POOL_CTRL_API_TC001
 * @title Test CRYPT_DECODE_PoolCtrl API
 * @precon None
 * @brief
 *    1. Test with NULL poolCtx
 *    2. Test with NULL val
 *    3. Test with invalid cmd
 * @expect
 *    1. Return CRYPT_NULL_INPUT
 *    2. Return CRYPT_NULL_INPUT
 *    3. Return CRYPT_INVALID_ARG
 */
/* BEGIN_CASE */
void SDV_CRYPT_DECODE_POOL_CTRL_API_TC001(void)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(libCtx, "test_attr", CRYPT_ALG_ID_RSA, "PEM", "RSA");
    
    /* Test with NULL poolCtx */
    int32_t ret = CRYPT_DECODE_PoolCtrl(NULL, CRYPT_DECODE_POOL_CMD_SET_SOURCE_DATA, NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    
    /* Test with NULL val */
    if (poolCtx != NULL) {
        ret = CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_SOURCE_DATA, NULL, 0);
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
        
        /* Test with invalid cmd */
        BSL_Param param = {0};
        ret = CRYPT_DECODE_PoolCtrl(poolCtx, -1, &param, sizeof(param));
        ASSERT_EQ(ret, CRYPT_INVALID_ARG);
        
        CRYPT_DECODE_PoolFreeCtx(poolCtx);
    }
}
/* END_CASE */
