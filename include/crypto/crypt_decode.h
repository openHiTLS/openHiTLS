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

#ifndef CRYPT_DECODE_H
#define CRYPT_DECODE_H

#include <stdint.h>
#include "bsl_params.h"
#include "bsl_list.h"
#include "crypt_eal_provider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct CRYPT_DecoderCtx CRYPT_DECODER_Ctx;

/**
 * @brief Create a decoder context for the specified format and type
 * 
 * @param libCtx EAL library context
 * @param keyType Decoding target type (e.g., CRYPT_ALG_ID_RSA, CRYPT_ALG_ID_EC)
 * @param attrName Attribute name for specific type decoding (can be NULL)
 * @return CRYPT_DECODER_Ctx* Decoder context, returns NULL on failure
 */
CRYPT_DECODER_Ctx *CRYPT_DECODE_ProviderNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t keyType, const char *attrName);

/**
 * @brief Free the decoder context
 * 
 * @param ctx Decoder context
 */
void CRYPT_DECODE_Free(CRYPT_DECODER_Ctx *ctx);

/**
 * @brief Set decoder parameters
 * 
 * @param ctx Decoder context
 * @param param Parameter
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_DECODE_SetParam(CRYPT_DECODER_Ctx *ctx, const BSL_Param *param);

/**
 * @brief Get decoder parameters
 * 
 * @param ctx Decoder context
 * @param param Parameter (output)
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_DECODE_GetParam(CRYPT_DECODER_Ctx *ctx, BSL_Param *param);

/**
 * @brief Perform decoding operation
 * 
 * @param ctx Decoder context
 * @param input Input data
 * @param inParam Input parameter
 * @param out Output object to store decoding results
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_DECODE_Decode(CRYPT_DECODER_Ctx *ctx, const BSL_Param *inParam, BSL_Param **outParam);

/**
 * @brief Free the output data
 * 
 * @param ctx Decoder context
 * @param data Output data
 */
void CRYPT_DECODE_FreeOutData(CRYPT_DECODER_Ctx *ctx, BSL_Param *outData);

typedef struct _CRYPT_DECODER_PoolCtx CRYPT_DECODER_PoolCtx;

/**
 * @brief Command codes for CRYPT_DECODE_PoolCtrl function
 */
typedef enum {
    /** Set the target format */
    CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT,
    /** Set the target type */
    CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE,
    /** Set the not free out data */
    CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA,
} CRYPT_DECODE_POOL_CMD;

/**
 * @brief Create a decoder pool context
 * 
 * @param libCtx EAL library context
 * @param attrName Provider attribute name, can be NULL
 * @param format Input data format (e.g., BSL_FORMAT_PEM, BSL_FORMAT_DER)
 * @param type Decoding target type (e.g., CRYPT_ALG_ID_RSA, CRYPT_ALG_ID_EC)
 * @return CRYPT_DECODER_PoolCtx* Decoder pool context on success, NULL on failure
 */
CRYPT_DECODER_PoolCtx *CRYPT_DECODE_PoolNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    int32_t keyType, const char *format, const char *type);
/**
 * @brief Free a decoder pool context
 * 
 * @param poolCtx Decoder pool context
 */
void CRYPT_DECODE_PoolFreeCtx(CRYPT_DECODER_PoolCtx *poolCtx);

/**
 * @brief Decode the input data with the decoder chain
 * 
 * @param poolCtx Decoder pool context
 * @param inParam Input data
 * @param outParam Output Data
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_DECODE_PoolDecode(CRYPT_DECODER_PoolCtx *poolCtx, BSL_Param *inParam, BSL_Param **outParam);

/**
 * @brief Control operation for decoder pool
 * 
 * @param poolCtx Decoder pool context
 * @param cmd Control command
 * @param val The value of the control command
 * @param valLen The length of the value
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_DECODE_PoolCtrl(CRYPT_DECODER_PoolCtx *poolCtx, int32_t cmd, void *val, int32_t valLen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CRYPT_DECODE_H */