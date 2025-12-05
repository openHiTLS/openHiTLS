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

/**
 * @defgroup crypt_eal_encode
 * @ingroup crypt
 * @brief pubkey encode/decode of crypto module
 */

#ifndef CRYPT_EAL_ENCODE_H
#define CRYPT_EAL_ENCODE_H

#include <stdint.h>

#include "bsl_params.h"
#include "bsl_types.h"
#include "bsl_list.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

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

typedef struct CRYPT_DECODER_PoolCtx CRYPT_DECODER_PoolCtx;

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
int32_t CRYPT_DECODE_PoolDecode(CRYPT_DECODER_PoolCtx *poolCtx, const BSL_Param *inParam, BSL_Param **outParam);

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

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted buffer of pkey
 *
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [IN] the encoded asn1 buffer.
 *          BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 *          the dataLen should exclude the end '\0'
 * @param   pwd [IN] the password, maybe NULL for unencrypted private key / public key.
 * @param   pwdlen [IN] the length of password.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the ans1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_DecodeBuffKey(int32_t format, int32_t type,
    BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted buffer of pkey with provider
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   keyType [IN] the type of pkey.
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [IN] the encoded asn1 buffer.
 *          BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 *          the dataLen should exclude the end '\0'
 * @param   pwd [IN] the password buffer, maybe NULL for unencrypted private key / public key.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the ans1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderDecodeBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t keyType,
    const char *format, const char *type, BSL_Buffer *encode, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted file of pkey
 *
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 * @param   pwd [IN] the password, maybe NULL for unencrypted private key / public key.
 * @param   pwdlen [IN] the length of password.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_DecodeFileKey(int32_t format, int32_t type, const char *path,
    uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted file of pkey with extended parameters
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 * @param   pwd [IN] the password buffer, maybe NULL for unencrypted private key / public key.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderDecodeFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t keyType,
    const char *format, const char *type, const char *path, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted buffer of pkey
 *
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [OUT] the encoded asn1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_EncodeBuffKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, BSL_Buffer *encode);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted buffer of pkey with provider
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [OUT] the encoded asn1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderEncodeBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, const char *format, const char *type, BSL_Buffer *encode);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted file of pkey
 *
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_EncodeFileKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, const char *path);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted file of pkey with provider
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderEncodeFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, const char *format, const char *type, const char *path);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_ENCODE_H