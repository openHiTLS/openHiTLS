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

#ifndef CRYPT_UTIL_CTRL_H
#define CRYPT_UTIL_CTRL_H

#include "hitls_build.h"

#include <stdint.h>
#include "crypt_local_types.h"
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t (*GetNumCallBack)(const void *arg);

#define CRYPT_CTRL_GET_NUM32_EX(getNumCb, arg, val, len) \
    CRYPT_CTRL_GetNum32Ex((GetNumCallBack)(getNumCb), (arg), (val), (len))

/**
 * @brief   Get 32-bit number
 *
 * @param   num [IN] 32-bit number (non-negative integer)
 * @param   val [OUT] value
 * @param   valLen [IN] length of value
 *
 * @retval  CRYPT_SUCCESS           Value is got successfully.
 * @retval  CRYPT_NULL_INPUT        Value is NULL.
 * @retval  CRYPT_INVALID_ARG       Value length is invalid.
 */
int32_t CRYPT_CTRL_GetNum32(uint32_t num, void *val, uint32_t valLen);

/**
 * @brief   Get int32_t number from data
 *
 * @param   getNumCb [IN] get data callback that returns int32_t
 * @param   cbArg [IN] argument of callback
 * @param   val [OUT] value
 * @param   valLen [IN] length of value
 *
 * @retval  CRYPT_SUCCESS           Value is got successfully.
 * @retval  CRYPT_NULL_INPUT        Value is NULL.
 * @retval  CRYPT_INVALID_ARG       Value length is invalid.
 */
int32_t CRYPT_CTRL_GetNum32Ex(GetNumCallBack getNumCb, void *cbArg, void *val, uint32_t valLen);

#if defined(HITLS_CRYPTO_HKDF) || defined(HITLS_CRYPTO_KDFTLS12) || defined(HITLS_CRYPTO_PBKDF2) || \
defined(HITLS_CRYPTO_SCRYPT)
/**
 * @brief   Deep set data
 *
 * @param   src [IN] source buffer
 * @param   srcLen [IN] length of source buffer
 * @param   dst [OUT] destination buffer, if it is not NULL, it will be freed first.
 * @param   dstLen [OUT] length of destination buffer
 *
 * @retval  CRYPT_SUCCESS           Data is set successfully.
 * @retval  CRYPT_NULL_INPUT        Source buffer is NULL.
 * @retval  CRYPT_MEM_ALLOC_FAIL    Memory allocation failed.
 */
int32_t CRYPT_CTRL_SetData(const uint8_t *src, uint32_t srcLen, uint8_t **dst, uint32_t *dstLen);
#endif

#if defined(HITLS_CRYPTO_HKDF) || defined(HITLS_CRYPTO_KDFTLS12) || defined(HITLS_CRYPTO_PBKDF2)
/**
 * @brief   Set mdAttr to hmacCtx
 *
 * @param   mdAttr [IN] md attribute
 * @param   mdAttrLen [IN] length of mdAttr
 * @param   setParamCb [IN] set parameter callback
 * @param   hmacCtx [IN/OUT] hmac context
 */
int32_t CRYPT_CTRL_SetMdAttrToHmac(const char *mdAttr, uint32_t mdAttrLen, MacSetParam setParamCb, void *hmacCtx);

/**
 * @brief   Set mac method
 *
 * @param   libCtx [IN] library context
 * @param   inId [IN] input id
 * @param   ret [IN] return value when the method in macMeth is NULL
 * @param   macCtx [IN/OUT] mac context
 * @param   macMeth [IN/OUT] mac method
 * @param   id [OUT] output id
 */
int32_t CRYPT_CTRL_SetMacMethod(void *libCtx, CRYPT_MAC_AlgId inId, int32_t ret, void **macCtx, EAL_MacMethod *macMeth,
    CRYPT_MAC_AlgId *id);
#endif

#ifdef __cplusplus
}
#endif

#endif // CRYPT_UTIL_CTRL_H
