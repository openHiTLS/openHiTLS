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
 * @defgroup crypt_eal_mac
 * @ingroup crypt
 * @brief mac of crypto module
 */

#ifndef CRYPT_EAL_MAC_H
#define CRYPT_EAL_MAC_H

#include <stdbool.h>
#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EAL_MacCtx CRYPT_EAL_MacCtx;

/**
 * @ingroup crypt_eal_mac
 * @brief   Check whether the id is Valid MAC algorithm ID.
 *
 * @param   id [IN] MAC algorithm ID
 *
 * @retval  true, if valid.
 *          false, if invalid.
 */
bool CRYPT_EAL_MacIsValidAlgId(CRYPT_MAC_AlgId id);

/**
 * @ingroup crypt_eal_mac
 * @brief   Apply for a MAC context.
 *
 * @param   id [IN] MAC algorithm ID
 *
 * @retval CRYPT_EAL_MacCtx Pointer.
 *         NULL, if the operation fails.
 */
CRYPT_EAL_MacCtx *CRYPT_EAL_MacNewCtx(CRYPT_MAC_AlgId id);

/**
 * @ingroup crypt_eal_mac
 * @brief   Create an MAC context in the providers.
 *
 * @param libCtx [IN] Library context
 * @param algId [IN] mac algorithm ID.
 * @param attrName [IN] Specify expected attribute values
 *
 * @retval  CRYPT_EAL_MacCtx pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_MacCtx *CRYPT_EAL_ProviderMacNewCtx(CRYPT_EAL_LibCtx *libCtx,  int32_t algId, const char *attrName);

/**
 * @ingroup crypt_eal_mac
 * @brief   Release the MAC context memory.
 *
 * @param   ctx [IN] MAC context, ctx set NULL by caller.
 */
void CRYPT_EAL_MacFreeCtx(CRYPT_EAL_MacCtx *ctx);

/**
 * @ingroup crypt_eal_mac
 *
 * MAC algorithm initialize the context, which is used after the CRYPT_EAL_MacNewCtx interface is called.
 * The initialization interface can be used at any time during the calculation, note that the last calculation data
 * is cleared after the initialization interface is called.
 *
 * @param   ctx [IN] MAC context
 * @param   key [IN] Key, The length specifications are as follows:
 *                   HMAC:Any integer greater than or equal to 0
 *                        The length of HMAC-SHA1, HMAC-SHA224, and HMAC-SHA256 must be less than 2^64 bits,
 *                        the length of HMAC-SHA384 and HMAC-SHA512 must be less than 2^128 bits.
 *                        HMAC-SHA3 series has no limit on length
 *                   CMAC: The length of CMAC-AES128 must be 128 bits, and the length of CMAC-AES192 must be 192 bits.
 *                         The length of CMAC-AES256 must be 256 bits.
 * @param   len [IN] Key length
 *
 * @retval #CRYPT_SUCCESS, initialization succeeded.
 * @retval #CRYPT_NULL_INPUT, pointer ctx parameter or key parameter is NULL.
 * @retval #CRYPT_AES_ERR_KEYLEN, the key length of the AES & CMAC algorithm is incorrect.
 *         Other error codes see the crypt_errno.h.
 */
int32_t CRYPT_EAL_MacInit(CRYPT_EAL_MacCtx *ctx, const uint8_t *key, uint32_t len);

/**
 * @ingroup crypt_eal_mac
 * @brief   Continuously input the MAC data.
 *
 * This command is used only after the CRYPT_EAL_MacInit interface is successfully called.
 *
 * @param   ctx [IN] MAC context
 * @param   in  [IN] Input data, when the variable is null, the len parameter must be 0.
 *                   Otherwise, an error is reported.
 * @param   len [IN] Input data length, the value can be 0.
 *
 * @retval #CRYPT_SUCCESS, succeeded in updating the internal status of the digest.
 * @retval #CRYPT_NULL_INPUT, the input parameter is NULL.
 * @retval #CRYPT_EAL_ERR_STATE, status error.
 * @retval #CRYPT_SHA1_INPUT_OVERFLOW, the length of the HMAC-SHA1 input data exceeds the maximum value.
 * @retval #CRYPT_SHA2_INPUT_OVERFLOW, the length of the HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, or HMAC-SHA512
 *         input data exceeds the maximum value, Other error codes see the crypt_errno.h.
 */
int32_t CRYPT_EAL_MacUpdate(CRYPT_EAL_MacCtx *ctx, const uint8_t *in, uint32_t len);

/**
 * @ingroup crypt_eal_mac
 * @brief   Output the MAC result.
 *
 *     This API must be used after the CRYPT_EAL_MacInit API is successfully executed, during the process, you
 * do not need to call the CRYPT_EAL_MacUpdate API.
 *     MAC output length. HMAC-SHA1 corresponds to 20 bytes, HMAC-SHA224 corresponds to 28 bytes, and HMAC-SHA256
 * corresponds to 32 bytes. HMAC-SHA384 corresponds to 48 bytes, HMAC-SHA512 corresponds to 64 bytes, and CMAC-AES
 * corresponds to 16 bytes. HMAC-SHA3-224 corresponds to 28 bytes, HMAC-SHA3-256 corresponds to 32 bytes,
 * HMAC-SHA3-384 corresponds to 48 bytes, and HMAC-SHA3-512 corresponds to 64 bytes.
 *
 * @param   ctx [IN] MAC context
 * @param   out [OUT] Output data. Sufficient memory must be allocated to store MAC results and cannot be null.
 * @param   len [IN/OUT] Output data length. The input parameter must specify the out length,
 *                       which must be greater than or equal to the length generated by the MAC.
 *                       The output parameter is the output length of the MAC.
 *
 * @retval #CRYPT_SUCCESS, calculation succeeded.
 * @retval #CRYPT_NULL_INPUT, the input parameter is NULL.
 * @retval #CRYPT_EAL_ERR_STATE, status incorrect.
 * @retval #CRYPT_HMAC_OUT_BUFF_LEN_NOT_ENOUGH, the length of the output buffer in the HMAC algorithm is insufficient.
 * @retval #CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH, the length of the output buffer in the  CMAC algorithm is insufficient.
 * @retval #CRYPT_SHA1_INPUT_OVERFLOW, the length of the HMAC-SHA1 input data exceeds the maximum.
 * @retval #CRYPT_SHA2_INPUT_OVERFLOW, the length of the input data in HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, or
 *                                    HMAC-SHA512 exceeds the maximum value.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_MacFinal(CRYPT_EAL_MacCtx *ctx, uint8_t *out, uint32_t *len);

/**
 * @ingroup crypt_eal_mac
 * @brief   Deinitialization function.
 *
 * If calculation is required after this function is called, it needs to be initialized again.
 *
 * @param   ctx [IN] MAC context
 */
void CRYPT_EAL_MacDeinit(CRYPT_EAL_MacCtx *ctx);

/**
 * @ingroup crypt_eal_mac
 * @brief  Re-initialize with the information retained in ctx.
 *
 * @attention Doesn't need call the init interface again for initialization, it is equivalent to the combination
 * of the deinit and init interfaces.
 * @param   ctx [IN] MAC context
 * @retval #CRYPT_SUCCESS, reinit succeeded.
 * @retval #CRYPT_NULL_INPUT, the input parameter is NULL.
 */
int32_t CRYPT_EAL_MacReinit(CRYPT_EAL_MacCtx *ctx);

/**
 * @ingroup crypt_eal_mac
 * @brief   Through the context, obtain the output MAC length of the corresponding algorithm.
 *
 * @param   ctx [IN] MAC context
 * @retval  The MAC length corresponding to the context.
 */
uint32_t CRYPT_EAL_GetMacLen(const CRYPT_EAL_MacCtx *ctx);

/**
 * @ingroup crypt_eal_mac
 * @brief   Set algorithm parameters. This API must be called after the CRYPT_EAL_MacInit API is called.
 *          This API supports only the GMAC algorithm.
 *
 *        Parameter            Data Type        len stands for length, and in represents the number of bytes
 * CRYPT_CTRL_SET_IV           uint8_t array    Length of IV
 * CRYPT_CTRL_SET_TAGLEN       uint32_t         4 bytes, sizeof(uint32_t)
 * CRYPT_CTRL_GET_MACLEN
 *
 * @param   ctx [IN] MAC context
 * @param   type [IN] Set parameter type.
 * @param   in [IN] Input data
 * @param   len [IN] Input data length
 * @retval #CRYPT_SUCCESS, parameters are set successfully.
 * @retval #CRYPT_EAL_ERR_STATE, status incorrect.
 * @retval #CRYPT_EAL_MAC_CTRL_TYPE_ERROR, the parameter type is set incorrect.
 * @retval #CRYPT_EAL_ERR_ALGID, algorithm ID exclude GMAC.
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_MacCtrl(CRYPT_EAL_MacCtx *ctx, int32_t type, void *in, uint32_t len);

/**
 * @ingroup crypt_eal_mac
 * @brief   Copy the MAC context.
 *
 * @param   to [IN] target MAC context.
 * @param   from [IN] original MAC context.
 * @retval #CRYPT_SUCCESS, parameters are set successfully.
 * @retval #CRYPT_NULL_INPUT, the input parameter is NULL.
 *         Other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_MacCopyCtx(CRYPT_EAL_MacCtx *to, const CRYPT_EAL_MacCtx *from);

/**
 * @ingroup crypt_eal_mac
 * @brief   Dup the MAC context.
 *
 * @param   from [IN] original MAC context.
 * @retval  CRYPT_EAL_MacCtx, MAC context pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_MacCtx *CRYPT_EAL_MacDupCtx(const CRYPT_EAL_MacCtx *from);

#ifdef __cplusplus
}   // end extern "C"
#endif

#endif // CRYPT_EAL_MAC_H
