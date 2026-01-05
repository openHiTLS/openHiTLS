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

#ifndef CRYPT_CBC_MAC_H
#define CRYPT_CBC_MAC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CBC_MAC
#include <stdint.h>
#include "crypt_types.h"
#include "crypt_cmac.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct CBC_MAC_Ctx CRYPT_CBC_MAC_Ctx;

/**
 * @brief Create a new CBC_MAC context.
 * @param id [IN] CBC_MAC algorithm ID
 * @return Pointer to the CBC_MAC context
 */
CRYPT_CBC_MAC_Ctx *CRYPT_CBC_MAC_NewCtx(CRYPT_MAC_AlgId id);

/**
 * @brief Use the key passed by the user to initialize the algorithm context.
 * @param ctx [IN] CBC_MAC context
 * @param key [in] symmetric algorithm key
 * @param len [in] Key length
 * @param param [in] param
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CBC_MAC_Init(CRYPT_CBC_MAC_Ctx *ctx, const uint8_t *key, uint32_t len, void *param);

/**
 * @brief Enter the data to be calculated and update the context.
 * @param ctx [IN] CBC_MAC context
 * @param *in [in] Pointer to the data to be calculated
 * @param len [in] Length of the data to be calculated
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CBC_MAC_Update(CRYPT_CBC_MAC_Ctx *ctx, const uint8_t *in, uint32_t len);

/**
 * @brief Output the cmac calculation result.
 * @param ctx [IN] CBC_MAC context
 * @param out [OUT] Output data. Sufficient memory must be allocated to store CBC_MAC results and cannot be null.
 * @param len [IN/OUT] Output data length
 * @retval #CRYPT_SUCCESS                   Succeeded.
 * @retval #CRYPT_NULL_INPUT                The input parameter is NULL.
 * @retval #CRYPT_EAL_BUFF_LEN_NOT_ENOUGH   The length of the output buffer is insufficient.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CBC_MAC_Final(CRYPT_CBC_MAC_Ctx *ctx, uint8_t *out, uint32_t *len);

/**
 * @brief Re-initialize using the information retained in the ctx. Do not need to invoke the init again.
 *        This function is equivalent to the combination of deinit and init interfaces.
 * @param ctx [IN] CBC_MAC context
 */
void CRYPT_CBC_MAC_Reinit(CRYPT_CBC_MAC_Ctx *ctx);

/**
 * @brief Deinitialization function.
 *        If calculation is required after this function is invoked, it needs to be initialized again.
 * @param ctx [IN] CBC_MAC context
 */
void CRYPT_CBC_MAC_Deinit(CRYPT_CBC_MAC_Ctx *ctx);

/**
 * @brief CBC_MAC control function to set some information
 * @param ctx [IN] CBC_MAC context
 * @param opt [IN] option
 * @param val [IN] value
 * @param len [IN] the length of value
 * @return See crypt_errno.h.
 */
int32_t CRYPT_CBC_MAC_Ctrl(CRYPT_CBC_MAC_Ctx *ctx, uint32_t opt, void *val, uint32_t len);

/**
 * @brief Free the CBC_MAC context.
 * @param ctx [IN] CBC_MAC context
 */
void CRYPT_CBC_MAC_FreeCtx(CRYPT_CBC_MAC_Ctx *ctx);

/**
 * @brief Dup the CBC_MAC context.
 * @param ctx [IN] CBC_MAC context.
 * @retval CBC_MAC context.
 */
CRYPT_CBC_MAC_Ctx *CRYPT_CBC_MAC_DupCtx(const CRYPT_CBC_MAC_Ctx *ctx);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif
#endif
