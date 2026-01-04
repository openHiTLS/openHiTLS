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

#ifndef CRYPT_CMAC_H
#define CRYPT_CMAC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMAC

#include <stdint.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct Cipher_MAC_Ctx CRYPT_CMAC_Ctx;

#define CRYPT_CMAC_SetParam NULL

/**
 * @brief Create a new CMAC context.
 * @param id [in] Symmetric encryption and decryption algorithm ID
 * @return CMAC context
 */
CRYPT_CMAC_Ctx *CRYPT_CMAC_NewCtx(CRYPT_MAC_AlgId id);

/**
 * @brief Create a new CMAC context with external library context.
 * @param libCtx [in] External library context
 * @param id [in] Symmetric encryption and decryption algorithm ID
 * @return CMAC context
 */
CRYPT_CMAC_Ctx *CRYPT_CMAC_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id);

/**
 * @brief Use the key passed by the user to initialize the algorithm context.
 * @param ctx [IN] CMAC context
 * @param key [in] symmetric algorithm key
 * @param len [in] Key length
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMAC_Init(CRYPT_CMAC_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief Use the key passed by the user to initialize the algorithm context.
 * @param ctx [IN] CMAC context
 * @param key [in] symmetric algorithm key
 * @param len [in] Key length
 * @param param [in] param
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMAC_InitEx(CRYPT_CMAC_Ctx *ctx, const uint8_t *key, uint32_t len, void *param);

/**
 * @brief Enter the data to be calculated and update the context.
 * @param ctx [IN] CMAC context
 * @param *in [in] Pointer to the data to be calculated
 * @param len [in] Length of the data to be calculated
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMAC_Update(CRYPT_CMAC_Ctx *ctx, const uint8_t *in, uint32_t len);
/**
 * @brief Output the cmac calculation result.
 * @param ctx [IN] CMAC context
 * @param out [OUT] Output data. Sufficient memory must be allocated to store CMAC results and cannot be null.
 * @param len [IN/OUT] Output data length
 * @retval #CRYPT_SUCCESS                   Succeeded.
 * @retval #CRYPT_NULL_INPUT                The input parameter is NULL.
 * @retval #CRYPT_EAL_BUFF_LEN_NOT_ENOUGH   The length of the output buffer is insufficient.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMAC_Final(CRYPT_CMAC_Ctx *ctx, uint8_t *out, uint32_t *len);
/**
 * @brief Re-initialize using the information retained in the ctx. Do not need to invoke the init again.
 *        This function is equivalent to the combination of deinit and init interfaces.
 * @param ctx [IN] CMAC context
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMAC_Reinit(CRYPT_CMAC_Ctx *ctx);

/**
 * @brief Deinitialization function.
 *        If calculation is required after this function is invoked, it needs to be initialized again.
 * @param ctx [IN] CMAC context
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMAC_Deinit(CRYPT_CMAC_Ctx *ctx);

/**
 * @brief Control function for CMAC.
 * @param ctx [IN] CMAC context
 * @param opt [IN] Control option
 * @param val [IN]/[OUT] Control value
 * @param len [IN] Control value length
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMAC_Ctrl(CRYPT_CMAC_Ctx *ctx, uint32_t opt, void *val, uint32_t len);

/**
 * @brief Free the CMAC context.
 * @param ctx [IN] CMAC context
 */
void CRYPT_CMAC_FreeCtx(CRYPT_CMAC_Ctx *ctx);

/**
 * @brief Dup the CMAC context.
 * @param ctx [IN] CMAC context.
 * @retval CMAC context.
 */
CRYPT_CMAC_Ctx *CRYPT_CMAC_DupCtx(const CRYPT_CMAC_Ctx *ctx);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif
#endif