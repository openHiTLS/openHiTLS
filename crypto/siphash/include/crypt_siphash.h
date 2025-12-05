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

#ifndef CRYPT_SIPHASH_H
#define CRYPT_SIPHASH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SIPHASH

#include <stdint.h>
#include <stdlib.h>
#include "crypt_local_types.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define SIPHASH_KEY_SIZE 16 // 128 bit
#define SIPHASH_WORD_SIZE 8 // 64 bit
#define DEFAULT_COMPRESSION_ROUND 2
#define DEFAULT_FINALIZATION_ROUND 4
// The siphash has only two output lengths: 8-byte and 16-byte.
#define SIPHASH_MIN_DIGEST_SIZE 8
#define SIPHASH_MAX_DIGEST_SIZE 16

typedef struct SIPHASH_Ctx CRYPT_SIPHASH_Ctx;

#define CRYPT_SIPHASH_SetParam NULL

/**
 * @brief Create a new siphash context.
 * @param id [IN] MAC algorithm id
 * @retval Pointer to the created siphash context.
 */
CRYPT_SIPHASH_Ctx *CRYPT_SIPHASH_NewCtx(CRYPT_MAC_AlgId id);

/**
 * @brief Create a new siphash context with external library context.
 * @param libCtx [in] External library context
 * @param id [in] siphash algorithm ID
 * @return Pointer to the siphash context
 */
CRYPT_SIPHASH_Ctx *CRYPT_SIPHASH_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id);

/**
 * @brief Initialize the siphash context by using the key passed by the user.
 * @param ctx [IN] siphash context
 * @param key [IN] MAC symmetric key
 * @param len [IN] Key length. The length of the siphash key is fixed to 128 bits.
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *         #CRYPT_INVALID_ARG   invalid input parameter. For example, the input key length is not 128 bits.
 */
int32_t CRYPT_SIPHASH_Init(CRYPT_SIPHASH_Ctx *ctx, const uint8_t *key, uint32_t keyLen);

/**
 * @brief Initialize the siphash context by using the key passed by the user.
 * @param ctx [IN] siphash context
 * @param key [IN] MAC symmetric key
 * @param len [IN] Key length. The length of the siphash key is fixed to 128 bits.
 * @param param [IN] param, reserved.
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 *         #CRYPT_INVALID_ARG   invalid input parameter. For example, the input key length is not 128 bits.
 */
int32_t CRYPT_SIPHASH_InitEx(CRYPT_SIPHASH_Ctx *ctx, const uint8_t *key, uint32_t keyLen, void *param);

/**
 * @brief siphash update, supporting streaming update
 * @param ctx [IN] siphash context
 * @param in [IN] Point to the data buffer for MAC calculation.
 * @param inlen [IN] Length of the data to be calculated
 * @retval #CRYPT_SUCCESS                           Succeeded.
 * @retval #CRYPT_NULL_INPUT                        The input parameter is NULL.
 */
int32_t CRYPT_SIPHASH_Update(CRYPT_SIPHASH_Ctx *ctx, const uint8_t *in, uint32_t inlen);

/**
 * @brief siphash closeout calculation
 * @param ctx [IN] siphash context
 * @param out [OUT] Output data. Sufficient memory must be allocated to store CMAC results and cannot be null.
 * @param outlen [IN/OUT] Output data length
 * @retval #CRYPT_SUCCESS                            Succeeded.
 * @retval #CRYPT_NULL_INPUT                         The input parameter is NULL.
 * @retval #CRYPT_SIPHASH_OUT_BUFF_LEN_NOT_ENOUGH    The output buffer is insufficient.
 */
int32_t CRYPT_SIPHASH_Final(CRYPT_SIPHASH_Ctx *ctx, uint8_t *out, uint32_t *outlen);

/**
 * @brief Re-initialize the siphash context
 * @param ctx [IN]  siphash context
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 */
int32_t CRYPT_SIPHASH_Reinit(CRYPT_SIPHASH_Ctx *ctx);

/**
 * @brief   siphash de-initialization
 * @param ctx [IN]  siphash context
 * @retval #CRYPT_SUCCESS       Succeeded.
 * @retval #CRYPT_NULL_INPUT    The input parameter is NULL.
 */
int32_t CRYPT_SIPHASH_Deinit(CRYPT_SIPHASH_Ctx *ctx);

/**
 * @brief   siphash control
 * @param ctx [IN]  siphash context
 * @param opt [IN]  control option
 * @param val [IN]/[OUT] Control value
 * @param len [IN]  control value length
 * @retval #CRYPT_SUCCESS                           Succeeded.
 * @retval #CRYPT_NULL_INPUT                        The input parameter is NULL.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SIPHASH_Ctrl(CRYPT_SIPHASH_Ctx *ctx, uint32_t opt, void *val, uint32_t len);

/**
 * @brief   siphash free context
 * @param ctx [IN]  siphash context
 */
void CRYPT_SIPHASH_FreeCtx(CRYPT_SIPHASH_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_SIPHASH */

#endif
