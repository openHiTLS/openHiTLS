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

#ifndef CRYPT_DRBG_H
#define CRYPT_DRBG_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DRBG

#include <stdint.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// hlcheck : health testing
// pr : prediction_resistance

typedef struct DrbgCtx DRBG_Ctx;

#define DRBG_MAX_LEN                (0x7ffffff0)
#define DRBG_MAX_REQUEST            (1 << 16)

#ifndef DRBG_MAX_RESEED_INTERVAL
#define DRBG_MAX_RESEED_INTERVAL    (10000)
#endif

#define DRBG_HASH_MAX_MDSIZE  (64)

/**
 * @ingroup drbg
 * @brief Apply for a context for the DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param algId     Algorithm ID for the DRBG
 * @param param     DRBG parameters
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      Failure
 */
DRBG_Ctx *DRBG_New(int32_t algId, BSL_Param *param);

/**
 * @ingroup drbg
 * @brief Release the DRBG context.
 * @brief This API does not support multiple threads.
 *
 * @param ctx DRBG context
 *
 * @retval None
 */
void DRBG_Free(DRBG_Ctx *ctx);

/**
 * @ingroup drbg
 * @brief Instantiating a DRBG based on personalization string.
 * @brief This API does not support multiple threads.
 *
 * @param ctx       DRBG context
 * @param person    Personalization string. The personalization string can be NULL.
 * @param persLen   Personalization string length,
 * @param param     DRBG parameters,Not in use yet
 *
 * @retval CRYPT_SUCCESS                Instantiation succeeded.
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_DRBG_ERR_STATE         The DRBG status is incorrect.
 * @retval CRYPT_DRBG_FAIL_GET_ENTROPY  Failed to obtain the entropy.
 * @retval CRYPT_DRBG_FAIL_GET_NONCE    Failed to obtain the nonce.
 * @retval Hash function error code:    Failed to invoke the hash function.
 */
int32_t DRBG_Instantiate(DRBG_Ctx *ctx, const uint8_t *person, uint32_t persLen, BSL_Param *param);

/**
 * @ingroup drbg
 * @brief Reseeding the DRBG.
 * @brief The additional input can be NULL. This API does not support multiple threads.
 *
 * @param ctx           DRBG context
 * @param adin          Additional input. The data can be empty.
 * @param adinLen       Additional input length
 * @param param         DRBG parameters,Not in use yet
 *
 * @retval CRYPT_SUCCESS                Instantiation succeeded.
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_DRBG_ERR_STATE         The DRBG status is incorrect.
 * @retval CRYPT_DRBG_FAIL_GET_ENTROPY  Failed to obtain the entropy.
 * @retval Hash function error code:    Failed to invoke the hash function.
 */
int32_t DRBG_Reseed(DRBG_Ctx *ctx, const uint8_t *adin, uint32_t adinLen, BSL_Param *param);

/**
 * @ingroup drbg
 * @brief Generating pseudorandom bits using a DRBG.
 * @brief The additional input can be null. The user specifies the additional obfuscation data.
 *        This API does not support multiple threads.
 * @brief External invoking must have a recovery mechanism after the status is abnormal.
 *
 * @param ctx           DRBG context
 * @param out           Output BUF
 * @param outLen        Output length
 * @param adin          Additional input. The data can be empty.
 * @param adinLen       Additional input length
 * @param param         DRBG parameters,involve:
 *     pr            Predicted resistance. If this parameter is set to true, reseed is executed each time.
 *
 * @retval CRYPT_SUCCESS        Instantiation succeeded.
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_DRBG_ERR_STATE The DRBG status is incorrect.
 * @retval Hash function error code: Failed to invoke the hash function.
 */
int32_t DRBG_Generate(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen, BSL_Param *param);

/**
 * @ingroup drbg
 * @brief Remove the DRBG instantiation
 * @brief This API does not support multiple threads.
 *
 * @param ctx DRBG context
 *
 * @retval CRYPT_SUCCESS    Removed successfully.
 * @retval CRYPT_NULL_INPUT Invalid null pointer
 */
int32_t DRBG_Uninstantiate(DRBG_Ctx *ctx);

/**
 * @ingroup drbg
 * @brief get or set drbg param
 *
 * @param ctx [IN] drbg context
 * @param cmd [IN] Option information
 * @param val [IN/OUT] Data to be set/obtained
 * @param valLen [IN] Length of the data marked as "val"
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t DRBG_Ctrl(void *ctx, int32_t cmd, void *val, uint32_t valLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DRBG

#endif // CRYPT_DRBG_H
