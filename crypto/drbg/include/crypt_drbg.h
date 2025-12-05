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
#ifdef HITLS_BSL_PARAMS
#include "bsl_params.h"
#include "crypt_params_key.h"
#endif

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

/* Default reseed intervals */
# define DRBG_RESEED_INTERVAL       (1 << 8)
# define DRBG_TIME_INTERVAL         (60 * 60)   /* 1 hour */

#ifndef DRBG_MAX_REQUEST_SM3
#define DRBG_MAX_REQUEST_SM3   (1 << 5)
#endif

#ifndef DRBG_MAX_REQUEST_SM4
#define DRBG_MAX_REQUEST_SM4 (1 << 4)
#endif

#ifndef DRBG_RESEED_INTERVAL_GM1
#define DRBG_RESEED_INTERVAL_GM1    (1 << 20)
#endif

#ifndef DRBG_RESEED_TIME_GM1
#define DRBG_RESEED_TIME_GM1    (600)
#endif

#ifndef DRBG_RESEED_INTERVAL_GM2
#define DRBG_RESEED_INTERVAL_GM2    (1 << 10)
#endif

#ifndef DRBG_RESEED_TIME_GM2
#define DRBG_RESEED_TIME_GM2    (60)
#endif

#ifndef HITLS_CRYPTO_DRBG_GM_LEVEL
#define HITLS_CRYPTO_DRBG_GM_LEVEL 2
#endif

#ifndef HITLS_CRYPTO_RESEED_INTERVAL_GM
#if HITLS_CRYPTO_DRBG_GM_LEVEL == 1
#define  HITLS_CRYPTO_RESEED_INTERVAL_GM   DRBG_RESEED_INTERVAL_GM1
#else
#define  HITLS_CRYPTO_RESEED_INTERVAL_GM   DRBG_RESEED_INTERVAL_GM2
#endif
#endif

#ifdef HITLS_CRYPTO_ENTROPY
    #ifndef HITLS_SEED_DRBG_INIT_RAND_ALG
        #ifdef HITLS_CRYPTO_AES
            #define  HITLS_SEED_DRBG_INIT_RAND_ALG   CRYPT_RAND_AES256_CTR
        #else
            #error "HITLS_SEED_DRBG_INIT_RAND_ALG configuration error."
        #endif
    #endif
#endif

#ifndef HITLS_CRYPTO_DRBG_RESEED_TIME_GM
#if HITLS_CRYPTO_DRBG_GM_LEVEL == 1
#define  HITLS_CRYPTO_DRBG_RESEED_TIME_GM  DRBG_RESEED_TIME_GM1
#else
#define  HITLS_CRYPTO_DRBG_RESEED_TIME_GM  DRBG_RESEED_TIME_GM2
#endif
#endif

#define DRBG_HASH_MAX_MDSIZE  (64)

typedef struct {
    CRYPT_RAND_AlgId  drbgId;
    int32_t depId;
    uint32_t type;
} DrbgIdMap;

/**
 * @ingroup drbg
 * @brief Apply for a context for the DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param libCtx    Library context
 * @param algId  RAND algorithm ID.
 * @param seedMethod  DRBG seed hook
 * @param seedCtx   DRBG seed context
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_New(void *libCtx, int32_t algId, CRYPT_RandSeedMethod *seedMethod, void *seedCtx);

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup drbg
 * @brief Apply for a context for the CTR_DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param libCtx    Library context
 * @param algId  RAND algorithm ID.
 * @param param  DRBG seed hook and seed context.
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_NewEx(void *libCtx, int32_t algId, BSL_Param *param);
#endif

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
 * @param persLen   Personalization string length
 *
 * @retval CRYPT_SUCCESS                Instantiation succeeded.
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_DRBG_ERR_STATE         The DRBG status is incorrect.
 * @retval CRYPT_DRBG_FAIL_GET_ENTROPY  Failed to obtain the entropy.
 * @retval CRYPT_DRBG_FAIL_GET_NONCE    Failed to obtain the nonce.
 * @retval Hash function error code:    Failed to invoke the hash function.
 */
int32_t DRBG_Instantiate(DRBG_Ctx *ctx, const uint8_t *person, uint32_t persLen);

/**
 * @ingroup drbg
 * @brief Reseeding the DRBG.
 * @brief The additional input can be NULL. This API does not support multiple threads.
 *
 * @param ctx           DRBG context
 * @param adin          Additional input. The data can be NULL.
 * @param adinLen       Additional input length
 * @param param         DRBG parameters,Not in use yet
 *
 * @retval CRYPT_SUCCESS                Instantiation succeeded.
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_DRBG_ERR_STATE         The DRBG status is incorrect.
 * @retval CRYPT_DRBG_FAIL_GET_ENTROPY  Failed to obtain the entropy.
 * @retval Hash function error code:    Failed to invoke the hash function.
 */
int32_t DRBG_Reseed(DRBG_Ctx *ctx, const uint8_t *adin, uint32_t adinLen);

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
 * @param pr            Predicted resistance. If this parameter is set to true, reseed is executed each time.
 *
 * @retval CRYPT_SUCCESS        Instantiation succeeded.
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_DRBG_ERR_STATE The DRBG status is incorrect.
 * @retval Hash function error code: Failed to invoke the hash function.
 */
int32_t DRBG_Generate(DRBG_Ctx *ctx,
                      uint8_t *out, uint32_t outLen,
                      const uint8_t *adin, uint32_t adinLen, bool pr);

/**
 * @ingroup drbg
 * @brief Generating pseudorandom bits using a DRBG, output can be any length.
 * @brief The additional input can be null. The user specifies the additional obfuscation data.
 *        This API does not support multiple threads.
 * @brief External invoking must have a recovery mechanism after the status is abnormal.
 *
 * @param ctx           DRBG context
 * @param out           Output BUF
 * @param outLen        Output length
 * @param adin          Additional input. The data can be empty.
 * @param adinLen       Additional input length
 *
 * @retval CRYPT_SUCCESS        Instantiation succeeded.
 * @retval CRYPT_NULL_INPUT     Invalid null pointer
 * @retval CRYPT_DRBG_ERR_STATE The DRBG status is incorrect.
 * @retval Hash function error code: Failed to invoke the hash function.
 */
int32_t DRBG_GenerateBytes(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen);

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
 * @brief Set reseed properties for DRBG
 *
 * @param opt options
 * @param val value
 * @param len length for val
 *
 * @retval CRYPT_SUCCESS    set successfully.
 * @retval CRYPT_INVALID_ARG Invalid arguments
 */
int32_t DRBG_Ctrl(DRBG_Ctx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup drbg
 * @brief Get the map corresponding to the algid.
 *
 * @param id enum of CRYPT_RAND_AlgId
 *
 * @retval DrbgIdMap
 * @retval NULL Invalid arguments
 */
const DrbgIdMap *DRBG_GetIdMap(CRYPT_RAND_AlgId id);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DRBG

#endif // CRYPT_DRBG_H
