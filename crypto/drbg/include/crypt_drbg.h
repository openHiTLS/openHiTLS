/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

#ifdef HITLS_CRYPTO_DRBG_HASH
/**
 * @ingroup drbg
 * @brief Apply for a context for the Hash_DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param md        HASH method
 * @param seedMeth  DRBG seed hook
 * @param seedCtx   DRBG seed context
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_NewHashCtx(const EAL_MdMethod *md, const CRYPT_RandSeedMethod *seedMeth, void *seedCtx);
#endif

#ifdef HITLS_CRYPTO_DRBG_HMAC
/**
 * @ingroup drbg
 * @brief Apply for a context for the HMAC_DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param hmacMeth  HMAC method
 * @param mdMeth    hash method
 * @param seedMeth  DRBG seed hook
 * @param seedCtx   DRBG seed context
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_NewHmacCtx(const EAL_MacMethod *hmacMeth, const EAL_MdMethod *mdMeth,
    const CRYPT_RandSeedMethod *seedMeth, void *seedCtx);
#endif

#ifdef HITLS_CRYPTO_DRBG_CTR
/**
 * @ingroup drbg
 * @brief Apply for a context for the CTR_DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param ciphMeth  AES method
 * @param keyLen    Key length
 * @param isUsedDf  Indicates whether to use derivation function.
 * @param seedMeth  DRBG seed hook
 * @param seedCtx   DRBG seed context
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_NewCtrCtx(const EAL_CipherMethod *ciphMeth, const uint32_t keyLen, const bool isUsedDf,
    const CRYPT_RandSeedMethod *seedMeth, void *seedCtx);
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
 * @brief Remove the DRBG instantiation
 * @brief This API does not support multiple threads.
 *
 * @param ctx DRBG context
 *
 * @retval CRYPT_SUCCESS    Removed successfully.
 * @retval CRYPT_NULL_INPUT Invalid null pointer
 */
int32_t DRBG_Uninstantiate(DRBG_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DRBG

#endif // CRYPT_DRBG_H
