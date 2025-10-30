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

#ifndef CRYPT_UTIL_RAND_H
#define CRYPT_UTIL_RAND_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_DRBG) || defined(HITLS_CRYPTO_CURVE25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_BN_RAND) || defined(HITLS_CRYPTO_SM9)

#include <stdint.h>
#include "crypt_eal_rand.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Random number registration
 *
 * @param   func [IN] Interface for obtaining random numbers
 */
void CRYPT_RandRegist(CRYPT_EAL_RandFunc func);

/**
 * @brief   Get the registered random number function
 *
 * @return  The registered random number function
 */
CRYPT_EAL_RandFunc CRYPT_RandRegistGet(void);

/**
 * @brief   Generate a random number
 *
 * @param   rand [OUT] buffer of random number
 * @param   randLen [IN] length of random number
 *
 * @retval  CRYPT_SUCCESS           A random number is generated successfully.
 * @retval  CRYPT_NO_REGIST_RAND    The random number function is not registered.
 * @retval  Error returned when the registered random number fails during the generate.
 */
int32_t CRYPT_Rand(uint8_t *rand, uint32_t randLen);

/**
 * @brief   Random number registration
 *
 * @param   func [IN] Interface for obtaining random numbers
 */
void CRYPT_RandRegistEx(CRYPT_EAL_RandFuncEx func);

/**
 * @brief   Get the registered random number function
 *
 * @return  The registered random number function
 */
CRYPT_EAL_RandFuncEx CRYPT_RandRegistExGet(void);

/**
 * @brief   Generate a random number
 *
 * @param   libCtx [IN] Library context
 * @param   rand [OUT] buffer of random number
 * @param   randLen [IN] length of random number
 *
 * @retval  CRYPT_SUCCESS           A random number is generated successfully.
 * @retval  CRYPT_NO_REGIST_RAND    The random number function is not registered.
 * @retval  Error returned when the registered random number fails during the generate.
 */
int32_t CRYPT_RandEx(void *libCtx, uint8_t *rand, uint32_t randLen);

#if defined(HITLS_CRYPTO_EAL)
#ifdef HITLS_CRYPTO_ENTROPY
/**
 * @brief Global seed-drbg lock initialization
 *
 * @param ctx handle of ctx
 */
int32_t EAL_SeedDrbgLockInit(void);

/**
 * @brief Global seed-drbg lock deinitialization
 *
 * @param ctx handle of ctx
 */
void EAL_SeedDrbgLockDeInit(void);
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif

#endif