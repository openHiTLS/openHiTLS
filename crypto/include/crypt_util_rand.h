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
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_BN)

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*CRYPT_RandFunc)(uint8_t *rand, uint32_t randLen);

typedef int32_t (*CRYPT_RandFuncEx)(void *libCtx, uint8_t *rand, uint32_t randLen);

/**
 * @brief   Random number registration
 *
 * @param   func [IN] Interface for obtaining random numbers
 */
void CRYPT_RandRegist(CRYPT_RandFunc func);

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
void CRYPT_RandRegistEx(CRYPT_RandFuncEx func);


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

#ifdef __cplusplus
}
#endif

#endif

#endif