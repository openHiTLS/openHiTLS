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
#ifndef CKKS_CKKS_H
#define CKKS_CKKS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CKKS

#include <stdlib.h>
#include <stdint.h>
#include "crypt_bn.h"
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define CKKS_MAX_MODULUS_BITS 2940 // With the increase of bits, the noise will increase faster, the security level will decrease, and bits if too small can not withstand the increase in noise.
#define CKKS_MAX_LOGN         16
#define PI                    3.1415926535897932384626433832795028841971693993751058209749445923078164
#define DEFAULT_PREC 20 // If the user does not specify precision, the default precision is used
#define DEFAULT_SCALE 10 // The default scale factor
#define DEFAULT_STDEV 3.2 // The variance of the LWE error, default = 3.2
#define CKKS_GAUSS_TRUNC 8 // Truncation range B, to avoid excessive noise.
#define SIMD_MAX_NBITS 49 // Intel HEXL works best with primes of fewer than 50 bits in SIMD
#define PRIME_BIT_BOUND 3 // The width of the candidate prime interval is 2^{len-PRIME_BIT_BOUND}

/* CKKS*/
typedef struct CKKS_Ctx CRYPT_CKKS_Ctx;
typedef struct CKKS_Para CRYPT_CKKS_Para;

 /**
  * @ingroup ckks
  * @brief Allocate aligned memory. If SIMD is available, Some extra space is allocated to ensure memory alignment.
  * 
  * @param n [IN] input length
  * @param n_size [IN] The size of each element in bytes
  * 
  * @retval Aligned memory pointer
  */
 void *CKKS_Aligned_Allocate(size_t n, size_t n_size);
 
 /**
  * @ingroup ckks
  * @brief Free Allocated aligned memory. 
  * 
  * @param ptr [IN] Memory pointer to be deallocated. If SIMD is available, it will perform additional offset processing.
  * 
  * @retval NULL
  */
 void CKKS_Aligned_Deallocate(void *ptr);

 /**
 * @ingroup ckks
 * @brief Allocate ckks context memory space.
 *
 * @retval (CRYPT_CKKS_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer.
 */
CRYPT_CKKS_Ctx *CRYPT_CKKS_NewCtx(void); // create key structure

/**
 * @ingroup ckks
 * @brief Copy the CKKS context. After the duplication is complete, call the CRYPT_CKKS_FreeCtx to release the memory.
 *
 * @param keyCtx [IN] CKKS context
 *
 * @retval CRYPT_CKKS_Ctx    CKKS context pointer
 * @retval NULL             Invalid null pointer.
 */
CRYPT_CKKS_Ctx *CRYPT_CKKS_DupCtx(CRYPT_CKKS_Ctx *keyCtx);

/**
 * @ingroup ckks
 * @brief Create ckks key parameter structure
 *
 * @param params [IN] CKKS External parameter
 *
 * @retval (CRYPT_CKKS_Para *)  Pointer to the allocated memory space of the structure
 * @retval NULL                     Invalid null pointer.
 */
CRYPT_CKKS_Para *CRYPT_CKKS_NewPara(const BSL_Param *params);

/**
 * @ingroup ckks
 * @brief release ckks key context structure
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_CKKS_FreeCtx(CRYPT_CKKS_Ctx *ctx);

/**
 * @ingroup ckks
 * @brief Release ckks key parameter structure
 *
 * @param para [IN] Storage pointer in the parameter structure to be released. The parameter is set NULL by the invoker.
 */
void CRYPT_CKKS_FreePara(CRYPT_CKKS_Para *para);

/**
 * @ingroup ckks
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [IN] CKKS context structure for which related parameters need to be set
 * @param param [IN] Key parameter structure
 * 
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_SetPara(CRYPT_CKKS_Ctx *ctx,  const BSL_Param *param);

/**
 * @ingroup ckks
 * @brief Obtain the valid length of the modular Q.
 *
 * @param ctx [IN] CKKS context structure
 *
 * @retval 0: The input is incorrect
 * @retval uint32_t: Valid modular length
 */
int32_t CRYPT_CKKS_GetBits(const CRYPT_CKKS_Ctx *ctx);

/**
 * @ingroup ckks
 * @brief Generate the CKKS key pair.
 *
 * @param ctx [IN/OUT] ckks context structure
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_Gen(CRYPT_CKKS_Ctx *ctx);

/**
 * @ingroup ckks
 * @brief CKKS Set the private key information.
 *
 * @param ctx [OUT] ckks context structure
 * @param para [IN] Private key data
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_SetPrvKey(CRYPT_CKKS_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup ckks
 * @brief CKKS Set the public key information.
 *
 * @param ctx [OUT] CKKS context structure
 * @param para [IN] Public key data
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_SetPubKey(CRYPT_CKKS_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup ckks
 * @brief CKKS Obtain the private key information.
 *
 * @param ctx [IN] CKKS context structure
 * @param para [OUT] Private key data
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_GetPrvKey(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup ckks
 * @brief CKKS Obtain the public key information.
 *
 * @param ctx [IN] CKKS context structure
 * @param para [OUT] Public key data
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_GetPubKey(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup ckks
 * @brief CKKS public key encryption
 *
 * @param ctx [IN] CKKS context structure
 * @param input [IN] Information to be encrypted
 * @param inputLen [IN] Length of the information to be encrypted
 * @param out [OUT] Pointer to the encrypted information output.
 * @param outLen [OUT] Pointer to the length of the encrypted information
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
*/
int32_t CRYPT_CKKS_Encrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *input,uint32_t inputLen, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup ckks
 * @brief CKKS private key decryption
 *
 * @param ctx [IN] CKKS context structure
 * @param data [IN] Information to be decrypted
 * @param dataLen [IN] Length of the information to be decrypted
 * @param out [OUT] Pointer to the output information after decryption.
 * @param outLen [OUT] Pointer to the length of the decrypted information
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_Decrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup ckks
 * @brief CKKS get security bits
 *
 * @param ctx [IN] CKKS Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_CKKS_GetSecBits(const CRYPT_CKKS_Ctx *ctx);

/**
 * @ingroup ckks
 * @brief CKKS control function for various operations
 *
 * @param ctx [IN/OUT] CKKS context structure
 * @param opt [IN] Control operation type
 * @param val [IN/OUT] Parameter value for the operation
 * @param len [IN] Length of the parameter value
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t CRYPT_CKKS_Ctrl(CRYPT_CKKS_Ctx *ctx, int32_t opt, void *val, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CKKS

#endif // CRYPT_CKKS_H