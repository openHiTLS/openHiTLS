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
#ifndef CRYPT_PAILLIER_H
#define CRYPT_PAILLIER_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PAILLIER

#include <stdlib.h>
#include <stdint.h>
#include "crypt_bn.h"
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define PAILLIER_MAX_MODULUS_BITS 16384

/* Paillier*/
typedef struct PAILLIER_Ctx CRYPT_PAILLIER_Ctx;
typedef struct PAILLIER_Para CRYPT_PAILLIER_Para;


/* Paillier method*/
/**
 * @ingroup paillier
 * @brief Allocate paillier context memory space.
 *
 * @retval (CRYPT_PAILLIER_Ctx *)   Pointer to the memory space of the allocated context
 * @retval NULL                     Invalid null pointer.
*/
CRYPT_PAILLIER_Ctx *CRYPT_PAILLIER_NewCtx(void);

/**
 * @ingroup paillier
 * @brief Allocate paillier context memory space.
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_PAILLIER_Ctx *)   Pointer to the memory space of the allocated context
 * @retval NULL                     Invalid null pointer.
*/
CRYPT_PAILLIER_Ctx *CRYPT_PAILLIER_NewCtxEx(void *libCtx);

/**
 * @ingroup paillier
 * @brief Copy the Paillier context. After the duplication is complete, call the CRYPT_PAILLIER_FreeCtx to release the memory.
 *
 * @param ctx [IN] PAILLIER context
 *
 * @return CRYPT_PAILLIER_Ctx    Paillier context pointer
 *         If the operation fails, a null value is returned.
 */
CRYPT_PAILLIER_Ctx *CRYPT_PAILLIER_DupCtx(CRYPT_PAILLIER_Ctx *keyCtx);

/**
 * @ingroup paillier
 * @brief Create paillier key parameter structure
 *
 * @param para [IN] PAILLIER External parameter
 *
 * @retval (CRYPT_PAILLIER_Para *)  Pointer to the allocated memory space of the structure
 * @retval NULL                     Invalid null pointer.
 */
CRYPT_PAILLIER_Para *CRYPT_PAILLIER_NewPara(const CRYPT_PaillierPara *para);

/**
 * @ingroup paillier
 * @brief release paillier key context structure
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_PAILLIER_FreeCtx(CRYPT_PAILLIER_Ctx *ctx);

/**
 * @ingroup paillier
 * @brief Release paillier key parameter structure
 *
 * @param para [IN] Storage pointer in the parameter structure to be released. The parameter is set NULL by the invoker.
 */
void CRYPT_PAILLIER_FreePara(CRYPT_PAILLIER_Para *para);

/**
 * @ingroup paillier
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [OUT] Paillier context structure for which related parameters need to be set
 * @param para [IN] Key parameter structure
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input.
 * @retval CRYPT_PAILLIER_ERR_KEY_BITS  The expected key length does not meet the requirements.
 * @retval CRYPT_PAILLIER_ERR_E_VALUE   The expected value of e does not meet the requirements.
 * @retval CRYPT_MEM_ALLOC_FAIL         internal memory allocation error
 * @retval CRYPT_SUCCESS                set successfully.
 */
int32_t CRYPT_PAILLIER_SetPara(CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPara *para);

/**
 * @ingroup paillier
 * @brief Obtain the valid length of the key.
 *
 * @param ctx [IN] Structure from which the key length is expected to be obtained
 *
 * @retval 0: The input is incorrect or the corresponding key structure does not have a valid key length.
 * @retval uint32_t: Valid key length
 */
uint32_t CRYPT_PAILLIER_GetBits(const CRYPT_PAILLIER_Ctx *ctx);

/**
 * @ingroup paillier
 * @brief Generate the Paillier key pair.
 *
 * @param ctx [IN/OUT] paillier context structure
 *
 * @retval CRYPT_NULL_INPUT             Error null pointer input
 * @retval CRYPT_PAILLIER_ERR_KEY_BITS  The value of e in the context structure does not meet the requirements.
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval BN error                     An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                The key pair is successfully generated.
 */
int32_t CRYPT_PAILLIER_Gen(CRYPT_PAILLIER_Ctx *ctx);

/**
 * @ingroup paillier
 * @brief Paillier public key encryption
 *
 * @param ctx [IN] Paillier context structure
 * @param input [IN] Information to be encrypted
 * @param inputLen [IN] Length of the information to be encrypted
 * @param out [OUT] Pointer to the encrypted information output.
 * @param outLen [IN/OUT] Pointer to the length of the encrypted information.
 *                        Before being transferred, the value must be set to the maximum length of the array.
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input
 * @retval CRYPT_PAILLIER_NO_KEY_INFO       does not contain the key information.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL               A security function error occurs.
 * @retval BN error                         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    encryption succeeded.
 */
int32_t  CRYPT_PAILLIER_PubEnc(const CRYPT_PAILLIER_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup paillier
 * @brief Paillier private key decryption
 *
 * @param ctx [IN] Paillier context structure
 * @param ciphertext [IN] Information to be decrypted
 * @param bits [IN] Length of the information to be decrypted
 * @param out [OUT] Pointer to the decrypted information output.
 * @param outLen [IN/OUT] Pointer to the length of the decrypted information.
 *                        Before being transferred, the value must be set to the maximum length of the array.
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input
 * @retval CRYPT_PAILLIER_ERR_DEC_BITS      Incorrect length of the encrypted private key.
 * @retval CRYPT_PAILLIER_NO_KEY_INFO       does not contain the key information.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL               A security function error occurs.
 * @retval BN error.                        An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    Decrypted Successfully
 */
int32_t CRYPT_PAILLIER_PrvDec(const CRYPT_PAILLIER_Ctx *ctx, const BN_BigNum *ciphertext, uint32_t bits,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup paillier
 * @brief Paillier Set the private key information.
 *
 * @param ctx [OUT] paillier context structure
 * @param prv [IN] Private key data
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_PAILLIER_ERR_KEY_BITS      The key length does not meet the requirements.
 * @retval CRYPT_PAILLIER_NO_KEY_INFO       does not contain the key information.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval BN error                         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    The private key is successfully set.
 */
int32_t CRYPT_PAILLIER_SetPrvKey(CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPrv *prv);

/**
 * @ingroup paillier
 * @brief Paillier Set the public key information.
 *
 * @param ctx [OUT] Paillier context structure
 * @param pub [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_PAILLIER_ERR_KEY_BITS      The key length does not meet the requirements.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval BN error                         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    The public key is successfully set.
 */
int32_t CRYPT_PAILLIER_SetPubKey(CRYPT_PAILLIER_Ctx *ctx, const CRYPT_PaillierPub *pub);

/**
 * @ingroup paillier
 * @brief Paillier Obtain the private key information.
 *
 * @param ctx [IN] Paillier context structure
 * @param prv [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT Invalid null pointer input
 * @retval BN error         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS    The private key is obtained successfully.
 */
int32_t CRYPT_PAILLIER_GetPrvKey(const CRYPT_PAILLIER_Ctx *ctx, CRYPT_PaillierPrv *prv);

/**
 * @ingroup paillier
 * @brief Paillier Obtain the public key information.
 *
 * @param ctx [IN] Paillier context structure
 * @param pub [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT Invalid null pointer input
 * @retval BN error         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS    The public key is obtained successfully.
 */
int32_t CRYPT_PAILLIER_GetPubKey(const CRYPT_PAILLIER_Ctx *ctx, CRYPT_PaillierPub *pub);

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup paillier
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [OUT] Paillier context structure for which related parameters need to be set
 * @param para [IN] Key parameter structure
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input.
 * @retval CRYPT_PAILLIER_ERR_KEY_BITS  The expected key length does not meet the requirements.
 * @retval CRYPT_PAILLIER_ERR_E_VALUE   The expected value of e does not meet the requirements.
 * @retval CRYPT_MEM_ALLOC_FAIL         internal memory allocation error
 * @retval CRYPT_SUCCESS                set successfully.
 */
int32_t CRYPT_PAILLIER_SetParaEx(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup paillier
 * @brief Paillier Set the private key information.
 *
 * @param ctx [OUT] paillier context structure
 * @param prv [IN] Private key data
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_PAILLIER_ERR_KEY_BITS      The key length does not meet the requirements.
 * @retval CRYPT_PAILLIER_NO_KEY_INFO       does not contain the key information.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval BN error                         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    The private key is successfully set.
 */
int32_t CRYPT_PAILLIER_SetPrvKeyEx(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup paillier
 * @brief Paillier Set the public key information.
 *
 * @param ctx [OUT] Paillier context structure
 * @param pub [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_PAILLIER_ERR_KEY_BITS      The key length does not meet the requirements.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval BN error                         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    The public key is successfully set.
 */
int32_t CRYPT_PAILLIER_SetPubKeyEx(CRYPT_PAILLIER_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup paillier
 * @brief Paillier Obtain the private key information.
 *
 * @param ctx [IN] Paillier context structure
 * @param prv [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT Invalid null pointer input
 * @retval BN error         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS    The private key is obtained successfully.
 */
int32_t CRYPT_PAILLIER_GetPrvKeyEx(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup paillier
 * @brief Paillier Obtain the public key information.
 *
 * @param ctx [IN] Paillier context structure
 * @param pub [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT Invalid null pointer input
 * @retval BN error         An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS    The public key is obtained successfully.
 */
int32_t CRYPT_PAILLIER_GetPubKeyEx(const CRYPT_PAILLIER_Ctx *ctx, BSL_Param *para);
#endif

/**
 * @ingroup paillier
 * @brief PAILLIER public key encryption
 *
 * @param ctx [IN] PAILLIER context structure
 * @param data [IN] Information to be encrypted
 * @param dataLen [IN] Length of the information to be encrypted
 * @param out [OUT] Pointer to the encrypted information output.
 * @param outLen [OUT] Pointer to the length of the encrypted information
 *
 * @retval CRYPT_NULL_INPUT                     Invalid null pointer input
 * @retval CRYPT_PAILLIER_NO_KEY_INFO           does not contain the key information.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE       The entered value does not meet the calculation conditions.
 * @retval CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH   Outbuf Insufficient
 * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL                   A safe function error occurs.
 * @retval BN error.                            An error occurs in the internal BigNum operation.
 * @retval CRYPT_EAL_ALG_NOT_SUPPORT            does not register the encryption method.
 * @retval CRYPT_SUCCESS                        encryption succeeded.
*/
int32_t CRYPT_PAILLIER_Encrypt(CRYPT_PAILLIER_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup paillier
 * @brief PAILLIER private key decryption
 *
 * @param ctx [IN] PAILLIER context structure
 * @param data [IN] Information to be decrypted
 * @param dataLen [IN] Length of the information to be decrypted
 * @param out [OUT] Pointer to the output information after decryption.
 * @param outLen [OUT] Pointer to the length of the decrypted information
 *
 * @retval CRYPT_NULL_INPUT                     Error null pointer input
 * @retval CRYPT_PAILLIER_NO_KEY_INFO           does not contain the key information.
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE       The entered value does not meet the calculation conditions.
 * @retval CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH   Outbuf Insufficient
 * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
 * @retval CRYPT_SECUREC_FAIL                   A security function error occurs.
 * @retval CRYPT_EAL_ALG_NOT_SUPPORT            does not register the decryption method.
 * @retval BN error.                            An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                        Decryption succeeded.
 */
int32_t CRYPT_PAILLIER_Decrypt(CRYPT_PAILLIER_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup paillier
 * @brief PAILLIER get security bits
 *
 * @param ctx [IN] PAILLIER Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_PAILLIER_GetSecBits(const CRYPT_PAILLIER_Ctx *ctx);

/**
 * @ingroup paillier
 * @brief PAILLIER control function for various operations
 *
 * @param ctx [IN/OUT] PAILLIER context structure
 * @param opt [IN] Control operation type
 * @param val [IN/OUT] Parameter value for the operation
 * @param len [IN] Length of the parameter value
 *
 * @retval CRYPT_NULL_INPUT                     Invalid null pointer input
 * @retval CRYPT_PAILLIER_ERR_INPUT_VALUE       The entered value does not meet the calculation conditions
 * @retval CRYPT_PAILLIER_NO_KEY_INFO           Does not contain the key information
 * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
 * @retval CRYPT_EAL_ALG_NOT_SUPPORT            Operation not supported
 * @retval CRYPT_SUCCESS                        Operation succeeded
 */
int32_t CRYPT_PAILLIER_Ctrl(CRYPT_PAILLIER_Ctx *ctx, int32_t opt, void *val, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_PAILLIER

#endif // CRYPT_PAILLIER_H