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

#ifndef CRYPT_ELGAMAL_H
#define CRYPT_ELGAMAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ELGAMAL

#include <stdlib.h>
#include <stdint.h>
#include "crypt_bn.h"
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define ELGAMAL_MAX_MODULUS_BITS 16384

/* ElGamal*/
typedef struct ELGAMAL_Ctx CRYPT_ELGAMAL_Ctx;
typedef struct ELGAMAL_Para CRYPT_ELGAMAL_Para;

/* ElGamal method*/
/**
   * @ingroup elgamal
   * @brief Allocate elgamal context memory space.
   *
   * @retval (CRYPT_ELGAMAL_Ctx *)   Pointer to the memory space of the allocated context
   * @retval NULL                     Invalid null pointer.
   */
CRYPT_ELGAMAL_Ctx *CRYPT_ELGAMAL_NewCtx(void);

CRYPT_ELGAMAL_Ctx *CRYPT_ELGAMAL_NewCtxEx(void *libCtx);

/**
   * @ingroup elgamal
   * @brief Copy the ElGamal context. After the duplication is complete, call the CRYPT_ELGAMAL_FreeCtx to release the memory.
   *
   * @param ctx [IN] ELGAMAL context
   *
   * @return CRYPT_ELGAMAL_Ctx    ELGAMAL context pointer
   *         If the operation fails, a null value is returned.
   */
CRYPT_ELGAMAL_Ctx *CRYPT_ELGAMAL_DupCtx(CRYPT_ELGAMAL_Ctx *keyCtx);

/**
   * @ingroup elgamal
   * @brief Create elgamal key parameter structure
   *
   * @param para [IN] ELGAMAL External parameter
   *
   * @retval (CRYPT_ELGAMAL_Para *)  Pointer to the allocated memory space of the structure
   * @retval NULL                     Invalid null pointer.
   */
CRYPT_ELGAMAL_Para *CRYPT_ELGAMAL_NewPara(const CRYPT_ElGamalPara *para);

/**
   * @ingroup elgamal
   * @brief release ElGamal key context structure
   *
   * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
   */
void CRYPT_ELGAMAL_FreeCtx(CRYPT_ELGAMAL_Ctx *ctx);

/**
   * @ingroup elgamal
   * @brief Release ElGamal key parameter structure
   *
   * @param para [IN] Storage pointer in the parameter structure to be released. The parameter is set NULL by the invoker.
   */
void CRYPT_ELGAMAL_FreePara(CRYPT_ELGAMAL_Para *para);

/**
   * @ingroup elgamal
   * @brief Set the data of the key parameter structure to the key structure.
   *
   * @param ctx [OUT] ElGamal context structure for which related parameters need to be set
   * @param para [IN] Key parameter structure
   *
   * @retval CRYPT_NULL_INPUT             Invalid null pointer input.
   * @retval CRYPT_ELGAMAL_ERR_KEY_BITS  The expected key length does not meet the requirements.
   * @retval CRYPT_ELGAMAL_ERR_E_VALUE   The expected value of e does not meet the requirements.
   * @retval CRYPT_MEM_ALLOC_FAIL         internal memory allocation error
   * @retval CRYPT_SUCCESS                set successfully.
   */
int32_t CRYPT_ELGAMAL_SetPara(CRYPT_ELGAMAL_Ctx *ctx, const CRYPT_ElGamalPara *para);

#ifdef HITLS_BSL_PARAMS
/**
   * @ingroup elgamal
   * @brief Set the data of the key parameter structure to the key structure.
   *
   * @param ctx [OUT] ElGamal context structure for which related parameters need to be set
   * @param para [IN] Key parameter structure
   *
   * @retval CRYPT_NULL_INPUT             Invalid null pointer input.
   * @retval CRYPT_ELGAMAL_ERR_KEY_BITS  The expected key length does not meet the requirements.
   * @retval CRYPT_ELGAMAL_ERR_E_VALUE   The expected value of e does not meet the requirements.
   * @retval CRYPT_MEM_ALLOC_FAIL         internal memory allocation error
   * @retval CRYPT_SUCCESS                set successfully.
   */
int32_t CRYPT_ELGAMAL_SetParaEx(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para);
#endif

/**
   * @ingroup elgamal
   * @brief Obtain the valid length of the key.
   *
   * @param ctx [IN] Structure from which the key length is expected to be obtained
   *
   * @retval 0: The input is incorrect or the corresponding key structure does not have a valid key length.
   * @retval uint32_t: Valid key length
   */
uint32_t CRYPT_ELGAMAL_GetBits(const CRYPT_ELGAMAL_Ctx *ctx);

/**
   * @ingroup elgamal
   * @brief Obtain the valid length of the k.
   *
   * @param ctx [IN] Structure from which the key length is expected to be obtained
   *
   * @retval 0: The input is incorrect or the corresponding key structure does not have a valid key length.
   * @retval uint32_t: Valid key length
   */
uint32_t CRYPT_ELGAMAL_GetKBits(const CRYPT_ELGAMAL_Ctx *ctx);

/**
   * @ingroup elgamal
   * @brief Generate the ElGamal key pair.
   *
   * @param ctx [IN/OUT] elgamal context structure
   *
   * @retval CRYPT_NULL_INPUT             Error null pointer input
   * @retval CRYPT_ELGAMAL_ERR_KEY_BITS  The value of e in the context structure does not meet the requirements.
   * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
   * @retval BN error                     An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                The key pair is successfully generated.
   */
int32_t CRYPT_ELGAMAL_Gen(CRYPT_ELGAMAL_Ctx *ctx);

/**
   * @ingroup elgamal
   * @brief ElGamal public key encryption
   *
   * @param ctx [IN] ElGamal context structure
   * @param input [IN] Information to be encrypted
   * @param inputLen [IN] Length of the information to be encrypted
   * @param out1 [OUT] Pointer to the encrypted information output.(c1)
   * @param out1Len [IN/OUT] Pointer to the length of the encrypted information.
   *                        Before being transferred, the value must be set to the maximum length of the array.
   * @param out2 [OUT] Pointer to the encrypted information output.(c2)
   * @param out2Len [IN/OUT] Pointer to the length of the encrypted information.
   *                        Before being transferred, the value must be set to the maximum length of the array.
   *
   * @retval CRYPT_NULL_INPUT                 Invalid null pointer input
   * @retval CRYPT_ELGAMAL_NO_KEY_INFO       does not contain the key information.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
   * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
   * @retval CRYPT_SECUREC_FAIL               A security function error occurs.
   * @retval BN error                         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                    encryption succeeded.
   */
int32_t CRYPT_ELGAMAL_PubEnc(const CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *input, uint32_t inputLen, uint8_t *out1,
                             uint32_t *out1Len, uint8_t *out2, uint32_t *out2Len);

/**
   * @ingroup elgamal
   * @brief ElGamal private key decryption
   *
   * @param ctx [IN] ElGamal context structure
   * @param c1 [IN] Information to be decrypted
   * @param c2 [IN] Information to be decrypted
   * @param bits [IN] Length of the information to be decrypted
   * @param out [OUT] Pointer to the decrypted information output.
   * @param outLen [IN/OUT] Pointer to the length of the decrypted information.
   *                        Before being transferred, the value must be set to the maximum length of the array.
   *
   * @retval CRYPT_NULL_INPUT                 Invalid null pointer input
   * @retval CRYPT_ELGAMAL_ERR_DEC_BITS      Incorrect length of the encrypted private key.
   * @retval CRYPT_ELGAMAL_NO_KEY_INFO       does not contain the key information.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
   * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
   * @retval CRYPT_SECUREC_FAIL               A security function error occurs.
   * @retval BN error.                        An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                    Decrypted Successfully
   */
int32_t CRYPT_ELGAMAL_PrvDec(const CRYPT_ELGAMAL_Ctx *ctx, const BN_BigNum *c1, const BN_BigNum *c2, uint32_t bits,
                             uint8_t *out, uint32_t *outLen);

/**
   * @ingroup elgamal
   * @brief ElGamal Set the private key information.
   *
   * @param ctx [OUT] ElGamal context structure
   * @param prv [IN] Private key data
   *
   * @retval CRYPT_NULL_INPUT                 Error null pointer input
   * @retval CRYPT_ELGAMAL_ERR_KEY_BITS      The key length does not meet the requirements.
   * @retval CRYPT_ELGAMAL_NO_KEY_INFO       does not contain the key information.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
   * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
   * @retval BN error                         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                    The private key is successfully set.
   */
int32_t CRYPT_ELGAMAL_SetPrvKey(CRYPT_ELGAMAL_Ctx *ctx, const CRYPT_ElGamalPrv *prv);

/**
   * @ingroup elgamal
   * @brief ElGamal Set the public key information.
   *
   * @param ctx [OUT] ElGamal context structure
   * @param pub [IN] Public key data
   *
   * @retval CRYPT_NULL_INPUT                 Error null pointer input
   * @retval CRYPT_ELGAMAL_ERR_KEY_BITS      The key length does not meet the requirements.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
   * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
   * @retval BN error                         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                    The public key is successfully set.
   */
int32_t CRYPT_ELGAMAL_SetPubKey(CRYPT_ELGAMAL_Ctx *ctx, const CRYPT_ElGamalPub *pub);

/**
   * @ingroup elgamal
   * @brief ElGamal Obtain the private key information.
   *
   * @param ctx [IN] ElGamal context structure
   * @param prv [OUT] Private key data
   *
   * @retval CRYPT_NULL_INPUT Invalid null pointer input
   * @retval BN error         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS    The private key is obtained successfully.
   */
int32_t CRYPT_ELGAMAL_GetPrvKey(const CRYPT_ELGAMAL_Ctx *ctx, CRYPT_ElGamalPrv *prv);

/**
   * @ingroup elgamal
   * @brief ElGamal Obtain the public key information.
   *
   * @param ctx [IN] ElGamal context structure
   * @param pub [OUT] Public key data
   *
   * @retval CRYPT_NULL_INPUT Invalid null pointer input
   * @retval BN error         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS    The public key is obtained successfully.
   */
int32_t CRYPT_ELGAMAL_GetPubKey(const CRYPT_ELGAMAL_Ctx *ctx, CRYPT_ElGamalPub *pub);

#ifdef HITLS_BSL_PARAMS
/**
   * @ingroup elgamal
   * @brief ElGamal Set the private key information.
   *
   * @param ctx [OUT] ElGamal context structure
   * @param para [IN] Private key data
   *
   * @retval CRYPT_NULL_INPUT                 Error null pointer input
   * @retval CRYPT_ELGAMAL_ERR_KEY_BITS      The key length does not meet the requirements.
   * @retval CRYPT_ELGAMAL_NO_KEY_INFO       does not contain the key information.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
   * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
   * @retval BN error                         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                    The private key is successfully set.
   */
int32_t CRYPT_ELGAMAL_SetPrvKeyEx(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para);

/**
   * @ingroup elgamal
   * @brief ElGamal Set the public key information.
   *
   * @param ctx [OUT] ElGamal context structure
   * @param para [IN] Public key data
   *
   * @retval CRYPT_NULL_INPUT                 Error null pointer input
   * @retval CRYPT_ELGAMAL_ERR_KEY_BITS      The key length does not meet the requirements.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE   The entered value does not meet the calculation conditions.
   * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
   * @retval BN error                         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                    The public key is successfully set.
   */
int32_t CRYPT_ELGAMAL_SetPubKeyEx(CRYPT_ELGAMAL_Ctx *ctx, const BSL_Param *para);

/**
   * @ingroup elgamal
   * @brief ElGamal Obtain the private key information.
   *
   * @param ctx [IN] ElGamal context structure
   * @param para [OUT] Private key data
   *
   * @retval CRYPT_NULL_INPUT Invalid null pointer input
   * @retval BN error         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS    The private key is obtained successfully.
   */
int32_t CRYPT_ELGAMAL_GetPrvKeyEx(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para);

/**
   * @ingroup elgamal
   * @brief ElGamal Obtain the public key information.
   *
   * @param ctx [IN] ElGamal context structure
   * @param para [OUT] Public key data
   *
   * @retval CRYPT_NULL_INPUT Invalid null pointer input
   * @retval BN error         An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS    The public key is obtained successfully.
   */
int32_t CRYPT_ELGAMAL_GetPubKeyEx(const CRYPT_ELGAMAL_Ctx *ctx, BSL_Param *para);
#endif

/**
   * @ingroup elgamal
   * @brief ElGamal public key encryption
   *
   * @param ctx [IN] ELGAMAL context structure
   * @param data [IN] Information to be encrypted
   * @param dataLen [IN] Length of the information to be encrypted
   * @param out [OUT] Pointer to the encrypted information output.
   * @param outLen [OUT] Pointer to the length of the encrypted information
   *
   * @retval CRYPT_NULL_INPUT                     Invalid null pointer input
   * @retval CRYPT_ELGAMAL_NO_KEY_INFO           does not contain the key information.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE       The entered value does not meet the calculation conditions.
   * @retval CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH   Outbuf Insufficient
   * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
   * @retval CRYPT_SECUREC_FAIL                   A safe function error occurs.
   * @retval BN error.                            An error occurs in the internal BigNum operation.
   * @retval CRYPT_EAL_ALG_NOT_SUPPORT            does not register the encryption method.
   * @retval CRYPT_SUCCESS                        encryption succeeded.
   */
int32_t CRYPT_ELGAMAL_Encrypt(CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out,
                              uint32_t *outLen);

/**
   * @ingroup elgamal
   * @brief ElGamal private key decryption
   *
   * @param ctx [IN] ELGAMAL context structure
   * @param data [IN] Information to be decrypted
   * @param dataLen [IN] Length of the information to be decrypted
   * @param out [OUT] Pointer to the output information after decryption.
   * @param outLen [OUT] Pointer to the length of the decrypted information
   *
   * @retval CRYPT_NULL_INPUT                     Error null pointer input
   * @retval CRYPT_ELGAMAL_NO_KEY_INFO           does not contain the key information.
   * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE       The entered value does not meet the calculation conditions.
   * @retval CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH   Outbuf Insufficient
   * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
   * @retval CRYPT_SECUREC_FAIL                   A security function error occurs.
   * @retval CRYPT_EAL_ALG_NOT_SUPPORT            does not register the decryption method.
   * @retval BN error.                            An error occurs in the internal BigNum operation.
   * @retval CRYPT_SUCCESS                        Decryption succeeded.
   */
int32_t CRYPT_ELGAMAL_Decrypt(CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out,
                              uint32_t *outLen);

/**
   * @ingroup elgamal
   * @brief ELGAMAL get security bits
   *
   * @param ctx [IN] ELGAMAL Context structure
   *
   * @retval security bits
   */
int32_t CRYPT_ELGAMAL_GetSecBits(const CRYPT_ELGAMAL_Ctx *ctx);

/**
 * @ingroup elgamal
 * @brief ELGAMAL control function for various operations
 *
 * @param ctx [IN/OUT] ELGAMAL context structure
 * @param opt [IN] Control operation type
 * @param val [IN/OUT] Parameter value for the operation
 * @param len [IN] Length of the parameter value
 *
 * @retval CRYPT_NULL_INPUT                     Invalid null pointer input
 * @retval CRYPT_ELGAMAL_ERR_INPUT_VALUE       The entered value does not meet the calculation conditions
 * @retval CRYPT_ELGAMAL_NO_KEY_INFO           Does not contain the key information
 * @retval CRYPT_MEM_ALLOC_FAIL                 Memory allocation failure
 * @retval CRYPT_EAL_ALG_NOT_SUPPORT            Operation not supported
 * @retval CRYPT_SUCCESS                        Operation succeeded
 */
int32_t CRYPT_ELGAMAL_Ctrl(CRYPT_ELGAMAL_Ctx *ctx, int32_t opt, void *val, uint32_t len);

#ifdef HITLS_CRYPTO_ELGAMAL
/**
 * @ingroup elgamal
 * @brief BigNum Calculate the original root
 *
 * @param g    [OUT] Safety prime
 * @param p    [IN] Big prime
 * @param q    [IN] Big prime
 * @param opt   [IN] Optimizer
 *
 * @retval CRYPT_SUCCESS
 * @retval CRYPT_NULL_INPUT             Invalid null pointer
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 */
int32_t OriginalRoot(void *libCtx, BN_BigNum *g, const BN_BigNum *p, const BN_BigNum *q, uint32_t bits);
#endif

#ifdef _cplusplus
}
#endif

#endif // HITLS_CRYPTO_ELGAMAL
#endif // CRYPT_ELGAMAL_H
