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

#ifndef CRYPT_DSA_H
#define CRYPT_DSA_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DSA

#include <stdint.h>
#include "crypt_bn.h"
#include "crypt_types.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#ifndef CRYPT_DSA_TRY_MAX_CNT
#define CRYPT_DSA_TRY_MAX_CNT 100 // Maximum number of attempts to generate keys and signatures
#endif

#define CRYPT_DSA_FFC_PARAM 1
#define CRYPT_DH_FFC_PARAM 2

#define CRYPT_DISABLE_SP800_KEYGEN_FLAG 0
#define CRYPT_ENABLE_SP800_KEYGEN_FLAG 1

/* DSA key parameters */
typedef struct DSA_Para CRYPT_DSA_Para;

/* DSA key context */
typedef struct DSA_Ctx CRYPT_DSA_Ctx;

typedef struct {
    int32_t algId; // hash algid
    int32_t index; // gen g need index
    uint32_t l; // pbits
    uint32_t n; // qbits
} DSA_FIPS186_4_Para;

/**
 * @ingroup dsa
 * @brief dsa Allocates context memory space.
 *
 * @retval (CRYPT_DSA_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_DSA_Ctx *CRYPT_DSA_NewCtx(void);

/**
 * @ingroup dsa
 * @brief dsa Allocates context memory space.
 * 
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_DSA_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_DSA_Ctx *CRYPT_DSA_NewCtxEx(void *libCtx);

/**
 * @ingroup dsa
 * @brief Copy the DSA context. After the duplication is complete, invoke the CRYPT_DSA_FreeCtx to release the memory.
 *
 * @param ctx [IN] Source DSA context
 *
 * @return CRYPT_DSA_Ctx Dsa context pointer
 * If the operation fails, null is returned.
 */
CRYPT_DSA_Ctx *CRYPT_DSA_DupCtx(CRYPT_DSA_Ctx *dsaCtx);

/**
 * @ingroup dsa
 * @brief dsa Release the key context structure
 *
 * @param ctx [IN] Indicates the pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_DSA_FreeCtx(CRYPT_DSA_Ctx *ctx);

/**
 * @ingroup dsa
 * @brief dsa generate key parameter structure
 *
 * @param para [IN] dsa external parameter
 *
 * @retval (CRYPT_DSA_Para *) Pointer to the memory space of the allocated context
 * @retval NULL               Invalid null pointer
 */
CRYPT_DSA_Para *CRYPT_DSA_NewPara(const CRYPT_DsaPara *para);

/**
 * @ingroup dsa
 * @brief Release the key parameter structure of DSA.
 *
 * @param para [IN] Pointer to the key parameter structure to be released. para is set NULL by the invoker.
 */
void CRYPT_DSA_FreePara(CRYPT_DSA_Para *para);

/**
 * @ingroup dsa
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [IN] Key structure for setting related parameters. The key specification is 1024-3072 bits.
 * @param para [IN] Key parameters
 *
 * @retval CRYPT_NULL_INPUT          Invalid null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_PARA    The key parameter data is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL      internal memory allocation error
 * @retval BN error code.            An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS             Set successfully.
 */
int32_t CRYPT_DSA_SetPara(CRYPT_DSA_Ctx *ctx, const CRYPT_DsaPara *para);

/**
 * @ingroup dsa
 * @brief Set the parameter data in the key structure to the key parameter structure.
 *
 * @param ctx [IN] Key structure for setting related parameters. The key specification is 1024-3072 bits.
 * @param para [OUT] Key parameters
 *
 * @retval CRYPT_NULL_INPUT          Invalid null pointer input.
 * @retval CRYPT_DSA_PARA_ERROR      The key parameter data is incorrect.
 * @retval BN error code.            An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS             Get successfully.
 */
int32_t CRYPT_DSA_GetPara(const CRYPT_DSA_Ctx *ctx, CRYPT_DsaPara *para);

/**
 * @ingroup dsa
 * @brief dsa Obtain the key length.
 *
 * @param ctx [IN] DSA context structure
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not contain valid key length.
 * @retval uint32_t Valid key length
 */
uint32_t CRYPT_DSA_GetBits(const CRYPT_DSA_Ctx *ctx);

/**
 * @ingroup dsa
 * @brief dsa Obtain the required length of the signature.
 *
 * @param ctx [IN] DSA context structure
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not contain valid parameter data.
 * @retval uint32_t Length required for valid signature data
 */
uint32_t CRYPT_DSA_GetSignLen(const CRYPT_DSA_Ctx *ctx);
/**
 * @ingroup dsa
 * @brief Generate a DSA key pair.
 *
 * @param ctx [IN/OUT] DSA context structure
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_PARA   The key parameter data is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure.
 * @retval CRYPT_DSA_ERR_TRY_CNT    Unable to generate results within the specified number of attempts.
 * @retval BN error code.           An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS            The key pair is successfully generated.
 */
int32_t CRYPT_DSA_Gen(CRYPT_DSA_Ctx *ctx);

/**
 * @ingroup dsa
 * @brief DSA Signature
 *
 * @param ctx [IN] DSA context structure
 * @param algId [IN] md algId
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [OUT] Signature data
 * @param signLen [IN/OUT] The input parameter is the space length of the sign,
 *                         and the output parameter is the valid length of the sign.
 *                         The required space can be obtained by calling CRYPT_DSA_GetSignLen.
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input.
 * @retval CRYPT_DSA_BUFF_LEN_NOT_ENOUGH    The buffer length is insufficient.
 * @retval CRYPT_DSA_ERR_KEY_INFO           The key information is incorrect.
 * @retval CRYPT_DSA_ERR_TRY_CNT            Unable to generate results within the specified number of attempts.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure.
 * @retval BN error                         An error occurred in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    Signed successfully.
 */
int32_t CRYPT_DSA_Sign(const CRYPT_DSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup dsa
 * @brief DSA Signature
 *
 * @param ctx [IN] DSA context structure
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [OUT] Signature data
 * @param signLen [IN/OUT] The input parameter is the space length of the sign,
 *                         and the output parameter is the valid length of the sign.
 *                         The required space can be obtained by calling CRYPT_DSA_GetSignLen.
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input.
 * @retval CRYPT_DSA_BUFF_LEN_NOT_ENOUGH    The buffer length is insufficient.
 * @retval CRYPT_DSA_ERR_KEY_INFO           The key information is incorrect.
 * @retval CRYPT_DSA_ERR_TRY_CNT            Unable to generate results within the specified number of attempts.
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure.
 * @retval BN error                         An error occurred in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                    Signed successfully.
 */
int32_t CRYPT_DSA_SignData(const CRYPT_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup dsa
 * @brief DSA verification
 *
 * @param ctx [IN] DSA context structure
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [IN] Signature data
 * @param signLen [IN] Valid length of the sign
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_INFO   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure.
 * @retval CRYPT_DSA_DECODE_FAIL    Signature Data Decoding Failure.
 * @retval CRYPT_DSA_VERIFY_FAIL    Failed to verify the signature.
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            The signature is verified successfully.
 */
int32_t CRYPT_DSA_VerifyData(const CRYPT_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup dsa
 * @brief DSA verification
 *
 * @param ctx [IN] DSA context structure
 * @param algId [IN] md algId
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [IN] Signature data
 * @param signLen [IN] Valid length of the sign
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_INFO   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure.
 * @retval CRYPT_DSA_DECODE_FAIL    Signature Data Decoding Failure.
 * @retval CRYPT_DSA_VERIFY_FAIL    Failed to verify the signature.
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            The signature is verified successfully.
 */
int32_t CRYPT_DSA_Verify(const CRYPT_DSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup dsa
 * @brief Set the private key data for the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param prv [IN] External private key data
 *
 * @retval CRYPT_NULL_INPUT          Invalid null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_PARA    The key parameter data is incorrect.
 * @retval CRYPT_DSA_ERR_KEY_INFO    The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL      Memory allocation failure.
 * @retval BN error.                 An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS             Set successfully.
 */
int32_t CRYPT_DSA_SetPrvKey(CRYPT_DSA_Ctx *ctx, const CRYPT_DsaPrv *prv);

/**
 * @ingroup dsa
 * @brief Set the public key data for the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param pub [IN] External public key data
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_PARA   The key parameter data is incorrect.
 * @retval CRYPT_DSA_ERR_KEY_INFO   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure.
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DSA_SetPubKey(CRYPT_DSA_Ctx *ctx, const CRYPT_DsaPub *pub);

/**
 * @ingroup dsa
 * @brief Obtain the private key data of the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param prv [OUT] External private key data
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input.
 * @retval CRYPT_DSA_BUFF_LEN_NOT_ENOUGH    The buffer length is insufficient.
 * @retval CRYPT_DSA_ERR_KEY_INFO           The key information is incorrect.
 * @retval BN error.                        An error occurs in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS                    Obtained successfully.
 */
int32_t CRYPT_DSA_GetPrvKey(const CRYPT_DSA_Ctx *ctx, CRYPT_DsaPrv *prv);

/**
 * @ingroup dsa
 * @brief Obtain the public key data of the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param pub [OUT] External public key data
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input.
 * @retval CRYPT_DSA_BUFF_LEN_NOT_ENOUGH    The buffer length is insufficient.
 * @retval CRYPT_DSA_ERR_KEY_INFO           The key information is incorrect.
 * @retval BN error.                        An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS                    Obtained successfully.
 */
int32_t CRYPT_DSA_GetPubKey(const CRYPT_DSA_Ctx *ctx, CRYPT_DsaPub *pub);

/**
 * @ingroup dsa
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [IN] Key structure for setting related parameters. The key specification is 1024-3072 bits.
 * @param para [IN] Key parameters
 *
 * @retval CRYPT_NULL_INPUT          Invalid null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_PARA    The key parameter data is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL      internal memory allocation error
 * @retval BN error code.            An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS             Set successfully.
 */
int32_t CRYPT_DSA_SetParaEx(CRYPT_DSA_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup dsa
 * @brief Set the parameter data in the key structure to the key parameter structure.
 *
 * @param ctx [IN] Key structure for setting related parameters. The key specification is 1024-3072 bits.
 * @param para [OUT] Key parameters
 *
 * @retval CRYPT_NULL_INPUT          Invalid null pointer input.
 * @retval CRYPT_DSA_PARA_ERROR      The key parameter data is incorrect.
 * @retval BN error code.            An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS             Get successfully.
 */
int32_t CRYPT_DSA_GetParaEx(const CRYPT_DSA_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup dsa
 * @brief Set the private key data for the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param para [IN] External private key data
 *
 * @retval CRYPT_NULL_INPUT          Invalid null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_PARA    The key parameter data is incorrect.
 * @retval CRYPT_DSA_ERR_KEY_INFO    The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL      Memory allocation failure.
 * @retval BN error.                 An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS             Set successfully.
 */
int32_t CRYPT_DSA_SetPrvKeyEx(CRYPT_DSA_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup dsa
 * @brief Set the public key data for the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param para [IN] External public key data
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_PARA   The key parameter data is incorrect.
 * @retval CRYPT_DSA_ERR_KEY_INFO   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure.
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DSA_SetPubKeyEx(CRYPT_DSA_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup dsa
 * @brief Obtain the private key data of the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param para [OUT] External private key data
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input.
 * @retval CRYPT_DSA_BUFF_LEN_NOT_ENOUGH    The buffer length is insufficient.
 * @retval CRYPT_DSA_ERR_KEY_INFO           The key information is incorrect.
 * @retval BN error.                        An error occurs in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS                    Obtained successfully.
 */
int32_t CRYPT_DSA_GetPrvKeyEx(const CRYPT_DSA_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup dsa
 * @brief Obtain the public key data of the DSA.
 *
 * @param ctx [IN] DSA context structure
 * @param para [OUT] External public key data
 *
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input.
 * @retval CRYPT_DSA_BUFF_LEN_NOT_ENOUGH    The buffer length is insufficient.
 * @retval CRYPT_DSA_ERR_KEY_INFO           The key information is incorrect.
 * @retval BN error.                        An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS                    Obtained successfully.
 */
int32_t CRYPT_DSA_GetPubKeyEx(const CRYPT_DSA_Ctx *ctx, BSL_Param *para);

#ifdef HITLS_CRYPTO_DSA_CMP
/**
 * @ingroup dsa
 * @brief dsa Compare public keys and parameters
 *
 * @param a [IN] DSA context structure
 * @param b [IN] DSA context structure
 *
 * @retval CRYPT_SUCCESS                is the same
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input.
 * @retval CRYPT_DSA_ERR_KEY_INFO       The key information is incorrect.
 * @retval CRYPT_DSA_PUBKEY_NOT_EQUAL   Public keys are not equal.
 * @retval CRYPT_DSA_PARA_ERROR         The parameter information is incorrect.
 * @retval CRYPT_DSA_PARA_NOT_EQUAL     The parameters are not equal.
 */
int32_t CRYPT_DSA_Cmp(const CRYPT_DSA_Ctx *a, const CRYPT_DSA_Ctx *b);
#else
#define CRYPT_DSA_Cmp NULL
#endif

/**
 * @ingroup dsa
 * @brief DSA control interface
 *
 * @param ctx [IN] DSA context structure
 * @param opt [IN] Operation mode
 * @param val [IN] Parameter
 * @param len [IN] val length
 *
 * @retval CRYPT_NULL_INPUT Invalid null pointer input
 * @retval CRYPT_SUCCESS    obtained successfully.
 */
int32_t CRYPT_DSA_Ctrl(CRYPT_DSA_Ctx *ctx, int32_t opt, void *val, uint32_t len);


/**
 * @ingroup DSA
 * @brief DSA get security bits
 *
 * @param ctx [IN] DSA Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_DSA_GetSecBits(const CRYPT_DSA_Ctx *ctx);

#ifdef HITLS_CRYPTO_DSA_CHECK

/**
 * @ingroup dsa
 * @brief check the key pair consistency
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] dsa key context structure
 * @param pkey2 [IN] dsa key context structure
 *
 * @retval CRYPT_SUCCESS            succeeded
 * @retval other                    error.
 */
int32_t CRYPT_DSA_Check(uint32_t checkType, const CRYPT_DSA_Ctx *pkey1, const CRYPT_DSA_Ctx *pkey2);

#endif // HITLS_CRYPTO_DSA_CHECK

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DSA

#endif // CRYPT_DSA_H
