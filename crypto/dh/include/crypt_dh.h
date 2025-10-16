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

#ifndef CRYPT_DH_H
#define CRYPT_DH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DH

#include <stdint.h>
#include "crypt_types.h"
#include "crypt_algid.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#ifndef CRYPT_DH_TRY_CNT_MAX
#define CRYPT_DH_TRY_CNT_MAX 100
#endif

/* DH key parameter */
typedef struct DH_Para CRYPT_DH_Para;

/* DH key context */
typedef struct DH_Ctx CRYPT_DH_Ctx;

/**
 * @ingroup dh
 * @brief dh Allocate the context of dh.
 *
 * @retval (CRYPT_DH_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer
 */
CRYPT_DH_Ctx *CRYPT_DH_NewCtx(void);

/**
 * @ingroup dh
 * @brief dh Allocate the context of dh.
 *
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_DH_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer
 */
CRYPT_DH_Ctx *CRYPT_DH_NewCtxEx(void *libCtx);

/**
 * @ingroup dh
 * @brief Copy the DH context. After the duplicated context is used up, call CRYPT_DH_FreeCtx to release the memory.
 *
 * @param ctx [IN] Source DH context
 *
 * @return CRYPT_DH_Ctx DH context pointer
 *         If the operation fails, null is returned.
 */
CRYPT_DH_Ctx *CRYPT_DH_DupCtx(CRYPT_DH_Ctx *ctx);

/**
 * @ingroup dh
 * @brief dh Release context structure of dh key
 *
 * @param ctx [IN] Indicates the pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_DH_FreeCtx(CRYPT_DH_Ctx *ctx);

/**
 * @ingroup dh
 * @brief dh Allocate key parameter structure space
 *
 * @param para [IN] DH External parameter
 *
 * @retval (CRYPT_DH_Para *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_DH_Para *CRYPT_DH_NewPara(const CRYPT_DhPara *para);

/**
 * @ingroup dh
 * @brief Release dh key parameter structure
 *
 * @param para [IN] Pointer to the key parameter structure to be released. The parameter is set NULL by the invoker.
 */
void CRYPT_DH_FreePara(CRYPT_DH_Para *dhPara);

/**
 * @ingroup dh
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [IN] Key structure for setting related parameters. The key specification is 1024-8192 bits.
 * @param para [IN] Key parameters
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input.
 * @retval CRYPT_DH_PARA_ERROR      The key parameter data is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Internal Memory Allocation Error
 * @retval BN error code:           An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DH_SetPara(CRYPT_DH_Ctx *ctx, const CRYPT_DhPara *para);

/**
 * @ingroup dh
 * @brief Obtain the key structure parameters.
 *
 * @param ctx [IN] Key structure
 * @param para [OUT] Obtained key parameter.
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input.
 * @retval CRYPT_DH_PARA_ERROR  The key parameter data is incorrect.
 * @retval BN error code:       An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t CRYPT_DH_GetPara(const CRYPT_DH_Ctx *ctx, CRYPT_DhPara *para);
/**
 * @ingroup dh
 * @brief Set a parameter based on the parameter ID.
 *
 * @param id [IN] Parameter ID
 *
 * @retval (CRYPT_DH_Para *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_DH_Para *CRYPT_DH_NewParaById(CRYPT_PKEY_ParaId id);

/**
 * @ingroup dh
 * @brief Obtain the parameter ID.
 *
 * @param ctx [IN] Key structure
 *
 * @retval ID. If the context is invalid, CRYPT_PKEY_PARAID_MAX is returned.
 */
CRYPT_PKEY_ParaId CRYPT_DH_GetParaId(const CRYPT_DH_Ctx *ctx);

/**
 * @ingroup dh
 * @brief Obtain the valid length of the key.
 *
 * @param ctx [IN] Structure from which the key length is expected to be obtained
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not have a valid key length.
 * @retval uint32_t Valid key length
 */
uint32_t CRYPT_DH_GetBits(const CRYPT_DH_Ctx *ctx);

/**
 * @ingroup dh
 * @brief Generate the DH key pair.
 *
 * @param ctx [IN] dh Context structure
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_DH_PARA_ERROR          The key parameter data is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval CRYPT_DH_RAND_GENRATE_ERROR  Unable to generate results within the specified number of attempts
 * @retval BN error code:               An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS                The key pair is successfully generated.
 */
int32_t CRYPT_DH_Gen(CRYPT_DH_Ctx *ctx);

/**
 * @ingroup dh
 * @brief DH key exchange
 *
 * @param ctx [IN] dh Context structure
 * @param pubKey [IN] Public key data
 * @param shareKey [OUT] Shared key
 * @param shareKeyLen [IN/OUT] The input parameter is the length of the shareKey,
 *                             and the output parameter is the valid length of the shareKey.
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_DH_BUFF_LEN_NOT_ENOUGH The buffer length is insufficient.
 * @retval CRYPT_DH_KEYINFO_ERROR       The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL         Memory allocation failure
 * @retval BN error.                    An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                Key exchange succeeded.
 */
int32_t CRYPT_DH_ComputeShareKey(const CRYPT_DH_Ctx *ctx, const CRYPT_DH_Ctx *pubKey,
    uint8_t *shareKey, uint32_t *shareKeyLen);

/**
 * @ingroup dh
 * @brief DH Set the private key.
 *
 * @param ctx [OUT] dh Context structure
 * @param prv [IN] Private key
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input
 * @retval CRYPT_DH_PARA_ERROR      The key parameter is incorrect.
 * @retval CRYPT_DH_KEYINFO_ERROR   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DH_SetPrvKey(CRYPT_DH_Ctx *ctx, const CRYPT_DhPrv *prv);

/**
 * @ingroup dh
 * @brief DH Set the public key data.
 *
 * @param ctx [OUT] dh Context structure
 * @param pub [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_DH_PARA_ERROR      The key parameter data is incorrect.
 * @retval CRYPT_DH_KEYINFO_ERROR   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DH_SetPubKey(CRYPT_DH_Ctx *ctx, const CRYPT_DhPub *pub);

/**
 * @ingroup dh
 * @brief DH Obtain the private key data.
 *
 * @param ctx [IN] dh Context structure
 * @param prv [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_DH_BUFF_LEN_NOT_ENOUGH The buffer length is insufficient.
 * @retval CRYPT_DH_KEYINFO_ERROR       The key information is incorrect.
 * @retval BN error.                    An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                obtained successfully.
 */
int32_t CRYPT_DH_GetPrvKey(const CRYPT_DH_Ctx *ctx, CRYPT_DhPrv *prv);

/**
 * @ingroup dh
 * @brief DH Obtain the public key data.
 *
 * @param ctx [IN] dh Context structure
 * @param pub [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_DH_BUFF_LEN_NOT_ENOUGH The buffer length is insufficient.
 * @retval CRYPT_DH_KEYINFO_ERROR       The key information is incorrect.
 * @retval BN error.                    An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t CRYPT_DH_GetPubKey(const CRYPT_DH_Ctx *ctx, CRYPT_DhPub *pub);

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup dh
 * @brief DH Set the private key.
 *
 * @param ctx [OUT] dh Context structure
 * @param para [IN] Private key
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input
 * @retval CRYPT_DH_PARA_ERROR      The key parameter is incorrect.
 * @retval CRYPT_DH_KEYINFO_ERROR   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DH_SetPrvKeyEx(CRYPT_DH_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup dh
 * @brief DH Set the public key data.
 *
 * @param ctx [OUT] dh Context structure
 * @param para [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_DH_PARA_ERROR      The key parameter data is incorrect.
 * @retval CRYPT_DH_KEYINFO_ERROR   The key information is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DH_SetPubKeyEx(CRYPT_DH_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup dh
 * @brief DH Obtain the private key data.
 *
 * @param ctx [IN] dh Context structure
 * @param para [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_DH_BUFF_LEN_NOT_ENOUGH The buffer length is insufficient.
 * @retval CRYPT_DH_KEYINFO_ERROR       The key information is incorrect.
 * @retval BN error.                    An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                obtained successfully.
 */
int32_t CRYPT_DH_GetPrvKeyEx(const CRYPT_DH_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup dh
 * @brief DH Obtain the public key data.
 *
 * @param ctx [IN] dh Context structure
 * @param para [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_DH_BUFF_LEN_NOT_ENOUGH The buffer length is insufficient.
 * @retval CRYPT_DH_KEYINFO_ERROR       The key information is incorrect.
 * @retval BN error.                    An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t CRYPT_DH_GetPubKeyEx(const CRYPT_DH_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup dh
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [IN] Key structure for setting related parameters. The key specification is 1024-8192 bits.
 * @param para [IN] Key parameters
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input.
 * @retval CRYPT_DH_PARA_ERROR      The key parameter data is incorrect.
 * @retval CRYPT_MEM_ALLOC_FAIL     Internal Memory Allocation Error
 * @retval BN error code:           An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS            Set successfully.
 */
int32_t CRYPT_DH_SetParaEx(CRYPT_DH_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup dh
 * @brief Obtain the key structure parameters.
 *
 * @param ctx [IN] Key structure
 * @param para [OUT] Obtained key parameter.
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input.
 * @retval CRYPT_DH_PARA_ERROR  The key parameter data is incorrect.
 * @retval BN error code:       An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t CRYPT_DH_GetParaEx(const CRYPT_DH_Ctx *ctx, BSL_Param *para);
#endif

#ifdef HITLS_CRYPTO_DH_CHECK
/**
 * @ingroup dh
 * @brief check the key pair consistency
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] dh key context structure
 * @param pkey2 [IN] dh key context structure
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_DH_Check(uint32_t checkType, const CRYPT_DH_Ctx *pkey1, const CRYPT_DH_Ctx *pkey2);

#endif // HITLS_CRYPTO_DH_CHECK

#ifdef HITLS_CRYPTO_DH_CMP
/**
 * @ingroup dh
 * @brief dh Compare public keys and parameters
 *
 * @param a [IN] dh Context structure
 * @param b [IN] dh Context structure
 *
 * @return CRYPT_SUCCESS            is the same
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input
 * @retval CRYPT_DH_KEYINFO_ERROR   The key information is incorrect.
 * @retval CRYPT_DH_PUBKEY_NOT_EQUAL Public Keys are not equal
 * @retval CRYPT_DH_PARA_ERROR      The parameter data is incorrect.
 * @retval CRYPT_DH_PARA_NOT_EQUAL  The parameters are not equal.
 */
int32_t CRYPT_DH_Cmp(const CRYPT_DH_Ctx *a, const CRYPT_DH_Ctx *b);
#else
#define CRYPT_DH_Cmp NULL
#endif

/**
 * @ingroup dh
 * @brief DH control interface
 *
 * @param ctx [IN] dh Context structure
 * @param opt [IN] Operation mode
 * @param val [IN] Parameter
 * @param len [IN] val length
 *
 * @retval CRYPT_NULL_INPUT Error null pointer input
 * @retval CRYPT_SUCCESS    obtained successfully.
 */
int32_t CRYPT_DH_Ctrl(CRYPT_DH_Ctx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup dh
 * @brief dh get security bits
 *
 * @param ctx [IN] dh Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_DH_GetSecBits(const CRYPT_DH_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DH

#endif // CRYPT_DH_H
