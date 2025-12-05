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

#ifndef CRYPT_ECDH_H
#define CRYPT_ECDH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECDH

#include <stdint.h>
#include "crypt_types.h"
#include "crypt_algid.h"
#include "crypt_ecc_pkey.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

/* ECDH key context */
typedef struct ECC_PkeyCtx CRYPT_ECDH_Ctx;

/* ECDH parameter structure */
typedef struct EccPara CRYPT_EcdhPara;

/**
 * @ingroup ecdh
 * @brief ecdh Allocate the context memory space.
 *
 * @retval (CRYPT_ECDH_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL               Invalid null pointer
 */
CRYPT_ECDH_Ctx *CRYPT_ECDH_NewCtx(void);

/**
 * @ingroup ecdh
 * @brief ecdh Allocate the context memory space.
 * 
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_ECDH_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL               Invalid null pointer
 */
CRYPT_ECDH_Ctx *CRYPT_ECDH_NewCtxEx(void *libCtx);

/**
 * @ingroup ecdh
 * @brief Copy the ECDH context. After the duplication is complete, call the CRYPT_ECDH_FreeCtx to release the memory.
 *
 * @param ctx [IN] Source ECDH context
 *
 * @return CRYPT_ECDH_Ctx ECDH context pointer
 * If the operation fails, null is returned.
 */
#define CRYPT_ECDH_DupCtx ECC_DupCtx

/**
 * @ingroup ecdh
 * @brief ecdh Release the key context structure
 *
 * @param ctx [IN] Indicate the pointer of the context structure to be released. The ctx is set NULL by the invoker.
 */
#define CRYPT_ECDH_FreeCtx ECC_FreeCtx

/**
 * @ingroup ecdh
 * @brief Set a parameter based on the parameter ID.
 *
 * @param id [IN] Curve ID Parameter ID, which can be selected CRYPT_ECC_NISTP224 to CRYPT_ECC_BRAINPOOLP512R1 only
 *                from CRYPT_PKEY_ParaId.
 *
 * @retval (CRYPT_EcdhPara *) Pointer to the memory space of the allocated context
 * @retval NULL               Invalid null pointer
 */
#define CRYPT_ECDH_NewParaById ECC_NewPara

/**
 * @ingroup ecdh
 * @brief Set a parameter based on the eccPara parameter.
 *
 * @param eccPara [IN] Curve parameter information,
 * which can be selected CRYPT_ECC_NISTP224 to CRYPT_ECC_BRAINPOOLP512R1 only from the CRYPT_PKEY_ParaId.
 *
 * @retval (CRYPT_EcdhPara *) Pointer to the memory space of the allocated context
 * @retval NULL               Invalid null pointer
 */
CRYPT_EcdhPara *CRYPT_ECDH_NewPara(const CRYPT_EccPara *eccPara);

/**
 * @ingroup ecdh
 * @brief Obtain the parameter ID.
 *
 * @param ctx [IN] ECDH context
 *
 * @retval ID. If the context is invalid, CRYPT_PKEY_PARAID_MAX is returned.
 */
CRYPT_PKEY_ParaId CRYPT_ECDH_GetParaId(const CRYPT_ECDH_Ctx *ctx);

/**
 * @ingroup ecdh
 * @brief ecdh Release a key parameter structure
 *
 * @param para [IN] Pointer to the key parameter structure to be released. The parameter is set NULL by the invoker.
 */
#define CRYPT_ECDH_FreePara ECC_FreePara

/**
 * @ingroup ecdh
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [OUT] Key structure for setting related parameters
 * @param para [IN] Key parameters
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL internal memory allocation error
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t CRYPT_ECDH_SetPara(CRYPT_ECDH_Ctx *ctx, const CRYPT_EccPara *para);

/**
 * @ingroup ecdh
 * @brief Get the data of the key structure to the key parameter structure.
 *
 * @param ctx [IN] Key structure for setting related parameters
 * @param para [OUT] Key parameters
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL Internal memory allocation error
 * @retval CRYPT_SUCCESS        Get successfully.
 */
#define CRYPT_ECDH_GetPara ECC_GetPara

/**
 * @ingroup ecdh
 * @brief Obtain the valid length of the private key, which is used before obtaining the private key.
 *
 * @param ctx [IN] Structure from which the key length is expected to be obtained
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not have a valid key length.
 * @retval uint32_t Valid key length
 */
#define CRYPT_ECDH_GetBits ECC_PkeyGetBits

/**
 * @ingroup ecdh
 * @brief Generate the ECDH key pair.
 *
 * @param ctx [IN] ECDH Context structure
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error code.      Internal ECC calculation error
 * @retval CRYPT_SUCCESS        The key pair is successfully generated.
 */
#define CRYPT_ECDH_Gen ECC_PkeyGen

/**
 * @ingroup ecdh
 * @brief ECDH key exchange
 *
 * @param ctx [IN] dh Context structure
 * @param pubKey [IN] Public key data
 * @param shareKey [OUT] Shared key
 * @param shareKeyLen [IN/OUT] The input parameter is the space length of the shareKey,
 *                             and the output parameter is the valid length of the shareKey.
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_ECDH_ERR_EMPTY_KEY         The ctx private key is empty or the public key pubKey is empty.
 * @retval CRYPT_ECDH_ERR_INVALID_COFACTOR  Invalid harmonic factor h
 * @retval BN error.                        An error occurs in the internal BigNum operation.
 * @retval ECC error code.                  Internal ECC calculation error
 * @retval CRYPT_SUCCESS                    Key exchange succeeded.
 */
int32_t CRYPT_ECDH_ComputeShareKey(const CRYPT_ECDH_Ctx *ctx, const CRYPT_ECDH_Ctx *pubKey,
    uint8_t *shareKey, uint32_t *shareKeyLen);

/**
 * @ingroup ecdh
 * @brief ECDH Set the private key data.
 *
 * @param ctx [OUT] ecdh context structure
 * @param prv [IN] Private key data
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
#define CRYPT_ECDH_SetPrvKey ECC_PkeySetPrvKey

/**
 * @ingroup ecdh
 * @brief ECDH Set the public key data.
 *
 * @param ctx [OUT] ecdh context structure
 * @param pub [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
#define CRYPT_ECDH_SetPubKey ECC_PkeySetPubKey

/**
 * @ingroup ecdh
 * @brief ECDH Obtain the private key data.
 *
 * @param ctx [IN] ecdh context structure
 * @param prv [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
#define CRYPT_ECDH_GetPrvKey ECC_PkeyGetPrvKey

/**
 * @ingroup ecdh
 * @brief ECDH Obtain the public key data.
 *
 * @param ctx [IN] ecdh context structure
 * @param pub [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
#define CRYPT_ECDH_GetPubKey ECC_PkeyGetPubKey

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup ecdh
 * @brief ECDH Set the private key data.
 *
 * @param ctx [OUT] ecdh context structure
 * @param para [IN] Private key data
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
#define CRYPT_ECDH_SetPrvKeyEx ECC_PkeySetPrvKeyEx

/**
 * @ingroup ecdh
 * @brief ECDH Set the public key data.
 *
 * @param ctx [OUT] ecdh context structure
 * @param para [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
#define CRYPT_ECDH_SetPubKeyEx ECC_PkeySetPubKeyEx

/**
 * @ingroup ecdh
 * @brief ECDH Obtain the private key data.
 *
 * @param ctx [IN] ecdh context structure
 * @param para [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
#define CRYPT_ECDH_GetPrvKeyEx ECC_PkeyGetPrvKeyEx

/**
 * @ingroup ecdh
 * @brief ECDH Obtain the public key data.
 *
 * @param ctx [IN] ecdh context structure
 * @param para [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
#define CRYPT_ECDH_GetPubKeyEx ECC_PkeyGetPubKeyEx

/**
 * @ingroup ecdh
 * @brief Get the data of the key structure to the key parameter structure.
 *
 * @param ctx [IN] Key structure for setting related parameters
 * @param para [OUT] Key parameters
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL Internal memory allocation error
 * @retval CRYPT_SUCCESS        Get successfully.
 */
#define CRYPT_ECDH_GetParaEx ECC_GetParaEx

/**
 * @ingroup ecdh
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [OUT] Key structure for setting related parameters
 * @param para [IN] Key parameters
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL internal memory allocation error
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t CRYPT_ECDH_SetParaEx(CRYPT_ECDH_Ctx *ctx, const BSL_Param *para);
#endif

/**
 * @ingroup ecdh
 * @brief ecdh control interface
 *
 * @param ctx [IN/OUT] ecdh context structure
 * @param opt [IN] Operation mode. For details, see ECC_CtrlType.
 * @param val [IN] Input parameter about ctrl
 * @param len [IN] val Length
 *
 * @retval CRYPT_SUCCESS                                Set successfully.
 * @retval CRYPT_NULL_INPUT                             If any input parameter is empty
 * @retval CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT      Invalid point format
 * @retval CRYPT_ECC_PKEY_ERR_CTRL_LEN                  The len is incorrect.
 * @retval CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION   opt mode not supported
 */
int32_t CRYPT_ECDH_Ctrl(CRYPT_ECDH_Ctx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup ecdh
 * @brief ecdh Compare public keys and parameters
 *
 * @param a [IN] ecdh context structure
 * @param b [IN] ecdh context structure
 *
 * @retval CRYPT_SUCCESS    is the same
 *         Others.          For details, see errno.
 */
#define CRYPT_ECDH_Cmp ECC_PkeyCmp

/**
 * @ingroup ecdh
 * @brief ecdh get security bits
 *
 * @param ctx [IN] ecdh Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_ECDH_GetSecBits(const CRYPT_ECDH_Ctx *ctx);

#ifdef HITLS_CRYPTO_ECDH_CHECK

/**
 * @ingroup ecdh
 * @brief ecdh check public key
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] ecdh context structure
 * @param pkey2 [IN] ecdh context structure
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_ECDH_Check(uint32_t checkType, const CRYPT_ECDH_Ctx *pkey1, const CRYPT_ECDH_Ctx *pkey2);

#endif // HITLS_CRYPTO_ECDH_CHECK

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ECDH

#endif // CRYPT_ECDH_H
