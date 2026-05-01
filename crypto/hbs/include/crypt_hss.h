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

#ifndef CRYPT_HSS_H
#define CRYPT_HSS_H

#include "hitls_build.h"

#ifdef HITLS_CRYPTO_HSS

#include <stdint.h>
#include <stddef.h>
#include "bsl_params.h"
#include "crypt_lms.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @defgroup hss HSS - Hierarchical Signature System (RFC 8554)
 * @ingroup crypt
 * @brief Hierarchical Signature System (HSS)
 */

typedef struct HssCtx CRYPT_HSS_Ctx;

/* HSS control commands (range 950-999, avoids collision with common CRYPT_CTRL_* enum) */
#define CRYPT_CTRL_HSS_SET_LEVELS     950 /**< Set hierarchy levels (1-3) */
#define CRYPT_CTRL_HSS_SET_LMS_TYPE   951 /**< Set LMS type for level */
#define CRYPT_CTRL_HSS_SET_OTS_TYPE   952 /**< Set OTS type for level */
#define CRYPT_CTRL_HSS_GET_PUBKEY_LEN 953 /**< Get public key length */
#define CRYPT_CTRL_HSS_GET_PRVKEY_LEN 954 /**< Get private key length */
#define CRYPT_CTRL_HSS_GET_SIG_LEN    955 /**< Get signature length */
#define CRYPT_CTRL_HSS_GET_REMAINING  956 /**< Get remaining signatures */
#define CRYPT_CTRL_HSS_GET_LEVELS     957 /**< Get number of levels */

/**
 * @ingroup hss
 * @brief hss Allocates context memory space.
 *
 * @retval (CRYPT_HSS_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtx(void);

/**
 * @ingroup hss
 * @brief hss Allocates context memory space.
 *
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_HSS_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtxEx(void *libCtx);

/**
 * @ingroup hss
 * @brief hss Release the key context structure.
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_HSS_FreeCtx(CRYPT_HSS_Ctx *ctx);

/**
 * @ingroup hss
 * @brief Copy the HSS context. After the duplication is complete, invoke CRYPT_HSS_FreeCtx to release the memory.
 *
 * @param srcCtx [IN] Source HSS context
 *
 * @retval (CRYPT_HSS_Ctx *) Pointer to the duplicated HSS context
 * @retval NULL              If the operation fails, null is returned.
 */
CRYPT_HSS_Ctx *CRYPT_HSS_DupCtx(CRYPT_HSS_Ctx *srcCtx);

/**
 * @ingroup hss
 * @brief hss Compare public keys and parameters.
 *
 * @param ctx1 [IN] HSS context structure
 * @param ctx2 [IN] HSS context structure
 *
 * @retval CRYPT_SUCCESS     The contexts are the same.
 * @retval CRYPT_NULL_INPUT  Invalid null pointer input.
 * @retval Other error code  The contexts are not equal.
 */
int32_t CRYPT_HSS_Cmp(CRYPT_HSS_Ctx *ctx1, CRYPT_HSS_Ctx *ctx2);

/**
 * @ingroup hss
 * @brief HSS control interface.
 *
 * @param ctx [IN] HSS context structure
 * @param cmd [IN] Control command
 * @param val [IN/OUT] Parameter value
 * @param valLen [IN] Length of val
 *
 * @retval CRYPT_NULL_INPUT  Invalid null pointer input.
 * @retval CRYPT_SUCCESS     Operation successful.
 */
int32_t CRYPT_HSS_Ctrl(CRYPT_HSS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup hss
 * @brief Generate an HSS key pair.
 *
 * @param ctx [IN/OUT] HSS context structure
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL  Memory allocation failure.
 * @retval CRYPT_SUCCESS         The key pair is successfully generated.
 */
int32_t CRYPT_HSS_Gen(CRYPT_HSS_Ctx *ctx);

/**
 * @ingroup hss
 * @brief Set the private key data for the HSS.
 *
 * @param ctx [IN] HSS context structure
 * @param param [IN] External private key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL  Memory allocation failure.
 * @retval CRYPT_SUCCESS         Set successfully.
 */
int32_t CRYPT_HSS_SetPrvKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup hss
 * @brief Set the public key data for the HSS.
 *
 * @param ctx [IN] HSS context structure
 * @param param [IN] External public key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL  Memory allocation failure.
 * @retval CRYPT_SUCCESS         Set successfully.
 */
int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup hss
 * @brief Obtain the private key data of the HSS.
 *
 * @param ctx [IN] HSS context structure
 * @param param [OUT] External private key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_SUCCESS         Obtained successfully.
 */
int32_t CRYPT_HSS_GetPrvKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup hss
 * @brief Obtain the public key data of the HSS.
 *
 * @param ctx [IN] HSS context structure
 * @param param [OUT] External public key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_SUCCESS         Obtained successfully.
 */
int32_t CRYPT_HSS_GetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup hss
 * @brief HSS Signature.
 *
 * @param ctx [IN] HSS context structure
 * @param algId [IN] Hash algorithm ID
 * @param msg [IN] Data to be signed
 * @param msgLen [IN] Length of the data to be signed
 * @param sig [OUT] Signature data
 * @param sigLen [IN/OUT] The input parameter is the space length of the sig,
 *                        and the output parameter is the valid length of the sig.
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL  Memory allocation failure.
 * @retval CRYPT_SUCCESS         Signed successfully.
 */
int32_t CRYPT_HSS_Sign(CRYPT_HSS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                       uint32_t *sigLen);

/**
 * @ingroup hss
 * @brief HSS Verification.
 *
 * @param ctx [IN] HSS context structure
 * @param algId [IN] Hash algorithm ID
 * @param msg [IN] Data to be verified
 * @param msgLen [IN] Length of the data to be verified
 * @param sig [IN] Signature data
 * @param sigLen [IN] Length of the signature data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_SUCCESS         The signature is verified successfully.
 */
int32_t CRYPT_HSS_Verify(const CRYPT_HSS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen,
                         const uint8_t *sig, uint32_t sigLen);

#ifdef HITLS_CRYPTO_HSS_CHECK
/**
 * @ingroup hss
 * @brief Check the key pair consistency.
 *
 * @param checkType [IN] Check type
 * @param pkey1 [IN] HSS key context structure
 * @param pkey2 [IN] HSS key context structure
 *
 * @retval CRYPT_SUCCESS     Succeeded.
 * @retval Other error code  Check failed.
 */
int32_t CRYPT_HSS_Check(uint32_t checkType, const CRYPT_HSS_Ctx *pkey1, const CRYPT_HSS_Ctx *pkey2);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_HSS */
#endif /* CRYPT_HSS_H */
