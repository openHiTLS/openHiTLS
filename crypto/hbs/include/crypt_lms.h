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

#ifndef CRYPT_LMS_H
#define CRYPT_LMS_H

#include "hitls_build.h"

#ifdef HITLS_CRYPTO_LMS

#include <stdint.h>
#include <stddef.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @defgroup lms LMS - Hash-Based Signatures (RFC 8554)
 * @ingroup crypt
 * @brief Leighton-Micali Signature (LMS)
 */

typedef struct LmsCtx CRYPT_LMS_Ctx;

/* LMS tree type identifiers (RFC 8554 Section 5.1) — for CRYPT_CTRL_LMS_SET_TYPE */
#define CRYPT_LMS_SHA256_M32_H5  0x00000005u /**< SHA-256, n=32, h=5  (32 signatures) */
#define CRYPT_LMS_SHA256_M32_H10 0x00000006u /**< SHA-256, n=32, h=10 (1024 signatures) */
#define CRYPT_LMS_SHA256_M32_H15 0x00000007u /**< SHA-256, n=32, h=15 (32768 signatures) */
#define CRYPT_LMS_SHA256_M32_H20 0x00000008u /**< SHA-256, n=32, h=20 (1048576 signatures) */
#define CRYPT_LMS_SHA256_M32_H25 0x00000009u /**< SHA-256, n=32, h=25 (33554432 signatures) */

/* LM-OTS type identifiers (RFC 8554 Section 4.1) — for CRYPT_CTRL_LMS_SET_OTS_TYPE */
#define CRYPT_LMOTS_SHA256_N32_W1 0x00000001u /**< SHA-256, n=32, w=1 */
#define CRYPT_LMOTS_SHA256_N32_W2 0x00000002u /**< SHA-256, n=32, w=2 */
#define CRYPT_LMOTS_SHA256_N32_W4 0x00000003u /**< SHA-256, n=32, w=4 */
#define CRYPT_LMOTS_SHA256_N32_W8 0x00000004u /**< SHA-256, n=32, w=8 */

/* LMS control commands (range 900-949, avoids collision with common CRYPT_CTRL_* enum) */
#define CRYPT_CTRL_LMS_SET_TYPE       900 /**< Set LMS tree type */
#define CRYPT_CTRL_LMS_SET_OTS_TYPE   901 /**< Set LM-OTS type */
#define CRYPT_CTRL_LMS_GET_PUBKEY_LEN 902 /**< Get public key length */
#define CRYPT_CTRL_LMS_GET_PRVKEY_LEN 903 /**< Get private key length */
#define CRYPT_CTRL_LMS_GET_SIG_LEN    904 /**< Get signature length */
#define CRYPT_CTRL_LMS_GET_REMAINING  905 /**< Get remaining signatures */

/**
 * @ingroup lms
 * @brief lms Allocates context memory space.
 *
 * @retval (CRYPT_LMS_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_LMS_Ctx *CRYPT_LMS_NewCtx(void);

/**
 * @ingroup lms
 * @brief lms Allocates context memory space.
 *
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_LMS_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer
 */
CRYPT_LMS_Ctx *CRYPT_LMS_NewCtxEx(void *libCtx);

/**
 * @ingroup lms
 * @brief lms Release the key context structure.
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_LMS_FreeCtx(CRYPT_LMS_Ctx *ctx);

/**
 * @ingroup lms
 * @brief Copy the LMS context. After the duplication is complete, invoke CRYPT_LMS_FreeCtx to release the memory.
 *
 * @param srcCtx [IN] Source LMS context
 *
 * @retval (CRYPT_LMS_Ctx *) Pointer to the duplicated LMS context
 * @retval NULL              If the operation fails, null is returned.
 */
CRYPT_LMS_Ctx *CRYPT_LMS_DupCtx(CRYPT_LMS_Ctx *srcCtx);

/**
 * @ingroup lms
 * @brief lms Compare public keys and parameters.
 *
 * @param ctx1 [IN] LMS context structure
 * @param ctx2 [IN] LMS context structure
 *
 * @retval CRYPT_SUCCESS     The contexts are the same.
 * @retval CRYPT_NULL_INPUT  Invalid null pointer input.
 * @retval Other error code  The contexts are not equal.
 */
int32_t CRYPT_LMS_Cmp(CRYPT_LMS_Ctx *ctx1, CRYPT_LMS_Ctx *ctx2);

/**
 * @ingroup lms
 * @brief LMS control interface.
 *
 * @param ctx [IN] LMS context structure
 * @param cmd [IN] Control command
 * @param val [IN/OUT] Parameter value
 * @param valLen [IN] Length of val
 *
 * @retval CRYPT_NULL_INPUT  Invalid null pointer input.
 * @retval CRYPT_SUCCESS     Operation successful.
 */
int32_t CRYPT_LMS_Ctrl(CRYPT_LMS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup lms
 * @brief Generate an LMS key pair.
 *
 * @param ctx [IN/OUT] LMS context structure
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL  Memory allocation failure.
 * @retval CRYPT_SUCCESS         The key pair is successfully generated.
 */
int32_t CRYPT_LMS_Gen(CRYPT_LMS_Ctx *ctx);

/**
 * @ingroup lms
 * @brief Set the private key data for the LMS.
 *
 * @param ctx [IN] LMS context structure
 * @param param [IN] External private key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL  Memory allocation failure.
 * @retval CRYPT_SUCCESS         Set successfully.
 */
int32_t CRYPT_LMS_SetPrvKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup lms
 * @brief Set the public key data for the LMS.
 *
 * @param ctx [IN] LMS context structure
 * @param param [IN] External public key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_MEM_ALLOC_FAIL  Memory allocation failure.
 * @retval CRYPT_SUCCESS         Set successfully.
 */
int32_t CRYPT_LMS_SetPubKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup lms
 * @brief Obtain the private key data of the LMS.
 *
 * @param ctx [IN] LMS context structure
 * @param param [OUT] External private key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_SUCCESS         Obtained successfully.
 */
int32_t CRYPT_LMS_GetPrvKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup lms
 * @brief Obtain the public key data of the LMS.
 *
 * @param ctx [IN] LMS context structure
 * @param param [OUT] External public key data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_SUCCESS         Obtained successfully.
 */
int32_t CRYPT_LMS_GetPubKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup lms
 * @brief LMS Signature.
 *
 * @param ctx [IN] LMS context structure
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
int32_t CRYPT_LMS_Sign(CRYPT_LMS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                       uint32_t *sigLen);

/**
 * @ingroup lms
 * @brief LMS Verification.
 *
 * @param ctx [IN] LMS context structure
 * @param algId [IN] Hash algorithm ID
 * @param msg [IN] Data to be verified
 * @param msgLen [IN] Length of the data to be verified
 * @param sig [IN] Signature data
 * @param sigLen [IN] Length of the signature data
 *
 * @retval CRYPT_NULL_INPUT      Invalid null pointer input.
 * @retval CRYPT_SUCCESS         The signature is verified successfully.
 */
int32_t CRYPT_LMS_Verify(const CRYPT_LMS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen,
                         const uint8_t *sig, uint32_t sigLen);

#ifdef HITLS_CRYPTO_LMS_CHECK
/**
 * @ingroup lms
 * @brief Check the key pair consistency.
 *
 * @param checkType [IN] Check type
 * @param pkey1 [IN] LMS key context structure
 * @param pkey2 [IN] LMS key context structure
 *
 * @retval CRYPT_SUCCESS     Succeeded.
 * @retval Other error code  Check failed.
 */
int32_t CRYPT_LMS_Check(uint32_t checkType, const CRYPT_LMS_Ctx *pkey1, const CRYPT_LMS_Ctx *pkey2);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_LMS */
#endif /* CRYPT_LMS_H */
