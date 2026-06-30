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

#ifndef CRYPT_XMSSMT_H
#define CRYPT_XMSSMT_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSSMT

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct CryptXmssmtCtx CryptXmssmtCtx;

/**
 * @ingroup xmssmt
 * @brief Allocate XMSSMT context memory space.
 *
 * @retval (CryptXmssmtCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptXmssmtCtx *CRYPT_XMSSMT_NewCtx(void);

/**
 * @ingroup xmssmt
 * @brief Allocate XMSSMT context memory space.
 *
 * @param libCtx [IN] Library context
 *
 * @retval (CryptXmssmtCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptXmssmtCtx *CRYPT_XMSSMT_NewCtxEx(void *libCtx);

/**
 * @ingroup xmssmt
 * @brief Release XMSSMT key context structure.
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_XMSSMT_FreeCtx(CryptXmssmtCtx *ctx);

/**
 * @ingroup xmssmt
 * @brief Generate the XMSSMT key pair.
 *
 * @param ctx [IN/OUT] XMSSMT context structure
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_SUCCESS            The key pair is successfully generated.
 */
int32_t CRYPT_XMSSMT_Gen(CryptXmssmtCtx *ctx);

/**
 * @ingroup xmssmt
 * @brief Sign data using XMSSMT.
 *
 * @param ctx     [IN] Pointer to the XMSSMT context
 * @param algId   [IN] Algorithm ID
 * @param data    [IN] Pointer to the data to sign
 * @param dataLen [IN] Length of the data
 * @param sign    [OUT] Pointer to the signature
 * @param signLen [IN/OUT] Length of the signature
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 *
 * @attention
 * 1. Stateful private key:
 *    XMSSMT is a stateful signature scheme. The signing index is advanced before
 *    signature generation and may be consumed even if this function later
 *    returns an error. After each signing attempt, whether it succeeds or fails,
 *    the caller MUST retrieve the updated private key via CRYPT_XMSSMT_GetPrvKey
 *    and persist it (e.g., to disk or secure storage). Failure to do so may
 *    result in reuse of one-time keys and compromise security.
 * 2. Thread safety:
 *    This function is NOT thread-safe. The internal index increment (idx++) is
 *    not atomic and no locking is performed. If concurrent access is required,
 *    the caller MUST provide external synchronization (e.g., mutex) to ensure
 *    that only one thread invokes signing at a time.
 */
int32_t CRYPT_XMSSMT_Sign(CryptXmssmtCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                          uint32_t *signLen);

/**
 * @ingroup xmssmt
 * @brief Verify data using XMSSMT.
 *
 * @param ctx     [IN] Pointer to the XMSSMT context
 * @param algId   [IN] Algorithm ID
 * @param data    [IN] Pointer to the data to verify
 * @param dataLen [IN] Length of the data
 * @param sign    [IN] Pointer to the signature
 * @param signLen [IN] Length of the signature
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_XMSSMT_Verify(const CryptXmssmtCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                            const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup xmssmt
 * @brief Control function for XMSSMT.
 *
 * @param ctx [IN/OUT] Pointer to the XMSSMT context
 * @param opt [IN] Option
 * @param val [IN] Value
 * @param len [IN] Length of the value
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_XMSSMT_Ctrl(CryptXmssmtCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup xmssmt
 * @brief Get the public key of XMSSMT.
 *
 * @param ctx  [IN] Pointer to the XMSSMT context
 * @param para [OUT] Pointer to the public key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_XMSSMT_GetPubKey(const CryptXmssmtCtx *ctx, BSL_Param *para);

/**
 * @ingroup xmssmt
 * @brief Get the private key of XMSSMT.
 *
 * @param ctx  [IN] Pointer to the XMSSMT context
 * @param para [OUT] Pointer to the private key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_XMSSMT_GetPrvKey(const CryptXmssmtCtx *ctx, BSL_Param *para);

/**
 * @ingroup xmssmt
 * @brief Set the public key of XMSSMT.
 *
 * @param ctx  [IN/OUT] Pointer to the XMSSMT context
 * @param para [IN] Pointer to the public key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_XMSSMT_SetPubKey(CryptXmssmtCtx *ctx, const BSL_Param *para);

/**
 * @ingroup xmssmt
 * @brief Set the private key of XMSSMT.
 *
 * @param ctx  [IN/OUT] Pointer to the XMSSMT context
 * @param para [IN] Pointer to the private key
 *
 * @retval CRYPT_SUCCESS    Success
 * @retval Other            For details, see crypt_errno.h
 */
int32_t CRYPT_XMSSMT_SetPrvKey(CryptXmssmtCtx *ctx, const BSL_Param *para);

/**
 * @ingroup xmssmt
 * @brief Duplicate XMSSMT context.
 *
 * @param ctx Pointer to the XMSSMT context
 * @note Since XMSSMT is not allowed to sign with the same private key and state, the function only duplicates the
 * public key of ctx to the new ctx, without duplicating private key.
 */
CryptXmssmtCtx *CRYPT_XMSSMT_DupCtx(CryptXmssmtCtx *ctx);

#ifdef HITLS_CRYPTO_XMSSMT_CHECK
/**
 * @ingroup xmssmt
 * @brief check the key pair consistency
 *
 * @param checkType [IN] check type
 * @param pkey1     [IN] xmssmt key context structure
 * @param pkey2     [IN] xmssmt key context structure
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_XMSSMT_Check(uint32_t checkType, const CryptXmssmtCtx *pkey1, const CryptXmssmtCtx *pkey2);
#endif /* HITLS_CRYPTO_XMSSMT_CHECK */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_XMSSMT */
#endif /* CRYPT_XMSSMT_H */
