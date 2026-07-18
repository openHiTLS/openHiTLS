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

#ifndef CRYPT_XMSS_H
#define CRYPT_XMSS_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT)

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct CryptXmssCtx CryptXmssCtx;

/**
 * @brief Allocate XMSS context memory space.
 *
 * @retval (CryptXmssCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptXmssCtx *CRYPT_XMSS_NewCtx(void); // create key structure

/**
 * @brief Allocate XMSS context memory space.
 * 
 * @param libCtx [IN] Library context
 *
 * @retval (CryptXmssCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptXmssCtx *CRYPT_XMSS_NewCtxEx(void *libCtx);

#ifdef HITLS_CRYPTO_XMSSMT
CryptXmssCtx *CRYPT_XMSSMT_NewCtx(void);

CryptXmssCtx *CRYPT_XMSSMT_NewCtxEx(void *libCtx);
#endif

/**
 * @brief release XMSS key context structure
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_XMSS_FreeCtx(CryptXmssCtx *ctx);

/**
 * @brief Generate the XMSS key pair.
 *
 * @param ctx [IN/OUT] XMSS context structure
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_SUCCESS            The key pair is successfully generated.
 */
int32_t CRYPT_XMSS_Gen(CryptXmssCtx *ctx);

/**
 * @brief Sign data using XMSS.
 *
 * @param ctx     [IN/OUT] Pointer to the XMSS context
 * @param algId   [IN] Algorithm ID
 * @param data    [IN] Pointer to the data to sign
 * @param dataLen [IN] Length of the data
 * @param sign    [OUT] Pointer to the signature
 * @param signLen [IN/OUT] Length of the signature
 *
 * @attention
 * 1. Stateful private key:
 *    XMSS is a stateful signature scheme. The signing index is advanced before
 *    signature generation and may be consumed even if this function later
 *    returns an error. After each signing attempt, whether it succeeds or fails,
 *    the caller MUST retrieve the updated private key via CRYPT_XMSS_GetPrvKey
 *    and durably persist it. A successful signature MUST NOT be published or
 *    used before the updated state is durably persisted. Failure to do so may
 *    result in reuse of one-time keys and compromise security.
 * 2. Exclusive private-key ownership:
 *    Each private-key state MUST have exactly one active signing owner. The same
 *    exported state MUST NOT be loaded into multiple signing contexts or used
 *    independently by multiple processes, containers, or virtual-machine
 *    snapshots.
 * 3. Process forking:
 *    After fork(), the child process MUST NOT sign with an inherited private-key
 *    context. Load or generate the signing key after forking, or keep the state
 *    exclusively in one signing process.
 * 4. Thread safety:
 *    This function is NOT thread-safe. The internal index increment (idx++) is
 *    not atomic and no locking is performed. If concurrent access is required,
 *    the caller MUST provide external synchronization (e.g., mutex) to ensure
 *    that only one thread invokes signing at a time.
 */
int32_t CRYPT_XMSS_Sign(CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                        uint32_t *signLen);

/**
 * @brief Verify data using XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param algId Algorithm ID
 * @param data Pointer to the data to verify
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 */
int32_t CRYPT_XMSS_Verify(const CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                          const uint8_t *sign, uint32_t signLen);

/**
 * @brief Control function for XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param opt Option
 * @param val Value
 * @param len Length of the value
 */
int32_t CRYPT_XMSS_Ctrl(CryptXmssCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @brief Get the public key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the public key
 */
int32_t CRYPT_XMSS_GetPubKey(const CryptXmssCtx *ctx, BSL_Param *para);

/**
 * @brief Get the private key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the private key
 *
 * @attention The returned data is a mutable private-key state snapshot, not a
 * reusable backup. It MUST NOT be loaded into multiple active signing contexts
 * or restored after a newer state has been used.
 */
int32_t CRYPT_XMSS_GetPrvKey(const CryptXmssCtx *ctx, BSL_Param *para);

/**
 * @brief Set the public key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the public key
 */
int32_t CRYPT_XMSS_SetPubKey(CryptXmssCtx *ctx, const BSL_Param *para);

/**
 * @brief Set the private key of XMSS
 * 
 * @param ctx Pointer to the XMSS context
 * @param para Pointer to the private key
 *
 * @attention The imported state MUST have one active signing owner and MUST NOT
 * be loaded into another signing context at the same time. Importing a stale or
 * duplicated state can reuse a one-time key and compromise security.
 */
int32_t CRYPT_XMSS_SetPrvKey(CryptXmssCtx *ctx, const BSL_Param *para);

/**
 * @brief Duplicate ctx
 *
 * @param ctx Pointer to the XMSS context
 * @note The function duplicates only the public key, not the private signing
 * state. The returned context can verify signatures but cannot sign.
 */
CryptXmssCtx *CRYPT_XMSS_DupCtx(CryptXmssCtx *ctx);

#ifdef HITLS_CRYPTO_XMSSMT
void CRYPT_XMSSMT_FreeCtx(CryptXmssCtx *ctx);

int32_t CRYPT_XMSSMT_Gen(CryptXmssCtx *ctx);

/**
 * @brief Sign data using XMSSMT.
 *
 * @param ctx     [IN/OUT] Pointer to the XMSSMT context
 * @param algId   [IN] Algorithm ID
 * @param data    [IN] Pointer to the data to sign
 * @param dataLen [IN] Length of the data
 * @param sign    [OUT] Pointer to the signature
 * @param signLen [IN/OUT] Length of the signature
 *
 * @attention
 * 1. Stateful private key:
 *    XMSSMT is a stateful signature scheme. The signing index is advanced before
 *    signature generation and may be consumed even if this function later
 *    returns an error. After each signing attempt, whether it succeeds or fails,
 *    the caller MUST retrieve the updated private key via CRYPT_XMSSMT_GetPrvKey
 *    and durably persist it. A successful signature MUST NOT be published or
 *    used before the updated state is durably persisted. Failure to do so may
 *    result in reuse of one-time keys and compromise security.
 * 2. Exclusive private-key ownership:
 *    Each private-key state MUST have exactly one active signing owner. The same
 *    exported state MUST NOT be loaded into multiple signing contexts or used
 *    independently by multiple processes, containers, or virtual-machine
 *    snapshots.
 * 3. Process forking:
 *    After fork(), the child process MUST NOT sign with an inherited private-key
 *    context. Load or generate the signing key after forking, or keep the state
 *    exclusively in one signing process.
 * 4. Thread safety:
 *    This function is NOT thread-safe. The internal index increment (idx++) is
 *    not atomic and no locking is performed. If concurrent access is required,
 *    the caller MUST provide external synchronization (e.g., mutex) to ensure
 *    that only one thread invokes signing at a time.
 */
int32_t CRYPT_XMSSMT_Sign(CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                          uint32_t *signLen);

int32_t CRYPT_XMSSMT_Verify(const CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                            const uint8_t *sign, uint32_t signLen);

int32_t CRYPT_XMSSMT_Ctrl(CryptXmssCtx *ctx, int32_t opt, void *val, uint32_t len);

int32_t CRYPT_XMSSMT_GetPubKey(const CryptXmssCtx *ctx, BSL_Param *para);

/**
 * @brief Get the private key of XMSSMT.
 *
 * @param ctx  [IN] Pointer to the XMSSMT context
 * @param para [OUT] Pointer to the private key
 *
 * @attention The returned data is a mutable private-key state snapshot, not a
 * reusable backup. It MUST NOT be loaded into multiple active signing contexts
 * or restored after a newer state has been used.
 */
int32_t CRYPT_XMSSMT_GetPrvKey(const CryptXmssCtx *ctx, BSL_Param *para);

int32_t CRYPT_XMSSMT_SetPubKey(CryptXmssCtx *ctx, const BSL_Param *para);

/**
 * @brief Set the private key of XMSSMT.
 *
 * @param ctx  [IN/OUT] Pointer to the XMSSMT context
 * @param para [IN] Pointer to the private key
 *
 * @attention The imported state MUST have one active signing owner and MUST NOT
 * be loaded into another signing context at the same time. Importing a stale or
 * duplicated state can reuse a one-time key and compromise security.
 */
int32_t CRYPT_XMSSMT_SetPrvKey(CryptXmssCtx *ctx, const BSL_Param *para);

/**
 * @brief Duplicate an XMSSMT context.
 *
 * @param ctx Pointer to the XMSSMT context
 * @note The function duplicates only the public key, not the private signing
 * state. The returned context can verify signatures but cannot sign.
 */
CryptXmssCtx *CRYPT_XMSSMT_DupCtx(CryptXmssCtx *ctx);
#endif

#ifdef HITLS_CRYPTO_XMSS_CHECK

/**
 * @ingroup xmss
 * @brief check the key pair consistency
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] xmss key context structure
 * @param pkey2 [IN] xmss key context structure
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_XMSS_Check(uint32_t checkType, const CryptXmssCtx *pkey1, const CryptXmssCtx *pkey2);

#endif // HITLS_CRYPTO_XMSS_CHECK

#ifdef HITLS_CRYPTO_XMSSMT_CHECK
int32_t CRYPT_XMSSMT_Check(uint32_t checkType, const CryptXmssCtx *pkey1, const CryptXmssCtx *pkey2);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_XMSS || HITLS_CRYPTO_XMSSMT

#endif // CRYPT_XMSS_H
