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

/**
 * @file crypt_sm9.h
 * @brief SM9 Identity-Based Cryptography EAL Adaptation Layer
 *
 * This file provides EAL-compatible interfaces for SM9 algorithms including:
 * - Digital signature (sign/verify)
 * - Public key encryption (encrypt/decrypt)
 * - Key exchange protocol
 */

#ifndef CRYPT_SM9_EAL_H
#define CRYPT_SM9_EAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include <stdint.h>
#include "crypt_types.h"
#include "bsl_params.h"
#include "crypt_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SM9 context is opaque to EAL layer */
typedef struct SM9_Ctx_st CRYPT_SM9_Ctx;

/**
 * @brief Create SM9 context
 * @return SM9 context pointer, or NULL on failure
 */
CRYPT_SM9_Ctx *CRYPT_SM9_NewCtx(void);

/**
 * @brief Duplicate SM9 context
 * @param ctx [IN] Source context
 * @return New SM9 context, or NULL on failure
 */
CRYPT_SM9_Ctx *CRYPT_SM9_DupCtx(const CRYPT_SM9_Ctx *ctx);

/**
 * @brief Free SM9 context
 * @param ctx [IN] Context to free
 */
void CRYPT_SM9_FreeCtx(CRYPT_SM9_Ctx *ctx);

/**
 * @brief Generate SM9 key pair (master or user key)
 * @param ctx [IN/OUT] SM9 context
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_Gen(CRYPT_SM9_Ctx *ctx);

/**
 * @brief Set public key context (for SM9: master private key + user identity + key type)
 *
 * For SM9 Identity-Based Cryptography:
 * - For encryption: Set master private key + target user's identity + key type
 *   The master private key is used to generate encryption parameters for the specified user
 * - For signature verification: Set master private key + key type (user_id optional)
 *   The master private key is used to derive the master public key for verification
 * - Parameters should include: "master_key" (32-byte master private key), "user_id" (optional), "key_type"
 *
 * Note: Despite the name "SetPubKeyEx", this function requires the master PRIVATE key,
 * not the master public key. The public key is derived internally from the private key.
 *
 * @param ctx [IN/OUT] SM9 context
 * @param param [IN] Parameters (master_key, user_id, key_type)
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_SetPubKeyEx(CRYPT_SM9_Ctx *ctx, const BSL_Param *param);

/**
 * @brief Set private key (for SM9: generate user private key from master key)
 *
 * For SM9 Identity-Based Cryptography:
 * - This function generates the user private key from the master private key (already set via SetPubKeyEx)
 * - Parameters should include: "user_id" (user's identity), "key_type"
 * - The function will call SM9_GenSignUserKey or SM9_GenEncUserKey internally
 * - Note: The "user_key" parameter is NOT used - the key is generated, not imported
 *
 * @param ctx [IN/OUT] SM9 context
 * @param param [IN] Private key parameters (user_id, key_type)
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_SetPrvKeyEx(CRYPT_SM9_Ctx *ctx, const BSL_Param *param);

/**
 * @brief Get public key
 * @param ctx [IN] SM9 context
 * @param param [OUT] Public key parameters
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_GetPubKeyEx(const CRYPT_SM9_Ctx *ctx, BSL_Param *param);

/**
 * @brief Get private key
 * @param ctx [IN] SM9 context
 * @param param [OUT] Private key parameters
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_GetPrvKeyEx(const CRYPT_SM9_Ctx *ctx, BSL_Param *param);

/**
 * @brief SM9 signature (with hash)
 * @param ctx [IN] SM9 context
 * @param mdId [IN] Hash algorithm ID (typically CRYPT_MD_SM3)
 * @param data [IN] Data to sign
 * @param dataLen [IN] Data length
 * @param sign [OUT] Signature output buffer
 * @param signLen [IN/OUT] Signature buffer size / actual signature length
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_Sign(const CRYPT_SM9_Ctx *ctx, int32_t mdId,
                       const uint8_t *data, uint32_t dataLen,
                       uint8_t *sign, uint32_t *signLen);

/**
 * @brief SM9 signature verification
 * @param ctx [IN] SM9 context
 * @param mdId [IN] Hash algorithm ID
 * @param data [IN] Signed data
 * @param dataLen [IN] Data length
 * @param sign [IN] Signature to verify
 * @param signLen [IN] Signature length
 * @return CRYPT_SUCCESS if signature valid, error code otherwise
 */
int32_t CRYPT_SM9_Verify(const CRYPT_SM9_Ctx *ctx, int32_t mdId,
                         const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen);

/**
 * @brief SM9 public key encryption
 * @param ctx [IN] SM9 context
 * @param data [IN] Plaintext data
 * @param dataLen [IN] Plaintext length
 * @param out [OUT] Ciphertext output buffer
 * @param outLen [IN/OUT] Buffer size / actual ciphertext length
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_Encrypt(const CRYPT_SM9_Ctx *ctx,
                          const uint8_t *data, uint32_t dataLen,
                          uint8_t *out, uint32_t *outLen);

/**
 * @brief SM9 decryption
 * @param ctx [IN] SM9 context
 * @param data [IN] Ciphertext data
 * @param dataLen [IN] Ciphertext length
 * @param out [OUT] Plaintext output buffer
 * @param outLen [IN/OUT] Buffer size / actual plaintext length
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_Decrypt(const CRYPT_SM9_Ctx *ctx,
                          const uint8_t *data, uint32_t dataLen,
                          uint8_t *out, uint32_t *outLen);

/**
 * @brief SM9 key exchange (compute shared key)
 * @param selfCtx [IN] Local SM9 context (with encryption user key)
 * @param peerCtx [IN] Peer SM9 context (with encryption system public key and user ID)
 * @param out [OUT] Shared key output buffer
 * @param outLen [IN/OUT] Buffer size / actual key length
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_ComputeShareKey(const CRYPT_SM9_Ctx *selfCtx, const CRYPT_SM9_Ctx *peerCtx,
                                  uint8_t *out, uint32_t *outLen);

/**
 * @brief Control function for SM9 operations
 * @param ctx [IN/OUT] SM9 context
 * @param cmd [IN] Control command
 * @param val [IN] Command parameter value
 * @param valLen [IN] Parameter length
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_SM9_Ctrl(CRYPT_SM9_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @brief Check SM9 key validity
 * @param ctx [IN] SM9 context
 * @param type [IN] Check type
 * @return CRYPT_SUCCESS if valid, error code otherwise
 */
int32_t CRYPT_SM9_Check(int32_t checkType, const CRYPT_SM9_Ctx *ctx1, const CRYPT_SM9_Ctx *ctx2);

/**
 * @brief Compare two SM9 keys
 * @param ctx1 [IN] First SM9 context
 * @param ctx2 [IN] Second SM9 context
 * @return CRYPT_SUCCESS if equal, error code otherwise
 */
int32_t CRYPT_SM9_Cmp(const CRYPT_SM9_Ctx *ctx1, const CRYPT_SM9_Ctx *ctx2);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9
#endif /* CRYPT_SM9_EAL_H */
