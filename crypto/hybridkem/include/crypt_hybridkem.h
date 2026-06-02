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

#ifndef CRYPT_HYBRIDKEM_H
#define CRYPT_HYBRIDKEM_H
#include <stdint.h>
#include "hitls_build.h"
#include "crypt_types.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#ifdef HITLS_CRYPTO_ECDH

typedef struct HybridKemCtx CRYPT_HybridKemCtx;

CRYPT_HybridKemCtx *CRYPT_HYBRID_KEM_NewCtx(void);

CRYPT_HybridKemCtx *CRYPT_HYBRID_KEM_NewCtxEx(void *libCtx);

void CRYPT_HYBRID_KEM_FreeCtx(CRYPT_HybridKemCtx *ctx);

int32_t CRYPT_HYBRID_KEM_KeyCtrl(CRYPT_HybridKemCtx *ctx, int32_t opt, void *val, uint32_t len);

int32_t CRYPT_HYBRID_KEM_GenKey(CRYPT_HybridKemCtx *ctx);

int32_t CRYPT_HYBRID_KEM_SetEncapsKey(CRYPT_HybridKemCtx *ctx, const CRYPT_KemEncapsKey *ek);
int32_t CRYPT_HYBRID_KEM_SetDecapsKey(CRYPT_HybridKemCtx *ctx, const CRYPT_KemDecapsKey *dk);

int32_t CRYPT_HYBRID_KEM_GetEncapsKey(const CRYPT_HybridKemCtx *ctx, CRYPT_KemEncapsKey *ek);
int32_t CRYPT_HYBRID_KEM_GetDecapsKey(const CRYPT_HybridKemCtx *ctx, CRYPT_KemDecapsKey *dk);

int32_t CRYPT_HYBRID_KEM_GetEncapsKeyEx(const CRYPT_HybridKemCtx *ctx, BSL_Param *para);
int32_t CRYPT_HYBRID_KEM_GetDecapsKeyEx(const CRYPT_HybridKemCtx *ctx, BSL_Param *para);

int32_t CRYPT_HYBRID_KEM_SetEncapsKeyEx(CRYPT_HybridKemCtx *ctx, const BSL_Param *para);
int32_t CRYPT_HYBRID_KEM_SetDecapsKeyEx(CRYPT_HybridKemCtx *ctx, const BSL_Param *para);

/**
 * @ingroup hybridkem
 * @brief Encapsulate: generate a hybrid shared secret and ciphertext.
 * @param ctx       [IN]  Hybrid KEM context.
 * @param cipher    [OUT] Ciphertext buffer. X25519 hybrids: ML-KEM ct || X25519 pubkey;
 *                  ECDH NISTP hybrids: ECDH pubkey || ML-KEM ct.
 * @param cipherLen [IN/OUT] On input, size of cipher; on output, actual length.
 * @param sharekey  [OUT] Shared secret buffer (raw concatenation of component secrets).
 * @param shareLen  [IN/OUT] On input, size of sharekey; on output, actual length.
 * @return CRYPT_SUCCESS on success, error code on failure.
 *
 * @note The shared secret is the raw concatenation of the two component secrets
 *       (no internal KDF), as required by draft-kwiatkowski-tls-ecdhe-mlkem.
 *       When used within TLS 1.3, the key schedule applies HKDF-Extract to this
 *       value. Standalone callers MUST pass the output through a KDF before using
 *       it as keying material.
 */
int32_t CRYPT_HYBRID_KEM_Encaps(const CRYPT_HybridKemCtx *ctx, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *sharekey, uint32_t *shareLen);

/**
 * @ingroup hybridkem
 * @brief Decapsulate: recover the hybrid shared secret from a ciphertext.
 * @param ctx       [IN]  Hybrid KEM context.
 * @param cipher    [IN]  Ciphertext in the same order produced by Encaps.
 *                  X25519 hybrids: ML-KEM ct || X25519 pubkey;
 *                  ECDH NISTP hybrids: ECDH pubkey || ML-KEM ct.
 * @param cipherLen [IN]  Length of cipher in bytes.
 * @param sharekey  [OUT] Shared secret buffer (raw concatenation of component secrets).
 * @param shareLen  [IN/OUT] On input, size of sharekey; on output, actual length.
 * @return CRYPT_SUCCESS on success, error code on failure.
 *
 * @note The shared secret is the raw concatenation of the two component secrets
 *       (no internal KDF), as required by draft-kwiatkowski-tls-ecdhe-mlkem.
 *       When used within TLS 1.3, the key schedule applies HKDF-Extract to this
 *       value. Standalone callers MUST pass the output through a KDF before using
 *       it as keying material.
 */
int32_t CRYPT_HYBRID_KEM_Decaps(const CRYPT_HybridKemCtx *ctx, uint8_t *cipher, uint32_t cipherLen,
    uint8_t *sharekey, uint32_t *shareLen);

#endif
#endif    // CRYPT_HYBRIDKEM_H
