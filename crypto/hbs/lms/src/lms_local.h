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

#ifndef LMS_LOCAL_H
#define LMS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "crypt_lms.h"
#include "lms_params.h"
#include "lms_internal.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * LMS type identifiers, tree constants, and field lengths shared with HSS
 * are defined in lms_internal.h (included above). Only LMS-internal
 * implementation constants are defined here.
 */

/* LMS implementation constants (not exposed via lms_internal.h) */
#define LMS_BITS_PER_BYTE             8 // Number of bits per byte
#define LMS_BYTE_MASK                 0xff // Byte mask
#define LMS_R_LEN                     4 // Node index r length (4 bytes)
#define LMS_K_LEN                     2 // OTS chain index k length (2 bytes)
#define LMS_J_LEN                     1 // OTS chain position j length (1 byte)
#define LMS_CHECKSUM_LEN              2 // OTS checksum length (2 bytes)
#define LMS_SEED_RANDOMIZER_INDEX     0xFFFFFFFE // Special j value for OTS randomizer generation (RFC 8554)
#define LMS_PRG_FF_VALUE              0xff // Fixed value for seed derivation (RFC 8554 Section 5.3)
#define LMS_ZERO_INIT_VALUE           0 // Zero initialization value
#define LMS_SIGNATURE_INDEX_INCREMENT 1 // Increment for signature counter after each signing

/* LMS context structure */
struct LmsCtx {
    LMS_Para para; // Parameter structure (embedded, not heap-allocated)
    uint8_t *publicKey; // Public key buffer
    uint8_t *privateKey; // Private key buffer
    uint64_t signatureIndex; // Current signature index (cached)
    void *libCtx; // Library context
    uint8_t *cachedTree; // Cached Merkle tree (optimization for Problem 7)
    size_t cachedTreeSize; // Size of cached tree in bytes
    bool treeCacheValid; // Whether the cached tree is valid
};

/*
 * LMS Public Key Format:
 * [0-3]   LMS type (4 bytes, big-endian)
 * [4-7]   OTS type (4 bytes, big-endian)
 * [8-23]  I value (16 bytes)
 * [24-55] Root hash (32 bytes for SHA-256)
 * Total: 56 bytes
 *
 * LMS Private Key Format:
 * [0-7]   Current signature index q (8 bytes, big-endian)
 * [8-11]  LMS type (4 bytes, big-endian)
 * [12-15] OTS type (4 bytes, big-endian)
 * [16-31] I value (16 bytes)
 * [32-63] Seed (32 bytes)
 * Total: 64 bytes
 *
 * The corresponding LMS_PUBKEY_* / LMS_PRVKEY_* offset and length macros are
 * defined once in lms_internal.h (which this header transitively includes) so
 * they can also be consumed by HSS without duplicate definitions.
 */

/*
 * LMS Signature Format:
 * [0-3]      q (leaf index, 4 bytes, big-endian)
 * [4-...]    LM-OTS signature
 * [...-...]  LMS type (4 bytes, big-endian)
 * [...-end]  Authentication path (h * n bytes)
 *
 * LM-OTS Signature Format:
 * [0-3]   OTS type (4 bytes, big-endian)
 * [4-35]  C randomizer (32 bytes for SHA-256)
 * [36-...]  y values (p * n bytes)
 */
#define LMS_SIG_Q_OFFSET   0
#define LMS_SIG_OTS_OFFSET 4

/* Message hash prefix offsets */
#define LMS_MESG_I_OFFSET 0
#define LMS_MESG_Q_OFFSET 16
#define LMS_MESG_D_OFFSET 20
#define LMS_MESG_C_OFFSET 22

/**
 * @ingroup lms
 * @brief Calculate message hash prefix length
 * @param n [IN] Hash output length in bytes
 * @return Message prefix length (I(16) + q(4) + D(2) + C(n))
 */
static inline size_t LMS_MESG_PREFIX_LEN(uint32_t n)
{
    return 22 + n; // I(16) + q(4) + D(2) + C(n)
}

/* OTS iteration hash prefix offsets */
#define LMS_ITER_I_OFFSET    0
#define LMS_ITER_Q_OFFSET    16
#define LMS_ITER_K_OFFSET    20
#define LMS_ITER_J_OFFSET    22
#define LMS_ITER_PREV_OFFSET 23

/**
 * @ingroup lms
 * @brief Calculate OTS iteration buffer length
 * @param n [IN] Hash output length in bytes
 * @return Iteration buffer length (I(16) + q(4) + k(2) + j(1) + prev(n))
 */
static inline size_t LMS_ITER_LEN(uint32_t n)
{
    return 23 + n; // I(16) + q(4) + k(2) + j(1) + prev(n)
}

/* OTS public key hash prefix offsets */
#define LMS_PBLC_I_OFFSET   0
#define LMS_PBLC_Q_OFFSET   16
#define LMS_PBLC_D_OFFSET   20
#define LMS_PBLC_PREFIX_LEN 22

/* Leaf node hash prefix offsets */
#define LMS_LEAF_I_OFFSET  0
#define LMS_LEAF_R_OFFSET  16
#define LMS_LEAF_D_OFFSET  20
#define LMS_LEAF_PK_OFFSET 22

/**
 * @ingroup lms
 * @brief Calculate leaf node hash buffer length
 * @param n [IN] Hash output length in bytes
 * @return Leaf buffer length (I(16) + r(4) + D(2) + pk(n))
 */
static inline size_t LMS_LEAF_LEN(uint32_t n)
{
    return 22 + n; // I(16) + r(4) + D(2) + pk(n)
}

/* Internal node hash prefix offsets */
#define LMS_INTR_I_OFFSET        0
#define LMS_INTR_R_OFFSET        16
#define LMS_INTR_D_OFFSET        20
#define LMS_INTR_LEFT_OFFSET     22
#define LMS_INTR_RIGHT_OFFSET(n) (22 + (n))

/**
 * @ingroup lms
 * @brief Calculate internal node hash buffer length
 * @param n [IN] Hash output length in bytes
 * @return Internal node buffer length (I(16) + r(4) + D(2) + left(n) + right(n))
 */
static inline size_t LMS_INTR_LEN(uint32_t n)
{
    return 22 + 2 * n; // I(16) + r(4) + D(2) + left(n) + right(n)
}

/* Seed derivation hash prefix offsets */
#define LMS_PRG_I_OFFSET    0
#define LMS_PRG_Q_OFFSET    16
#define LMS_PRG_J_OFFSET    20
#define LMS_PRG_FF_OFFSET   22
#define LMS_PRG_SEED_OFFSET 23
#define LMS_PRG_LEN         (23 + LMS_SEED_LEN)

/* OTS validation context */
typedef struct {
    uint8_t *data; // Buffer pointer
    size_t len; // Buffer length
} LMS_OutputBuffer;

/* OTS validation context */
typedef struct {
    const uint8_t *I; // Public key identifier
    uint32_t q; // Leaf index
    uint32_t expectedOtsType; // Expected OTS type
} LMS_OtsValidateCtx;

/* Tree parameters (I and seed) */
typedef struct {
    const uint8_t *I;
    const uint8_t *seed;
} LMS_TreeParams;

/* LmsPutBigendian and LmsGetBigendian are defined as static inline in lms_internal.h */

/**
 * @ingroup lms
 * @brief Set domain separation value D
 * @param p     [OUT] Target buffer
 * @param value [IN]  Domain separation value
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsSetD(uint8_t *p, uint16_t value);

/**
 * @ingroup lms
 * @brief Set chain position j in seed derivation context
 * @param derive [IN/OUT] Seed derivation context
 * @param j      [IN]     Chain position
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsSeedDeriveSetJ(LMS_SeedDerive *derive, uint32_t j);

/**
 * @ingroup lms
 * @brief Derive seed value from context
 * @param seed       [OUT]    Output seed buffer (32 bytes)
 * @param derive     [IN/OUT] Seed derivation context
 * @param incrementJ [IN]     Whether to increment j after derivation
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsSeedDerive(uint8_t *seed, LMS_SeedDerive *derive, bool incrementJ);

/**
 * @ingroup lms
 * @brief Extract coefficient from message hash (RFC 8554 Algorithm 2)
 * @param Q [IN] Message hash
 * @param i [IN] Coefficient index
 * @param w [IN] Winternitz parameter
 * @return Coefficient value
 */
uint32_t LmOtsCoef(const uint8_t *Q, uint32_t i, uint32_t w);

/**
 * @ingroup lms
 * @brief Compute OTS checksum (RFC 8554 Algorithm 2)
 * @param Q    [IN] Message hash
 * @param qLen [IN] Message hash length
 * @param w    [IN] Winternitz parameter
 * @param ls   [IN] Left shift value
 * @return Checksum value
 */
uint32_t LmOtsComputeChecksum(const uint8_t *Q, uint32_t qLen, uint32_t w, uint32_t ls);

/**
 * @ingroup lms
 * @brief Generate LM-OTS signature (RFC 8554 Algorithm 3)
 * @param otsType   [IN]  OTS parameter set identifier
 * @param seed      [IN]  Seed derivation context
 * @param hashFuncs [IN]  Hash function pointers
 * @param message   [IN]  Message to sign
 * @param signature [OUT] Output signature buffer
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmOtsSign(uint32_t otsType, LMS_SeedDerive *seed, const LmsFamilyHashFuncs *hashFuncs,
                  const LMS_InputBuffer *message, LMS_OutputBuffer *signature);

/**
 * @ingroup lms
 * @brief Validate LM-OTS signature and compute public key (RFC 8554 Algorithm 4b)
 * @param computedPubKey [OUT] Computed public key from signature
 * @param ctx            [IN]  Validation context
 * @param hashFuncs      [IN]  Hash function pointers
 * @param message        [IN]  Message that was signed
 * @param signature      [IN]  Signature to validate
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmOtsValidateSignature(uint8_t *computedPubKey, const LMS_OtsValidateCtx *ctx,
                               const LmsFamilyHashFuncs *hashFuncs, const LMS_InputBuffer *message,
                               const LMS_InputBuffer *signature);

/**
 * @ingroup lms
 * @brief Get LM-OTS signature length
 * @param otsType [IN] OTS parameter set identifier
 * @return Signature length in bytes, or 0 if invalid
 */
size_t LmOtsGetSigLen(uint32_t otsType);

/**
 * @ingroup lms
 * @brief Compute Merkle tree root hash (RFC 8554 Algorithm 6)
 * @param root [OUT] Output root hash (32 bytes)
 * @param para [IN]  LMS parameters
 * @param I    [IN]  Public key identifier (16 bytes)
 * @param seed [IN]  Master seed (32 bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsComputeRoot(uint8_t *root, const LMS_Para *para, const uint8_t *I, const uint8_t *seed);

/**
 * @ingroup lms
 * @brief Generate authentication path for leaf node (RFC 8554 Algorithm 5)
 * @param authPath [OUT] Output authentication path (h * n bytes)
 * @param para     [IN]  LMS parameters
 * @param I        [IN]  Public key identifier (16 bytes)
 * @param seed     [IN]  Master seed (32 bytes)
 * @param q        [IN]  Leaf index
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsGenerateAuthPath(uint8_t *authPath, const LMS_Para *para, const uint8_t *I, const uint8_t *seed, uint32_t q);

/**
 * @ingroup lms
 * @brief Generate authentication path with tree caching optimization
 * @param authPath   [OUT]    Output authentication path (h * n bytes)
 * @param para       [IN]     LMS parameters
 * @param treeParams [IN]     Tree parameters (I and seed)
 * @param q          [IN]     Leaf index
 * @param cache      [IN/OUT] Tree cache structure
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsGenerateAuthPathCached(uint8_t *authPath, const LMS_Para *para, const LMS_TreeParams *treeParams, uint32_t q,
                                  LMS_TreeCache *cache);

/**
 * @ingroup lms
 * @brief Validate LMS signature (RFC 8554 Algorithm 6)
 * @param publicKey    [IN] Public key (56 bytes)
 * @param message      [IN] Message that was signed
 * @param messageLen   [IN] Message length
 * @param signature    [IN] Signature to validate
 * @param signatureLen [IN] Signature length
 * @return CRYPT_SUCCESS if valid, error code otherwise
 */
int32_t LmsValidateSignature(const uint8_t *publicKey, const uint8_t *message, size_t messageLen,
                             const uint8_t *signature, size_t signatureLen);

/**
 * @ingroup lms
 * @brief Hash message using SHA-256
 * @param result     [OUT] Output hash (32 bytes)
 * @param message    [IN]  Message to hash
 * @param messageLen [IN]  Message length
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsHash(uint8_t *result, const void *message, size_t messageLen);

/**
 * @ingroup lms
 * @brief Generate LMS key pair (RFC 8554)
 * @param libCtx     [IN]  Library context for RNG isolation (may be NULL)
 * @param para       [IN]  LMS parameters
 * @param publicKey  [OUT] Output public key (56 bytes)
 * @param privateKey [OUT] Output private key (64 bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsKeyGen(void *libCtx, LMS_Para *para, uint8_t *publicKey, uint8_t *privateKey);

/**
 * @ingroup lms
 * @brief Sign message with LMS (RFC 8554 Algorithm 5)
 * @param para       [IN]     LMS parameters
 * @param privateKey [IN/OUT] Private key (counter incremented)
 * @param message    [IN]     Message to sign
 * @param signature  [OUT]    Output signature buffer
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsSign(const LMS_Para *para, uint8_t *privateKey, const LMS_InputBuffer *message,
                LMS_SignatureBuffer *signature);

/**
 * @ingroup lms
 * @brief Sign message with LMS using tree caching
 * @param para       [IN]     LMS parameters
 * @param privateKey [IN/OUT] Private key (counter incremented)
 * @param message    [IN]     Message to sign
 * @param signature  [OUT]    Output signature buffer
 * @param cache      [IN/OUT] Tree cache structure
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsSignCached(const LMS_Para *para, uint8_t *privateKey, const LMS_InputBuffer *message,
                      LMS_SignatureBuffer *signature, LMS_TreeCache *cache);

/**
 * @ingroup lms
 * @brief Get remaining signature capacity
 * @param privateKey [IN] Private key (64 bytes)
 * @param height     [IN] Tree height
 * @return Number of remaining signatures
 */
uint64_t LmsGetRemainingSignatures(const uint8_t *privateKey, uint32_t height);

/* Helper functions */
static inline void *LIBCTX_FROM_LMS_CTX(const struct LmsCtx *ctx)
{
    return (ctx == NULL) ? NULL : ctx->libCtx;
}

/* LMS_FREE_PARA removed: para is now embedded in the context struct. */

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_LMS */

#endif /* LMS_LOCAL_H */
