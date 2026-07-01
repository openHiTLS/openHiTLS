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

/*
 * lms_internal.h - LMS internal boundary header for HSS
 *
 * Exposes only the LMS internals that HSS legitimately needs,
 * replacing the direct dependency on lms_local.h in HSS files.
 * This is the stable internal API boundary between LMS and HSS.
 */

#ifndef LMS_INTERNAL_H
#define LMS_INTERNAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_HSS_LMS)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "lms_params.h"
#include "lms_hash.h"
#include "lms_common.h"
#include "bsl_bytes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Buffer types used by LMS signing/verification */
typedef struct {
    const uint8_t *data;
    size_t len;
} LMS_InputBuffer;

typedef struct {
    uint8_t *data;
    size_t *len;
} LMS_SignatureBuffer;

typedef struct {
    uint8_t **tree;
    size_t *size;
    bool *valid;
} LMS_TreeCache;

/* LMS type identifiers (needed by HSS for parameter validation) */
#define LMS_SHA256_M32_H5  0x00000005 /* SHA-256, n=32, h=5 */
#define LMS_SHA256_M32_H10 0x00000006 /* SHA-256, n=32, h=10 */
#define LMS_SHA256_M32_H15 0x00000007 /* SHA-256, n=32, h=15 */
#define LMS_SHA256_M32_H20 0x00000008 /* SHA-256, n=32, h=20 */
#define LMS_SHA256_M32_H25 0x00000009 /* SHA-256, n=32, h=25 */

/* LMOTS type identifiers (needed by HSS for parameter validation) */
#define LMOTS_SHA256_N32_W1 0x00000001 /* SHA-256, n=32, w=1 */
#define LMOTS_SHA256_N32_W2 0x00000002 /* SHA-256, n=32, w=2 */
#define LMOTS_SHA256_N32_W4 0x00000003 /* SHA-256, n=32, w=4 */
#define LMOTS_SHA256_N32_W8 0x00000004 /* SHA-256, n=32, w=8 */

/* Common field lengths and size constants */
#define LMS_TYPE_LEN                   4 /* Type field length (4 bytes, big-endian) */
#define LMS_Q_LEN                      4 /* Leaf index q field length in LMS signature (4 bytes) */
#define LMS_TREE_INDEX_BYTES           8 /* Tree index size in bytes (uint64_t) */
#define LMS_LEVEL_INDEX_BYTES          4 /* Level index size in bytes (uint32_t) */
#define LMS_MAX_SAFE_HEIGHT_FOR_UINT64 60 /* Maximum height to prevent uint64_t overflow */

/* Tree structure constants (needed by hbs_tree.c LMS path) */
#define LMS_ROOT_NODE_INDEX       1 /* Root node index in tree array */
#define LMS_LEFT_CHILD_MULTIPLIER 2 /* Multiplier for left child index */
#define LMS_RIGHT_CHILD_OFFSET    1 /* right = 2*r + 1 */

/* Seed derivation context (needed by hbs_tree.c to call LmOtsGeneratePublicKey) */
typedef struct {
    const uint8_t *I;
    const uint8_t *masterSeed;
    uint32_t q;
    uint32_t j;
} LMS_SeedDerive;

/*
 * Initialize seed derivation context
 */
int32_t LmsSeedDeriveInit(LMS_SeedDerive *derive, const uint8_t *I, const uint8_t *seed);

/*
 * Set leaf index q in seed derivation context
 */
int32_t LmsSeedDeriveSetQ(LMS_SeedDerive *derive, uint32_t q);

/*
 * Generate LM-OTS public key (RFC 8554 Algorithm 1)
 */
int32_t LmOtsGeneratePublicKey(uint32_t otsType, LMS_SeedDerive *seed, const LmsFamilyHashFuncs *hashFuncs,
                               uint8_t *publicKey, size_t publicKeyLen);

/*
 * Compute SHA-256 hash
 * Used by HSS seed derivation functions.
 */
int32_t LmsHash(uint8_t *result, const void *message, size_t messageLen);

/* Private key field offsets (needed by HSS to construct per-level private keys) */
#define LMS_PRVKEY_INDEX_OFFSET    0
#define LMS_PRVKEY_INDEX_LEN       8
#define LMS_PRVKEY_LMS_TYPE_OFFSET 8
#define LMS_PRVKEY_OTS_TYPE_OFFSET 12
#define LMS_PRVKEY_I_OFFSET        16
#define LMS_PRVKEY_SEED_OFFSET     32
/**
 * @brief Maximum possible LMS private key size for stack allocations.
 *
 * Private key = index(8) || lmsType(4) || otsType(4) || I(16) || seed(32) = 64 bytes.
 * Runtime code MUST use para->prvKeyLen when the actual size is needed.
 */
#define LMS_PRVKEY_MAX_LEN         (32 + LMS_SEED_LEN)

/* Public key field offsets (needed by HSS to construct/parse per-level public keys) */
#define LMS_PUBKEY_LMS_TYPE_OFFSET 0
#define LMS_PUBKEY_OTS_TYPE_OFFSET 4
#define LMS_PUBKEY_I_OFFSET        8
#define LMS_PUBKEY_ROOT_OFFSET     24

/**
 * @brief Maximum possible LMS public key size for stack allocations.
 *
 * The actual length depends on n (= hash output bytes):
 *   LMS public key = type(4) || ots_type(4) || I(16) || root(n)
 *                  = 24 + n
 * For all currently defined parameter sets n ≤ 32, so 56 bytes is the maximum.
 * Runtime code MUST use para->pubKeyLen (from LmsParaInit) instead of this macro
 * when the actual n is known.
 */
#define LMS_PUBKEY_MAX_LEN         (24 + LMS_SHA256_N)

/*
 * Compute Merkle tree root hash (RFC 8554 Algorithm 6)
 * Used by HSS to compute child tree roots for signed public keys.
 */
int32_t LmsComputeRoot(uint8_t *root, const LMS_Para *para, const uint8_t *I, const uint8_t *seed);

/*
 * Sign message with LMS using tree caching
 * Used by HSS to sign child public keys and the final message.
 */
int32_t LmsSignCached(const LMS_Para *para, uint8_t *privateKey, const LMS_InputBuffer *message,
                      LMS_SignatureBuffer *signature, LMS_TreeCache *cache);

/*
 * Validate LMS signature (RFC 8554 Algorithm 6)
 * Used by HSS verification to validate each level's signature.
 */
int32_t LmsValidateSignature(const uint8_t *publicKey, const uint8_t *message, size_t messageLen,
                             const uint8_t *signature, size_t signatureLen);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* LMS_INTERNAL_H */
