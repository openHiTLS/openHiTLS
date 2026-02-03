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

#ifndef XMSS_COMMON_H
#define XMSS_COMMON_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum digest size for hash operations (shared between XMSS and SLH-DSA) */
#define MAX_MDSIZE 64
#define MAX_ADRS_SIZE 32

/*
 * Multi-message hash calculation utility
 *
 * This function is used by both XMSS and SLH-DSA for computing
 * hash of multiple message segments.
 *
 * @param mdId        Hash algorithm ID
 * @param hashData    Array of message segments
 * @param hashDataLen Number of segments
 * @param out         Output buffer
 * @param outLen      Output length (will be truncated if needed)
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t CalcMultiMsgHash(CRYPT_MD_AlgId mdId, const CRYPT_ConstData *hashData, uint32_t hashDataLen, uint8_t *out,
                         uint32_t outLen);



/*
 * Generic Hash Functions Interface
 *
 * This structure defines a set of generic hash function pointers that can be
 * implemented by different cryptographic algorithms (XMSS, SLH-DSA, etc.).
 */
typedef struct CryptHashFuncs {
    /**
     * PRF - Pseudorandom Function
     * Used for generating pseudorandom outputs from a seed and address
     */
    int32_t (*prf)(const void *ctx, const void *adrs, uint8_t *out);

    /**
     * F - Hash function for WOTS+ chaining
     * Used in WOTS+ key generation and signature generation
     */
    int32_t (*f)(const void *ctx, const void *adrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out);

    /**
     * H - Tree hash function
     * Used for computing internal nodes in the Merkle tree
     */
    int32_t (*h)(const void *ctx, const void *adrs, const uint8_t *in, uint32_t inLen, uint8_t *out);

    /**
     * Hmsg - Randomized hash for message
     * Used for hashing the message with randomness and index
     */
    int32_t (*hmsg)(const void *ctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen, const uint8_t *idx,
                    uint8_t *out);

    /**
     * TL - L-tree compression
     * Compresses WOTS+ public key into a single leaf node
     */
    int32_t (*tl)(const void *ctx, const void *adrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out);

    /**
     * PRFmsg - PRF for message
     * Used for generating randomness for message-dependent operations
     */
    int32_t (*prfmsg)(const void *ctx, const uint8_t *key, const uint8_t *msg, uint32_t msgLen, uint8_t *out);
} CryptHashFuncs;

/*
 * Generic Address Operations Interface
 *
 * This structure provides a standard interface for manipulating addresses
 * used by both XMSS and SLH-DSA.
 */
typedef struct CryptAdrsOps {
    /* Set functions - modify address fields */
    void (*setLayerAddr)(void *adrs, uint32_t layer);
    void (*setTreeAddr)(void *adrs, uint64_t tree);
    void (*setType)(void *adrs, uint32_t type);
    void (*setKeyPairAddr)(void *adrs, uint32_t keyPair);
    void (*setChainAddr)(void *adrs, uint32_t chain);
    void (*setTreeHeight)(void *adrs, uint32_t height);
    void (*setHashAddr)(void *adrs, uint32_t hash);
    void (*setTreeIndex)(void *adrs, uint32_t index);

    /* Get functions - retrieve address fields */
    uint32_t (*getTreeHeight)(const void *adrs);
    uint32_t (*getTreeIndex)(const void *adrs);

    /* Copy function */
    void (*copyKeyPairAddr)(void *dest, const void *src);

    /* Utility */
    uint32_t (*getAdrsLen)(void);
} CryptAdrsOps;

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_XMSS || HITLS_CRYPTO_SLH_DSA
#endif // XMSS_COMMON_H
