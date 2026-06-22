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

#ifndef HSS_LOCAL_H
#define HSS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HSS

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "crypt_hss.h"
#include "lms_internal.h"
#include "hss_params.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HSS_PUBKEY_MAX_LEN / HSS_PRVKEY_LEN are defined in hss_params.h, included above. */

/**
 * @ingroup hss
 * @brief HSS context structure
 */
struct HssCtx {
    HSS_Para para; /**< HSS parameters (embedded, not heap-allocated) */
    uint8_t *publicKey; /**< HSS public key buffer */
    uint8_t *privateKey; /**< HSS private key buffer */
    uint32_t publicLen; /**< Actual allocated length of publicKey buffer */
    uint64_t signatureIndex; /**< Current signature index (cached from private key) */
    void *libCtx; /**< Library context */
    uint8_t *cachedTrees[HSS_LEVELS_ARRAY_SIZE]; /**< Cached Merkle trees for each level */
    size_t cachedTreeSizes[HSS_LEVELS_ARRAY_SIZE]; /**< Sizes of cached trees */
    bool treeCacheValid[HSS_LEVELS_ARRAY_SIZE]; /**< Cache validity flags for each level */
    uint64_t cachedTreeIndex[HSS_LEVELS_ARRAY_SIZE]; /**< Tree index each cache was built for */
};

/**
 * @ingroup hss
 * @brief Initialize HSS parameter structure
 * @param para     [OUT] Parameter structure to initialize
 * @param levels   [IN]  Number of hierarchy levels (1-8)
 * @param lmsTypes [IN]  Array of LMS types for each level
 * @param otsTypes [IN]  Array of OTS types for each level
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssParaInit(HSS_Para *para, uint32_t levels, const uint32_t *lmsTypes, const uint32_t *otsTypes);

/**
 * @ingroup hss
 * @brief Compress HSS parameter set to 8 bytes
 * @param compressed [OUT] Compressed parameter buffer (8 bytes)
 * @param para       [IN]  HSS parameters
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssCompressParamSet(uint8_t compressed[8], const HSS_Para *para);

/**
 * @ingroup hss
 * @brief Decompress HSS parameter set from 8 bytes
 * @param para       [OUT] HSS parameters
 * @param compressed [IN]  Compressed parameter buffer (8 bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssDecompressParamSet(HSS_Para *para, const uint8_t compressed[8]);

/**
 * @ingroup hss
 * @brief Get HSS signature length
 * @param para [IN] HSS parameters
 * @return Signature length in bytes
 */
uint32_t HssGetSignatureLen(const HSS_Para *para);

/**
 * @ingroup hss
 * @brief Get maximum signature capacity
 * @param para [IN] HSS parameters
 * @return Maximum number of signatures
 */
uint64_t HssGetMaxSignatures(const HSS_Para *para);

/**
 * @ingroup hss
 * @brief Generate root tree seed from master seed (RFC 8554 Appendix A)
 * @param rootI      [OUT] Root tree identifier (16 bytes)
 * @param rootSeed   [OUT] Root tree seed (32 bytes)
 * @param masterSeed [IN]  Master seed (32 bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssGenerateRootSeed(uint8_t rootI[16], uint8_t rootSeed[32], const uint8_t masterSeed[32]);

/**
 * @ingroup hss
 * @brief Child tree position information
 */
typedef struct {
    uint64_t treeIndex; /**< Child tree index */
    uint32_t level; /**< Child level index */
} HssChildPosition;

/**
 * @ingroup hss
 * @brief Generate child tree seed from parent (RFC 8554 Appendix A)
 * @param childI     [OUT] Child tree identifier (16 bytes)
 * @param childSeed  [OUT] Child tree seed (32 bytes)
 * @param parentI    [IN]  Parent tree identifier (16 bytes)
 * @param parentSeed [IN]  Parent tree seed (32 bytes)
 * @param position   [IN]  Child position information
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssGenerateChildSeed(uint8_t childI[16], uint8_t childSeed[32], const uint8_t parentI[16],
                             const uint8_t parentSeed[32], const HssChildPosition *position);

/**
 * @ingroup hss
 * @brief Generate all level seeds from master seed
 * @param levelI     [OUT] Tree identifiers for each level
 * @param levelSeed  [OUT] Tree seeds for each level
 * @param masterSeed [IN]  Master seed (32 bytes)
 * @param treeIndex  [IN]  Tree indices for each level
 * @param levels     [IN]  Number of levels
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssGenerateAllSeeds(uint8_t levelI[HSS_LEVELS_ARRAY_SIZE][LMS_I_LEN],
                            uint8_t levelSeed[HSS_LEVELS_ARRAY_SIZE][LMS_SEED_LEN],
                            const uint8_t masterSeed[LMS_SEED_LEN], const uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE],
                            uint32_t levels);

/**
 * @ingroup hss
 * @brief Calculate tree and leaf indices from global signature index
 * @param para      [IN]  HSS parameters
 * @param globalIndex [IN]  Global signature index
 * @param treeIndex [OUT] Tree index for each level
 * @param leafIndex [OUT] Leaf index for each level
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssCalculateTreeIndices(const HSS_Para *para, uint64_t globalIndex, uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE],
                                uint32_t leafIndex[HSS_LEVELS_ARRAY_SIZE]);

/**
 * @ingroup hss
 * @brief Parsed HSS signature structure
 */
typedef struct {
    uint32_t nspk; /**< Number of signed public keys */
    const uint8_t *bottomSig; /**< Bottom-level LMS signature */
    size_t bottomSigLen; /**< Bottom signature length */
    const uint8_t *signedPubKeys[HSS_LEVELS_ARRAY_SIZE]; /**< Signed public keys (level 1 to L-1) */
    size_t signedPubKeyLens[HSS_LEVELS_ARRAY_SIZE]; /**< Signed public key lengths */
    size_t lmsSigLens[HSS_LEVELS_ARRAY_SIZE]; /**< LMS signature length for each intermediate level */
} HSS_ParsedSig;

/**
 * @ingroup hss
 * @brief HSS output buffer structure
 */
typedef struct {
    uint8_t *data; /**< Buffer pointer */
    size_t *len; /**< Buffer length pointer */
} HSS_OutputBuffer;

/**
 * @ingroup hss
 * @brief Parse HSS signature into components
 * @param parsed       [OUT] Parsed signature structure
 * @param para         [IN]  HSS parameters
 * @param signature    [IN]  Signature to parse
 * @param signatureLen [IN]  Signature length
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssParseSignature(HSS_ParsedSig *parsed, const HSS_Para *para, const uint8_t *signature, size_t signatureLen);

/**
 * @ingroup hss
 * @brief HSS tree context for signing operations
 */
typedef struct {
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    const uint8_t *seed; /**< Tree seed (32 bytes) */
    uint32_t leafIndex; /**< Leaf index in tree */
} HssTreeContext;

/**
 * @ingroup hss
 * @brief HSS signing context for generating signed public keys
 */
typedef struct {
    uint32_t parentLevel; /**< Parent level index */
    uint32_t childLevel; /**< Child level index */
    const HSS_Para *para; /**< HSS parameters */
} HssSignContext;

/**
 * @ingroup hss
 * @brief Generate signed public key (parent signs child's public key)
 * @param output  [OUT]    Output buffer for signed public key
 * @param signCtx [IN]     Signing context
 * @param parent  [IN]     Parent tree context
 * @param child   [IN]     Child tree context
 * @param cache   [IN/OUT] Tree cache for parent level
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssGenerateSignedPubKey(HSS_OutputBuffer *output, const HssSignContext *signCtx, const HssTreeContext *parent,
                                const HssTreeContext *child, LMS_TreeCache *cache);

/**
 * @ingroup hss
 * @brief Get library context from HSS context
 * @param ctx [IN] HSS context
 * @return Library context pointer
 */
static inline void *LIBCTX_FROM_HSS_CTX(const struct HssCtx *ctx)
{
    return (ctx == NULL) ? NULL : ctx->libCtx;
}

/* HSS_FREE_PARA removed: para is now embedded in the context struct. */

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS */

#endif /* HSS_LOCAL_H */
