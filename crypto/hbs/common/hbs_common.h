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

#ifndef HBS_COMMON_H
#define HBS_COMMON_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <stddef.h>
#include "hbs_hash_if.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hbs
 * @brief Algorithm type identifier for HbsTreeCtx
 */
typedef enum {
    HBS_ALGO_XMSS = 0, /**< XMSS / XMSSMT */
    HBS_ALGO_SLH_DSA = 1, /**< SLH-DSA (Stateless Hash-Based DSA) */
} HbsAlgoType;

/**
 * @ingroup hbs
 * @brief Tree context shared by XMSS, XMSSMT and SLH-DSA
 */
typedef struct {
    uint32_t n; /**< Hash output length in bytes */
    uint32_t hp; /**< Tree height per layer */
    uint32_t d; /**< Number of layers */
    uint32_t otsLen; /**< WOTS+ chain length */

    const uint8_t *pubSeed; /**< Public seed */
    const uint8_t *skSeed; /**< Private seed */
    const uint8_t *root; /**< Tree root, used during verification */

    const HbsHashFuncs *hashFuncs; /**< XMSS/SLH-DSA hash function table */

    const HbsAdrsOps *adrsOps; /**< Address operations */
    const void *originalCtx; /**< Original XMSS/SLH-DSA context */
    HbsAlgoType algoType; /**< Algorithm type, used to select correct paths */
} HbsTreeCtx;

/* Maximum hash output size for stack buffers (SHA-512 = 64 bytes) */
#define HBS_MAX_MDSIZE 64
/* Maximum address structure size (XMSS/SLH-DSA = 32 bytes) */
#define HBS_MAX_ADRS_SIZE 32

/* Convenience macro: true when tree uses XMSS height offset convention */
#define HBS_IS_XMSS(ctx) ((ctx)->algoType == HBS_ALGO_XMSS)

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_XMSSMT || HITLS_CRYPTO_SLH_DSA */
#endif /* HBS_COMMON_H */
